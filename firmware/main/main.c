/**
 * AutoQrypt: ESP32 Hardware-in-the-Loop (HIL) Automotive ECU Surrogate
 * Problem Statement PQC-02: Automotive Firmware Authentication & Rollback Defense
 *
 * Runs on ESP32-WROOM-32 (Xtensa Dual-Core LX6 @ 240 MHz, 520 KB SRAM, 4 MB Flash).
 * Admission gate for OTA packages received over UART0 from scripts/hil.py:
 *   - Director role:  Falcon-512 (PQClean falcon-padded-512) over vehicle id + manifest
 *   - Image role:     Ed25519 (Monocypher) AND ML-DSA-44 (PQClean, FIPS 204) over the manifest
 *   - Policy:         strict manifest parse, target id, pinned key ids, NVS monotonic version
 *   - Image:          streamed into the inactive OTA slot, SHA3-256 checked incrementally
 *   - Activation:     A/B boot switch only after every check passes; the new image is
 *                     confirmed on first boot (bootloader rollback is enabled)
 *   - Telemetry:      per-verifier latency (us + CPU cycles), task stack peak, heap watermarks
 *   - Application:    LED blink + battery-temperature feature that differs per release
 *                     (APP_FW_VERSION, set at build time), so an installed update is visible
 *
 * Every check is mandatory. A failure, error or timeout rejects the package; there is no
 * fallback to fewer signatures.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_cpu.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_ota_ops.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_app_desc.h"
#include "esp_random.h"

#include "fips202.h"
#include "ml-dsa-44/api.h"
#include "falcon-padded-512/api.h"
#include "monocypher-ed25519.h"
#include "trusted_keys.h"

static const char *TAG = "AUTOQRYPT_ECU";

#define UART_PORT             UART_NUM_0
#define UART_RX_BUF           8192
#define CHUNK_SIZE            4096   // host waits for "AQ:ACK" after each chunk
#define RX_TIMEOUT_MS         5000   // silence longer than this aborts the transfer
#define VERIFY_TASK_STACK     65536  // each verifier runs in a fresh task of this size
#define BENCH_RUNS            10
#define FACTORY_SECURITY_VER  1      // security version provisioned with the factory image
#define APP_LED_GPIO          2      // ponytail: onboard LED on most ESP32 DevKits; change for other boards

// ---- Wire format (must match scripts/hil.py) ----
#define MANIFEST_LEN   108
#define FALCON_SIG_LEN PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES   // 666
#define ED_SIG_LEN     64
#define MLDSA_SIG_LEN  PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES           // 2420
#define HEADER_LEN     (MANIFEST_LEN + FALCON_SIG_LEN + ED_SIG_LEN + MLDSA_SIG_LEN)

#define IMAGE_DOMAIN    "AQ-IMAGE-V1"
#define DIRECTOR_DOMAIN "AQ-DIRECTOR-V1"
#define ID_FIELD_LEN    16

typedef struct {
    char target_id[ID_FIELD_LEN + 1];
    char version[ID_FIELD_LEN + 1];
    uint32_t security_version;
    uint32_t image_size;
    uint8_t digest[32];
} manifest_t;

enum { V_FALCON, V_ED25519, V_MLDSA, V_COUNT };
static const char *VERIFIER_NAMES[V_COUNT] = {"falcon512_director", "ed25519_image", "mldsa44_image"};

typedef struct {
    int which;
    bool ran;
    bool ok;
    int64_t us;
    uint32_t cycles;
    uint32_t stack_peak_bytes;
    TaskHandle_t caller;
} verify_job_t;

static uint8_t s_header[HEADER_LEN];
static uint8_t s_chunk[CHUNK_SIZE];
static uint8_t s_image_msg[sizeof(IMAGE_DOMAIN) - 1 + MANIFEST_LEN];
static uint8_t s_director_msg[sizeof(DIRECTOR_DOMAIN) - 1 + ID_FIELD_LEN + MANIFEST_LEN];
static uint32_t s_security_version = FACTORY_SECURITY_VER;

static const char *running_slot(void) {
    const esp_partition_t *p = esp_ota_get_running_partition();
    return p ? p->label : "unknown";
}

// ---------------------------------------------------------------- NVS vault

static uint32_t nvs_get_or(nvs_handle_t h, const char *key, uint32_t fallback) {
    uint32_t v;
    return nvs_get_u32(h, key, &v) == ESP_OK ? v : fallback;
}

/**
 * Loads the monotonic security version. A version staged by an accepted update is only
 * committed once that image is running and confirmed, so a rolled-back boot never
 * raises the counter.
 */
static void load_security_version(bool running_confirmed) {
    nvs_handle_t vault;
    ESP_ERROR_CHECK(nvs_open("sec_vault", NVS_READWRITE, &vault));
    s_security_version = nvs_get_or(vault, "monotonic_ver", FACTORY_SECURITY_VER);

    uint32_t pending = nvs_get_or(vault, "pending_ver", 0);
    char slot[17] = {0};
    size_t len = sizeof(slot);
    bool has_slot = nvs_get_str(vault, "pending_slot", slot, &len) == ESP_OK;
    if (pending) {
        if (running_confirmed && has_slot && strcmp(slot, running_slot()) == 0 && pending > s_security_version) {
            s_security_version = pending;
            nvs_set_u32(vault, "monotonic_ver", pending);
            ESP_LOGI(TAG, "Committed monotonic security version %" PRIu32 " for %s", pending, slot);
        }
        nvs_erase_key(vault, "pending_ver");
        nvs_erase_key(vault, "pending_slot");
    }
    nvs_set_u32(vault, "monotonic_ver", s_security_version);
    nvs_commit(vault);
    nvs_close(vault);
}

static esp_err_t stage_security_version(uint32_t ver, const char *slot) {
    nvs_handle_t vault;
    esp_err_t err = nvs_open("sec_vault", NVS_READWRITE, &vault);
    if (err != ESP_OK) return err;
    err = nvs_set_u32(vault, "pending_ver", ver);
    if (err == ESP_OK) err = nvs_set_str(vault, "pending_slot", slot);
    if (err == ESP_OK) err = nvs_commit(vault);
    nvs_close(vault);
    return err;
}

// ---------------------------------------------------------------- UART transport

static bool read_exact(uint8_t *buf, size_t n, uint32_t timeout_ms) {
    size_t got = 0;
    while (got < n) {
        int r = uart_read_bytes(UART_PORT, buf + got, n - got, pdMS_TO_TICKS(timeout_ms));
        if (r <= 0) return false;
        got += (size_t)r;
    }
    return true;
}

/** Blocks until a 4-byte frame magic arrives; returns it as a NUL-terminated string. */
static void wait_for_magic(char out[5]) {
    uint8_t win[4] = {0};
    for (;;) {
        uint8_t b;
        if (uart_read_bytes(UART_PORT, &b, 1, portMAX_DELAY) != 1) continue;
        memmove(win, win + 1, 3);
        win[3] = b;
        if (memcmp(win, "AQPK", 4) == 0 || memcmp(win, "AQBM", 4) == 0 || memcmp(win, "AQLD", 4) == 0) {
            memcpy(out, win, 4);
            out[4] = '\0';
            return;
        }
    }
}

static void proto(const char *line) {
    printf("AQ:%s\n", line);
    fflush(stdout);
}

// ---------------------------------------------------------------- manifest

static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }

static bool copy_id_field(char out[ID_FIELD_LEN + 1], const uint8_t *in) {
    size_t n = 0;
    while (n < ID_FIELD_LEN && in[n]) {
        if (in[n] < 0x20 || in[n] > 0x7e) return false;
        n++;
    }
    for (size_t i = n; i < ID_FIELD_LEN; i++) {
        if (in[i]) return false;  // padding must be all zero
    }
    if (n == 0) return false;
    memcpy(out, in, n);
    out[n] = '\0';
    return true;
}

/** Strict fixed-layout parse. Returns NULL on success or the rejection reason. */
static const char *parse_manifest(const uint8_t *b, manifest_t *m) {
    if (memcmp(b, "AQM1", 4) != 0) return "MALFORMED_MANIFEST_MAGIC";
    if (rd16(b + 4) != 1) return "UNSUPPORTED_FORMAT_VERSION";
    if (b[6] != 1) return "UNSUPPORTED_HASH_ALGORITHM";   // 1 = SHA3-256
    if (b[7] != 0) return "MALFORMED_MANIFEST_FLAGS";
    if (!copy_id_field(m->target_id, b + 8)) return "MALFORMED_TARGET_ID";
    if (!copy_id_field(m->version, b + 24)) return "MALFORMED_VERSION";
    m->security_version = rd32(b + 40);
    m->image_size = rd32(b + 44);
    if (b[48] != 1 || b[49] != 2 || b[50] != 3 || b[51] != 0) return "UNSUPPORTED_SIGNATURE_ALGORITHMS";
    if (memcmp(b + 52, TRUSTED_ED25519_KEY_ID, 8) != 0) return "UNTRUSTED_ED25519_KEY_ID";
    if (memcmp(b + 60, TRUSTED_MLDSA44_KEY_ID, 8) != 0) return "UNTRUSTED_MLDSA44_KEY_ID";
    if (memcmp(b + 68, TRUSTED_FALCON512_KEY_ID, 8) != 0) return "UNTRUSTED_FALCON512_KEY_ID";
    memcpy(m->digest, b + 76, 32);
    if (m->image_size == 0) return "MALFORMED_IMAGE_SIZE";
    return NULL;
}

// ---------------------------------------------------------------- measured verifiers

static bool run_verifier(int which) {
    const uint8_t *falcon_sig = s_header + MANIFEST_LEN;
    const uint8_t *ed_sig = falcon_sig + FALCON_SIG_LEN;
    const uint8_t *mldsa_sig = ed_sig + ED_SIG_LEN;
    switch (which) {
    case V_FALCON:
        return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(falcon_sig, FALCON_SIG_LEN,
                s_director_msg, sizeof(s_director_msg), TRUSTED_FALCON512_PK) == 0;
    case V_ED25519:
        return crypto_ed25519_check(ed_sig, TRUSTED_ED25519_PK, s_image_msg, sizeof(s_image_msg)) == 0;
    case V_MLDSA:
        return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(mldsa_sig, MLDSA_SIG_LEN,
                s_image_msg, sizeof(s_image_msg), TRUSTED_MLDSA44_PK) == 0;
    }
    return false;
}

static void verify_task(void *arg) {
    verify_job_t *job = arg;
    uint32_t c0 = esp_cpu_get_cycle_count();
    int64_t t0 = esp_timer_get_time();
    job->ok = run_verifier(job->which);
    job->us = esp_timer_get_time() - t0;
    job->cycles = esp_cpu_get_cycle_count() - c0;
    // ESP-IDF stack sizes and high-water marks are in bytes
    job->stack_peak_bytes = VERIFY_TASK_STACK - uxTaskGetStackHighWaterMark(NULL);
    job->ran = true;
    xTaskNotifyGive(job->caller);
    vTaskDelete(NULL);
}

/** Runs one verifier in a fresh task so its stack high-water mark is its own. */
static bool measure_verifier(verify_job_t *job, int which) {
    memset(job, 0, sizeof(*job));
    job->which = which;
    job->caller = xTaskGetCurrentTaskHandle();
    if (xTaskCreatePinnedToCore(verify_task, "pqc_verify", VERIFY_TASK_STACK, job, 5, NULL, 1) != pdPASS) {
        return false;  // could not allocate the verifier task: fail closed
    }
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    return job->ok;
}

// ---------------------------------------------------------------- telemetry

// The last decision line is kept so the host can ask for it again ("AQLD") if the
// serial link garbles it.
static char s_last_decision[1024];
static size_t s_last_len;

static void jcat(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(s_last_decision + s_last_len, sizeof(s_last_decision) - s_last_len, fmt, ap);
    va_end(ap);
    if (n > 0) {
        s_last_len = s_last_len + (size_t)n < sizeof(s_last_decision) ? s_last_len + (size_t)n : sizeof(s_last_decision) - 1;
    }
}

static void emit_decision(const char *decision, const char *reason, const manifest_t *m,
                          const verify_job_t jobs[V_COUNT], int64_t hash_us) {
    s_last_len = 0;
    jcat("{\"device_id\":\"%s\",\"event_type\":\"ota_decision\",\"level\":\"%s\",\"logger\":\"esp32_ecu_%s\","
         "\"message\":\"%s: %s\",\"decision\":\"%s\",\"reason\":\"%s\",\"running_slot\":\"%s\","
         "\"installed_security_version\":%" PRIu32,
         DEVICE_VEHICLE_ID, strcmp(decision, "ACCEPT") == 0 ? "INFO" : "ERROR", DEVICE_VEHICLE_ID,
         decision, reason, decision, reason, running_slot(), s_security_version);
    if (m && m->target_id[0]) {
        jcat(",\"target_id\":\"%s\",\"firmware_version\":\"%s\",\"security_version\":%" PRIu32 ",\"image_size\":%" PRIu32,
             m->target_id, m->version, m->security_version, m->image_size);
    }
    for (int i = 0; i < V_COUNT; i++) {
        if (!jobs[i].ran) continue;
        jcat(",\"%s\":{\"ok\":%s,\"us\":%" PRId64 ",\"cycles\":%" PRIu32 ",\"stack_peak_bytes\":%" PRIu32 "}",
             VERIFIER_NAMES[i], jobs[i].ok ? "true" : "false", jobs[i].us, jobs[i].cycles, jobs[i].stack_peak_bytes);
    }
    if (hash_us >= 0) jcat(",\"image_sha3_us\":%" PRId64, hash_us);
    jcat(",\"free_heap_bytes\":%u,\"min_free_heap_bytes\":%u,\"largest_free_block_bytes\":%u}\n",
         (unsigned)esp_get_free_heap_size(), (unsigned)esp_get_minimum_free_heap_size(),
         (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    fputs(s_last_decision, stdout);
    fflush(stdout);
}

/** Dashboard "Measured" modal format (dashboard/app.py reads perf_data). */
static void emit_perf_report(const verify_job_t jobs[V_COUNT], const char *target_slot) {
    uint32_t peak = 0, cycles = 0;
    int64_t us = 0;
    for (int i = 0; i < V_COUNT; i++) {
        if (jobs[i].stack_peak_bytes > peak) peak = jobs[i].stack_peak_bytes;
        cycles += jobs[i].cycles;
        us += jobs[i].us;
    }
    printf("{\"device_id\":\"%s\",\"event_type\":\"perf_report\",\"level\":\"INFO\",\"logger\":\"esp32_ecu_%s\","
           "\"message\":\"Measured on physical ESP32\",\"perf_data\":{\"stack_high_water_mark_bytes\":%" PRIu32 ","
           "\"sram_utilization_pct\":\"%.2f%% of 520 KB\",\"cpu_cycles\":%" PRIu32 ",\"latency_ms\":%.2f,"
           "\"min_free_heap_bytes\":%u,\"active_partition_slot\":\"%s\","
           "\"pqt_hybrid_status\":\"Falcon-512 + Ed25519 + ML-DSA-44 verified on silicon\"}}\n",
           DEVICE_VEHICLE_ID, DEVICE_VEHICLE_ID, peak, peak * 100.0 / (520.0 * 1024.0), cycles, us / 1000.0,
           (unsigned)esp_get_minimum_free_heap_size(), target_slot);
    fflush(stdout);
}

// ---------------------------------------------------------------- admission gate

static void build_signed_messages(void) {
    size_t d = sizeof(IMAGE_DOMAIN) - 1;
    memcpy(s_image_msg, IMAGE_DOMAIN, d);
    memcpy(s_image_msg + d, s_header, MANIFEST_LEN);

    uint8_t vid[ID_FIELD_LEN] = {0};
    memcpy(vid, DEVICE_VEHICLE_ID, strlen(DEVICE_VEHICLE_ID));
    d = sizeof(DIRECTOR_DOMAIN) - 1;
    memcpy(s_director_msg, DIRECTOR_DOMAIN, d);
    memcpy(s_director_msg + d, vid, ID_FIELD_LEN);
    memcpy(s_director_msg + d + ID_FIELD_LEN, s_header, MANIFEST_LEN);
}

static void handle_package(void) {
    manifest_t m = {0};
    verify_job_t jobs[V_COUNT] = {0};
    s_last_len = 0;  // never let "AQLD" return the previous package's decision
    s_last_decision[0] = '\0';

    if (!read_exact(s_header, HEADER_LEN, RX_TIMEOUT_MS)) {
        emit_decision("REJECT", "TRUNCATED_HEADER", NULL, jobs, -1);
        return;
    }
    const char *reason = parse_manifest(s_header, &m);
    if (reason) { emit_decision("REJECT", reason, &m, jobs, -1); return; }
    if (strcmp(m.target_id, DEVICE_TARGET_ID) != 0) { emit_decision("REJECT", "WRONG_TARGET", &m, jobs, -1); return; }
    if (m.security_version <= s_security_version) { emit_decision("REJECT", "ROLLBACK_ATTACK_DETECTED", &m, jobs, -1); return; }

    const esp_partition_t *target = esp_ota_get_next_update_partition(NULL);
    if (!target || m.image_size > target->size) { emit_decision("REJECT", "IMAGE_TOO_LARGE", &m, jobs, -1); return; }

    build_signed_messages();
    static const char *fail_reason[V_COUNT] = {"DIRECTOR_FALCON512_SIGNATURE_INVALID",
                                               "IMAGE_ED25519_SIGNATURE_INVALID",
                                               "IMAGE_MLDSA44_SIGNATURE_INVALID"};
    for (int i = 0; i < V_COUNT; i++) {
        if (!measure_verifier(&jobs[i], i)) {
            emit_decision("REJECT", jobs[i].ran ? fail_reason[i] : "VERIFIER_RESOURCE_FAILURE", &m, jobs, -1);
            return;
        }
    }

    // Signatures cover the manifest; now stream the image into the inactive slot and
    // check it against the signed digest. Nothing is bootable until esp_ota_set_boot_partition.
    esp_ota_handle_t ota;
    if (esp_ota_begin(target, m.image_size, &ota) != ESP_OK) {
        emit_decision("REJECT", "OTA_BEGIN_FAILED", &m, jobs, -1);
        return;
    }
    sha3_256incctx st;
    sha3_256_inc_init(&st);
    int64_t hash_us = 0;
    proto("SEND");
    for (uint32_t received = 0; received < m.image_size;) {
        size_t n = m.image_size - received < CHUNK_SIZE ? m.image_size - received : CHUNK_SIZE;
        if (!read_exact(s_chunk, n, RX_TIMEOUT_MS)) {
            sha3_256_inc_ctx_release(&st);
            esp_ota_abort(ota);
            emit_decision("REJECT", "TRANSFER_INTERRUPTED", &m, jobs, -1);
            return;
        }
        int64_t t0 = esp_timer_get_time();
        sha3_256_inc_absorb(&st, s_chunk, n);
        hash_us += esp_timer_get_time() - t0;
        if (esp_ota_write(ota, s_chunk, n) != ESP_OK) {
            sha3_256_inc_ctx_release(&st);
            esp_ota_abort(ota);
            emit_decision("REJECT", "FLASH_WRITE_FAILED", &m, jobs, -1);
            return;
        }
        received += n;
        char ack[24];
        snprintf(ack, sizeof(ack), "ACK %" PRIu32, received);
        proto(ack);
    }
    uint8_t digest[32];
    sha3_256_inc_finalize(digest, &st);
    if (memcmp(digest, m.digest, 32) != 0) {
        esp_ota_abort(ota);
        emit_decision("REJECT", "IMAGE_DIGEST_MISMATCH", &m, jobs, hash_us);
        return;
    }
    if (esp_ota_end(ota) != ESP_OK) {  // ESP-IDF app image header/checksum validation
        emit_decision("REJECT", "IMAGE_FORMAT_INVALID", &m, jobs, hash_us);
        return;
    }
    if (stage_security_version(m.security_version, target->label) != ESP_OK ||
        esp_ota_set_boot_partition(target) != ESP_OK) {
        emit_decision("REJECT", "ACTIVATION_FAILED", &m, jobs, hash_us);
        return;
    }
    emit_decision("ACCEPT", "ALL_CHECKS_PASSED", &m, jobs, hash_us);
    emit_perf_report(jobs, target->label);
    ESP_LOGI(TAG, "Rebooting into %s (pending first-boot confirmation)", target->label);
    vTaskDelay(pdMS_TO_TICKS(200));
    esp_restart();
}

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/** Repeats the three verifiers on a valid header. Installs nothing. */
static void handle_bench(void) {
    manifest_t m = {0};
    verify_job_t jobs[V_COUNT] = {0};
    if (!read_exact(s_header, HEADER_LEN, RX_TIMEOUT_MS)) { emit_decision("REJECT", "TRUNCATED_HEADER", NULL, jobs, -1); return; }
    const char *reason = parse_manifest(s_header, &m);
    if (reason) { emit_decision("REJECT", reason, &m, jobs, -1); return; }
    build_signed_messages();

    s_last_len = 0;
    jcat("{\"device_id\":\"%s\",\"event_type\":\"bench_report\",\"level\":\"INFO\",\"logger\":\"esp32_ecu_%s\","
         "\"message\":\"Verifier benchmark, %d runs each\",\"runs\":%d",
         DEVICE_VEHICLE_ID, DEVICE_VEHICLE_ID, BENCH_RUNS, BENCH_RUNS);
    for (int i = 0; i < V_COUNT; i++) {
        int64_t us[BENCH_RUNS];
        uint32_t peak = 0;
        bool all_ok = true;
        for (int r = 0; r < BENCH_RUNS; r++) {
            all_ok &= measure_verifier(&jobs[i], i);
            us[r] = jobs[i].us;
            if (jobs[i].stack_peak_bytes > peak) peak = jobs[i].stack_peak_bytes;
        }
        qsort(us, BENCH_RUNS, sizeof(us[0]), cmp_i64);
        jcat(",\"%s\":{\"all_ok\":%s,\"min_us\":%" PRId64 ",\"median_us\":%" PRId64 ",\"max_us\":%" PRId64
             ",\"stack_peak_bytes\":%" PRIu32 "}",
             VERIFIER_NAMES[i], all_ok ? "true" : "false", us[0], us[BENCH_RUNS / 2], us[BENCH_RUNS - 1], peak);
    }
    jcat(",\"min_free_heap_bytes\":%u}\n", (unsigned)esp_get_minimum_free_heap_size());
    fputs(s_last_decision, stdout);  // one write, so the app task's prints can't split the line
    fflush(stdout);
}

/**
 * The ECU's actual application. v1 reads the battery temperature with the LED solid on;
 * v2 adds a sustained over-temperature warning and blinks the LED, so an installed update
 * is visible. The temperature is simulated: the ESP32 has no battery sensor.
 */
static void app_task(void *arg) {
    const char *ver = esp_app_get_description()->version;
    gpio_reset_pin(APP_LED_GPIO);
    gpio_set_direction(APP_LED_GPIO, GPIO_MODE_OUTPUT);
    const int period_ms = 250;
    int over_temp_reads = 0;
    for (int tick = 0;; tick++) {
        gpio_set_level(APP_LED_GPIO, APP_FW_VERSION >= 2 ? (tick & 1) : 1);
        vTaskDelay(pdMS_TO_TICKS(period_ms));
        if (tick % (4000 / period_ms) != 0) continue;
        float temp = 38.0f + (float)(esp_random() % 60) / 10.0f;
        printf("[APP %s] battery temp %.1f C (simulated sensor)\n", ver, temp);
#if APP_FW_VERSION >= 2
        over_temp_reads = temp > 41.0f ? over_temp_reads + 1 : 0;
        if (over_temp_reads >= 2) {
            printf("[APP %s] NEW IN v2: sustained over-temperature warning (%d reads > 41.0 C)\n", ver, over_temp_reads);
        }
#else
        (void)over_temp_reads;
#endif
    }
}

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

#if APP_FW_VERSION == 3
    // Fault-injected release: dies before confirming itself. The bootloader then marks
    // this slot invalid and boots the previous confirmed image on the next reset.
    printf("[APP v3.0.0] FAULT INJECTED: crashing before first-boot confirmation\n");
    vTaskDelay(pdMS_TO_TICKS(300));
    abort();
#endif

    // First boot of a freshly activated image: we reached app_main with NVS working,
    // which is this demonstrator's health check. Confirm it so the bootloader keeps it.
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    esp_ota_get_state_partition(running, &state);
    bool confirmed_now = false;
    if (state == ESP_OTA_IMG_PENDING_VERIFY) {
        confirmed_now = esp_ota_mark_app_valid_cancel_rollback() == ESP_OK;
    }
    load_security_version(state != ESP_OTA_IMG_PENDING_VERIFY || confirmed_now);

    uart_driver_install(UART_PORT, UART_RX_BUF, 0, 0, NULL, 0);

    printf("\n=================================================================\n");
    printf("  AutoQrypt: ESP32 Hardware-in-the-Loop ECU Surrogate\n");
    printf("=================================================================\n");
    const char *app_version = esp_app_get_description()->version;
    // Set by the bootloader when it rolled back from an image that never confirmed itself
    const esp_partition_t *invalid = esp_ota_get_last_invalid_partition();
    esp_app_desc_t invalid_desc = {0};
    bool has_invalid = invalid && esp_ota_get_partition_description(invalid, &invalid_desc) == ESP_OK;

    printf("[ECU-HW] Firmware:         %s\n", app_version);
    printf("[ECU-HW] Target ID:        %s (vehicle %s)\n", DEVICE_TARGET_ID, DEVICE_VEHICLE_ID);
    printf("[ECU-HW] Running slot:     %s @ 0x%08" PRIx32 "\n", running->label, running->address);
    printf("[ECU-HW] Security version: %" PRIu32 " (NVS monotonic counter)\n", s_security_version);
    if (has_invalid) {
        printf("[ECU-HW] Rolled back:      %s in %s never confirmed itself\n", invalid_desc.version, invalid->label);
    }
    printf("[ECU-HW] Free heap:        %u bytes\n", (unsigned)esp_get_free_heap_size());
    printf("-----------------------------------------------------------------\n");
    printf("{\"device_id\":\"%s\",\"event_type\":\"boot_report\",\"level\":\"INFO\",\"logger\":\"esp32_ecu_%s\","
           "\"message\":\"ECU booted %s\",\"app_version\":\"%s\",\"running_slot\":\"%s\",\"installed_security_version\":%" PRIu32
           ",\"confirmed_on_this_boot\":%s,\"last_invalid_slot\":\"%s\",\"last_invalid_version\":\"%s\",\"free_heap_bytes\":%u}\n",
           DEVICE_VEHICLE_ID, DEVICE_VEHICLE_ID, app_version, app_version, running->label, s_security_version,
           confirmed_now ? "true" : "false", has_invalid ? invalid->label : "", has_invalid ? invalid_desc.version : "",
           (unsigned)esp_get_free_heap_size());

    xTaskCreatePinnedToCore(app_task, "ecu_app", 3072, NULL, 3, NULL, 0);

    for (;;) {
        proto("READY");
        char magic[5];
        wait_for_magic(magic);
        if (strcmp(magic, "AQBM") == 0) {
            handle_bench();
        } else if (strcmp(magic, "AQLD") == 0) {
            if (s_last_len) fputs(s_last_decision, stdout);
            fflush(stdout);
        } else {
            handle_package();
        }
    }
}
