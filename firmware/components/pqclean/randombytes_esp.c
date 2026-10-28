// PQClean randombytes() backed by the ESP32 hardware RNG. Only signing/keygen use it;
// the verifiers linked by the firmware never call it.
#include "randombytes.h"
#include "esp_random.h"

int randombytes(uint8_t *output, size_t n) {
    esp_fill_random(output, n);
    return 0;
}
