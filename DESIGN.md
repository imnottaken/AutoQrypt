# Design System: AutoQrpt (PQC-02 Automotive Post-Quantum OTA Gateway)

## 1. Visual Theme & Atmosphere
AutoQrpt uses a **High-Craft Achromatic Hardware & Spatial Telemetry** aesthetic grounded in `AGENTS.md`, `tasteskill v2` (`design-taste-frontend`), and Vercel's engineering design language.

- **Achromatic Foundation**: Deep obsidian background (`#09090b` / `bg-zinc-950`), crisp high-contrast foreground (`#fafafa` / `text-zinc-100`), and muted zinc secondary hierarchy (`#a1a1aa` / `text-zinc-400`, `#71717a` / `text-zinc-500`).
- **Shadow-as-Border**: Surfaces are separated by subtle tone steps (`#09090b` → `#121215` → `#18181b`) and crisp 1px ring shadows (`box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.08)`), never glowing gradients or heavy outlines.
- **Full-Viewport Snapping Rhythm (`100dvh` / `snap-start`)**: Each full-viewport screen on the Landing Page communicates one distinct architectural proof with generous breathing room, anchored by an interactive Three.js 3D Silicon & Lattice WebGL stage.
- **Substance Over Ornament**: Real cryptographic measurements (NIST FIPS 204 `ML-DSA-44` at `17.7 ms`, `Falcon-512` at `666 B / 11 CAN-FD frames`, FreeRTOS stack high-water mark at `36,496 B / 6.85% SRAM`, and `3,262 B` wire headers) are the visual centerpiece.

---

## 2. Color Palette & Roles

- **Obsidian Ground** (`#09090b` / `zinc-950`) — Primary canvas and WebGL backdrop.
- **Elevated Panel** (`#111113` / `rgba(24, 24, 27, 0.65)`) — Shadcn card and HUD surface.
- **Recessed Well** (`#18181b` / `zinc-900`) — Interactive controls, byte-map cells, and active tabs.
- **Ring Border** (`rgba(255, 255, 255, 0.08)`) — `1px` structural hairline (`box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.08)`).
- **Primary Ink** (`#fafafa` / `zinc-50`) — Headlines, primary figures, and primary CTA fill.
- **Secondary Ink** (`#a1a1aa` / `zinc-400`) — Narrative body copy (`max-w-[60ch]`).
- **Muted Telemetry** (`#71717a` / `zinc-500`) — Byte offsets, memory addresses, axis labels.
- **Semantic Status Signals** (used strictly for real state, never decoration):
  - **Verified Emerald** (`#10b981`) — Signature valid / `ACCEPT` / active partition confirmed.
  - **Rollback Amber** (`#f59e0b`) — Watchdog boot rollback / NVS counter alert.
  - **Fault Crimson** (`#ef4444`) — Fail-closed rejection (`REJECT`) / bit-flip / forged signature.

---

## 3. Typography Discipline

- **Display & UI Sans (`Geist`)**:
  - Tight tracking (`-0.035em`), crisp geometric rhythm, maximum 2 lines per headline.
  - Hero Headline: `clamp(2.25rem, 4.2vw, 4rem)`, `font-semibold` to `font-bold`, `leading-[1.04]`.
  - Section Headings: `clamp(1.75rem, 3vw, 2.75rem)`, `tracking-tight`.
- **Telemetry & Hashes (`Geist Mono`)**:
  - `font-variant-numeric: tabular-nums` enforced on all latencies, cycle counts, byte offsets, SHA3-256 digests, and security versions (`SV`).

---

## 4. Full-Viewport Landing Page Architecture (`snap-y snap-mandatory`)

1. **Screen 01 — Hero & Interactive 3D Silicon/Lattice Stage (`#hero`)**:
   - Asymmetric split: Left column delivers the PQC-02 problem statement, two-line punchy headline, concise explanation, primary CTA (`Open HIL Test Bench`), and interactive 3D subsystem selector (`[ML-DSA-44 Lattice]`, `[Uptane Dual-Role]`, `[CAN-FD 51-Frame Bus]`, `[ESP32 Dual-Slot Silicon]`). Right column frames the interactive Three.js 3D assembly and live hardware readouts (`17.7 ms`, `4.9 ms`, `36,496 B`, `ota_0`).
2. **Screen 02 — Interactive Threat & Fail-Closed Defense Matrix (`#threats`)**:
   - Asymmetric 5:7 split: Select any of the 4 automotive attack vectors (`HNDL Shor Forgery`, `Monotonic Rollback Replay`, `Compromised Fleet Director`, `CAN-FD In-Transit Bit Flip`) to rotate the 3D stage, inspect the exact wire byte offset and C verification gate, and launch that exact attack in the HIL Test Bench with one click.
3. **Screen 03 — 3,262-Byte `AQPK` Wire Protocol & Uptane Split (`#protocol`)**:
   - Interactive proportional byte-map of the `3,262 B` frame header (`AQPK` 4B | `Manifest` 108B | `Falcon-512` 666B | `Ed25519` 64B | `ML-DSA-44` 2,420B) paired with the Uptane Two-Role HSM split and QpiAI 8-qubit Hadamard QRNG provenance.
4. **Screen 04 — ESP32-LX6 Silicon Benchmarks & Dual-Bank Flash Map (`#silicon`)**:
   - Cycle-accurate latency bars (`4.9 ms` Falcon-512, `14.8 ms` SHA3-256, `17.7 ms` ML-DSA-44, `34.0 ms` Ed25519) beside the `firmware/partitions.csv` 4 MB flash layout (`nvs 0x9000`, `ota_0 0x10000`, `ota_1 0x190000`) and direct launch bar into the HIL Test Bench.

---

## 5. HIL Test Bench Console (`testbench` View)

- Built with clean **shadcn/ui** primitives (`Card`, `Badge`, `Button`, `Progress`, `Select`, `Table`) on the same `#09090b` achromatic foundation.
- Top 5-metric telemetry strip + live `ota_0 ⇄ ota_1` partition indicator.
- Two-column dispatch deck (`Dispatch Signed OEM Release` vs. `Inject Targeted Fault Vector` across all 8 test cases).
- 5-Stage verification pipeline gate strip + per-algorithm silicon latency/stack breakdown + chronological Security Audit Ledger.
