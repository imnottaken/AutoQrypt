# AutoQrpt — Agent Instructions & Design System

## Project Context
AutoQrpt is an automotive post-quantum OTA firmware authentication and monotonic anti-rollback gateway (PQC-02) for connected Software-Defined Vehicles (SDVs). It features Uptane two-role separation (Director vs OEM Image), FIPS 204 ML-DSA-44 + Ed25519 hybrid dual-signing, Falcon-512 CAN-FD bus compression, and hardware NVS monotonic counters on ESP32 silicon.

- **Frontend**: Single-page application in [`scripts/hil_demo.html`](file:///Users/koustavdey/Downloads/AutoQrpt/scripts/hil_demo.html) using React 18, Tailwind CSS, Three.js, and shadcn design tokens.
- **Backend HIL Server**: Python HTTP server in [`scripts/hil.py`](file:///Users/koustavdey/Downloads/AutoQrpt/scripts/hil.py) serving on `http://127.0.0.1:8080`.
- **Live Reload**: The server re-reads `scripts/hil_demo.html` from disk on every page reload (`Cmd + R`).

---

## Anti-"AI Slop" Frontend Design Rules (tasteskill v2 & Vercel Design Language)

When modifying or designing UI components in this repository, follow these strict anti-slop rules:

### 1. Ban AI Design Defaults
- ❌ **NO generic purple/violet/cyan glowing mesh gradients** behind cards.
- ❌ **NO identical 3-column rounded-card rows with centered icons** and 3-line filler text.
- ❌ **NO decorative clutter**: every pill, border, badge, and rule must carry real technical data, not visual padding.
- ❌ **NO cramped or wall-of-text sections**: ruthlessly remove fluff and use whitespace to establish hierarchy.

### 2. High-Craft House Style
- **Achromatic Foundation**: Deep obsidian dark background (`#09090b` / `bg-zinc-950`), high-contrast crisp text (`#fafafa` / `text-zinc-100`), and subtle zinc borders (`border-zinc-800/80` or `rgba(255, 255, 255, 0.08)`).
- **Shadow-as-Border**: Use subtle 1px inset ring or `box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.1)` rather than heavy CSS borders.
- **Typography Discipline**:
  - Headers: Geist Sans with tight letter-spacing (`tracking-tight`, `-0.03em`) and uppercase or sentence-case punchiness.
  - Telemetry & Hashes: Geist Mono for addresses, firmware versions, stack bytes, and timestamps.
- **Full-Page Snapping Rhythm**:
  - Landing page sections are full viewport height (`100vh`, `min-h-screen`, `snap-start`) so each screen communicates one clear concept.
- **Substance Over Ornament**: Let the domain substance (cryptographic latencies, FreeRTOS stack watermarks, CAN-FD frame counts, monotonic security versions) be the hero elements.

---

## Installed Skills for OpenCode
OpenCode has the following skills installed and linked in `~/.config/opencode/skills/`:
1. `design-taste-frontend` (`tasteskill v2`): Distilled from 247 award-winning gallery sites to eliminate AI design clichés and enforce art direction.
2. `web-design-guidelines`: Vercel Labs engineering and aesthetic guidelines.
