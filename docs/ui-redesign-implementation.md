# UI Redesign Implementation Guide

## Overview

Redesign all attack views and scanner to use the "Signal Intelligence" visual language.
Core change: events no longer print to scrollback as log lines. Instead, the active zone
shows everything live, and when a target completes, a framed summary freezes to scrollback.

Design spec: `docs/ui-design-spec.md`
prism-rs library: `../prism-rs/` (see exploration notes below)

## Architecture Change

### Current Flow (event → scrollback)
```
Engine fires events → EventRing
app.rs poll_modules() → drain_events() → format_event() → layout.print(line)
Active zone: render_wps_view() builds frame from WpsInfo snapshot
```

### New Flow (event → live view → freeze on complete)
```
Engine fires events → EventRing (unchanged)
app.rs poll_modules() → drain_events() → DISCARD (don't print to scrollback)
  EXCEPT: on TargetComplete → call freeze_target_summary() → layout.print(framed summary)
Active zone: render_wps_view() builds live view from WpsInfo snapshot (redesigned)
```

The key change in `app.rs` (around line 366):
```rust
// BEFORE:
let events = wps_mod.drain_events();
let lines: Vec<String> = events.iter().map(|e| wps_cli::format_event(e)).collect();
drop(state);
for line in &lines {
    self.layout.print(line);
}

// AFTER:
let events = wps_mod.drain_events();
drop(state);
for event in &events {
    if matches!(event.kind, WpsEventKind::TargetComplete { .. }) {
        // Freeze the target summary to scrollback
        let summary = wps_cli::freeze_target_summary(event, &cached_info);
        for line in &summary {
            self.layout.print(line);
        }
    }
    // All other events: active zone renders them live, no scrollback print needed
}
```

## Data Structures Already In Place

### SubAttackInfo (src/attacks/wps.rs, added this session)
```rust
pub struct SubAttackInfo {
    pub name: String,        // "Computed PINs", "Pixie Dust", "Null PIN"
    pub status: WpsStatus,   // InProgress, Success, PinWrong, Stopped, etc.
    pub detail: String,      // "no candidates", "timeout at M3", "rejected at M4"
    pub elapsed: Duration,
    pub active: bool,        // true = currently running (show spinner)
}
```

Already populated by the Auto mode dispatch in `run_wps_attack_single()`.
Accessible via `info.sub_attacks` in the view's render function.

### WpsInfo fields available for rendering:
- `phase: WpsPhase` — current protocol phase (AUTH, ASSOC, EAP, M1-M7, etc.)
- `attack_type: WpsAttackType` — PixieDust, BruteForce, NullPin, ComputedPin, Auto
- `status: WpsStatus` — InProgress, Success, PinWrong, Locked, etc.
- `bssid, ssid, channel` — current target
- `target_index, target_total` — multi-target progress
- `sub_attacks: Vec<SubAttackInfo>` — resolved/active sub-attacks
- `current_pin, attempts, half1_found, half1_pin` — brute force progress
- `ap_manufacturer, ap_model_name, ap_device_name` — from M1
- `pin_found, psk_found` — results
- `frames_sent, frames_received` — frame counters
- `tx_feedback` — ACK/NACK/delivery%
- `lockouts_detected` — lockout count
- `results: Vec<WpsResult>` — per-target results (for multi-target)
- `start_time` — for elapsed calculation

### WpsPhase for pipeline rendering:
```
Idle, KeyGeneration, Authenticating, Associating, EapIdentity, WscStart,
M1Received, M2Sent, M3Received, M4Sent, PixieCracking,
M5Received, M6Sent, M7Received,
BruteForcePhase1, BruteForcePhase2, LockoutWait, NullPin, Done
```

phase_ordinal() maps these to 0-99 for step comparison.

## File-by-File Implementation

### 1. src/cli/views/wps.rs — FULL REWRITE of render_wps_view()

Current: ~500 lines. New design target: ~400 lines (simpler structure).

The new render_wps_view() should produce:

```
╭──────────────────────────────────────────────────────────────────────────────────╮
│                                                                                  │
│   wps auto                        [6/432]          ▸▸▸░░░░░░░░░░░░░░░░░  1.4%   │
│                                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
│                                                                                  │
│   Raimunda 5G                 D8:C6:78:ED:C4:A7    ch157    ▂▄▆█  -42dBm        │
│   Quantenna Topaz · GPT-2741GNAC-N15G                                            │
│                                                                                  │
│   ✗  Computed PINs       no candidates for D8:C6:78                     0ms      │
│   ⠋  Pixie Dust                                                                  │
│                                                                                  │
│       ✓ AUTH ━━ ✓ ASSOC ━━ ✓ EAP ━━ ✓ ←M1 ━━ ✓ →M2 ━━ ⠋ ←M3          0.4s     │
│       tx: 12  rx: 8  ack: 92%  last rx: 0.1s ago                                │
│                                                                                  │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
│                                                                                  │
│   1 cracked   4 failed   1 locked                          34 tx · 12 rx · 87%  │
│                                                 [s] skip attack  [n] next target │
│                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────╯
```

Structure of render function:
1. Outer frame with dim rounded border
2. Header: attack badge (magenta bold) + target progress + progress bar
3. Dashed separator
4. Target info: SSID (white bold) + BSSID (dim) + channel (cyan) + signal bar
5. AP info line (dim italic): manufacturer + model + device name
6. Empty line
7. Sub-attacks list: iterate info.sub_attacks, show icon + name + detail + elapsed
   - active=true: cyan spinner + name (bold)
   - status=Success: green ✓ + name + detail (green)
   - status=PinWrong/failed: red ✗ + name + detail (dim)
   - status=Stopped: dim ─ + name + "skipped" (dim)
8. Empty line (only if active sub-attack exists)
9. Protocol pipeline (only when a sub-attack is active):
   ✓ AUTH ━━ ✓ ASSOC ━━ ⠋ EAP ━━ ○ ←M1 ...
   Use phase_ordinal(info.phase) vs step ordinals to determine icons
10. Live metrics line: tx + rx + ack% + last_rx_ago
11. Empty line
12. Trophy box (if pin_found): heavy border ┏━┓ with spaced PIN digits + PSK
13. Dashed separator
14. Footer: result counts + total metrics + key hints

### Rendering helpers needed:

```rust
/// Render signal strength as bar characters
fn signal_bar(rssi: i8) -> String {
    // ▂▄▆█ for -40 to -80 dBm range
    let bars = match rssi {
        -50..=0 => "▂▄▆█",
        -60..=-51 => "▂▄▆░",
        -70..=-61 => "▂▄░░",
        -80..=-71 => "▂░░░",
        _ => "░░░░",
    };
    bars.to_string()
}

/// Render dashed separator
fn dashed_sep(w: usize) -> String {
    "─ ".repeat(w / 2).trim_end().to_string()
}

/// Render sub-attack line
fn render_sub_attack(sub: &SubAttackInfo, spinner_frame: &str) -> String {
    if sub.active {
        format!("{}  {}", cyan(spinner_frame), bold(&sub.name))
    } else {
        let icon = match sub.status {
            WpsStatus::Success => green_bold("✓"),
            WpsStatus::Stopped => dim("─"),
            _ => red("✗"),
        };
        let detail = dim(&sub.detail);
        let elapsed = dim(&format_elapsed(sub.elapsed));
        format!("{}  {}       {}  {}", icon, dim(&sub.name), detail, elapsed)
    }
}

/// Render trophy box for cracked PIN
fn render_trophy(pin: &str, psk: &str, inner_w: usize) -> Vec<String> {
    let spaced_pin = pin.chars().map(|c| c.to_string()).collect::<Vec<_>>().join(" ");
    // Heavy box with green bold contents
    vec![
        green("┏━━━...━━━┓"),
        green(&format!("┃   PIN  {}    PSK  {}   ┃", green_bold(&spaced_pin), green_bold(psk))),
        green("┗━━━...━━━┛"),
    ]
}
```

### 2. src/cli/views/wps.rs — NEW freeze_target_summary() function

Called from app.rs when a target completes. Produces framed or unframed summary
based on result:

```rust
pub fn freeze_target_summary(info: &WpsInfo, target_result: &WpsResult) -> Vec<String> {
    match target_result.status {
        WpsStatus::Success => {
            // Green framed box
            // ╭─ ✓ ─ SSID ── BSSID  ch ── Manufacturer ── time ──╮
            // │  ✓ Algo    PIN xxxxxxxx    PSK xxxxxxxx            │
            // ╰───────────────────────────────────────────────────╯
        }
        WpsStatus::Locked => {
            // Red accent, no frame
            // ── 🔒 ── SSID ── BSSID  ch ── Manufacturer ── time ──
            //    🔒 detail
        }
        _ => {
            // Dim, no frame, compact
            // ── ✗ ── SSID ── BSSID  ch ── Manufacturer ── time ──
            //    sub-attack summary on one line
        }
    }
}
```

### 3. src/cli/app.rs — Change WPS event processing (~line 366)

Replace:
```rust
let events = wps_mod.drain_events();
let lines: Vec<String> = events.iter().map(|e| wps_cli::format_event(e)).collect();
drop(state);
for line in &lines {
    self.layout.print(line);
}
```

With:
```rust
let events = wps_mod.drain_events();
let info = wps_mod.info(); // snapshot for freeze
drop(state);
for event in &events {
    match &event.kind {
        WpsEventKind::TargetComplete { .. } => {
            // Find the matching result in info.results
            if let Some(result) = info.results.last() {
                let summary = wps_cli::freeze_target_summary(&info, result);
                for line in &summary {
                    self.layout.print(line);
                }
            }
        }
        WpsEventKind::AttackComplete { .. } => {
            // Final summary — use existing freeze_summary()
        }
        _ => {
            // All other events: active zone handles them, no scrollback
        }
    }
}
```

### 4. Status bar (separate task, applies globally)

File: wherever the status bar is rendered (likely app.rs or a status module).
Changes:
- Fixed-width number fields (right-aligned in 6-char cells)
- Width breakpoints: ≥160 full, ≥120 compact, ≥80 minimal
- Multi-adapter layout: each adapter gets ◉ dot + mode + channel
- Attack info always rightmost before timestamp
- Spinner character for running attacks

### 5. Scanner view (separate task)

File: src/cli/scanner/mod.rs or similar view files
Changes:
- Signal bars (▂▄▆█) replace numeric RSSI
- Color coding: WPS-enabled rows have magenta WPS badge
- Captured handshakes: green █ prefix
- Open networks: red SEC badge
- Weak signal rows: dimmer overall
- Column dropping at width breakpoints
- Footer with categorized counts (WPS/PMKID/Open/Hidden)

## prism-rs Primitives to Use

| Primitive | Usage |
|-----------|-------|
| `frame()` | Outer attack frame, trophy box, frozen summaries |
| `s().dim/cyan/magenta/green/red/bold/italic` | All text styling |
| `get_spinner("dots")` | Active phase spinner frames |
| `render_progress_bar()` | Multi-target progress, brute force progress, lockout countdown |
| `truncate()` | SSID/manufacturer truncation |
| `pad()` | Fixed-width alignment |
| `measure_width()` | Width-responsive layout |
| `term_width()` / `term_height()` | Terminal size for responsive breakpoints |
| `format_time()` | Elapsed time display |
| `format_number()` | Frame count formatting |

## Implementation Order (per session)

### Session 1: WPS Attack View
1. Rewrite render_wps_view() with new visual language
2. Add freeze_target_summary()
3. Change app.rs event processing for WPS
4. Test with `/wps --all`

### Session 2: Scanner View
1. Redesign scanner table with signal bars + color hierarchy
2. Add column dropping at width breakpoints
3. Redesign footer with categorized counts
4. Test at various terminal widths

### Session 3: Other Attack Views
1. Apply same pattern to PMKID, DoS, EAP, etc.
2. Each needs: render rewrite + freeze_target_summary + app.rs event change
3. Pattern is identical — just different sub-attacks and pipeline steps

### Session 4: Status Bar + Polish
1. Fixed-width status bar
2. Multi-adapter layout
3. Width breakpoints
4. Final spacing/breathing room pass across all views

## Key Files Reference

| File | Purpose |
|------|---------|
| `src/cli/views/wps.rs` | WPS view render + freeze + format_event |
| `src/cli/app.rs:~366` | WPS event processing in poll_modules() |
| `src/attacks/wps.rs` | Engine: WpsInfo, SubAttackInfo, WpsResult, events |
| `src/cli/module.rs` | Module trait (render, handle_key, freeze_summary) |
| `src/cli/scanner/mod.rs` | Scanner view |
| `docs/ui-design-spec.md` | Visual language reference |
| `../prism-rs/src/` | All primitives (spinner, frame, layout, etc.) |

## Notes from This Session

- `WpsAttackType` now has 5 variants: PixieDust, BruteForce, NullPin, ComputedPin, Auto
- Auto is the new default (changed in cli/commands/wps.rs)
- skip_attack / skip_target atomics are wired (s/n keys in view)
- PIN generation engine: src/protocol/wps_pin_gen.rs (170+ OUI prefixes)
- Pixie Dust enhanced: 5 PRNG modes + simple mode
- Fast DH: wps_dh_generate_fast() for multi-exchange modes
- NEVER call layout.print() while holding the state mutex (deadlock risk)
- REPL input line must always be visible below status bar
- Active zone capped at 80% terminal height
- All colors are ANSI terminal-defined only (no hex/RGB)
