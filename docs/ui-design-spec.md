# WIFIKIT UI Design Spec — "Signal Intelligence"

## Design Direction
Military SIGINT console meets cyberpunk energy. Dim is default, bright is earned.
Information in structured grids. Color is currency — spent only on events that matter.

## Color Language (ANSI terminal-defined only)
| Color | Meaning | Usage |
|-------|---------|-------|
| `dim` | Structure, labels, noise | 80% of all text |
| `white bold` | Primary content | SSIDs, PINs, PSKs |
| `cyan` | Informational, identity | Headers, badges, counts |
| `magenta` | Attack-specific accent | WPS badge, Pixie Dust |
| `green bold` | Breakthrough / captured | Cracked PINs, PMKIDs |
| `yellow` | Attention / partial | Pixie data, warnings |
| `red` | Failure / danger | Locked, timeout, error |

## Layout Architecture
```
+-------------------------------------------+
| Scrollback (frozen target summaries)      |  <- layout.print()
| - Gallery of framed results               |
| - Successes LOUD (green frame)            |
| - Failures QUIET (dim, unframed)          |
+-------------------------------------------+
| Active Zone (live attack view)            |  <- set_active() + refresh()
| - Current target with live phases         |
| - Spinners resolve to icons               |
| - On target complete -> freeze to above   |
+-------------------------------------------+
| Status Bar (fixed-width segments)         |  <- statusbar()
| - Adapter(s) + mode + attack + timing     |
+-------------------------------------------+
| REPL Input                                |  <- always visible
+-------------------------------------------+
```

## Phase Display — Universal Pipeline
```
In progress:  ⠋ AUTH              (cyan spinner + white label)
Completed:    ✓ AUTH              (green check + dim label)
Failed:       ✗ AUTH              (red cross + dim label)
Skipped:      ─ AUTH              (dim dash + dim label)

Connected:    ✓ AUTH ━━ ✓ ASSOC ━━ ⠋ EAP
              (green trail, cyan active, dim future)
```

## Live Metrics Line (below pipeline, always present during exchange)
```
tx: 34  rx: 12  ack: 87%  last rx: 0.1s ago
```

## Trophy Moment (PIN cracked)
```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   PIN  4 8 5 6 3 7 1 0    PSK  MyPassword123  ┃  (green bold, spaced digits)
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## Frozen Summaries (scrollback gallery)
- Cracked: green framed box with PIN/PSK
- Failed: dim unframed one-liner
- Locked: red accent, no frame
- Timeout: yellow accent with signal info

## Status Bar — Fixed Width
```
≥160: ◉ RTL8852AU scan ch:hop  708 APs · 132 STAs  wps auto 6/432 ⠋  5m 12s
≥120: ◉ RTL8852AU 🔒ch6  708·132  wps 6/432 ⠋  5m12s
≥80:  ◉ 8852AU 🔒6 708/132 wps6/432 5m
```

## Responsive Width Breakpoints
- ≥160: full layout with all columns and details
- ≥120: compact labels, pipeline wraps to 2 lines
- ≥80: vertical phase list, drop manufacturer/timing
- <80: no frame border, essential info only

## Active Zone Height
- max: 80% of terminal height
- min scrollback: 4 lines always visible
- REPL input always visible below status bar

## Spacing Rhythm
- 1 empty line between content sections
- Dashed separators (─ ─ ─) not solid
- Breathing room makes dense info parseable during hours-long sessions
