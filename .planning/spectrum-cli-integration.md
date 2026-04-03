# Spectrum Analyzer CLI Integration Plan

## What's Done (Session 90)

### Driver Layer — COMPLETE & HARDWARE VALIDATED
- `src/chips/mt7921au.rs`: testmode MCU commands, MIB register survey
- `src/core/chip.rs`: ChannelSurvey struct, ChipDriver trait methods (survey + testmode)
- All validated on Fenvi MT7921AU hardware

### Spectrum View — COMPLETE (standalone)
- `src/cli/views/spectrum.rs`: SpectrumData, render_spectrum() (braille), render_spectrum_mini()
- 7 tests passing

### Test Binary — COMPLETE
- `src/bin/test_spectrum_mt7921.rs`: 8 modes including `visual` (live braille display)
- Visual mode confirmed working — real spectrum rendered in terminal

## What Needs Building

### 1. Add Spectrum as ScannerModule View

The scanner already has multiple views (APs, Clients, Handshakes, Events). Spectrum should be view index 5.

**File:** `src/cli/scanner/mod.rs` (~1100 lines)

Look at `ScanView` enum and add `Spectrum` variant:
```rust
enum ScanView {
    Aps,        // 1
    Clients,    // 2
    Handshakes, // 3
    Events,     // 4
    Spectrum,   // 5  ← NEW
}
```

The scanner already collects per-channel RSSI from every frame it processes. Wire that into a `SpectrumData` instance stored in the scanner state.

### 2. Feed Real-Time Data into SpectrumData

In the scanner's frame processing loop, for each received frame:
```rust
// Already have: frame.channel, frame.rssi
spectrum_data.update_rssi(frame.channel, frame.rssi as i16);
```

For AP counts per channel, the scanner already tracks this. After updating the AP database:
```rust
// Count APs per channel from scanner state
for ch in channels {
    let count = aps.iter().filter(|ap| ap.channel == ch).count();
    spectrum_data.update_ap_count(ch, count as u16);
}
```

### 3. Add MIB Register Reads to Channel Hop

In the scanner's channel switching code (wherever `set_channel()` is called):
```rust
// After channel switch, read MIB survey
if let Ok(survey) = driver.survey_read(0) {
    // Feed busy_us into spectrum data for the PREVIOUS channel
    // (counters accumulated during the dwell on that channel)
}
driver.survey_reset(0);  // Reset for next dwell
```

### 4. Render in Scanner's render() Method

When `ScanView::Spectrum` is active:
```rust
ScanView::Spectrum => {
    spectrum::render_spectrum(&self.spectrum_data, width, height)
}
```

### 5. Key Bindings

- `5` or `s` in Normal mode → switch to Spectrum view
- `m` → cycle display mode (Peak/Average/Current)
- Standard vim navigation for the AP table below the graph

### 6. Status Bar Segments

When spectrum view is active:
```rust
StatusSegment::new("SPECTRUM", SegmentStyle::CyanBold),
StatusSegment::new(format!("{} APs", total_aps), SegmentStyle::Green),
StatusSegment::new(format!("{}/s", format_rate(frames)), SegmentStyle::Yellow),
```

## prism-rs Primitives to Use

| Primitive | Where | How |
|-----------|-------|-----|
| `braille::grid_to_braille` | Main graph | Already using |
| `frame()` Rounded | Wrap spectrum display | `frame(content, &FrameOptions { border: Rounded, title: Some("SPECTRUM") })` |
| `scroll_table()` | AP list below graph | Channel/SSID/RSSI/Busy/Enc columns |
| `kv()` | Summary stats | Strongest AP, busiest channel |
| `badge()` Bracket | Mode label | `[PEAK]` `[LIVE]` `[AVG]` |
| `format_rate()` | Packet rate | `146.2/s` |
| `format_number()` | Frame counts | `1,234` |
| `statusbar()` | Bottom line | Left: mode+stats, Right: key hints |
| `style::fg(Color::Rgb)` | Signal gradient | RGB interpolation green→yellow→red |
| `progress_bar()` Smooth | Per-channel bars | Alternative to braille for channel detail view |

## Key Files to Read First

1. `src/cli/scanner/mod.rs` — ScannerModule, ScanView enum, render(), handle_key()
2. `src/cli/views/spectrum.rs` — SpectrumData, render functions (already built)
3. `src/cli/module.rs` — Module trait, ViewDef, StatusSegment
4. `src/core/chip.rs` — ChannelSurvey struct, ChipDriver survey methods
5. `../prism-rs/src/frame.rs` — frame() for boxing the display
6. `../prism-rs/src/scroll.rs` — scroll_table() for AP list

## Hardware Test Commands

```bash
# Quick validation — channel sweep with RSSI
cargo run --bin test_spectrum_mt7921 -- --mode sweep

# Live braille display
cargo run --bin test_spectrum_mt7921 -- --mode visual --duration 60

# MIB register survey (busy/tx/rx per channel)
cargo run --bin test_spectrum_mt7921 -- --mode survey

# RF test mode — query all AT commands
cargo run --bin test_spectrum_mt7921 -- --mode query

# TX power control test
cargo run --bin test_spectrum_mt7921 -- --mode power
```

## Architecture Notes

- SpectrumData lives in ScannerModule state (Arc<Mutex<>> snapshot pattern)
- Updated on UI thread from scanner's frame processing (same as AP/client updates)
- MIB reads happen in the scanner's channel hop thread
- Braille rendering is pure (no I/O) — render_spectrum() returns Vec<String>
- The view should split: top 60% = braille graph, bottom 40% = scroll_table of APs sorted by signal
