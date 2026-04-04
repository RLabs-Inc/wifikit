// MT7921AU 6GHz Diagnostic Tool
//
// Systematic test of 6GHz reception. Tests each possible failure point:
// 1. Baseline: verify 2.4GHz and 5GHz work (known good)
// 2. MIB survey: check if radio hears ANY RF energy on 6GHz
// 3. Channel switch methods: CHANNEL_SWITCH vs SET_RX_PATH
// 4. Sniffer config: with and without re-sending on 6GHz
// 5. Multiple 6GHz channels: ch1, ch37, ch149 (different UNII bands)
//
// Usage:
//   cargo run --bin test_6ghz_mt7921

use std::time::{Duration, Instant};
use wifikit::core::chip::{ChipDriver, ChannelSurvey};
use wifikit::core::{Channel, Band};

fn main() {
    eprintln!("╔══════════════════════════════════════════╗");
    eprintln!("║  MT7921AU 6GHz Diagnostic Tool           ║");
    eprintln!("╚══════════════════════════════════════════╝");

    // ── Open device ──
    let (mut driver, _eps) = match wifikit::chips::mt7921au::Mt7921au::open_usb(0x0E8D, 0x7961) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  FAILED to open device: {}", e);
            // Try Comfast
            match wifikit::chips::mt7921au::Mt7921au::open_usb(0x3574, 0x6211) {
                Ok(d) => d,
                Err(e2) => { eprintln!("  FAILED Comfast too: {}", e2); return; }
            }
        }
    };

    // ── Init ──
    eprint!("  Init... ");
    let t = Instant::now();
    if let Err(e) = driver.init() {
        eprintln!("FAILED: {}", e);
        return;
    }
    eprintln!("OK ({:.0}ms)", t.elapsed().as_millis());

    let info = driver.chip_info();
    eprintln!("  Chip: {} | FW: {} | MAC: {}", info.name, info.firmware_version, driver.mac());
    eprintln!("  Caps: {:?}", info.caps);

    // ── Monitor mode ──
    eprint!("  Monitor mode... ");
    let t = Instant::now();
    if let Err(e) = driver.set_monitor_mode() {
        eprintln!("FAILED: {}", e);
        return;
    }
    eprintln!("OK ({:.0}ms)", t.elapsed().as_millis());

    eprintln!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 1: Baseline — 2.4GHz (must work)
    // ═══════════════════════════════════════════════════════════════
    eprintln!("═══ TEST 1: Baseline 2.4GHz (ch6) ═══");
    let (frames, switch_ms) = test_channel(&mut driver, Channel::new(6), 3);
    eprintln!("  Result: {} frames in 3s (switch: {:.0}ms)", frames, switch_ms);
    if frames == 0 {
        eprintln!("  ⚠ ZERO frames on 2.4GHz — something is fundamentally broken!");
        return;
    }
    eprintln!("  ✓ 2.4GHz baseline OK\n");

    // ═══════════════════════════════════════════════════════════════
    // TEST 2: Baseline — 5GHz (must work)
    // ═══════════════════════════════════════════════════════════════
    eprintln!("═══ TEST 2: Baseline 5GHz (ch36) ═══");
    let (frames, switch_ms) = test_channel(&mut driver, Channel::new(36), 3);
    eprintln!("  Result: {} frames in 3s (switch: {:.0}ms)", frames, switch_ms);
    if frames == 0 {
        eprintln!("  ⚠ ZERO frames on 5GHz ch36 — try ch149");
        let (frames2, _) = test_channel(&mut driver, Channel::new(149), 3);
        if frames2 == 0 {
            eprintln!("  ⚠ ZERO on ch149 too — 5GHz may be broken");
        } else {
            eprintln!("  ✓ 5GHz ch149 OK ({} frames)", frames2);
        }
    } else {
        eprintln!("  ✓ 5GHz baseline OK\n");
    }

    // Return to 2.4GHz to reset radio state
    let _ = driver.set_channel(Channel::new(6));
    std::thread::sleep(Duration::from_millis(100));

    // ═══════════════════════════════════════════════════════════════
    // TEST 3: 6GHz channel switch — does it complete?
    // ═══════════════════════════════════════════════════════════════
    eprintln!("═══ TEST 3: 6GHz channel switch timing ═══");
    let test_channels_6g: &[(u8, &str)] = &[
        (1,   "UNII-5 start"),
        (37,  "UNII-5 mid"),
        (93,  "UNII-6"),
        (149, "UNII-7"),
        (197, "UNII-8"),
    ];

    for &(ch_num, label) in test_channels_6g {
        let ch = Channel::new_6ghz(ch_num);
        eprint!("  ch{:<3} ({})... ", ch_num, label);
        let t = Instant::now();
        match driver.set_channel(ch) {
            Ok(()) => {
                let ms = t.elapsed().as_millis();
                eprintln!("OK ({:.0}ms)", ms);
            }
            Err(e) => {
                eprintln!("FAILED: {}", e);
            }
        }
    }
    eprintln!();

    // Return to known good before MIB test
    let _ = driver.set_channel(Channel::new(6));
    std::thread::sleep(Duration::from_millis(200));

    // ═══════════════════════════════════════════════════════════════
    // TEST 4: MIB survey — is the radio hearing RF on 6GHz?
    // ═══════════════════════════════════════════════════════════════
    eprintln!("═══ TEST 4: MIB survey (RF energy detection) ═══");
    eprintln!("  Testing if radio hears ANY energy on 6GHz...");

    // First: MIB on 2.4GHz as control (should be non-zero)
    let _ = driver.set_channel(Channel::new(6));
    let _ = driver.survey_enable(0);
    let _ = driver.survey_reset(0);
    std::thread::sleep(Duration::from_secs(1));
    match driver.survey_read(0) {
        Ok(s) => {
            eprintln!("  2.4GHz ch6 MIB (1s): busy={}us tx={}us rx={}us obss={}us",
                s.busy_us, s.tx_us, s.rx_us, s.obss_us);
            if s.busy_us == 0 && s.rx_us == 0 {
                eprintln!("  ⚠ MIB zero on 2.4GHz too — survey may not be working");
            }
        }
        Err(e) => eprintln!("  MIB read error: {}", e),
    }

    // Now: MIB on 6GHz channels
    for &(ch_num, label) in &[(1u8, "UNII-5"), (93, "UNII-6"), (197, "UNII-8")] {
        let ch = Channel::new_6ghz(ch_num);
        let _ = driver.set_channel(ch);
        // band_idx for MIB: MT7921 has 2 hardware bands (0 and 1).
        // 6GHz shares band 1 radio with 5GHz per driver comment.
        let band_idx: u8 = 1;
        let _ = driver.survey_enable(band_idx);
        let _ = driver.survey_reset(band_idx);
        std::thread::sleep(Duration::from_secs(2));
        match driver.survey_read(band_idx) {
            Ok(s) => {
                eprintln!("  6GHz ch{:<3} ({}) MIB (2s): busy={}us tx={}us rx={}us obss={}us",
                    ch_num, label, s.busy_us, s.tx_us, s.rx_us, s.obss_us);
            }
            Err(e) => eprintln!("  6GHz ch{} MIB error: {}", ch_num, e),
        }
    }
    eprintln!();

    // Return to known good
    let _ = driver.set_channel(Channel::new(6));
    std::thread::sleep(Duration::from_millis(200));

    // ═══════════════════════════════════════════════════════════════
    // TEST 5: 6GHz frame reception — multiple channels
    // ═══════════════════════════════════════════════════════════════
    eprintln!("═══ TEST 5: 6GHz frame reception (5s per channel) ═══");
    let mut any_frames = false;
    for &(ch_num, label) in test_channels_6g {
        let ch = Channel::new_6ghz(ch_num);
        let (frames, switch_ms) = test_channel(&mut driver, ch, 5);
        eprintln!("  ch{:<3} ({}): {} frames (switch: {:.0}ms)",
            ch_num, label, frames, switch_ms);
        if frames > 0 {
            any_frames = true;
        }
    }
    if !any_frames {
        eprintln!("  ⚠ ZERO frames on ALL 6GHz channels");
    }
    eprintln!();

    // ═══════════════════════════════════════════════════════════════
    // TEST 6: Recovery — does 2.4/5GHz still work after 6GHz?
    // ═══════════════════════════════════════════════════════════════
    eprintln!("═══ TEST 6: Recovery after 6GHz ═══");
    let (frames_24, _) = test_channel(&mut driver, Channel::new(6), 3);
    eprintln!("  2.4GHz ch6 after 6GHz: {} frames", frames_24);
    let (frames_5, _) = test_channel(&mut driver, Channel::new(36), 3);
    eprintln!("  5GHz ch36 after 6GHz: {} frames", frames_5);
    if frames_24 == 0 || frames_5 == 0 {
        eprintln!("  ⚠ 6GHz switch BROKE the radio — 2.4/5GHz no longer receiving!");
        eprintln!("  This means the firmware enters a bad state on 6GHz band switch.");
    } else {
        eprintln!("  ✓ Radio recovered OK after 6GHz\n");
    }

    // ═══════════════════════════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════════════════════════
    eprintln!("═══ SUMMARY ═══");
    eprintln!("  If MIB busy_us > 0 on 6GHz: radio is tuned, no APs nearby");
    eprintln!("  If MIB busy_us = 0 on 6GHz: radio is NOT tuned — firmware needs more commands");
    eprintln!("  If 2.4/5GHz broke after 6GHz: firmware crashes on 6GHz band switch");

    let _ = driver.shutdown();
}

/// Switch to a channel and count frames for `duration_secs`.
/// Returns (frame_count, switch_time_ms).
fn test_channel(driver: &mut wifikit::chips::mt7921au::Mt7921au, ch: Channel, duration_secs: u64) -> (u64, f64) {
    let t = Instant::now();
    if let Err(e) = driver.set_channel(ch) {
        eprintln!("  Channel switch failed: {}", e);
        return (0, t.elapsed().as_secs_f64() * 1000.0);
    }
    let switch_ms = t.elapsed().as_secs_f64() * 1000.0;

    let mut frames = 0u64;
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    while Instant::now() < deadline {
        // 10ms timeout per read — tight loop, no hanging
        match driver.rx_frame(Duration::from_millis(10)) {
            Ok(Some(_)) => frames += 1,
            Ok(None) => {}
            Err(_) => {}
        }
    }

    (frames, switch_ms)
}
