// MT7921AU Spectrum / RF Test Mode Explorer
//
// Probes the firmware's hidden test modes:
//   1. RF Test mode — TX/RX control, power tuning
//   2. WiFi Spectrum mode — spectral energy data
//   3. ICAP mode — raw I/Q baseband capture
//
// This is EXPLORATORY — we send the MCU commands the Linux driver defines
// and observe what the firmware returns. Nobody has done this from userspace
// on macOS before.
//
// Usage:
//   cargo run --bin test_spectrum_mt7921
//   cargo run --bin test_spectrum_mt7921 -- --mode spectrum
//   cargo run --bin test_spectrum_mt7921 -- --mode icap
//   cargo run --bin test_spectrum_mt7921 -- --mode rftest
//   cargo run --bin test_spectrum_mt7921 -- --mode query
//   cargo run --bin test_spectrum_mt7921 -- --channel 36

use std::time::{Duration, Instant};
use wifikit::core::chip::ChipDriver;
use wifikit::core::{Channel, Band};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut mode = "query".to_string();
    let mut channel: u8 = 6;
    let mut duration_secs: u64 = 10;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" | "-m" => {
                i += 1;
                if i < args.len() { mode = args[i].clone(); }
            }
            "--channel" | "-c" => {
                i += 1;
                if i < args.len() { channel = args[i].parse().unwrap_or(6); }
            }
            "--duration" | "-d" => {
                i += 1;
                if i < args.len() { duration_secs = args[i].parse().unwrap_or(10); }
            }
            "--help" | "-h" => {
                eprintln!("Usage: test_spectrum_mt7921 [options]");
                eprintln!("  --mode <query|rftest|spectrum|icap|power|sweep>  Test mode (default: query)");
                eprintln!("  --channel <N>      Channel to use (default: 6)");
                eprintln!("  --duration <secs>  Duration for capture modes (default: 10)");
                eprintln!();
                eprintln!("Modes:");
                eprintln!("  query    — Enter RF test mode and query various AT commands");
                eprintln!("  rftest   — Enter RF test mode, read RX stats");
                eprintln!("  spectrum — Enter WiFi Spectrum analyzer mode, capture data");
                eprintln!("  icap     — Enter I/Q capture mode, capture raw baseband");
                eprintln!("  power    — Test TX power control at various levels");
                eprintln!("  sweep    — Sweep all channels reading signal levels");
                eprintln!("  survey   — Read MIB register survey per channel (busy/tx/rx time)");
                eprintln!("  visual   — LIVE braille spectrum display (the dream!)");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    eprintln!("╔══════════════════════════════════════════════════╗");
    eprintln!("║  MT7921AU Spectrum / RF Test Mode Explorer       ║");
    eprintln!("╠══════════════════════════════════════════════════╣");
    eprintln!("║  Mode:     {:40}║", mode);
    eprintln!("║  Channel:  {:40}║", channel);
    eprintln!("║  Duration: {:40}║", format!("{}s", duration_secs));
    eprintln!("╚══════════════════════════════════════════════════╝");
    eprintln!();

    // ── Find and open MT7921AU ──
    let mut adapter = match open_mt7921() {
        Some(a) => a,
        None => {
            eprintln!("ERROR: No MT7921AU adapter found. Plug one in and retry.");
            return;
        }
    };

    // ── Initialize ──
    eprintln!("[*] Initializing adapter...");
    if let Err(e) = adapter.init() {
        eprintln!("ERROR: Init failed: {}", e);
        return;
    }
    eprintln!("[+] Adapter initialized: {}", adapter.chip_info().firmware_version);

    // ── Enter monitor mode first (required for testmode per Linux driver) ──
    eprintln!("[*] Entering monitor mode...");
    if let Err(e) = adapter.set_monitor_mode() {
        eprintln!("ERROR: Monitor mode failed: {}", e);
        return;
    }
    eprintln!("[+] Monitor mode active");

    // ── Set channel ──
    let ch = Channel::new(channel);
    eprintln!("[*] Setting channel {} ({} MHz, {:?})...", ch.number, ch.center_freq_mhz, ch.band);
    if let Err(e) = adapter.set_channel(ch) {
        eprintln!("ERROR: Channel switch failed: {}", e);
        return;
    }
    eprintln!("[+] Channel {} set", ch.number);
    eprintln!();

    // ── Run selected test mode ──
    match mode.as_str() {
        "query" => test_query_at_commands(&mut adapter),
        "rftest" => test_rftest_mode(&mut adapter, duration_secs),
        "spectrum" => test_spectrum_mode(&mut adapter, duration_secs),
        "icap" => test_icap_mode(&mut adapter, duration_secs),
        "power" => test_power_control(&mut adapter),
        "sweep" => test_channel_sweep(&mut adapter),
        "survey" => test_channel_survey(&mut adapter),
        "visual" => test_visual_spectrum(&mut adapter, duration_secs),
        _ => {
            eprintln!("Unknown mode: {}. Use --help for options.", mode);
        }
    }

    // ── Cleanup ──
    eprintln!();
    eprintln!("[*] Exiting test mode...");
    let _ = adapter.exit_testmode();
    eprintln!("[*] Shutting down...");
    let _ = adapter.shutdown();
    eprintln!("[+] Done.");
}

/// Test: Enter RF test mode and query various AT command IDs.
/// This probes what the firmware supports and what data it returns.
fn test_query_at_commands(adapter: &mut wifikit::chips::mt7921au::Mt7921au) {
    eprintln!("═══ QUERY AT COMMANDS ═══");
    eprintln!("[*] Entering RF test mode...");

    if let Err(e) = adapter.enter_rftest_mode() {
        eprintln!("ERROR: Failed to enter RF test mode: {}", e);
        return;
    }
    eprintln!("[+] RF test mode active!");
    eprintln!();

    // Query a range of AT function IDs to see what's available
    // Known IDs from Linux: 0x01 (TRX), 0x0A (FREQ_OFFSET), 0x13 (SLOT_TIME), 0x15 (TX_POWER)
    let known_funcs = [
        (0x01, "SET_TRX"),
        (0x02, "SET_PREAMBLE"),
        (0x03, "SET_RATE"),
        (0x04, "SET_NSS"),
        (0x05, "SET_SYSTEM_BW"),
        (0x06, "SET_TX_LENGTH"),
        (0x07, "SET_TX_COUNT"),
        (0x08, "SET_RX_FILTER_PKT_LEN"),
        (0x09, "SET_ANT"),
        (0x0A, "SET_FREQ_OFFSET"),
        (0x0B, "GET_FREQ_OFFSET"),
        (0x0C, "SET_CHANNEL_BANDWIDTH"),
        (0x0D, "SET_DATA_BW"),
        (0x0E, "SET_PRIMARY_BW"),
        (0x0F, "SET_ENCODE_MODE"),
        (0x10, "SET_GI"),
        (0x11, "SET_STBC"),
        (0x12, "SET_DBDC_BAND_IDX"),
        (0x13, "SET_SLOT_TIME"),
        (0x14, "SET_MAC_HEADER"),
        (0x15, "SET_TX_POWER"),
        (0x16, "SET_TX_POWER_CTRL"),
        (0x80, "GET_TX_CNT"),
        (0x81, "GET_RX_CNT"),
        (0x82, "GET_RX_OK_CNT"),
        (0x83, "GET_RX_STATS"),
    ];

    eprintln!("  {:>6}  {:30}  {:>12}  {:>12}", "FuncID", "Name", "param0", "param1");
    eprintln!("  {:>6}  {:30}  {:>12}  {:>12}", "------", "-----", "------", "------");

    for (func_id, name) in &known_funcs {
        match adapter.testmode_query_at(*func_id) {
            Ok((p0, p1)) => {
                eprintln!("  0x{:04X}  {:30}  0x{:08X}  0x{:08X}", func_id, name, p0, p1);
            }
            Err(e) => {
                eprintln!("  0x{:04X}  {:30}  ERROR: {}", func_id, name, e);
            }
        }
    }
}

/// Test: Enter RF test mode and read RX statistics.
fn test_rftest_mode(adapter: &mut wifikit::chips::mt7921au::Mt7921au, duration_secs: u64) {
    eprintln!("═══ RF TEST MODE ═══");
    eprintln!("[*] Entering RF test mode...");

    if let Err(e) = adapter.enter_rftest_mode() {
        eprintln!("ERROR: Failed to enter RF test mode: {}", e);
        return;
    }
    eprintln!("[+] RF test mode active!");

    // Enable RX
    eprintln!("[*] Enabling RX in test mode...");
    if let Err(e) = adapter.testmode_set_trx(2, true) {
        eprintln!("WARN: Failed to enable RX: {}", e);
    }

    eprintln!("[*] Reading RX stats for {}s...", duration_secs);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(duration_secs) {
        // Try to read RX frames in test mode
        match adapter.rx_frame(Duration::from_millis(100)) {
            Ok(Some(frame)) => {
                eprintln!("  RX: {} bytes, RSSI={} dBm, ch={}",
                    frame.data.len(), frame.rssi, frame.channel);
            }
            Ok(None) => {} // timeout, normal
            Err(e) => {
                eprintln!("  RX error: {}", e);
                break;
            }
        }
    }

    // Disable RX
    let _ = adapter.testmode_set_trx(2, false);
}

/// Test: Enter WiFi Spectrum mode and capture spectral data.
fn test_spectrum_mode(adapter: &mut wifikit::chips::mt7921au::Mt7921au, duration_secs: u64) {
    eprintln!("═══ WIFI SPECTRUM MODE ═══");
    eprintln!("[*] Entering WiFi Spectrum mode...");
    eprintln!("[!] This is EXPERIMENTAL — observing what the firmware sends back.");
    eprintln!();

    if let Err(e) = adapter.enter_spectrum_mode() {
        eprintln!("ERROR: Failed to enter spectrum mode: {}", e);
        return;
    }
    eprintln!("[+] WiFi Spectrum mode active!");

    eprintln!("[*] Capturing for {}s — watching USB endpoint for spectral data...", duration_secs);
    let start = Instant::now();
    let mut total_bytes = 0u64;
    let mut total_packets = 0u32;

    while start.elapsed() < Duration::from_secs(duration_secs) {
        match adapter.rx_frame(Duration::from_millis(200)) {
            Ok(Some(frame)) => {
                total_packets += 1;
                total_bytes += frame.data.len() as u64;
                // Dump first few packets in hex for analysis
                if total_packets <= 10 {
                    let hex: String = frame.data.iter().take(64)
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("  PKT#{:3}: {} bytes RSSI={:4} | {}{}",
                        total_packets, frame.data.len(), frame.rssi,
                        hex,
                        if frame.data.len() > 64 { "..." } else { "" }
                    );
                } else if total_packets % 100 == 0 {
                    eprintln!("  ... {} packets, {} bytes total ({:.1}s)",
                        total_packets, total_bytes, start.elapsed().as_secs_f32());
                }
            }
            Ok(None) => {} // timeout
            Err(e) => {
                eprintln!("  RX error: {}", e);
                break;
            }
        }
    }

    eprintln!();
    eprintln!("[*] Spectrum capture complete:");
    eprintln!("    Packets: {}", total_packets);
    eprintln!("    Bytes:   {} ({:.1} KB)", total_bytes, total_bytes as f64 / 1024.0);
    eprintln!("    Rate:    {:.1} pkt/s", total_packets as f64 / duration_secs as f64);
}

/// Test: Enter I/Q capture mode (raw baseband samples).
fn test_icap_mode(adapter: &mut wifikit::chips::mt7921au::Mt7921au, duration_secs: u64) {
    eprintln!("═══ I/Q CAPTURE (ICAP) MODE ═══");
    eprintln!("[*] Entering ICAP mode...");
    eprintln!("[!] This captures raw baseband I/Q samples — SDR territory!");
    eprintln!();

    if let Err(e) = adapter.enter_icap_mode() {
        eprintln!("ERROR: Failed to enter ICAP mode: {}", e);
        return;
    }
    eprintln!("[+] ICAP mode active!");

    eprintln!("[*] Capturing I/Q data for {}s...", duration_secs);
    let start = Instant::now();
    let mut total_bytes = 0u64;
    let mut total_packets = 0u32;
    // Save raw data for analysis
    let mut raw_data: Vec<u8> = Vec::new();

    while start.elapsed() < Duration::from_secs(duration_secs) {
        match adapter.rx_frame(Duration::from_millis(200)) {
            Ok(Some(frame)) => {
                total_packets += 1;
                total_bytes += frame.data.len() as u64;
                if raw_data.len() < 1_000_000 { // cap at 1MB
                    raw_data.extend_from_slice(&frame.data);
                }
                if total_packets <= 5 {
                    let hex: String = frame.data.iter().take(64)
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("  IQ#{:3}: {} bytes | {}{}", total_packets, frame.data.len(), hex,
                        if frame.data.len() > 64 { "..." } else { "" });
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("  RX error: {}", e);
                break;
            }
        }
    }

    eprintln!();
    eprintln!("[*] ICAP capture complete:");
    eprintln!("    Packets:  {}", total_packets);
    eprintln!("    Raw data: {} bytes ({:.1} KB)", raw_data.len(), raw_data.len() as f64 / 1024.0);

    // Save raw I/Q data to file for analysis
    if !raw_data.is_empty() {
        let filename = format!("/tmp/mt7921_iq_capture_{}.bin", chrono_timestamp());
        match std::fs::write(&filename, &raw_data) {
            Ok(_) => eprintln!("    Saved:    {}", filename),
            Err(e) => eprintln!("    Save failed: {}", e),
        }
    }
}

/// Test: TX power control at various levels.
fn test_power_control(adapter: &mut wifikit::chips::mt7921au::Mt7921au) {
    eprintln!("═══ TX POWER CONTROL ═══");
    eprintln!("[*] Entering RF test mode...");

    if let Err(e) = adapter.enter_rftest_mode() {
        eprintln!("ERROR: Failed to enter RF test mode: {}", e);
        return;
    }
    eprintln!("[+] RF test mode active!");
    eprintln!();

    // Test power levels from minimum to maximum
    // Values are in half-dBm units: 20 = 10dBm, 40 = 20dBm, etc.
    let power_levels = [
        (10, "5 dBm (low)"),
        (20, "10 dBm"),
        (30, "15 dBm"),
        (40, "20 dBm (max standard)"),
        (50, "25 dBm (regulatory max in most regions)"),
        (60, "30 dBm (1 Watt — if hardware allows)"),
    ];

    for (half_dbm, label) in &power_levels {
        eprintln!("  [*] Setting TX power to {} ({} half-dBm)...", label, half_dbm);
        match adapter.testmode_set_tx_power(*half_dbm) {
            Ok(()) => eprintln!("      OK"),
            Err(e) => eprintln!("      FAILED: {}", e),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Test: Sweep all channels reading signal levels.
fn test_channel_sweep(adapter: &mut wifikit::chips::mt7921au::Mt7921au) {
    eprintln!("═══ CHANNEL SWEEP ═══");
    eprintln!("[*] Sweeping all channels, counting frames per channel...");
    eprintln!();

    let channels = adapter.supported_channels().to_vec();
    let dwell_ms = 200; // 200ms per channel

    eprintln!("  {:>3}  {:>5}  {:>6}  {:>8}  {:>6}", "Ch", "Band", "Freq", "Frames", "Best");
    eprintln!("  {:>3}  {:>5}  {:>6}  {:>8}  {:>6}", "---", "----", "----", "------", "----");

    for ch in &channels {
        if let Err(_) = adapter.set_channel(*ch) { continue; }

        let mut frames = 0u32;
        let mut best_rssi: i8 = -120;
        let start = Instant::now();

        while start.elapsed() < Duration::from_millis(dwell_ms) {
            match adapter.rx_frame(Duration::from_millis(50)) {
                Ok(Some(frame)) => {
                    frames += 1;
                    if frame.rssi > best_rssi {
                        best_rssi = frame.rssi;
                    }
                }
                _ => {}
            }
        }

        let rssi_str = if best_rssi > -120 {
            format!("{:>4}", best_rssi)
        } else {
            "  --".to_string()
        };

        let band_str = match ch.band {
            Band::Band2g => "2.4G",
            Band::Band5g => " 5G ",
            Band::Band6g => " 6G ",
        };

        eprintln!("  {:>3}  {:>5}  {:>5}M  {:>8}  {:>6}",
            ch.number, band_str, ch.center_freq_mhz, frames, rssi_str);
    }
}

/// Test: LIVE braille spectrum display!
/// Continuously sweeps channels, collecting RSSI + busy_us, and renders
/// a real-time braille spectrum analyzer in the terminal.
fn test_visual_spectrum(adapter: &mut wifikit::chips::mt7921au::Mt7921au, duration_secs: u64) {
    use wifikit::core::chip::ChipDriver;
    use wifikit::cli::views::spectrum::{SpectrumData, render_spectrum, render_spectrum_mini};

    eprintln!("═══ LIVE SPECTRUM ANALYZER ═══");
    eprintln!("[*] Enabling MIB counters...");
    let _ = adapter.survey_enable(0);

    // Build channel list — skip 6GHz for speed (mostly empty)
    let all_channels = adapter.supported_channels().to_vec();
    let channels: Vec<_> = all_channels.iter()
        .filter(|ch| ch.band != wifikit::core::Band::Band6g)
        .cloned()
        .collect();

    eprintln!("[+] Scanning {} channels (2.4G + 5G)", channels.len());
    eprintln!("[*] Running for {}s — Ctrl+C to stop", duration_secs);
    eprintln!();

    let mut spectrum = SpectrumData::new(&channels);
    let dwell_ms: u64 = 100; // faster dwell for more responsive display

    // Get terminal size
    let (term_width, term_height) = crossterm::terminal::size().unwrap_or((80, 24));

    let start = Instant::now();
    let mut round = 0u32;

    while start.elapsed() < Duration::from_secs(duration_secs) {
        round += 1;

        // Sweep all channels
        for ch in &channels {
            if start.elapsed() >= Duration::from_secs(duration_secs) { break; }

            if adapter.set_channel(*ch).is_err() { continue; }
            let _ = adapter.survey_enable(0);
            let _ = adapter.survey_reset(0);

            // Dwell and collect frames
            let dwell_start = Instant::now();
            while dwell_start.elapsed() < Duration::from_millis(dwell_ms) {
                match adapter.rx_frame(Duration::from_millis(20)) {
                    Ok(Some(frame)) => {
                        spectrum.update_rssi(ch.number, frame.rssi as i16);
                    }
                    _ => {}
                }
            }

            // Read MIB busy time
            if let Ok(survey) = adapter.survey_read(0) {
                // Use busy_us as a proxy for channel energy
                // Scale: 200000us dwell = 100%, so busy_us / 2000 = percentage
                if survey.busy_us > 0 {
                    // Convert busy_us to a pseudo-RSSI for display
                    // More busy = stronger signal presence
                    let busy_pct = (survey.busy_us as f32 / (dwell_ms as f32 * 1000.0) * 100.0).min(100.0);
                    // Map 0-100% utilization to -100 to -20 dBm range for display
                    let pseudo_rssi = -100.0 + (busy_pct * 0.8); // 0% → -100, 100% → -20
                    // Only use busy_us if we didn't get frame RSSI (frame RSSI is more accurate)
                    if spectrum.measurements.iter().find(|m| m.channel.number == ch.number)
                        .map_or(true, |m| m.frame_count == 0)
                    {
                        spectrum.update_rssi(ch.number, pseudo_rssi as i16);
                    }
                }
            }
        }

        // Clear screen and render spectrum
        eprint!("\x1B[2J\x1B[H"); // ANSI clear screen + home
        eprintln!(" Round {} | {:.0}s elapsed | {} channels", round, start.elapsed().as_secs_f32(), channels.len());
        eprintln!();

        let lines = render_spectrum(&spectrum, term_width, term_height.saturating_sub(4));
        for line in &lines {
            eprintln!("{}", line);
        }

        // Mini bar at the bottom
        eprintln!();
        eprint!(" Mini: ");
        eprintln!("{}", render_spectrum_mini(&spectrum, (term_width as usize).saturating_sub(8)));
    }

    eprintln!();
    eprintln!("[+] Spectrum capture complete. {} rounds.", round);
}

/// Test: Sweep all channels reading MIB survey registers.
/// This gives per-channel busy/tx/rx time in microseconds — real channel utilization!
fn test_channel_survey(adapter: &mut wifikit::chips::mt7921au::Mt7921au) {
    use wifikit::core::chip::ChipDriver;

    eprintln!("═══ CHANNEL SURVEY (MIB REGISTERS) ═══");

    // Enable survey counters
    eprintln!("[*] Enabling MIB duration counters...");
    match adapter.survey_enable(0) {
        Ok(()) => eprintln!("[+] MIB counters enabled for band 0"),
        Err(e) => eprintln!("[!] Band 0 enable: {}", e),
    }

    let channels = adapter.supported_channels().to_vec();
    let dwell_ms: u64 = 200;

    eprintln!("[*] Surveying {} channels ({}ms dwell each)...", channels.len(), dwell_ms);
    eprintln!();
    eprintln!("  {:>3}  {:>5}  {:>5}M  {:>8}  {:>8}  {:>8}  {:>8}  {:>5}%  {:>4}",
        "Ch", "Band", "Freq", "Busy", "TX", "RX", "OBSS", "Util", "RSSI");
    eprintln!("  {:>3}  {:>5}  {:>5}-  {:>8}  {:>8}  {:>8}  {:>8}  {:>5}-  {:>4}",
        "---", "----", "----", "------", "------", "------", "------", "----", "----");

    for ch in &channels {
        let band_idx: u8 = match ch.band {
            wifikit::core::Band::Band2g => 0,
            wifikit::core::Band::Band5g => 0,  // MT7921 single DBDC, band 0 for all
            wifikit::core::Band::Band6g => 0,
        };

        // Switch channel
        if adapter.set_channel(*ch).is_err() { continue; }

        // Enable + reset survey counters AFTER channel switch
        // Linux does this in mac_init_band — MIB counters may reset on channel change
        let _ = adapter.survey_enable(band_idx);
        let _ = adapter.survey_reset(band_idx);

        // Dwell — let the radio accumulate measurements
        let start = Instant::now();
        let mut best_rssi: i8 = -120;
        let mut frames = 0u32;

        while start.elapsed() < Duration::from_millis(dwell_ms) {
            match adapter.rx_frame(Duration::from_millis(50)) {
                Ok(Some(frame)) => {
                    frames += 1;
                    if frame.rssi > best_rssi { best_rssi = frame.rssi; }
                }
                _ => {}
            }
        }

        // Read survey data
        let survey = adapter.survey_read(band_idx).unwrap_or_default();
        let dwell_us = (dwell_ms * 1000) as u32;
        let util = survey.utilization_pct(dwell_us);

        let band_str = match ch.band {
            wifikit::core::Band::Band2g => "2.4G",
            wifikit::core::Band::Band5g => " 5G ",
            wifikit::core::Band::Band6g => " 6G ",
        };

        let rssi_str = if best_rssi > -120 { format!("{:>4}", best_rssi) } else { "  --".to_string() };

        eprintln!("  {:>3}  {:>5}  {:>4}M  {:>7}u  {:>7}u  {:>7}u  {:>7}u  {:>4.1}%  {:>4}",
            ch.number, band_str, ch.center_freq_mhz,
            survey.busy_us, survey.tx_us, survey.rx_us, survey.obss_us,
            util, rssi_str);

        // Skip remaining 6GHz if empty
        if ch.band == wifikit::core::Band::Band6g && frames == 0 && ch.number > 5 {
            eprintln!("  ... (skipping remaining empty 6GHz channels)");
            break;
        }
    }
}

/// Open the first MT7921AU adapter found.
fn open_mt7921() -> Option<wifikit::chips::mt7921au::Mt7921au> {
    let devices = [
        (0x0E8D, 0x7961, "Fenvi MT7921AU"),
        (0x3574, 0x6211, "COMFAST CF-952AX"),
        (0x0846, 0x9060, "Netgear A8000"),
        (0x0846, 0x9065, "Netgear A7500"),
        (0x35BC, 0x0107, "TP-Link TXE50UH"),
    ];
    for (vid, pid, name) in &devices {
        match wifikit::chips::mt7921au::Mt7921au::open_usb(*vid, *pid) {
            Ok((d, _ep)) => {
                eprintln!("[+] Found: {} ({:04X}:{:04X})", name, vid, pid);
                return Some(d);
            }
            Err(_) => continue,
        }
    }
    None
}

fn chrono_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}
