// Standalone RTL8852AU TX verification — sends probes, shows actual responses
// Writes full diagnostic dump to /tmp/wifikit_tx_diag.log
use std::time::{Duration, Instant};
use wifikit::core::chip::ChipDriver;
use wifikit::core::frame::{TxOptions, TxRate, TxFlags};

fn main() {
    eprintln!("=== RTL8852AU TX Verification ===\n");

    // Clear previous diagnostic log
    let _ = std::fs::remove_file("/tmp/wifikit_tx_diag.log");

    let (mut driver, _endpoints) = match wifikit::chips::rtl8852au::Rtl8852au::open_usb(0x2357, 0x013F) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open: {}", e);
            std::process::exit(1);
        }
    };

    match driver.init() {
        Ok(()) => eprintln!("INIT OK"),
        Err(e) => { eprintln!("INIT FAILED: {}", e); std::process::exit(1); }
    }

    let mac = driver.mac();
    eprintln!("MAC: {}\n", mac);

    // ── Diagnostic dump BEFORE channel switch ──
    eprintln!("Dumping TX diagnostics (before channel switch)...");
    if let Err(e) = driver.dump_tx_diagnostics() {
        eprintln!("  diag error: {}", e);
    }

    let test_ch = 149u8;
    eprintln!("--- Channel {} ---", test_ch);
    driver.set_channel(wifikit::core::Channel::new(test_ch)).unwrap();
    std::thread::sleep(Duration::from_millis(100));

    // ── Diagnostic dump AFTER channel switch, BEFORE first TX ──
    eprintln!("Dumping TX diagnostics (after channel switch, before TX)...");
    if let Err(e) = driver.dump_tx_diagnostics() {
        eprintln!("  diag error: {}", e);
    }

    let tx_mac = mac.0;
    eprintln!("TX MAC (= driver MAC = ADDR_CAM MAC): {}\n", mac);
    let probe = build_probe_request(&tx_mac);

    // ── Log the actual TX buffer that will be sent ──
    log_tx_buffer(&probe);

    let tx_opts = TxOptions {
        rate: TxRate::Ofdm6m,
        retries: 0,
        flags: TxFlags::NO_ACK | TxFlags::NO_RETRY,
        ..Default::default()
    };

    // ── Test 1: Send EXACT pcap TX frame (BULK_212) verbatim ──
    eprintln!("Sending 10 EXACT pcap probe requests (BULK_212 verbatim)...");
    for i in 0..10 {
        match driver.send_pcap_probe_verbatim() {
            Ok(()) => {
                if i == 0 { eprintln!("  pcap_verbatim #0: Ok"); }
            }
            Err(e) => eprintln!("  pcap_verbatim #{}: ERROR: {}", i, e),
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // ── Test 2: Send our probe with our WD ──
    eprintln!("Sending 10 our probe requests...");
    for i in 0..10 {
        match driver.tx_frame(&probe, &tx_opts) {
            Ok(()) => {
                if i == 0 { eprintln!("  tx_frame #0: Ok"); }
            }
            Err(e) => eprintln!("  tx_frame #{}: ERROR: {}", i, e),
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // ── Diagnostic dump AFTER first TX ──
    eprintln!("Dumping TX diagnostics (after TX)...");
    if let Err(e) = driver.dump_tx_diagnostics() {
        eprintln!("  diag error: {}", e);
    }

    // ── Listen and print ALL probe responses with their DA (destination) ──
    eprintln!("\nListening 5s for probe responses...");
    eprintln!("{:<18} {:<18} {:<18} {}", "DA (to)", "SA (from)", "BSSID", "SSID");
    eprintln!("{}", "-".repeat(75));

    let pcap_mac: [u8; 6] = [0x0A, 0xC4, 0x90, 0x27, 0x7C, 0xAB];
    let our_mac_bytes = tx_mac;
    let start = Instant::now();
    let mut total = 0u32;
    let mut probe_resp_total = 0u32;
    let mut probe_resp_to_us = 0u32;

    while start.elapsed() < Duration::from_secs(5) {
        match driver.rx_frame(Duration::from_millis(50)) {
            Ok(Some(frame)) => {
                total += 1;
                let d = &frame.data;
                if d.len() < 24 { continue; }

                let fc = d[0];
                let frame_type = (fc >> 2) & 0x3;
                let subtype = (fc >> 4) & 0xF;

                // Probe Response: type=0, subtype=5
                if frame_type == 0 && subtype == 5 {
                    probe_resp_total += 1;

                    let da = &d[4..10];
                    let sa = &d[10..16];
                    let bssid = &d[16..22];

                    let is_to_us = da == &our_mac_bytes || da == &pcap_mac;
                    let is_broadcast = da == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

                    // Extract SSID from tagged params (offset 36 in probe resp: 24 hdr + 12 fixed)
                    let ssid = if d.len() > 38 && d[36] == 0x00 {
                        let ssid_len = d[37] as usize;
                        if d.len() >= 38 + ssid_len {
                            String::from_utf8_lossy(&d[38..38+ssid_len]).to_string()
                        } else { String::new() }
                    } else { String::new() };

                    if is_to_us {
                        probe_resp_to_us += 1;
                        eprintln!(">>> {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {} <<<< TO US!",
                            da[0],da[1],da[2],da[3],da[4],da[5],
                            sa[0],sa[1],sa[2],sa[3],sa[4],sa[5],
                            bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
                            ssid);
                    } else if is_broadcast {
                        // skip broadcast probe responses (not from our probe)
                    } else {
                        // Unicast probe response to someone else — show first few
                        if probe_resp_total <= 5 {
                            eprintln!("    {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {} (to other)",
                                da[0],da[1],da[2],da[3],da[4],da[5],
                                sa[0],sa[1],sa[2],sa[3],sa[4],sa[5],
                                bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
                                ssid);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    eprintln!("\n--- Results ---");
    eprintln!("Total frames: {}", total);
    eprintln!("Probe responses: {} total, {} addressed to {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        probe_resp_total, probe_resp_to_us,
        tx_mac[0], tx_mac[1], tx_mac[2], tx_mac[3], tx_mac[4], tx_mac[5]);

    if probe_resp_to_us > 0 {
        eprintln!("\nTX WORKS — {} APs responded directly to us!", probe_resp_to_us);
    } else {
        eprintln!("\nTX NOT WORKING — no probe responses addressed to {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            tx_mac[0], tx_mac[1], tx_mac[2], tx_mac[3], tx_mac[4], tx_mac[5]);
        eprintln!("Frames go to USB but don't leave the radio.");
    }

    eprintln!("\nDiagnostics saved to /tmp/wifikit_tx_diag.log");
    let _ = driver.shutdown();
}

fn build_probe_request(mac: &[u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64);
    frame.extend_from_slice(&[0x40, 0x00]); // Probe Request
    frame.extend_from_slice(&[0x00, 0x00]); // Duration
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // DA: broadcast
    frame.extend_from_slice(mac); // SA: our MAC
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // BSSID: broadcast
    frame.extend_from_slice(&[0x00, 0x00]); // Seq ctrl
    frame.extend_from_slice(&[0x00, 0x00]); // SSID: wildcard
    frame.extend_from_slice(&[0x01, 0x08, 0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C]); // Rates
    frame
}

/// Log the raw 802.11 frame that inject_frame will wrap with WD
fn log_tx_buffer(frame: &[u8]) {
    use std::io::Write;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open("/tmp/wifikit_tx_diag.log") else { return };

    let _ = writeln!(f, "\n=== PROBE REQUEST FRAME ({} bytes) ===", frame.len());
    // Hex dump in 16-byte rows
    for (i, chunk) in frame.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
        let ascii: String = chunk.iter().map(|&b| {
            if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
        }).collect();
        let _ = writeln!(f, "  {:04X}: {:<48} {}", i * 16, hex.join(" "), ascii);
    }

    // Parse key fields
    if frame.len() >= 24 {
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        let _ = writeln!(f, "  FC=0x{:04X} type={} subtype={}", fc, (fc >> 2) & 3, (fc >> 4) & 0xF);
        let _ = writeln!(f, "  DA={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            frame[4], frame[5], frame[6], frame[7], frame[8], frame[9]);
        let _ = writeln!(f, "  SA={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]);
    }

    // Show expected WD DW0 for this frame (management, 24-byte header)
    let expected_dw0: u32 = (1u32 << 10)    // STF_MODE
        | (24u32 << 11)                      // HDR_LLC_LEN = 24
        | (8u32 << 16)                       // CH_DMA = B0MG
        | (1u32 << 22);                      // WDINFO_EN
    let _ = writeln!(f, "  Expected WD DW0 = 0x{:08X} (should be 0x0048C400)", expected_dw0);
    let _ = writeln!(f, "  Total USB payload = 48 (WD) + {} (frame) = {} bytes", frame.len(), 48 + frame.len());
    let _ = writeln!(f, "=== END FRAME DUMP ===\n");
}
