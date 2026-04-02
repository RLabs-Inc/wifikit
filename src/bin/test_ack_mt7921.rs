// MT7921AU Active Monitor ACK Test
//
// Tests whether the firmware ACKs incoming unicast frames in monitor mode.
//
// Method: Send a directed probe request to a visible AP, then count how many
// probe responses we receive. If we're ACKing, the AP sends 1 response.
// If not, the AP retransmits 3-7 times.
//
// Usage:
//   cargo run --bin test_ack_mt7921
//   cargo run --bin test_ack_mt7921 -- --channel 36
//   cargo run --bin test_ack_mt7921 -- --channel 6 --target AA:BB:CC:DD:EE:FF

use std::time::{Duration, Instant};
use std::collections::HashMap;
use wifikit::core::chip::ChipDriver;
use wifikit::core::{Channel, Band, MacAddress, TxOptions, TxFlags};
use wifikit::core::frame::TxRate;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut channel: u8 = 6;
    let mut target_mac: Option<[u8; 6]> = None;
    let mut spoof_mac: Option<[u8; 6]> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" | "-c" => {
                i += 1;
                if i < args.len() { channel = args[i].parse().unwrap_or(6); }
            }
            "--target" | "-t" => {
                i += 1;
                if i < args.len() { target_mac = parse_mac(&args[i]); }
            }
            "--spoof" | "-s" => {
                i += 1;
                if i < args.len() { spoof_mac = parse_mac(&args[i]); }
            }
            _ => {}
        }
        i += 1;
    }

    eprintln!("╔══════════════════════════════════════════╗");
    eprintln!("║  MT7921AU Active Monitor ACK Test        ║");
    eprintln!("╚══════════════════════════════════════════╝\n");

    // Open device
    let devices = [(0x0E8D, 0x7961, "Fenvi MT7921AU"), (0x3574, 0x6211, "COMFAST CF-952AX")];
    let mut driver = None;
    for (vid, pid, name) in &devices {
        match wifikit::chips::mt7921au::Mt7921au::open_usb(*vid, *pid) {
            Ok((d, _ep)) => {
                eprintln!("  Found: {} ({:04X}:{:04X})", name, vid, pid);
                driver = Some(d);
                break;
            }
            Err(_) => continue,
        }
    }
    let mut driver = match driver {
        Some(d) => d,
        None => { eprintln!("ERROR: No MT7921AU found"); std::process::exit(1); }
    };

    // Init
    eprint!("  Init... ");
    driver.init().expect("init failed");
    eprintln!("OK");

    let orig_mac = driver.mac().0;
    eprintln!("  Real MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        orig_mac[0], orig_mac[1], orig_mac[2], orig_mac[3], orig_mac[4], orig_mac[5]);

    // Monitor mode
    eprint!("  Monitor mode... ");
    driver.set_monitor_mode().expect("monitor failed");
    eprintln!("OK");

    // MAC spoofing (if requested)
    if let Some(new_mac) = spoof_mac {
        eprint!("  Spoofing MAC to {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}... ",
            new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5]);
        driver.set_mac(MacAddress(new_mac)).expect("MAC spoof failed");
        eprintln!("OK (POWERED_ADDR_CHANGE)");
    }

    let our_mac = driver.mac().0;

    // Set channel
    let ch = Channel::new(channel);
    eprint!("  Channel {}... ", channel);
    driver.set_channel(ch).expect("channel failed");
    eprintln!("OK");

    // Phase 1: If no target specified, scan for 3s to find an AP
    let target = if let Some(mac) = target_mac {
        mac
    } else {
        eprintln!("\n── Phase 1: Scanning for AP (3s) ──");
        let mut best_ap: Option<([u8; 6], i8, String)> = None;
        let scan_end = Instant::now() + Duration::from_secs(3);

        while Instant::now() < scan_end {
            match driver.rx_frame(Duration::from_millis(10)) {
                Ok(Some(frame)) => {
                    if frame.data.len() < 38 { continue; }
                    let fc0 = frame.data[0];
                    let frame_type = (fc0 >> 2) & 0x3;
                    let subtype = (fc0 >> 4) & 0xF;

                    // Beacon (type=0, subtype=8)
                    if frame_type == 0 && subtype == 8 {
                        let mut bssid = [0u8; 6];
                        bssid.copy_from_slice(&frame.data[16..22]);

                        // Skip broadcast/multicast BSSIDs
                        if bssid[0] & 1 != 0 { continue; }

                        // Parse SSID from tagged parameters (offset 36+)
                        let ssid = parse_ssid(&frame.data[36..]);

                        let rssi = frame.rssi;
                        if best_ap.is_none() || rssi > best_ap.as_ref().unwrap().1 {
                            best_ap = Some((bssid, rssi, ssid));
                        }
                    }
                }
                _ => {}
            }
        }

        match best_ap {
            Some((mac, rssi, ssid)) => {
                eprintln!("  Best AP: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} ({}) RSSI={}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ssid, rssi);
                mac
            }
            None => {
                eprintln!("  ERROR: No APs found on channel {}", channel);
                std::process::exit(1);
            }
        }
    };

    // Phase 2: Send directed probe request and count responses
    eprintln!("\n── Phase 2: ACK Test ──");
    eprintln!("  Target: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        target[0], target[1], target[2], target[3], target[4], target[5]);

    // Build directed probe request
    // FC=0x0040 (type=0 mgmt, subtype=4 probe_req)
    // addr1=target (DA), addr2=our_mac (SA), addr3=target (BSSID)
    let probe_req = build_probe_request(&our_mac, &target);

    eprintln!("  Sending directed probe request...");

    // Clear RX buffer first
    for _ in 0..50 {
        let _ = driver.rx_frame(Duration::from_millis(5));
    }

    // Send probe request (with WANT_ACK so WE get the AP's ACK for our TX)
    let tx_opts = TxOptions {
        rate: TxRate::Ofdm6m,
        flags: TxFlags::WANT_ACK,
        retries: 3,
        ..Default::default()
    };
    driver.tx_frame(&probe_req, &tx_opts).expect("TX failed");
    eprintln!("  Probe request sent!");

    // Listen for probe responses addressed to our MAC
    eprintln!("  Listening for probe responses (5s)...\n");

    let mut responses: Vec<(u16, i8)> = Vec::new(); // (seq_num, rssi)
    let mut seq_counts: HashMap<u16, u32> = HashMap::new();
    let listen_end = Instant::now() + Duration::from_secs(5);

    while Instant::now() < listen_end {
        match driver.rx_frame(Duration::from_millis(10)) {
            Ok(Some(frame)) => {
                if frame.data.len() < 24 { continue; }
                let fc0 = frame.data[0];
                let frame_type = (fc0 >> 2) & 0x3;
                let subtype = (fc0 >> 4) & 0xF;

                // Probe response (type=0, subtype=5)
                if frame_type == 0 && subtype == 5 {
                    // Check if addressed to us (addr1 = our MAC)
                    let da = &frame.data[4..10];
                    if da == &our_mac {
                        // Check if from target (addr2 = target BSSID)
                        let sa = &frame.data[10..16];
                        if sa == &target {
                            let seq_ctrl = u16::from_le_bytes([frame.data[22], frame.data[23]]);
                            let seq_num = seq_ctrl >> 4;
                            let retry = (frame.data[1] & 0x08) != 0;

                            responses.push((seq_num, frame.rssi));
                            *seq_counts.entry(seq_num).or_insert(0) += 1;

                            eprintln!("  ← Probe Response seq={} rssi={} retry={}",
                                seq_num, frame.rssi, retry);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Results
    eprintln!("\n╔══ ACK Test Results ══");
    eprintln!("║ Probe responses received: {}", responses.len());
    eprintln!("║ Unique sequence numbers:  {}", seq_counts.len());

    if responses.is_empty() {
        eprintln!("║");
        eprintln!("║ ⚠ No probe responses received!");
        eprintln!("║   - AP may not have received our probe request");
        eprintln!("║   - Try a closer AP or different channel");
    } else {
        let max_dups = seq_counts.values().max().unwrap_or(&0);
        eprintln!("║ Max duplicates per seq:   {}", max_dups);
        eprintln!("║");

        if *max_dups <= 1 {
            eprintln!("║ ✓ ACK IS WORKING!");
            eprintln!("║   AP sent each response once — we're ACKing them.");
        } else if *max_dups <= 2 {
            eprintln!("║ ~ LIKELY WORKING (minor retransmit may be RF)");
            eprintln!("║   1-2 copies is normal in noisy environments.");
        } else {
            eprintln!("║ ✗ ACK NOT WORKING");
            eprintln!("║   AP retransmitted {} times — we're not ACKing.", max_dups);
            eprintln!("║   Firmware doesn't auto-ACK in sniffer mode.");
        }

        // Show per-seq breakdown
        eprintln!("║");
        for (seq, count) in &seq_counts {
            eprintln!("║   seq={}: {} copies", seq, count);
        }
    }
    eprintln!("╚══════════════════════════════════════");
}

fn build_probe_request(our_mac: &[u8; 6], target: &[u8; 6]) -> Vec<u8> {
    let mut frame = vec![0u8; 28]; // FC(2) + dur(2) + addr1(6) + addr2(6) + addr3(6) + seq(2) + SSID IE(2) + rates IE(4)

    // Frame Control: type=0 (mgmt), subtype=4 (probe request)
    frame[0] = 0x40; // subtype=4 << 4 | type=0 << 2
    frame[1] = 0x00;

    // Duration
    frame[2] = 0x00;
    frame[3] = 0x00;

    // addr1 (DA) = target AP BSSID
    frame[4..10].copy_from_slice(target);
    // addr2 (SA) = our MAC
    frame[10..16].copy_from_slice(our_mac);
    // addr3 (BSSID) = target AP BSSID
    frame[16..22].copy_from_slice(target);

    // Sequence control (will be set by HW or us)
    frame[22] = 0x10; // seq=1
    frame[23] = 0x00;

    // Tagged parameters
    // SSID IE: tag=0, len=0 (wildcard — AP responds with its SSID)
    frame[24] = 0x00; // tag: SSID
    frame[25] = 0x00; // len: 0 (wildcard)

    // Supported Rates IE: tag=1, len=1, rate=12 (6 Mbps)
    frame[26] = 0x01; // tag: Supported Rates
    frame[27] = 0x01; // len: 1
    frame.push(0x0C); // 6 Mbps

    frame
}

fn parse_ssid(tagged_params: &[u8]) -> String {
    let mut i = 0;
    while i + 1 < tagged_params.len() {
        let tag = tagged_params[i];
        let len = tagged_params[i + 1] as usize;
        if i + 2 + len > tagged_params.len() { break; }
        if tag == 0 && len > 0 {
            return String::from_utf8_lossy(&tagged_params[i+2..i+2+len]).to_string();
        }
        i += 2 + len;
    }
    "<hidden>".to_string()
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 { return None; }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}
