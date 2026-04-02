// MT7921AU Rogue AP Test
//
// Creates a rogue access point and monitors for client probe requests
// and association attempts. Firmware handles beacon TX automatically.
//
// Usage:
//   cargo run --bin test_ap_mt7921
//   cargo run --bin test_ap_mt7921 -- --ssid "Free WiFi" --channel 6
//   cargo run --bin test_ap_mt7921 -- --ssid "EvilTwin" --channel 36 --duration 30

use std::time::{Duration, Instant};
use wifikit::core::chip::ChipDriver;
use wifikit::core::{Channel, MacAddress, TxOptions, TxFlags};
use wifikit::core::frame::TxRate;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut ssid = "wifikit-test".to_string();
    let mut channel: u8 = 6;
    let mut duration_secs: u64 = 30;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ssid" | "-s" => {
                i += 1;
                if i < args.len() { ssid = args[i].clone(); }
            }
            "--channel" | "-c" => {
                i += 1;
                if i < args.len() { channel = args[i].parse().unwrap_or(6); }
            }
            "--duration" | "-t" => {
                i += 1;
                if i < args.len() { duration_secs = args[i].parse().unwrap_or(30); }
            }
            "--help" | "-h" => {
                eprintln!("MT7921AU Rogue AP Test");
                eprintln!();
                eprintln!("Usage:");
                eprintln!("  test_ap_mt7921                              Open AP 'wifikit-test' on ch6");
                eprintln!("  test_ap_mt7921 --ssid 'Free WiFi' -c 36    Custom SSID on ch36");
                eprintln!("  test_ap_mt7921 --duration 60                Run for 60 seconds");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    eprintln!("╔══════════════════════════════════════════╗");
    eprintln!("║  MT7921AU Rogue AP Test                  ║");
    eprintln!("╚══════════════════════════════════════════╝\n");

    // Open device
    let devices = [(0x0E8D, 0x7961, "Fenvi MT7921AU"), (0x3574, 0x6211, "COMFAST CF-952AX")];
    let mut driver = None;
    for (vid, pid, name) in &devices {
        match wifikit::chips::mt7921au::Mt7921au::open_usb(*vid, *pid) {
            Ok((d, _)) => {
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

    // Monitor mode first (sets up RX path)
    eprint!("  Monitor mode... ");
    driver.set_monitor_mode().expect("monitor failed");
    eprintln!("OK");

    // Set channel
    let ch = Channel::new(channel);
    eprint!("  Channel {}... ", channel);
    match driver.set_channel(ch) {
        Ok(()) => eprintln!("OK"),
        Err(e) => {
            eprintln!("FAILED: {} — try replugging the adapter", e);
            std::process::exit(1);
        }
    }
    eprintln!("OK");

    // Generate a BSSID from our MAC (or use a random one)
    let bssid = driver.mac().0;

    // Start AP
    eprintln!("\n── Starting Rogue AP ──");
    eprintln!("  SSID:     \"{}\"", ssid);
    eprintln!("  BSSID:    {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    eprintln!("  Channel:  {}", channel);
    eprintln!("  Beacon:   100 TU (102.4ms)");
    eprintln!("  Security: Open (no encryption)");

    eprint!("  Starting... ");
    match driver.start_ap(&ssid, &bssid, 100) {
        Ok(()) => eprintln!("OK — AP is beaconing!"),
        Err(e) => {
            eprintln!("FAILED: {}", e);
            std::process::exit(1);
        }
    }

    // Build beacon for software TX loop
    let beacon_frame = wifikit::chips::mt7921au::build_beacon_frame_pub(&ssid, &bssid, channel, 100);
    let beacon_opts = TxOptions {
        rate: TxRate::Ofdm6m,
        flags: TxFlags::NO_ACK,
        retries: 0,
        ..Default::default()
    };

    // Monitor for client activity + inject software beacons
    eprintln!("\n── Monitoring for {}s (beaconing every 102ms) ──", duration_secs);
    eprintln!("  (Look for our AP on your phone's WiFi list!)\n");

    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_secs);
    let mut probe_reqs = 0u64;
    let mut auth_reqs = 0u64;
    let mut assoc_reqs = 0u64;
    let mut total_frames = 0u64;
    let mut beacons_sent = 0u64;
    let mut last_report = start;
    let mut last_beacon = start;
    let beacon_interval = Duration::from_millis(102); // ~100 TU

    while Instant::now() < deadline {
        // Inject beacon if interval has elapsed
        let now = Instant::now();
        if now.duration_since(last_beacon) >= beacon_interval {
            let _ = driver.tx_frame(&beacon_frame, &beacon_opts);
            beacons_sent += 1;
            last_beacon = now;
        }

        match driver.rx_frame(Duration::from_millis(5)) {
            Ok(Some(frame)) => {
                total_frames += 1;
                if frame.data.len() < 24 { continue; }

                let fc0 = frame.data[0];
                let frame_type = (fc0 >> 2) & 0x3;
                let subtype = (fc0 >> 4) & 0xF;

                // Only interested in management frames addressed to our BSSID
                if frame_type == 0 {
                    // Check if addressed to us (addr1 or addr3 = our BSSID)
                    let to_us = (frame.data.len() >= 10 && frame.data[4..10] == bssid)
                        || (frame.data.len() >= 22 && frame.data[16..22] == bssid);

                    let ack_opts = TxOptions {
                        rate: TxRate::Ofdm6m,
                        flags: TxFlags::WANT_ACK,
                        retries: 3,
                        ..Default::default()
                    };

                    match subtype {
                        4 => { // Probe Request
                            probe_reqs += 1;
                            let is_broadcast = frame.data.len() >= 10 && frame.data[4..10] == [0xFF; 6];
                            if to_us || is_broadcast {
                                let ssid_str = if frame.data.len() > 26 {
                                    parse_ssid(&frame.data[24..])
                                } else {
                                    "<empty>".to_string()
                                };
                                let mut sa = [0u8; 6];
                                sa.copy_from_slice(&frame.data[10..16]);
                                eprintln!("  ← Probe Req from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} SSID=\"{}\" rssi={}",
                                    sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], ssid_str, frame.rssi);

                                // Reply with probe response if directed to us or broadcast
                                if ssid_str == ssid || ssid_str == "<broadcast>" {
                                    let resp = build_probe_response(&bssid, &sa, &ssid, channel, 100);
                                    let _ = driver.tx_frame(&resp, &ack_opts);
                                    eprintln!("    → Probe Response sent!");
                                }
                            }
                        }
                        11 if to_us => { // Authentication
                            auth_reqs += 1;
                            let mut sa = [0u8; 6];
                            sa.copy_from_slice(&frame.data[10..16]);
                            eprintln!("  ★ AUTH from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} rssi={}",
                                sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], frame.rssi);

                            // Send AUTH response (Open System: algo=0, seq=2, status=0)
                            let resp = build_auth_response(&bssid, &sa);
                            let _ = driver.tx_frame(&resp, &ack_opts);
                            eprintln!("    → AUTH Response sent (Open System, status=SUCCESS)");
                        }
                        0 if to_us => { // Association Request
                            assoc_reqs += 1;
                            let mut sa = [0u8; 6];
                            sa.copy_from_slice(&frame.data[10..16]);
                            eprintln!("  ★★ ASSOC REQ from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} rssi={}",
                                sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], frame.rssi);

                            // Send ASSOC response (status=0, AID=1)
                            let resp = build_assoc_response(&bssid, &sa, channel);
                            let _ = driver.tx_frame(&resp, &ack_opts);
                            eprintln!("    → ASSOC Response sent (AID=1, status=SUCCESS)");
                            eprintln!("    ★★★ CLIENT CONNECTED! ★★★");
                        }
                        _ => {}
                    }
                }

                // Live stats
                let now = Instant::now();
                if now.duration_since(last_report) >= Duration::from_secs(5) {
                    eprint!("\r  [{:.0}s] {} bcns TX | {} frames RX | {} probes | {} auths",
                        now.duration_since(start).as_secs_f64(),
                        beacons_sent, total_frames, probe_reqs, auth_reqs);
                    last_report = now;
                }
            }
            _ => {}
        }
    }

    eprintln!("\n\n╔══ Rogue AP Results ══");
    eprintln!("║ Total frames:     {}", total_frames);
    eprintln!("║ Probe requests:   {}", probe_reqs);
    eprintln!("║ Auth requests:    {}", auth_reqs);
    eprintln!("║ Assoc requests:   {}", assoc_reqs);
    eprintln!("╚══════════════════════════════════════");

    // Cleanup
    let _ = driver.stop_ap();
}

fn parse_ssid(tagged_params: &[u8]) -> String {
    let mut i = 0;
    while i + 1 < tagged_params.len() {
        let tag = tagged_params[i];
        let len = tagged_params[i + 1] as usize;
        if i + 2 + len > tagged_params.len() { break; }
        if tag == 0 {
            if len == 0 { return "<broadcast>".to_string(); }
            return String::from_utf8_lossy(&tagged_params[i+2..i+2+len]).to_string();
        }
        i += 2 + len;
    }
    "<none>".to_string()
}

/// Build an 802.11 Authentication Response (Open System, seq=2, status=success)
fn build_auth_response(bssid: &[u8; 6], client: &[u8; 6]) -> Vec<u8> {
    let mut f = Vec::with_capacity(30);
    // FC: type=0(mgmt), subtype=11(auth)
    f.push(0xB0); f.push(0x00);
    // Duration
    f.push(0x00); f.push(0x00);
    // addr1 (DA) = client
    f.extend_from_slice(client);
    // addr2 (SA) = our BSSID
    f.extend_from_slice(bssid);
    // addr3 (BSSID) = our BSSID
    f.extend_from_slice(bssid);
    // Seq ctrl
    f.push(0x00); f.push(0x00);
    // Auth fixed params:
    // Auth algo = 0 (Open System)
    f.push(0x00); f.push(0x00);
    // Auth seq = 2 (response)
    f.push(0x02); f.push(0x00);
    // Status = 0 (success)
    f.push(0x00); f.push(0x00);
    f
}

/// Build an 802.11 Probe Response
fn build_probe_response(bssid: &[u8; 6], client: &[u8; 6], ssid: &str, channel: u8, beacon_interval: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(256);
    // FC: type=0(mgmt), subtype=5(probe response)
    f.push(0x50); f.push(0x00);
    // Duration
    f.push(0x00); f.push(0x00);
    // addr1 (DA) = requesting client
    f.extend_from_slice(client);
    // addr2 (SA) = our BSSID
    f.extend_from_slice(bssid);
    // addr3 (BSSID) = our BSSID
    f.extend_from_slice(bssid);
    // Seq ctrl
    f.push(0x00); f.push(0x00);

    // Fixed params (same as beacon)
    // Timestamp (8 bytes)
    f.extend_from_slice(&[0u8; 8]);
    // Beacon interval
    f.extend_from_slice(&beacon_interval.to_le_bytes());
    // Capability: ESS + short preamble
    f.extend_from_slice(&[0x21, 0x00]);

    // Tagged parameters
    // SSID
    f.push(0x00);
    f.push(ssid.len().min(32) as u8);
    f.extend_from_slice(&ssid.as_bytes()[..ssid.len().min(32)]);

    // Supported Rates
    let rates: &[u8] = if channel > 14 {
        &[0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C]
    } else {
        &[0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]
    };
    f.push(0x01);
    f.push(rates.len() as u8);
    f.extend_from_slice(rates);

    // DS Parameter
    f.push(0x03); f.push(0x01); f.push(channel);

    f
}

/// Build an 802.11 Association Response (status=success, AID=1)
fn build_assoc_response(bssid: &[u8; 6], client: &[u8; 6], channel: u8) -> Vec<u8> {
    let mut f = Vec::with_capacity(128);
    // FC: type=0(mgmt), subtype=1(assoc response)
    f.push(0x10); f.push(0x00);
    // Duration
    f.push(0x00); f.push(0x00);
    // addr1 (DA) = client
    f.extend_from_slice(client);
    // addr2 (SA) = our BSSID
    f.extend_from_slice(bssid);
    // addr3 (BSSID) = our BSSID
    f.extend_from_slice(bssid);
    // Seq ctrl
    f.push(0x00); f.push(0x00);

    // Fixed params:
    // Capability: ESS + short preamble
    f.extend_from_slice(&[0x21, 0x00]);
    // Status = 0 (success)
    f.push(0x00); f.push(0x00);
    // AID = 1 (bit 14-15 must be set per spec: 0xC001)
    f.push(0x01); f.push(0xC0);

    // Supported Rates
    let rates: &[u8] = if channel > 14 {
        &[0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C]
    } else {
        &[0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]
    };
    f.push(0x01);
    f.push(rates.len() as u8);
    f.extend_from_slice(rates);

    f
}
