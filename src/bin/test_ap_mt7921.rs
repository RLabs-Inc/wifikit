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
use wifikit::core::{Channel, TxOptions, TxFlags};
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
    driver.set_channel(ch).expect("channel failed");
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

                    match subtype {
                        4 => { // Probe Request
                            probe_reqs += 1;
                            if to_us || (frame.data.len() >= 10 && frame.data[4..10] == [0xFF; 6]) {
                                // Parse SSID from probe
                                let ssid_str = if frame.data.len() > 26 {
                                    parse_ssid(&frame.data[24..])
                                } else {
                                    "<empty>".to_string()
                                };
                                let sa = &frame.data[10..16];
                                eprintln!("  ← Probe Request from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} SSID=\"{}\" rssi={}",
                                    sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], ssid_str, frame.rssi);
                            }
                        }
                        11 if to_us => { // Authentication
                            auth_reqs += 1;
                            let sa = &frame.data[10..16];
                            eprintln!("  ★ AUTH from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} rssi={}",
                                sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], frame.rssi);
                        }
                        0 if to_us => { // Association Request
                            assoc_reqs += 1;
                            let sa = &frame.data[10..16];
                            eprintln!("  ★★ ASSOC from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} rssi={}",
                                sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], frame.rssi);
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
