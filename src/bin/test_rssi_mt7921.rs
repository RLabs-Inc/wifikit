// MT7921AU RSSI Diagnostic — Park on channel, measure raw RCPI
//
// Parks on a single channel for N seconds and reports every RCPI value
// seen from a target BSSID. Eliminates hopping noise for clean comparison.
//
// Usage:
//   cargo run --bin test_rssi_mt7921
//   cargo run --bin test_rssi_mt7921 -- --channel 161   # 5GHz channel
//   cargo run --bin test_rssi_mt7921 -- --channel 3     # 2.4GHz channel
//   cargo run --bin test_rssi_mt7921 -- --duration 20   # 20 seconds

use std::time::{Duration, Instant};
use wifikit::core::chip::ChipDriver;
use wifikit::core::{Channel, Band};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut channel: u8 = 161;
    let mut duration_secs: u64 = 10;
    let mut target_bssid: Option<[u8; 6]> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" | "-c" => {
                i += 1;
                if i < args.len() { channel = args[i].parse().unwrap_or(161); }
            }
            "--duration" | "-d" => {
                i += 1;
                if i < args.len() { duration_secs = args[i].parse().unwrap_or(10); }
            }
            "--bssid" | "-b" => {
                i += 1;
                if i < args.len() {
                    let parts: Vec<u8> = args[i].split(':')
                        .filter_map(|s| u8::from_str_radix(s, 16).ok())
                        .collect();
                    if parts.len() == 6 {
                        target_bssid = Some([parts[0], parts[1], parts[2],
                                           parts[3], parts[4], parts[5]]);
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    let band = if channel >= 36 { Band::Band5g } else { Band::Band2g };

    eprintln!("╔═══════════════════════════════════════════╗");
    eprintln!("║  MT7921AU RSSI Diagnostic                 ║");
    eprintln!("╚═══════════════════════════════════════════╝\n");
    eprintln!("  Channel:  {} ({:?})", channel, band);
    eprintln!("  Duration: {}s", duration_secs);
    if let Some(b) = target_bssid {
        eprintln!("  Target:   {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            b[0], b[1], b[2], b[3], b[4], b[5]);
    } else {
        eprintln!("  Target:   ALL (no filter)");
    }
    eprintln!();

    // ── Open device ──
    let devices = [
        (0x0E8D, 0x7961, "Fenvi MT7921AU"),
        (0x3574, 0x6211, "COMFAST CF-952AX"),
    ];
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
        None => { eprintln!("ERROR: No MT7921AU found!"); std::process::exit(1); }
    };

    eprint!("  Init... ");
    driver.init().expect("init failed");
    eprintln!("OK");

    eprint!("  Monitor mode... ");
    driver.set_monitor_mode().expect("monitor failed");
    eprintln!("OK");

    eprint!("  Channel {}... ", channel);
    driver.set_channel(Channel::new(channel))
        .expect("channel failed");
    eprintln!("OK\n");

    // ── Collect frames ──
    let start = Instant::now();
    let timeout = Duration::from_secs(duration_secs);
    let mut total_frames = 0u64;
    let mut rssi_values: Vec<(i8, [u8; 6])> = Vec::new(); // (rssi, bssid)

    // Per-BSSID tracking
    let mut bssid_stats: std::collections::HashMap<[u8; 6], Vec<i8>> =
        std::collections::HashMap::new();

    eprintln!("  Collecting frames for {}s on ch{}...\n", duration_secs, channel);

    while start.elapsed() < timeout {
        match driver.rx_frame(Duration::from_millis(100)) {
            Ok(Some(frame)) => {
                total_frames += 1;

                // Extract BSSID from 802.11 header (offset 16 for management frames)
                if frame.data.len() >= 24 {
                    let fc = frame.data[0];
                    let frame_type = (fc >> 2) & 0x3;
                    let subtype = (fc >> 4) & 0xF;

                    // Only beacons (type=0, subtype=8) and probe responses (type=0, subtype=5)
                    if frame_type == 0 && (subtype == 8 || subtype == 5) {
                        let bssid = [frame.data[16], frame.data[17], frame.data[18],
                                    frame.data[19], frame.data[20], frame.data[21]];

                        if let Some(target) = target_bssid {
                            if bssid != target { continue; }
                        }

                        rssi_values.push((frame.rssi, bssid));
                        bssid_stats.entry(bssid).or_default().push(frame.rssi);
                    }
                }
            }
            Ok(None) | Err(_) => {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    // ── Report ──
    eprintln!("  ═══ Results ═══\n");
    eprintln!("  Total frames:  {}", total_frames);
    eprintln!("  Beacon/Probe:  {}", rssi_values.len());
    eprintln!();

    // Sort BSSIDs by best RSSI
    let mut sorted: Vec<([u8; 6], Vec<i8>)> = bssid_stats.into_iter().collect();
    sorted.sort_by(|a, b| {
        let max_a = a.1.iter().copied().max().unwrap_or(-128);
        let max_b = b.1.iter().copied().max().unwrap_or(-128);
        max_b.cmp(&max_a) // strongest first
    });

    eprintln!("  {:17}  {:>5}  {:>5}  {:>5}  {:>5}  {:>5}",
        "BSSID", "Count", "Best", "Avg", "Worst", "Stdev");
    eprintln!("  {}", "─".repeat(62));

    for (bssid, values) in sorted.iter().take(30) {
        let count = values.len();
        let best = values.iter().copied().max().unwrap_or(-128);
        let worst = values.iter().copied().min().unwrap_or(-128);
        let sum: i32 = values.iter().map(|&v| v as i32).sum();
        let avg = sum as f64 / count as f64;

        // Standard deviation
        let variance: f64 = values.iter()
            .map(|&v| { let d = v as f64 - avg; d * d })
            .sum::<f64>() / count as f64;
        let stdev = variance.sqrt();

        eprintln!("  {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}  {:>5}  {:>5}  {:>5.1}  {:>5}  {:>5.1}",
            bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
            count, best, avg, worst, stdev);
    }
    eprintln!();
}
