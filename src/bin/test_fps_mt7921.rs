// MT7921AU FPS Benchmark — measure frames/sec per band
//
// Parks on a channel for N seconds, counts ALL frames, reports FPS.
// Run on 2.4GHz and 5GHz channels to compare sensitivity.
//
// Usage:
//   cargo run --bin test_fps_mt7921                          # Default: ch6 10s
//   cargo run --bin test_fps_mt7921 -- -c 6 -d 10           # 2.4GHz ch6, 10s
//   cargo run --bin test_fps_mt7921 -- -c 36 -d 10          # 5GHz ch36, 10s
//   cargo run --bin test_fps_mt7921 -- --sweep               # All channels, 5s each

use std::time::{Duration, Instant};
use wifikit::core::chip::ChipDriver;
use wifikit::core::{Channel, Band};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut channel: u8 = 6;
    let mut duration_secs: u64 = 10;
    let mut sweep = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" | "-c" => {
                i += 1;
                if i < args.len() { channel = args[i].parse().unwrap_or(6); }
            }
            "--duration" | "-d" => {
                i += 1;
                if i < args.len() { duration_secs = args[i].parse().unwrap_or(10); }
            }
            "--sweep" | "-s" => { sweep = true; }
            _ => {}
        }
        i += 1;
    }

    eprintln!("======================================");
    eprintln!("  MT7921AU FPS Benchmark");
    eprintln!("======================================\n");

    // Open device
    let devices = [
        (0x0E8D, 0x7961, "Fenvi MT7921AU"),
        (0x3574, 0x6211, "COMFAST CF-952AX"),
    ];
    let mut driver = None;
    for (vid, pid, name) in &devices {
        match wifikit::chips::mt7921au::Mt7921au::open_usb(*vid, *pid) {
            Ok((d, _ep)) => {
                eprintln!("  Device: {} ({:04X}:{:04X})", name, vid, pid);
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

    let info = driver.chip_info();
    eprintln!("  Chip: {} (FW: {})", info.name, info.firmware_version);

    eprint!("  Monitor mode... ");
    driver.set_monitor_mode().expect("monitor failed");
    eprintln!("OK\n");

    if sweep {
        // Sweep all channels
        let channels_2g: Vec<u8> = (1..=13).collect();
        let channels_5g: Vec<u8> = vec![36, 40, 44, 48, 52, 56, 60, 64,
                                         100, 104, 108, 112, 116, 120, 124, 128,
                                         132, 136, 140, 149, 153, 157, 161, 165];

        eprintln!("--- 2.4 GHz ({}s per channel) ---", duration_secs);
        for &ch in &channels_2g {
            let fps = measure_fps(&mut driver, ch, Band::Band2g, duration_secs);
            eprintln!("  ch{:>3}: {:>6.0} fps", ch, fps);
        }

        eprintln!("\n--- 5 GHz ({}s per channel) ---", duration_secs);
        for &ch in &channels_5g {
            let fps = measure_fps(&mut driver, ch, Band::Band5g, duration_secs);
            eprintln!("  ch{:>3}: {:>6.0} fps", ch, fps);
        }
    } else {
        // Single channel
        let band = if channel >= 36 { Band::Band5g } else { Band::Band2g };
        eprintln!("  Measuring ch{} ({:?}) for {}s...\n", channel, band, duration_secs);
        let fps = measure_fps(&mut driver, channel, band, duration_secs);
        eprintln!("\n  Result: {:.0} fps on ch{}", fps, channel);
    }

    eprintln!("\nDone.");
}

fn measure_fps(driver: &mut wifikit::chips::mt7921au::Mt7921au, ch: u8, band: Band, secs: u64) -> f64 {
    let channel = match band {
        Band::Band2g => Channel::new(ch),
        Band::Band5g => Channel::new(ch),
        Band::Band6g => Channel::new_6ghz(ch),
    };
    if let Err(e) = driver.set_channel(channel) {
        eprintln!("    ch{} switch failed: {}", ch, e);
        return 0.0;
    }

    // Small settle time after channel switch
    std::thread::sleep(Duration::from_millis(50));

    let start = Instant::now();
    let timeout = Duration::from_secs(secs);
    let mut total = 0u64;
    let mut mgmt = 0u64;
    let mut data = 0u64;
    let mut ctrl = 0u64;

    while start.elapsed() < timeout {
        match driver.rx_frame(Duration::from_millis(100)) {
            Ok(Some(frame)) => {
                total += 1;
                if frame.data.len() >= 2 {
                    let fc = frame.data[0];
                    let frame_type = (fc >> 2) & 0x3;
                    match frame_type {
                        0 => mgmt += 1,
                        1 => ctrl += 1,
                        2 => data += 1,
                        _ => {}
                    }
                }
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let fps = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

    if fps > 0.0 {
        eprint!("  (mgmt:{} data:{} ctrl:{}) ", mgmt, data, ctrl);
    }
    fps
}
