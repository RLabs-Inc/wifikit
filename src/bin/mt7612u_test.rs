// Quick test: open MT7612U and run through init + RX
use wifikit::core::adapter::scan_adapters;
use wifikit::chips::mt7612u::Mt7612u;
use wifikit::core::chip::ChipDriver;
use std::time::{Duration, Instant};

fn frame_type_name(fc: u16) -> &'static str {
    let ftype = (fc >> 2) & 0x3;
    let subtype = (fc >> 4) & 0xF;
    match (ftype, subtype) {
        (0, 0) => "AssocReq",
        (0, 1) => "AssocResp",
        (0, 4) => "ProbeReq",
        (0, 5) => "ProbeResp",
        (0, 8) => "Beacon",
        (0, 10) => "Disassoc",
        (0, 11) => "Auth",
        (0, 12) => "Deauth",
        (0, 13) => "Action",
        (1, _) => "Control",
        (2, _) => "Data",
        _ => "Other",
    }
}

fn main() {
    println!("=== MT7612U RX Test ===\n");

    match scan_adapters() {
        Ok(adapters) => {
            println!("Found {} adapters:", adapters.len());
            for a in &adapters {
                println!("  {} ({:#06x}:{:#06x}) - {}", a.chip, a.vid, a.pid, a.name);
            }

            let mt = adapters.iter().find(|a| a.vid == 0x0E8D && a.pid == 0x7612);
            if let Some(info) = mt {
                println!("\nOpening MT7612U...");
                match Mt7612u::open_usb(info.vid, info.pid) {
                    Ok((mut driver, endpoints)) => {
                        println!("USB open OK! endpoints: IN=0x{:02X} OUT=0x{:02X}",
                            endpoints.bulk_in, endpoints.bulk_out);

                        println!("\nRunning init...");
                        match driver.init() {
                            Ok(()) => {
                                println!("\n*** INIT SUCCESS! ***\n");

                                println!("=== Channel 1 (2.4 GHz) — 5 seconds ===");
                                rx_test(&mut driver, 5);

                                println!("=== Switching to channel 6 ===");
                                let ch6 = wifikit::core::Channel::new(6);
                                match driver.set_channel(ch6) {
                                    Ok(()) => { rx_test(&mut driver, 5); }
                                    Err(e) => println!("  Channel switch failed: {}\n", e),
                                }

                                println!("=== Switching to channel 36 (5 GHz) ===");
                                let ch36 = wifikit::core::Channel {
                                    number: 36,
                                    band: wifikit::core::Band::Band5g,
                                    bandwidth: wifikit::core::channel::Bandwidth::Bw20,
                                    center_freq_mhz: 5180,
                                };
                                match driver.set_channel(ch36) {
                                    Ok(()) => { rx_test(&mut driver, 5); }
                                    Err(e) => println!("  Channel switch failed: {}\n", e),
                                }

                                println!("Supported channels: {} total", driver.supported_channels().len());
                                let _ = driver.shutdown();
                            }
                            Err(e) => println!("INIT FAILED: {}", e),
                        }
                    }
                    Err(e) => println!("USB open failed: {}", e),
                }
            } else {
                println!("\nNo MT7612U found. Run modeswitch first if device is in CD-ROM mode.");
            }
        }
        Err(e) => println!("Scan failed: {}", e),
    }
}

fn rx_test(driver: &mut Mt7612u, seconds: u64) {
    let start = Instant::now();
    let mut count: u64 = 0;
    let mut timeouts: u64 = 0;
    let duration = Duration::from_secs(seconds);

    while start.elapsed() < duration {
        match driver.rx_frame(Duration::from_millis(200)) {
            Ok(Some(frame)) => {
                count += 1;
                if count <= 30 {
                    let fc = if frame.data.len() >= 2 {
                        u16::from_le_bytes([frame.data[0], frame.data[1]])
                    } else { 0 };
                    let name = frame_type_name(fc);
                    let bssid = if frame.data.len() >= 22 {
                        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            frame.data[16], frame.data[17], frame.data[18],
                            frame.data[19], frame.data[20], frame.data[21])
                    } else {
                        "??".to_string()
                    };
                    println!("  #{:4}: {:>10} {:3}B RSSI={:3} {}",
                        count, name, frame.data.len(), frame.rssi, bssid);
                } else if count == 31 {
                    println!("  ... (suppressing further output)");
                }
            }
            Ok(None) => { timeouts += 1; }
            Err(e) => {
                println!("  RX error: {}", e);
                break;
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let fps = count as f64 / elapsed;
    println!("  {} frames in {:.1}s = {:.1} fps ({} timeouts)\n",
        count, elapsed, fps, timeouts);
}
