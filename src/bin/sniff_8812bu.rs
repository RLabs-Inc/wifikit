// Sniffer: use RTL8812BU on ch149 to watch for probe requests from 8852AU
use std::time::{Duration, Instant};
use wifikit::core::chip::ChipDriver;

fn main() {
    eprintln!("=== RTL8812BU Sniffer — watching ch149 for 8852AU probes ===\n");

    let (mut driver, _) = match wifikit::chips::rtl8812bu::Rtl8812bu::open_usb(0x2357, 0x0115) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open RTL8812BU: {}", e);
            std::process::exit(1);
        }
    };

    driver.init().expect("init failed");
    driver.set_monitor_mode().expect("monitor mode failed");
    driver.set_channel(wifikit::core::Channel::new(149)).expect("channel failed");
    eprintln!("Listening on channel 149...\n");
    eprintln!("Looking for probe requests from:");
    eprintln!("  - 0A:C4:90:27:7C:AB (pcap MAC)");
    eprintln!("  - Any locally-administered MAC (02:xx:xx:xx:xx:xx)");
    eprintln!();

    let target_mac: [u8; 6] = [0x0A, 0xC4, 0x90, 0x27, 0x7C, 0xAB];
    let start = Instant::now();
    let mut total = 0u32;
    let mut probes = 0u32;
    let mut target_probes = 0u32;

    while start.elapsed() < Duration::from_secs(30) {
        match driver.rx_frame(Duration::from_millis(50)) {
            Ok(Some(frame)) => {
                total += 1;
                let d = &frame.data;
                if d.len() < 24 { continue; }

                let fc = d[0];
                let frame_type = (fc >> 2) & 0x3;
                let subtype = (fc >> 4) & 0xF;

                // Probe Request: type=0, subtype=4
                if frame_type == 0 && subtype == 4 {
                    probes += 1;
                    let sa = &d[10..16];

                    if sa == &target_mac {
                        target_probes += 1;
                        eprintln!(">>> FOUND PROBE from 0A:C4:90:27:7C:AB! <<<");
                    } else if sa[0] == 0x02 || sa[0] == 0x0A {
                        // Locally administered MAC — might be ours
                        eprintln!("  probe from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
                    }
                }

                if total % 1000 == 0 {
                    eprintln!("  [{:.1}s] {} frames, {} probes, {} from target",
                        start.elapsed().as_secs_f32(), total, probes, target_probes);
                }
            }
            _ => {}
        }
    }

    eprintln!("\n--- Sniffer Results ---");
    eprintln!("Total frames: {}", total);
    eprintln!("Probe requests: {}", probes);
    eprintln!("Target probes (0A:C4:90:27:7C:AB): {}", target_probes);
    if target_probes > 0 {
        eprintln!("\n8852AU IS transmitting on air!");
    } else {
        eprintln!("\n8852AU frames NEVER reached the air.");
    }

    let _ = driver.shutdown();
}
