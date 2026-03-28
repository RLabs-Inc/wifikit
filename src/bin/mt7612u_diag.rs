// MT7612U diagnostic: test both adapters on all channels
use wifikit::chips::mt7612u::Mt7612u;
use wifikit::core::chip::ChipDriver;
use wifikit::core::adapter::scan_adapters;
use std::time::{Duration, Instant};

fn rx_count(driver: &mut Mt7612u, secs: u64) -> u64 {
    let start = Instant::now();
    let mut frames = 0u64;
    while start.elapsed() < Duration::from_secs(secs) {
        match driver.rx_frame(Duration::from_millis(200)) {
            Ok(Some(f)) => {
                frames += 1;
                if frames <= 5 {
                    let fc = if f.data.len() >= 2 {
                        u16::from_le_bytes([f.data[0], f.data[1]])
                    } else { 0 };
                    let ftype = (fc >> 2) & 0x3;
                    let subtype = (fc >> 4) & 0xF;
                    println!("      frame: {}B type={}/{} rssi={}", f.data.len(), ftype, subtype, f.rssi);
                }
            }
            Ok(None) => {}
            Err(e) => { println!("      RX error: {}", e); break; }
        }
    }
    let fps = frames as f64 / start.elapsed().as_secs_f64();
    println!("    => {} frames, {:.0} fps", frames, fps);
    frames
}

fn test_adapter(info: &wifikit::core::adapter::AdapterInfo) {
    println!("\n{}", "=".repeat(60));
    println!("Testing: {} (bus={} addr={})", info.name, info.bus, info.address);
    println!("  VID={:#06x} PID={:#06x}", info.vid, info.pid);

    let (mut driver, ep) = match Mt7612u::open_usb(info.vid, info.pid) {
        Ok(d) => d,
        Err(e) => { println!("  OPEN FAILED: {}", e); return; }
    };
    println!("  Endpoints: IN=0x{:02X} OUT=0x{:02X}", ep.bulk_in, ep.bulk_out);

    match driver.init() {
        Ok(()) => println!("  Init OK! MAC={}", driver.mac()),
        Err(e) => { println!("  INIT FAILED: {}", e); return; }
    }

    // Test channels 6, 11, 36, 44
    for &ch in &[6u8, 11, 36, 44] {
        let c = if ch >= 36 {
            wifikit::core::Channel {
                number: ch,
                band: wifikit::core::Band::Band5g,
                bandwidth: wifikit::core::channel::Bandwidth::Bw20,
                center_freq_mhz: 5000 + ch as u16 * 5,
            }
        } else {
            wifikit::core::Channel::new(ch)
        };
        print!("  ch{:>3}: ", ch);
        match driver.set_channel(c) {
            Ok(()) => { rx_count(&mut driver, 3); }
            Err(e) => println!("FAILED: {}", e),
        }
    }

    let _ = driver.shutdown();
}

fn main() {
    println!("=== MT7612U Dual-Adapter Diagnostic ===\n");

    let adapters = scan_adapters().expect("scan failed");
    let mt_adapters: Vec<_> = adapters.iter()
        .filter(|a| a.vid == 0x0E8D && a.pid == 0x7612)
        .collect();

    println!("Found {} MT7612U adapter(s):", mt_adapters.len());
    for a in &mt_adapters {
        println!("  bus={} addr={} - {}", a.bus, a.address, a.name);
    }

    if mt_adapters.is_empty() {
        println!("\nNo MT7612U found! Run modeswitch first.");
        return;
    }

    // Test each adapter
    for info in &mt_adapters {
        test_adapter(info);
    }

    println!("\n=== Done ===");
}
