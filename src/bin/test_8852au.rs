// Standalone RTL8852AU driver test — init + TX + RX
use std::time::Duration;
use wifikit::core::chip::ChipDriver;
use wifikit::core::frame::{TxOptions, TxRate, TxFlags};

fn main() {
    eprintln!("=== RTL8852AU USB3 Driver Test (Full Phase Pipeline) ===\n");

    // Open the device (TP-Link 2357:013f)
    let (mut driver, endpoints) = match wifikit::chips::rtl8852au::Rtl8852au::open_usb(0x2357, 0x013F) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open device: {}", e);
            eprintln!("Make sure: diskutil eject diskN, then usb3_switch");
            std::process::exit(1);
        }
    };

    eprintln!("Device opened. Endpoints: IN=0x{:02X} OUT=0x{:02X}", endpoints.bulk_in, endpoints.bulk_out);

    // Init the driver (power on + FW + post-boot + ch1 + txpower + rxtx)
    eprintln!("\n--- INIT ---");
    match driver.init() {
        Ok(()) => eprintln!("\n--- INIT OK ---"),
        Err(e) => {
            eprintln!("\n--- INIT FAILED: {} ---", e);
            std::process::exit(1);
        }
    }

    // Show chip info
    let info = driver.chip_info();
    eprintln!("\nChip: {} (VID={:04X} PID={:04X})", info.name, info.vid, info.pid);
    eprintln!("FW: {}", info.firmware_version);
    eprintln!("MAC: {}", driver.mac());

    // ── TX Test ──
    // Build a probe request frame (the simplest TX test)
    eprintln!("\n--- TX Test (Probe Request) ---");
    let probe_request = build_probe_request(&driver.mac().0);
    let tx_opts = TxOptions {
        rate: TxRate::Ofdm6m,
        flags: TxFlags::empty(),
        retries: 0,
    };

    for i in 0..3 {
        match driver.tx_frame(&probe_request, &tx_opts) {
            Ok(()) => eprintln!("  TX #{}: OK ({} bytes)", i + 1, probe_request.len()),
            Err(e) => eprintln!("  TX #{}: FAILED: {}", i + 1, e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // ── RX Test ──
    eprintln!("\n--- RX Test (10 seconds) ---");
    let start = std::time::Instant::now();
    let mut frame_count = 0u32;
    let mut byte_count = 0u64;

    while start.elapsed() < Duration::from_secs(10) {
        match driver.rx_frame(Duration::from_millis(100)) {
            Ok(Some(frame)) => {
                frame_count += 1;
                byte_count += frame.data.len() as u64;
                if frame_count <= 5 {
                    eprintln!("  Frame {}: {} bytes, type=0x{:02X}{:02X}, ch={}",
                        frame_count, frame.data.len(),
                        frame.data.get(0).unwrap_or(&0),
                        frame.data.get(1).unwrap_or(&0),
                        frame.channel);
                }
                if frame_count == 6 {
                    eprintln!("  ... (suppressing further frame logs)");
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("  RX error: {}", e);
                break;
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    eprintln!("\n--- Results ---");
    eprintln!("TX: 3 probe requests attempted");
    eprintln!("RX: {} frames in {:.1}s ({:.1} fps)", frame_count, elapsed, frame_count as f64 / elapsed);
    eprintln!("Bytes: {} ({:.1} KB/s)", byte_count, byte_count as f64 / elapsed / 1024.0);

    // Shutdown
    let _ = driver.shutdown();
    eprintln!("\nDone!");
}

/// Build a minimal 802.11 probe request frame
fn build_probe_request(mac: &[u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64);

    // Frame control: Probe Request (0x0040)
    frame.extend_from_slice(&[0x40, 0x00]);
    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);
    // DA: broadcast
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // SA: our MAC
    frame.extend_from_slice(mac);
    // BSSID: broadcast
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // Sequence control
    frame.extend_from_slice(&[0x00, 0x00]);

    // Tagged parameters
    // SSID: wildcard (empty)
    frame.extend_from_slice(&[0x00, 0x00]);
    // Supported rates: 6, 9, 12, 18, 24, 36, 48, 54 Mbps
    frame.extend_from_slice(&[0x01, 0x08, 0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C]);

    frame
}
