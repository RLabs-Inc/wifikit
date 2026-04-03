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
        ..Default::default()
    };

    for i in 0..3 {
        match driver.tx_frame(&probe_request, &tx_opts) {
            Ok(()) => eprintln!("  TX #{}: OK ({} bytes)", i + 1, probe_request.len()),
            Err(e) => eprintln!("  TX #{}: FAILED: {}", i + 1, e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // ── Channel Switch + RX Test ──
    // Test all 39 channels like the real scanner does
    let all_channels: Vec<(u8, String)> = driver.supported_channels().iter()
        .map(|ch| (ch.number, format!("ch{}", ch.number)))
        .collect();
    let test_channels: Vec<(u8, String)> = all_channels;

    let mut total_frames = 0u32;
    let dwell = Duration::from_millis(500); // match scanner default
    for (i, (ch, label)) in test_channels.iter().enumerate() {
        let sw = std::time::Instant::now();
        if i > 0 {
            match driver.set_channel(wifikit::core::Channel::new(*ch)) {
                Ok(()) => {},
                Err(e) => { eprintln!("  → {} FAILED: {}", label, e); continue; }
            }
        }
        let sw_ms = sw.elapsed().as_secs_f64() * 1000.0;

        let start = std::time::Instant::now();
        let mut frames = 0u32;
        while start.elapsed() < dwell {
            match driver.rx_frame(Duration::from_millis(50)) {
                Ok(Some(_)) => frames += 1,
                _ => {}
            }
        }
        if frames > 0 || i < 5 || i == test_channels.len() - 1 {
            eprintln!("  {} → {} frames ({:.0} fps) [{:.0}ms sw]", label, frames, frames as f64 / dwell.as_secs_f64(), sw_ms);
        }
        total_frames += frames;
    }

    eprintln!("\n--- Results ---");
    eprintln!("Total: {} frames across {} channels (500ms dwell)", total_frames, test_channels.len());

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
