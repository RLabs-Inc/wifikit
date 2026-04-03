// RTL8852AU concurrent RX + channel switch test
// Reproduces the scanner's threading model: one thread does read_bulk
// continuously while the main thread hops channels via set_channel.
//
// If this test bricks the device like the scanner does, the issue is
// concurrent read_bulk + set_channel. If it works, something else is wrong.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wifikit::core::chip::ChipDriver;
use wifikit::core::frame::{TxOptions, TxRate, TxFlags};

fn main() {
    eprintln!("=== RTL8852AU CONCURRENT RX Test ===");
    eprintln!("Simulates scanner: RX thread + channel hopping on main thread\n");

    let (mut driver, endpoints) = match wifikit::chips::rtl8852au::Rtl8852au::open_usb(0x2357, 0x013F) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open device: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("Device opened. Endpoints: IN=0x{:02X} OUT=0x{:02X}", endpoints.bulk_in, endpoints.bulk_out);

    // Init (same as test_8852au)
    match driver.init() {
        Ok(()) => eprintln!("INIT OK"),
        Err(e) => {
            eprintln!("INIT FAILED: {}", e);
            std::process::exit(1);
        }
    }

    let info = driver.chip_info();
    eprintln!("Chip: {} MAC: {}", info.name, driver.mac());

    // These two calls happen in the scanner path but NOT in the original test.
    // Adding them to match the scanner exactly.
    let randomized_mac = wifikit::core::mac::MacAddress::new([0x02, 0xE0, 0x2B, 0xAA, 0xBB, 0xCC]);
    driver.set_mac(randomized_mac).expect("set_mac failed");
    eprintln!("set_mac: {}", driver.mac());

    driver.set_monitor_mode().expect("set_monitor_mode failed");
    eprintln!("set_monitor_mode: OK\n");

    // Take RX handle — exactly what SharedAdapter::spawn does
    let rx_handle = driver.take_rx_handle().expect("no RX handle");
    let alive = Arc::new(AtomicBool::new(true));
    let frame_count = Arc::new(AtomicU32::new(0));

    // Spawn RX thread — mirrors shared.rs start_rx_thread
    let alive_rx = Arc::clone(&alive);
    let frame_count_rx = Arc::clone(&frame_count);
    let rx_thread = std::thread::Builder::new()
        .name("rx-test".into())
        .spawn(move || {
            let mut buf = vec![0u8; rx_handle.rx_buf_size];
            let mut reads = 0u64;
            let mut timeouts = 0u64;
            let start = std::time::Instant::now();

            loop {
                if !alive_rx.load(Ordering::SeqCst) {
                    break;
                }

                match rx_handle.device.read_bulk(
                    rx_handle.ep_in,
                    &mut buf,
                    Duration::from_millis(1), // same as RX_POLL_TIMEOUT
                ) {
                    Ok(n) if n > 0 => {
                        reads += 1;
                        // Parse frames like the RX thread does
                        let mut pos = 0;
                        while pos < n {
                            let remaining = &buf[pos..n];
                            let (consumed, _packet) = (rx_handle.parse_fn)(remaining, 0);
                            if consumed == 0 {
                                pos += 4;
                                continue;
                            }
                            pos += consumed;
                            frame_count_rx.fetch_add(1, Ordering::Relaxed);
                        }

                        if reads <= 5 || reads % 500 == 0 {
                            eprintln!("  [RX] read #{}: {} bytes, total frames: {}",
                                reads, n, frame_count_rx.load(Ordering::Relaxed));
                        }
                    }
                    Ok(_) => {}
                    Err(rusb::Error::Timeout) => {
                        timeouts += 1;
                        if timeouts % 5000 == 0 {
                            eprintln!("  [RX] timeout #{} ({:.1}s)",
                                timeouts, start.elapsed().as_secs_f64());
                        }
                        continue;
                    }
                    Err(rusb::Error::Interrupted) => continue,
                    Err(rusb::Error::Overflow) => continue,
                    Err(e) => {
                        eprintln!("  [RX] FATAL: {:?} at {:.1}s", e, start.elapsed().as_secs_f64());
                        break;
                    }
                }
            }

            eprintln!("  [RX] exiting: {} reads, {} timeouts, {} frames",
                reads, timeouts, frame_count_rx.load(Ordering::Relaxed));
        })
        .expect("spawn rx thread");

    // Give RX thread a moment to start reading
    std::thread::sleep(Duration::from_millis(100));
    eprintln!("RX thread running. Starting channel hopping...\n");

    // Channel hop — same as scanner, using driver.set_channel via &mut
    let channels: Vec<u8> = driver.supported_channels().iter()
        .map(|ch| ch.number)
        .collect();

    let dwell = Duration::from_millis(500);
    let mut total_frames_before = 0u32;

    for (i, &ch) in channels.iter().enumerate() {
        let frames_before = frame_count.load(Ordering::Relaxed);

        match driver.set_channel(wifikit::core::Channel::new(ch)) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("  ch{} set_channel FAILED: {}", ch, e);
                continue;
            }
        }

        std::thread::sleep(dwell);

        // TX probe request after dwell — exactly what the scanner does
        let probe = build_probe_request(&driver.mac().0);
        let tx_opts = TxOptions {
            rate: TxRate::Ofdm6m,
            flags: TxFlags::empty(),
            retries: 1,
            ..Default::default()
        };
        match driver.tx_frame(&probe, &tx_opts) {
            Ok(()) => {}
            Err(e) => eprintln!("  ch{} TX FAILED: {}", ch, e),
        }

        let frames_after = frame_count.load(Ordering::Relaxed);
        let ch_frames = frames_after - frames_before;

        if ch_frames > 0 || i < 5 || i == channels.len() - 1 {
            eprintln!("  ch{} → {} frames", ch, ch_frames);
        }

        total_frames_before = frames_after;

        // Check if RX thread is still getting data
        if i > 0 && i % 10 == 0 {
            eprintln!("  --- checkpoint: {} total frames so far ---", frames_after);
        }
    }

    eprintln!("\n--- Results ---");
    eprintln!("Total: {} frames across {} channels", frame_count.load(Ordering::Relaxed), channels.len());

    // Stop RX thread
    alive.store(false, Ordering::SeqCst);
    let _ = rx_thread.join();

    let _ = driver.shutdown();
    eprintln!("Done!");
}

fn build_probe_request(mac: &[u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64);
    frame.extend_from_slice(&[0x40, 0x00]); // Probe Request
    frame.extend_from_slice(&[0x00, 0x00]); // Duration
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // DA: broadcast
    frame.extend_from_slice(mac); // SA
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // BSSID: broadcast
    frame.extend_from_slice(&[0x00, 0x00]); // Sequence control
    frame.extend_from_slice(&[0x00, 0x00]); // SSID: wildcard
    frame.extend_from_slice(&[0x01, 0x08, 0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C]); // Rates
    frame
}
