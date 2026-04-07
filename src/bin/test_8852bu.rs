// Test RTL8852BU driver init
use wifikit::chips::rtl8852bu::Rtl8852bu;
use wifikit::core::chip::ChipDriver;

fn frame_type_str(data: &[u8]) -> String {
    if data.len() < 2 {
        return format!("too-short({}B)", data.len());
    }
    let fc = u16::from_le_bytes([data[0], data[1]]);
    let ftype = (fc >> 2) & 0x3;
    let subtype = (fc >> 4) & 0xF;
    match ftype {
        0 => match subtype {
            0 => "Assoc Req".into(),
            1 => "Assoc Resp".into(),
            2 => "Reassoc Req".into(),
            3 => "Reassoc Resp".into(),
            4 => "Probe Req".into(),
            5 => "Probe Resp".into(),
            8 => "Beacon".into(),
            10 => "Disassoc".into(),
            11 => "Auth".into(),
            12 => "Deauth".into(),
            13 => "Action".into(),
            _ => format!("Mgmt(sub={})", subtype),
        },
        1 => match subtype {
            9 => "BAR".into(),
            10 => "BA".into(),
            11 => "RTS".into(),
            12 => "CTS".into(),
            13 => "ACK".into(),
            _ => format!("Ctrl(sub={})", subtype),
        },
        2 => {
            let ds = (fc >> 8) & 0x3;
            match ds {
                0 => "Data(IBSS)".into(),
                1 => "Data(ToAP)".into(),
                2 => "Data(FromAP)".into(),
                3 => "Data(WDS)".into(),
                _ => "Data".into(),
            }
        },
        _ => format!("Unknown(type={},sub={})", ftype, subtype),
    }
}

fn main() {
    eprintln!("=== RTL8852BU Driver Test ===\n");

    let (mut driver, endpoints) = match Rtl8852bu::open_usb(0x0BDA, 0xB832) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to open: {}", e);
            std::process::exit(1);
        }
    };
    eprintln!("Device opened! Endpoints: {:?}\n", endpoints);

    eprintln!("--- Running chip_init() ---");
    match driver.init() {
        Ok(()) => {
            eprintln!("\n*** INIT SUCCESS! ***");
            let info = driver.chip_info();
            eprintln!("Chip: {}", info.name);
            eprintln!("MAC: {}", driver.mac());
            eprintln!("TX power: {} dBm", driver.tx_power());
        }
        Err(e) => {
            eprintln!("\nInit failed: {}", e);
            std::process::exit(1);
        }
    }

    // Switch to channel 161 (home WiFi)
    eprintln!("\n--- Switching to channel 161 HT20 ---");
    let ch_start = std::time::Instant::now();
    match driver.set_channel_pcap(161, 0) {
        Ok(()) => eprintln!("Channel switch done in {:.1}s", ch_start.elapsed().as_secs_f64()),
        Err(e) => eprintln!("Channel switch failed: {}", e),
    }

    // Listen and classify frames
    eprintln!("\n--- Listening 5s for RX frames on ch161 ---");
    let start = std::time::Instant::now();
    let mut count = 0u32;
    let mut types: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    while start.elapsed() < std::time::Duration::from_secs(5) {
        match driver.rx_frame(std::time::Duration::from_millis(100)) {
            Ok(Some(frame)) => {
                count += 1;
                let ft = frame_type_str(&frame.data);
                *types.entry(ft.clone()).or_insert(0) += 1;
                if count <= 20 {
                    // Show first bytes of frame for debugging
                    let hex: String = frame.data.iter().take(16)
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>().join(" ");
                    eprintln!("  RX #{:3}: {:4}B  {}  [{}]", count, frame.data.len(), ft, hex);
                }
            }
            _ => {}
        }
    }
    eprintln!("\nTotal RX: {} frames in 5s", count);
    eprintln!("\nFrame type breakdown:");
    let mut sorted: Vec<_> = types.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (ft, n) in &sorted {
        eprintln!("  {:20} {:5} ({:.1}%)", ft, n, **n as f64 / count as f64 * 100.0);
    }

    eprintln!("\n--- Shutdown ---");
    let _ = driver.shutdown();
    eprintln!("Done.");
}
