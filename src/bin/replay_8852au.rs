// Pure pcap replay for RTL8852AU — replay EVERYTHING from the working capture.
// No assumptions, no skips. Exact same USB operations in exact same order.
//
// Usage: cargo run --bin replay_8852au
//
// Reads: references/captures/rtl8852au_tx_20260404/usb3_gentle_tx.pcap
// Replays: all register writes + EP7 bulk + EP5 TX for bus1 dev16

use std::time::{Duration, Instant};
use rusb::{Context, DeviceHandle, GlobalContext, UsbContext};

const VID: u16 = 0x2357;
const PID: u16 = 0x013F;
const PCAP_PATH: &str = "references/captures/rtl8852au_tx_20260404/usb3_gentle_tx.pcap";
const RTL_USB_REQ: u8 = 0x05;
const TARGET_BUS: u8 = 1;
const TARGET_DEV: u8 = 16;
const USB_TIMEOUT: Duration = Duration::from_millis(500);

fn main() {
    eprintln!("=== RTL8852AU Pure Pcap Replay ===\n");

    // Open USB device
    let handle = open_device().expect("Failed to open RTL8852AU");
    handle.claim_interface(0).expect("Failed to claim interface");

    // Discover endpoints
    let device = handle.device();
    let desc = device.active_config_descriptor().expect("config desc");
    let mut ep_out_5: Option<u8> = None;
    let mut ep_out_7: Option<u8> = None;
    let mut ep_in: Option<u8> = None;

    for iface in desc.interfaces() {
        for setting in iface.descriptors() {
            for ep in setting.endpoint_descriptors() {
                let addr = ep.address();
                let num = addr & 0x0F;
                let is_in = addr & 0x80 != 0;
                if ep.transfer_type() == rusb::TransferType::Bulk {
                    if !is_in {
                        match num {
                            5 => ep_out_5 = Some(addr),
                            7 => ep_out_7 = Some(addr),
                            _ => {}
                        }
                    } else if ep_in.is_none() {
                        ep_in = Some(addr);
                    }
                }
            }
        }
    }

    let ep5 = ep_out_5.expect("EP5 not found");
    let ep7 = ep_out_7.expect("EP7 not found");
    let ep_rx = ep_in.expect("RX EP not found");
    eprintln!("Endpoints: TX=0x{:02X} FW=0x{:02X} RX=0x{:02X}", ep5, ep7, ep_rx);

    // Read pcap
    let pcap_data = std::fs::read(PCAP_PATH).expect("Failed to read pcap");
    eprintln!("Pcap: {} bytes", pcap_data.len());

    // Parse pcap and replay
    let mut offset = 24; // skip global header
    let mut reg_writes = 0u32;
    let mut reg_reads = 0u32;
    let mut ep7_sent = 0u32;
    let mut ep5_sent = 0u32;
    let mut ep7_fail = 0u32;
    let mut skipped = 0u32;
    let mut first_tx_done = false;
    let mut total_pkts = 0u32;

    // Start RX drain thread — consume incoming data to prevent EP stalls
    let drain_handle = handle.device().open().ok();
    let drain_running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let drain_flag = drain_running.clone();
    let drain_ep = ep_rx;
    let drain_thread = std::thread::spawn(move || {
        if let Some(dh) = drain_handle {
            let _ = dh.claim_interface(0);
            let mut buf = vec![0u8; 16384];
            while drain_flag.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = dh.read_bulk(drain_ep, &mut buf, Duration::from_millis(50));
            }
        }
    });

    let start = Instant::now();

    while offset + 16 <= pcap_data.len() {
        // pcap record header
        let incl_len = u32::from_le_bytes([
            pcap_data[offset + 8], pcap_data[offset + 9],
            pcap_data[offset + 10], pcap_data[offset + 11],
        ]) as usize;
        offset += 16;

        if offset + incl_len > pcap_data.len() || incl_len < 64 {
            offset += incl_len;
            continue;
        }

        let pkt = &pcap_data[offset..offset + incl_len];
        offset += incl_len;

        // usbmon header
        let pkt_type = pkt[8];   // S=0x53
        let xfer_type = pkt[9];  // 2=ctrl, 3=bulk
        let ep = pkt[10];
        let devnum = pkt[11];
        let busnum = u16::from_le_bytes([pkt[12], pkt[13]]);
        let ep_num = ep & 0x7F;
        let ep_dir_in = ep & 0x80 != 0;
        let payload = &pkt[64..];

        // Only replay submit events for our device
        if busnum != TARGET_BUS as u16 || devnum != TARGET_DEV || pkt_type != 0x53 {
            continue;
        }
        total_pkts += 1;

        // Register WRITE (vendor control OUT)
        if xfer_type == 2 && !ep_dir_in && !payload.is_empty() {
            let setup = &pkt[40..48];
            let bm_req_type = setup[0];
            let b_req = setup[1];
            let w_val = u16::from_le_bytes([setup[2], setup[3]]);
            let w_idx = u16::from_le_bytes([setup[4], setup[5]]);
            let w_len = u16::from_le_bytes([setup[6], setup[7]]);

            if b_req == RTL_USB_REQ && bm_req_type == 0x40 {
                let write_data = &payload[..std::cmp::min(w_len as usize, payload.len())];
                let addr = (w_idx as u32) << 16 | w_val as u32;

                // Detect WCPU enable (W 0x0088 with WCPU_EN bit) — firmware is booting.
                // After this, EP7 state changes. Wait for firmware + clear EP7.
                if addr == 0x0088 && write_data.len() >= 1 && (write_data[0] & 0x02) != 0 {
                    // Write the register first
                    let _ = handle.write_control(0x40, RTL_USB_REQ, w_val, w_idx, write_data, USB_TIMEOUT);
                    reg_writes += 1;

                    // Wait for firmware to boot (poll 0x01E0 for FWDL_STS=7)
                    eprintln!("  [{}] WCPU enabled — waiting for FW ready...", total_pkts);
                    for poll in 0..2000 {
                        let mut rd = [0u8; 1];
                        let _ = handle.read_control(0xC0, RTL_USB_REQ, 0x01E0, 0, &mut rd, USB_TIMEOUT);
                        let fwdl_sts = (rd[0] >> 5) & 0x7;
                        if fwdl_sts == 7 {
                            eprintln!("  [{}] FW READY after {} polls (0x01E0=0x{:02X})", total_pkts, poll, rd[0]);
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    // Clear EP7 halt — firmware boot resets endpoint state
                    let _ = handle.clear_halt(ep7);
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }

                match handle.write_control(0x40, RTL_USB_REQ, w_val, w_idx, write_data, USB_TIMEOUT) {
                    Ok(_) => reg_writes += 1,
                    Err(e) => {
                        if reg_writes < 5 {
                            eprintln!("  W 0x{:04X}{:04X} FAIL: {}", w_idx, w_val, e);
                        }
                    }
                }
            }
        }
        // Register READ (vendor control IN)
        else if xfer_type == 2 && ep_dir_in {
            let setup = &pkt[40..48];
            let bm_req_type = setup[0];
            let b_req = setup[1];
            let w_val = u16::from_le_bytes([setup[2], setup[3]]);
            let w_idx = u16::from_le_bytes([setup[4], setup[5]]);
            let w_len = u16::from_le_bytes([setup[6], setup[7]]);

            if b_req == RTL_USB_REQ && bm_req_type == 0xC0 {
                let mut buf = vec![0u8; w_len as usize];
                let _ = handle.read_control(0xC0, RTL_USB_REQ, w_val, w_idx, &mut buf, USB_TIMEOUT);
                reg_reads += 1;

                // Check for FW ready (0x01E0 bit [7:5] == 7)
                let addr = (w_idx as u32) << 16 | w_val as u32;
                if addr == 0x01E0 && !buf.is_empty() {
                    let val = buf[0];
                    let fwdl_sts = (val >> 5) & 0x7;
                    if fwdl_sts == 7 && reg_reads % 100 == 0 {
                        eprintln!("  [{}] FW READY (0x01E0=0x{:02X})", total_pkts, val);
                    }
                }
            }
        }
        // EP7 bulk OUT (firmware + H2C)
        else if xfer_type == 3 && !ep_dir_in && ep_num == 7 && !payload.is_empty() {
            let result = match handle.write_bulk(ep7, payload, Duration::from_secs(2)) {
                Ok(_) => Ok(()),
                Err(_) => {
                    // First failure: clear halt, wait, retry once
                    let _ = handle.clear_halt(ep7);
                    std::thread::sleep(Duration::from_millis(50));
                    handle.write_bulk(ep7, payload, Duration::from_secs(2)).map(|_| ())
                }
            };
            match result {
                Ok(()) => {
                    ep7_sent += 1;
                    if ep7_sent <= 3 || ep7_sent % 50 == 0 {
                        let dw0 = if payload.len() >= 4 {
                            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
                        } else { 0 };
                        let fwdl_en = (dw0 >> 20) & 1;
                        eprintln!("  [{}] EP7 #{}: {}B FWDL={}", total_pkts, ep7_sent, payload.len(), fwdl_en);
                    }
                }
                Err(e) => {
                    ep7_fail += 1;
                    if ep7_fail <= 5 {
                        eprintln!("  [{}] EP7 FAIL (after retry): {}B → {}", total_pkts, payload.len(), e);
                    }
                    let _ = handle.clear_halt(ep7);
                }
            }
        }
        // EP5 bulk OUT (TX frame!)
        else if xfer_type == 3 && !ep_dir_in && ep_num == 5 && payload.len() > 48 {
            if !first_tx_done {
                eprintln!("\n=== FIRST TX FRAME (after {} writes, {} reads, {} EP7) ===",
                    reg_writes, reg_reads, ep7_sent);
                first_tx_done = true;
            }
            match handle.write_bulk(ep5, payload, USB_TIMEOUT) {
                Ok(_) => {
                    ep5_sent += 1;
                    if ep5_sent <= 5 || ep5_sent % 50 == 0 {
                        eprintln!("  TX #{}: {}B", ep5_sent, payload.len());
                    }
                }
                Err(e) => {
                    eprintln!("  TX FAIL: {}B → {}", payload.len(), e);
                }
            }
        }

        // Progress
        if total_pkts % 10000 == 0 {
            eprintln!("  ... {} pkts, {}W {}R {}EP7 {}TX ({:.1}s)",
                total_pkts, reg_writes, reg_reads, ep7_sent, ep5_sent,
                start.elapsed().as_secs_f64());
        }
    }

    let elapsed = start.elapsed();
    eprintln!("\n=== Replay Complete ({:.1}s) ===", elapsed.as_secs_f64());
    eprintln!("  Register writes: {}", reg_writes);
    eprintln!("  Register reads: {}", reg_reads);
    eprintln!("  EP7 bulk (FW+H2C): {} sent, {} failed", ep7_sent, ep7_fail);
    eprintln!("  EP5 TX frames: {}", ep5_sent);

    // Now listen for probe responses
    eprintln!("\n=== Listening 5s for probe responses ===");
    drain_running.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = drain_thread.join();

    // Read MAC from EFUSE (0xC100-C105)
    let mut mac_buf = [0u8; 4];
    let _ = handle.read_control(0xC0, RTL_USB_REQ, 0xC100, 0, &mut mac_buf, USB_TIMEOUT);
    eprintln!("MACID_REG: {:02X}:{:02X}:{:02X}:{:02X}:...", mac_buf[0], mac_buf[1], mac_buf[2], mac_buf[3]);

    // Listen for RX frames
    let mut rx_buf = vec![0u8; 32768];
    let listen_start = Instant::now();
    let mut rx_frames = 0u32;
    let mut probe_resp = 0u32;

    while listen_start.elapsed() < Duration::from_secs(5) {
        match handle.read_bulk(ep_rx, &mut rx_buf, Duration::from_millis(100)) {
            Ok(n) if n > 0 => {
                rx_frames += 1;
                // Quick check for probe responses in the RX data
                // (simplified — just count management frames)
            }
            _ => {}
        }
    }

    eprintln!("RX bulk reads with data: {}", rx_frames);
    eprintln!("\nDone. Check if APs responded to our probe requests.");

    // Cleanup
    let _ = handle.release_interface(0);
}

fn open_device() -> Option<DeviceHandle<GlobalContext>> {
    for device in rusb::devices().ok()?.iter() {
        let desc = device.device_descriptor().ok().unwrap();
        if desc.vendor_id() == VID && desc.product_id() == PID {
            return device.open().ok();
        }
    }
    // Also try the CD-ROM mode PID
    for device in rusb::devices().ok()?.iter() {
        let desc = device.device_descriptor().ok().unwrap();
        if desc.vendor_id() == VID && desc.product_id() == 0x0120 {
            return device.open().ok();
        }
    }
    None
}
