// Pure pcap replay for RTL8852BU — replay EVERYTHING verbatim.
// Same approach as the working 8852AU: disable_cpu, power_off, drain thread, pcap replay.
// Only special handling: clear EP7 halt after WCPU_EN (macOS fix from 8852AU).

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use rusb::{DeviceHandle, GlobalContext};

const VID: u16 = 0x0BDA;
const PID_C832: u16 = 0xC832;
const PID_B832: u16 = 0xB832;
const PCAP_PATH: &str = "references/captures/rtl8852bu-b832/full_capture_bus3.pcap";
const RTL_USB_REQ: u8 = 0x05;
const TARGET_BUS: u16 = 3;
const TARGET_DEV: u8 = 5;
const USB_TIMEOUT: Duration = Duration::from_millis(500);
const BULK_TIMEOUT: Duration = Duration::from_secs(2);

fn read32(h: &DeviceHandle<GlobalContext>, addr: u16) -> u32 {
    let mut buf = [0u8; 4];
    let _ = h.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, USB_TIMEOUT);
    u32::from_le_bytes(buf)
}

fn write32(h: &DeviceHandle<GlobalContext>, addr: u16, val: u32) {
    let _ = h.write_control(0x40, RTL_USB_REQ, addr, 0, &val.to_le_bytes(), USB_TIMEOUT);
}

fn read8(h: &DeviceHandle<GlobalContext>, addr: u16) -> u8 {
    let mut buf = [0u8; 1];
    let _ = h.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, USB_TIMEOUT);
    buf[0]
}

fn clear_bits32(h: &DeviceHandle<GlobalContext>, addr: u16, mask: u32) {
    let v = read32(h, addr);
    write32(h, addr, v & !mask);
}

fn main() {
    eprintln!("=== RTL8852BU Pure Pcap Replay ===\n");

    let handle = open_device().expect("Failed to open RTL8852BU");
    handle.claim_interface(0).expect("Failed to claim interface");

    // Discover endpoints
    let device = handle.device();
    let config = device.active_config_descriptor().expect("config desc");
    let mut eps_out: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
    let mut ep_in: Option<u8> = None;
    for iface in config.interfaces() {
        for setting in iface.descriptors() {
            for ep in setting.endpoint_descriptors() {
                let addr = ep.address();
                let num = addr & 0x0F;
                if ep.transfer_type() == rusb::TransferType::Bulk {
                    if addr & 0x80 == 0 {
                        eps_out.insert(num, addr);
                    } else if ep_in.is_none() {
                        ep_in = Some(addr);
                    }
                }
            }
        }
    }
    let ep_rx = ep_in.expect("RX EP not found");
    eprintln!("Bulk OUT: {:?}, Bulk IN: 0x{:02X}", eps_out, ep_rx);

    // ── Phase -1: disable_cpu + power_off (exact 8852AU approach) ──
    let fw_ctrl = read8(&handle, 0x01E0);
    eprintln!("Pre-init: 0x01E0=0x{:02X} (STS={})", fw_ctrl, (fw_ctrl >> 5) & 7);
    if fw_ctrl != 0 {
        eprintln!("  Cleaning stale FW state...");
        clear_bits32(&handle, 0x0088, 0x02);  // clear WCPU_EN
        write32(&handle, 0x01E0, 0);           // clear FW_CTRL
        clear_bits32(&handle, 0x0008, 1 << 14); // clear CPU_CLK_EN
        clear_bits32(&handle, 0x0088, 0x02);   // clear WCPU_EN again
        // power_off
        let v = read8(&handle, 0x0005);
        let _ = handle.write_control(0x40, RTL_USB_REQ, 0x0005, 0, &[v | 0x01], USB_TIMEOUT);
        for _ in 0..200 {
            if read8(&handle, 0x0005) & 0x01 == 0 { break; }
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(50));
        eprintln!("  After: 0x01E0=0x{:02X} 0x0088=0x{:08X}", read8(&handle, 0x01E0), read32(&handle, 0x0088));
    }

    // ── Drain thread (shared handle, 8852AU style) ──
    let handle = Arc::new(handle);
    let drain_running = Arc::new(AtomicBool::new(true));
    let drain_flag = drain_running.clone();
    let drain_h = Arc::clone(&handle);
    let drain_thread = std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let mut total = 0usize;
        while drain_flag.load(Ordering::Relaxed) {
            if let Ok(n) = drain_h.read_bulk(ep_rx, &mut buf, Duration::from_millis(1)) {
                if n > 0 {
                    total += n;
                    if total <= 500 || total % 50000 < n {
                        eprintln!("  [drain] {}B (total: {})", n, total);
                    }
                }
            }
        }
        eprintln!("  [drain] done, total: {} bytes", total);
    });

    // ── Read pcap ──
    let pcap_data = std::fs::read(PCAP_PATH).expect("Failed to read pcap");
    eprintln!("Pcap: {} bytes\n", pcap_data.len());

    let mut offset = 24;
    let mut reg_w = 0u32;
    let mut reg_r = 0u32;
    let mut bulk_ok: std::collections::HashMap<u8, u32> = std::collections::HashMap::new();
    let mut bulk_fail: std::collections::HashMap<u8, u32> = std::collections::HashMap::new();
    let mut total = 0u32;
    let start = Instant::now();

    // ── REPLAY EVERYTHING ──
    while offset + 16 <= pcap_data.len() {
        let incl_len = u32::from_le_bytes([
            pcap_data[offset+8], pcap_data[offset+9],
            pcap_data[offset+10], pcap_data[offset+11],
        ]) as usize;
        offset += 16;
        if offset + incl_len > pcap_data.len() || incl_len < 64 {
            offset += incl_len;
            continue;
        }
        let pkt = &pcap_data[offset..offset+incl_len];
        offset += incl_len;

        if pkt[8] != 0x53 { continue; } // submit only
        let xfer_type = pkt[9];
        let ep = pkt[10];
        let devnum = pkt[11];
        let busnum = u16::from_le_bytes([pkt[12], pkt[13]]);
        if busnum != TARGET_BUS || devnum != TARGET_DEV { continue; }
        total += 1;

        let ep_num = ep & 0x7F;
        let ep_dir_in = ep & 0x80 != 0;
        let payload = &pkt[64..];

        // ── Control WRITE ──
        if xfer_type == 2 && !ep_dir_in && !payload.is_empty() {
            let setup = &pkt[40..48];
            if setup[1] == RTL_USB_REQ && setup[0] == 0x40 {
                let w_val = u16::from_le_bytes([setup[2], setup[3]]);
                let w_idx = u16::from_le_bytes([setup[4], setup[5]]);
                let w_len = u16::from_le_bytes([setup[6], setup[7]]) as usize;
                let data = &payload[..w_len.min(payload.len())];
                let addr = (w_idx as u32) << 16 | w_val as u32;

                let _ = handle.write_control(0x40, RTL_USB_REQ, w_val, w_idx, data, USB_TIMEOUT);
                reg_w += 1;

                // After WCPU_EN: clear EP7 halt (macOS fix from 8852AU)
                if addr == 0x0088 && !data.is_empty() && data[0] & 0x02 != 0 {
                    eprintln!("  [{}] WCPU_EN! Clearing EP7 halt...", total);
                    std::thread::sleep(Duration::from_millis(100));
                    if let Some(&ep7) = eps_out.get(&7) {
                        let _ = handle.clear_halt(ep7);
                    }
                }

                if reg_w <= 50 || addr == 0x0088 || addr == 0x01E0 {
                    eprintln!("  [{}] W 0x{:08X} = {:02x?}", total, addr,
                        &data[..data.len().min(4)]);
                }
            }
        }
        // ── Control READ ──
        else if xfer_type == 2 && ep_dir_in {
            let setup = &pkt[40..48];
            if setup[1] == RTL_USB_REQ && setup[0] == 0xC0 {
                let w_val = u16::from_le_bytes([setup[2], setup[3]]);
                let w_idx = u16::from_le_bytes([setup[4], setup[5]]);
                let w_len = u16::from_le_bytes([setup[6], setup[7]]) as usize;
                let mut buf = vec![0u8; w_len];
                let _ = handle.read_control(0xC0, RTL_USB_REQ, w_val, w_idx, &mut buf, USB_TIMEOUT);
                reg_r += 1;
                let addr = (w_idx as u32) << 16 | w_val as u32;
                if reg_r <= 50 || addr == 0x0088 || addr == 0x01E0 {
                    eprintln!("  [{}] R 0x{:08X} = {:02x?}", total, addr,
                        &buf[..buf.len().min(4)]);
                }
            }
        }
        // ── Bulk OUT ──
        else if xfer_type == 3 && !ep_dir_in && !payload.is_empty() {
            if let Some(&ep_addr) = eps_out.get(&ep_num) {
                match handle.write_bulk(ep_addr, payload, BULK_TIMEOUT) {
                    Ok(_) => {
                        *bulk_ok.entry(ep_num).or_insert(0) += 1;
                        let c = bulk_ok[&ep_num];
                        if c <= 5 || c % 100 == 0 {
                            eprintln!("  [{}] EP{} #{}: {}B OK", total, ep_num, c, payload.len());
                        }
                    }
                    Err(e) => {
                        *bulk_fail.entry(ep_num).or_insert(0) += 1;
                        let f = bulk_fail[&ep_num];
                        if f <= 10 {
                            eprintln!("  [{}] EP{} FAIL #{}: {}B → {}", total, ep_num, f, payload.len(), e);
                        }
                        let _ = handle.clear_halt(ep_addr);
                    }
                }
            }
        }

        // Progress every 5000 pkts
        if total % 5000 == 0 {
            eprintln!("  --- {} pkts, {}W {}R ok={:?} fail={:?} ({:.1}s) ---",
                total, reg_w, reg_r, bulk_ok, bulk_fail, start.elapsed().as_secs_f64());
        }
    }

    eprintln!("\n=== Replay Complete ({:.1}s) ===", start.elapsed().as_secs_f64());
    eprintln!("  Writes: {}, Reads: {}", reg_w, reg_r);
    eprintln!("  Bulk OK: {:?}", bulk_ok);
    eprintln!("  Bulk FAIL: {:?}", bulk_fail);

    // Stop drain, listen for RX
    drain_running.store(false, Ordering::Relaxed);
    let _ = drain_thread.join();

    eprintln!("\n=== Listening 5s for RX ===");
    let mut rx_buf = vec![0u8; 32768];
    let t = Instant::now();
    let mut rx_n = 0u32;
    let mut rx_bytes = 0usize;
    while t.elapsed() < Duration::from_secs(5) {
        if let Ok(n) = handle.read_bulk(ep_rx, &mut rx_buf, Duration::from_millis(100)) {
            if n > 0 { rx_n += 1; rx_bytes += n; }
        }
    }
    eprintln!("RX: {} reads, {} bytes", rx_n, rx_bytes);
    let _ = handle.release_interface(0);
}

fn open_device() -> Option<DeviceHandle<GlobalContext>> {
    for device in rusb::devices().ok()?.iter() {
        if let Ok(desc) = device.device_descriptor() {
            if desc.vendor_id() == VID && (desc.product_id() == PID_C832 || desc.product_id() == PID_B832) {
                return device.open().ok();
            }
        }
    }
    None
}
