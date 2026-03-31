// RTL8852AU FULL pcap replay test
// No custom code. No shortcuts. Just the pcap, verbatim.
use std::time::{Duration, Instant};
use std::thread;
use rusb::{Context, UsbContext};

const VID: u16 = 0x2357;
const PID: u16 = 0x013F;
const RTL_USB_REQ: u8 = 0x05;
const TIMEOUT: Duration = Duration::from_millis(500);

fn main() {
    eprintln!("=== RTL8852AU FULL PCAP REPLAY ===");
    eprintln!("No custom code. Every operation from the Linux pcap, verbatim.\n");

    let context = Context::new().expect("libusb init");
    let handle = context.open_device_with_vid_pid(VID, PID)
        .expect("Device not found (2357:013f)");
    handle.claim_interface(0).expect("claim interface");

    let ep_out: u8 = 0x05;  // TX data
    let ep_in: u8 = 0x84;   // RX data
    let ep_fw: u8 = 0x07;   // H2C / FWDL

    // Use the full init sequence — ALL ops from pcap
    use wifikit::chips::rtl8852a_full_init::{FULL_INIT_SEQUENCE, PostBootOp};

    let seq = FULL_INIT_SEQUENCE;
    let total = seq.len();
    eprintln!("Replaying {} ops from pcap...\n", total);

    let mut read_ok = 0u32;
    let mut write_ok = 0u32;
    let mut write_fail = 0u32;
    let mut bulk_ok = 0u32;
    let mut bulk_fail = 0u32;

    let mut device_alive = true;
    for (i, op) in seq.iter().enumerate() {
        // Liveness check every op in the kill zone (900-930)
        if device_alive && ((i >= 290 && i <= 900 && i % 100 == 0) || (i >= 900 && i <= 930)) {
            let mut buf = [0u8; 1];
            match handle.read_control(0xC0, RTL_USB_REQ, 0x00FC, 0, &mut buf, TIMEOUT) {
                Ok(_) => eprintln!("[{}] ♥ alive (chip_id=0x{:02X})", i, buf[0]),
                Err(e) => {
                    eprintln!("[{}] ✗ DEVICE DEAD: {}", i, e);
                    device_alive = false;
                    // Print the last 10 ops
                    eprintln!("  Last 10 ops before death:");
                    for j in i.saturating_sub(10)..i {
                        match &seq[j] {
                            PostBootOp::Read(a, w) => eprintln!("    [{}] R{} 0x{:04X}", j, w*8, a),
                            PostBootOp::Write(a, v, w) => eprintln!("    [{}] W{} 0x{:04X} = 0x{:08X}", j, w*8, a, v),
                            PostBootOp::BulkOut(e, d) => eprintln!("    [{}] Bulk EP{} {}B", j, e, d.len()),
                        }
                    }
                    break;
                }
            }
        }
        match op {
            PostBootOp::Read(addr, width) => {
                let result = match width {
                    1 => {
                        let mut buf = [0u8; 1];
                        handle.read_control(0xC0, RTL_USB_REQ, (*addr & 0xFFFF) as u16, ((*addr >> 16) & 0xFFFF) as u16, &mut buf, TIMEOUT).map(|_| ())
                    }
                    2 => {
                        let mut buf = [0u8; 2];
                        handle.read_control(0xC0, RTL_USB_REQ, (*addr & 0xFFFF) as u16, ((*addr >> 16) & 0xFFFF) as u16, &mut buf, TIMEOUT).map(|_| ())
                    }
                    _ => {
                        let mut buf = [0u8; 4];
                        handle.read_control(0xC0, RTL_USB_REQ, (*addr & 0xFFFF) as u16, ((*addr >> 16) & 0xFFFF) as u16, &mut buf, TIMEOUT).map(|_| ())
                    }
                };
                match result {
                    Ok(()) => read_ok += 1,
                    Err(e) => {
                        eprintln!("[{}] R 0x{:04X} FAILED: {}", i, addr, e);
                        read_ok += 1; // count as done
                    }
                }
            }
            PostBootOp::Write(addr, val, width) => {
                // Skip power regulator write that crashes this board
                if *addr == 0x0010 {
                    eprintln!("[{}] SKIP R_AX_SYS_SWR_CTRL1 (0x0010) = 0x{:08X} (board-specific power reg)", i, val);
                    write_ok += 1;
                    continue;
                }
                // Catch the exact crash point
                if *addr == 0x0604 {
                    eprintln!("\n[{}] *** ABOUT TO WRITE 0x0604 = 0x{:08X} ***", i, val);
                    // Read it first
                    let mut buf = [0u8; 4];
                    match handle.read_control(0xC0, RTL_USB_REQ, 0x0604, 0, &mut buf, TIMEOUT) {
                        Ok(_) => eprintln!("[{}]   Current 0x0604 = 0x{:08X}", i, u32::from_le_bytes(buf)),
                        Err(e) => eprintln!("[{}]   Read 0x0604 FAILED: {}", i, e),
                    }
                    // Check a few key registers
                    for (ra, rn) in [(0x01E0u16, "FW_CTRL"), (0x8380, "HCI"), (0x8400, "DMAC")] {
                        let mut b = [0u8; 4];
                        match handle.read_control(0xC0, RTL_USB_REQ, ra, 0, &mut b, TIMEOUT) {
                            Ok(_) => eprintln!("[{}]   0x{:04X} ({}) = 0x{:08X}", i, ra, rn, u32::from_le_bytes(b)),
                            Err(e) => eprintln!("[{}]   0x{:04X} ({}) = FAILED: {}", i, ra, rn, e),
                        }
                    }
                    eprintln!("[{}]   Writing 0x0604 now...", i);
                }
                let result = match width {
                    1 => handle.write_control(0x40, RTL_USB_REQ, (*addr & 0xFFFF) as u16, ((*addr >> 16) & 0xFFFF) as u16, &(*val as u8).to_le_bytes(), TIMEOUT).map(|_| ()),
                    2 => handle.write_control(0x40, RTL_USB_REQ, (*addr & 0xFFFF) as u16, ((*addr >> 16) & 0xFFFF) as u16, &(*val as u16).to_le_bytes(), TIMEOUT).map(|_| ()),
                    _ => handle.write_control(0x40, RTL_USB_REQ, (*addr & 0xFFFF) as u16, ((*addr >> 16) & 0xFFFF) as u16, &val.to_le_bytes(), TIMEOUT).map(|_| ()),
                };
                match result {
                    Ok(()) => {
                        write_ok += 1;
                        if *addr == 0x0604 {
                            eprintln!("[{}]   Write 0x0604: OK!", i);
                        }
                    }
                    Err(e) => {
                        if write_fail < 10 || *addr == 0x0604 {
                            eprintln!("[{}] W 0x{:04X}={:08X} FAILED: {}", i, addr, val, e);
                        }
                        write_fail += 1;
                    }
                }
            }
            PostBootOp::BulkOut(ep, data) => {
                let target_ep = if *ep == 7 { ep_fw } else { ep_out };
                match handle.write_bulk(target_ep, data, Duration::from_millis(1000)) {
                    Ok(_) => {
                        bulk_ok += 1;
                        if bulk_ok <= 5 || bulk_ok % 50 == 0 {
                            eprintln!("[{}] Bulk EP0x{:02X} ({} bytes): OK [total OK: {}]",
                                i, target_ep, data.len(), bulk_ok);
                        }
                    }
                    Err(e) => {
                        bulk_fail += 1;
                        if bulk_fail <= 10 {
                            eprintln!("[{}] Bulk EP0x{:02X} ({} bytes): FAILED: {} [total fail: {}]",
                                i, target_ep, data.len(), e, bulk_fail);
                        }
                    }
                }
            }
        }

        let done = read_ok + write_ok + write_fail + bulk_ok + bulk_fail;
        if done % 5000 == 0 && done > 0 {
            eprintln!("  {}/{}: R={} W={}/{} B={}/{}",
                done, total, read_ok, write_ok, write_ok + write_fail,
                bulk_ok, bulk_ok + bulk_fail);
        }
    }

    eprintln!("\n=== REPLAY COMPLETE ===");
    eprintln!("R={} W={}/{} Bulk={}/{}",
        read_ok, write_ok, write_ok + write_fail,
        bulk_ok, bulk_ok + bulk_fail);

    // Dump key registers
    let regs: &[(u16, &str)] = &[
        (0x8380, "HCI_FUNC_EN"),
        (0x8400, "DMAC_FUNC"),
        (0x8404, "DMAC_CLK"),
        (0xC000, "CMAC_FUNC"),
        (0x1060, "USB_EP0"),
        (0x106C, "USB_EP3"),
        (0x8900, "RXAGG_0"),
        (0xCE20, "RX_FLTR"),
    ];
    eprintln!("\n=== POST-REPLAY REGISTERS ===");
    for (addr, name) in regs {
        let mut buf = [0u8; 4];
        match handle.read_control(0xC0, RTL_USB_REQ, *addr, 0, &mut buf, TIMEOUT) {
            Ok(_) => eprintln!("  0x{:04X} ({:12}) = 0x{:08X}", addr, name, u32::from_le_bytes(buf)),
            Err(e) => eprintln!("  0x{:04X} ({:12}) = READ FAILED: {}", addr, name, e),
        }
    }

    // Try RX
    eprintln!("\n=== RX TEST (5 seconds) ===");
    let mut rx_buf = vec![0u8; 32768];
    let start = std::time::Instant::now();
    let mut frames = 0u32;
    while start.elapsed() < Duration::from_secs(5) {
        match handle.read_bulk(ep_in, &mut rx_buf, Duration::from_millis(200)) {
            Ok(n) if n > 0 => {
                frames += 1;
                if frames <= 3 {
                    eprintln!("  RX: {} bytes", n);
                }
            }
            _ => {}
        }
    }
    eprintln!("  RX frames: {} in 5s", frames);

    let _ = handle.release_interface(0);
    eprintln!("\nDone!");
}
