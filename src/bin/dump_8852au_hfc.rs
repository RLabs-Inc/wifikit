//! Dump RTL8852AU HFC (HCI Flow Control) register state.
//!
//! Reads R_AX_ACHx_PAGE_CTRL (0x8A10-0x8A3C) before and after a data frame TX
//! to check if the ACH data queues are properly initialized.
//!
//! Usage: cargo run --bin dump_8852au_hfc

use std::time::Duration;
use wifikit::core::chip::ChipId;

/// Read a 32-bit register via USB vendor control transfer.
fn read32(handle: &rusb::DeviceHandle<rusb::GlobalContext>, addr: u32) -> u32 {
    let w_val = (addr & 0xFFFF) as u16;
    let w_idx = ((addr >> 16) & 0xFFFF) as u16;
    let mut buf = [0u8; 4];
    match handle.read_control(0xC0, 0x05, w_val, w_idx, &mut buf, Duration::from_secs(1)) {
        Ok(_) => u32::from_le_bytes(buf),
        Err(e) => { eprintln!("  read {:#06x} failed: {:?}", addr, e); 0xDEADBEEF }
    }
}

fn dump_hfc(handle: &rusb::DeviceHandle<rusb::GlobalContext>, label: &str) {
    let regs: &[(u32, &str)] = &[
        (0x8A00, "R_AX_HFC_CTRL"),
        (0x8A04, "R_AX_HFC_CFG (pub_cfg)"),
        (0x8A10, "R_AX_ACH0_PAGE_CTRL (AC_BE)"),
        (0x8A14, "R_AX_ACH1_PAGE_CTRL (AC_BK)"),
        (0x8A18, "R_AX_ACH2_PAGE_CTRL (AC_VI)"),
        (0x8A1C, "R_AX_ACH3_PAGE_CTRL (AC_VO)"),
        (0x8A20, "R_AX_ACH4_PAGE_CTRL"),
        (0x8A24, "R_AX_ACH5_PAGE_CTRL"),
        (0x8A28, "R_AX_ACH6_PAGE_CTRL"),
        (0x8A2C, "R_AX_ACH7_PAGE_CTRL"),
        (0x8A30, "R_AX_CH8_PAGE_CTRL (B0MGQ)"),
        (0x8A34, "R_AX_CH9_PAGE_CTRL (B0HIQ)"),
        (0x8A38, "R_AX_CH10_PAGE_CTRL (B1MGQ)"),
        (0x8A3C, "R_AX_CH11_PAGE_CTRL (B1HIQ)"),
        (0x8A50, "R_AX_ACH0_PAGE_INFO"),
        (0x8A70, "R_AX_CH8_PAGE_INFO (B0MGQ)"),
        (0x8A80, "R_AX_PUB_PAGE_INFO"),
    ];

    println!("=== {} ===\n", label);
    for &(addr, name) in regs {
        let val = read32(handle, addr);
        let min = val & 0xFFF;
        let max = (val >> 16) & 0xFFF;
        let grp = (val >> 31) & 1;
        println!("  {:#06X} {:<38} = {:#010X}  (min={}, max={}, grp={})",
            addr, name, val, min, max, grp);
    }
    println!();
}

fn main() {
    // Find the 8852AU adapter
    let adapters = wifikit::core::adapter::scan_adapters().expect("scan failed");
    let info = adapters.iter().find(|a| a.chip == ChipId::Rtl8852au);
    let info = match info {
        Some(i) => i.clone(),
        None => {
            eprintln!("No RTL8852AU adapter found");
            std::process::exit(1);
        }
    };

    eprintln!("Found: {} (VID={:#06x} PID={:#06x} bus={} addr={})",
        info.name, info.vid, info.pid, info.bus, info.address);

    // Open and init through normal adapter path
    let mut adapter = wifikit::core::adapter::Adapter::open(&info).expect("adapter open");
    adapter.driver.init().expect("init failed");
    eprintln!("Init complete.\n");

    // Open a second handle for register reads (control transfers don't need interface claim)
    let devices = rusb::DeviceList::new().expect("usb list");
    let dev = devices.iter().find(|d| {
        if let Ok(desc) = d.device_descriptor() {
            desc.vendor_id() == info.vid && desc.product_id() == info.pid
                && d.bus_number() == info.bus && d.address() == info.address
        } else { false }
    }).expect("device not found");
    let reg_handle = dev.open().expect("second open for registers");

    // Dump registers after init
    dump_hfc(&reg_handle, "HFC after init (BEFORE any TX)");

    // Send a management frame (known working)
    println!("--- Sending MGMT frame (probe request) via B0MG ---");
    let our_mac = adapter.driver.mac();
    let probe = wifikit::protocol::frames::build_probe_request(
        &our_mac, "test", &[0x82, 0x84, 0x8B, 0x96],
    ).expect("build probe");
    match adapter.driver.tx_frame(&probe, &wifikit::core::TxOptions::default()) {
        Ok(()) => println!("  Mgmt TX: OK\n"),
        Err(e) => println!("  Mgmt TX: ERROR {:?}\n", e),
    }
    std::thread::sleep(Duration::from_millis(100));
    dump_hfc(&reg_handle, "HFC after MGMT TX");

    // Send a DATA frame through ACH0
    println!("--- Sending DATA frame via ACH0 (EAPOL-Start style) ---");
    let mut frame = vec![0u8; 32];
    frame[0] = 0x08; // Data frame, subtype 0
    frame[1] = 0x01; // ToDS
    frame[4..10].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    frame[10..16].copy_from_slice(our_mac.as_bytes());
    frame[16..22].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    frame[24..32].copy_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);

    match adapter.driver.tx_frame(&frame, &wifikit::core::TxOptions::default()) {
        Ok(()) => println!("  Data TX: OK\n"),
        Err(e) => println!("  Data TX: ERROR {:?}\n", e),
    }
    std::thread::sleep(Duration::from_millis(200));
    dump_hfc(&reg_handle, "HFC after DATA TX");

    // Check if RX still works
    println!("--- RX check after data TX (2 seconds) ---");
    let start = std::time::Instant::now();
    let mut rx_count = 0u32;
    while start.elapsed() < Duration::from_secs(2) {
        match adapter.driver.rx_frame(Duration::from_millis(100)) {
            Ok(Some(_)) => rx_count += 1,
            _ => {}
        }
    }
    if rx_count == 0 {
        println!("  *** RX IS DEAD — 0 frames in 2 seconds ***");
    } else {
        println!("  RX alive: {} frames in 2 seconds", rx_count);
    }

    adapter.driver.shutdown().ok();
    eprintln!("\nDone.");
}
