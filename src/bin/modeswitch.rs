// USB mode switch utility for WiFi adapters that present as mass storage
// Sends SCSI eject command to trigger device mode switch from CD-ROM to WiFi

use rusb::UsbContext;
use std::time::Duration;

const VID_MEDIATEK: u16 = 0x0E8D;
const PID_MT7612_CDROM: u16 = 0x2870;
const PID_MT7612_WIFI: u16 = 0x7612;

const VID_REALTEK: u16 = 0x0BDA;
const PID_REALTEK_STORAGE: u16 = 0x1A2B;
// Known Realtek WiFi-mode PIDs after modeswitch
const REALTEK_WIFI_PIDS: &[(u16, &str)] = &[
    (0xC832, "RTL8852BU"),   // confirmed: TP-Link 802.11ax WLAN Adapter
    (0xB832, "RTL8832BU"),
    (0xB852, "RTL8852AU"),
    (0xB812, "RTL8812BU"),
    (0x8812, "RTL8812AU"),
    (0xC82C, "RTL8852CU"),
];

// SCSI TEST UNIT READY wrapped in CBW (wake up the device)
const SCSI_TEST_UNIT_READY: [u8; 31] = [
    0x55, 0x53, 0x42, 0x43, // "USBC"
    0x01, 0x00, 0x00, 0x00, // tag
    0x00, 0x00, 0x00, 0x00, // transfer length: 0
    0x00,                   // flags: host-to-device
    0x00,                   // LUN: 0
    0x06,                   // CB length: 6
    0x00,                   // opcode: TEST UNIT READY
    0x00, 0x00, 0x00, 0x00, 0x00, // params
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// SCSI INQUIRY wrapped in CBW
const SCSI_INQUIRY: [u8; 31] = [
    0x55, 0x53, 0x42, 0x43, // "USBC"
    0x02, 0x00, 0x00, 0x00, // tag
    0x24, 0x00, 0x00, 0x00, // transfer length: 36
    0x80,                   // flags: device-to-host
    0x00,                   // LUN: 0
    0x06,                   // CB length: 6
    0x12,                   // opcode: INQUIRY
    0x00,                   // EVPD=0
    0x00,                   // page code
    0x00, 0x24,             // allocation length: 36
    0x00,                   // control
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// SCSI START STOP UNIT (eject) wrapped in CBW
const SCSI_EJECT: [u8; 31] = [
    0x55, 0x53, 0x42, 0x43, // "USBC"
    0x03, 0x00, 0x00, 0x00, // tag
    0x00, 0x00, 0x00, 0x00, // transfer length: 0
    0x00,                   // flags: host-to-device
    0x00,                   // LUN: 0
    0x06,                   // CB length: 6
    0x1B,                   // opcode: START STOP UNIT
    0x00,                   // Immed=0
    0x00, 0x00,             // reserved
    0x02,                   // LoEj=1, Start=0 (eject)
    0x00,                   // control
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn find_device(context: &rusb::Context, vid: u16, pid: u16) -> Option<rusb::Device<rusb::Context>> {
    for device in context.devices().ok()?.iter() {
        if let Ok(desc) = device.device_descriptor() {
            if desc.vendor_id() == vid && desc.product_id() == pid {
                return Some(device);
            }
        }
    }
    None
}

fn send_cbw(handle: &rusb::DeviceHandle<rusb::Context>, ep_out: u8, ep_in: u8, cbw: &[u8], name: &str, expect_data: usize) {
    let timeout = Duration::from_secs(3);

    // Send CBW
    match handle.write_bulk(ep_out, cbw, timeout) {
        Ok(n) => println!("  {} CBW sent ({} bytes)", name, n),
        Err(e) => {
            println!("  {} CBW send failed: {}", name, e);
            return;
        }
    }

    // Read data phase if expected
    if expect_data > 0 {
        let mut buf = vec![0u8; expect_data];
        match handle.read_bulk(ep_in, &mut buf, timeout) {
            Ok(n) => {
                println!("  {} data: {} bytes", name, n);
                if name == "INQUIRY" && n >= 36 {
                    let vendor = std::str::from_utf8(&buf[8..16]).unwrap_or("?").trim();
                    let product = std::str::from_utf8(&buf[16..32]).unwrap_or("?").trim();
                    println!("  SCSI device: '{}' '{}'", vendor, product);
                }
            }
            Err(e) => println!("  {} data read: {}", name, e),
        }
    }

    // Read CSW (use 512-byte buffer to avoid overflow from stale data)
    let mut csw = [0u8; 512];
    match handle.read_bulk(ep_in, &mut csw, timeout) {
        Ok(n) if n >= 13 && &csw[..4] == b"USBS" => {
            let status = csw[12];
            println!("  {} CSW status: {} ({})", name,
                status, if status == 0 { "OK" } else { "FAIL" });
        }
        Ok(n) => println!("  {} response: {} bytes (not a CSW: {:02x?})", name, n, &csw[..n.min(16)]),
        Err(e) => println!("  {} CSW: {} (may have disconnected)", name, e),
    }
}

fn find_realtek_wifi(context: &rusb::Context) -> Option<(u16, &'static str)> {
    for device in context.devices().ok()?.iter() {
        if let Ok(desc) = device.device_descriptor() {
            if desc.vendor_id() == VID_REALTEK {
                for &(pid, name) in REALTEK_WIFI_PIDS {
                    if desc.product_id() == pid {
                        return Some((pid, name));
                    }
                }
            }
        }
    }
    None
}

fn main() {
    println!("=== USB Mode Switch ===\n");

    let context = match rusb::Context::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to init libusb: {}", e);
            std::process::exit(1);
        }
    };

    // Try Realtek storage mode first (covers 8852AU, 8852BU, 8812BU, etc.)
    let device = if let Some(d) = find_device(&context, VID_REALTEK, PID_REALTEK_STORAGE) {
        println!("Found Realtek storage device ({:04X}:{:04X})", VID_REALTEK, PID_REALTEK_STORAGE);
        d
    } else if let Some(d) = find_device(&context, VID_MEDIATEK, PID_MT7612_CDROM) {
        println!("Found MediaTek CD-ROM device ({:04X}:{:04X})", VID_MEDIATEK, PID_MT7612_CDROM);
        d
    } else {
        // Check if already in WiFi mode
        if find_device(&context, VID_MEDIATEK, PID_MT7612_WIFI).is_some() {
            println!("MT7612U already in WiFi mode! ({:04X}:{:04X})", VID_MEDIATEK, PID_MT7612_WIFI);
            std::process::exit(0);
        }
        if let Some((pid, name)) = find_realtek_wifi(&context) {
            println!("{} already in WiFi mode! ({:04X}:{:04X})", name, VID_REALTEK, pid);
            std::process::exit(0);
        }
        eprintln!("No device in storage mode found. Is it plugged in?");
        std::process::exit(1);
    };

    println!("Found at bus {:03} addr {:03}", device.bus_number(), device.address());

    let handle: rusb::DeviceHandle<rusb::Context> = match device.open() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to open: {} (try sudo)", e);
            std::process::exit(1);
        }
    };

    let config = device.active_config_descriptor().expect("No config");
    let iface = config.interfaces().next().expect("No interfaces");
    let iface_desc = iface.descriptors().next().expect("No descriptors");
    let iface_num = iface_desc.interface_number();

    // Find bulk endpoints
    let mut ep_out: u8 = 0;
    let mut ep_in: u8 = 0;
    for ep in iface_desc.endpoint_descriptors() {
        if ep.transfer_type() == rusb::TransferType::Bulk {
            match ep.direction() {
                rusb::Direction::Out => ep_out = ep.address(),
                rusb::Direction::In => ep_in = ep.address(),
            }
        }
    }
    println!("Endpoints: OUT=0x{:02X} IN=0x{:02X}", ep_out, ep_in);

    // Detach kernel driver
    if let Ok(true) = handle.kernel_driver_active(iface_num) {
        println!("Detaching kernel driver...");
        if let Err(e) = handle.detach_kernel_driver(iface_num) {
            eprintln!("  detach failed: {} (continuing)", e);
        }
    }

    // Clear halt on both endpoints before claiming
    println!("Clearing endpoint halts...");
    let _ = handle.clear_halt(ep_out);
    let _ = handle.clear_halt(ep_in);

    // Claim interface
    if let Err(e) = handle.claim_interface(iface_num) {
        eprintln!("Failed to claim interface: {}", e);

        // Fallback: try device reset
        println!("Trying USB device reset...");
        match handle.reset() {
            Ok(()) => {
                println!("Reset sent. Waiting 3s...");
                std::thread::sleep(Duration::from_secs(3));
                check_result(&context);
            }
            Err(e) => eprintln!("Reset failed: {}", e),
        }
        return;
    }
    println!("Interface claimed.\n");

    // Clear halt again after claim
    let _ = handle.clear_halt(ep_out);
    let _ = handle.clear_halt(ep_in);

    // Drain any stale data from IN endpoint (e.g. SCSI sense data from previous attempts)
    println!("Draining stale data...");
    let mut drained = 0;
    for _ in 0..5 {
        let mut buf = [0u8; 512];
        match handle.read_bulk(ep_in, &mut buf, Duration::from_millis(200)) {
            Ok(n) => {
                println!("  Drained {} bytes", n);
                drained += n;
            }
            Err(_) => break,
        }
    }
    if drained > 0 {
        println!("  Total drained: {} bytes", drained);
    }

    // Step 1: TEST UNIT READY (wake up)
    println!("Step 1: TEST UNIT READY");
    send_cbw(&handle, ep_out, ep_in, &SCSI_TEST_UNIT_READY, "TUR", 0);

    // Step 2: INQUIRY (get device info)
    println!("Step 2: INQUIRY");
    send_cbw(&handle, ep_out, ep_in, &SCSI_INQUIRY, "INQUIRY", 36);

    // Step 3: EJECT (mode switch!)
    println!("Step 3: START STOP UNIT (eject)");
    send_cbw(&handle, ep_out, ep_in, &SCSI_EJECT, "EJECT", 0);

    let _ = handle.release_interface(iface_num);
    drop(handle);

    println!("\nWaiting for re-enumeration (3s)...");
    std::thread::sleep(Duration::from_secs(3));

    check_result(&context);
}

fn check_result(context: &rusb::Context) {
    // Check MediaTek
    if find_device(context, VID_MEDIATEK, PID_MT7612_WIFI).is_some() {
        println!("\n*** SUCCESS! MT7612U switched to WiFi mode! ***");
        println!("Device ready at {:04X}:{:04X}", VID_MEDIATEK, PID_MT7612_WIFI);
        return;
    }
    // Check Realtek WiFi PIDs
    if let Some((pid, name)) = find_realtek_wifi(context) {
        println!("\n*** SUCCESS! {} switched to WiFi mode! ***", name);
        println!("Device ready at {:04X}:{:04X}", VID_REALTEK, pid);
        return;
    }
    // Check if any new Realtek device appeared (unknown PID)
    for device in context.devices().unwrap().iter() {
        if let Ok(desc) = device.device_descriptor() {
            if desc.vendor_id() == VID_REALTEK && desc.product_id() != PID_REALTEK_STORAGE {
                println!("\n*** Realtek device appeared with PID {:04X}! ***", desc.product_id());
                println!("Device at {:04X}:{:04X} — add this PID to REALTEK_WIFI_PIDS",
                    VID_REALTEK, desc.product_id());
                return;
            }
        }
    }
    // Still in storage mode?
    if find_device(context, VID_REALTEK, PID_REALTEK_STORAGE).is_some()
        || find_device(context, VID_MEDIATEK, PID_MT7612_CDROM).is_some()
    {
        println!("\nStill in storage mode. Try unplugging and replugging.");
    } else {
        println!("\nDevice disconnected — replug it, should come back in WiFi mode.");
    }
}
