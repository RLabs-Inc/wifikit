use rusb::UsbContext;
use std::time::Duration;

const VID: u16 = 0x0BDA;
const PID_DISK: u16 = 0x1A2B;

// SCSI Command Block Wrappers (31 bytes each)

// TEST UNIT READY
const CBW_TUR: [u8; 31] = [
    0x55, 0x53, 0x42, 0x43, // "USBC"
    0x01, 0x00, 0x00, 0x00, // tag=1
    0x00, 0x00, 0x00, 0x00, // transfer length: 0
    0x00, 0x00, 0x06,       // flags=H2D, LUN=0, CB len=6
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TEST UNIT READY
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// INQUIRY (request 36 bytes)
const CBW_INQUIRY: [u8; 31] = [
    0x55, 0x53, 0x42, 0x43, // "USBC"
    0x02, 0x00, 0x00, 0x00, // tag=2
    0x24, 0x00, 0x00, 0x00, // transfer length: 36
    0x80, 0x00, 0x06,       // flags=D2H, LUN=0, CB len=6
    0x12, 0x00, 0x00, 0x00, 0x24, 0x00, // INQUIRY, alloc=36
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// START STOP UNIT — eject (standard)
const CBW_EJECT: [u8; 31] = [
    0x55, 0x53, 0x42, 0x43, // "USBC"
    0x03, 0x00, 0x00, 0x00, // tag=3
    0x00, 0x00, 0x00, 0x00, // transfer length: 0
    0x00, 0x00, 0x06,       // flags=H2D, LUN=0, CB len=6
    0x1B, 0x00, 0x00, 0x00, 0x02, 0x00, // START STOP UNIT, LoEj=1 Start=0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Realtek vendor 0xF0 switch
const CBW_RTK_F0: [u8; 31] = [
    0x55, 0x53, 0x42, 0x43, // "USBC"
    0x04, 0x00, 0x00, 0x00, // tag=4
    0x00, 0x00, 0x00, 0x00, // transfer length: 0
    0x00, 0x00, 0x06,       // flags=H2D, LUN=0, CB len=6
    0xF0, 0x01, 0x00, 0x00, 0x00, 0x00, // Realtek vendor switch
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ALLOW MEDIUM REMOVAL (unlock first, some devices need this before eject)
const CBW_ALLOW_REMOVAL: [u8; 31] = [
    0x55, 0x53, 0x42, 0x43, // "USBC"
    0x05, 0x00, 0x00, 0x00, // tag=5
    0x00, 0x00, 0x00, 0x00, // transfer length: 0
    0x00, 0x00, 0x06,       // flags=H2D, LUN=0, CB len=6
    0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, // PREVENT ALLOW MEDIUM REMOVAL, allow=0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn send_cbw(
    handle: &rusb::DeviceHandle<rusb::Context>,
    ep_out: u8,
    ep_in: u8,
    cbw: &[u8],
    name: &str,
    data_len: usize,
) -> bool {
    let timeout = Duration::from_secs(3);

    // Send CBW
    match handle.write_bulk(ep_out, cbw, timeout) {
        Ok(n) => print!("  {}: sent {} bytes", name, n),
        Err(e) => {
            println!("  {}: send failed — {} (device may have disconnected)", name, e);
            return false;
        }
    }

    // Data phase (device-to-host)
    if data_len > 0 {
        let mut buf = vec![0u8; data_len];
        match handle.read_bulk(ep_in, &mut buf, timeout) {
            Ok(n) => {
                print!(", data={} bytes", n);
                if name == "INQUIRY" && n >= 36 {
                    let vendor = std::str::from_utf8(&buf[8..16]).unwrap_or("?").trim();
                    let product = std::str::from_utf8(&buf[16..32]).unwrap_or("?").trim();
                    let revision = std::str::from_utf8(&buf[32..36]).unwrap_or("?").trim();
                    println!();
                    println!("         SCSI: '{}' '{}' rev '{}'", vendor, product, revision);
                    print!("        ");
                }
            }
            Err(e) => print!(", data: {}", e),
        }
    }

    // Read CSW (13 bytes)
    let mut csw = [0u8; 13];
    match handle.read_bulk(ep_in, &mut csw, timeout) {
        Ok(n) if n >= 13 && csw[0..4] == [0x55, 0x53, 0x42, 0x53] => {
            let status = csw[12];
            println!(", CSW={}", if status == 0 { "OK" } else { "FAIL" });
        }
        Ok(n) => println!(", CSW={} bytes (unexpected)", n),
        Err(e) => {
            println!(", CSW: {} (device likely disconnected!)", e);
            return false; // device disconnected = success!
        }
    }
    true
}

fn main() {
    println!("=== Realtek USB Mode Switch ===");
    println!("Looking for DISK mode {:04X}:{:04X}...\n", VID, PID_DISK);

    let ctx = rusb::Context::new().expect("libusb init");

    let device = ctx.devices().unwrap().iter().find(|d| {
        d.device_descriptor()
            .map(|desc| desc.vendor_id() == VID && desc.product_id() == PID_DISK)
            .unwrap_or(false)
    });

    let device = match device {
        Some(d) => d,
        None => {
            println!("DISK mode device not found. Scanning for Realtek WiFi devices...");
            for d in ctx.devices().unwrap().iter() {
                if let Ok(desc) = d.device_descriptor() {
                    if desc.vendor_id() == VID && desc.product_id() != PID_DISK {
                        print!("  {:04X}:{:04X}", VID, desc.product_id());
                        identify_chip(desc.product_id());
                        println!(" (already in WiFi mode!)");
                    }
                }
            }
            return;
        }
    };

    let desc = device.device_descriptor().unwrap();
    println!("Found: bus {} addr {}", device.bus_number(), device.address());
    println!("  bcdDevice: {}.{}", desc.device_version().0, desc.device_version().1);

    let handle = device.open().expect("Failed to open (need sudo)");

    if let Ok(s) = handle.read_manufacturer_string_ascii(&desc) {
        println!("  Manufacturer: {}", s);
    }
    if let Ok(s) = handle.read_product_string_ascii(&desc) {
        println!("  Product: {}", s);
    }

    // Dump all interfaces and endpoints
    let config = device.active_config_descriptor().expect("No config");
    println!("  Interfaces: {}", config.num_interfaces());
    for iface in config.interfaces() {
        for idesc in iface.descriptors() {
            println!("    iface {} alt {} class {:02X}:{:02X}:{:02X} eps={}",
                idesc.interface_number(),
                idesc.setting_number(),
                idesc.class_code(),
                idesc.sub_class_code(),
                idesc.protocol_code(),
                idesc.num_endpoints(),
            );
            for ep in idesc.endpoint_descriptors() {
                println!("      EP 0x{:02X} {:?} {:?} maxpkt={}",
                    ep.address(),
                    ep.direction(),
                    ep.transfer_type(),
                    ep.max_packet_size(),
                );
            }
        }
    }

    let iface = config.interfaces().next().expect("No interface");
    let iface_desc = iface.descriptors().next().expect("No descriptor");
    let iface_num = iface_desc.interface_number();

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

    if let Ok(true) = handle.kernel_driver_active(iface_num) {
        let _ = handle.detach_kernel_driver(iface_num);
        println!("  Detached kernel driver");
    }

    let _ = handle.clear_halt(ep_out);
    let _ = handle.clear_halt(ep_in);
    handle.claim_interface(iface_num).expect("Failed to claim");
    println!("\n--- SCSI sequence ---\n");

    // Step 1: Wake up
    println!("Step 1: TEST UNIT READY");
    if !send_cbw(&handle, ep_out, ep_in, &CBW_TUR, "TUR", 0) {
        wait_and_scan();
        return;
    }

    // Step 2: Identify
    println!("Step 2: INQUIRY");
    if !send_cbw(&handle, ep_out, ep_in, &CBW_INQUIRY, "INQUIRY", 36) {
        wait_and_scan();
        return;
    }

    // Step 3: Allow medium removal (unlock)
    println!("Step 3: ALLOW MEDIUM REMOVAL");
    if !send_cbw(&handle, ep_out, ep_in, &CBW_ALLOW_REMOVAL, "UNLOCK", 0) {
        wait_and_scan();
        return;
    }

    // Step 4: Try Realtek vendor command first
    println!("Step 4: Realtek vendor switch (0xF0)");
    if !send_cbw(&handle, ep_out, ep_in, &CBW_RTK_F0, "RTK-F0", 0) {
        wait_and_scan();
        return;
    }

    std::thread::sleep(Duration::from_secs(1));
    if check_switched() {
        return;
    }

    // Step 5: Standard eject
    println!("Step 5: SCSI EJECT");
    if !send_cbw(&handle, ep_out, ep_in, &CBW_EJECT, "EJECT", 0) {
        wait_and_scan();
        return;
    }

    std::thread::sleep(Duration::from_secs(1));
    if check_switched() {
        return;
    }

    // Step 6: USB reset as last resort
    println!("Step 6: USB device reset");
    match handle.reset() {
        Ok(()) => println!("  Reset OK"),
        Err(e) => println!("  Reset: {}", e),
    }

    let _ = handle.release_interface(iface_num);
    drop(handle);

    wait_and_scan();
}

fn wait_and_scan() {
    println!("\nWaiting 5s for re-enumeration...");
    std::thread::sleep(Duration::from_secs(5));

    println!("\n--- USB scan ---\n");
    let ctx = rusb::Context::new().unwrap();
    let mut found = false;
    for d in ctx.devices().unwrap().iter() {
        if let Ok(desc) = d.device_descriptor() {
            if desc.vendor_id() == VID {
                found = true;
                let pid = desc.product_id();
                if pid == PID_DISK {
                    println!("  {:04X}:{:04X} — still DISK mode", VID, pid);
                    println!("  → Try: unplug, wait 5s, replug");
                } else {
                    print!("  {:04X}:{:04X} — WiFi mode!", VID, pid);
                    identify_chip(pid);
                    println!();
                }
            }
        }
    }
    if !found {
        println!("  No Realtek device — unplug/replug should bring it back in WiFi mode");
    }
}

fn check_switched() -> bool {
    let ctx = rusb::Context::new().unwrap();
    for d in ctx.devices().unwrap().iter() {
        if let Ok(desc) = d.device_descriptor() {
            if desc.vendor_id() == VID && desc.product_id() != PID_DISK {
                print!("\n  SUCCESS! {:04X}:{:04X}", VID, desc.product_id());
                identify_chip(desc.product_id());
                println!();
                return true;
            }
        }
    }
    false
}

fn identify_chip(pid: u16) {
    match pid {
        0xB812 => print!(" — RTL8812BU (AC1200, 2T2R)"),
        0xB82C => print!(" — RTL8822BU (AC1200, 2T2R, BT)"),
        0xC811 => print!(" — RTL8811CU (AC600, 1T1R)"),
        0xC821 => print!(" — RTL8821CU (AC600, 1T1R, BT)"),
        0xC82C => print!(" — RTL8822CU (AC1200, 2T2R, BT)"),
        0x8812 => print!(" — RTL8812AU (AC1200, 2T2R)"),
        0xC820 => print!(" — RTL8821AU (AC600, 1T1R)"),
        0xA8A5 => print!(" — RTL8852AU (WiFi 6, AX1800, 2T2R)"),
        0x885A | 0xA85A => print!(" — RTL8852BU (WiFi 6, AX1800, 2T2R)"),
        0x886A => print!(" — RTL8852CU (WiFi 6E)"),
        0xB832 | 0xB83A => print!(" — RTL8832BU (WiFi 6E, AXE3000)"),
        0xB852 => print!(" — RTL8852BU (WiFi 6)"),
        0x4853 => print!(" — RTL8852AE (WiFi 6, AX1800, PCIe-via-USB?)"),
        // WiFi 6E tri-band candidates (AXE5400)
        0x8832 => print!(" — RTL8832AU (WiFi 6E, AXE5400, tri-band!)"),
        0xA832 => print!(" — RTL8832AU variant (WiFi 6E)"),
        // WiFi 7
        0x8922 | 0xA922 | 0xB922 => print!(" — RTL8922 (WiFi 7, BE)"),
        _ => print!(" — Unknown Realtek (0x{:04X})", pid),
    }
}
