// USB 2→3 mode switch for RTL8852AU
// Reads R_AX_USB_STATUS to confirm USB2, then writes U2SWITCHU3 to R_AX_PAD_CTRL2+2
// Device will disconnect and re-enumerate on USB 3.0 as "802.11ax WLAN Adapter"

use rusb::{Context, UsbContext};
use std::time::Duration;

const VID_TPLINK: u16 = 0x2357;
const PID_8852AU: u16 = 0x013F;
const VID_RTL: u16 = 0x0BDA;
// Some 8852AU devices use Realtek VID instead of TP-Link

// Register addresses
const R_AX_USB_STATUS: u16 = 0x11F0;
const R_AX_PAD_CTRL2: u16 = 0x00C4;

// Bits
const B_AX_R_USB2_SEL: u32 = 1 << 1;  // bit 1: 1=USB3, 0=USB2
const B_AX_MODE_HS: u32 = 1 << 0;     // bit 0: High Speed mode

// USB switch values
const USB_SWITCH_DELAY: u8 = 0x0F;
const U2SWITCHU3: u8 = 0x0B;

const RTL_USB_REQ: u8 = 0x05;
const TIMEOUT: Duration = Duration::from_millis(500);

fn read32(handle: &rusb::DeviceHandle<Context>, addr: u16) -> Result<u32, rusb::Error> {
    let mut buf = [0u8; 4];
    handle.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, TIMEOUT)?;
    Ok(u32::from_le_bytes(buf))
}

fn write8(handle: &rusb::DeviceHandle<Context>, addr: u16, val: u8) -> Result<(), rusb::Error> {
    handle.write_control(0x40, RTL_USB_REQ, addr, 0, &[val], TIMEOUT)?;
    Ok(())
}

fn read8(handle: &rusb::DeviceHandle<Context>, addr: u16) -> Result<u8, rusb::Error> {
    let mut buf = [0u8; 1];
    handle.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, TIMEOUT)?;
    Ok(buf[0])
}

fn main() {
    println!("=== RTL8852AU USB 2→3 Mode Switch ===\n");

    let context = Context::new().expect("Failed to init libusb");

    // Find the device (try TP-Link VID first, then Realtek VID)
    let device = context.devices().unwrap().iter()
        .find(|d| {
            if let Ok(desc) = d.device_descriptor() {
                (desc.vendor_id() == VID_TPLINK && desc.product_id() == PID_8852AU) ||
                (desc.vendor_id() == VID_RTL && desc.product_id() == PID_8852AU)
            } else {
                false
            }
        });

    let device = match device {
        Some(d) => d,
        None => {
            eprintln!("RTL8852AU not found (2357:013f). Is it in WiFi mode?");
            eprintln!("If it shows as 'DISK', eject it first: diskutil eject diskN");
            std::process::exit(1);
        }
    };

    let desc = device.device_descriptor().unwrap();
    println!("Found: {:04x}:{:04x} at bus {} addr {}",
        desc.vendor_id(), desc.product_id(),
        device.bus_number(), device.address());
    println!("USB bcdUSB: {}.{}", desc.usb_version().major(), desc.usb_version().minor());
    println!("Speed: {:?}", device.speed());

    let handle = device.open().expect("Failed to open device (try sudo)");

    // Read current USB mode
    let usb_status = read32(&handle, R_AX_USB_STATUS).expect("Failed to read USB_STATUS");
    let is_usb3 = (usb_status & B_AX_R_USB2_SEL) != 0;
    let is_hs = (usb_status & B_AX_MODE_HS) != 0;

    println!("\nR_AX_USB_STATUS (0x{:04X}) = 0x{:08X}", R_AX_USB_STATUS, usb_status);
    println!("  USB2_SEL (bit 1) = {} → {}", (usb_status >> 1) & 1,
        if is_usb3 { "USB 3.0" } else { "USB 2.0" });
    println!("  MODE_HS (bit 0)  = {} → {}", usb_status & 1,
        if is_hs { "High Speed" } else { "Full/Low Speed" });

    if is_usb3 {
        println!("\nAlready in USB 3.0 mode! No switch needed.");
        return;
    }

    println!("\nCurrently USB 2.0. Switching to USB 3.0...");

    // Read current PAD_CTRL2
    let pad = read32(&handle, R_AX_PAD_CTRL2).expect("Failed to read PAD_CTRL2");
    println!("R_AX_PAD_CTRL2 (0x{:04X}) = 0x{:08X}", R_AX_PAD_CTRL2, pad);

    // Step 1: Set switch delay
    println!("\nStep 1: Write USB_SWITCH_DELAY (0x{:02X}) to PAD_CTRL2+1 (0x{:04X})",
        USB_SWITCH_DELAY, R_AX_PAD_CTRL2 + 1);
    write8(&handle, R_AX_PAD_CTRL2 + 1, USB_SWITCH_DELAY)
        .expect("Failed to write switch delay");

    // Verify
    let v = read8(&handle, R_AX_PAD_CTRL2 + 1).expect("Failed to read back");
    println!("  Readback: 0x{:02X}", v);

    // Step 2: Trigger the switch
    println!("\nStep 2: Write U2SWITCHU3 (0x{:02X}) to PAD_CTRL2+2 (0x{:04X})",
        U2SWITCHU3, R_AX_PAD_CTRL2 + 2);
    println!("  Device will disconnect and re-enumerate on USB 3.0...");

    match write8(&handle, R_AX_PAD_CTRL2 + 2, U2SWITCHU3) {
        Ok(()) => println!("  Switch command sent!"),
        Err(e) => {
            // Device may disconnect immediately, causing a pipe error
            println!("  Write returned: {} (expected if device disconnected)", e);
        }
    }

    drop(handle);

    println!("\nWaiting 5 seconds for re-enumeration...");
    std::thread::sleep(Duration::from_secs(5));

    // Re-scan
    let context2 = Context::new().expect("Failed to reinit libusb");
    let found = context2.devices().unwrap().iter().find(|d| {
        if let Ok(desc) = d.device_descriptor() {
            (desc.vendor_id() == VID_TPLINK && desc.product_id() == PID_8852AU) ||
            (desc.vendor_id() == VID_RTL && desc.product_id() == PID_8852AU)
        } else {
            false
        }
    });

    match found {
        Some(d) => {
            let desc = d.device_descriptor().unwrap();
            println!("\n*** Device re-appeared! ***");
            println!("  {:04x}:{:04x} speed={:?}",
                desc.vendor_id(), desc.product_id(), d.speed());

            if let Ok(h) = d.open() {
                match read32(&h, R_AX_USB_STATUS) {
                    Ok(status) => {
                        let usb3 = (status & B_AX_R_USB2_SEL) != 0;
                        println!("  USB_STATUS = 0x{:08X} → {}",
                            status, if usb3 { "USB 3.0 ✓" } else { "Still USB 2.0 ✗" });
                    }
                    Err(e) => println!("  Could not read USB_STATUS: {}", e),
                }
            }
        }
        None => {
            println!("\nDevice not found after switch. It may need a moment to re-enumerate.");
            println!("Check: ioreg -p IOUSB | grep -i wlan");
        }
    }
}
