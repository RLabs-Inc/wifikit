//! Adapter discovery, identification, and lifecycle management.
//!
//! Matches the C implementation pattern:
//!   wifikit_init()           → UsbContext::new()
//!   wifikit_scan_adapters()  → scan_adapters()
//!   wifikit_open(vid, pid)   → Adapter::open(&AdapterInfo)
//!   wifikit_close()          → Adapter::close() / Drop
//!   wifikit_cleanup()        → UsbContext dropped

use super::{ChipDriver, MacAddress, Result, Error};
use super::chip::{ChipId, AdapterState, ChipInfo, identify_chip, find_adapter_name};

// ── USB endpoint discovery ──

/// Maximum number of bulk OUT endpoints to track (matches WIFIKIT_MAX_BULK_OUT from C)
const MAX_BULK_OUT: usize = 4;

/// USB endpoint information discovered during open.
#[derive(Debug, Clone)]
pub struct UsbEndpoints {
    pub bulk_in: u8,
    pub bulk_out: u8,
    pub bulk_out_all: Vec<u8>,
}

impl UsbEndpoints {
    /// Number of bulk OUT endpoints discovered.
    pub fn num_bulk_out(&self) -> usize {
        self.bulk_out_all.len()
    }
}

// ── AdapterInfo — Scan result (before opening) ──

/// Information about a discovered adapter, before it's opened.
/// Matches wifikit_adapter_info_t from C implementation.
#[derive(Debug, Clone)]
pub struct AdapterInfo {
    pub vid: u16,
    pub pid: u16,
    pub chip: ChipId,
    pub name: &'static str,
    pub bus: u8,
    pub address: u8,
}

// ── Adapter — An opened, active adapter ──

/// An opened USB WiFi adapter with its chip driver.
/// Matches wifikit_adapter_t from C implementation.
///
/// Lifecycle: scan_adapters() → Adapter::open() → init() → use → close()
pub struct Adapter {
    pub driver: Box<dyn ChipDriver>,
    pub info: AdapterInfo,
    pub endpoints: UsbEndpoints,
    pub state: AdapterState,
    pub real_mac: MacAddress,
    pub fake_mac: MacAddress,
}

impl Adapter {
    /// Open an adapter from scan results.
    /// Matches wifikit_open() from C implementation:
    ///   1. Open USB device by VID/PID
    ///   2. Detach kernel driver if active
    ///   3. Claim USB interface
    ///   4. Discover bulk endpoints
    ///   5. Create chip driver via dispatch
    ///   6. Return ready-to-init adapter
    pub fn open(info: &AdapterInfo) -> Result<Self> {
        let (driver, endpoints) = crate::chips::create_driver(info)?;

        Ok(Self {
            driver,
            info: info.clone(),
            endpoints,
            state: AdapterState::Opened,
            real_mac: MacAddress::ZERO,
            fake_mac: MacAddress::ZERO,
        })
    }

    /// Initialize the adapter: power on, load firmware, configure hardware.
    /// Generates a locally-administered MAC (matches C get_our_mac() behavior).
    /// After this, the adapter is ready for monitor mode.
    pub fn init(&mut self) -> Result<()> {
        self.driver.init()?;

        // Generate a locally-administered unicast MAC, matching get_our_mac() from C.
        // The C version uses adapter pointer + pid as seed. We use bus + address + pid.
        let seed = (self.info.bus as u64) << 40
            | (self.info.address as u64) << 32
            | (self.info.vid as u64) << 16
            | self.info.pid as u64;
        let mac = MacAddress::randomized_with_seed([0x02, 0xE0, 0x2B], seed);
        self.driver.set_mac(mac)?;
        self.real_mac = mac;
        self.fake_mac = mac;
        self.state = AdapterState::Initialized;
        Ok(())
    }

    /// Enter monitor mode for packet capture and injection.
    pub fn set_monitor_mode(&mut self) -> Result<()> {
        self.driver.set_monitor_mode()?;
        self.state = AdapterState::Monitor;
        Ok(())
    }

    /// Get the current (possibly spoofed) MAC address.
    pub fn mac(&self) -> MacAddress {
        self.fake_mac
    }

    /// Spoof the MAC address. Stores both real and fake.
    pub fn set_mac(&mut self, mac: MacAddress) -> Result<()> {
        self.driver.set_mac(mac)?;
        self.fake_mac = mac;
        Ok(())
    }

    /// Restore the original MAC address.
    pub fn restore_mac(&mut self) -> Result<()> {
        self.driver.set_mac(self.real_mac)?;
        self.fake_mac = self.real_mac;
        Ok(())
    }

    /// Get chip info from the live driver.
    pub fn chip_info(&self) -> ChipInfo {
        self.driver.chip_info()
    }

    /// Shut down the adapter. Releases USB resources.
    pub fn close(&mut self) -> Result<()> {
        self.driver.shutdown()?;
        self.state = AdapterState::Closed;
        Ok(())
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        if self.state != AdapterState::Closed {
            // Error safe to ignore: best-effort USB cleanup in Drop, can't propagate errors
            let _ = self.driver.shutdown();
        }
    }
}

// ── scan_adapters — USB enumeration with chip identification ──

/// Scan for compatible USB WiFi adapters.
/// Matches wifikit_scan_adapters() from C implementation:
///   1. Enumerate all USB devices
///   2. Check each VID/PID against KNOWN_ADAPTERS registry
///   3. Return info for all recognized adapters
pub fn scan_adapters() -> Result<Vec<AdapterInfo>> {
    let mut found = Vec::new();
    let devices = rusb::devices().map_err(Error::Usb)?;

    for device in devices.iter() {
        let desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue,
        };

        let vid = desc.vendor_id();
        let pid = desc.product_id();

        // Look up in registry — matches identify_chip() from C
        let chip = match identify_chip(vid, pid) {
            Some(c) => c,
            None => continue,
        };

        // Get name from registry — matches find_adapter_name() from C
        let name = find_adapter_name(vid, pid).unwrap_or("Unknown Adapter");

        found.push(AdapterInfo {
            vid,
            pid,
            chip,
            name,
            bus: device.bus_number(),
            address: device.address(),
        });
    }

    Ok(found)
}


/// Discover bulk IN and OUT endpoints from a USB device's active config.
/// Matches the endpoint discovery loop in wifikit_open() from C.
pub fn discover_endpoints(device: &rusb::Device<rusb::GlobalContext>) -> Result<UsbEndpoints> {
    let config = device.active_config_descriptor().map_err(Error::Usb)?;

    let iface = config
        .interfaces()
        .next()
        .ok_or(Error::ChipInitFailed {
            chip: "unknown".into(),
            stage: crate::core::error::InitStage::UsbEnumeration,
            reason: "no USB interfaces found".into(),
        })?;

    let alt = iface
        .descriptors()
        .next()
        .ok_or(Error::ChipInitFailed {
            chip: "unknown".into(),
            stage: crate::core::error::InitStage::UsbEnumeration,
            reason: "no interface descriptors found".into(),
        })?;

    let mut bulk_in: Option<u8> = None;
    let mut bulk_out_first: Option<u8> = None;
    let mut bulk_out_all = Vec::new();

    for ep in alt.endpoint_descriptors() {
        use rusb::TransferType;
        if ep.transfer_type() != TransferType::Bulk {
            continue;
        }

        if ep.address() & 0x80 != 0 {
            // IN endpoint
            if bulk_in.is_none() {
                bulk_in = Some(ep.address());
            }
        } else {
            // OUT endpoint
            if bulk_out_all.len() < MAX_BULK_OUT {
                bulk_out_all.push(ep.address());
            }
            if bulk_out_first.is_none() {
                bulk_out_first = Some(ep.address());
            }
        }
    }

    let bulk_in = bulk_in.ok_or(Error::EndpointNotFound {
        direction: "bulk IN",
        vid: 0,
        pid: 0,
    })?;
    let bulk_out = bulk_out_first.ok_or(Error::EndpointNotFound {
        direction: "bulk OUT",
        vid: 0,
        pid: 0,
    })?;

    Ok(UsbEndpoints {
        bulk_in,
        bulk_out,
        bulk_out_all,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_adapters_returns_vec() {
        // Just verify it doesn't panic — actual USB may or may not be present
        let result = scan_adapters();
        assert!(result.is_ok());
    }

    #[test]
    fn test_usb_endpoints_num_bulk_out() {
        let ep = UsbEndpoints {
            bulk_in: 0x84,
            bulk_out: 0x02,
            bulk_out_all: vec![0x02, 0x03, 0x04],
        };
        assert_eq!(ep.num_bulk_out(), 3);
    }

    #[test]
    fn test_adapter_info_clone() {
        let info = AdapterInfo {
            vid: 0x2357,
            pid: 0x0115,
            chip: ChipId::Rtl8812bu,
            name: "TP-Link Archer T4U V3 (RTL8812BU)",
            bus: 1,
            address: 3,
        };
        let cloned = info.clone();
        assert_eq!(cloned.vid, 0x2357);
        assert_eq!(cloned.chip, ChipId::Rtl8812bu);
    }
}
