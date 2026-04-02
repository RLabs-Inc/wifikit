//! Chip driver registry and dispatch.
//!
//! Matches the C pattern:
//!   get_chip_ops(chip)  → create_driver(info)
//!   extern chip_ops_t   → mod rtl8812bu, mod mt7921au, mod mt76x1
//!
//! To add a new chip:
//!   1. Add VID/PID entries to KNOWN_ADAPTERS in core/chip.rs
//!   2. Add ChipId variant in core/chip.rs
//!   3. Create chips/new_chip.rs implementing ChipDriver
//!   4. Add match arm in create_driver() below

mod rtl8822b_tables;
mod rtl8812a_tables;
mod rtl8812a_fw;
mod rtl8852a_tables;
mod rtl8852a_post_boot;
mod rtl8852a_pre_fwdl;
mod rtl8852a_phase_pre_fwdl;
mod rtl8852a_phase_post_fwdl;
mod rtl8852a_phase_inter_fwdl;
mod rtl8852a_phase_monitor;
mod rtl8852a_phase_ch1;
mod rtl8852a_phase_ch6_2g;
mod rtl8852a_phase_ch11_2g;
mod rtl8852a_phase_ch36_5g;
mod rtl8852a_phase_ch48_5g;
mod rtl8852a_phase_ch149_5g;
mod rtl8852a_phase_ch165_5g;
mod rtl8852a_phase_txpower;
mod rtl8852a_phase_rxtx;
pub mod rtl8852a_full_init;
pub mod rtl8812au;
pub mod rtl8812bu;
pub mod rtl8852au;
pub mod mt7921au;
pub mod mt7612u;

pub use rtl8812au::Rtl8812au;
pub use rtl8812bu::Rtl8812bu;
pub use rtl8852au::Rtl8852au;
pub use mt7921au::Mt7921au;
pub use mt7612u::Mt7612u;

use crate::core::{ChipDriver, Result, Error};
use crate::core::chip::ChipId;
use crate::core::adapter::{AdapterInfo, UsbEndpoints};

/// Create the appropriate chip driver for a discovered adapter.
/// Matches get_chip_ops() dispatch from C implementation, but also handles
/// USB open + endpoint discovery (since Rust drivers own their USB handle).
///
/// Flow: open USB → discover endpoints → construct chip-specific driver
pub fn create_driver(info: &AdapterInfo) -> Result<(Box<dyn ChipDriver>, UsbEndpoints)> {
    match info.chip {
        ChipId::Rtl8812au => {
            let (driver, endpoints) = Rtl8812au::open_usb(info.vid, info.pid)?;
            Ok((Box::new(driver), endpoints))
        }
        ChipId::Rtl8812bu => {
            let (driver, endpoints) = Rtl8812bu::open_usb(info.vid, info.pid)?;
            Ok((Box::new(driver), endpoints))
        }
        ChipId::Rtl8852au => {
            let (driver, endpoints) = Rtl8852au::open_usb(info.vid, info.pid)?;
            Ok((Box::new(driver), endpoints))
        }
        ChipId::Mt7921au => {
            let (driver, endpoints) = Mt7921au::open_usb(info.vid, info.pid)?;
            Ok((Box::new(driver), endpoints))
        }
        ChipId::Mt7612u => {
            let (driver, endpoints) = Mt7612u::open_usb(info.vid, info.pid)?;
            Ok((Box::new(driver), endpoints))
        }
        ChipId::Mt76x1 => {
            Err(Error::UnsupportedChip { vid: info.vid, pid: info.pid })
        }
    }
}
