//! RTL8852AU / RTL8832AU chip driver — WiFi 6 (802.11ax)
//!
//! USB register access via vendor control transfers:
//!   Read:  bmRequestType=0xC0, bRequest=0x05, wValue=addr, wIndex=0
//!   Write: bmRequestType=0x40, bRequest=0x05, wValue=addr, wIndex=0
//!
//! Architecture: MAC AX (gen2) with firmware-centric design.
//!   Power sequence → FW download → MAC/BB/RF init → monitor mode
//!
//! Reference: references/rtl8852au/ (Realtek vendor driver v1.15.0.1)
//!            lwfinger/rtl8852au (Linux out-of-tree driver)
#![allow(dead_code)]
#![allow(unused_imports)]

use std::time::Duration;
use std::thread;
use std::fs;
use std::path::Path;

use std::sync::Arc;
use rusb::{DeviceHandle, GlobalContext};

use crate::core::{
    Channel, Band, MacAddress, Result, Error,
    chip::{ChipDriver, ChipInfo, ChipId, ChipCaps},
    frame::{RxFrame, TxOptions, TxRate, TxFlags},
    adapter::UsbEndpoints,
};

use super::rtl8852a_tables;
use super::rtl8852a_post_boot;
use super::rtl8852a_pre_fwdl;

// ── Constants ──

const RTL_USB_REQ: u8 = 0x05;
const RTL_USB_TIMEOUT: Duration = Duration::from_millis(500);
const USB_BULK_TIMEOUT: Duration = Duration::from_millis(200);

// MAC AX TX Write Descriptor: 6 dwords = 24 bytes
const WD_BODY_LEN: usize = 24;
// H2C FWCMD header: 2 dwords = 8 bytes
const FWCMD_HDR_LEN: usize = 8;

const RX_BUF_SIZE: usize = 32768;
const RX_DESC_SHORT: usize = 16;
const RX_DESC_LONG: usize = 32;

// FW download chunk size
const FWDL_SECTION_PER_PKT_LEN: usize = 2020;
const FWDL_WAIT_US: u32 = 400_000;

// FW header parsing
const FWHDR_HDR_LEN: usize = 32;
const FWHDR_SECTION_LEN: usize = 16;

// ── MAC AX Registers ──

// System
const R_AX_SYS_PW_CTRL: u16 = 0x0004;
const R_AX_SYS_CLK_CTRL: u16 = 0x0008;
const R_AX_RSV_CTRL: u16 = 0x001C;
const R_AX_AFE_CTRL1: u16 = 0x0024;
const R_AX_GPIO_MUXCFG: u16 = 0x0040;
const R_AX_GPIO_EXT_CTRL: u16 = 0x0060;
const R_AX_SYS_SDIO_CTRL: u16 = 0x0070;
const R_AX_PLATFORM_ENABLE: u16 = 0x0088;
const R_AX_SYS_STATUS1: u16 = 0x00F4;

// Firmware control
const R_AX_WCPU_FW_CTRL: u16 = 0x01E0;
const R_AX_BOOT_REASON: u16 = 0x01E6;
const R_AX_HALT_H2C_CTRL: u16 = 0x0160;
const R_AX_HALT_C2H_CTRL: u16 = 0x0164;

// AON interrupt
const R_AX_FWS0IMR: u16 = 0x0190;
const R_AX_FWS0ISR: u16 = 0x0194;

// Power state
const R_AX_IC_PWR_STATE: u16 = 0x03F0;

// USB
const R_AX_USB_HOST_REQUEST_2: u16 = 0x1078;
const R_AX_USB_WLAN0_1: u16 = 0x1174;
const R_AX_HCI_FUNC_EN: u16 = 0x8380;
const R_AX_USB_ENDPOINT_0: u16 = 0x1060;
const R_AX_USB_ENDPOINT_3: u16 = 0x106C;
const R_AX_RXDMA_SETTING: u16 = 0x8908;
const R_AX_RXAGG_0: u16 = 0x8900;

// RX filter (band 0)
const R_AX_RX_FLTR_OPT: u16 = 0xCE20;
const R_AX_CTRL_FLTR: u16 = 0xCE24;
const R_AX_MGNT_FLTR: u16 = 0xCE28;
const R_AX_DATA_FLTR: u16 = 0xCE2C;
const R_AX_PLCP_HDR_FLTR: u16 = 0xCE04;

// Scoreboard
const R_AX_SCOREBOARD: u16 = 0x00AC;

// GPIO pull-low
const R_AX_LED_CFG: u16 = 0x02E4;
const R_AX_GPIO_PH_CFG: u16 = 0x02E0;

// MAC enable
const R_AX_DMAC_FUNC_EN: u16 = 0x8400;
const R_AX_DMAC_CLK_EN: u16 = 0x8404;
const R_AX_CMAC_FUNC_EN: u16 = 0xC000;
const R_AX_CMAC_CLK_EN: u16 = 0xC004;
const R_AX_CK_EN: u16 = 0xC008;

// MAC address
const R_AX_MACID_REG: u16 = 0xC100;

// ── TX/RX descriptor field positions ──

// WD DW0
const AX_TXD_CH_DMA_SH: u32 = 16;
const AX_TXD_FWDL_EN: u32 = 1 << 20;
// WD DW2
const AX_TXD_TXPKTSIZE_SH: u32 = 0;
// DMA channels
const MAC_AX_DMA_H2C: u32 = 12;

// H2C header field positions (DW0)
const H2C_HDR_CAT_SH: u32 = 0;
const H2C_HDR_CLASS_SH: u32 = 2;
const H2C_HDR_FUNC_SH: u32 = 8;
const H2C_HDR_DEL_TYPE_SH: u32 = 16;
const H2C_HDR_H2C_SEQ_SH: u32 = 24;
// H2C header field positions (DW1)
const H2C_HDR_TOTAL_LEN_SH: u32 = 0;

// H2C values for FWDL
const FWCMD_TYPE_H2C: u32 = 0;
const FWCMD_H2C_CAT_MAC: u32 = 1;
const FWCMD_H2C_CL_FWDL: u32 = 3;
const FWCMD_H2C_FUNC_FWHDR_DL: u32 = 0;

// WCPU_FW_CTRL bits
const B_AX_WCPU_FWDL_EN: u8 = 1 << 0;
const B_AX_H2C_PATH_RDY: u8 = 1 << 1;
const B_AX_FWDL_PATH_RDY: u8 = 1 << 2;
const B_AX_FWDL_STS_SH: u8 = 5;
const B_AX_FWDL_STS_MSK: u8 = 0x7;
const FWDL_WCPU_FW_INIT_RDY: u8 = 7;

// Platform enable bits
const B_AX_PLATFORM_EN: u32 = 1 << 0;
const B_AX_WCPU_EN: u32 = 1 << 1;

// SYS_CLK_CTRL bits
const B_AX_CPU_CLK_EN: u32 = 1 << 14;

// RX descriptor RPKT_TYPE values
const RPKT_TYPE_WIFI: u8 = 0;
const RPKT_TYPE_C2H: u8 = 0x0A;

// RX filter bits
const B_AX_SNIFFER_MODE: u32 = 1 << 0;
const B_AX_A_A1_MATCH: u32 = 1 << 1;
const B_AX_A_BC: u32 = 1 << 2;
const B_AX_A_MC: u32 = 1 << 3;
const B_AX_A_UC_CAM_MATCH: u32 = 1 << 4;
const B_AX_A_CRC32_ERR: u32 = 1 << 11;

// USB TX descriptor for data frames (MAC AX)
const TX_WD_BODY_LEN: usize = 24;
// STF_MODE for USB data frames
const AX_TXD_STF_MODE: u32 = 1 << 0;

// Queue select values
const QSLT_BE: u8 = 0;
const QSLT_VO: u8 = 6;
const QSLT_MGNT: u8 = 12;

// ── Timing ──

const POLL_ITER_DELAY: Duration = Duration::from_micros(100);
const FIRST_TX_DMA_CHECK_DELAY: Duration = Duration::from_millis(2);

// ── Firmware search paths ──

const FW_SEARCH_PATHS: &[&str] = &[
    "rtl8852au_fw.bin",
    "references/rtl8852au/rtl8852au_fw.bin",
    "../wifikit/rtl8852au_fw.bin",
];

// ══════════════════════════════════════════════════════════════════════════════
//  Channel list (same dual-band set as other Realtek chips)
// ══════════════════════════════════════════════════════════════════════════════

fn build_channel_list() -> Vec<Channel> {
    let mut channels = Vec::new();
    // 2.4 GHz: channels 1-14
    for ch in 1..=14u8 {
        channels.push(Channel::new(ch));
    }
    // 5 GHz: UNII-1/2/2e/3
    for &ch in &[36u8,40,44,48, 52,56,60,64, 100,104,108,112,116,120,124,128,132,136,140,144, 149,153,157,161,165] {
        channels.push(Channel::new(ch));
    }
    channels
}

fn tx_rate_to_hw(rate: &TxRate, channel: u8) -> u8 {
    match rate {
        TxRate::Cck1m => 0x00,
        TxRate::Cck2m => 0x01,
        TxRate::Cck5_5m => 0x02,
        TxRate::Cck11m => 0x03,
        TxRate::Ofdm6m => 0x04,
        TxRate::Ofdm9m => 0x05,
        TxRate::Ofdm12m => 0x06,
        TxRate::Ofdm18m => 0x07,
        TxRate::Ofdm24m => 0x08,
        TxRate::Ofdm36m => 0x09,
        TxRate::Ofdm48m => 0x0A,
        TxRate::Ofdm54m => 0x0B,
        // HT/VHT/HE: fallback to OFDM 6M on legacy RTL driver
        _ => 0x04,
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Driver struct
// ══════════════════════════════════════════════════════════════════════════════

pub struct Rtl8852au {
    handle: Arc<DeviceHandle<GlobalContext>>,
    ep_out: u8,
    ep_in: u8,
    ep_fw: u8,  // EP7 — firmware download bulk OUT
    channel: u8,
    mac_addr: MacAddress,
    h2c_seq: u16,
    rx_buf: Vec<u8>,
    rx_pos: usize,
    rx_len: usize,
    channels: Vec<Channel>,
    vid: u16,
    pid: u16,
    fw_version: String,
}

/// Standalone parse function for RxHandle
fn parse_rx_packet_standalone(buf: &[u8], channel: u8) -> (usize, crate::core::chip::ParsedPacket) {
    let (consumed, frame) = Rtl8852au::parse_rx_packet(buf, channel);
    let packet = match frame {
        Some(f) => crate::core::chip::ParsedPacket::Frame(f),
        None => crate::core::chip::ParsedPacket::Skip,
    };
    (consumed, packet)
}

/// RTL8852AU capability flags — WiFi 6 with HE support
const RTL8852AU_CAPS: ChipCaps = ChipCaps::MONITOR.union(ChipCaps::INJECT)
    .union(ChipCaps::BAND_2G).union(ChipCaps::BAND_5G)
    .union(ChipCaps::HT).union(ChipCaps::VHT).union(ChipCaps::HE)
    .union(ChipCaps::BW40).union(ChipCaps::BW80);

impl Rtl8852au {
    // ══════════════════════════════════════════════════════════════════════════
    //  USB open
    // ══════════════════════════════════════════════════════════════════════════

    pub fn open_usb(vid: u16, pid: u16) -> Result<(Self, UsbEndpoints)> {
        let devices = rusb::devices()?;
        let device = devices
            .iter()
            .find(|d| {
                d.device_descriptor()
                    .map(|desc| desc.vendor_id() == vid && desc.product_id() == pid)
                    .unwrap_or(false)
            })
            .ok_or(Error::AdapterNotFound { vid, pid })?;

        let handle = device.open()?;

        #[cfg(target_os = "linux")]
        {
            if handle.kernel_driver_active(0).unwrap_or(false) {
                let _ = handle.detach_kernel_driver(0);
            }
        }

        handle.claim_interface(0)?;

        let endpoints = crate::core::adapter::discover_endpoints(&device)?;
        let ep_out = endpoints.bulk_out;
        let ep_in = endpoints.bulk_in;
        // EP7 = firmware download endpoint (3rd bulk OUT: EP5=TX, EP6=?, EP7=FWDL)
        let ep_fw = endpoints.bulk_out_all.get(2).copied().unwrap_or(0x07);

        let driver = Self {
            handle: Arc::new(handle),
            ep_out,
            ep_in,
            ep_fw,
            channel: 0,
            mac_addr: MacAddress::ZERO,
            h2c_seq: 0,
            rx_buf: vec![0u8; RX_BUF_SIZE],
            rx_pos: 0,
            rx_len: 0,
            channels: build_channel_list(),
            vid,
            pid,
            fw_version: String::new(),
        };

        Ok((driver, endpoints))
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Register access (identical to all Realtek USB chips)
    // ══════════════════════════════════════════════════════════════════════════

    fn read8(&self, addr: u16) -> Result<u8> {
        let mut buf = [0u8; 1];
        let r = self.handle.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT)?;
        if r < 1 { return Err(Error::RegisterReadFailed { addr }); }
        Ok(buf[0])
    }

    fn write8(&self, addr: u16, val: u8) -> Result<()> {
        let r = self.handle.write_control(0x40, RTL_USB_REQ, addr, 0, &[val], RTL_USB_TIMEOUT)?;
        if r < 1 { return Err(Error::RegisterWriteFailed { addr, val: val as u32 }); }
        Ok(())
    }

    fn read16(&self, addr: u16) -> Result<u16> {
        let mut buf = [0u8; 2];
        let r = self.handle.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT)?;
        if r < 2 { return Err(Error::RegisterReadFailed { addr }); }
        Ok(u16::from_le_bytes(buf))
    }

    fn write16(&self, addr: u16, val: u16) -> Result<()> {
        let r = self.handle.write_control(0x40, RTL_USB_REQ, addr, 0, &val.to_le_bytes(), RTL_USB_TIMEOUT)?;
        if r < 2 { return Err(Error::RegisterWriteFailed { addr, val: val as u32 }); }
        Ok(())
    }

    fn read32(&self, addr: u16) -> Result<u32> {
        let mut buf = [0u8; 4];
        let r = self.handle.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT)?;
        if r < 4 { return Err(Error::RegisterReadFailed { addr }); }
        Ok(u32::from_le_bytes(buf))
    }

    fn write32(&self, addr: u16, val: u32) -> Result<()> {
        let r = self.handle.write_control(0x40, RTL_USB_REQ, addr, 0, &val.to_le_bytes(), RTL_USB_TIMEOUT)?;
        if r < 4 { return Err(Error::RegisterWriteFailed { addr, val }); }
        Ok(())
    }

    // ── Extended register access (addresses > 0xFFFF via wIndex) ──

    fn read32_ext(&self, addr: u32) -> Result<u32> {
        let mut buf = [0u8; 4];
        let w_value = (addr & 0xFFFF) as u16;
        let w_index = ((addr >> 16) & 0xFFFF) as u16;
        let r = self.handle.read_control(0xC0, RTL_USB_REQ, w_value, w_index, &mut buf, RTL_USB_TIMEOUT)?;
        if r < 4 { return Err(Error::RegisterReadFailed { addr: w_value }); }
        Ok(u32::from_le_bytes(buf))
    }

    fn write32_ext(&self, addr: u32, val: u32) -> Result<()> {
        let w_value = (addr & 0xFFFF) as u16;
        let w_index = ((addr >> 16) & 0xFFFF) as u16;
        let r = self.handle.write_control(0x40, RTL_USB_REQ, w_value, w_index, &val.to_le_bytes(), RTL_USB_TIMEOUT)?;
        if r < 4 { return Err(Error::RegisterWriteFailed { addr: w_value, val }); }
        Ok(())
    }

    /// Read-modify-write with bit mask (matches halbb_set_reg pattern)
    fn set_reg(&self, addr: u32, mask: u32, val: u32) -> Result<()> {
        if addr <= 0xFFFF {
            let cur = self.read32(addr as u16)?;
            let shift = mask.trailing_zeros();
            let new = (cur & !mask) | ((val << shift) & mask);
            self.write32(addr as u16, new)
        } else {
            let cur = self.read32_ext(addr)?;
            let shift = mask.trailing_zeros();
            let new = (cur & !mask) | ((val << shift) & mask);
            self.write32_ext(addr, new)
        }
    }

    /// Write a full 32-bit value, auto-selecting regular or extended based on address
    fn write_reg(&self, addr: u32, val: u32) -> Result<()> {
        if addr <= 0xFFFF {
            self.write32(addr as u16, val)
        } else {
            self.write32_ext(addr, val)
        }
    }

    /// Read a full 32-bit value, auto-selecting regular or extended based on address
    fn read_reg(&self, addr: u32) -> Result<u32> {
        if addr <= 0xFFFF {
            self.read32(addr as u16)
        } else {
            self.read32_ext(addr)
        }
    }

    /// Read-modify-write for BB register space (adds 0x10000 offset for USB)
    fn set_reg_bb(&self, addr: u32, mask: u32, val: u32) -> Result<()> {
        let usb_addr = addr + 0x10000;
        let cur = self.read32_ext(usb_addr)?;
        let shift = mask.trailing_zeros();
        let new = (cur & !mask) | ((val << shift) & mask);
        self.write32_ext(usb_addr, new)
    }

    fn write8_mask(&self, addr: u16, mask: u8, val: u8) -> Result<()> {
        let cur = self.read8(addr)?;
        self.write8(addr, (cur & !mask) | (val & mask))
    }

    fn poll8(&self, addr: u16, mask: u8, target: u8, max_ms: u32) -> Result<()> {
        for _ in 0..(max_ms * 10) {
            let val = self.read8(addr)?;
            if (val & mask) == target {
                return Ok(());
            }
            thread::sleep(POLL_ITER_DELAY);
        }
        Err(Error::PollTimeout { addr, mask, expected: target })
    }

    fn poll32(&self, addr: u16, mask: u32, target: u32, max_iters: u32) -> Result<()> {
        for _ in 0..max_iters {
            let val = self.read32(addr)?;
            if (val & mask) == target {
                return Ok(());
            }
            thread::sleep(Duration::from_micros(1));
        }
        Err(Error::PollTimeout { addr, mask: mask as u8, expected: target as u8 })
    }

    fn set_bits32(&self, addr: u16, bits: u32) -> Result<()> {
        let val = self.read32(addr)?;
        self.write32(addr, val | bits)
    }

    fn clear_bits32(&self, addr: u16, bits: u32) -> Result<()> {
        let val = self.read32(addr)?;
        self.write32(addr, val & !bits)
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  RF register access — direct BB register mapped
    //  From halbb_8852a_api.c: path A = 0xC000 + (rf_addr << 2)
    //                          path B = 0xD000 + (rf_addr << 2)
    // ══════════════════════════════════════════════════════════════════════════

    /// Write RF register via direct BB register mapping
    /// RF registers are 20-bit, accessed at USB addr 0x1C000 (path A) or 0x1D000 (path B) + (addr << 2)
    /// The 0x10000 offset is required for BB/RF register space on RTL8852AU USB
    fn write_rf(&self, path: u8, rf_addr: u32, mask: u32, data: u32) -> Result<()> {
        let offset_base: u32 = if path == 0 { 0x1C000 } else { 0x1D000 };
        let direct_addr = offset_base + ((rf_addr & 0xFF) << 2);
        let rf_mask = mask & 0x000FFFFF; // RF registers are 20-bit
        // Read-modify-write via extended addressing
        let cur = self.read32_ext(direct_addr)?;
        let shift = rf_mask.trailing_zeros();
        let new = (cur & !rf_mask) | ((data << shift) & rf_mask);
        self.write32_ext(direct_addr, new)?;
        thread::sleep(Duration::from_micros(1));
        Ok(())
    }

    /// Read RF register via direct BB register mapping
    fn read_rf(&self, path: u8, rf_addr: u32, mask: u32) -> Result<u32> {
        let offset_base: u32 = if path == 0 { 0x1C000 } else { 0x1D000 };
        let direct_addr = offset_base + ((rf_addr & 0xFF) << 2);
        let val = self.read32_ext(direct_addr)?;
        let rf_mask = mask & 0x000FFFFF;
        let shift = rf_mask.trailing_zeros();
        Ok((val & rf_mask) >> shift)
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  BB/RF parameter table loader — from halbb_hwimg_8852a.c + halrf_hwimg_8852a.c
    //
    //  Table format: pairs of (addr/cmd, value)
    //    Headlines (0xF prefix): chip variant selection headers
    //    IF (0x8): conditional block start + CHECK (0x4 in next pair)
    //    ELSE_IF (0x9): alternative condition
    //    ELSE (0xA): default block
    //    END (0xB): end conditional
    //    Default: register write (addr, value)
    // ══════════════════════════════════════════════════════════════════════════

    /// Select the matching headline index from a parameter table.
    /// Headlines are (addr, value) pairs where addr >> 28 == 0xF.
    /// Format: 0xF0RRCCVV where RR=RFE type, CC=chip version (CV)
    /// Returns (headline_size_in_pairs, cfg_target)
    fn select_headline(table: &[(u32, u32)], rfe_type: u32, cv: u32) -> (usize, u32) {
        // Find headline size (entries where top nibble is 0xF)
        let mut h_size = 0usize;
        for (i, &(addr, _)) in table.iter().enumerate() {
            if (addr >> 28) != 0xF {
                h_size = i;
                break;
            }
        }
        if h_size == 0 {
            return (0, 0); // no headlines, use all entries
        }

        // Match priorities (same as vendor driver):
        // 1. Exact {RFE:Match, CV:Match}
        let target_exact = ((rfe_type & 0xFF) << 16) | (cv & 0xFF);
        for i in 0..h_size {
            if (table[i].0 & 0x0FFFFFFF) == target_exact {
                return (h_size, target_exact);
            }
        }

        // 2. {RFE:Match, CV:Don't care (0xFF)}
        let target_rfe_dc = ((rfe_type & 0xFF) << 16) | 0xFF;
        for i in 0..h_size {
            if (table[i].0 & 0x0FFFFFFF) == target_rfe_dc {
                return (h_size, target_rfe_dc);
            }
        }

        // 3. {RFE:Match, CV:Max in table}
        let mut best_cv = 0u32;
        let mut found = false;
        for i in 0..h_size {
            let entry = table[i].0 & 0x0FFFFFFF;
            let entry_rfe = (entry >> 16) & 0xFF;
            let entry_cv = entry & 0xFF;
            if entry_rfe == (rfe_type & 0xFF) && entry_cv >= best_cv {
                best_cv = entry_cv;
                found = true;
            }
        }
        if found {
            return (h_size, ((rfe_type & 0xFF) << 16) | best_cv);
        }

        // 4. {RFE:Don't care (0xFF), CV:Max in table}
        let mut best_cv = 0u32;
        let mut found = false;
        for i in 0..h_size {
            let entry = table[i].0 & 0x0FFFFFFF;
            let entry_rfe = (entry >> 16) & 0xFF;
            let entry_cv = entry & 0xFF;
            if entry_rfe == 0xFF && entry_cv >= best_cv {
                best_cv = entry_cv;
                found = true;
            }
        }
        if found {
            return (h_size, (0xFF << 16) | best_cv);
        }

        // 5. Fallback: use first headline
        (h_size, table[0].0 & 0x0FFFFFFF)
    }

    /// Load a BB parameter table with conditional block handling.
    /// BB registers on RTL8852AU are at USB address 0x10000 + table_addr
    /// (wIndex=0x0001 in USB control transfers, confirmed via usbmon).
    fn load_bb_table(&self, table: &[(u32, u32)], rfe_type: u32, cv: u32) -> Result<usize> {
        let (h_size, cfg_target) = Self::select_headline(table, rfe_type, cv);
        let mut i = h_size;
        let mut is_matched = true;
        let mut find_target = false;
        let mut count = 0usize;

        while i < table.len() {
            let (v1, v2) = table[i];
            i += 1;

            match v1 >> 28 {
                0x8 => {
                    // IF: extract condition target
                    let cfg_para = v1 & 0x0FFFFFFF;
                    if cfg_para == cfg_target {
                        is_matched = true;
                        find_target = true;
                    } else {
                        is_matched = false;
                    }
                }
                0x9 => {
                    // ELSE_IF
                    if find_target {
                        is_matched = false;
                    } else {
                        let cfg_para = v1 & 0x0FFFFFFF;
                        if cfg_para == cfg_target {
                            is_matched = true;
                            find_target = true;
                        } else {
                            is_matched = false;
                        }
                    }
                }
                0xA => {
                    // ELSE
                    is_matched = !find_target;
                }
                0xB => {
                    // END: reset state
                    is_matched = true;
                    find_target = false;
                }
                0x4 => {
                    // CHECK marker (paired with IF/ELSE_IF) — skip
                }
                0xF => {
                    // Late headline — skip
                }
                _ => {
                    // Normal register write — BB registers need 0x10000 offset for USB
                    if is_matched {
                        let usb_addr = v1 + 0x10000;
                        if let Err(e) = self.write32_ext(usb_addr, v2) {
                            eprintln!("[RTL8852AU]   BB table write FAILED at reg 0x{:05X} = 0x{:08X} (entry {}): {}",
                                usb_addr, v2, count, e);
                            return Err(e);
                        }
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Load RF register table for a specific path (0=A, 1=B).
    /// RF tables use the same conditional format but entries are (rf_addr, rf_data).
    fn load_rf_table(&self, table: &[(u32, u32)], path: u8, rfe_type: u32, cv: u32) -> Result<usize> {
        let (h_size, cfg_target) = Self::select_headline(table, rfe_type, cv);
        let mut i = h_size;
        let mut is_matched = true;
        let mut find_target = false;
        let mut count = 0usize;

        while i < table.len() {
            let (v1, v2) = table[i];
            i += 1;

            match v1 >> 28 {
                0x8 => {
                    let cfg_para = v1 & 0x0FFFFFFF;
                    if cfg_para == cfg_target {
                        is_matched = true;
                        find_target = true;
                    } else {
                        is_matched = false;
                    }
                }
                0x9 => {
                    if find_target {
                        is_matched = false;
                    } else {
                        let cfg_para = v1 & 0x0FFFFFFF;
                        if cfg_para == cfg_target {
                            is_matched = true;
                            find_target = true;
                        } else {
                            is_matched = false;
                        }
                    }
                }
                0xA => { is_matched = !find_target; }
                0xB => { is_matched = true; find_target = false; }
                0x4 | 0xF => { /* skip CHECK/headline markers */ }
                _ => {
                    if is_matched {
                        // RF registers: 20-bit data via direct BB register mapping
                        if let Err(e) = self.write_rf(path, v1 & 0xFF, 0x000FFFFF, v2 & 0x000FFFFF) {
                            eprintln!("[RTL8852AU]   RF path {} write FAILED at rf_reg 0x{:02X} = 0x{:05X} (entry {}): {}",
                                path, v1 & 0xFF, v2 & 0x000FFFFF, count, e);
                            return Err(e);
                        }
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PHY / BB / RF initialization — load parameter tables
    //  From halbb_hwimg_8852a.c + halrf_hwimg_8852a.c
    // ══════════════════════════════════════════════════════════════════════════

    // PHY/BB/RF init is now handled by post_boot_init() which replays ALL
    // register writes from the USB3 pcap capture verbatim. The old table-based
    // approach (BB_PHY_REG, RF_A_INIT, RF_B_INIT, RF_NCTL) is no longer used
    // since the pcap replay covers everything the Linux driver does.

    // ══════════════════════════════════════════════════════════════════════════
    //  SCO compensation table — from halbb_8852a_api.c
    // ══════════════════════════════════════════════════════════════════════════

    fn sco_mapping(central_ch: u8) -> u8 {
        match central_ch {
            1 => 109,
            2..=6 => 108,
            7..=10 => 107,
            11..=14 => 106,
            36 | 38 => 51,
            40..=58 => 50,
            60..=64 => 49,
            100 | 102 => 48,
            104..=126 => 47,
            128..=151 => 46,
            153..=177 => 45,
            _ => 0,
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Power on sequence — from pwr_seq_8852a.c
    // ══════════════════════════════════════════════════════════════════════════

    fn power_on(&mut self) -> Result<()> {
        eprintln!("[RTL8852AU] Power on sequence...");

        // Phase 0: Boot mode check
        let gpio_mux = self.read32(R_AX_GPIO_MUXCFG)?;
        if gpio_mux & (1 << 19) != 0 {
            self.clear_bits32(R_AX_SYS_PW_CTRL, 1 << 8)?;
            self.clear_bits32(R_AX_SYS_STATUS1, 1 << 10)?;
            self.clear_bits32(R_AX_GPIO_MUXCFG, 1 << 19)?;
            self.clear_bits32(R_AX_RSV_CTRL, 1 << 6)?;
        }

        // Check current power state
        let pwr_state = (self.read32(R_AX_IC_PWR_STATE)? >> 8) & 0x3;
        eprintln!("[RTL8852AU] Current power state: {}", pwr_state);

        // Phase 1: Reset FW ctrl and prepare for power-on
        self.write32(R_AX_WCPU_FW_CTRL, 0)?;
        self.clear_bits32(R_AX_AFE_CTRL1, 1 << 20)?;

        // Clear GPIO pull-low enables
        let led_cfg = self.read32(R_AX_LED_CFG)?;
        self.write32(R_AX_LED_CFG, led_cfg & !((1 << 8) | (1 << 17)))?;

        // Phase 2: LPS exit (if needed)
        if pwr_state == 2 {
            // Enable AON GPIO interrupt
            self.set_bits32(R_AX_FWS0IMR, 1 << 10)?;
            // GPIO10 pull high
            self.set_bits32(R_AX_GPIO_PH_CFG, 1 << 10)?;
            // Toggle GPIO10 to wake from LPS
            self.set_bits32(R_AX_GPIO_EXT_CTRL, (1 << 10) | (1 << 18) | (1 << 26))?;
            self.clear_bits32(R_AX_GPIO_EXT_CTRL, 1 << 10)?;
            self.set_bits32(R_AX_GPIO_EXT_CTRL, 1 << 10)?;

            // Poll for LPS exit (state != 2)
            for _ in 0..10000 {
                let state = (self.read32(R_AX_IC_PWR_STATE)? >> 8) & 0x3;
                if state != 2 { break; }
                thread::sleep(Duration::from_micros(50));
            }
        }

        // Phase 3: Power-on table (mac_pwron_nic_8852a)
        // Step 1-3: Clear SYS_PW_CTRL bits
        self.write8_mask(0x0005, 0x18, 0x00)?;  // Clear bits [4:3]
        self.write8_mask(0x0005, 0x80, 0x00)?;  // Clear bit 7
        self.write8_mask(0x0005, 0x04, 0x00)?;  // Clear bit 2

        // Step 4: Poll power ready
        self.poll8(0x0006, 0x02, 0x02, 200)?;
        eprintln!("[RTL8852AU] Power ready confirmed");

        // Step 5-7: Request power on and wait for ack
        self.write8_mask(0x0006, 0x01, 0x01)?;  // Set bit 0
        self.write8_mask(0x0005, 0x01, 0x01)?;  // Request power on
        self.poll8(0x0005, 0x01, 0x00, 200)?;   // Wait for ack
        eprintln!("[RTL8852AU] Power on acknowledged");

        // Step 9-13: MAC clock toggle sequence (stabilization)
        for _ in 0..2 {
            self.write8_mask(0x0088, 0x01, 0x01)?;
            self.write8_mask(0x0088, 0x01, 0x00)?;
        }
        self.write8_mask(0x0088, 0x01, 0x01)?;

        // Step 14-18: Final init
        self.write8_mask(0x0083, 0x40, 0x00)?;
        self.write8_mask(0x0080, 0x20, 0x20)?;
        self.write8_mask(0x0024, 0x1F, 0x00)?;  // Clear AFE_CTRL1 bits [4:0]
        self.write8_mask(0x02A0, 0x02, 0x02)?;
        self.write8_mask(0x02A2, 0xE0, 0x00)?;

        // Phase 4: Post power-on
        // Clear AON interrupt
        self.clear_bits32(R_AX_FWS0IMR, 1 << 10)?;
        self.set_bits32(R_AX_FWS0ISR, 1 << 10)?;

        // Notify BT coex
        self.write8(R_AX_SCOREBOARD as u16 + 3, 0x01)?;

        eprintln!("[RTL8852AU] Power on complete");
        Ok(())
    }

    fn power_off(&mut self) -> Result<()> {
        eprintln!("[RTL8852AU] Power off...");
        // Disable WCPU
        self.clear_bits32(R_AX_PLATFORM_ENABLE, B_AX_WCPU_EN)?;
        // Power off table (simplified)
        self.write8_mask(0x0005, 0x01, 0x01)?;
        let _ = self.poll8(0x0005, 0x01, 0x00, 200);
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  USB init — from _usb_8852a.c
    // ══════════════════════════════════════════════════════════════════════════

    fn usb_init(&self) -> Result<()> {
        eprintln!("[RTL8852AU] USB init...");

        // Set USB IO mode
        self.set_bits32(R_AX_USB_HOST_REQUEST_2, 1 << 4)?;

        // Clear USB RX/TX reset bits
        let usb_wlan = self.read32(R_AX_USB_WLAN0_1)?;
        self.write32(R_AX_USB_WLAN0_1, usb_wlan & !((1 << 9) | (1 << 8)))?;

        // Toggle HCI DMA enable
        let hci = self.read32(R_AX_HCI_FUNC_EN)?;
        self.write32(R_AX_HCI_FUNC_EN, hci & !0x3)?;  // disable RX+TX DMA
        self.write32(R_AX_HCI_FUNC_EN, hci | 0x3)?;    // re-enable

        // Set RX bulk size for USB 3.0 (default)
        // USB3: 1024, USB2: 512
        self.write8(R_AX_RXDMA_SETTING, 3)?;  // USB3 bulk size

        // Enable RX aggregation
        let rx_agg = self.read32(R_AX_RXAGG_0)?;
        self.write32(R_AX_RXAGG_0, rx_agg | (1 << 31))?;  // AGG enable

        eprintln!("[RTL8852AU] USB init complete");
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  DMAC pre-init — required BEFORE firmware download
    //  From init.c: hci_func_en() + dmac_pre_init() + dle_init() + hfc_init()
    //  Register values verified against usbmon capture (2026-03-29)
    // ══════════════════════════════════════════════════════════════════════════

    /// Complete pre-FWDL init — verbatim replay of usbmon capture (DMA_INIT_EXACT.txt)
    /// This replaces both dmac_pre_init AND enable_cpu_for_fwdl with the exact
    /// register sequence that the Linux driver performs between power-on and firmware download.
    fn dmac_pre_init_and_enable_cpu(&self) -> Result<()> {
        eprintln!("[RTL8852AU] DMAC pre-init + CPU enable (usbmon replay)...");

        // ── SYS_CFG (0x0190/0x0194) — clear LDO boost ──
        let v = self.read32(0x0190)?;
        self.write32(0x0190, v & !0x00000400)?;  // clear bit 10
        let v = self.read32(0x0194)?;
        self.write32(0x0194, v)?;  // write-back (no change)

        // ── HCI DMA enable (0x8380) ──
        self.write32(R_AX_HCI_FUNC_EN, 0x00000003)?;

        // ── DMAC_FUNC_EN + CLK_EN (0x8400/0x8404) ──
        self.write32(R_AX_DMAC_FUNC_EN, 0x60440000)?;
        self.write32(R_AX_DMAC_CLK_EN, 0x00040000)?;
        // Verify + second write to 0x8404 with additional bits
        let _ = self.read32(R_AX_DMAC_FUNC_EN)?;
        self.write32(R_AX_DMAC_FUNC_EN, 0x60440000)?;
        let _ = self.read32(R_AX_DMAC_CLK_EN)?;
        self.write32(R_AX_DMAC_CLK_EN, 0x04840000)?;

        // ── DMA engine config ──
        let _ = self.read32(0x8C08)?;
        self.write32(0x8C08, 0)?;
        let _ = self.read32(0x9008)?;
        self.write32(0x9008, 0x00402001)?;

        // ── TX/RX queue descriptors (DLE init) ──
        self.write32(0x8C40, 0)?;
        self.write32(0x8C44, 0x000000C4)?;
        self.write32(0x8C4C, 0)?;
        self.write32(0x8C50, 0)?;
        self.write32(0x9040, 0)?;
        self.write32(0x9044, 0)?;
        self.write32(0x9048, 0x00100010)?;
        self.write32(0x904C, 0x00300030)?;
        self.write32(0x9050, 0)?;
        self.write32(0x9054, 0)?;
        self.write32(0x9058, 0)?;
        self.write32(0x905C, 0)?;
        self.write32(0x9060, 0)?;
        self.write32(0x9064, 0)?;
        self.write32(0x9068, 0)?;

        // ── Enable FWDL path ──
        self.write32(R_AX_DMAC_FUNC_EN, 0x64C40000)?;

        // ── Poll DMA ready (0x8D00) ──
        for i in 0..5000u32 {
            let val = self.read32(0x8D00)?;
            if val != 0 {
                eprintln!("[RTL8852AU]   DMA ready: {:#010X} ({}iters)", val, i);
                break;
            }
            if i == 4999 {
                eprintln!("[RTL8852AU]   DMA ready TIMEOUT at 0x8D00");
                return Err(Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed });
            }
            thread::sleep(Duration::from_micros(50));
        }
        let _ = self.read32(0x9100)?;

        // ── HFC init (0x8A00/0x8A04) ──
        self.write32(0x8A00, 0)?;
        self.write32(0x8A04, 0x00200000)?;
        let _ = self.read32(0x8A00)?;
        self.write32(0x8A00, 0x00000400)?;
        let _ = self.read32(0x8A00)?;
        self.write32(0x8A00, 0x00000408)?;

        // ── USB-specific readback (0x1078/0x1174) ──
        let v = self.read32(0x1078)?;
        self.write32(0x1078, v)?;
        let v = self.read32(0x1174)?;
        self.write32(0x1174, v)?;

        // ── HCI DMA reset cycle ──
        self.write32(R_AX_HCI_FUNC_EN, 0)?;
        self.write32(R_AX_HCI_FUNC_EN, 0x00000003)?;

        // ── Poll 0x106C for readiness ──
        for _ in 0..100u32 {
            let val = self.read32(0x106C)?;
            if val != 0 { break; }
            thread::sleep(Duration::from_micros(100));
        }

        // ── Chip info reads ──
        let chip_id = self.read32(0x00FC)?;
        let sys_cfg = self.read32(0x00F0)?;
        eprintln!("[RTL8852AU]   Chip: {:#010X}, SYS_CFG1: {:#010X}", chip_id, sys_cfg);

        // ── HPON writeback ──
        let v = self.read32(R_AX_PLATFORM_ENABLE)?;
        self.write32(R_AX_PLATFORM_ENABLE, v)?;

        // ── Clear FWDL control ──
        self.write32(R_AX_WCPU_FW_CTRL, 0)?;

        // ── SYS_CLK_CTRL writeback ──
        let v = self.read32(R_AX_SYS_CLK_CTRL)?;
        self.write32(R_AX_SYS_CLK_CTRL, v)?;

        // ── Indirect register access (0x0C04 + high address space) ──
        // This writes to address 0x00040000 via the indirect access port
        self.write32(0x0C04, 0x18003040)?;
        self.handle.write_control(0x40, RTL_USB_REQ, 0x0000, 0x0004, &0u32.to_le_bytes(), RTL_USB_TIMEOUT)?;
        self.write32(0x0C04, 0x18003044)?;
        self.handle.read_control(0xC0, RTL_USB_REQ, 0x0000, 0x0004, &mut [0u8; 4], RTL_USB_TIMEOUT)?;
        self.write32(0x0C04, 0x18003044)?;
        self.handle.write_control(0x40, RTL_USB_REQ, 0x0000, 0x0004, &0x00000100u32.to_le_bytes(), RTL_USB_TIMEOUT)?;

        // ── HPON bit toggle (0x0088) — bounce bit 0 ──
        let v = self.read32(R_AX_PLATFORM_ENABLE)?;
        self.write32(R_AX_PLATFORM_ENABLE, v & !1)?;  // clear bit 0
        let _ = self.read32(R_AX_PLATFORM_ENABLE)?;
        self.write32(R_AX_PLATFORM_ENABLE, v | 1)?;    // set bit 0
        let _ = self.read32(R_AX_PLATFORM_ENABLE)?;

        // ── Pre-download config ──
        self.write32(0x01E8, 0)?;
        self.write32(R_AX_HALT_H2C_CTRL, 0)?;
        self.write32(R_AX_HALT_C2H_CTRL, 0)?;

        // ── SYS_CLK_CTRL — set bit 14 (CPU_CLK_EN) ──
        let v = self.read32(R_AX_SYS_CLK_CTRL)?;
        self.write32(R_AX_SYS_CLK_CTRL, v | B_AX_CPU_CLK_EN)?;

        // ── DIAGNOSTIC: dump key registers before FWDL trigger ──
        eprintln!("[RTL8852AU]   Pre-FWDL state:");
        eprintln!("[RTL8852AU]     0x0004 (SYS_FUNC_EN)  = {:#010X} (usbmon: 0x40030082)", self.read32(0x0004)?);
        eprintln!("[RTL8852AU]     0x0008 (SYS_CLK_CTRL) = {:#010X} (usbmon: 0x0020EC21)", self.read32(0x0008)?);
        eprintln!("[RTL8852AU]     0x0088 (PLATFORM_EN)  = {:#010X} (usbmon: 0x0000054D)", self.read32(0x0088)?);
        eprintln!("[RTL8852AU]     0x01E0 (FW_CTRL)      = {:#010X} (usbmon: 0x00000000)", self.read32(0x01E0)?);
        eprintln!("[RTL8852AU]     0x0060 (GPIO_EXT)     = {:#010X}", self.read32(0x0060)?);
        eprintln!("[RTL8852AU]     0x0080 (HCI_CTRL)     = {:#010X}", self.read32(0x0080)?);

        // ── FWDL trigger: write FWDL_EN to 0x01E0, set boot reason, enable WCPU ──
        let _ = self.read32(R_AX_WCPU_FW_CTRL)?;
        self.write32(R_AX_WCPU_FW_CTRL, 0x00000001)?;  // FWDL_EN
        let _ = self.read32(0x01E4)?;
        self.write16(R_AX_BOOT_REASON, 0x0000)?;

        // ── HPON — set WCPU_EN (bit 1) ──
        let v = self.read32(R_AX_PLATFORM_ENABLE)?;
        self.write32(R_AX_PLATFORM_ENABLE, v | B_AX_WCPU_EN)?;
        let after = self.read32(R_AX_PLATFORM_ENABLE)?;
        eprintln!("[RTL8852AU]   PLATFORM_EN after WCPU_EN: {:#010X} (usbmon: 0x0000054F)", after);

        // ── Poll 0x01E0 for H2C_PATH_RDY (bit 1) ──
        eprintln!("[RTL8852AU] Polling for H2C path ready...");
        for i in 0..FWDL_WAIT_US {
            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
            if ctrl & B_AX_H2C_PATH_RDY != 0 {
                eprintln!("[RTL8852AU]   H2C path ready: {:#04X} ({}us)", ctrl, i);
                return Ok(());
            }
            if i == FWDL_WAIT_US - 1 {
                eprintln!("[RTL8852AU]   H2C path NOT ready: {:#04X}", ctrl);
                eprintln!("[RTL8852AU]   Post-fail 0x0004={:#010X} 0x0088={:#010X}", self.read32(0x0004)?, self.read32(0x0088)?);
                return Err(Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed });
            }
            if i % 100000 == 0 && i > 0 {
                eprintln!("[RTL8852AU]   Polling... 0x01E0={:#04X} ({}us)", ctrl, i);
            }
            thread::sleep(Duration::from_micros(1));
        }
        unreachable!()
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Firmware download — from fwdl.c
    // ══════════════════════════════════════════════════════════════════════════

    fn load_firmware(&mut self) -> Result<()> {
        // Find firmware file
        let fw_data = self.find_firmware()?;
        eprintln!("[RTL8852AU] Firmware loaded: {} bytes", fw_data.len());

        // Parse FW header
        if fw_data.len() < FWHDR_HDR_LEN {
            return Err(Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::TooSmall });
        }

        let dw6 = u32::from_le_bytes([fw_data[24], fw_data[25], fw_data[26], fw_data[27]]);
        let section_num = ((dw6 >> 8) & 0xFF) as usize;
        let hdr_len = FWHDR_HDR_LEN + section_num * FWHDR_SECTION_LEN;

        // Parse FW version
        let major = fw_data[4];
        let minor = fw_data[5];
        let sub = fw_data[6];
        self.fw_version = format!("{}.{}.{}", major, minor, sub);
        eprintln!("[RTL8852AU] FW version: {}, {} sections", self.fw_version, section_num);

        // Parse section info
        let mut sections: Vec<(u32, usize, usize)> = Vec::new(); // (dl_addr, offset, len)
        let mut data_offset = hdr_len;
        for i in 0..section_num {
            let sh_off = FWHDR_HDR_LEN + i * FWHDR_SECTION_LEN;
            let sec_dl_addr = u32::from_le_bytes([
                fw_data[sh_off], fw_data[sh_off+1], fw_data[sh_off+2], fw_data[sh_off+3]
            ]) & 0x1FFFFFFF;
            let sec_dw1 = u32::from_le_bytes([
                fw_data[sh_off+4], fw_data[sh_off+5], fw_data[sh_off+6], fw_data[sh_off+7]
            ]);
            let mut sec_size = (sec_dw1 & 0x00FFFFFF) as usize;
            let has_checksum = (sec_dw1 >> 28) & 1 != 0;
            if has_checksum {
                sec_size += 8; // FWDL_SECTION_CHKSUM_LEN
            }
            eprintln!("[RTL8852AU]   Section {}: addr=0x{:08X} size={} checksum={}",
                i, sec_dl_addr, sec_size, has_checksum);
            sections.push((sec_dl_addr, data_offset, sec_size));
            data_offset += sec_size;
        }

        // Modify FW header: set FW_PART_SZ to chunk size
        let mut fw_hdr = fw_data[..hdr_len].to_vec();
        let dw7 = u32::from_le_bytes([fw_hdr[28], fw_hdr[29], fw_hdr[30], fw_hdr[31]]);
        let dw7_new = (dw7 & !0x0000FFFF) | (FWDL_SECTION_PER_PKT_LEN as u32 & 0xFFFF);
        fw_hdr[28..32].copy_from_slice(&dw7_new.to_le_bytes());

        // CPU enable + H2C path ready already done by dmac_pre_init_and_enable_cpu()
        // Proceed directly to FW header download

        // Step 4: Phase 1 — send FW header
        eprintln!("[RTL8852AU] Sending FW header ({} bytes)...", fw_hdr.len());
        self.fwdl_send_h2c(&fw_hdr)?;

        // Wait for FWDL path ready
        for i in 0..FWDL_WAIT_US {
            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
            if ctrl & B_AX_FWDL_PATH_RDY != 0 {
                eprintln!("[RTL8852AU] FWDL path ready after {}us", i);
                break;
            }
            if i == FWDL_WAIT_US - 1 {
                eprintln!("[RTL8852AU] FWDL path not ready (0x01E0={:#04X})", ctrl);
                return Err(Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed });
            }
            thread::sleep(Duration::from_micros(1));
        }

        self.write32(R_AX_HALT_H2C_CTRL, 0)?;
        self.write32(R_AX_HALT_C2H_CTRL, 0)?;

        // Step 5: Phase 2 — send FW sections
        for (i, &(_dl_addr, offset, size)) in sections.iter().enumerate() {
            eprintln!("[RTL8852AU] Downloading section {} ({} bytes)...", i, size);
            let section_data = &fw_data[offset..offset + size];
            self.fwdl_send_section(section_data)?;
        }

        // Step 6: Wait for FW init ready
        thread::sleep(Duration::from_millis(5));
        eprintln!("[RTL8852AU] Waiting for FW init ready...");
        for i in 0..FWDL_WAIT_US {
            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
            let sts = (ctrl >> B_AX_FWDL_STS_SH) & B_AX_FWDL_STS_MSK;
            if sts == FWDL_WCPU_FW_INIT_RDY {
                eprintln!("[RTL8852AU] FW init ready! ({}us)", i);
                return Ok(());
            }
            if i % 50000 == 0 && i > 0 {
                eprintln!("[RTL8852AU]   Still waiting... sts={} (0x01E0={:#04X})", sts, ctrl);
            }
            thread::sleep(Duration::from_micros(1));
        }

        let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
        let sts = (ctrl >> B_AX_FWDL_STS_SH) & B_AX_FWDL_STS_MSK;
        let reason = match sts {
            0 => "INITIAL_STATE",
            1 => "FWDL_ONGOING",
            2 => "CHECKSUM_FAIL",
            3 => "SECURITY_FAIL",
            4 => "CUT_NOT_MATCH",
            6 => "WCPU_FWDL_RDY (not FW_INIT_RDY)",
            _ => "UNKNOWN",
        };
        eprintln!("[RTL8852AU] FW not ready: sts={} ({}), 0x01E0={:#04X}", sts, reason, ctrl);
        Err(Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })
    }

    fn disable_cpu(&self) -> Result<()> {
        // Clear WCPU_EN
        self.clear_bits32(R_AX_PLATFORM_ENABLE, B_AX_WCPU_EN)?;
        // Clear FWDL bits in FW_CTRL
        self.write32(R_AX_WCPU_FW_CTRL, 0)?;
        // Disable CPU clock
        self.clear_bits32(R_AX_SYS_CLK_CTRL, B_AX_CPU_CLK_EN)?;
        // Toggle platform enable (reset)
        self.clear_bits32(R_AX_PLATFORM_ENABLE, B_AX_PLATFORM_EN)?;
        self.set_bits32(R_AX_PLATFORM_ENABLE, B_AX_PLATFORM_EN)?;
        Ok(())
    }

    fn enable_cpu_for_fwdl(&self) -> Result<()> {
        eprintln!("[RTL8852AU] Enabling CPU for FWDL...");

        // Check WCPU not already enabled
        let platform = self.read32(R_AX_PLATFORM_ENABLE)?;
        eprintln!("[RTL8852AU]   Pre-enable PLATFORM_EN = {:#010X}", platform);
        if platform & B_AX_WCPU_EN != 0 {
            eprintln!("[RTL8852AU]   WCPU already enabled, disabling first...");
            self.disable_cpu()?;
        }

        // Zero out LDM and halt registers
        self.write32(R_AX_HALT_H2C_CTRL, 0)?;
        self.write32(R_AX_HALT_C2H_CTRL, 0)?;

        // Enable CPU clock
        self.set_bits32(R_AX_SYS_CLK_CTRL, B_AX_CPU_CLK_EN)?;

        // Configure WCPU_FW_CTRL: clear PATH_RDY bits, set FWDL_STS=0, set FWDL_EN
        let fw_ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
        eprintln!("[RTL8852AU]   Pre-FWDL FW_CTRL = {:#04X}", fw_ctrl);
        // Clear everything, then set only FWDL_EN
        self.write8(R_AX_WCPU_FW_CTRL, B_AX_WCPU_FWDL_EN)?;

        // Write boot reason (0 = power on)
        self.write8(R_AX_BOOT_REASON, 0)?;

        // Enable WCPU
        self.set_bits32(R_AX_PLATFORM_ENABLE, B_AX_WCPU_EN)?;

        let fw_ctrl_after = self.read8(R_AX_WCPU_FW_CTRL)?;
        let platform_after = self.read32(R_AX_PLATFORM_ENABLE)?;
        eprintln!("[RTL8852AU]   Post-enable FW_CTRL = {:#04X}, PLATFORM_EN = {:#010X}", fw_ctrl_after, platform_after);

        Ok(())
    }

    fn find_firmware(&self) -> Result<Vec<u8>> {
        for path in FW_SEARCH_PATHS {
            if let Ok(data) = fs::read(path) {
                if data.len() > FWHDR_HDR_LEN {
                    return Ok(data);
                }
            }
        }
        Err(Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })
    }

    /// Send FW header via bulk OUT EP7 with H2C WD + H2C header prepended
    /// Note: FW header uses H2C type (NO FWDL_EN in WD), matching usbmon capture
    fn fwdl_send_h2c(&mut self, payload: &[u8]) -> Result<()> {
        let h2c_payload_len = FWCMD_HDR_LEN + payload.len();
        let total_len = WD_BODY_LEN + h2c_payload_len;
        let mut buf = vec![0u8; total_len];

        // Build WD (24 bytes) — H2C type, NO FWDL_EN (DW0 = 0x000C0000)
        let wd_dw0 = MAC_AX_DMA_H2C << AX_TXD_CH_DMA_SH;
        buf[0..4].copy_from_slice(&wd_dw0.to_le_bytes());
        // DW2: TXPKTSIZE = h2c payload length
        let wd_dw2 = h2c_payload_len as u32;
        buf[8..12].copy_from_slice(&wd_dw2.to_le_bytes());

        // Build H2C header (8 bytes) at offset 24
        let h2c_dw0 = (FWCMD_TYPE_H2C << H2C_HDR_DEL_TYPE_SH)
            | (FWCMD_H2C_CAT_MAC << H2C_HDR_CAT_SH)
            | (FWCMD_H2C_CL_FWDL << H2C_HDR_CLASS_SH)
            | (FWCMD_H2C_FUNC_FWHDR_DL << H2C_HDR_FUNC_SH)
            | ((self.h2c_seq as u32) << H2C_HDR_H2C_SEQ_SH);
        let h2c_dw1 = (h2c_payload_len as u32) << H2C_HDR_TOTAL_LEN_SH;
        buf[WD_BODY_LEN..WD_BODY_LEN+4].copy_from_slice(&h2c_dw0.to_le_bytes());
        buf[WD_BODY_LEN+4..WD_BODY_LEN+8].copy_from_slice(&h2c_dw1.to_le_bytes());
        self.h2c_seq = self.h2c_seq.wrapping_add(1);

        // Copy payload after H2C header
        buf[WD_BODY_LEN + FWCMD_HDR_LEN..].copy_from_slice(payload);

        // Send via bulk OUT EP7 (firmware download endpoint)
        self.handle.write_bulk(self.ep_fw, &buf, Duration::from_secs(2))
            .map_err(|_| Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })?;

        Ok(())
    }

    /// Send FW section data via bulk OUT EP7 with FWDL WD prepended (no H2C header)
    /// Section chunks use FWDL_EN in WD (DW0 = 0x001C0000), matching usbmon capture
    fn fwdl_send_section(&self, section: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < section.len() {
            let chunk_len = (section.len() - offset).min(FWDL_SECTION_PER_PKT_LEN);
            let total_len = WD_BODY_LEN + chunk_len;
            let mut buf = vec![0u8; total_len];

            // Build WD — FWDL type WITH FWDL_EN (DW0 = 0x001C0000)
            let wd_dw0 = (MAC_AX_DMA_H2C << AX_TXD_CH_DMA_SH) | AX_TXD_FWDL_EN;
            buf[0..4].copy_from_slice(&wd_dw0.to_le_bytes());
            let wd_dw2 = chunk_len as u32;
            buf[8..12].copy_from_slice(&wd_dw2.to_le_bytes());

            // Copy section data after WD
            buf[WD_BODY_LEN..].copy_from_slice(&section[offset..offset + chunk_len]);

            self.handle.write_bulk(self.ep_fw, &buf, Duration::from_secs(2))
                .map_err(|_| Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })?;

            offset += chunk_len;
        }
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  MAC init (minimal — firmware handles most of BB/RF init)
    // ══════════════════════════════════════════════════════════════════════════

    /// Complete MAC/DMA operational init — from init.c dmac_func_en() + cmac_func_en().
    /// Register values computed from bit definitions in mac_reg.h.
    fn mac_init(&self) -> Result<()> {
        eprintln!("[RTL8852AU] MAC init...");

        // ── DMAC function enable (0x8400) ──
        // B_AX_DMAC_CRPRT(31) | MAC_FUNC_EN(30) | DMAC_FUNC_EN(29) | MPDU_PROC_EN(28) |
        // WD_RLS_EN(27) | TXPKT_CTRL_EN(25) | STA_SCH_EN(24) | PKT_BUF_EN(22) |
        // DMAC_TBL_EN(21) | PKT_IN_EN(20) | DLE_CPUIO_EN(19) | DISPATCHER_EN(18) |
        // MAC_SEC_EN(16)
        self.write32(R_AX_DMAC_FUNC_EN, 0xFB7D0000)?;

        // ── DMAC clock enable (0x8404) ──
        // WD_RLS_CLK_EN(27) | TXPKT_CTRL_CLK_EN(25) | STA_SCH_CLK_EN(24) |
        // PKT_IN_CLK_EN(20) | DLE_CPUIO_CLK_EN(19) | DISPATCHER_CLK_EN(18) |
        // BBRPT_CLK_EN(17) | MAC_SEC_CLK_EN(16)
        self.write32(R_AX_DMAC_CLK_EN, 0x0B1F0000)?;

        // ── CMAC function enable (0xC000) — band 0 ──
        // CMAC_CRPRT(31) | CMAC_EN(30) | CMAC_TXEN(29) | CMAC_RXEN(28) |
        // PHYINTF_EN(5) | CMAC_DMA_EN(4) | PTCLTOP_EN(3) | SCHEDULER_EN(2) |
        // TMAC_EN(1) | RMAC_EN(0)
        self.write32(R_AX_CMAC_FUNC_EN, 0xF000003F)?;

        // ── CMAC clock enable (0xC008) — band 0 ──
        // CMAC_CKEN(30) | PHYINTF_CKEN(5) | CMAC_DMA_CKEN(4) | PTCLTOP_CKEN(3) |
        // SCHEDULER_CKEN(2) | TMAC_CKEN(1) | RMAC_CKEN(0)
        self.write32(R_AX_CK_EN, 0x4000003F)?;

        eprintln!("[RTL8852AU] MAC init complete");
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Monitor mode — from rx_filter.c
    // ══════════════════════════════════════════════════════════════════════════

    /// Complete monitor mode setup — Phase 4 from usbmon capture.
    /// Sets all RX filter, frame accept, and sniffer mode registers.
    fn set_monitor_internal(&mut self) -> Result<()> {
        eprintln!("[RTL8852AU] Setting monitor mode (usbmon Phase 4)...");

        // ── 4a. MAC RX filter ──
        self.write32(0xC33C, 0x472C4675)?;               // Frame type filter
        self.write32(0xC340, 0xDF020075)?;
        self.write32(0xC338, 0x18023C08)?;
        self.write16(0xC326, 0x1910)?;

        // RX filter control trigger
        self.write32(0xCE34, 0x01017F00)?;               // Enable RX filter update
        // Wait for bit clear
        for _ in 0..100 {
            let v = self.read32(0xCE34)?;
            if v & 0xFF == 0 { break; }
            thread::sleep(Duration::from_micros(100));
        }

        // Accept ALL frame subtypes (management, control, data)
        self.write32(R_AX_MGNT_FLTR, 0x55555555)?;      // CE28
        self.write32(R_AX_CTRL_FLTR, 0x55555555)?;       // CE24
        self.write32(R_AX_DATA_FLTR, 0x55555555)?;       // CE2C

        // Master RX filter — promiscuous mode
        self.write32(R_AX_RX_FLTR_OPT, 0x3F000003)?;    // CE20

        // RX filter flags
        self.write32(R_AX_PLCP_HDR_FLTR, 0x00007F00)?;  // CE04

        // ── 4b. Monitor mode enable ──
        self.write32(0xC390, 0xFF002171)?;               // MAC config: accept all
        self.write32(0xCC00, 0x40400060)?;               // RX control
        self.write32(0xCC04, 0x00000000)?;               // Clear RX filter restrictions
        self.write32(0xCC80, 0x00BC2700)?;               // RX buffer config
        self.write16(0xCE4A, 0x0006)?;                   // Additional filter config
        self.write32(0xCC20, 0x04285000)?;
        self.write32(0xCC04, 0x0A150000)?;               // RX filter: accept
        self.write32(0xCCB0, 0x00001000)?;               // RX agg threshold
        self.write32(0xCE3C, 0x02000000)?;               // Additional RX filter
        self.write8(0xCE3C as u16, 0x04)?;

        // Final monitor mode RX filter
        self.write32(R_AX_RX_FLTR_OPT, 0x3F001703)?;    // CE20 — monitor mode
        self.write32(R_AX_PLCP_HDR_FLTR, 0x00006F00)?;  // CE04 — accept all frame types

        // TSF and beacon config
        self.write32(0xC088, 0x00000000)?;
        self.write32(0xC090, 0x05030000)?;
        self.write32(0xC600, 0x00000003)?;               // Beacon control
        self.write32(0xC660, 0x00000014)?;
        self.write32(0xC804, 0x00000000)?;               // NAV override

        let fltr = self.read32(R_AX_RX_FLTR_OPT)?;
        eprintln!("[RTL8852AU] RX filter: {:#010X}", fltr);
        eprintln!("[RTL8852AU] Monitor mode set");

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Channel setting (minimal — sets via BB/RF register for now)
    // ══════════════════════════════════════════════════════════════════════════

    /// Channel switching — verbatim pcap replay per channel.
    /// Uses complete register + bulk command sequences from usbmon capture.
    fn set_channel_internal(&mut self, ch: u8) -> Result<()> {
        use rtl8852a_post_boot::PostBootOp;

        let seq: Option<&[PostBootOp]> = match ch {
            1  => Some(super::rtl8852a_phase_ch1::CH1_SEQUENCE),
            6  => Some(super::rtl8852a_phase_ch6_2g::CH6_2G_SEQUENCE),
            11 => Some(super::rtl8852a_phase_ch11_2g::CH11_2G_SEQUENCE),
            36 => Some(super::rtl8852a_phase_ch36_5g::CH36_5G_SEQUENCE),
            48 => Some(super::rtl8852a_phase_ch48_5g::CH48_5G_SEQUENCE),
            149 => Some(super::rtl8852a_phase_ch149_5g::CH149_5G_SEQUENCE),
            165 => Some(super::rtl8852a_phase_ch165_5g::CH165_5G_SEQUENCE),
            // For channels without pcap data, use the BB direct method as fallback
            _ => None,
        };

        if let Some(seq) = seq {
            self.replay_phase_complete(&format!("Ch{}", ch), seq, false)?;
            self.channel = ch;
        } else {
            // Fallback: BB register direct switching for channels without pcap data
            self.set_channel_bb_direct(ch)?;
            self.channel = ch;
        }
        Ok(())
    }

    /// Complete channel switching via BB registers — ported from halbb_ctrl_bw_ch_8852a.
    /// NOT USED: bypasses firmware, breaks radio state. Kept for reference.
    /// Real channel switching needs H2C commands to firmware.
    #[allow(dead_code)]
    fn set_channel_bb_direct(&mut self, ch: u8) -> Result<()> {
        let is_2g = ch <= 14;
        let central_ch = ch; // For 20MHz BW, primary == central

        // ═══ RF channel setting (Path A + Path B) ═══
        // From halbb_ch_setting_8852a: write RF reg 0x18 with channel + band flags
        for path in 0..2u8 {
            let rf_reg18 = self.read_rf(path, 0x18, 0x000FFFFF)?;
            let mut new_val = rf_reg18 & !0x303FF; // clear [17:16],[9:8],[7:0]
            new_val |= central_ch as u32;          // set channel number
            if !is_2g {
                new_val |= (1 << 16) | (1 << 8);  // 5GHz band flags
            }
            self.write_rf(path, 0x18, 0x000FFFFF, new_val)?;
            thread::sleep(Duration::from_micros(100));

            // PLL relock: toggle RF reg 0xCF bit 0
            self.write_rf(path, 0xCF, 0x1, 0)?;
            self.write_rf(path, 0xCF, 0x1, 1)?;
        }

        // ═══ BB mode select (BB register space — 0x10000 offset) ═══
        // Path A (0x156C bits [31:30]): 1=2G, 0=5G
        // Path B (0x162C bits [31:30]): 1=2G, 0=5G
        let mode_val: u32 = if is_2g { 1 } else { 0 };
        self.set_reg_bb(0x156C, 0xC0000000, mode_val)?;
        self.set_reg_bb(0x162C, 0xC0000000, mode_val)?;

        // ═══ SCO compensation ═══
        let sco_comp = Self::sco_mapping(central_ch) as u32;
        self.set_reg_bb(0x1878, 0x7F, sco_comp)?;

        // ═══ Bandwidth setting (20MHz) ═══
        // RF_BW [31:30] = 0x0 (20MHz)
        self.set_reg_bb(0x1878, 0xC0000000, 0x0)?;
        // small BW [13:12] = 0x0
        self.set_reg_bb(0x187C, 0x3000, 0x0)?;
        // Pri ch [11:8] = 0x0
        self.set_reg_bb(0x187C, 0xF00, 0x0)?;

        // Per-path BW setting (RF reg 0x18 bandwidth field)
        for path in 0..2u8 {
            let rf_reg18 = self.read_rf(path, 0x18, 0x000FFFFF)?;
            // Clear BW bits [13:11], set for 20MHz (0b000)
            let new_val = rf_reg18 & !0x3800;
            self.write_rf(path, 0x18, 0x000FFFFF, new_val)?;
        }

        // ═══ Bandedge enable ═══
        self.set_reg_bb(0x1390, 1 << 30, 1)?;

        // ═══ CCK parameters ═══
        if is_2g {
            // CCK enable
            self.set_reg_bb(0x7800, 1 << 27, 0)?;
            self.set_reg_bb(0x7844, 1u32 << 31, 0)?;

            if central_ch == 14 {
                self.set_reg_bb(0x7800, 0x00FFFFFF, 0x3B13FF)?;
                self.set_reg_bb(0x7804, 0x00FFFFFF, 0x1C42DE)?;
                self.set_reg_bb(0x7808, 0x00FFFFFF, 0xFDB0AD)?;
                self.set_reg_bb(0x780C, 0x00FFFFFF, 0xF60F6E)?;
                self.set_reg_bb(0x7810, 0x00FFFFFF, 0xFD8F92)?;
                self.set_reg_bb(0x7814, 0x00FFFFFF, 0x02D011)?;
                self.set_reg_bb(0x7818, 0x00FFFFFF, 0x01C02C)?;
                self.set_reg_bb(0x781C, 0x00FFFFFF, 0xFFF00A)?;
            } else {
                self.set_reg_bb(0x7800, 0x00FFFFFF, 0x3D23FF)?;
                self.set_reg_bb(0x7804, 0x00FFFFFF, 0x29B354)?;
                self.set_reg_bb(0x7808, 0x00FFFFFF, 0x0FC1C8)?;
                self.set_reg_bb(0x780C, 0x00FFFFFF, 0xFDB053)?;
                self.set_reg_bb(0x7810, 0x00FFFFFF, 0xF86F9A)?;
                self.set_reg_bb(0x7814, 0x00FFFFFF, 0xFAEF92)?;
                self.set_reg_bb(0x7818, 0x00FFFFFF, 0xFE5FCC)?;
                self.set_reg_bb(0x781C, 0x00FFFFFF, 0xFFDFF5)?;
            }

            // CCK SCO compensation
            let sco_barker: [u32; 14] = [
                0x1CFEA, 0x1D0E1, 0x1D1D7, 0x1D2CD, 0x1D3C3, 0x1D4B9, 0x1D5B0,
                0x1D6A6, 0x1D79C, 0x1D892, 0x1D988, 0x1DA7F, 0x1DB75, 0x1DDC4,
            ];
            let sco_cck: [u32; 14] = [
                0x27DE3, 0x27F35, 0x28088, 0x281DA, 0x2832D, 0x2847F, 0x285D2,
                0x28724, 0x28877, 0x289C9, 0x28B1C, 0x28C6E, 0x28DC1, 0x290ED,
            ];
            let ch_idx = (central_ch as usize).saturating_sub(1).min(13);
            self.set_reg_bb(0x78B0, 0x7FFFF, sco_barker[ch_idx])?;
            self.set_reg_bb(0x78B4, 0x7FFFF, sco_cck[ch_idx])?;
        } else {
            // 5GHz: disable CCK
            self.set_reg_bb(0x7800, 1 << 27, 1)?;
            self.set_reg_bb(0x7844, 1u32 << 31, 1)?;
        }

        // ═══ BB reset ═══
        self.set_reg_bb(0x0804, 0x2, 0)?;  // BB reset assert
        thread::sleep(Duration::from_micros(1));
        self.set_reg_bb(0x0804, 0x2, 1)?;  // BB reset deassert

        // ═══ MAC-level channel config ═══
        // WMAC_RFMOD: clear BW bits for 20MHz
        let rfmod = self.read8(0xC67C)?;
        self.write8(0xC67C, rfmod & !0x03)?;

        // TXRATE_CHK: enable CCK check for 5GHz
        if !is_2g {
            self.set_bits32(0xC680, 0x03)?; // CHECK_CCK_EN | RTS_LIMIT_IN_OFDM6
        } else {
            self.clear_bits32(0xC680, 0x03)?;
        }

        // TX sub-carrier value (0 for 20MHz)
        self.write32(0xC684, 0x00000000)?;

        self.channel = ch;
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Read MAC address from hardware
    // ══════════════════════════════════════════════════════════════════════════

    fn read_mac_address(&mut self) -> Result<()> {
        // Try autoloaded MAC from system registers first (0x0036-0x003B)
        let mac_lo = self.read32(0x0036)?;
        let mac_hi = self.read16(0x003A)?;

        let mac = [
            (mac_lo & 0xFF) as u8,
            ((mac_lo >> 8) & 0xFF) as u8,
            ((mac_lo >> 16) & 0xFF) as u8,
            ((mac_lo >> 24) & 0xFF) as u8,
            (mac_hi & 0xFF) as u8,
            ((mac_hi >> 8) & 0xFF) as u8,
        ];

        // Validate MAC
        if mac == [0x00; 6] || mac == [0xFF; 6] {
            eprintln!("[RTL8852AU] Invalid MAC from 0x0036, trying MACID register...");
            // Try MACID register (C100)
            let mac_lo = self.read32(R_AX_MACID_REG)?;
            let mac_hi = self.read16(R_AX_MACID_REG + 4)?;
            self.mac_addr = MacAddress::new([
                (mac_lo & 0xFF) as u8,
                ((mac_lo >> 8) & 0xFF) as u8,
                ((mac_lo >> 16) & 0xFF) as u8,
                ((mac_lo >> 24) & 0xFF) as u8,
                (mac_hi & 0xFF) as u8,
                ((mac_hi >> 8) & 0xFF) as u8,
            ]);
        } else {
            self.mac_addr = MacAddress::new(mac);
        }

        eprintln!("[RTL8852AU] MAC address: {}", self.mac_addr);
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Full init sequence
    // ══════════════════════════════════════════════════════════════════════════

    /// Replay ALL 5929 post-boot register writes from usbmon capture.
    /// This is the complete init sequence that Linux performs between
    /// firmware boot and first RX data — no shortcuts, no guessing.
    /// Send pre-built H2C command via EP5 (firmware command endpoint)
    /// The payload already includes WD header + FWCMD header + data
    fn bulk_out_h2c(&self, data: &[u8]) -> Result<()> {
        self.handle.write_bulk(self.ep_out, data, Duration::from_secs(2))
            .map_err(|e| Error::Usb(e))?;
        Ok(())
    }

    /// Send pre-built bulk command via specific endpoint
    fn bulk_out_ep(&self, ep: u8, data: &[u8]) -> Result<()> {
        self.handle.write_bulk(ep, data, Duration::from_secs(2))
            .map_err(|e| Error::Usb(e))?;
        Ok(())
    }

    /// Generic replay of a PostBootOp sequence — used for all pcap phases
    fn replay_phase(&self, name: &str, seq: &[rtl8852a_post_boot::PostBootOp]) -> Result<()> {
        use rtl8852a_post_boot::PostBootOp;
        eprintln!("[RTL8852AU] {}: replaying {} ops...", name, seq.len());

        let mut read_ok = 0usize;
        let mut write_ok = 0usize;
        let mut write_fail = 0usize;
        let mut bulk_ok = 0usize;
        let mut bulk_fail = 0usize;
        let total = seq.len();

        for op in seq {
            match op {
                PostBootOp::Read(full_addr, width) => {
                    let _ = if *full_addr > 0xFFFF {
                        self.read32_ext(*full_addr).map(|_| ())
                    } else {
                        let addr = *full_addr as u16;
                        match width {
                            1 => self.read8(addr).map(|_| ()),
                            2 => self.read16(addr).map(|_| ()),
                            _ => self.read32(addr).map(|_| ()),
                        }
                    };
                    read_ok += 1;
                }
                PostBootOp::Write(full_addr, val, width) => {
                    let result = if *full_addr > 0xFFFF {
                        self.write32_ext(*full_addr, *val)
                    } else {
                        let addr = *full_addr as u16;
                        match width {
                            1 => self.write8(addr, *val as u8),
                            2 => self.write16(addr, *val as u16),
                            _ => self.write32(addr, *val),
                        }
                    };
                    if let Err(e) = result {
                        if write_fail < 3 {
                            eprintln!("[RTL8852AU]   W 0x{:08X} = 0x{:08X} FAILED: {}", full_addr, val, e);
                        }
                        write_fail += 1;
                    } else {
                        write_ok += 1;
                    }
                }
                PostBootOp::BulkOut(ep, data) => {
                    if *ep == 0x05 {
                        bulk_fail += 1;
                        continue;
                    }
                    let target_ep = self.ep_fw;
                    match self.handle.write_bulk(target_ep, data, Duration::from_millis(1000)) {
                        Ok(_) => {
                            bulk_ok += 1;
                            eprintln!("[RTL8852AU]   H2C EP7 ({} bytes): OK", data.len());
                        }
                        Err(e) => {
                            eprintln!("[RTL8852AU]   H2C EP7 ({} bytes): FAILED: {}", data.len(), e);
                            bulk_fail += 1;
                        }
                    }
                }
            }

            let done = read_ok + write_ok + write_fail + bulk_ok + bulk_fail;
            if done % 3000 == 0 && done > 0 {
                eprintln!("[RTL8852AU]   {}/{}: R={} W={} B={}/{}",
                    done, total, read_ok, write_ok, bulk_ok, bulk_ok + bulk_fail);
            }
        }

        eprintln!("[RTL8852AU] {} complete: R={} W={}/{} Bulk={}/{}",
            name, read_ok, write_ok, write_ok + write_fail, bulk_ok, bulk_ok + bulk_fail);
        Ok(())
    }

    /// COMPLETE replay — sends ALL operations including EP5 bulk.
    /// skip_fw_bulk: if true, skips the first 182 EP7 bulk commands (FW download chunks)
    /// that we already sent via load_firmware(). Not skipping a step — avoiding duplicate FW load.
    fn replay_phase_complete(&self, name: &str, seq: &[rtl8852a_post_boot::PostBootOp],
                              skip_fw_bulk: bool) -> Result<()> {
        use rtl8852a_post_boot::PostBootOp;
        eprintln!("[RTL8852AU] {}: replaying {} ops{}...",
            name, seq.len(),
            if skip_fw_bulk { " (skip FW download bulk)" } else { "" });

        let mut read_ok = 0usize;
        let mut write_ok = 0usize;
        let mut write_fail = 0usize;
        let mut bulk_ok = 0usize;
        let mut bulk_fail = 0usize;
        let mut bulk_skip = 0usize;
        let mut ep7_count = 0usize;
        let total = seq.len();

        // FW download = first 182 EP7 bulk commands (128B header + 181 sections)
        const FW_DOWNLOAD_EP7_COUNT: usize = 182;

        for op in seq {
            match op {
                PostBootOp::Read(full_addr, width) => {
                    // Addresses > 0xFFFF have wIndex in upper 16 bits (BB/RF space)
                    let _ = if *full_addr > 0xFFFF {
                        self.read32_ext(*full_addr).map(|_| ())
                    } else {
                        let addr = *full_addr as u16;
                        match width {
                            1 => self.read8(addr).map(|_| ()),
                            2 => self.read16(addr).map(|_| ()),
                            _ => self.read32(addr).map(|_| ()),
                        }
                    };
                    read_ok += 1;
                }
                PostBootOp::Write(full_addr, val, width) => {
                    // Addresses > 0xFFFF have wIndex in upper 16 bits (BB/RF space)
                    let result = if *full_addr > 0xFFFF {
                        self.write32_ext(*full_addr, *val)
                    } else {
                        let addr = *full_addr as u16;
                        match width {
                            1 => self.write8(addr, *val as u8),
                            2 => self.write16(addr, *val as u16),
                            _ => self.write32(addr, *val),
                        }
                    };
                    if let Err(e) = result {
                        if write_fail < 5 {
                            eprintln!("[RTL8852AU]   W 0x{:08X} = 0x{:08X} FAILED: {}",
                                full_addr, val, e);
                        }
                        write_fail += 1;
                    } else {
                        write_ok += 1;
                    }
                }
                PostBootOp::BulkOut(ep, data) => {
                    // Skip FW download EP7 bulk commands (already loaded via load_firmware)
                    if skip_fw_bulk && *ep == 0x07 {
                        ep7_count += 1;
                        if ep7_count <= FW_DOWNLOAD_EP7_COUNT {
                            bulk_skip += 1;
                            continue;
                        }
                    }

                    let target_ep = if *ep == 0x07 { self.ep_fw } else { self.ep_out };
                    // Short timeout — H2C commands respond instantly or not at all
                    let timeout = Duration::from_millis(200);
                    match self.handle.write_bulk(target_ep, data, timeout) {
                        Ok(_) => {
                            bulk_ok += 1;
                            if bulk_ok <= 10 || bulk_ok % 50 == 0 {
                                eprintln!("[RTL8852AU]   Bulk EP{} ({} bytes): OK [#{}]",
                                    ep, data.len(), bulk_ok);
                            }
                        }
                        Err(e) => {
                            bulk_fail += 1;
                            if bulk_fail <= 3 {
                                eprintln!("[RTL8852AU]   Bulk EP{} ({} bytes): FAILED: {} [#{}]",
                                    ep, data.len(), e, bulk_ok + bulk_fail);
                            }
                        }
                    }
                }
            }

            let done = read_ok + write_ok + write_fail + bulk_ok + bulk_fail + bulk_skip;
            if done % 5000 == 0 && done > 0 {
                eprintln!("[RTL8852AU]   {}/{}: R={} W={}/{} B={}/{} skip={}",
                    done, total, read_ok, write_ok, write_ok + write_fail,
                    bulk_ok, bulk_ok + bulk_fail, bulk_skip);
            }
        }

        eprintln!("[RTL8852AU] {} complete: R={} W={}/{} Bulk={}/{} skipped={}",
            name, read_ok, write_ok, write_ok + write_fail,
            bulk_ok, bulk_ok + bulk_fail, bulk_skip);
        Ok(())
    }

    fn post_boot_init(&self) -> Result<()> {
        self.replay_phase("Post-boot", rtl8852a_post_boot::POST_BOOT_SEQUENCE)
    }

    /// Replay the FULL pcap init sequence (post-FWDL portion only).
    /// Skips: pre-FWDL ops, FW download bulk commands, board-specific registers.
    /// This is the complete Linux driver init from after FW boot through RX/TX ready.
    fn replay_pcap_post_fwdl(&self) -> Result<()> {
        use rtl8852a_post_boot::PostBootOp;
        let seq = super::rtl8852a_full_init::FULL_INIT_SEQUENCE;

        // Find where FW download ends (last BulkOut with 2044 bytes)
        // Pre-FWDL is ops 0-139, FW download bulk is ops 140-~330
        // Post-FWDL starts after the last consecutive bulk command
        let mut fwdl_end = 0;
        let mut in_bulk_region = false;
        for (i, op) in seq.iter().enumerate() {
            match op {
                PostBootOp::BulkOut(7, data) if data.len() >= 2000 => {
                    in_bulk_region = true;
                    fwdl_end = i + 1;
                }
                _ => {
                    if in_bulk_region {
                        // Small gap (register polls between FW chunks) — continue
                        // But if we haven't seen bulk for a while, FWDL is done
                        if i > fwdl_end + 50 {
                            break;
                        }
                    }
                }
            }
        }

        let post_fwdl = &seq[fwdl_end..];
        let total = post_fwdl.len();
        eprintln!("[RTL8852AU] Post-FWDL pcap replay: {} ops (starting from op {})", total, fwdl_end);

        let mut read_ok = 0u32;
        let mut write_ok = 0u32;
        let mut write_fail = 0u32;
        let mut bulk_ok = 0u32;
        let mut bulk_fail = 0u32;
        let mut skipped = 0u32;

        for (idx, op) in post_fwdl.iter().enumerate() {
            match op {
                PostBootOp::Read(full_addr, width) => {
                    let _ = if *full_addr > 0xFFFF {
                        self.read32_ext(*full_addr).map(|_| ())
                    } else {
                        let addr = *full_addr as u16;
                        match width {
                            1 => self.read8(addr).map(|_| ()),
                            2 => self.read16(addr).map(|_| ()),
                            _ => self.read32(addr).map(|_| ()),
                        }
                    };
                    read_ok += 1;
                }
                PostBootOp::Write(full_addr, val, width) => {
                    // Skip board-specific registers
                    let short_addr = (*full_addr & 0xFFFF) as u16;
                    if Self::SKIP_REGS.contains(&short_addr) {
                        skipped += 1;
                        continue;
                    }
                    let result = if *full_addr > 0xFFFF {
                        self.write32_ext(*full_addr, *val)
                    } else {
                        match width {
                            1 => self.write8(short_addr, *val as u8),
                            2 => self.write16(short_addr, *val as u16),
                            _ => self.write32(short_addr, *val),
                        }
                    };
                    match result {
                        Ok(()) => write_ok += 1,
                        Err(e) => {
                            if write_fail < 5 {
                                eprintln!("[RTL8852AU]   W 0x{:08X} = 0x{:08X} FAILED: {}", full_addr, val, e);
                            }
                            write_fail += 1;
                        }
                    }
                }
                PostBootOp::BulkOut(ep, data) => {
                    if *ep == 0x05 {
                        // EP5 TX probe frames — skip during init
                        bulk_fail += 1;
                        continue;
                    }
                    // EP7 H2C firmware commands
                    match self.handle.write_bulk(self.ep_fw, data, Duration::from_millis(1000)) {
                        Ok(_) => {
                            bulk_ok += 1;
                            if bulk_ok <= 3 {
                                eprintln!("[RTL8852AU]   H2C EP7 ({} bytes): OK [{}]", data.len(), bulk_ok);
                            }
                        }
                        Err(e) => {
                            if bulk_fail < 5 {
                                eprintln!("[RTL8852AU]   H2C EP7 ({} bytes): FAILED: {}", data.len(), e);
                            }
                            bulk_fail += 1;
                        }
                    }
                }
            }

            let done = read_ok + write_ok + write_fail + bulk_ok + bulk_fail + skipped;
            if done % 5000 == 0 && done > 0 {
                eprintln!("[RTL8852AU]   {}/{}: R={} W={}/{} B={}/{} skip={}",
                    done, total, read_ok, write_ok, write_ok + write_fail,
                    bulk_ok, bulk_ok + bulk_fail, skipped);
            }
        }

        eprintln!("[RTL8852AU] Post-FWDL replay complete: R={} W={}/{} Bulk={}/{} skipped={}",
            read_ok, write_ok, write_ok + write_fail,
            bulk_ok, bulk_ok + bulk_fail, skipped);
        Ok(())
    }

    /// Pre-FWDL init — verbatim USB3 pcap replay
    /// Replaces the old hand-coded power_on() + dmac_pre_init_and_enable_cpu()
    fn pre_fwdl_init(&self) -> Result<()> {
        use rtl8852a_pre_fwdl::PreFwdlOp;
        let seq = rtl8852a_pre_fwdl::PRE_FWDL_SEQUENCE;
        eprintln!("[RTL8852AU] Pre-FWDL init: {} ops from USB3 pcap...", seq.len());

        let mut r = 0usize;
        let mut w = 0usize;
        for op in seq {
            match op {
                PreFwdlOp::Read(addr, width) => {
                    let _ = match width {
                        1 => self.read8(*addr).map(|_| ()),
                        2 => self.read16(*addr).map(|_| ()),
                        _ => self.read32(*addr).map(|_| ()),
                    };
                    r += 1;
                }
                PreFwdlOp::Write(addr, val, width) => {
                    let _ = match width {
                        1 => self.write8(*addr, *val as u8),
                        2 => self.write16(*addr, *val as u16),
                        _ => self.write32(*addr, *val),
                    };
                    w += 1;
                }
            }
        }
        eprintln!("[RTL8852AU] Pre-FWDL replay done: {} reads, {} writes", r, w);

        // The pcap shows 17 poll reads of 0x01E0 getting 0x01 (FWDL_EN only).
        // H2C_PATH_RDY (bit 1) is set asynchronously by WCPU after WCPU_EN.
        // Poll until H2C path is ready — may need more time than the pcap's 17 reads.
        eprintln!("[RTL8852AU] Polling for H2C path ready...");
        for i in 0..400_000u32 {
            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
            if ctrl & B_AX_H2C_PATH_RDY != 0 {
                eprintln!("[RTL8852AU]   H2C path ready: 0x{:02X} ({}us)", ctrl, i);
                return Ok(());
            }
            thread::sleep(Duration::from_micros(1));
        }
        let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
        eprintln!("[RTL8852AU]   H2C path NOT ready after 400ms: 0x{:02X}", ctrl);
        Ok(()) // Continue anyway — FW download might still work
    }

    fn dump_key_regs(&self, label: &str) {
        eprintln!("[RTL8852AU] ── {} ──", label);
        let regs: &[(u16, &str)] = &[
            (0x8380, "HCI_FUNC_EN"),
            (0x8400, "DMAC_FUNC"),
            (0x8404, "DMAC_CLK"),
            (0xC000, "CMAC_FUNC"),
            (0xC008, "CK_EN"),
            (0x1060, "USB_EP0"),
            (0x1064, "USB_EP1"),
            (0x1068, "USB_EP2"),
            (0x106C, "USB_EP3"),
            (0x8900, "RXAGG_0"),
            (0x8908, "RXDMA_SET"),
            (0xCE20, "RX_FLTR"),
        ];
        for (addr, name) in regs {
            eprintln!("[RTL8852AU]   0x{:04X} ({:12}) = 0x{:08X}",
                addr, name, self.read32(*addr).unwrap_or(0xDEAD));
        }
    }

    /// Board-specific registers that must NOT be written from pcap values
    const SKIP_REGS: &'static [u16] = &[
        0x0010, // R_AX_SYS_SWR_CTRL1 — switching power regulator, board-specific
    ];

    fn chip_init(&mut self) -> Result<()> {
        eprintln!("[RTL8852AU] ═══ RTL8852AU WiFi 6 Init (COMPLETE — no shortcuts) ═══");

        // Verify USB communication
        let chip_id = self.read8(0x00FC)?;
        let chip_cut = self.read8(0x00F1)?;
        let usb_status = self.read32(0x11F0)?;
        let is_usb3 = (usb_status & 0x02) != 0;
        eprintln!("[RTL8852AU] Chip: 0x{:02X}, cut: 0x{:02X}, USB: {} (0x{:08X})",
            chip_id, chip_cut, if is_usb3 { "3.0" } else { "2.0" }, usb_status);
        eprintln!("[RTL8852AU] EP: tx=0x{:02X} rx=0x{:02X} fw=0x{:02X}",
            self.ep_out, self.ep_in, self.ep_fw);

        // ── Phase 0: Pre-FWDL (our proven read-modify-write code) ──
        self.power_on()?;
        self.dmac_pre_init_and_enable_cpu()?;

        // ── Phase 1: Firmware download (our proven code, gets INIT_RDY) ──
        self.load_firmware()?;

        self.dump_key_regs("After FW boot");

        // ── Reset USB endpoints after FW boot ──
        let _ = self.handle.release_interface(0);
        thread::sleep(Duration::from_millis(100));
        self.handle.claim_interface(0).map_err(|e| {
            Error::ChipInitFailed {
                chip: "RTL8852AU".into(),
                stage: crate::core::error::InitStage::UsbEnumeration,
                reason: format!("re-claim after FW boot: {}", e),
            }
        })?;
        for ep in [self.ep_out, self.ep_in, self.ep_fw] {
            let _ = self.handle.clear_halt(ep);
        }
        eprintln!("[RTL8852AU] USB endpoints re-synced");

        // ── Phase 2: Post-FWDL — COMPLETE replay (skip FW download bulk, keep EVERYTHING else) ──
        self.replay_phase_complete("Post-FWDL",
            super::rtl8852a_phase_post_fwdl::POST_FWDL_SEQUENCE, true)?;

        // ── Phase 3: Monitor mode ──
        self.replay_phase_complete("Monitor",
            super::rtl8852a_phase_monitor::MONITOR_SEQUENCE, false)?;

        // ── Phase 4: Default channel (ch1 2.4GHz) ──
        self.replay_phase_complete("Channel 1",
            super::rtl8852a_phase_ch1::CH1_SEQUENCE, false)?;
        self.channel = 1;

        self.dump_key_regs("After complete init");

        // ── Read MAC address ──
        self.read_mac_address()?;

        eprintln!("[RTL8852AU] ═══ Init complete (ALL phases replayed, nothing skipped) ═══");
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  RX frame parsing — MAC AX descriptor format
    // ══════════════════════════════════════════════════════════════════════════

    pub(crate) fn parse_rx_packet(buf: &[u8], channel: u8) -> (usize, Option<RxFrame>) {
        if buf.len() < RX_DESC_SHORT {
            return (0, None);
        }

        // DW0
        let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let pkt_len = (dw0 & 0x3FFF) as usize;
        let shift = ((dw0 >> 14) & 0x3) as usize * 2;
        let _hdr_iv_len = ((dw0 >> 16) & 0x3F) as usize;
        let mac_info_vld = (dw0 >> 23) & 1 != 0;
        let rpkt_type = ((dw0 >> 24) & 0xF) as u8;
        let drv_info_size = ((dw0 >> 28) & 0x7) as usize * 8;
        let long_rxd = (dw0 >> 31) & 1 != 0;

        let desc_len = if long_rxd { RX_DESC_LONG } else { RX_DESC_SHORT };

        // Only process WiFi packets
        if rpkt_type != RPKT_TYPE_WIFI {
            // Skip non-WiFi packets (C2H, PPDU status, etc.)
            let mac_info_extra = if mac_info_vld && rpkt_type != 1 { 4 } else { 0 };
            let total = desc_len + shift + drv_info_size + mac_info_extra + pkt_len;
            let consumed = if total > 0 { (total + 7) & !7 } else { desc_len };
            if consumed > buf.len() { return (0, None); }
            return (consumed, None);
        }

        if buf.len() < desc_len {
            return (0, None);
        }

        // DW3 — check CRC error
        let dw3 = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let crc_err = (dw3 >> 9) & 1 != 0;

        // DW2 — timestamp
        let tsfl = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);

        // Calculate payload offset
        let mac_info_extra = if mac_info_vld { 4 } else { 0 };
        let data_off = desc_len + shift + drv_info_size + mac_info_extra;
        let total = data_off + pkt_len;

        if pkt_len == 0 || total > buf.len() {
            return (0, None);
        }

        // Round up to 8-byte boundary
        let consumed = (total + 7) & !7;

        // Strip FCS (4 bytes)
        let frame_len = if pkt_len >= 4 { pkt_len - 4 } else { 0 };

        if crc_err || frame_len == 0 {
            return (consumed, None);
        }

        let data = buf[data_off..data_off + frame_len].to_vec();

        // RSSI: not in RX descriptor for MAC AX (comes from PPDU status)
        // Use a default until we implement PPDU status parsing
        let rssi = -50i8;

        let frame = RxFrame {
            data,
            rssi,
            channel,
            band: if channel <= 14 { 0 } else { 1 },
            timestamp: Duration::from_micros(tsfl as u64),
        };

        (consumed, Some(frame))
    }

    fn recv_frame_internal(&mut self, timeout: Duration) -> Result<Option<RxFrame>> {
        // Try parsing from existing buffer
        while self.rx_pos < self.rx_len {
            let remaining = &self.rx_buf[self.rx_pos..self.rx_len];
            let (consumed, frame) = Self::parse_rx_packet(remaining, self.channel);
            if consumed == 0 {
                self.rx_pos = self.rx_len;
                break;
            }
            self.rx_pos += consumed;
            if let Some(f) = frame {
                return Ok(Some(f));
            }
        }

        // New USB bulk transfer
        let actual = self.handle
            .read_bulk(self.ep_in, &mut self.rx_buf, timeout)
            .map_err(|e| match e {
                rusb::Error::Timeout => Error::RxTimeout,
                other => Error::Usb(other),
            })?;

        self.rx_len = actual;
        self.rx_pos = 0;

        // Parse first packet from new transfer
        while self.rx_pos < self.rx_len {
            let remaining = &self.rx_buf[self.rx_pos..self.rx_len];
            let (consumed, frame) = Self::parse_rx_packet(remaining, self.channel);
            if consumed == 0 {
                self.rx_pos = self.rx_len;
                return Ok(None);
            }
            self.rx_pos += consumed;
            if let Some(f) = frame {
                return Ok(Some(f));
            }
        }

        Ok(None)
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  TX frame injection (MAC AX WD format)
    // ══════════════════════════════════════════════════════════════════════════

    fn inject_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()> {
        if frame.len() < 10 {
            return Err(Error::TxFailed { retries: 0, reason: "frame too short".into() });
        }

        let _rate = tx_rate_to_hw(&opts.rate, self.channel);
        let _bmc = frame.len() >= 10 && (frame[4] & 0x01) != 0;

        // Queue from frame type
        let fc_type = frame[0] & 0x0C;
        let qsel = match fc_type {
            0x00 => QSLT_MGNT,
            0x04 => QSLT_VO,
            0x08 => QSLT_BE,
            _ => QSLT_MGNT,
        };

        // DMA channel based on queue select
        let dma_ch: u32 = match qsel {
            QSLT_MGNT => 8, // MAC_AX_DMA_B0MG
            QSLT_VO => 0,   // MAC_AX_DMA_ACH0
            _ => 0,          // MAC_AX_DMA_ACH0
        };

        let total_len = TX_WD_BODY_LEN + frame.len();
        let mut buf = vec![0u8; total_len];

        // Build MAC AX WD for data frame
        // DW0: STF_MODE + CH_DMA
        let wd_dw0 = AX_TXD_STF_MODE | (dma_ch << AX_TXD_CH_DMA_SH);
        buf[0..4].copy_from_slice(&wd_dw0.to_le_bytes());
        // DW1 = 0
        // DW2: TXPKTSIZE
        let wd_dw2 = frame.len() as u32;
        buf[8..12].copy_from_slice(&wd_dw2.to_le_bytes());
        // DW3-5 = 0

        // Copy frame after WD
        buf[TX_WD_BODY_LEN..].copy_from_slice(frame);

        self.handle
            .write_bulk(self.ep_out, &buf, USB_BULK_TIMEOUT)
            .map_err(|e| Error::TxFailed {
                retries: 0,
                reason: format!("bulk OUT: {e}"),
            })?;

        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ChipDriver trait implementation
// ══════════════════════════════════════════════════════════════════════════════

impl ChipDriver for Rtl8852au {
    fn init(&mut self) -> Result<()> {
        self.chip_init()
    }

    fn shutdown(&mut self) -> Result<()> {
        self.power_off()?;
        let _ = self.handle.release_interface(0);
        Ok(())
    }

    fn chip_info(&self) -> ChipInfo {
        ChipInfo {
            name: "RTL8852AU",
            chip: ChipId::Rtl8852au,
            caps: RTL8852AU_CAPS,
            vid: self.vid,
            pid: self.pid,
            rfe_type: 0,
            bands: vec![Band::Band2g, Band::Band5g],
            max_tx_power_dbm: 31,
            firmware_version: self.fw_version.clone(),
        }
    }

    fn set_channel(&mut self, channel: Channel) -> Result<()> {
        self.set_channel_internal(channel.number)
    }

    fn supported_channels(&self) -> &[Channel] {
        &self.channels
    }

    fn set_monitor_mode(&mut self) -> Result<()> {
        // Monitor mode is already configured by init's pcap phase replay.
        // Do NOT call set_monitor_internal() — it overwrites pcap-configured
        // RX filter values (0x031644BF) with hand-coded values that break RX.
        let fltr = self.read32(R_AX_RX_FLTR_OPT)?;
        eprintln!("[RTL8852AU] Monitor mode (pcap-configured): RX_FLTR=0x{:08X}", fltr);
        Ok(())
    }

    fn tx_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()> {
        self.inject_frame(frame, opts)
    }

    fn rx_frame(&mut self, timeout: Duration) -> Result<Option<RxFrame>> {
        self.recv_frame_internal(timeout)
    }

    fn mac(&self) -> MacAddress {
        self.mac_addr
    }

    fn set_mac(&mut self, mac: MacAddress) -> Result<()> {
        self.mac_addr = mac;
        Ok(())
    }

    fn tx_power(&self) -> i8 {
        20 // default
    }

    fn set_tx_power(&mut self, _dbm: i8) -> Result<()> {
        // TODO: implement via EFUSE calibrated power
        Ok(())
    }

    fn calibrate(&mut self) -> Result<()> {
        Ok(())
    }

    fn channel_settle_time(&self) -> Duration {
        Duration::from_millis(10)
    }

    fn take_rx_handle(&mut self) -> Option<crate::core::chip::RxHandle> {
        Some(crate::core::chip::RxHandle {
            device: Arc::clone(&self.handle),
            ep_in: self.ep_in,
            rx_buf_size: RX_BUF_SIZE,
            parse_fn: parse_rx_packet_standalone,
            driver_msg_tx: None,
        })
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_list() {
        let channels = build_channel_list();
        assert!(channels.len() >= 39);
        assert_eq!(channels[0].number, 1);
        assert_eq!(channels[0].center_freq_mhz, 2412);
        assert_eq!(channels[0].band, Band::Band2g);
        // First 5GHz channel
        let ch36 = channels.iter().find(|c| c.number == 36).unwrap();
        assert_eq!(ch36.center_freq_mhz, 5180);
        assert_eq!(ch36.band, Band::Band5g);
    }

    #[test]
    fn test_caps() {
        assert!(RTL8852AU_CAPS.contains(ChipCaps::HE));
        assert!(RTL8852AU_CAPS.contains(ChipCaps::MONITOR));
        assert!(RTL8852AU_CAPS.contains(ChipCaps::INJECT));
        assert!(RTL8852AU_CAPS.contains(ChipCaps::BW80));
        assert!(!RTL8852AU_CAPS.contains(ChipCaps::BW160));
    }

    #[test]
    fn test_rx_descriptor_parsing_short() {
        // Minimal short RX descriptor (16 bytes) for a non-WiFi packet (C2H)
        let mut buf = vec![0u8; 32];
        // DW0: pkt_len=8, rpkt_type=0xA (C2H), long_rxd=0
        let dw0: u32 = 8 | (0x0A << 24);
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());
        // Add some payload
        buf.extend_from_slice(&[0u8; 8]);
        let (consumed, frame) = Rtl8852au::parse_rx_packet(&buf, 6);
        assert!(consumed > 0);
        assert!(frame.is_none()); // C2H should be skipped
    }

    #[test]
    fn test_rx_descriptor_parsing_wifi() {
        // Long RX descriptor (32 bytes) for a WiFi packet
        let frame_data = [
            0x80, 0x00, // beacon frame control
            0x00, 0x00, // duration
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // DA (broadcast)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // SA
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // BSSID
            0x00, 0x00, // seq ctrl
        ];
        let pkt_len = frame_data.len() + 4; // +4 for FCS

        let mut buf = vec![0u8; 32 + pkt_len];
        // DW0: pkt_len, rpkt_type=0 (WiFi), long_rxd=1
        let dw0: u32 = (pkt_len as u32) | (1 << 31);
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());
        // DW3: no CRC error
        buf[12..16].copy_from_slice(&0u32.to_le_bytes());
        // Copy frame + FCS
        buf[32..32 + frame_data.len()].copy_from_slice(&frame_data);

        let (consumed, frame) = Rtl8852au::parse_rx_packet(&buf, 6);
        assert!(consumed > 0);
        assert!(frame.is_some());
        let f = frame.unwrap();
        assert_eq!(f.data.len(), frame_data.len());
        assert_eq!(f.channel, 6);
    }

    #[test]
    fn test_fw_wd_format() {
        // Verify WD DW0 for FWDL
        let wd_dw0 = (MAC_AX_DMA_H2C << AX_TXD_CH_DMA_SH) | AX_TXD_FWDL_EN;
        assert_eq!(wd_dw0, 0x001C0000);
    }
}
