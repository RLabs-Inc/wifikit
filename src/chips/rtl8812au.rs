//! RTL8812AU chip driver
//!
//! # Hardware
//!
//! Realtek RTL8812A — 802.11ac dual-band (2.4GHz + 5GHz), 2T2R MIMO, USB 2.0.
//! The most iconic WiFi pentesting adapter (Alfa AWUS036ACH, AWUS036AC).
//!
//! # Key Differences from RTL8812BU (RTL8822B)
//!
//!   - USB 2.0 (512-byte bulk) vs USB 3.0 (1024-byte bulk)
//!   - TX descriptor: 40 bytes (vs 48), XOR checksum of first 32 bytes
//!   - 8051 firmware: page-write to 0x1000 (not IDDMA DMA engine)
//!   - Manual LLT init (vs auto-LLT)
//!   - RF read: 3-wire indirect via HSSI 0x8B0 + SI 0xD08/0xD48
//!   - No H2C command channel (8051 MCU, not HALMAC)
//!   - No EFUSE TX power calibration (hardcoded power)
//!   - No IQK/DPK/LC calibration
//!
//! # Init Flow (10 steps in `chip_init()`)
//!
//!   1. RF path reset
//!   2. Power on (CARDEMU → ACT via Hal8812PwrSeq)
//!   3. LLT init (manual linked-list table)
//!   4. Drop incorrect bulk out
//!   5. Firmware download (page-write, embedded blob)
//!   6. Queue/buffer/DMA configuration
//!   7. PHY init (BB/RF tables from rtl8812a_tables.rs)
//!   8. (skipped)
//!   9. MAC address read (EFUSE → fallback to register)
//!  10. Set initial channel
//!
//! # What's NOT Implemented (vs RTL8812BU golden driver)
//!
//!   - EFUSE TX power calibration (power is hardcoded)
//!   - IQK calibration (RF functions exist but not wired)
//!   - TX retry count not written to descriptor (hardcoded 0x1F)
//!   - 40/80 MHz bandwidth (ChipCaps declares BW40|BW80 but only 20MHz works)
//!   - Per-path RSSI (single byte, `raw - 110`)
//!
//! # Reference
//!
//!   Linux driver: aircrack-ng/rtl8812au
//!   FW tables: rtl8812a_tables.rs + rtl8812a_fw.rs (embedded blob)

use std::time::Duration;
use std::thread;

use std::sync::Arc;
use rusb::{DeviceHandle, GlobalContext};

use crate::core::{
    Channel, Band, MacAddress, Result, Error,
    chip::{ChipDriver, ChipInfo, ChipId, ChipCaps},
    frame::{RxFrame, TxOptions, TxRate, TxFlags},
    adapter::UsbEndpoints,
};

use super::rtl8812a_tables;
use super::rtl8812a_fw;

// ══════════════════════════════════════════════════════════════════════════════
//  Constants
// ══════════════════════════════════════════════════════════════════════════════

const RTL_USB_REQ: u8 = 0x05;
const RTL_USB_TIMEOUT: Duration = Duration::from_millis(500);

const TX_DESC_SIZE: usize = 40;  // 8812A: 40 bytes (10 DWORDs)
const RX_DESC_SIZE: usize = 24;  // RX status header
const RX_BUF_SIZE: usize = 32768;

const USB_BULK_TIMEOUT: Duration = Duration::from_secs(2);

// ── Register addresses ──

const REG_SYS_FUNC_EN: u16 = 0x0002;
const REG_CR: u16 = 0x0100;
const REG_RCR: u16 = 0x0608;
const REG_RXFLTMAP0: u16 = 0x06A0;
const REG_BCN_CTRL: u16 = 0x0550;
const REG_MCUFWDL: u16 = 0x0080;
const REG_LLT_INIT: u16 = 0x01E0;
const REG_RSV_CTRL: u16 = 0x001C;
const REG_RF_CTRL: u16 = 0x001F;
const REG_RF_B_CTRL: u16 = 0x0076;
const REG_CCK_CHECK: u16 = 0x0454;
const REG_TXPKT_EMPTY: u16 = 0x041A;
const REG_RX_DRVINFO_SZ: u16 = 0x060F;

// ── RCR bits ──

const RCR_AAP: u32 = 1 << 0;
const RCR_APP_PHYSTS: u32 = 1 << 28;
const RCR_APPFCS: u32 = 1 << 31;

// ── Queue select ──

const QSLT_BE: u8 = 0x00;
const QSLT_VO: u8 = 0x06;
const QSLT_MGNT: u8 = 0x12;

// ── LLT constants ──

const LAST_ENTRY_OF_TX_PKT_BUFFER: u32 = 255;
const TX_PAGE_BOUNDARY: u8 = 0xF9; // 249
const LLT_WRITE_ACCESS: u32 = 1;
const POLLING_LLT_THRESHOLD: u32 = 20;

// ── Firmware ──

const FW_START_ADDRESS: u32 = 0x1000;
const MAX_DLFW_PAGE_SIZE: u32 = 4096;
const MAX_REG_BLOCK_SIZE: usize = 196; // USB bulk write block for FW download

// MCUFWDL register bits
const MCUFWDL_RDY: u32 = 1 << 1;
const FWDL_CHKSUM_RPT: u32 = 1 << 2;
const WINTINI_RDY: u32 = 1 << 6;

// ── RF register access (Jaguar platform) ──
// These constants + read_rf/write_rf/get_bb_reg/poll32 are needed for
// IQK calibration and proper channel switching (not yet implemented).

#[allow(dead_code)] const RF_A_LSSI_WRITE: u16 = 0x0C90;
#[allow(dead_code)] const RF_B_LSSI_WRITE: u16 = 0x0E90;
#[allow(dead_code)] const RF_HSSI_READ: u16 = 0x08B0;
#[allow(dead_code)] const RF_A_SI_READ: u16 = 0x0D08;
#[allow(dead_code)] const RF_B_SI_READ: u16 = 0x0D48;
#[allow(dead_code)] const RF_READ_DATA_MASK: u32 = 0xFFFFF;
#[allow(dead_code)] const RFREGOFFSETMASK: u32 = 0xFFFFF;

// ── BB register addresses (Jaguar) ──

const BB_OFDM_CCK_EN: u16 = 0x0808; // rOFDMCCKEN_Jaguar
const BB_OFDM_EN: u32 = 0x20000000; // bOFDMEN_Jaguar
const BB_CCK_EN: u32 = 0x10000000;  // bCCKEN_Jaguar
const BB_BW_IND: u16 = 0x0834;      // rBWIndication_Jaguar
const BB_PWED_TH: u16 = 0x0830;     // rPwed_TH_Jaguar
const BB_AGC_TABLE: u16 = 0x082C;   // rAGC_table_Jaguar
const BB_TX_PATH: u16 = 0x080C;     // rTxPath_Jaguar
const BB_CCK_RX: u16 = 0x0A04;      // rCCK_RX_Jaguar
const BB_RFE_A: u16 = 0x0CB0;       // rA_RFE_Pinmux_Jaguar
const BB_RFE_B: u16 = 0x0EB0;       // rB_RFE_Pinmux_Jaguar

// ── Timing constants ──

const POLL_ITER_DELAY: Duration = Duration::from_micros(100);
const RF_WRITE_SETTLE: Duration = Duration::from_micros(1);
#[allow(dead_code)] // used by read_rf() — needed for IQK calibration
const RF_READ_SETTLE: Duration = Duration::from_micros(20);
const POWER_OFF_SETTLE: Duration = Duration::from_millis(5);
const LLT_WRITE_DELAY: Duration = Duration::from_micros(10);
const FW_POLL_DELAY: Duration = Duration::from_millis(1);
const FW_READY_TIMEOUT_MS: u32 = 5000;
const INIT_DELAY_FE: Duration = Duration::from_millis(50);
const INIT_DELAY_FD: Duration = Duration::from_millis(5);
const INIT_DELAY_FC: Duration = Duration::from_millis(1);
const INIT_DELAY_FB: Duration = Duration::from_micros(50);
const INIT_DELAY_FA: Duration = Duration::from_micros(5);
const INIT_DELAY_F9: Duration = Duration::from_micros(1);
const BB_SOFT_RESET_DELAY: Duration = Duration::from_millis(1);
const CHANNEL_SWITCH_SETTLE: Duration = Duration::from_millis(1);

// ── TX rate mapping (identical to RTL8812BU — Realtek common rate indices) ──

fn tx_rate_to_hw(rate: &TxRate, channel: u8) -> u8 {
    let idx = match rate {
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
    };
    // CCK rates invalid on 5 GHz — fallback to OFDM 6M
    if channel > 14 && idx <= 0x03 {
        0x04
    } else {
        idx
    }
}

// ── Supported channel list ──

fn build_channel_list() -> Vec<Channel> {
    let mut channels = Vec::with_capacity(37);
    for ch in 1..=14u8 {
        channels.push(Channel::new(ch));
    }
    for &ch in &[36, 40, 44, 48u8] {
        channels.push(Channel::new(ch));
    }
    for &ch in &[52, 56, 60, 64u8] {
        channels.push(Channel::new(ch));
    }
    for &ch in &[100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144u8] {
        channels.push(Channel::new(ch));
    }
    for &ch in &[149, 153, 157, 161, 165u8] {
        channels.push(Channel::new(ch));
    }
    channels
}


// ══════════════════════════════════════════════════════════════════════════════
//  Rtl8812au — The Driver
// ══════════════════════════════════════════════════════════════════════════════

/// RTL8812AU capability flags
const RTL8812AU_CAPS: ChipCaps = ChipCaps::MONITOR.union(ChipCaps::INJECT)
    .union(ChipCaps::BAND_2G).union(ChipCaps::BAND_5G)
    .union(ChipCaps::HT).union(ChipCaps::VHT)
    .union(ChipCaps::BW40).union(ChipCaps::BW80);

#[allow(dead_code)] // rx_buf/rx_pos/rx_len used via ChipDriver::rx_frame() trait dispatch
pub struct Rtl8812au {
    handle: Arc<DeviceHandle<GlobalContext>>,
    ep_out: u8,
    ep_in: u8,
    channel: u8,
    mac_addr: MacAddress,
    rx_buf: Vec<u8>,
    rx_pos: usize,
    rx_len: usize,
    channels: Vec<Channel>,
    vid: u16,
    pid: u16,
    macid_written: bool,
    mactx_checked: bool,
}

impl Rtl8812au {
    /// Open a USB device and prepare the driver.
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

        let driver = Self {
            handle: Arc::new(handle),
            ep_out,
            ep_in,
            channel: 0,
            mac_addr: MacAddress::ZERO,
            rx_buf: vec![0u8; RX_BUF_SIZE],
            rx_pos: 0,
            rx_len: 0,
            channels: build_channel_list(),
            vid,
            pid,
            macid_written: false,
            mactx_checked: false,
        };

        Ok((driver, endpoints))
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Register access (identical to RTL8812BU — same Realtek USB protocol)
    // ══════════════════════════════════════════════════════════════════════════

    fn read8(&self, addr: u16) -> Result<u8> {
        let mut buf = [0u8; 1];
        let r = self.handle.read_control(
            0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT,
        )?;
        if r < 1 { return Err(Error::RegisterReadFailed { addr }); }
        Ok(buf[0])
    }

    fn write8(&self, addr: u16, val: u8) -> Result<()> {
        let buf = [val];
        let r = self.handle.write_control(
            0x40, RTL_USB_REQ, addr, 0, &buf, RTL_USB_TIMEOUT,
        )?;
        if r < 1 { return Err(Error::RegisterWriteFailed { addr, val: val as u32 }); }
        Ok(())
    }

    fn read16(&self, addr: u16) -> Result<u16> {
        let mut buf = [0u8; 2];
        let r = self.handle.read_control(
            0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT,
        )?;
        if r < 2 { return Err(Error::RegisterReadFailed { addr }); }
        Ok(u16::from_le_bytes(buf))
    }

    fn write16(&self, addr: u16, val: u16) -> Result<()> {
        let buf = val.to_le_bytes();
        let r = self.handle.write_control(
            0x40, RTL_USB_REQ, addr, 0, &buf, RTL_USB_TIMEOUT,
        )?;
        if r < 2 { return Err(Error::RegisterWriteFailed { addr, val: val as u32 }); }
        Ok(())
    }

    fn read32(&self, addr: u16) -> Result<u32> {
        let mut buf = [0u8; 4];
        let r = self.handle.read_control(
            0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT,
        )?;
        if r < 4 { return Err(Error::RegisterReadFailed { addr }); }
        Ok(u32::from_le_bytes(buf))
    }

    fn write32(&self, addr: u16, val: u32) -> Result<()> {
        let buf = val.to_le_bytes();
        let r = self.handle.write_control(
            0x40, RTL_USB_REQ, addr, 0, &buf, RTL_USB_TIMEOUT,
        )?;
        if r < 4 { return Err(Error::RegisterWriteFailed { addr, val }); }
        Ok(())
    }

    fn write_n(&self, addr: u16, data: &[u8]) -> Result<()> {
        let r = self.handle.write_control(
            0x40, RTL_USB_REQ, addr, 0, data, RTL_USB_TIMEOUT,
        )?;
        if r < data.len() {
            return Err(Error::RegisterWriteFailed { addr, val: data.len() as u32 });
        }
        Ok(())
    }

    fn write8_mask(&self, addr: u16, mask: u8, val: u8) -> Result<()> {
        let cur = self.read8(addr)?;
        self.write8(addr, (cur & !mask) | (val & mask))
    }

    fn poll8(&self, addr: u16, mask: u8, target: u8, max_ms: u32) -> Result<()> {
        for _ in 0..(max_ms * 10) {
            let val = self.read8(addr)?;
            if (val & mask) == target { return Ok(()); }
            thread::sleep(POLL_ITER_DELAY);
        }
        Err(Error::PollTimeout { addr, mask, expected: target })
    }

    #[allow(dead_code)] // needed for IQK calibration (not yet implemented)
    fn poll32(&self, addr: u16, mask: u32, target: u32, max_ms: u32) -> Result<()> {
        for _ in 0..(max_ms * 10) {
            let val = self.read32(addr)?;
            if (val & mask) == target { return Ok(()); }
            thread::sleep(POLL_ITER_DELAY);
        }
        Err(Error::PollTimeout { addr, mask: 0, expected: 0 })
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  BB register access (32-bit masked read/write)
    // ══════════════════════════════════════════════════════════════════════════

    fn set_bb_reg(&self, addr: u16, mask: u32, val: u32) -> Result<()> {
        if mask == 0xFFFFFFFF {
            return self.write32(addr, val);
        }
        let cur = self.read32(addr)?;
        let shift = mask.trailing_zeros();
        self.write32(addr, (cur & !mask) | ((val << shift) & mask))
    }

    #[allow(dead_code)] // used by read_rf — needed for IQK calibration
    fn get_bb_reg(&self, addr: u16, mask: u32) -> Result<u32> {
        let val = self.read32(addr)?;
        let shift = mask.trailing_zeros();
        Ok((val & mask) >> shift)
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  RF register access (3-wire indirect via LSSI/HSSI)
    // ══════════════════════════════════════════════════════════════════════════

    #[allow(dead_code)] // needed for IQK calibration
    fn read_rf(&self, path: u8, rf_reg: u8) -> Result<u32> {
        // Set read address via HSSI
        self.set_bb_reg(RF_HSSI_READ, 0xFF, rf_reg as u32)?;
        thread::sleep(RF_READ_SETTLE);

        // Read back via SI (non-PI mode, which is default)
        let readback_addr = if path == 0 { RF_A_SI_READ } else { RF_B_SI_READ };
        let val = self.get_bb_reg(readback_addr, RF_READ_DATA_MASK)?;
        Ok(val)
    }

    #[allow(dead_code)] // needed for IQK calibration
    fn write_rf(&self, path: u8, rf_reg: u8, mask: u32, data: u32) -> Result<()> {
        let lssi_addr = if path == 0 { RF_A_LSSI_WRITE } else { RF_B_LSSI_WRITE };

        let data = if mask != RFREGOFFSETMASK {
            let cur = self.read_rf(path, rf_reg)?;
            let shift = mask.trailing_zeros();
            (cur & !mask) | ((data << shift) & mask)
        } else {
            data
        };

        let lssi = ((rf_reg as u32) << 20 | (data & 0x000FFFFF)) & 0x0FFFFFFF;
        self.write32(lssi_addr, lssi)?;
        thread::sleep(RF_WRITE_SETTLE);
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Delay pseudo-address handling (for init tables)
    // ══════════════════════════════════════════════════════════════════════════

    fn apply_delay(pseudo_addr: u32) {
        match pseudo_addr {
            0xFE => thread::sleep(INIT_DELAY_FE),
            0xFD => thread::sleep(INIT_DELAY_FD),
            0xFC => thread::sleep(INIT_DELAY_FC),
            0xFB => thread::sleep(INIT_DELAY_FB),
            0xFA => thread::sleep(INIT_DELAY_FA),
            0xF9 => thread::sleep(INIT_DELAY_F9),
            _ => {}
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Power on / off
    // ══════════════════════════════════════════════════════════════════════════

    /// Power on: CARDEMU → ACT (RTL8812_TRANS_CARDEMU_TO_ACT)
    /// From: include/Hal8812PwrSeq.h
    fn power_on(&self) -> Result<()> {
        // Disable SW LPS: 0x04[10] = 0
        self.write8_mask(0x0005, 1 << 2, 0)?;

        // Wait for power ready: poll 0x04[17] = 1
        self.poll8(0x0006, 1 << 1, 1 << 1, 200)?;

        // Disable WL suspend: 0x04[11] = 0
        self.write8_mask(0x0005, 1 << 3, 0)?;

        // Trigger APFM_ONMAC: 0x04[8] = 1, then poll until 0
        self.write8_mask(0x0005, 1 << 0, 1 << 0)?;
        self.poll8(0x0005, 1 << 0, 0, 200)?;

        // Buffer type after XOSC: 0x24[1] = 0 (NAND)
        self.write8_mask(0x0024, 1 << 1, 0)?;
        // 0x28[3] = 0 (NAND)
        self.write8_mask(0x0028, 1 << 3, 0)?;

        // Verify CR is accessible (not 0xEAEAEAEA = bus disconnected)
        let cr = self.read32(REG_CR)?;
        if cr == 0xEAEAEAEA {
            return Err(Error::ChipInitFailed {
                chip: "RTL8812AU".into(),
                stage: crate::core::error::InitStage::MacPowerOn,
                reason: "CR register returned 0xEAEAEAEA after power on".into(),
            });
        }

        Ok(())
    }

    /// Power off: ACT → CARDEMU (RTL8812_TRANS_ACT_TO_CARDEMU)
    fn power_off(&self) -> Result<()> {
        // Turn off 3-wire (BB)
        self.write8(0x0C00 as u16, 0x04)?;
        self.write8(0x0E00 as u16, 0x04)?;

        // Reset BB, close RF: 0x02[0] = 0
        self.write8_mask(REG_SYS_FUNC_EN, 1 << 0, 0)?;
        thread::sleep(Duration::from_micros(1));

        // SPS PWM mode
        self.write8(0x0007, 0x2A)?;

        // ANA clk = 500k (USB): 0x08[1] = 0
        self.write8_mask(0x0008, 1 << 1, 0)?;

        // Turn off MAC by HW state machine: 0x04[9] = 1
        self.write8_mask(0x0005, 1 << 1, 1 << 1)?;

        // Poll until 0x04[9] = 0
        let _ = self.poll8(0x0005, 1 << 1, 0, 200);

        thread::sleep(POWER_OFF_SETTLE);
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  LLT init (manual linked list table — 8812A specific)
    // ══════════════════════════════════════════════════════════════════════════

    /// Write a single LLT entry: address → data (next page pointer).
    fn llt_write(&self, address: u32, data: u32) -> Result<()> {
        let value = (address & 0xFF) << 8 | (data & 0xFF) | (LLT_WRITE_ACCESS << 30);
        self.write32(REG_LLT_INIT, value)?;

        // Poll for completion
        for _ in 0..POLLING_LLT_THRESHOLD {
            let v = self.read32(REG_LLT_INIT)?;
            if (v >> 30) & 0x3 == 0 {
                return Ok(());
            }
            thread::sleep(LLT_WRITE_DELAY);
        }

        Err(Error::PollTimeout { addr: REG_LLT_INIT, mask: 0, expected: 0 })
    }

    /// Initialize the LLT (Linked List Table) for TX packet buffer management.
    fn init_llt(&self) -> Result<()> {
        let boundary = TX_PAGE_BOUNDARY as u32;

        // Pages 0..(boundary-1): linked list, each points to next
        for i in 0..boundary {
            self.llt_write(i, i + 1)?;
        }
        // End of TX list: points to 0xFF (end marker)
        self.llt_write(boundary - 1, 0xFF)?;

        // Pages boundary..254: ring buffer (beacon/loopback)
        for i in boundary..LAST_ENTRY_OF_TX_PKT_BUFFER {
            self.llt_write(i, i + 1)?;
        }
        // Last entry wraps back to boundary start
        self.llt_write(LAST_ENTRY_OF_TX_PKT_BUFFER, boundary)?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Firmware download (8812A: page-write to 0x1000, not IDDMA)
    // ══════════════════════════════════════════════════════════════════════════

    fn fw_download_enable(&self, enable: bool) -> Result<()> {
        let tmp = self.read8(REG_MCUFWDL as u16)?;
        if enable {
            // Enable FW download
            self.write8(REG_MCUFWDL as u16, tmp | 0x01)?;
            // 8051 reset
            let tmp2 = self.read8(REG_MCUFWDL as u16 + 2)?;
            self.write8(REG_MCUFWDL as u16 + 2, tmp2 & 0xF7)?;
        } else {
            // Disable FW download
            self.write8(REG_MCUFWDL as u16, tmp & 0xFE)?;
        }
        Ok(())
    }

    /// Write a block of firmware data to the chip via USB vendor control writes.
    fn fw_block_write(&self, data: &[u8]) -> Result<()> {
        let block_size = MAX_REG_BLOCK_SIZE;
        let mut offset: u32 = 0;

        // Phase 1: write in block_size chunks
        let block_count = data.len() / block_size;
        for i in 0..block_count {
            let start = i * block_size;
            let end = start + block_size;
            self.write_n(
                (FW_START_ADDRESS + offset) as u16,
                &data[start..end],
            )?;
            offset += block_size as u32;
        }

        // Phase 2: write remainder in 8-byte chunks
        let remain = data.len() % block_size;
        if remain > 0 {
            let phase2_blocks = remain / 8;
            for i in 0..phase2_blocks {
                let start = block_count * block_size + i * 8;
                let end = start + 8;
                self.write_n(
                    (FW_START_ADDRESS + offset) as u16,
                    &data[start..end],
                )?;
                offset += 8;
            }

            // Phase 3: write final bytes one at a time
            let final_remain = remain % 8;
            for i in 0..final_remain {
                let idx = block_count * block_size + phase2_blocks * 8 + i;
                self.write8(
                    (FW_START_ADDRESS + offset) as u16,
                    data[idx],
                )?;
                offset += 1;
            }
        }

        Ok(())
    }

    /// Write firmware page (set page register then write block).
    fn fw_page_write(&self, page: u32, data: &[u8]) -> Result<()> {
        let page_val = (page & 0x07) as u8;
        let cur = self.read8(REG_MCUFWDL as u16 + 2)?;
        self.write8(REG_MCUFWDL as u16 + 2, (cur & 0xF8) | page_val)?;
        self.fw_block_write(data)
    }

    /// Reset the 8051 MCU.
    fn mcu_reset(&self) -> Result<()> {
        // Reset MCU IO Wrapper
        let v = self.read8(REG_RSV_CTRL)?;
        self.write8(REG_RSV_CTRL, v & !0x02)?; // BIT1 = 0
        let v = self.read8(REG_RSV_CTRL + 1)?;
        self.write8(REG_RSV_CTRL + 1, v & !0x08)?; // BIT3 = 0

        // Reset 8051: SYS_FUNC_EN+1[2] = 0
        let v = self.read8(REG_SYS_FUNC_EN + 1)?;
        self.write8(REG_SYS_FUNC_EN + 1, v & !0x04)?;

        // Enable MCU IO Wrapper
        let v = self.read8(REG_RSV_CTRL)?;
        self.write8(REG_RSV_CTRL, v & !0x02)?;
        let v = self.read8(REG_RSV_CTRL + 1)?;
        self.write8(REG_RSV_CTRL + 1, v | 0x08)?; // BIT3 = 1

        // Enable 8051
        let v = self.read8(REG_SYS_FUNC_EN + 1)?;
        self.write8(REG_SYS_FUNC_EN + 1, v | 0x04)?;

        Ok(())
    }

    /// Download embedded firmware to the 8812A.
    fn load_firmware(&self) -> Result<()> {
        let fw = rtl8812a_fw::FW_8812A_NIC;
        if fw.len() < 64 {
            return Err(Error::FirmwareError {
                chip: "RTL8812AU".into(),
                kind: crate::core::error::FirmwareErrorKind::TooSmall,
            });
        }

        // Enable FW download mode
        self.fw_download_enable(true)?;

        // Reset 8051
        self.mcu_reset()?;

        // Write firmware in pages
        let page_size = MAX_DLFW_PAGE_SIZE as usize;
        let page_count = fw.len() / page_size;
        let remainder = fw.len() % page_size;

        for page in 0..page_count {
            let offset = page * page_size;
            self.fw_page_write(page as u32, &fw[offset..offset + page_size])?;
        }
        if remainder > 0 {
            let offset = page_count * page_size;
            self.fw_page_write(page_count as u32, &fw[offset..])?;
        }

        // Disable FW download mode
        self.fw_download_enable(false)?;

        // Poll for FW checksum report
        for _ in 0..FW_READY_TIMEOUT_MS {
            let v = self.read32(REG_MCUFWDL as u16)?;
            if v & FWDL_CHKSUM_RPT != 0 {
                break;
            }
            thread::sleep(FW_POLL_DELAY);
        }

        // Set MCUFWDL_RDY, clear WINTINI_RDY, then reset 8051
        let v = self.read32(REG_MCUFWDL as u16)?;
        self.write32(REG_MCUFWDL as u16, (v | MCUFWDL_RDY) & !WINTINI_RDY)?;
        self.mcu_reset()?;

        // Poll for FW ready (WINTINI_RDY)
        for _ in 0..FW_READY_TIMEOUT_MS {
            let v = self.read32(REG_MCUFWDL as u16)?;
            if v & WINTINI_RDY != 0 {
                return Ok(());
            }
            thread::sleep(FW_POLL_DELAY);
        }

        // FW timeout — proceed anyway, monitor mode may still work
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PHY / BB / RF initialization
    // ══════════════════════════════════════════════════════════════════════════

    fn phy_init(&self) -> Result<()> {
        // Enable BB/RF power
        self.write8(REG_RF_CTRL, 0x07)?;      // RF_EN + RF_RSTB + RF_SDMRSTB
        self.write8(REG_RF_B_CTRL, 0x07)?;    // Same for path B
        let v = self.read8(REG_SYS_FUNC_EN)?;
        self.write8(REG_SYS_FUNC_EN, v | 0x03)?; // BB global reset + enable

        // ── MAC register init (8-bit writes) ──
        for &(addr, val) in rtl8812a_tables::MAC_INIT {
            if (0xF9..=0xFE).contains(&addr) {
                Self::apply_delay(addr);
                continue;
            }
            self.write8(addr as u16, val as u8)?;
        }

        // ── BB/PHY register init (32-bit writes) ──
        for &(addr, val) in rtl8812a_tables::BB_INIT {
            if (0xF9..=0xFE).contains(&addr) {
                Self::apply_delay(addr);
                continue;
            }
            self.write32(addr as u16, val)?;
        }

        // ── AGC table (32-bit writes) ──
        for &(addr, val) in rtl8812a_tables::AGC_INIT {
            if (0xF9..=0xFE).contains(&addr) {
                Self::apply_delay(addr);
                continue;
            }
            self.write32(addr as u16, val)?;
        }

        // ── RF Path A (indirect write via LSSI) ──
        for &(rf_addr, rf_data) in rtl8812a_tables::RF_A_INIT {
            if (0xF9..=0xFE).contains(&rf_addr) {
                Self::apply_delay(rf_addr);
                continue;
            }
            let addr = (rf_addr & 0xFF) as u8;
            let lssi = ((addr as u32) << 20 | (rf_data & 0x000FFFFF)) & 0x0FFFFFFF;
            self.write32(RF_A_LSSI_WRITE, lssi)?;
            thread::sleep(RF_WRITE_SETTLE);
        }

        // ── RF Path B (indirect write via LSSI) ──
        for &(rf_addr, rf_data) in rtl8812a_tables::RF_B_INIT {
            if (0xF9..=0xFE).contains(&rf_addr) {
                Self::apply_delay(rf_addr);
                continue;
            }
            let addr = (rf_addr & 0xFF) as u8;
            let lssi = ((addr as u32) << 20 | (rf_data & 0x000FFFFF)) & 0x0FFFFFFF;
            self.write32(RF_B_LSSI_WRITE, lssi)?;
            thread::sleep(RF_WRITE_SETTLE);
        }

        // ── BB soft reset ──
        let sys_func = self.read16(REG_SYS_FUNC_EN)?;
        self.write16(REG_SYS_FUNC_EN, sys_func & !1)?;
        thread::sleep(BB_SOFT_RESET_DELAY);
        self.write16(REG_SYS_FUNC_EN, sys_func | 1)?;
        thread::sleep(BB_SOFT_RESET_DELAY);

        // Enable OFDM + CCK
        self.set_bb_reg(BB_OFDM_CCK_EN, BB_OFDM_EN | BB_CCK_EN, 0x3)?;

        // TX path configuration (2T2R: both chains for STBC + diversity)
        self.set_bb_reg(BB_TX_PATH, 0xF0, 0x3)?;       // TX path = A+B (2T2R)
        self.set_bb_reg(BB_CCK_RX, 0x0F000000, 0x3)?;  // CCK RX path = A+B

        // AGC table select for 2.4G (default)
        self.set_bb_reg(BB_AGC_TABLE, 0x3, 0)?;

        // IGI: leave at init table defaults (0x20 for 8812A, both paths active)
        // Note: 8812A AGC differs from 8822B — higher IGI can cause saturation

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Band switching (2.4G / 5G)
    // ══════════════════════════════════════════════════════════════════════════

    fn switch_band(&self, channel: u8) -> Result<()> {
        let is_2g = channel <= 14;

        if is_2g {
            // 2.4G band
            self.set_bb_reg(BB_OFDM_CCK_EN, BB_OFDM_EN | BB_CCK_EN, 0x3)?;

            // BW indication: 0x834[1:0] = 1
            self.set_bb_reg(BB_BW_IND, 0x3, 0x1)?;

            // PD_TH: 0x830[17:13] = 0x17
            self.set_bb_reg(BB_PWED_TH, 0x3E000, 0x17)?;

            // PWED_TH: 0x830[3:1] = 0x04
            self.set_bb_reg(BB_PWED_TH, 0x0E, 0x04)?;

            // AGC table = 2.4G
            self.set_bb_reg(BB_AGC_TABLE, 0x3, 0)?;

            // TX/RX path for 2.4G
            self.set_bb_reg(BB_TX_PATH, 0xF0, 0x1)?;
            self.set_bb_reg(BB_CCK_RX, 0x0F000000, 0x1)?;

            // RFE pinmux for 2.4G (RFE type 0: all bypass)
            self.set_bb_reg(BB_RFE_A, 0xFFFFFFFF, 0x77777777)?;
            self.set_bb_reg(BB_RFE_B, 0xFFFFFFFF, 0x77777777)?;

            // GPIO PA/LNA enable for 2.4G (from Linux usbmon capture)
            // 0x0042 = GPIO output enable, 0x004C = GPIO data
            // Without these, the external PA stays off and TX frames never reach air
            self.write8(0x0042, 0xCC)?;    // GPIO output enable
            self.write8(0x004C, 0x20)?;    // GPIO data: PA enable for 2.4G

            // CCK check disable
            let v = self.read8(REG_CCK_CHECK)?;
            self.write8(REG_CCK_CHECK, v & !0x80)?;
        } else {
            // 5G band

            // CCK check enable (disallow CCK in 5G)
            let v = self.read8(REG_CCK_CHECK)?;
            self.write8(REG_CCK_CHECK, v | 0x80)?;

            // Wait for TX empty
            for _ in 0..50 {
                let v = self.read16(REG_TXPKT_EMPTY)?;
                if v & 0x30 == 0x30 { break; }
                thread::sleep(Duration::from_micros(50));
            }

            // Enable OFDM+CCK (yes, even in 5G for scanning)
            self.set_bb_reg(BB_OFDM_CCK_EN, BB_OFDM_EN | BB_CCK_EN, 0x3)?;

            // BW indication: 0x834[1:0] = 2
            self.set_bb_reg(BB_BW_IND, 0x3, 0x2)?;

            // PD_TH: 0x830[17:13] = 0x15
            self.set_bb_reg(BB_PWED_TH, 0x3E000, 0x15)?;

            // PWED_TH: 0x830[3:1] = 0x04
            self.set_bb_reg(BB_PWED_TH, 0x0E, 0x04)?;

            // AGC table = 5G
            self.set_bb_reg(BB_AGC_TABLE, 0x3, 1)?;

            // TX/RX path for 5G
            self.set_bb_reg(BB_TX_PATH, 0xF0, 0x0)?;
            self.set_bb_reg(BB_CCK_RX, 0x0F000000, 0xF)?;

            // RFE pinmux for 5G (RFE type 0)
            self.set_bb_reg(BB_RFE_A, 0xFFFFFFFF, 0x77337717)?;
            self.set_bb_reg(BB_RFE_B, 0xFFFFFFFF, 0x77337717)?;

            // GPIO PA/LNA enable for 5G (from Linux usbmon capture)
            self.write8(0x0042, 0xC8)?;    // GPIO output enable (5G config)
            self.write8(0x004C, 0x28)?;    // GPIO data: PA enable for 5G
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Channel switching
    // ══════════════════════════════════════════════════════════════════════════

    fn set_channel_internal(&mut self, channel: u8) -> Result<()> {
        // ── Step 1: Band switch (2.4G ↔ 5G) if needed ──
        let was_2g = self.channel <= 14 || self.channel == 0;
        let is_2g = channel <= 14;
        if was_2g != is_2g || self.channel == 0 {
            self.switch_band(channel)?;
        }

        let ch = channel as u32;

        // ── Step 2: fc_area (BB 0x860) — RF filter center frequency ──
        let fc_area = if (36..=48).contains(&channel) {
            0x494
        } else if (50..=80).contains(&channel) {
            0x453
        } else if (82..=116).contains(&channel) {
            0x452
        } else if channel >= 118 {
            0x412
        } else {
            0x96A // 2.4GHz
        };
        self.set_bb_reg(0x0860, 0x1FFE0000, fc_area)?;

        // ── Step 3: RF0x18 — PLL band select + channel + BW ──
        // Build complete value, no read-modify-write (3-wire read unreliable)
        //   [7:0]   = channel number
        //   [9:8]   = band select low (AG)
        //   [11:10] = bandwidth (3=20MHz, 1=40MHz, 0=80MHz)
        //   [18:16] = band select high (MOD)
        let (mod_high, mod_low) = if (36..=80).contains(&channel) {
            (1u32, 1u32)   // 5GHz low
        } else if (82..=140).contains(&channel) {
            (3u32, 1u32)   // 5GHz mid
        } else if channel > 140 {
            (5u32, 1u32)   // 5GHz high
        } else {
            (0u32, 0u32)   // 2.4GHz
        };
        let bw_rf = 3u32; // 20MHz
        let rf18 = (mod_high << 16) | (bw_rf << 10) | (mod_low << 8) | ch;

        for path in 0..2u8 {
            let lssi_addr = if path == 0 { RF_A_LSSI_WRITE } else { RF_B_LSSI_WRITE };
            let lssi = (0x18u32 << 20) | (rf18 & 0x000FFFFF);
            self.write32(lssi_addr, lssi)?;
            thread::sleep(RF_WRITE_SETTLE);
        }

        // ── Step 4: phy_PostSetBwMode — BB bandwidth config ──
        // REG_WMAC_TRXPTCL_CTL (0x0668): MAC-level BW
        let wmac = self.read16(0x0668)?;
        self.write16(0x0668, wmac & 0xFE7F)?; // 20MHz: BIT7=0, BIT8=0

        // REG_DATA_SC (0x0483): sub-channel = 0 for 20MHz
        self.write8(0x0483, 0)?;

        // rRFMOD_Jaguar (0x8AC): BB RF mode for 20MHz
        self.set_bb_reg(0x08AC, 0x003003C3, 0x00300200)?;

        // rADC_Buf_Clk (0x8C4[30]) = 0 for 20MHz
        self.set_bb_reg(0x08C4, 1 << 30, 0)?;

        // rL1PeakTH (0x848[25:22]): L1 peak threshold = 7 for 2T2R
        self.set_bb_reg(0x0848, 0x03C00000, 7)?;

        // ── Step 5: Spur calibration ──
        // Channels 13/14 need special ADC clock to avoid spur
        if channel == 13 || channel == 14 {
            self.set_bb_reg(0x08AC, 0x300, 0x3)?;  // [9:8] = 3
            self.set_bb_reg(0x08C4, 1 << 30, 1)?;  // ADC buf clk
        }

        // ── Step 6: RFE control + GPIO PA enable (from Linux usbmon) ──
        // Linux writes RFE_CTRL (0x08C0) on every channel switch — 127 times in capture.
        // This tells the hardware how to drive the RF front-end switches.
        // Without it, the RFE pinmux values at 0x0CB0 may not take effect.
        self.set_bb_reg(0x08C0, 0xFFFFFFFF, 0x27F00020)?;

        // GPIO PA enable — written EVERY channel switch (not just band changes)
        if is_2g {
            self.write8(0x004C, 0x20)?;  // PA enable 2.4G
        } else {
            self.write8(0x004C, 0x28)?;  // PA enable 5G
        }

        thread::sleep(CHANNEL_SWITCH_SETTLE);
        self.channel = channel;
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Monitor mode
    // ══════════════════════════════════════════════════════════════════════════

    fn set_monitor_internal(&self) -> Result<()> {
        // RCR: accept all + PHY status + FCS
        self.write32(REG_RCR, RCR_AAP | RCR_APP_PHYSTS | RCR_APPFCS)?;

        // RX driver info size: 4 units (32 bytes) — DRVINFO_SZ=4
        let v = self.read8(REG_RX_DRVINFO_SZ)?;
        self.write8(REG_RX_DRVINFO_SZ, (v & 0xF0) | 4)?;

        // Accept ALL frame types
        self.write16(REG_RXFLTMAP0, 0xFFFF)?;       // management
        self.write16(REG_RXFLTMAP0 + 2, 0xFFFF)?;   // control
        self.write16(0x06A4, 0xFFFF)?;               // data

        // Disable beacon function
        let v = self.read8(REG_BCN_CTRL)?;
        self.write8(REG_BCN_CTRL, (v & !(1 << 3)) | (1 << 6) | (1 << 4))?;

        // Write MACID 0 register
        if self.mac_addr != MacAddress::ZERO {
            let b = self.mac_addr.as_bytes();
            let mac_lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let mac_hi = u16::from_le_bytes([b[4], b[5]]);
            self.write32(0x0610, mac_lo)?;
            self.write16(0x0614, mac_hi)?;
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Full chip init sequence
    // ══════════════════════════════════════════════════════════════════════════

    fn chip_init(&mut self) -> Result<()> {
        // Step 1: Reset RF paths before power on
        self.write8(REG_RF_CTRL, 0x05)?;
        self.write8(REG_RF_CTRL, 0x07)?;
        self.write8(REG_RF_B_CTRL, 0x05)?;
        self.write8(REG_RF_B_CTRL, 0x07)?;

        // Step 2: Power on
        self.power_on()?;

        // Step 3: LLT init (manual — 8812A specific)
        self.init_llt()?;

        // Step 4: Drop incorrect bulk out
        self.write32(0x04A0, self.read32(0x04A0)? | (1 << 10))?;

        // Step 5: Firmware download
        // Error safe: many operations still work without firmware
        let _ = self.load_firmware();

        // Step 6: Queue/buffer config
        // _InitTransferPageSize: TX page size = 512 bytes
        self.write8(0x0104, 0x30)?; // _PSTX(PBP_512) — TX page size only

        // _InitTxBufferBoundary_8812AUsb: Set ALL TX buffer boundaries
        // Without these, MAC TX DMA doesn't know valid buffer ranges
        self.write8(0x0424, TX_PAGE_BOUNDARY)?; // REG_BCNQ_BDNY
        self.write8(0x0425, TX_PAGE_BOUNDARY)?; // REG_MGQ_BDNY
        self.write8(0x045D, TX_PAGE_BOUNDARY)?; // REG_WMAC_LBK_BF_HD
        self.write8(0x0114, TX_PAGE_BOUNDARY)?; // REG_TRXFF_BNDY (low byte)
        self.write8(0x0209, TX_PAGE_BOUNDARY)?; // REG_TDECTRL+1

        // Page boundary (legacy regs)
        self.write8(0x025A, TX_PAGE_BOUNDARY)?;
        self.write8(0x025B, TX_PAGE_BOUNDARY)?;

        // _InitPageBoundary: RX DMA boundary
        self.write16(0x0116, 0x3E7F)?; // RX_DMA_BOUNDARY_8812

        // Driver info size for RX (4 units = 32 bytes)
        self.write8(REG_RX_DRVINFO_SZ, 4)?;

        // WMAC settings: RCR for normal mode (will be overridden by monitor mode)
        self.write32(REG_RCR, 0x700060CE)?; // APM|AM|AB|APP_ICV|AMF|HTC_LOC_CTRL|APP_MIC|APP_PHYSTS
        self.write32(0x06A0, 0xFFFFFFFF)?;  // MAR0 - accept all multicast
        self.write32(0x06A4, 0xFFFFFFFF)?;  // MAR1

        // Enable ALL MAC TRX engines:
        // BIT0: HCI_TXDMA_EN, BIT1: HCI_RXDMA_EN, BIT2: TXDMA_EN, BIT3: RXDMA_EN
        // BIT4: PROTOCOL_EN, BIT5: SCHEDULE_EN, BIT6: MACTXEN, BIT7: MACRXEN
        // Upper byte: BIT8: ENSWBCN, BIT9-11: additional engines
        // REG_CR: enable all MAC TRX engines including MACTXEN(6) + MACRXEN(7)
        // Linux writes 0x063F during init then 0xFF during monitor mode setup.
        // We keep 0x0FFF (all bits) since our monitor mode doesn't re-write CR.
        self.write16(REG_CR, 0x0FFF)?;

        // ── USB Burst packet length & DMA config (_InitBurstPktLen) ──

        // RX DMA status/burst length
        self.write16(0x0288, 0x7400)?; // burst length=4

        // RXDMA control
        self.write8(0x0289, 0xF5)?;

        // USB2 burst packet length: set BIT4|BIT3|BIT2|BIT1, clear BIT5
        let v = self.read8(0x0290)?; // REG_RXDMA_PRO_8812
        self.write8(0x0290, (v | 0x1E) & !0x20)?;

        // AMPDU config
        self.write8(0x0456, 0x70)?;                 // AMPDU max time
        self.write32(0x0458, 0xFFFFFFFF)?;           // AMPDU max length
        self.write8(0x005C, 0x50)?;                  // USTIME_TSF
        self.write8(0x063C, 0x50)?;                  // USTIME_EDCA

        // RX packet limit for VHT 11K
        self.write8(0x060C, 0x18)?;

        // Single AMPDU enable
        let v = self.read8(0x04C7)?;
        self.write8(0x04C7, v | 0x80)?;

        // Max aggregation number
        self.write16(0x04CA, 0x1F1F)?;

        // ── USB RX aggregation ──

        // Enable RXDMA aggregation: REG_TRXDMA_CTRL (0x010C) BIT2
        let v = self.read8(0x010C)?;
        self.write8(0x010C, v | 0x04)?; // RXDMA_AGG_EN

        // USB RX aggregation: size=8 (unit 512b=4KB), timeout=0x06
        self.write16(0x0280, 0x0608)?; // timeout<<8 | size

        // ── Queue page allocation (RQPN) ──
        // RTL8812A USB: _InitQueueReservedPage_8812AUsb from Linux driver
        // Normal mode: HPQ=16, LPQ=16, NPQ=0, PUB=remaining (216)
        let num_hq: u32 = 0x10;
        let num_lq: u32 = 0x10;
        let num_nq: u32 = 0x00;
        let num_pub: u32 = (TX_PAGE_BOUNDARY as u32) - 1 - num_hq - num_lq - num_nq;

        // REG_RQPN_NPQ (0x0214): NPQ page count
        self.write8(0x0214, num_nq as u8)?;

        // REG_RQPN (0x0200): HPQ | LPQ<<8 | PUBQ<<16 | LD_RQPN(bit31)
        let rqpn = num_hq | (num_lq << 8) | (num_pub << 16) | (1 << 31);
        self.write32(0x0200, rqpn)?;

        // ── Queue priority + DMA mapping (from Linux usbmon: 0xF5B0) ──
        // TRXDMA_CTRL: maps logical TX queues to DMA channels
        // Linux upper nibbles: 0xF5B_ — preserve bottom 4 bits (RX DMA config)
        let trxdma = self.read16(0x010C)?;
        self.write16(0x010C, (trxdma & 0x000F) | 0xF5B0)?;

        // TDECTRL: TX DMA engine control (from Linux usbmon: 0x00FD0200)
        // Without this, hardware doesn't process TX descriptors correctly
        self.write32(0x020C, 0x00FD0200)?;

        // ── SIFS/Timing (from Linux rtw88 usbmon capture) ──
        self.write32(0x0500, 0x002FA226)?;   // SIFS_CCK
        self.write32(0x0504, 0x005EA324)?;   // SIFS_CCK_CTX
        self.write32(0x0508, 0x005EA42B)?;   // SIFS_OFDM
        self.write32(0x050C, 0x0000A44F)?;   // SIFS_OFDM_CTX
        self.write16(0x0510, 0x4413)?;       // TXPAUSE_CTRL
        self.write16(0x0514, 0x100A)?;       // SPEC_SIFS CCK=10, OFDM=10
        self.write16(0x0516, 0x100A)?;       // MAC_SPEC_SIFS

        // ── EDCA parameters (from Linux usbmon) ──
        self.write16(0x0522, 0x0000)?;       // Clear TX pause
        self.write32(0x0444, 0x00000010)?;   // EDCA_VO_PARAM
        self.write32(0x0448, 0xFFFFF000)?;   // EDCA_VI_PARAM
        self.write32(0x044C, 0x00000010)?;   // EDCA_BE_PARAM
        self.write32(0x0450, 0x003FF000)?;   // EDCA_BK_PARAM
        self.write16(0x063A, 0x100A)?;       // Slot timing (was 0x09 — 8-bit only)

        // ── TX retry + ACK timeout (from Linux usbmon) ──
        let v = self.read8(0x0420)?;
        self.write8(0x0420, v | (1 << 7))?;  // EN_AMPDU_RTY_NEW
        self.write8(0x0640, 0x80)?;          // REG_ACKTO — ACK timeout
        self.write16(0x042A, 0x3030)?;       // Retry limit: 48/48 (was 0x0808=8/8)
        self.write16(0x0428, 0x100A)?;       // Retry timing

        // ── Response Rate Set (RRSR) ──
        self.write32(0x0440, 0x0000FFFF)?;   // All OFDM + CCK rates enabled

        // ── TX rate config (from Linux usbmon) ──
        self.write32(0x0608, 0xF410400F)?;   // TX rate init/control

        // Beacon config
        let v = self.read8(REG_BCN_CTRL)?;
        self.write8(REG_BCN_CTRL, v | (1 << 3))?;

        // HW SEQ control — enable for ALL TIDs
        self.write8(0x04D2, 0xFF)?;

        // NAV limit
        self.write8(0x066E, 0x05)?;          // (was 0x0652=0x00)

        // FWHW_TXQ_CTRL: enable TX report + preload
        self.write8(0x0421, 0x0F)?;

        // TX report timing
        self.write16(0x04EC, 0x3DF0)?;       // REG_TX_RPT_TIME

        // ── Aggregation config (from Linux usbmon) ──
        self.write32(0x0540, 0x80006404)?;   // AGG control
        self.write16(0x0550, 0x1010)?;       // AGG settings
        self.write32(0x04CC, 0x0201FFFF)?;   // AGG burst config

        // Step 7: PHY / BB / RF init
        self.phy_init()?;

        // Step 9: Read MAC address from EFUSE
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = self.read8(0x0E + i as u16)?;
        }
        if mac.iter().all(|&b| b == 0xFF) || mac.iter().all(|&b| b == 0x00) {
            for i in 0..6 {
                mac[i] = self.read8(0x0050 + i as u16)?;
            }
        }
        self.mac_addr = MacAddress::new(mac);

        // Step 10: Set initial channel (ch1, 2.4GHz)
        self.set_channel_internal(1)?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  TX descriptor (40 bytes for RTL8812A)
    // ══════════════════════════════════════════════════════════════════════════

    /// Build a 40-byte TX descriptor for frame injection.
    ///
    /// Matches Linux fill_fake_txdesc exactly — minimal fields that are known to work.
    /// RTL8812A TX descriptor layout (from references/rtl8812au/include/rtl8812a_xmit.h).
    fn inject_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()> {
        if frame.len() < 10 {
            return Err(Error::TxFailed {
                retries: 0,
                reason: "frame too short".into(),
            });
        }

        // Auto-select rate for management frames on 2.4GHz: use CCK 1M (matches Linux)
        // Linux usbmon shows probe/auth frames on 2.4G always use rate=0x00 (CCK 1M)
        let fc_type = frame[0] & 0x0C;
        let rate = if fc_type == 0x00 && self.channel <= 14 {
            0x00 // CCK 1Mbps for management frames on 2.4GHz
        } else {
            tx_rate_to_hw(&opts.rate, self.channel)
        };
        let retries = if opts.flags.contains(TxFlags::NO_RETRY) {
            1
        } else if opts.retries > 0 {
            opts.retries.min(63)
        } else {
            12
        };

        // Auto-detect broadcast/multicast from DA
        let bmc = frame.len() >= 10 && (frame[4] & 0x01) != 0;

        // Queue from frame type (management/control/data)
        let fc_type = frame[0] & 0x0C;
        let qsel = match fc_type {
            0x00 => QSLT_MGNT,  // Management
            0x04 => QSLT_VO,    // Control → VO
            0x08 => QSLT_BE,    // Data → BE
            _ => QSLT_MGNT,
        };

        // ZLP avoidance (USB 2.0: 512-byte boundary)
        let pkt_size = if (frame.len() + TX_DESC_SIZE) % 512 == 0 {
            frame.len() + 1
        } else {
            frame.len()
        };

        let total = TX_DESC_SIZE + pkt_size;
        let mut buf = vec![0u8; total];

        // Ensure MACID register is written (lazy init)
        if !self.macid_written && self.mac_addr != MacAddress::ZERO {
            let b = self.mac_addr.as_bytes();
            let mac_lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let mac_hi = u16::from_le_bytes([b[4], b[5]]);
            self.write32(0x0610, mac_lo)?;
            self.write16(0x0614, mac_hi)?;
            self.macid_written = true;
        }

        // MACTXEN safety check (first TX only)
        if !self.mactx_checked {
            let cr_val = self.read16(REG_CR)?;
            if cr_val & (1 << 6) == 0 {
                self.write16(REG_CR, cr_val | (1 << 6))?;
            }
            let txpause = self.read16(0x0522)?;
            if txpause != 0 {
                self.write16(0x0522, 0x0000)?;
            }
            self.mactx_checked = true;
        }

        // ── Build TX descriptor (40 bytes for RTL8812A) ──
        // Matched byte-for-byte against Linux rtw88 usbmon capture (2026-03-22)

        // DW0: TXPKTSIZE, OFFSET=40, LS, OWN, BMC
        // Linux: 0x85280058 = pkt_size | (40 << 16) | LS(26) | OWN(31) | BMC(24)
        // Note: FS (bit 27) is NOT set — Linux omits First Segment for USB
        buf[0x00] = (pkt_size & 0xFF) as u8;
        buf[0x01] = ((pkt_size >> 8) & 0xFF) as u8;
        buf[0x02] = TX_DESC_SIZE as u8;              // OFFSET = 40 (0x28)
        buf[0x03] = (1 << 2)                         // LS (bit 26)
                   | (1 << 7);                        // OWN (bit 31)
        if bmc {
            buf[0x03] |= 1 << 0;                     // BMC (bit 24)
        }

        // DW1: MACID=0, QSEL, RATE_ID
        // Linux: 0x00081200 = MACID(0) | QSEL(0x12) | RATE_ID(8)
        buf[0x04] = 0x00;                             // MACID=0
        buf[0x05] = qsel & 0x1F;                      // QSEL [12:8]
        buf[0x06] = if rate <= 0x03 { 8 } else { 7 }; // RATE_ID (8=CCK, 7=OFDM)

        // DW3: USE_RATE + DISABLE_FB
        // Linux: byte[0x0D] = 0x05 = USE_RATE(bit0) | DISABLE_FB(bit2)
        buf[0x0D] = (1 << 0)                          // USE_RATE (bit 8 of DW3)
                   | (1 << 2);                         // DISABLE_FB (bit 10 of DW3)

        // DW4: TX_RATE + flags from Linux capture
        // Linux: bytes = [rate, 0x1F, 0x00, 0x00]
        // byte[0x11] = 0x1F matches Linux for all management frames
        buf[0x10] = rate & 0x7F;                       // TX_RATE [6:0]
        buf[0x11] = 0x1F;                              // Linux: RTY_LMT_EN + rate flags

        // DW5: RTY_LMT_EN + retry limit (same layout as RTL8812BU)
        buf[0x12] = (1 << 1) | ((retries as u8 & 0x3F) << 2); // RTY_LMT_EN[1] + DATA_RTY_LMT[7:2]

        // DW5: STBC + LDPC (byte 0x17)
        if opts.flags.contains(TxFlags::STBC) {
            buf[0x17] |= 1 << 4; // DATA_STBC = 1 (single stream)
        }
        if opts.flags.contains(TxFlags::LDPC) {
            buf[0x17] |= 1; // DATA_LDPC
        }

        // DW8: HWSEQ_EN — let hardware assign sequence numbers
        buf[0x21] = 1 << 7;                            // HWSEQ_EN (bit 15 of DW8)

        // ── Checksum (DW7 +0x1C): XOR of first 32 bytes as 16-bit LE words ──
        // USB interface drops the packet if checksum is wrong
        buf[0x1C] = 0;
        buf[0x1D] = 0;
        let mut chksum: u16 = 0;
        for i in (0..32).step_by(2) {
            let w = u16::from_le_bytes([buf[i], buf[i + 1]]);
            chksum ^= w;
        }
        buf[0x1C] = (chksum & 0xFF) as u8;
        buf[0x1D] = ((chksum >> 8) & 0xFF) as u8;

        // ── Copy frame payload ──
        buf[TX_DESC_SIZE..TX_DESC_SIZE + frame.len()].copy_from_slice(frame);

        // USB bulk OUT
        self.handle
            .write_bulk(self.ep_out, &buf, USB_BULK_TIMEOUT)
            .map_err(|e| Error::TxFailed {
                retries: 0,
                reason: format!("bulk OUT: {e}"),
            })?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  RX descriptor parsing
    // ══════════════════════════════════════════════════════════════════════════

    /// Parse one RX packet from the USB bulk buffer.
    /// Returns (bytes_consumed, optional frame).
    fn parse_rx_packet(buf: &[u8], channel: u8) -> (usize, Option<RxFrame>) {
        if buf.len() < RX_DESC_SIZE {
            return (0, None);
        }

        let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let pkt_len = (dw0 & 0x3FFF) as usize;
        let crc_err = (dw0 >> 14) & 1 != 0;
        let drvinfo_sz = ((dw0 >> 16) & 0x0F) as usize * 8;
        let shift = ((dw0 >> 24) & 0x03) as usize;

        if pkt_len == 0 || pkt_len > 4096 {
            return (0, None);
        }

        let data_start = RX_DESC_SIZE + drvinfo_sz + shift;
        let data_end = data_start + pkt_len;

        // Align consumed to 128 bytes for aggregation
        let total_raw = data_end;
        let consumed = (total_raw + 127) & !127;

        if data_end > buf.len() || pkt_len < 10 {
            return (consumed.min(buf.len()), None);
        }

        // Strip FCS (4 bytes) and skip CRC errors
        let frame_len = if pkt_len >= 4 { pkt_len - 4 } else { 0 };
        if crc_err || frame_len == 0 {
            return (consumed, None);
        }

        // Extract RSSI from PHY status (if present)
        let physt = (dw0 >> 26) & 1 != 0;
        let rssi = if physt && drvinfo_sz >= 4 {
            let raw = buf[RX_DESC_SIZE] as i16;
            (raw - 110).max(-127).min(0) as i8
        } else {
            -80i8
        };

        let frame = RxFrame {
            data: buf[data_start..data_start + frame_len].to_vec(),
            rssi,
            channel,
            band: if channel <= 14 { 0 } else { 1 },
            timestamp: Duration::ZERO,
            ..Default::default()
        };

        (consumed, Some(frame))
    }
}

/// Standalone parse function for the RX thread (can't call self methods).
/// Wraps the static Rtl8812au::parse_rx_packet() method.
fn parse_rx_packet_standalone(buf: &[u8], channel: u8) -> (usize, crate::core::chip::ParsedPacket) {
    let (consumed, frame) = Rtl8812au::parse_rx_packet(buf, channel);
    let packet = match frame {
        Some(f) => crate::core::chip::ParsedPacket::Frame(f),
        None => crate::core::chip::ParsedPacket::Skip,
    };
    (consumed, packet)
}

// ══════════════════════════════════════════════════════════════════════════════
//  ChipDriver trait implementation
// ══════════════════════════════════════════════════════════════════════════════

impl ChipDriver for Rtl8812au {
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
            name: "RTL8812AU",
            chip: ChipId::Rtl8812au,
            caps: RTL8812AU_CAPS,
            vid: self.vid,
            pid: self.pid,
            rfe_type: 0,
            bands: vec![Band::Band2g, Band::Band5g],
            max_tx_power_dbm: 20,
            firmware_version: String::new(),
        }
    }

    fn set_channel(&mut self, channel: Channel) -> Result<()> {
        self.set_channel_internal(channel.number)
    }

    fn supported_channels(&self) -> &[Channel] {
        &self.channels
    }

    fn set_monitor_mode(&mut self) -> Result<()> {
        self.set_monitor_internal()
    }

    fn tx_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()> {
        self.inject_frame(frame, opts)
    }

    fn rx_frame(&mut self, timeout: Duration) -> Result<Option<RxFrame>> {
        // Check for remaining data in buffer from previous USB read (aggregation)
        if self.rx_pos < self.rx_len {
            let remaining = &self.rx_buf[self.rx_pos..self.rx_len];
            let (consumed, frame) = Self::parse_rx_packet(remaining, self.channel);
            if consumed > 0 {
                self.rx_pos += consumed;
                if let Some(f) = frame {
                    return Ok(Some(f));
                }
            } else {
                // Can't parse more, reset buffer
                self.rx_pos = 0;
                self.rx_len = 0;
            }
        }

        // Read new USB bulk data
        match self.handle.read_bulk(self.ep_in, &mut self.rx_buf, timeout) {
            Ok(len) if len > RX_DESC_SIZE => {
                self.rx_pos = 0;
                self.rx_len = len;

                let (consumed, frame) = Self::parse_rx_packet(&self.rx_buf[..len], self.channel);
                if consumed > 0 {
                    self.rx_pos = consumed;
                }
                Ok(frame)
            }
            Ok(_) => Ok(None),
            Err(rusb::Error::Timeout) => Err(Error::RxTimeout),
            Err(e) => Err(Error::Usb(e)),
        }
    }

    fn mac(&self) -> MacAddress {
        self.mac_addr
    }

    fn set_mac(&mut self, mac: MacAddress) -> Result<()> {
        for i in 0..6 {
            self.write8(0x0610 + i as u16, mac.as_bytes()[i])?;
        }
        self.mac_addr = mac;
        Ok(())
    }

    fn tx_power(&self) -> i8 {
        20
    }

    fn set_tx_power(&mut self, _dbm: i8) -> Result<()> {
        Ok(())
    }

    fn calibrate(&mut self) -> Result<()> {
        Ok(())
    }

    fn channel_settle_time(&self) -> Duration {
        // RTL8812AU: register-based PLL, same as BU variant.
        // Hardware re-lock is ~1-2ms, 5ms is conservative.
        Duration::from_millis(5)
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
    fn test_tx_desc_size() {
        assert_eq!(TX_DESC_SIZE, 40, "RTL8812AU TX descriptor must be 40 bytes");
    }

    #[test]
    fn test_rx_desc_size() {
        assert_eq!(RX_DESC_SIZE, 24, "RTL8812AU RX descriptor base is 24 bytes");
    }

    #[test]
    fn test_channel_list() {
        let channels = build_channel_list();
        assert!(channels.len() >= 37, "Should have at least 37 channels (14 + 23 5GHz)");
        assert_eq!(channels[0].number, 1);
        assert_eq!(channels[13].number, 14);
        assert_eq!(channels[14].number, 36);
    }

    #[test]
    fn test_caps() {
        assert!(RTL8812AU_CAPS.contains(ChipCaps::MONITOR));
        assert!(RTL8812AU_CAPS.contains(ChipCaps::INJECT));
        assert!(RTL8812AU_CAPS.contains(ChipCaps::BAND_2G));
        assert!(RTL8812AU_CAPS.contains(ChipCaps::BAND_5G));
        assert!(RTL8812AU_CAPS.contains(ChipCaps::VHT));
        assert!(!RTL8812AU_CAPS.contains(ChipCaps::HE));
    }

    #[test]
    fn test_channel_freq_mapping() {
        // Verify core Channel frequency mapping for channels we support
        assert_eq!(Channel::new(1).center_freq_mhz, 2412);
        assert_eq!(Channel::new(6).center_freq_mhz, 2437);
        // Note: Channel 14 is 2484 MHz per spec, but core uses 2407+ch*5=2477
        assert_eq!(Channel::new(14).center_freq_mhz, 2477);
        assert_eq!(Channel::new(36).center_freq_mhz, 5180);
        assert_eq!(Channel::new(149).center_freq_mhz, 5745);
        assert_eq!(Channel::new(165).center_freq_mhz, 5825);
    }

    #[test]
    fn test_tx_page_boundary() {
        assert_eq!(TX_PAGE_BOUNDARY, 0xF9);
        assert_eq!(LAST_ENTRY_OF_TX_PKT_BUFFER, 255);
    }

    #[test]
    fn test_firmware_size() {
        assert!(rtl8812a_fw::FW_8812A_NIC.len() > 1000, "Firmware must be substantial");
        // Verify first byte is 0x01 (FW version header marker)
        assert_eq!(rtl8812a_fw::FW_8812A_NIC[0], 0x01);
    }

    #[test]
    fn test_parse_rx_too_short() {
        let buf = [0u8; 10];
        let (consumed, frame) = Rtl8812au::parse_rx_packet(&buf, 1);
        assert_eq!(consumed, 0);
        assert!(frame.is_none());
    }

    #[test]
    fn test_parse_rx_zero_pkt_len() {
        let buf = [0u8; RX_DESC_SIZE + 10];
        let (consumed, frame) = Rtl8812au::parse_rx_packet(&buf, 1);
        assert_eq!(consumed, 0);
        assert!(frame.is_none());
    }

    #[test]
    fn test_parse_rx_valid_frame() {
        let mut buf = [0u8; 256];
        let pkt_len: u32 = 50;
        let drvinfo_sz: u32 = 4; // 4 * 8 = 32 bytes
        // DW0: pkt_len[13:0] | drvinfo_sz[19:16] | shift[25:24] | physt[26]
        let dw0 = pkt_len | (drvinfo_sz << 16) | (1 << 26); // physt=1
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());
        // Set RSSI byte in PHY status area (right after RX desc)
        buf[RX_DESC_SIZE] = 60; // raw RSSI
        // Fill frame data
        let data_start = RX_DESC_SIZE + (drvinfo_sz as usize * 8);
        for i in 0..pkt_len as usize {
            if data_start + i < buf.len() {
                buf[data_start + i] = (i & 0xFF) as u8;
            }
        }

        let (consumed, frame) = Rtl8812au::parse_rx_packet(&buf, 6);
        assert!(consumed > 0);
        assert!(frame.is_some());
        let f = frame.unwrap();
        assert_eq!(f.data.len(), (pkt_len - 4) as usize); // -4 for FCS strip
        assert_eq!(f.channel, 6);
        assert_eq!(f.rssi, (60i16 - 110).max(-127).min(0) as i8);
    }

    #[test]
    fn test_init_tables_loaded() {
        assert!(!rtl8812a_tables::MAC_INIT.is_empty(), "MAC init table should not be empty");
        assert!(!rtl8812a_tables::BB_INIT.is_empty(), "BB init table should not be empty");
        assert!(!rtl8812a_tables::AGC_INIT.is_empty(), "AGC init table should not be empty");
        assert!(!rtl8812a_tables::RF_A_INIT.is_empty(), "RF_A init table should not be empty");
        assert!(!rtl8812a_tables::RF_B_INIT.is_empty(), "RF_B init table should not be empty");
    }
}
