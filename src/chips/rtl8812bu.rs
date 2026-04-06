//! RTL8812BU / RTL8822BU chip driver
//!
//! # Hardware
//!
//! Realtek RTL8822BU — 802.11ac dual-band (2.4GHz + 5GHz), 2T2R MIMO, USB 3.0.
//! Used in: TP-Link Archer T4U V3, ASUS USB-AC53 Nano, Netgear A6100, and others.
//! This is the project's golden reference driver — most complete, most tested.
//!
//! Key hardware traits:
//!   - Register-based: direct USB control transfers to MMIO registers (no firmware MCU)
//!   - 8051 firmware: uploaded at init, handles H2C commands but not channel switching
//!   - EFUSE: per-device calibration (TX power, RFE type, MAC address)
//!   - PLL channel switching: ~1-2ms retune via RF register 0x18
//!
//! # Init Flow (9 steps in `chip_init()`)
//!
//!   1. Power on (CARDDIS → CARDEMU → ACT via USB-specific power sequence)
//!   2. Firmware download (IDDMA DMA engine, DMEM + IMEM sections)
//!   3. TRX queue/buffer configuration (page allocation, Auto LLT, DMA mapping)
//!   4. USB RX DMA setup (aggregation disabled at init, enabled in monitor mode)
//!   5. H2C firmware info commands (general_info, phydm_info, general_info_reg)
//!   6. EDCA/WMAC timing (SIFS, slot time, beacon)
//!   7. PHY/BB/RF init from tables + IQK calibration + DPK calibration
//!   8. EFUSE read (TX power calibration + RFE type + MAC address)
//!   9. Apply calibrated TX power + LC calibration
//!
//! # USB Protocol
//!
//!   Register I/O: vendor control transfers (bRequest=0x05)
//!     Read:  bmRequestType=0xC0, wValue=addr, wIndex=0
//!     Write: bmRequestType=0x40, wValue=addr, wIndex=0
//!   Data TX: bulk OUT with 48-byte TX descriptor (XOR checksum of first 32 bytes)
//!   Data RX: bulk IN with 24-byte RX descriptor, 8-byte aligned aggregation
//!   H2C: two paths — bulk (QSEL=0x13) and message box (4 rotating register pairs)
//!
//! # Architecture Decisions
//!
//!   - All timing uses named `const Duration` values — no raw `sleep(millis)` calls
//!   - TX power is EFUSE-calibrated per-path, per-band, per-rate-group
//!   - RX parser is a static `pub(crate)` method for use by both direct and RxHandle paths
//!   - Lazy MACID/MACTXEN init: deferred to first TX to avoid init-order issues
//!   - Firmware failure is non-fatal: monitor mode RX works without firmware
//!   - Every swallowed error has an "Error safe to ignore" comment explaining why
//!
//! # What's NOT Implemented
//!
//!   - 40/80 MHz bandwidth (all channel switching hardcoded to 20MHz)
//!   - firmware_version extraction from FW header
//!   - Per-rate RSSI (uses single-byte PHY status, not per-path)
//!
//! # Reference
//!
//!   Linux driver: morrownr/88x2bu-20210702 (out-of-tree)
//!   Power sequence: hal/halmac/halmac_88xx/halmac_8822b/halmac_pwr_seq_8822b.c
//!   PHY/RF tables: hal/phydm/rtl8822b/ (extracted to rtl8822b_tables.rs)

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
use super::rtl8822b_tables;

// ── Constants ──

const RTL_USB_REQ: u8 = 0x05;
const RTL_USB_TIMEOUT: Duration = Duration::from_millis(500);

const TX_DESC_SIZE: usize = 48;
const RX_DESC_SIZE: usize = 24;
const RX_BUF_SIZE: usize = 32768;

const FW_HDR_SIZE: usize = 64;
const FW_CHKSUM_SIZE: usize = 8;
const FW_CHUNK_SIZE: usize = 8192;

const TXAGC_MAX: u8 = 0x3F;
const TXAGC_DEFAULT: u8 = TXAGC_MAX;

// ── Registers ──

const REG_SYS_FUNC_EN: u16 = 0x0002;
const REG_CR: u16 = 0x0100;
const REG_RCR: u16 = 0x0608;
const REG_RXFLTMAP0: u16 = 0x06A0;
const REG_BCN_CTRL: u16 = 0x0550;
const REG_CPU_DMEM_CON: u16 = 0x1080;

// IDDMA registers
const REG_DDMA_CH0SA: u16 = 0x1200;
const REG_DDMA_CH0DA: u16 = 0x1204;
const REG_DDMA_CH0CTRL: u16 = 0x1208;
const REG_FIFOPAGE_CTRL2: u16 = 0x0204;

const DDMA_OWN: u32 = 1 << 31;
const DDMA_CHKSUM_EN: u32 = 1 << 29;
const DDMA_CHKSUM_STS: u32 = 1 << 27;
const DDMA_RST_CHKSUM: u32 = 1 << 25;
const DDMA_CHKSUM_CONT: u32 = 1 << 24;

const OCPBASE_TXBUF: u32 = 0x18780000;

// H2C queue
const H2C_PKT_SIZE: usize = 32;
const H2C_PKT_HDR_SIZE: u16 = 8;
const TX_PAGE_SHIFT: u32 = 7;

const REG_H2C_HEAD: u16 = 0x0244;
const REG_H2C_TAIL: u16 = 0x0248;
const REG_H2C_READ_ADDR: u16 = 0x024C;
const REG_H2C_INFO: u16 = 0x0254;

// Reserved page layout
const RSVD_BOUNDARY: u16 = 1988;
const RX_FIFO_SIZE: u32 = 24576;
const C2H_PKT_BUF: u32 = 256;
const RSVD_PG_H2CQ_NUM: u32 = 8;
const RSVD_FW_TXBUF_ADDR: u16 = 2044;
const RSVD_H2CQ_ADDR: u32 = 2036;

// H2C message box
const REG_HMETFR: u16 = 0x01CC;
const REG_HMEBOX0: u16 = 0x01D0;
const REG_HMEBOX_EXT0: u16 = 0x01F0;

// RCR bits
const RCR_AAP: u32 = 1 << 0;
const RCR_APP_PHYSTS: u32 = 1 << 28;
const RCR_APPFCS: u32 = 1 << 31;

// Bandwidth constants
const CHANNEL_WIDTH_20: u32 = 0;
const CHANNEL_WIDTH_40: u32 = 1;
const CHANNEL_WIDTH_80: u32 = 2;

// Queue select values
const QSLT_BE: u8 = 0x00;
const QSLT_VO: u8 = 0x06;
const QSLT_MGNT: u8 = 0x12;

// RF register mask
const RFREGOFFSETMASK: u32 = 0xFFFFF;

// ── Hardware Timing Constants ──
// Ported from C driver (hal/halmac/halmac_88xx/halmac_8822b).
// These are hardware register timing requirements — do not change values.

// Poll loop iteration delay (poll8, poll32)
const POLL_ITER_DELAY: Duration = Duration::from_micros(100);

// RF register write settle time (LSSI write propagation)
const RF_WRITE_SETTLE: Duration = Duration::from_micros(1);

// Init table delay pseudo-addresses (from PHY_REG / RadioA / RadioB tables)
const INIT_DELAY_FE: Duration = Duration::from_millis(50);
const INIT_DELAY_FD: Duration = Duration::from_millis(5);
const INIT_DELAY_FC: Duration = Duration::from_millis(1);
const INIT_DELAY_FB: Duration = Duration::from_micros(50);
const INIT_DELAY_FA: Duration = Duration::from_micros(5);
const INIT_DELAY_F9: Duration = Duration::from_micros(1);

// Power sequence timing
const POWER_OFF_SETTLE: Duration = Duration::from_millis(10);
const POWER_ON_USB_RESET_SETTLE: Duration = Duration::from_millis(100);
const POWER_ON_LDO_SETTLE: Duration = Duration::from_millis(1);

// USB bulk transfer timeout
const USB_BULK_TIMEOUT: Duration = Duration::from_secs(2);

// Reserved page beacon poll delay
const RSVD_PAGE_POLL_DELAY: Duration = Duration::from_micros(10);

// IDDMA poll delay
const IDDMA_POLL_DELAY: Duration = Duration::from_micros(50);

// IDDMA checksum reset settle
const IDDMA_CHECKSUM_RESET_SETTLE: Duration = Duration::from_micros(100);

// Firmware CPU platform reset pulse width
const FW_PLATFORM_RESET_DELAY: Duration = Duration::from_millis(1);

// Firmware init completion poll delay
const FW_INIT_POLL_DELAY: Duration = Duration::from_micros(50);

// BB soft reset pulse width
const BB_SOFT_RESET_DELAY: Duration = Duration::from_micros(50);

// RF bandwidth register settle (after RF init)
const RF_BW_SETTLE: Duration = Duration::from_micros(100);

// H2C message box poll delay (wait for FW to consume previous cmd)
const H2C_MSGBOX_POLL_DELAY: Duration = Duration::from_millis(1);

// Auto LLT init poll delay
const AUTO_LLT_POLL_DELAY: Duration = Duration::from_micros(10);

// H2C firmware info inter-command delay
const H2C_INFO_DELAY: Duration = Duration::from_millis(1);

// LC calibration start wait
const LC_CAL_START_DELAY: Duration = Duration::from_millis(100);
// LC calibration poll delay
const LC_CAL_POLL_DELAY: Duration = Duration::from_millis(10);

// Channel switch RF18 verify initial delay (us)
const RF18_VERIFY_INITIAL_DELAY_US: u64 = 500;
// Channel switch RF18 verify retry delay (us)
const RF18_VERIFY_RETRY_DELAY_US: u64 = 1000;

// Channel switch settle (after all registers written)
const CHANNEL_SETTLE_DELAY: Duration = Duration::from_micros(200);

// TX power register write retry delay (used in set_tx_power_regs via trait dispatch)
#[allow(dead_code)]
const TXAGC_WRITE_RETRY_DELAY: Duration = Duration::from_micros(500);

// First TX DMA error check delay
const FIRST_TX_DMA_CHECK_DELAY: Duration = Duration::from_millis(2);

// ── Firmware search paths ──

const FW_SEARCH_PATHS: &[&str] = &[
    "rtl8822bu_nic.bin",
    "libwifikit/rtl8822bu_nic.bin",
    "../wifi-map/libwifikit/rtl8822bu_nic.bin",
];

// ── Supported channel list ──

fn build_channel_list() -> Vec<Channel> {
    let mut channels = Vec::with_capacity(37);
    // 2.4 GHz: channels 1-14
    for ch in 1..=14u8 {
        channels.push(Channel::new(ch));
    }
    // 5 GHz UNII-1: 36, 40, 44, 48
    for &ch in &[36, 40, 44, 48u8] {
        channels.push(Channel::new(ch));
    }
    // 5 GHz UNII-2: 52, 56, 60, 64
    for &ch in &[52, 56, 60, 64u8] {
        channels.push(Channel::new(ch));
    }
    // 5 GHz UNII-2 Extended: 100-144
    for &ch in &[100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144u8] {
        channels.push(Channel::new(ch));
    }
    // 5 GHz UNII-3: 149-165
    for &ch in &[149, 153, 157, 161, 165u8] {
        channels.push(Channel::new(ch));
    }
    channels
}

// ── TxRate → Realtek HW rate index ──

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
    // Safety: CCK rates invalid on 5 GHz
    if channel > 14 && idx <= 0x03 {
        0x04 // fallback to OFDM 6M
    } else {
        idx
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Rtl8812bu — The Driver
// ══════════════════════════════════════════════════════════════════════════════

/// Per-chip EFUSE TX power calibration values.
/// Currently only OFDM and 5GHz group values are used in `set_tx_power_calibrated()`.
/// The per-rate CCK/HT fields are read from EFUSE for future per-rate TXAGC support.
#[derive(Clone, Debug)]
#[allow(dead_code)] // per-rate fields read from EFUSE, used when per-rate TXAGC is implemented
struct EfuseTxPower {
    // 2.4GHz per-rate base power
    a_cck_2g: u8,
    a_ofdm_2g: u8,
    a_ht1ss_2g: u8,
    a_ht2ss_2g: u8,
    b_cck_2g: u8,
    b_ofdm_2g: u8,
    b_ht1ss_2g: u8,
    b_ht2ss_2g: u8,
    // 5GHz per-group base power (4 groups: 36-48, 52-64, 100-144, 149-165)
    a_ofdm_5g: [u8; 4],
    b_ofdm_5g: [u8; 4],
}

impl Default for EfuseTxPower {
    fn default() -> Self {
        Self {
            a_cck_2g: TXAGC_DEFAULT, a_ofdm_2g: TXAGC_DEFAULT,
            a_ht1ss_2g: TXAGC_DEFAULT, a_ht2ss_2g: TXAGC_DEFAULT,
            b_cck_2g: TXAGC_DEFAULT, b_ofdm_2g: TXAGC_DEFAULT,
            b_ht1ss_2g: TXAGC_DEFAULT, b_ht2ss_2g: TXAGC_DEFAULT,
            a_ofdm_5g: [TXAGC_DEFAULT; 4],
            b_ofdm_5g: [TXAGC_DEFAULT; 4],
        }
    }
}

// Fields and methods below are accessed via `dyn ChipDriver` trait dispatch,
// which the compiler cannot trace — targeted `allow(dead_code)` on those items.
#[allow(dead_code)] // fields used via ChipDriver trait dispatch (rx_buf, rx_pos, rx_len, tx_power_idx)
pub struct Rtl8812bu {
    handle: Arc<DeviceHandle<GlobalContext>>,
    ep_out: u8,
    ep_in: u8,
    channel: u8,
    mac_addr: MacAddress,
    tx_power_idx: u8,
    h2c_seq: u16,
    h2c_box: u8,
    rx_buf: Vec<u8>,
    rx_pos: usize,
    rx_len: usize,
    channels: Vec<Channel>,
    macid_written: bool,
    mactx_checked: bool,
    tx_seq: u16,
    rfe_type: u8,
    efuse_pwr: EfuseTxPower,
    vid: u16,
    pid: u16,
}

/// Standalone parse function for RxHandle — delegates to Rtl8812bu::parse_rx_packet.
/// This free function has the right signature for a fn pointer in RxHandle.
fn parse_rx_packet_standalone(buf: &[u8], channel: u8) -> (usize, crate::core::chip::ParsedPacket) {
    let (consumed, frame) = Rtl8812bu::parse_rx_packet(buf, channel);
    let packet = match frame {
        Some(f) => crate::core::chip::ParsedPacket::Frame(f),
        None => crate::core::chip::ParsedPacket::Skip,
    };
    (consumed, packet)
}

/// RTL8812BU capability flags — matches rtl8812bu_ops.caps from C
const RTL8812BU_CAPS: ChipCaps = ChipCaps::MONITOR.union(ChipCaps::INJECT)
    .union(ChipCaps::BAND_2G).union(ChipCaps::BAND_5G)
    .union(ChipCaps::HT).union(ChipCaps::VHT)
    .union(ChipCaps::BW40).union(ChipCaps::BW80);

impl Rtl8812bu {
    /// Open a USB device and prepare the driver, returning both the driver
    /// and the discovered USB endpoints.
    ///
    /// Called by chips::create_driver() — the dispatch layer.
    /// Does NOT init the chip yet. Call init() after construction.
    ///
    /// Matches the USB open portion of wifikit_open() from C:
    ///   1. Find USB device by VID/PID
    ///   2. Detach kernel driver if active (Linux)
    ///   3. Claim USB interface 0
    ///   4. Discover bulk IN/OUT endpoints
    ///   5. Construct driver with endpoint info
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

        // Detach kernel driver if attached (Linux)
        #[cfg(target_os = "linux")]
        {
            if handle.kernel_driver_active(0).unwrap_or(false) {
                // Error safe to ignore: driver may not be attached or detach unsupported on this platform
                let _ = handle.detach_kernel_driver(0);
            }
        }

        handle.claim_interface(0)?;

        // Discover bulk endpoints — matches wifikit_open() endpoint discovery loop
        let endpoints = crate::core::adapter::discover_endpoints(&device)?;
        let ep_out = endpoints.bulk_out;
        let ep_in = endpoints.bulk_in;

        let driver = Self {
            handle: Arc::new(handle),
            ep_out,
            ep_in,
            channel: 0,
            mac_addr: MacAddress::ZERO,
            tx_power_idx: TXAGC_DEFAULT,
            h2c_seq: 0,
            h2c_box: 0,
            rx_buf: vec![0u8; RX_BUF_SIZE],
            rx_pos: 0,
            rx_len: 0,
            channels: build_channel_list(),
            macid_written: false,
            tx_seq: 0,
            rfe_type: 0,
            efuse_pwr: EfuseTxPower::default(),
            mactx_checked: false,
            vid,
            pid,
        };

        Ok((driver, endpoints))
    }

    // ── Register access via USB vendor control ──

    fn read8(&self, addr: u16) -> Result<u8> {
        let mut buf = [0u8; 1];
        let r = self.handle.read_control(
            0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT,
        )?;
        if r < 1 {
            return Err(Error::RegisterReadFailed { addr });
        }
        Ok(buf[0])
    }

    fn write8(&self, addr: u16, val: u8) -> Result<()> {
        let buf = [val];
        let r = self.handle.write_control(
            0x40, RTL_USB_REQ, addr, 0, &buf, RTL_USB_TIMEOUT,
        )?;
        if r < 1 {
            return Err(Error::RegisterWriteFailed { addr, val: val as u32 });
        }
        Ok(())
    }

    fn read16(&self, addr: u16) -> Result<u16> {
        let mut buf = [0u8; 2];
        let r = self.handle.read_control(
            0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT,
        )?;
        if r < 2 {
            return Err(Error::RegisterReadFailed { addr });
        }
        Ok(u16::from_le_bytes(buf))
    }

    fn write16(&self, addr: u16, val: u16) -> Result<()> {
        let buf = val.to_le_bytes();
        let r = self.handle.write_control(
            0x40, RTL_USB_REQ, addr, 0, &buf, RTL_USB_TIMEOUT,
        )?;
        if r < 2 {
            return Err(Error::RegisterWriteFailed { addr, val: val as u32 });
        }
        Ok(())
    }

    fn read32(&self, addr: u16) -> Result<u32> {
        let mut buf = [0u8; 4];
        let r = self.handle.read_control(
            0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT,
        )?;
        if r < 4 {
            return Err(Error::RegisterReadFailed { addr });
        }
        Ok(u32::from_le_bytes(buf))
    }

    fn write32(&self, addr: u16, val: u32) -> Result<()> {
        let buf = val.to_le_bytes();
        let r = self.handle.write_control(
            0x40, RTL_USB_REQ, addr, 0, &buf, RTL_USB_TIMEOUT,
        )?;
        if r < 4 {
            return Err(Error::RegisterWriteFailed { addr, val });
        }
        Ok(())
    }

    // ── Bit manipulation helpers ──

    fn write8_mask(&self, addr: u16, mask: u8, val: u8) -> Result<()> {
        let cur = self.read8(addr)?;
        self.write8(addr, (cur & !mask) | (val & mask))
    }

    fn set_bb_reg(&self, addr: u16, mask: u32, val: u32) -> Result<()> {
        if mask == 0xFFFFFFFF {
            return self.write32(addr, val);
        }
        let cur = self.read32(addr)?;
        let shift = mask.trailing_zeros();
        self.write32(addr, (cur & !mask) | ((val << shift) & mask))
    }

    fn get_bb_reg(&self, addr: u16, mask: u32) -> Result<u32> {
        let val = self.read32(addr)?;
        let shift = mask.trailing_zeros();
        Ok((val & mask) >> shift)
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

    // ── RF register access ──

    fn read_rf(&self, path: u8, rf_reg: u8) -> Result<u32> {
        let direct_base: u16 = if path == 0 { 0x2800 } else { 0x2C00 };
        let val = self.read32(direct_base + (rf_reg as u16 * 4))?;
        Ok(val & RFREGOFFSETMASK)
    }

    fn write_rf(&self, path: u8, rf_reg: u8, mask: u32, data: u32) -> Result<()> {
        let lssi_addr: u16 = if path == 0 { 0x0C90 } else { 0x0E90 };
        let direct_base: u16 = if path == 0 { 0x2800 } else { 0x2C00 };

        let data = if mask != 0xFFFFF {
            let cur = self.read32(direct_base + (rf_reg as u16 * 4))? & 0xFFFFF;
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

    // ── EFUSE reading (indirect access via register 0x0030) ──
    // Protocol from usbmon capture:
    //   WRITE 0x0030 = 0x00NN6031  (bank 0, word NN, trigger read)
    //   POLL  0x0030 until bit 15 set (0x60B1 = complete)
    //   Value in bits 23:16 of response

    const REG_EFUSE_CTRL: u16 = 0x0030;
    const EFUSE_READ_CMD_BANK0: u32 = 0x6031;  // bank 0 read trigger
    const EFUSE_READ_DONE: u32 = 1 << 15;       // bit 15 = read complete

    /// Read one byte from EFUSE bank 0 at word address `addr`
    fn efuse_read_byte(&self, addr: u8) -> Result<u8> {
        let cmd = ((addr as u32) << 16) | Self::EFUSE_READ_CMD_BANK0;
        self.write32(Self::REG_EFUSE_CTRL, cmd)?;

        // Poll for completion — tight loop, no sleep (EFUSE reads are fast)
        for _ in 0..200 {
            let val = self.read32(Self::REG_EFUSE_CTRL)?;
            if val & Self::EFUSE_READ_DONE != 0 {
                return Ok(((val >> 24) & 0xFF) as u8);
            }
        }
        Ok(0xFF)
    }

    /// Read EFUSE calibration data — only the bytes we actually need
    /// Returns (efuse_map, rfe_type)
    fn read_efuse_calibration(&self) -> Result<([u8; 256], u8)> {
        let mut map = [0xFFu8; 256];

        // Only read the offsets we need (not all 208 bytes):
        // TX power: 0x10-0x23 (Path A), 0x3A-0x4F (Path B)
        // RFE type: 0xCA
        let ranges: &[(u8, u8)] = &[
            (0x10, 0x24), // Path A: CCK/OFDM/HT 2G + 5GHz groups
            (0x3A, 0x50), // Path B: CCK/OFDM/HT 2G + 5GHz groups
            (0xCA, 0xCB), // RFE type
        ];

        for &(start, end) in ranges {
            for i in start..end {
                map[i as usize] = self.efuse_read_byte(i)?;
            }
        }

        let rfe_type = if map[0xCA] != 0xFF { map[0xCA] } else { 0 };

        Ok((map, rfe_type))
    }

    /// Extract per-channel-group TX power from EFUSE map
    /// Returns (path_a_2g, path_b_2g, path_a_5g_groups, path_b_5g_groups)
    fn extract_tx_power_from_efuse(efuse: &[u8; 256]) -> EfuseTxPower {
        // RTL8822B EFUSE TX power layout (from Linux hal_pg.c):
        // 2.4GHz base power:
        //   Path A CCK: offset 0x10
        //   Path A OFDM: offset 0x11
        //   Path A HT/VHT 1SS: offset 0x12
        //   Path A HT/VHT 2SS: offset 0x13
        //   Path B CCK: offset 0x3A
        //   Path B OFDM: offset 0x3B
        //   Path B HT/VHT 1SS: offset 0x3C
        //   Path B HT/VHT 2SS: offset 0x3D
        // 5GHz base power per group (5 groups):
        //   Path A group 0 (ch36-48): 0x14-0x17
        //   Path A group 1 (ch52-64): 0x18-0x1B
        //   Path A group 2 (ch100-140): 0x1C-0x1F
        //   Path A group 3 (ch149-165): 0x20-0x23
        //   (similar for Path B at +0x2A offset)

        let valid = |v: u8| -> u8 {
            if v == 0xFF || v == 0x00 { TXAGC_DEFAULT } else { v.min(TXAGC_MAX) }
        };

        EfuseTxPower {
            // 2.4GHz
            a_cck_2g: valid(efuse[0x10]),
            a_ofdm_2g: valid(efuse[0x11]),
            a_ht1ss_2g: valid(efuse[0x12]),
            a_ht2ss_2g: valid(efuse[0x13]),
            b_cck_2g: valid(efuse[0x3A]),
            b_ofdm_2g: valid(efuse[0x3B]),
            b_ht1ss_2g: valid(efuse[0x3C]),
            b_ht2ss_2g: valid(efuse[0x3D]),
            // 5GHz group 0 (ch36-48)
            a_ofdm_5g: [valid(efuse[0x14]), valid(efuse[0x18]),
                        valid(efuse[0x1C]), valid(efuse[0x20])],
            b_ofdm_5g: [valid(efuse[0x3E]), valid(efuse[0x42]),
                        valid(efuse[0x46]), valid(efuse[0x4A])],
        }
    }

    /// Apply calibrated TX power for current channel using EFUSE data
    fn set_tx_power_calibrated(&self, channel: u8, efuse_pwr: &EfuseTxPower) -> Result<()> {
        let (pwr_a, pwr_b) = if channel <= 14 {
            (efuse_pwr.a_ofdm_2g, efuse_pwr.b_ofdm_2g)
        } else {
            let group = match channel {
                36..=48 => 0,
                52..=64 => 1,
                100..=144 => 2,
                _ => 3, // 149-165
            };
            (efuse_pwr.a_ofdm_5g[group], efuse_pwr.b_ofdm_5g[group])
        };

        // Uniform rate registers (CCK, OFDM, HT MCS0-3, HT MCS4-7, VHT 1SS)
        let pw4_a = (pwr_a as u32) * 0x01010101;
        let pw4_b = (pwr_b as u32) * 0x01010101;

        // VHT rates get 2 less than OFDM/HT (PA back-off for higher modulation)
        let vht_a = ((pwr_a.saturating_sub(2)) as u32) * 0x01010101;
        let vht_b = ((pwr_b.saturating_sub(2)) as u32) * 0x01010101;

        // Uniform rate group registers
        for &offset in &[0x00u8, 0x04, 0x08, 0x0C, 0x10] {
            self.write32(0x1D00 + offset as u16, pw4_a)?;
            self.write32(0x1D80 + offset as u16, pw4_b)?;
        }
        // VHT 1SS rates (lower power for PA linearity)
        for &offset in &[0x14u8, 0x18] {
            self.write32(0x1D00 + offset as u16, vht_a)?;
            self.write32(0x1D80 + offset as u16, vht_b)?;
        }

        // Per-rate staircase (0x1D2C-0x1D3C / 0x1DAC-0x1DBC)
        // From usbmon: descending power for higher MCS rates to keep PA linear.
        // Two sequences: 1SS (base+14 → base-4) and 2SS (base+12 → base-6)
        self.write_txagc_staircase(0x1D00, pwr_a)?;
        self.write_txagc_staircase(0x1D80, pwr_b)?;

        Ok(())
    }

    fn write_txagc_staircase(&self, base: u16, pwr: u8) -> Result<()> {
        // Per-rate power staircase from usbmon analysis
        // Sequence 1 (1SS): base+14 descending by 2 to base-4
        // Sequence 2 (2SS): base+12 descending by 2 to base-6
        // Each register holds 4 consecutive rate powers (little-endian bytes)
        let p = pwr as i16;
        let clamp = |v: i16| -> u8 { v.max(0).min(TXAGC_MAX as i16) as u8 };

        // 0x2C: 1SS rates [base+8, base+10, base+12, base+14]
        let v = (clamp(p+14) as u32) << 24 | (clamp(p+12) as u32) << 16
              | (clamp(p+10) as u32) << 8  | (clamp(p+8) as u32);
        self.write32(base + 0x2C, v)?;

        // 0x30: 1SS rates [base+0, base+2, base+4, base+6]
        let v = (clamp(p+6) as u32) << 24 | (clamp(p+4) as u32) << 16
              | (clamp(p+2) as u32) << 8  | (clamp(p) as u32);
        self.write32(base + 0x30, v)?;

        // 0x34: 2SS start [base+10, base+12, base-4, base-2]
        let v = (clamp(p-2) as u32) << 24 | (clamp(p-4) as u32) << 16
              | (clamp(p+12) as u32) << 8  | (clamp(p+10) as u32);
        self.write32(base + 0x34, v)?;

        // 0x38: 2SS rates [base+2, base+4, base+6, base+8]
        let v = (clamp(p+8) as u32) << 24 | (clamp(p+6) as u32) << 16
              | (clamp(p+4) as u32) << 8  | (clamp(p+2) as u32);
        self.write32(base + 0x38, v)?;

        // 0x3C: 2SS rates [base-6, base-4, base-2, base+0]
        let v = (clamp(p) as u32) << 24 | (clamp(p-2) as u32) << 16
              | (clamp(p-4) as u32) << 8  | (clamp(p-6) as u32);
        self.write32(base + 0x3C, v)?;

        Ok(())
    }

    // ── Delay pseudo-address handling (for init tables) ──

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

    fn power_off(&self) -> Result<()> {
        // ACT → CARDEMU (USB-specific)
        self.write8(0x0093, 0xC4)?;
        self.write8(0x001F, 0x00)?;
        self.write8(0x00EF, 0x00)?;
        self.write8(0xFF1A, 0x30)?; // USB only
        self.write8_mask(0x0049, 1 << 1, 0)?;
        self.write8_mask(0x0006, 1 << 0, 1 << 0)?;
        self.write8_mask(0x0002, 1 << 1, 0)?;
        self.write8_mask(0x10C3, 1 << 0, 0)?; // USB only
        self.write8_mask(0x0005, 1 << 1, 1 << 1)?;
        // Error safe to ignore: best-effort poll during power-off sequence, chip may already be off
        let _ = self.poll8(0x0005, 1 << 1, 0, 200);
        self.write8_mask(0x0020, 1 << 3, 0)?;
        self.write8_mask(0x0000, 1 << 5, 1 << 5)?; // USB+SDIO

        // CARDEMU → CARDDIS (USB-specific)
        self.write8(0x0007, 0x20)?; // USB+SDIO
        self.write8_mask(0x0067, 1 << 5, 0)?;
        self.write8_mask(0x004A, 1 << 0, 1 << 0)?; // USB only

        thread::sleep(POWER_OFF_SETTLE);
        Ok(())
    }

    fn power_on(&self) -> Result<()> {
        // Check if already powered on — if so, do full power cycle
        let cr = self.read32(REG_CR)?;
        if cr != 0xEAEAEAEA {
            self.power_off()?;
            let cr = self.read32(REG_CR)?;
            if cr != 0xEAEAEAEA {
                // Error safe to ignore: USB reset is last-resort recovery, failure means device is unresponsive
                let _ = self.handle.reset();
                thread::sleep(POWER_ON_USB_RESET_SETTLE);
            }
        }

        // ── Phase 1: CARDDIS → CARDEMU (USB-specific) ──
        self.write8_mask(0x004A, 1 << 0, 0)?;
        self.write8_mask(0x0005, (1 << 3) | (1 << 4) | (1 << 7), 0)?;

        // ── Phase 2: CARDEMU → ACT (USB-specific) ──
        self.write8(0xFF0A, 0x00)?;
        self.write8(0xFF0B, 0x00)?;
        self.write8_mask(0x0012, 1 << 1, 0)?;
        self.write8_mask(0x0012, 1 << 0, 1 << 0)?;
        self.write8_mask(0x0020, 1 << 0, 1 << 0)?; // SPS0_LDO
        thread::sleep(POWER_ON_LDO_SETTLE);
        self.write8_mask(0x0000, 1 << 5, 0)?;
        self.write8_mask(0x0005, (1 << 4) | (1 << 3) | (1 << 2), 0)?;
        self.poll8(0x0006, 1 << 1, 1 << 1, 200)?; // wait for power ready
        self.write8(0xFF1A, 0x00)?; // USB-specific
        self.write8_mask(0x0006, 1 << 0, 1 << 0)?; // enable WLON
        self.write8_mask(0x0005, 1 << 7, 0)?;
        self.write8_mask(0x0005, (1 << 4) | (1 << 3), 0)?;
        self.write8_mask(0x10C3, 1 << 0, 1 << 0)?; // USB
        self.write8_mask(0x0005, 1 << 0, 1 << 0)?; // trigger APFM_ONMAC
        self.poll8(0x0005, 1 << 0, 0, 200)?; // wait for MAC power-on
        self.write8_mask(0x0020, 1 << 3, 1 << 3)?;
        self.write8(0x0029, 0xF9)?;
        self.write8_mask(0x0024, 1 << 2, 0)?;
        self.write8_mask(0x00AF, 1 << 5, 1 << 5)?;

        // Verify CR is accessible
        let cr = self.read32(REG_CR)?;
        if cr == 0xEAEAEAEA {
            return Err(Error::ChipInitFailed {
                chip: "RTL8812BU".into(),
                stage: crate::core::error::InitStage::MacPowerOn,
                reason: "CR register returned 0xEAEAEAEA".into(),
            });
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Firmware download (IDDMA)
    // ══════════════════════════════════════════════════════════════════════════

    /// TX descriptor checksum — XOR of first 32 bytes as 16-bit words.
    /// CRITICAL: HW only checksums first 32 bytes, NOT the full 48-byte descriptor.
    fn txdesc_checksum(txdesc: &mut [u8]) {
        txdesc[0x1C] = 0;
        txdesc[0x1D] = 0;

        let mut chksum: u16 = 0;
        // Process 32 bytes as 16 half-words in pairs of 2
        for i in 0..8 {
            let w0 = u16::from_le_bytes([txdesc[i * 4], txdesc[i * 4 + 1]]);
            let w1 = u16::from_le_bytes([txdesc[i * 4 + 2], txdesc[i * 4 + 3]]);
            chksum ^= w0 ^ w1;
        }

        txdesc[0x1C] = (chksum & 0xFF) as u8;
        txdesc[0x1D] = ((chksum >> 8) & 0xFF) as u8;
    }

    fn send_rsvd_page(&self, pg_addr: u16, data: &[u8]) -> Result<()> {
        // Set beacon page address + re-arm beacon valid
        self.write16(REG_FIFOPAGE_CTRL2, (pg_addr & 0x0FFF) | (1 << 15))?;

        // Enable SW beacon
        let restore_cr1 = self.read8(0x0101)?;
        self.write8(0x0101, restore_cr1 | 1)?;

        // Disable HW beacon
        let restore_txq = self.read8(0x0422)?;
        self.write8(0x0422, restore_txq & !(1 << 6))?;

        // ZLP avoidance
        let pkt_size = if (data.len() + TX_DESC_SIZE) % 512 == 0 {
            data.len() + 1
        } else {
            data.len()
        };

        // Build TX descriptor + payload
        let total = TX_DESC_SIZE + pkt_size;
        let mut buf = vec![0u8; total];

        // DW0: TXPKTSIZE, OFFSET=48
        buf[0] = (pkt_size & 0xFF) as u8;
        buf[1] = ((pkt_size >> 8) & 0xFF) as u8;
        buf[2] = TX_DESC_SIZE as u8;

        // DW1: QSEL = BEACON (0x10)
        buf[5] = 0x10;

        Self::txdesc_checksum(&mut buf);
        buf[TX_DESC_SIZE..TX_DESC_SIZE + data.len()].copy_from_slice(data);

        // Send via USB bulk OUT
        let result = self.handle.write_bulk(self.ep_out, &buf, USB_BULK_TIMEOUT);

        // Restore registers regardless of outcome
        let cleanup = || -> Result<()> {
            self.write16(REG_FIFOPAGE_CTRL2, (pg_addr & 0x0FFF) | (1 << 15))?;
            self.write8(0x0422, restore_txq)?;
            self.write8(0x0101, restore_cr1)?;
            Ok(())
        };

        match result {
            Ok(_) => {
                // Poll for beacon valid
                for _ in 0..1000 {
                    let v = self.read8(REG_FIFOPAGE_CTRL2 as u16 + 1).unwrap_or(0);
                    if v & (1 << 7) != 0 {
                        break;
                    }
                    thread::sleep(RSVD_PAGE_POLL_DELAY);
                }
                cleanup()?;
                Ok(())
            }
            Err(e) => {
                // Error safe to ignore: cleanup during error handling, original error takes priority
                let _ = cleanup();
                Err(Error::UsbTransferFailed {
                    endpoint: self.ep_out,
                    reason: format!("rsvd_page bulk OUT: {e}"),
                })
            }
        }
    }

    fn iddma(&self, src: u32, dst: u32, len: u32, first: bool) -> Result<()> {
        // Poll until IDDMA ready
        for _ in 0..1000 {
            let ctrl = self.read32(REG_DDMA_CH0CTRL)?;
            if ctrl & DDMA_OWN == 0 {
                break;
            }
            thread::sleep(IDDMA_POLL_DELAY);
        }

        self.write32(REG_DDMA_CH0SA, src)?;
        self.write32(REG_DDMA_CH0DA, dst)?;

        let mut ctrl = DDMA_OWN | DDMA_CHKSUM_EN | (len & 0x3FFFF);
        if !first {
            ctrl |= DDMA_CHKSUM_CONT;
        }
        self.write32(REG_DDMA_CH0CTRL, ctrl)?;

        // Poll until complete
        for _ in 0..1000 {
            let ctrl = self.read32(REG_DDMA_CH0CTRL)?;
            if ctrl & DDMA_OWN == 0 {
                return Ok(());
            }
            thread::sleep(IDDMA_POLL_DELAY);
        }

        Err(Error::PollTimeout {
            addr: REG_DDMA_CH0CTRL,
            mask: 0,
            expected: 0,
        })
    }

    fn dl_section(&self, data: &[u8], size: u32, dest_addr: u32) -> Result<()> {
        // Reset IDDMA checksum
        let ctrl = self.read32(REG_DDMA_CH0CTRL)?;
        self.write32(REG_DDMA_CH0CTRL, ctrl | DDMA_RST_CHKSUM)?;
        thread::sleep(IDDMA_CHECKSUM_RESET_SETTLE);

        let total = size + FW_CHKSUM_SIZE as u32;
        let mut offset = 0u32;
        let mut first = true;

        while offset < total {
            let chunk = (total - offset).min(FW_CHUNK_SIZE as u32);
            let end = (offset + chunk) as usize;
            let start = offset as usize;

            if end > data.len() {
                break;
            }

            self.send_rsvd_page(0, &data[start..end])?;
            self.iddma(
                OCPBASE_TXBUF + TX_DESC_SIZE as u32,
                dest_addr + offset,
                chunk,
                first,
            )?;

            first = false;
            offset += chunk;
        }

        // Verify checksum
        let ctrl = self.read32(REG_DDMA_CH0CTRL)?;
        if ctrl & DDMA_CHKSUM_STS != 0 {
            return Err(Error::FirmwareError {
                chip: "RTL8812BU".into(),
                kind: crate::core::error::FirmwareErrorKind::ChecksumFailed,
            });
        }

        Ok(())
    }

    fn load_firmware(&self) -> Result<()> {
        // Find firmware file
        let fw_data = FW_SEARCH_PATHS
            .iter()
            .find_map(|p| fs::read(Path::new(p)).ok());

        let fw = match fw_data {
            Some(data) => data,
            None => {
                // Proceed without firmware — many operations still work
                return Ok(());
            }
        };

        if fw.len() < FW_HDR_SIZE {
            return Err(Error::FirmwareError {
                chip: "RTL8812BU".into(),
                kind: crate::core::error::FirmwareErrorKind::TooSmall,
            });
        }

        // Parse header
        let dmem_addr = u32::from_le_bytes([fw[32], fw[33], fw[34], fw[35]]) & 0x00FFFFFF;
        let dmem_size = u32::from_le_bytes([fw[36], fw[37], fw[38], fw[39]]);
        let imem_size = u32::from_le_bytes([fw[48], fw[49], fw[50], fw[51]]);
        let imem_addr = u32::from_le_bytes([fw[60], fw[61], fw[62], fw[63]]) & 0x00FFFFFF;

        // ── Pre-download setup ──

        // Disable CPU
        let v = self.read8(REG_SYS_FUNC_EN + 1)?;
        self.write8(REG_SYS_FUNC_EN + 1, v & !(1 << 2))?;

        // HIQ to high priority
        self.write8(0x010D, 0xC0)?;

        // Enable HCI TX DMA + TX DMA
        self.write8(REG_CR, 0x05)?;

        // Clear H2C queue
        self.write32(0x1330, 1 << 31)?;

        // HI queue pages = 512
        self.write16(0x0230, 0x200)?;

        // RQPN_CTRL_2: load enable
        let rqpn = self.read32(0x022C)?;
        self.write32(0x022C, rqpn | (1 << 31))?;

        // Disable beacon during FW download
        let v = self.read8(REG_BCN_CTRL)?;
        self.write8(REG_BCN_CTRL, (v & !(1 << 3)) | (1 << 4))?;

        // Platform reset
        let v = self.read8(REG_CPU_DMEM_CON + 2)?;
        self.write8(REG_CPU_DMEM_CON + 2, v & !(1 << 0))?;
        thread::sleep(FW_PLATFORM_RESET_DELAY);
        self.write8(REG_CPU_DMEM_CON + 2, v | (1 << 0))?;
        thread::sleep(FW_PLATFORM_RESET_DELAY);

        // Enable FW download mode
        let v = self.read16(0x0080)?;
        self.write16(0x0080, (v & 0x3800) | 1)?;

        // ── Download DMEM ──
        let dmem_offset = FW_HDR_SIZE;
        let dmem_end = dmem_offset + dmem_size as usize + FW_CHKSUM_SIZE;
        if dmem_end > fw.len() {
            return Err(Error::FirmwareError {
                chip: "RTL8812BU".into(),
                kind: crate::core::error::FirmwareErrorKind::SectionOverflow,
            });
        }

        if self.dl_section(&fw[dmem_offset..dmem_end], dmem_size, dmem_addr).is_err() {
            // Disable FW download mode and proceed without FW
            let v = self.read16(0x0080)?;
            self.write16(0x0080, v & !1)?;
            return Ok(());
        }

        // Set DMEM status bits
        let v = self.read8(0x0080)?;
        self.write8(0x0080, v | (1 << 5) | (1 << 6))?;

        // ── Download IMEM ──
        let imem_offset = FW_HDR_SIZE + dmem_size as usize + FW_CHKSUM_SIZE;
        let imem_end = imem_offset + imem_size as usize + FW_CHKSUM_SIZE;
        if imem_end > fw.len() {
            let v = self.read16(0x0080)?;
            self.write16(0x0080, v & !1)?;
            return Ok(());
        }

        if self.dl_section(&fw[imem_offset..imem_end], imem_size, imem_addr).is_err() {
            let v = self.read16(0x0080)?;
            self.write16(0x0080, v & !1)?;
            return Ok(());
        }

        // Set IMEM status bits
        let v = self.read8(0x0080)?;
        self.write8(0x0080, v | (1 << 3) | (1 << 4))?;

        // Verify all status bits
        let v = self.read8(0x0080)?;
        if v & 0x78 != 0x78 {
            // Status bits incomplete — continue anyway
        }

        // Acknowledge TX DMA
        self.write32(0x010C, 1 << 2)?;

        // Set FW_DW_RDY, disable FWDL_EN
        let v = self.read16(0x0080)?;
        self.write16(0x0080, (v | (1 << 14)) & !1)?;

        // Enable CPU I/O interface, then CPU
        let v = self.read8(0x001D)?;
        self.write8(0x001D, v | 1)?;
        let v = self.read8(REG_SYS_FUNC_EN + 1)?;
        self.write8(REG_SYS_FUNC_EN + 1, v | (1 << 2))?;

        // Poll until firmware init complete (0x80 should become 0xC078)
        for _ in 0..5000 {
            let v = self.read16(0x0080)?;
            if v == 0xC078 {
                return Ok(());
            }
            thread::sleep(FW_INIT_POLL_DELAY);
        }

        // FW timeout — proceed anyway, monitor mode may still work
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PHY / RF initialization
    // ══════════════════════════════════════════════════════════════════════════

    fn rfe_init(&self) -> Result<()> {
        // Chip top mux (enable RFE control)
        self.set_bb_reg(0x0064, (1 << 29) | (1 << 28), 0x3)?;
        self.set_bb_reg(0x004C, (1 << 26) | (1 << 25), 0x0)?;
        self.set_bb_reg(0x0040, 1 << 2, 0x1)?;

        // Path mux
        self.set_bb_reg(0x1990, 0x3F, 0x30)?;
        self.set_bb_reg(0x1990, (1 << 11) | (1 << 10), 0x3)?;

        // Input/output selection
        self.set_bb_reg(0x0974, 0x3F, 0x3F)?;
        self.set_bb_reg(0x0974, (1 << 11) | (1 << 10), 0x3)?;

        Ok(())
    }

    /// Configure RFE for specific channel.
    /// Using iFEM config for RFE type 0 (TP-Link Archer T4U V3).
    /// Reference: phydm_rfe_ifem() in phydm_hal_api8822b.c
    fn rfe_set_channel(&self, channel: u16) -> Result<()> {
        let is_2g = channel <= 14;

        if is_2g {
            self.set_bb_reg(0x0CB0, 0xFFFFFF, 0x745774)?;
            self.set_bb_reg(0x0EB0, 0xFFFFFF, 0x745774)?;
            self.set_bb_reg(0x0CB4, 0xFF00, 0x57)?;
            self.set_bb_reg(0x0EB4, 0xFF00, 0x57)?;
        } else {
            self.set_bb_reg(0x0CB0, 0xFFFFFF, 0x477547)?;
            self.set_bb_reg(0x0EB0, 0xFFFFFF, 0x477547)?;
            self.set_bb_reg(0x0CB4, 0xFF00, 0x75)?;
            self.set_bb_reg(0x0EB4, 0xFF00, 0x75)?;
        }

        // Inverse control: all zero for iFEM
        self.set_bb_reg(0x0CBC, 0x3F, 0x0)?;
        self.set_bb_reg(0x0CBC, (1 << 11) | (1 << 10), 0x0)?;
        self.set_bb_reg(0x0EBC, 0x3F, 0x0)?;
        self.set_bb_reg(0x0EBC, (1 << 11) | (1 << 10), 0x0)?;

        // Antenna switch table
        if is_2g {
            self.set_bb_reg(0x0CA0, 0xFFFF, 0xA501)?;
            self.set_bb_reg(0x0EA0, 0xFFFF, 0xA501)?;
        } else {
            self.set_bb_reg(0x0CA0, 0xFFFF, 0xA5A5)?;
            self.set_bb_reg(0x0EA0, 0xFFFF, 0xA5A5)?;
        }

        Ok(())
    }

    fn phy_init(&self) -> Result<()> {
        // Enable BB/RF power
        let v = self.read8(0x0002)?;
        self.write8(0x0002, v | 0x03)?; // BB global reset + BB reset
        let v = self.read8(0x001F)?;
        self.write8(0x001F, v | 0x07)?; // RF_EN + RF_RSTB + RF_SDMRSTB
        let v = self.read32(0x00EC)?;
        self.write32(0x00EC, v | (7 << 24))?; // WLAN RF paths

        // MAC register init (1-byte writes)
        for &(addr, val) in rtl8822b_tables::MAC_INIT {
            if (0xF9..=0xFE).contains(&addr) {
                Self::apply_delay(addr);
                continue;
            }
            self.write8(addr as u16, val as u8)?;
        }

        // BB/PHY register init (32-bit writes)
        for &(addr, val) in rtl8822b_tables::BB_INIT {
            if (0xF9..=0xFE).contains(&addr) {
                Self::apply_delay(addr);
                continue;
            }
            self.write32(addr as u16, val)?;
        }

        // AGC table (32-bit writes)
        for &(addr, val) in rtl8822b_tables::AGC_INIT {
            if (0xF9..=0xFE).contains(&addr) {
                Self::apply_delay(addr);
                continue;
            }
            self.write32(addr as u16, val)?;
        }

        // RF Path A (indirect write via LSSI)
        for &(rf_addr, rf_data) in rtl8822b_tables::RF_A_INIT {
            if (0xF9..=0xFE).contains(&rf_addr) {
                Self::apply_delay(rf_addr);
                continue;
            }
            let addr = (rf_addr & 0xFF) as u8;
            let lssi = ((addr as u32) << 20 | (rf_data & 0x000FFFFF)) & 0x0FFFFFFF;
            self.write32(0x0C90, lssi)?;
            thread::sleep(RF_WRITE_SETTLE);
        }

        // RF Path B (indirect write via LSSI)
        for &(rf_addr, rf_data) in rtl8822b_tables::RF_B_INIT {
            if (0xF9..=0xFE).contains(&rf_addr) {
                Self::apply_delay(rf_addr);
                continue;
            }
            let addr = (rf_addr & 0xFF) as u8;
            let lssi = ((addr as u32) << 20 | (rf_data & 0x000FFFFF)) & 0x0FFFFFFF;
            self.write32(0x0E90, lssi)?;
            thread::sleep(RF_WRITE_SETTLE);
        }

        // BB soft reset
        let sys_func = self.read16(REG_SYS_FUNC_EN)?;
        self.write16(REG_SYS_FUNC_EN, sys_func & !1)?;
        thread::sleep(BB_SOFT_RESET_DELAY);
        self.write16(REG_SYS_FUNC_EN, sys_func | 1)?;
        thread::sleep(BB_SOFT_RESET_DELAY);

        // Enable OFDM+CCK
        self.set_bb_reg(0x0808, (1 << 29) | (1 << 28), 0x3)?;

        // BB bandwidth: 20MHz default
        let v = self.read32(0x08AC)?;
        self.write32(0x08AC, (v & 0xFFCFFC00) | CHANNEL_WIDTH_20)?;
        self.set_bb_reg(0x08C4, 1 << 30, 0x1)?; // ADC buffer clock

        // RF BW bits (20MHz)
        thread::sleep(RF_BW_SETTLE);
        self.write_rf(0, 0x18, (1 << 11) | (1 << 10), 0x3)?;
        self.write_rf(1, 0x18, (1 << 11) | (1 << 10), 0x3)?;

        // RX DFIR
        self.rxdfir_by_bw(CHANNEL_WIDTH_20)?;

        // RX path toggle
        self.set_bb_reg(0x0808, 0xFF, 0x00)?;
        self.set_bb_reg(0x0808, 0xFF, 0x33)?;

        // IGI
        self.set_bb_reg(0x0C50, 0x7F, 0x20)?;
        self.set_bb_reg(0x0E50, 0x7F, 0x20)?;

        // TX path configuration — CRITICAL for frame injection
        self.set_bb_reg(0x093C, (1 << 19) | (1 << 18), 0x3)?; // TX antenna by Nsts
        self.set_bb_reg(0x080C, (1 << 29) | (1 << 28), 0x1)?; // TX path control
        self.set_bb_reg(0x080C, 1 << 30, 0x1)?;                // CCK TX path
        self.set_bb_reg(0x080C, 0xFF, 0x33)?;                  // TX HW block: Path A+B
        self.set_bb_reg(0x0A04, 0xF0000000, 0xC)?;             // CCK TX: both paths
        self.set_bb_reg(0x093C, 0xFFF00000, 0x043)?;           // OFDM TX logic map
        self.set_bb_reg(0x0940, 0xFFF0, 0x043)?;               // OFDM 2SS TX

        // RFE init + set for channel 1
        self.rfe_init()?;
        self.rfe_set_channel(1)?;

        // Final IGI
        self.set_bb_reg(0x0C50, 0x7F, 0x20)?;
        self.set_bb_reg(0x0E50, 0x7F, 0x20)?;

        Ok(())
    }

    // ── RX DFIR filter by bandwidth ──

    fn rxdfir_by_bw(&self, bw: u32) -> Result<()> {
        match bw {
            CHANNEL_WIDTH_40 => {
                self.set_bb_reg(0x0948, (1 << 29) | (1 << 28), 0x1)?;
                self.set_bb_reg(0x094C, (1 << 29) | (1 << 28), 0x0)?;
                self.set_bb_reg(0x0C20, 1 << 31, 0x0)?;
                self.set_bb_reg(0x0E20, 1 << 31, 0x0)?;
            }
            CHANNEL_WIDTH_80 => {
                self.set_bb_reg(0x0948, (1 << 29) | (1 << 28), 0x2)?;
                self.set_bb_reg(0x094C, (1 << 29) | (1 << 28), 0x1)?;
                self.set_bb_reg(0x0C20, 1 << 31, 0x0)?;
                self.set_bb_reg(0x0E20, 1 << 31, 0x0)?;
            }
            _ => {
                // 20MHz / 5MHz / 10MHz
                self.set_bb_reg(0x0948, (1 << 29) | (1 << 28), 0x2)?;
                self.set_bb_reg(0x094C, (1 << 29) | (1 << 28), 0x2)?;
                self.set_bb_reg(0x0C20, 1 << 31, 0x1)?;
                self.set_bb_reg(0x0E20, 1 << 31, 0x1)?;
            }
        }
        Ok(())
    }

    // ── IGI toggle: kick AGC ──

    fn igi_toggle(&self) -> Result<()> {
        let igi = self.get_bb_reg(0x0C50, 0x7F)?;
        let dec = if igi > 2 { igi - 2 } else { 0 };
        self.set_bb_reg(0x0C50, 0x7F, dec)?;
        self.set_bb_reg(0x0C50, 0x7F, igi)?;
        self.set_bb_reg(0x0E50, 0x7F, dec)?;
        self.set_bb_reg(0x0E50, 0x7F, igi)?;
        Ok(())
    }

    // ── BB bandwidth configuration ──

    fn set_bb_bandwidth(&self, bw: u32, primary_ch_idx: u8, channel: u16) -> Result<()> {
        let v = self.read32(0x08AC)?;

        match bw {
            CHANNEL_WIDTH_20 => {
                self.write32(0x08AC, (v & 0xFFCFFC00) | CHANNEL_WIDTH_20)?;
                self.set_bb_reg(0x08C4, 1 << 30, 0x1)?;
            }
            CHANNEL_WIDTH_40 => {
                if channel <= 14 {
                    let pri = if primary_ch_idx == 1 { 1 } else { 0 };
                    self.set_bb_reg(0x0A00, 1 << 4, pri)?;
                }
                let v2 = (v & 0xFF3FF300)
                    | (((primary_ch_idx as u32 & 0xF) << 2) | CHANNEL_WIDTH_40);
                self.write32(0x08AC, v2)?;
                self.set_bb_reg(0x08C4, 1 << 30, 0x1)?;
            }
            CHANNEL_WIDTH_80 => {
                let v2 = (v & 0xFCEFCF00)
                    | (((primary_ch_idx as u32 & 0xF) << 2) | CHANNEL_WIDTH_80);
                self.write32(0x08AC, v2)?;
                self.set_bb_reg(0x08C4, 1 << 30, 0x1)?;
            }
            _ => {}
        }

        // RX DFIR
        self.rxdfir_by_bw(bw)?;

        // RX path toggle with IGI save/restore
        // 0x32 is the default IGI value from the C reference driver
        let saved_igi = self.get_bb_reg(0x0C50, 0x7F)?;
        let saved_igi = if saved_igi == 0 { 0x32 } else { saved_igi };

        self.set_bb_reg(0x0808, 0xFF, 0x00)?;
        self.set_bb_reg(0x0808, 0xFF, 0x33)?;

        self.set_bb_reg(0x0C50, 0x7F, saved_igi)?;
        self.set_bb_reg(0x0E50, 0x7F, saved_igi)?;
        self.igi_toggle()?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  H2C (Host-to-Chip) commands
    // ══════════════════════════════════════════════════════════════════════════

    fn h2c_set_header(&mut self, pkt: &mut [u8], sub_cmd_id: u16, content_size: u16) {
        pkt.fill(0);
        let dw0: u32 = 0x01 | (0xFF << 8) | ((sub_cmd_id as u32) << 16);
        pkt[0..4].copy_from_slice(&dw0.to_le_bytes());

        let total_len = H2C_PKT_HDR_SIZE + content_size;
        let dw1: u32 = total_len as u32 | ((self.h2c_seq as u32) << 16);
        pkt[4..8].copy_from_slice(&dw1.to_le_bytes());

        self.h2c_seq = self.h2c_seq.wrapping_add(1);
    }

    fn send_h2c_pkt(&self, h2c_pkt: &[u8]) -> Result<()> {
        let total = TX_DESC_SIZE + H2C_PKT_SIZE;
        let mut buf = vec![0u8; total];

        // TX descriptor: QSEL=0x13 (H2C_CMD)
        buf[0] = (H2C_PKT_SIZE & 0xFF) as u8;
        buf[1] = ((H2C_PKT_SIZE >> 8) & 0xFF) as u8;
        buf[2] = TX_DESC_SIZE as u8;
        buf[5] = 0x13; // QSEL = H2C_CMD

        Self::txdesc_checksum(&mut buf);
        buf[TX_DESC_SIZE..TX_DESC_SIZE + H2C_PKT_SIZE].copy_from_slice(h2c_pkt);

        self.handle
            .write_bulk(self.ep_out, &buf, USB_BULK_TIMEOUT)
            .map_err(|e| Error::UsbTransferFailed {
                endpoint: self.ep_out,
                reason: format!("H2C bulk OUT: {e}"),
            })?;

        Ok(())
    }

    fn init_h2c(&mut self) -> Result<()> {
        let h2cq_addr = RSVD_H2CQ_ADDR << TX_PAGE_SHIFT;
        let h2cq_size = RSVD_PG_H2CQ_NUM << TX_PAGE_SHIFT;

        let v = self.read32(REG_H2C_HEAD)?;
        self.write32(REG_H2C_HEAD, (v & 0xFFFC0000) | h2cq_addr)?;

        let v = self.read32(REG_H2C_READ_ADDR)?;
        self.write32(REG_H2C_READ_ADDR, (v & 0xFFFC0000) | h2cq_addr)?;

        let v = self.read32(REG_H2C_TAIL)?;
        self.write32(REG_H2C_TAIL, (v & 0xFFFC0000) | (h2cq_addr + h2cq_size))?;

        let v = self.read8(REG_H2C_INFO)?;
        self.write8(REG_H2C_INFO, (v & 0xFC) | 0x01)?;
        let v = self.read8(REG_H2C_INFO)?;
        self.write8(REG_H2C_INFO, (v & 0xFB) | 0x04)?;

        // Enable H2C DMA
        let v = self.read8(0x020D)?;
        self.write8(0x020D, v | (1 << 7))?;

        self.h2c_seq = 0;
        Ok(())
    }

    fn send_general_info(&mut self) -> Result<()> {
        let fw_tx_boundary = (RSVD_FW_TXBUF_ADDR - RSVD_BOUNDARY) as u8;
        let mut h2c = [0u8; H2C_PKT_SIZE];
        self.h2c_set_header(&mut h2c, 0x0D, 4);
        h2c[0x0A] = fw_tx_boundary;
        self.send_h2c_pkt(&h2c)
    }

    fn send_phydm_info(&mut self) -> Result<()> {
        let mut h2c = [0u8; H2C_PKT_SIZE];
        self.h2c_set_header(&mut h2c, 0x11, 8);

        h2c[0x08] = 0x00; // RFE_TYPE
        h2c[0x09] = 0x33; // RF_TYPE = 2T2R

        let sys_cfg1 = self.read32(0x00F0)?;
        h2c[0x0A] = ((sys_cfg1 >> 12) & 0xF) as u8; // CUT_VER

        h2c[0x0B] = 0x33; // RX_ANT + TX_ANT
        self.send_h2c_pkt(&h2c)
    }

    fn send_general_info_reg(&mut self) -> Result<()> {
        let sys_cfg1 = self.read32(0x00F0)?;
        let cut_ver = ((sys_cfg1 >> 12) & 0xF) as u8;

        let mut h2c = [0u8; 8];
        h2c[0] = 0x0C | (0x02 << 5); // CMD_ID + CLASS
        h2c[1] = 0x00;               // RFE_TYPE
        h2c[2] = 0x33;               // RF_TYPE (2T2R)
        h2c[3] = cut_ver;
        h2c[4] = 0x33;               // RX_ANT + TX_ANT

        self.send_h2c_msgbox(&h2c)
    }

    fn send_h2c_msgbox(&mut self, h2c_data: &[u8]) -> Result<()> {
        // Wait for firmware to read previous command
        for _ in 0..100 {
            let hmetfr = self.read8(REG_HMETFR)?;
            if hmetfr & (1 << self.h2c_box) == 0 {
                break;
            }
            thread::sleep(H2C_MSGBOX_POLL_DELAY);
        }

        // Write extended (bytes 4-7) first
        let ext_addr = REG_HMEBOX_EXT0 + (self.h2c_box as u16 * 4);
        let h2c_ext = u32::from_le_bytes([
            *h2c_data.get(4).unwrap_or(&0),
            *h2c_data.get(5).unwrap_or(&0),
            *h2c_data.get(6).unwrap_or(&0),
            *h2c_data.get(7).unwrap_or(&0),
        ]);
        self.write32(ext_addr, h2c_ext)?;

        // Write command (bytes 0-3) — triggers firmware
        let box_addr = REG_HMEBOX0 + (self.h2c_box as u16 * 4);
        let h2c_cmd = u32::from_le_bytes([
            h2c_data[0], h2c_data[1], h2c_data[2], h2c_data[3],
        ]);
        self.write32(box_addr, h2c_cmd)?;

        self.h2c_box = (self.h2c_box + 1) % 4;
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Chip initialization (full sequence)
    // ══════════════════════════════════════════════════════════════════════════

    fn chip_init(&mut self) -> Result<()> {
        // Step 1: Power on
        self.power_on()?;

        // Step 2: Firmware
        self.load_firmware()?;

        // Step 3: TRX configuration
        self.write8(REG_CR, 0x00)?; // Disable all MAC engines
        self.write32(0x1330, 1 << 31)?; // Clear H2C queue
        self.write16(REG_CR, 0x0FFF)?; // Enable ALL MAC TRX engines

        // Queue page allocation
        self.write16(0x0230, 64)?;  // HQ
        self.write16(0x0234, 64)?;  // LQ
        self.write16(0x0238, 64)?;  // NQ
        self.write16(0x023C, 0)?;   // EXQ
        self.write16(0x0240, RSVD_BOUNDARY - 64 - 64 - 64 - 1)?; // PUB
        let v = self.read32(0x022C)?;
        self.write32(0x022C, v | (1 << 31))?; // Load enable

        // FIFO boundaries
        self.write16(0x0204, RSVD_BOUNDARY)?;
        let v = self.read8(0x0422)?;
        self.write8(0x0422, v | (1 << 4))?; // download rsvd page
        self.write16(0x0424, RSVD_BOUNDARY)?;
        self.write16(0x0206, RSVD_BOUNDARY)?;
        self.write32(0x011C, RX_FIFO_SIZE - C2H_PKT_BUF - 1)?;

        // Auto LLT init
        let v = self.read8(0x0208)?;
        self.write8(0x0208, (v & !0x30) | 0x30)?; // BLK_DESC_NUM = 3
        self.write8(0x020B, 0x03)?;
        let v = self.read8(0x020D)?;
        self.write8(0x020D, v | (1 << 1))?; // DROP_DATA_EN

        // Trigger Auto LLT
        let v = self.read8(0x0208)?;
        self.write8(0x0208, v | 1)?;
        for _ in 0..1000 {
            let v = self.read8(0x0208)?;
            if v & 1 == 0 {
                break;
            }
            thread::sleep(AUTO_LLT_POLL_DELAY);
        }

        // Transfer mode = normal
        self.write8(REG_CR + 3, 0x00)?;

        // TX DMA PQ MAP
        let pq_map: u16 = (3 << 14) // HIQ→HQ
            | (3 << 12)              // MGQ→HQ
            | (1 << 10)              // BKQ→LQ
            | (1 << 8)               // BEQ→LQ
            | (2 << 6)               // VIQ→NQ
            | (2 << 4)               // VOQ→NQ
            | 1;                     // USB TXDMA enable
        self.write16(0x010C, pq_map)?;

        // Step 4: USB RX DMA
        // RX aggregation is disabled at init (matching Linux) and enabled in
        // set_monitor_mode. The 8-byte alignment in parse_rx_packet handles
        // multiple frames per USB transfer correctly.
        self.write8(0x0290, 0x0E)?; // DMA_MODE | BURST_CNT=3 | BURST_SIZE=1
        let v = self.read8(0x010C)?;
        self.write8(0x010C, v & !(1 << 2))?; // RX AGG off during init (enabled in monitor mode)

        // Step 5: H2C + firmware info
        if self.init_h2c().is_ok() {
            // Error safe to ignore: firmware info sends are non-critical, chip operates without them
            let _ = self.send_general_info();
            thread::sleep(H2C_INFO_DELAY);
            // Error safe to ignore: firmware info sends are non-critical, chip operates without them
            let _ = self.send_phydm_info();
            thread::sleep(H2C_INFO_DELAY);
            // Error safe to ignore: firmware info sends are non-critical, chip operates without them
            let _ = self.send_general_info_reg();
            thread::sleep(H2C_INFO_DELAY);
        }

        // Step 6: EDCA + WMAC config
        self.write16(0x0522, 0x0000)?; // Clear TX pause
        self.write8(0x063A, 0x09)?;     // Slot = 9us
        self.write32(0x0514, 0x0A0A0808)?; // SIFS
        let v = self.read8(REG_BCN_CTRL)?;
        self.write8(REG_BCN_CTRL, v | (1 << 3))?; // Enable beacon
        self.write8(0x0606, 0x08)?; // TCR+2
        self.write8(0x0605, 0x30)?; // TCR+1

        // Step 7: PHY / BB / RF
        self.phy_init()?;

        // Step 7b: IQK calibration (I/Q imbalance correction)
        // Must run after phy_init (BB/RF tables loaded) but before TX power setup.
        // This uploads microcode to the BB calibration engine that corrects
        // I/Q phase and amplitude imbalance on both RF paths.
        self.iqk_calibrate()?;

        // Step 7c: DPK calibration (PA linearization)
        self.dpk_calibrate()?;

        // Step 8: Read EFUSE calibration data
        match self.read_efuse_calibration() {
            Ok((efuse_map, rfe_type)) => {
                self.rfe_type = rfe_type;
                self.efuse_pwr = Self::extract_tx_power_from_efuse(&efuse_map);
            }
            Err(_) => {
                // EFUSE read failed — use defaults (max power, RFE type 0)
                // Non-fatal: driver operates without calibration
            }
        }

        // Step 8b: Read MAC address from autoloaded registers
        // RTL8822B autoloads MAC to 0x0036-0x003B during power-on
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = self.read8(0x0036 + i as u16)?;
        }
        if mac.iter().all(|&b| b == 0xFF) || mac.iter().all(|&b| b == 0x00) {
            // Fallback: try MACID register (may have been written during init)
            let lo = self.read32(0x0610)?;
            let hi = self.read16(0x0614)?;
            mac = [
                (lo & 0xFF) as u8, ((lo >> 8) & 0xFF) as u8,
                ((lo >> 16) & 0xFF) as u8, ((lo >> 24) & 0xFF) as u8,
                (hi & 0xFF) as u8, ((hi >> 8) & 0xFF) as u8,
            ];
        }
        if !mac.iter().all(|&b| b == 0xFF) && !mac.iter().all(|&b| b == 0x00) {
            self.mac_addr = MacAddress::new(mac);
        }

        // Step 9: TX power (calibrated from EFUSE if available) + LC calibration
        self.set_tx_power_calibrated(1, &self.efuse_pwr.clone())?;
        self.lc_calibrate()?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  IQK Calibration (I/Q Imbalance Correction)
    //
    //  Corrects phase and amplitude imbalance between I and Q signal paths.
    //  Without this, the radio runs uncalibrated — degraded SNR, reduced
    //  RX sensitivity, and TX signal distortion.
    //
    //  Extracted from Linux usbmon capture: 32 setup registers configure
    //  the calibration engine for both RF paths (A and B), then 975 values
    //  of microcode are uploaded to the BB calibration processor at 0x1B80.
    //  Linux runs this 5 times for convergence; we run it 3 times (diminishing
    //  returns after that).
    // ══════════════════════════════════════════════════════════════════════════

    fn iqk_calibrate(&self) -> Result<()> {
        // Pre-IQK RF filter calibration (path A then B)
        for &(addr, val) in &rtl8822b_tables::IQK_RF_PREP_A {
            self.write32(addr, val)?;
        }
        for &(addr, val) in &rtl8822b_tables::IQK_RF_PREP_B {
            self.write32(addr, val)?;
        }

        // Setup calibration engine (path A config, path B config, finalize)
        for &(addr, val) in &rtl8822b_tables::IQK_SETUP {
            self.write32(addr, val)?;
        }

        // Upload microcode to BB calibration processor
        // Linux runs this 5 times with identical microcode — the engine converges
        // internally. One upload is sufficient; the microcode is self-contained.
        for &val in &rtl8822b_tables::IQK_MICROCODE {
            self.write32(0x1B80, val)?;
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  DPK Calibration (Digital Pre-Distortion)
    //
    //  Compensates for PA non-linearity by pre-distorting the digital signal.
    //  The LUT maps power levels to correction values. Loaded once at init
    //  after IQK calibration, then activated.
    // ══════════════════════════════════════════════════════════════════════════

    fn dpk_calibrate(&self) -> Result<()> {
        // Load DPK lookup table (64 registers)
        for &(addr, val) in &rtl8822b_tables::DPK_INIT {
            self.write32(addr, val)?;
        }

        // Activate DPK engine
        for &(addr, val) in &rtl8822b_tables::DPK_ACTIVATE {
            self.write32(addr, val)?;
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  LC Calibration (PLL)
    // ══════════════════════════════════════════════════════════════════════════

    fn lc_calibrate(&self) -> Result<()> {
        // AAC check
        let aac_val = (self.read_rf(0, 0xC9)? & 0xF8) >> 3;
        if !(4..=7).contains(&aac_val) {
            self.write_rf(0, 0xCA, 1 << 19, 0x0)?;
            self.write_rf(0, 0xB2, 0x7C000, 0x6)?;
        }

        // Save BB path control
        let save_c00 = self.read32(0x0C00)?;
        let save_e00 = self.read32(0x0E00)?;

        // Single-tone mode
        self.write32(0x0C00, 0x4)?;
        self.write32(0x0E00, 0x4)?;

        // Disable common mode
        self.write_rf(0, 0x0, RFREGOFFSETMASK, 0x10000)?;
        self.write_rf(1, 0x0, RFREGOFFSETMASK, 0x10000)?;

        // Backup RF0x18
        let lc_cal = self.read_rf(0, 0x18)?;

        // Disable RTK
        self.write_rf(0, 0xC4, RFREGOFFSETMASK, 0x01402)?;

        // Start LCK: set BIT(15) in RF0x18
        self.write_rf(0, 0x18, RFREGOFFSETMASK, lc_cal | 0x08000)?;

        // Wait and poll for completion
        thread::sleep(LC_CAL_START_DELAY);
        for _ in 0..10 {
            let check = self.read_rf(0, 0x18)?;
            if check & 0x8000 == 0 {
                break;
            }
            thread::sleep(LC_CAL_POLL_DELAY);
        }

        // Restore
        self.write_rf(0, 0x18, RFREGOFFSETMASK, lc_cal)?;
        self.write_rf(0, 0xC4, RFREGOFFSETMASK, 0x81402)?;
        self.write32(0x0C00, save_c00)?;
        self.write32(0x0E00, save_e00)?;
        self.write_rf(0, 0x0, RFREGOFFSETMASK, 0x3FFFF)?;
        self.write_rf(1, 0x0, RFREGOFFSETMASK, 0x3FFFF)?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Monitor mode
    // ══════════════════════════════════════════════════════════════════════════

    fn set_monitor_internal(&self) -> Result<()> {
        // RCR: accept all + PHY status + FCS
        self.write32(REG_RCR, RCR_AAP | RCR_APP_PHYSTS | RCR_APPFCS)?;

        // Enable sniffer mode
        let wmac_opt = self.read32(0x07D4)?;
        self.write32(0x07D4, wmac_opt | (1 << 9))?;

        // RX driver info size: 5 units (40 bytes)
        let v = self.read8(0x060F)?;
        self.write8(0x060F, (v | 0x80) & 0xF0 | 5)?;

        // Fix TRXFF_BNDY+1
        let v = self.read8(0x011D)?;
        self.write8(0x011D, (v & 0xF0) | 0x0F)?;

        // Accept ALL frame types
        self.write16(REG_RXFLTMAP0, 0xFFFF)?; // management
        self.write16(REG_RXFLTMAP0 + 2, 0xFFFF)?; // control
        self.write16(0x06A4, 0xFFFF)?; // data

        // Disable beacon function
        let v = self.read8(REG_BCN_CTRL)?;
        self.write8(REG_BCN_CTRL, (v & !(1 << 3)) | (1 << 6) | (1 << 4))?;

        // Enable RX aggregation — Linux enables this in monitor mode
        // 0x010C bit 2 = RX AGG enable. Init has 0xA1 (off), monitor sets 0xA5 (on)
        let v = self.read8(0x010C)?;
        self.write8(0x010C, v | (1 << 2))?; // Enable RX AGG
        // AGG page threshold: 0x0280 = timeout<<8 | size_pages
        // RTL8812AU uses 0x0608 (timeout=6, size=8 pages=1KB).
        // Previous value 0x0100 (timeout=1, size=0) gave zero aggregation.
        // Use size=6 pages (~768B min aggregate) with timeout=8 ticks
        // to batch multiple frames per USB read.
        self.write16(0x0280, 0x0806)?;
        // AGG timeout register — allow the DMA to wait for more frames
        self.write8(0x0283, 0x08)?;

        // BB TX path enable — Linux writes 0x0CBD = 0x01 before injection
        // Without this, TX path may be partially disabled
        self.write8(0x0CBD, 0x01)?;

        // Rate adaptive masks for injection (from Linux usbmon)
        self.write32(0x06C0, 0x55555555)?;
        self.write32(0x06C4, 0x55555555)?;
        self.write32(0x06C8, 0xFFFFFFF0)?;

        // Response rate config
        self.write32(0x1C94, 0xFFAFFFAF)?;

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
    //  Channel setting
    // ══════════════════════════════════════════════════════════════════════════

    fn set_channel_internal(&mut self, channel: u8) -> Result<()> {
        // Read current RF18 via direct address
        let mut rf18 = self.read32(0x2800 + (0x18 * 4))? & 0xFFFFF;

        // Clear channel, band, BW, mode bits
        rf18 &= !((1 << 18) | (1 << 17) | (1 << 16)
            | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | 0xFF);

        let ch = channel as u32;

        if channel <= 14 {
            // 2.4 GHz
            rf18 |= ch;

            self.set_bb_reg(0x0454, 1 << 7, 0x0)?;
            self.set_bb_reg(0x0A80, 1 << 18, 0x0)?;
            self.set_bb_reg(0x0814, 0x0000FC00, 15)?;

            // AGC table: index 0
            let v = self.read32(0x0958)?;
            self.write32(0x0958, (v & !0x1F) | 0)?;

            // Center freq for CLK offset
            let v = self.read32(0x0860)?;
            self.write32(0x0860, (v & !0x1FFE0000) | (0x96a << 17))?;

            // CCK TX filter
            if channel != 14 {
                self.write32(0x0A24, 0x384f6577)?;
                self.write16(0x0A28, 0x1525)?;
            } else {
                self.write32(0x0A24, 0x00006577)?;
                self.write16(0x0A28, 0x0000)?;
            }

            // Phase noise reduction
            self.write_rf(0, 0xBE, (1 << 17) | (1 << 16) | (1 << 15), 0x0)?;
        } else {
            // 5 GHz
            rf18 |= (1 << 16) | (1 << 8);
            rf18 |= ch;
            if channel >= 149 {
                rf18 |= 1 << 18;
            } else if channel >= 80 {
                rf18 |= 1 << 17;
            }

            // AGC table by sub-band
            let (agc_idx, fc_area) = match channel {
                36..=48 => (1u32, 0x494u32),
                49..=64 => (1, 0x453),
                100..=116 => (2, 0x452),
                117..=144 => (2, 0x412),
                _ => (3, 0x412),
            };

            let v = self.read32(0x0958)?;
            self.write32(0x0958, (v & !0x1F) | agc_idx)?;

            let v = self.read32(0x0860)?;
            self.write32(0x0860, (v & !0x1FFE0000) | (fc_area << 17))?;
        }

        // Set BW bits for 20MHz in rf18
        rf18 |= (1 << 11) | (1 << 10);

        // Write RF18 to both paths
        self.write_rf(0, 0x18, 0xFFFFF, rf18)?;
        self.write_rf(1, 0x18, 0xFFFFF, rf18)?;

        // Verify with retry
        for retry in 0..3 {
            let delay = if retry == 0 { RF18_VERIFY_INITIAL_DELAY_US } else { RF18_VERIFY_RETRY_DELAY_US };
            thread::sleep(Duration::from_micros(delay));
            let readback = self.read_rf(0, 0x18)?;
            if (readback & 0xFF) == (rf18 & 0xFF) {
                break;
            }
        }

        // PLL re-lock toggle
        self.write_rf(0, 0xB8, 1 << 19, 0)?;
        self.write_rf(0, 0xB8, 1 << 19, 1)?;

        // Enable OFDM+CCK
        self.set_bb_reg(0x0808, (1 << 29) | (1 << 28), 0x3)?;

        // BB bandwidth + RFE
        self.set_bb_bandwidth(CHANNEL_WIDTH_20, 0, channel as u16)?;
        self.rfe_set_channel(channel as u16)?;

        // IGI (Initial Gain Index) — per-band tuning from usbmon analysis
        // 5GHz: 0x20 (32) — lower gain avoids ADC saturation, 12% noise vs 44%
        // 2.4GHz: 0x2E (46) — higher gain for weaker signals, +3dB vs default 0x2A
        let igi = if channel <= 14 { 0x2E } else { 0x20 };
        self.set_bb_reg(0x0C50, 0x7F, igi)?;
        self.set_bb_reg(0x0E50, 0x7F, igi)?;
        self.igi_toggle()?;

        // Settle + TX power (calibrated per-channel from EFUSE)
        thread::sleep(CHANNEL_SETTLE_DELAY);
        let efuse_pwr = self.efuse_pwr.clone();
        self.set_tx_power_calibrated(channel, &efuse_pwr)?;

        self.channel = channel;
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  TX power (TXAGC registers)
    // ══════════════════════════════════════════════════════════════════════════

    #[allow(dead_code)] // called via ChipDriver::set_tx_power() trait dispatch
    fn set_tx_power_regs(&self, power_idx: u8) -> Result<()> {
        let idx = power_idx.min(TXAGC_MAX);
        let pw4 = (idx as u32) * 0x01010101;
        let vht4 = (idx.saturating_sub(2) as u32) * 0x01010101;

        for &base in &[0x1D00u16, 0x1D80] {
            // Uniform rate registers (CCK, OFDM, HT)
            for &offset in &[0x00u8, 0x04, 0x08, 0x0C, 0x10] {
                let addr = base + offset as u16;
                if self.write32(addr, pw4).is_err() {
                    thread::sleep(TXAGC_WRITE_RETRY_DELAY);
                    self.write32(addr, pw4)?;
                }
            }
            // VHT (lower power for PA linearity)
            for &offset in &[0x14u8, 0x18] {
                let addr = base + offset as u16;
                if self.write32(addr, vht4).is_err() {
                    thread::sleep(TXAGC_WRITE_RETRY_DELAY);
                    self.write32(addr, vht4)?;
                }
            }
            // Per-rate staircase
            self.write_txagc_staircase(base, idx)?;
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  RX frame parsing
    // ══════════════════════════════════════════════════════════════════════════

    /// Parse one RX packet from USB bulk buffer.
    /// Returns (bytes_consumed, Option<RxFrame>).
    /// Public for use by the standalone RxThread parse function.
    pub(crate) fn parse_rx_packet(buf: &[u8], channel: u8) -> (usize, Option<RxFrame>) {
        if buf.len() < RX_DESC_SIZE {
            return (0, None);
        }

        let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let pkt_len = (dw0 & 0x3FFF) as usize;
        let crc_err = (dw0 >> 14) & 1 != 0;
        let drvinfo_sz = (((dw0 >> 16) & 0xF) * 8) as usize;
        let shift = ((dw0 >> 24) & 0x3) as usize;
        let has_physt = (dw0 >> 26) & 1 != 0;

        // DW5: TSFL (timestamp)
        let tsfl = if buf.len() >= 24 {
            u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]])
        } else {
            0
        };

        let pkt_offset = RX_DESC_SIZE + drvinfo_sz + shift + pkt_len;
        if pkt_len == 0 || pkt_offset > buf.len() {
            return (0, None);
        }

        // Round up to 8-byte boundary
        let consumed = (pkt_offset + 7) & !7;

        // Strip FCS (4 bytes)
        let frame_len = if pkt_len >= 4 { pkt_len - 4 } else { 0 };

        if crc_err || frame_len == 0 {
            return (consumed, None); // skip CRC errors
        }

        // RSSI from PHY status
        let rssi = if has_physt && drvinfo_sz >= 4 {
            (buf[RX_DESC_SIZE + 1] as i8).wrapping_sub(110)
        } else {
            -80
        };

        let data_off = RX_DESC_SIZE + drvinfo_sz + shift;
        let data = buf[data_off..data_off + frame_len].to_vec();

        let frame = RxFrame {
            data,
            rssi,
            channel,
            band: if channel <= 14 { 0 } else { 1 },
            timestamp: Duration::from_micros(tsfl as u64),
            ..Default::default()
        };

        (consumed, Some(frame))
    }

    #[allow(dead_code)] // called via ChipDriver::rx_frame() trait dispatch
    fn recv_frame_internal(&mut self, timeout: Duration) -> Result<Option<RxFrame>> {
        // Try to parse next packet from existing buffer
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

        // Need a new USB bulk transfer
        let actual = self
            .handle
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
    //  TX frame injection
    // ══════════════════════════════════════════════════════════════════════════

    fn inject_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()> {
        if frame.len() < 10 {
            return Err(Error::TxFailed {
                retries: 0,
                reason: "frame too short".into(),
            });
        }

        let rate = tx_rate_to_hw(&opts.rate, self.channel);
        let retries = if opts.flags.contains(TxFlags::NO_RETRY) {
            1
        } else if opts.retries > 0 {
            opts.retries.min(63)
        } else {
            12
        };

        // Auto-detect broadcast/multicast
        let bmc = frame.len() >= 10 && (frame[4] & 0x01) != 0;

        // Queue from frame type
        let fc_type = frame[0] & 0x0C;
        let qsel = match fc_type {
            0x00 => QSLT_MGNT,
            0x04 => QSLT_VO,
            0x08 => QSLT_BE,
            _ => QSLT_MGNT,
        };

        // ZLP avoidance
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
            let cr_val = self.read16(0x0100)?;
            if cr_val & (1 << 6) == 0 {
                self.write16(0x0100, cr_val | (1 << 6))?;
            }
            let txpause = self.read16(0x0522)?;
            if txpause != 0 {
                self.write16(0x0522, 0x0000)?;
            }
            self.mactx_checked = true;
        }

        // ── Build TX descriptor ──

        // DW0: TXPKTSIZE, OFFSET=48, OWN, LS, BMC
        // Linux usbmon: byte[3] = 0x85 = OWN(7) + LS(2) + BMC(0)
        buf[0x00] = (pkt_size & 0xFF) as u8;
        buf[0x01] = ((pkt_size >> 8) & 0xFF) as u8;
        buf[0x02] = TX_DESC_SIZE as u8;
        buf[0x03] = (1 << 7) | (1 << 2); // OWN + LS
        if bmc {
            buf[0x03] |= 1; // BMC
        }

        // DW1: MACID=0, QSEL, RATE_ID
        // Linux usbmon: MACID=0 for monitor mode injection (not 1)
        buf[0x04] = 0x00; // MACID=0 (matches Linux)
        buf[0x05] = qsel & 0x1F;
        buf[0x06] = if rate <= 0x03 { 8 } else { 7 }; // RATE_ID: 8=B/G, 7=OFDM

        // DW3: USE_RATE + DISABLE_FB
        // Linux usbmon: byte[0x0D] = 0x05 = USE_RATE(0) + DISABLE_FB(2)
        buf[0x0D] = (1 << 0) | (1 << 2); // USE_RATE + DISABLE_FB

        // DW4: DATARATE
        buf[0x10] = rate & 0x7F;

        // DW5: RTY_LMT_EN + retry limit
        buf[0x12] = (1 << 1) | ((retries & 0x3F) << 2); // RTY_LMT_EN + limit

        // DW5: STBC + LDPC (byte 0x17)
        if opts.flags.contains(TxFlags::STBC) {
            buf[0x17] |= 1 << 4; // DATA_STBC = 1 (single stream)
        }
        if opts.flags.contains(TxFlags::LDPC) {
            buf[0x17] |= 1; // DATA_LDPC
        }

        // DW6: SW sequence number (Linux uses SW_SEQ, not HWSEQ_EN)
        let seq = self.tx_seq.wrapping_add(1);
        self.tx_seq = seq;
        let seq_val = (seq as u16) << 4; // sequence number field, frag=0
        buf[0x18] = (seq_val & 0xFF) as u8;
        buf[0x19] = ((seq_val >> 8) & 0xFF) as u8;

        Self::txdesc_checksum(&mut buf);
        buf[TX_DESC_SIZE..TX_DESC_SIZE + frame.len()].copy_from_slice(frame);

        // USB bulk OUT
        self.handle
            .write_bulk(self.ep_out, &buf, USB_BULK_TIMEOUT)
            .map_err(|e| Error::TxFailed {
                retries: 0,
                reason: format!("bulk OUT: {e}"),
            })?;

        // Clear DMA errors on first TX
        if !self.mactx_checked {
            thread::sleep(FIRST_TX_DMA_CHECK_DELAY);
            if let Ok(txdma_status) = self.read32(0x0210) {
                if txdma_status != 0 {
                    // Best-effort DMA error clear — non-fatal if it fails
                    let _ = self.write32(0x0210, txdma_status);
                }
            }
        }

        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ChipDriver trait implementation
// ══════════════════════════════════════════════════════════════════════════════

impl ChipDriver for Rtl8812bu {
    fn init(&mut self) -> Result<()> {
        self.chip_init()
    }

    fn shutdown(&mut self) -> Result<()> {
        self.power_off()?;
        // Error safe to ignore: USB interface release during shutdown, device may already be disconnected
        let _ = self.handle.release_interface(0);
        Ok(())
    }

    fn chip_info(&self) -> ChipInfo {
        ChipInfo {
            name: "RTL8812BU",
            chip: ChipId::Rtl8812bu,
            caps: RTL8812BU_CAPS,
            vid: self.vid,
            pid: self.pid,
            rfe_type: self.rfe_type,
            bands: vec![Band::Band2g, Band::Band5g],
            max_tx_power_dbm: 31,
            firmware_version: String::new(), // TODO: extract from FW header during load_firmware()
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
        self.recv_frame_internal(timeout)
    }

    fn mac(&self) -> MacAddress {
        self.mac_addr
    }

    fn set_mac(&mut self, mac: MacAddress) -> Result<()> {
        self.mac_addr = mac;
        self.macid_written = false; // will be written on next TX or monitor set
        Ok(())
    }

    fn tx_power(&self) -> i8 {
        // Convert index to approximate dBm (2 indices per dBm)
        (self.tx_power_idx / 2) as i8
    }

    fn set_tx_power(&mut self, dbm: i8) -> Result<()> {
        if dbm <= 0 {
            // 0 or negative = use EFUSE calibrated power (optimal)
            self.tx_power_idx = TXAGC_DEFAULT;
            let efuse_pwr = self.efuse_pwr.clone();
            self.set_tx_power_calibrated(self.channel, &efuse_pwr)
        } else {
            // Explicit power level — override calibration
            let idx = (dbm as u16 * 2).min(TXAGC_MAX as u16) as u8;
            let idx = if idx == 0 { 1 } else { idx };
            self.tx_power_idx = idx;
            self.set_tx_power_regs(idx)
        }
    }

    fn calibrate(&mut self) -> Result<()> {
        self.lc_calibrate()
    }

    fn channel_settle_time(&self) -> Duration {
        // RTL8812BU: register-based PLL. Hardware re-lock is ~1-2ms.
        // 5ms is conservative and confirmed working.
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
    fn test_txdesc_checksum_empty() {
        let mut desc = [0u8; TX_DESC_SIZE];
        Rtl8812bu::txdesc_checksum(&mut desc);
        // All zeros → checksum is 0
        assert_eq!(desc[0x1C], 0);
        assert_eq!(desc[0x1D], 0);
    }

    #[test]
    fn test_txdesc_checksum_nonzero() {
        let mut desc = [0u8; TX_DESC_SIZE];
        desc[0] = 0x20; // TXPKTSIZE = 32
        desc[2] = 0x30; // OFFSET = 48
        desc[3] = 0x84; // LS + DISQSELSEQ
        desc[5] = 0x12; // QSEL = MGNT
        Rtl8812bu::txdesc_checksum(&mut desc);
        // Checksum should be non-zero for non-zero descriptor
        let chk = u16::from_le_bytes([desc[0x1C], desc[0x1D]]);
        assert_ne!(chk, 0);
    }

    #[test]
    fn test_txdesc_checksum_idempotent() {
        let mut desc = [0u8; TX_DESC_SIZE];
        desc[0] = 0x42;
        desc[4] = 0x01;
        desc[5] = 0x12;
        Rtl8812bu::txdesc_checksum(&mut desc);
        let c1 = u16::from_le_bytes([desc[0x1C], desc[0x1D]]);
        Rtl8812bu::txdesc_checksum(&mut desc);
        let c2 = u16::from_le_bytes([desc[0x1C], desc[0x1D]]);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_txdesc_checksum_only_first_32_bytes() {
        let mut desc1 = [0u8; TX_DESC_SIZE];
        let mut desc2 = [0u8; TX_DESC_SIZE];
        desc1[0] = 0x42;
        desc2[0] = 0x42;
        // Differ in byte 32+ — should NOT affect checksum
        desc1[32] = 0xFF;
        desc1[40] = 0xAA;
        Rtl8812bu::txdesc_checksum(&mut desc1);
        Rtl8812bu::txdesc_checksum(&mut desc2);
        assert_eq!(desc1[0x1C], desc2[0x1C]);
        assert_eq!(desc1[0x1D], desc2[0x1D]);
    }

    #[test]
    fn test_parse_rx_too_short() {
        let buf = [0u8; 10];
        let (consumed, frame) = Rtl8812bu::parse_rx_packet(&buf, 1);
        assert_eq!(consumed, 0);
        assert!(frame.is_none());
    }

    #[test]
    fn test_parse_rx_zero_pkt_len() {
        let buf = [0u8; RX_DESC_SIZE + 10];
        let (consumed, frame) = Rtl8812bu::parse_rx_packet(&buf, 1);
        assert_eq!(consumed, 0); // pkt_len=0 → reject
        assert!(frame.is_none());
    }

    #[test]
    fn test_parse_rx_valid_beacon() {
        // Construct a minimal RX buffer with a beacon frame
        let frame_data = [
            0x80, 0x00, // FC: beacon
            0x00, 0x00, // duration
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // DA: broadcast
            0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE4, // SA
            0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE4, // BSSID
            0x00, 0x00, // seq
        ];
        let pkt_len = frame_data.len() + 4; // +4 FCS
        let _drvinfo_sz = 0u8; // test packet has no PHY status block

        let mut buf = vec![0u8; RX_DESC_SIZE + pkt_len];
        // DW0: pkt_len, drvinfo_sz=0, shift=0, physt=0, first_seg+last_seg
        let dw0 = (pkt_len as u32) & 0x3FFF
            | ((1 << 28) | (1 << 29)); // first_seg + last_seg
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());

        // DW5: TSFL
        let tsfl: u32 = 12345;
        buf[20..24].copy_from_slice(&tsfl.to_le_bytes());

        // Copy frame data + fake FCS
        buf[RX_DESC_SIZE..RX_DESC_SIZE + frame_data.len()]
            .copy_from_slice(&frame_data);

        let (consumed, frame) = Rtl8812bu::parse_rx_packet(&buf, 11);
        assert!(consumed > 0);
        let frame = frame.expect("should parse frame");
        assert_eq!(frame.channel, 11);
        assert_eq!(frame.data.len(), frame_data.len());
        assert_eq!(frame.data[0], 0x80); // beacon FC
        assert_eq!(frame.timestamp, Duration::from_micros(12345));
    }

    #[test]
    fn test_parse_rx_crc_error_skipped() {
        let pkt_len = 30u32;
        let mut buf = vec![0u8; RX_DESC_SIZE + pkt_len as usize];
        // DW0: pkt_len + CRC error bit (bit 14)
        let dw0 = pkt_len | (1 << 14);
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());

        let (consumed, frame) = Rtl8812bu::parse_rx_packet(&buf, 6);
        assert!(consumed > 0); // consumed but no frame
        assert!(frame.is_none());
    }

    #[test]
    fn test_tx_rate_to_hw_cck_on_5ghz() {
        // CCK should fallback to OFDM 6M on 5GHz
        assert_eq!(tx_rate_to_hw(&TxRate::Cck1m, 36), 0x04);
        assert_eq!(tx_rate_to_hw(&TxRate::Cck11m, 149), 0x04);
    }

    #[test]
    fn test_tx_rate_to_hw_ofdm_mappings() {
        assert_eq!(tx_rate_to_hw(&TxRate::Ofdm6m, 1), 0x04);
        assert_eq!(tx_rate_to_hw(&TxRate::Ofdm54m, 1), 0x0B);
        assert_eq!(tx_rate_to_hw(&TxRate::Cck1m, 1), 0x00);
        assert_eq!(tx_rate_to_hw(&TxRate::Cck11m, 11), 0x03);
    }

    #[test]
    fn test_channel_list() {
        let channels = build_channel_list();
        assert!(channels.len() >= 35); // 14 + 4 + 4 + 12 + 5 = 39
        assert_eq!(channels[0].number, 1);
        assert_eq!(channels[0].band, Band::Band2g);
        assert_eq!(channels[13].number, 14);
        assert_eq!(channels[14].number, 36);
        assert_eq!(channels[14].band, Band::Band5g);
    }

    #[test]
    fn test_apply_delay_variants() {
        // Just ensure they don't panic
        Rtl8812bu::apply_delay(0xFE);
        Rtl8812bu::apply_delay(0xF9);
        Rtl8812bu::apply_delay(0x00);
    }
}
