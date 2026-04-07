//! RTL8852BU chip driver — WiFi 6E (802.11ax)
//!
//! # Hardware
//!
//! Realtek RTL8852B — 802.11ax dual-band (2.4GHz + 5GHz), 2T2R MIMO, USB 3.0.
//! WiFi 6 (HE) capable. Used in: TP-Link AX5400 6E and others.
//! Same MAC AX gen2 architecture as RTL8852A — firmware-centric design
//! with PPDU status correlation for RSSI.
//!
//! Key hardware traits:
//!   - MAC AX (gen2): firmware runs on WCPU, handles BB/RF init + calibration
//!   - Firmware: single binary with header + sections, downloaded via EP7 bulk OUT
//!   - H2C commands: via EP7 with WD + FWCMD header, sequence-tracked with REC_ACK
//!   - Extended register space: addresses > 0xFFFF via wIndex in control transfers
//!
//! # Init Flow (pcap replay from usbmon capture)
//!
//!   Phase -1: Clean dirty FW state (disable CPU + power off if previous session)
//!   Phase  0: Replay pcap init (power on, DMAC, FWDL, post-FWDL H2C)
//!             Background RX drain thread runs during init to prevent EP stall
//!   Phase  1: Post-replay: monitor mode, clear EP5 halt, read MAC, set channel
//!   Final:    TX scheduler enable + max TX power
//!
//! # USB Protocol
//!
//!   Register I/O: vendor control transfers (bRequest=0x05)
//!     Read:  bmRequestType=0xC0, wValue=addr, wIndex=0
//!     Write: bmRequestType=0x40, wValue=addr, wIndex=0
//!     Extended (addr > 0xFFFF): wValue=addr[15:0], wIndex=addr[31:16]
//!   Data TX: bulk OUT EP5 with 48-byte MAC AX WD (WD_BODY + WD_INFO) + frame
//!   Data RX: bulk IN with 16/32-byte RX descriptor, 8-byte aligned aggregation
//!   FW/H2C: bulk OUT EP7 with 24-byte WD + 8-byte FWCMD header + payload
//!
//! # Key difference from 8852AU
//!
//!   - disable_cpu() must NOT toggle PLATFORM_EN (bit 0 of 0x0088).
//!     The 8852BU ROM auto-boots WCPU when PLATFORM_EN cycles.
//!   - Firmware binary: rtw8852b_fw-1.bin (not rtl8852au_fw.bin)
//!   - PIDs: 0xB832 and 0xC832
//!
//! # What's NOT Implemented
//!
//!   - Channel switching (no per-channel pcaps yet)
//!   - Complex RX pipeline (stubbed — need init verification first)
//!   - Phase table files (no 8852B post-boot tables yet)
//!   - 40/80 MHz bandwidth
//!   - TX power calibration from EFUSE

// Register map constants — many not yet wired but needed for full driver implementation.
// Struct fields/methods used via ChipDriver trait dispatch appear unused to the compiler.
#![allow(dead_code)]
#![allow(unused_variables)]

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;
use std::thread;
use std::fs;

use std::sync::Arc;
use rusb::{DeviceHandle, GlobalContext};

use crate::core::{
    Channel, Band, MacAddress, Result, Error,
    chip::{ChipDriver, ChipInfo, ChipId, ChipCaps},
    frame::{RxFrame, TxOptions, TxRate, TxFlags},
    adapter::UsbEndpoints,
};

// ── Constants — hardware register map ──
// Complete MAC AX register addresses, bit definitions, and protocol constants.
// Shared between 8852A and 8852B — same MAC AX gen2 architecture.

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

// H2C command categories (from fwcmd_intf.h)
const FWCMD_H2C_CAT_TEST: u32 = 0;
const FWCMD_H2C_CAT_OUTSRC: u32 = 2;

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

// RX filter bits
const B_AX_SNIFFER_MODE: u32 = 1 << 0;
const B_AX_A_A1_MATCH: u32 = 1 << 1;
const B_AX_A_BC: u32 = 1 << 2;
const B_AX_A_MC: u32 = 1 << 3;
const B_AX_A_UC_CAM_MATCH: u32 = 1 << 4;
const B_AX_A_CRC32_ERR: u32 = 1 << 11;

// ── TX Write Descriptor — MAC AX ──
// WD = WD_BODY (24 bytes) + optional WD_INFO (24 bytes when WDINFO_EN=1)

const TX_WD_BODY_LEN: usize = 24;
const TX_WD_INFO_LEN: usize = 24;
const TX_WD_TOTAL_LEN: usize = TX_WD_BODY_LEN + TX_WD_INFO_LEN; // 48 bytes

// WD_BODY DW0 — control word
const AX_TXD_STF_MODE: u32    = 1 << 10;  // store-and-forward (USB)
const AX_TXD_WDINFO_EN: u32   = 1 << 22;  // WD_INFO section present
const AX_TXD_HDR_LLC_LEN_SH: u32 = 11;    // hdr_len / 2, 5-bit field [15:11]

// WD_BODY DW2
const AX_TXD_QSEL_SH: u32 = 17;           // queue select [22:17], 6-bit
const AX_TXD_MACID_SH: u32 = 24;          // MAC ID [30:24], 7-bit

// WD_BODY DW3
const AX_TXD_WIFI_SEQ_SH: u32 = 0;        // software sequence [11:0]
const AX_TXD_AGG_EN: u32      = 1 << 12;  // A-MPDU aggregation enable
const AX_TXD_BK: u32          = 1 << 13;  // break aggregation

// WD_INFO DW0 (at WD offset 24) — rate control
const AX_TXD_DATARATE_SH: u32 = 16;       // rate index [24:16], 9-bit
const AX_TXD_GI_LTF_SH: u32   = 25;       // GI/LTF type [27:25], 3-bit
const AX_TXD_DATA_BW_SH: u32  = 28;       // bandwidth [29:28], 2-bit
const AX_TXD_USERATE_SEL: u32 = 1 << 30;  // use explicit rate (not rate adaptation)
const AX_TXD_DATA_STBC: u32   = 1 << 12;
const AX_TXD_DATA_LDPC: u32   = 1 << 11;
const AX_TXD_DISDATAFB: u32   = 1 << 10;  // disable data rate fallback

// WD_INFO DW1 (at WD offset 28) — retry + flags
const AX_TXD_DATA_TXCNT_LMT_SH: u32  = 25;  // max TX count [30:25], 6-bit
const AX_TXD_DATA_TXCNT_LMT_SEL: u32 = 1 << 31; // enable TX count limit
const AX_TXD_BMC: u32         = 1 << 11;  // broadcast/multicast
const AX_TXD_SPE_RPT: u32     = 1 << 10;  // DW9 (INFO DW3): request TX status report from firmware
const AX_TXD_NAVUSEHDR: u32   = 1 << 10;  // use NAV from 802.11 header

// WD_INFO DW4 (at WD offset 40) — protection
const AX_TXD_RTS_EN: u32      = 1 << 27;  // RTS before frame
const AX_TXD_CTS2SELF: u32    = 1 << 28;  // CTS-to-self protection

// Queue select values (from type.h)
const MAC_AX_MG0_SEL: u32 = 18;   // management queue 0 (band 0)
const MAC_AX_MG1_SEL: u32 = 26;   // management queue 1 (band 1)

// DMA channel mapping for data frames
const MAC_AX_DMA_ACH0: u32 = 0;  // AC_BE
const MAC_AX_DMA_ACH1: u32 = 1;  // AC_BK
const MAC_AX_DMA_ACH2: u32 = 2;  // AC_VI
const MAC_AX_DMA_ACH3: u32 = 3;  // AC_VO
const MAC_AX_DMA_B0MG: u32 = 8;  // band 0 management

// ── Timing ──

const POLL_ITER_DELAY: Duration = Duration::from_micros(100);
const FIRST_TX_DMA_CHECK_DELAY: Duration = Duration::from_millis(2);

// ── Firmware search paths ──

const FW_SEARCH_PATHS: &[&str] = &[
    "firmware/rtw8852b_fw-1.bin",
    "references/firmware_all/rtw8852b_fw-1.bin",
];

// ══════════════════════════════════════════════════════════════════════════════
//  Channel list (same dual-band set as other Realtek chips)
// ══════════════════════════════════════════════════════════════════════════════

fn build_channel_list() -> Vec<Channel> {
    let mut channels = Vec::new();
    // 2.4 GHz: channels 1-13
    for ch in 1..=13u8 {
        channels.push(Channel::new(ch));
    }
    // 5 GHz: UNII-1/2/2e/3
    for &ch in &[36u8,40,44,48, 52,56,60,64, 100,104,108,112,116,120,124,128,132,136,140,144, 149,153,157,161,165] {
        channels.push(Channel::new(ch));
    }
    channels
}

/// MAC AX DATARATE encoding (9-bit, from rtw_general_def.h)
fn ax_rate_to_hw(rate: &TxRate) -> u16 {
    match rate {
        TxRate::Cck1m   => 0x00,
        TxRate::Cck2m   => 0x01,
        TxRate::Cck5_5m => 0x02,
        TxRate::Cck11m  => 0x03,
        TxRate::Ofdm6m  => 0x04,
        TxRate::Ofdm9m  => 0x05,
        TxRate::Ofdm12m => 0x06,
        TxRate::Ofdm18m => 0x07,
        TxRate::Ofdm24m => 0x08,
        TxRate::Ofdm36m => 0x09,
        TxRate::Ofdm48m => 0x0A,
        TxRate::Ofdm54m => 0x0B,
        TxRate::HtMcs(mcs) => 0x80 + (*mcs as u16),
        TxRate::VhtMcs { mcs, nss } => 0x100 + ((nss.saturating_sub(1) as u16) << 4) + (*mcs as u16),
        TxRate::HeMcs { mcs, nss } | TxRate::HeExtSuMcs { mcs, nss }
        | TxRate::HeTbMcs { mcs, nss } | TxRate::HeMuMcs { mcs, nss } => {
            0x180 + ((nss.saturating_sub(1) as u16) << 4) + (*mcs as u16)
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Driver struct
// ══════════════════════════════════════════════════════════════════════════════

pub struct Rtl8852bu {
    handle: Arc<DeviceHandle<GlobalContext>>,
    ep_out: u8,
    ep_in: u8,
    ep_fw: u8,  // EP7 — firmware download bulk OUT
    /// Current channel — Arc<AtomicU8> so the RX pipeline parser thread
    /// can read it without locking the driver.
    channel: Arc<AtomicU8>,
    mac_addr: MacAddress,
    h2c_seq: u16,
    tx_power_dbm: i8,
    rx_buf: Vec<u8>,
    rx_pos: usize,
    rx_len: usize,
    channels: Vec<Channel>,
    vid: u16,
    pid: u16,
    fw_version: String,
}

/// RTL8852BU capability flags — WiFi 6 with HE support
const RTL8852BU_CAPS: ChipCaps = ChipCaps::MONITOR.union(ChipCaps::INJECT)
    .union(ChipCaps::BAND_2G).union(ChipCaps::BAND_5G)
    .union(ChipCaps::HT).union(ChipCaps::VHT).union(ChipCaps::HE)
    .union(ChipCaps::BW40).union(ChipCaps::BW80);

impl Rtl8852bu {
    // ══════════════════════════════════════════════════════════════════════════
    //  Accessors for diagnostic tools
    // ══════════════════════════════════════════════════════════════════════════

    pub fn usb_handle(&self) -> Arc<DeviceHandle<GlobalContext>> { Arc::clone(&self.handle) }
    pub fn bulk_in_ep(&self) -> u8 { self.ep_in }

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
        // EP7 = firmware/H2C endpoint (3rd bulk OUT: EP5=TX, EP6=?, EP7=FWDL/H2C)
        let ep_fw = endpoints.bulk_out_all.get(2).copied().ok_or_else(|| {
            Error::ChipInitFailed {
                chip: "RTL8852BU".into(),
                stage: crate::core::error::InitStage::UsbEnumeration,
                reason: format!("need 3 bulk OUT endpoints, found {}: {:?}",
                    endpoints.bulk_out_all.len(),
                    endpoints.bulk_out_all),
            }
        })?;

        let driver = Self {
            handle: Arc::new(handle),
            ep_out,
            ep_in,
            ep_fw,
            channel: Arc::new(AtomicU8::new(0)),
            mac_addr: MacAddress::ZERO,
            h2c_seq: 0,
            tx_power_dbm: 20,
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

    pub(crate) fn read8(&self, addr: u16) -> Result<u8> {
        let mut buf = [0u8; 1];
        let r = self.handle.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT)?;
        if r < 1 { return Err(Error::RegisterReadFailed { addr }); }
        Ok(buf[0])
    }

    pub(crate) fn write8(&self, addr: u16, val: u8) -> Result<()> {
        let r = self.handle.write_control(0x40, RTL_USB_REQ, addr, 0, &[val], RTL_USB_TIMEOUT)?;
        if r < 1 { return Err(Error::RegisterWriteFailed { addr, val: val as u32 }); }
        Ok(())
    }

    pub(crate) fn read16(&self, addr: u16) -> Result<u16> {
        let mut buf = [0u8; 2];
        let r = self.handle.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT)?;
        if r < 2 { return Err(Error::RegisterReadFailed { addr }); }
        Ok(u16::from_le_bytes(buf))
    }

    pub(crate) fn write16(&self, addr: u16, val: u16) -> Result<()> {
        let r = self.handle.write_control(0x40, RTL_USB_REQ, addr, 0, &val.to_le_bytes(), RTL_USB_TIMEOUT)?;
        if r < 2 { return Err(Error::RegisterWriteFailed { addr, val: val as u32 }); }
        Ok(())
    }

    pub fn read32(&self, addr: u16) -> Result<u32> {
        let mut buf = [0u8; 4];
        let r = self.handle.read_control(0xC0, RTL_USB_REQ, addr, 0, &mut buf, RTL_USB_TIMEOUT)?;
        if r < 4 { return Err(Error::RegisterReadFailed { addr }); }
        Ok(u32::from_le_bytes(buf))
    }

    pub fn write32(&self, addr: u16, val: u32) -> Result<()> {
        let r = self.handle.write_control(0x40, RTL_USB_REQ, addr, 0, &val.to_le_bytes(), RTL_USB_TIMEOUT)?;
        if r < 4 { return Err(Error::RegisterWriteFailed { addr, val }); }
        Ok(())
    }

    // ── Extended register access (addresses > 0xFFFF via wIndex) ──

    pub(crate) fn read32_ext(&self, addr: u32) -> Result<u32> {
        let mut buf = [0u8; 4];
        let w_value = (addr & 0xFFFF) as u16;
        let w_index = ((addr >> 16) & 0xFFFF) as u16;
        let r = self.handle.read_control(0xC0, RTL_USB_REQ, w_value, w_index, &mut buf, RTL_USB_TIMEOUT)?;
        if r < 4 { return Err(Error::RegisterReadFailed { addr: w_value }); }
        Ok(u32::from_le_bytes(buf))
    }

    pub(crate) fn write32_ext(&self, addr: u32, val: u32) -> Result<()> {
        let w_value = (addr & 0xFFFF) as u16;
        let w_index = ((addr >> 16) & 0xFFFF) as u16;
        let r = self.handle.write_control(0x40, RTL_USB_REQ, w_value, w_index, &val.to_le_bytes(), RTL_USB_TIMEOUT)?;
        if r < 4 { return Err(Error::RegisterWriteFailed { addr: w_value, val }); }
        Ok(())
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

    fn set_bits32(&self, addr: u16, bits: u32) -> Result<()> {
        let val = self.read32(addr)?;
        self.write32(addr, val | bits)
    }

    fn clear_bits32(&self, addr: u16, bits: u32) -> Result<()> {
        let val = self.read32(addr)?;
        self.write32(addr, val & !bits)
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Power on sequence — from pwr_seq_8852b.c
    // ══════════════════════════════════════════════════════════════════════════

    fn power_on(&mut self) -> Result<()> {
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

        // Phase 1: Reset FW ctrl and prepare for power-on
        self.write32(R_AX_WCPU_FW_CTRL, 0)?;
        self.clear_bits32(R_AX_AFE_CTRL1, 1 << 20)?;

        // Clear GPIO pull-low enables
        let led_cfg = self.read32(R_AX_LED_CFG)?;
        self.write32(R_AX_LED_CFG, led_cfg & !((1 << 8) | (1 << 17)))?;

        // Phase 2: LPS exit (if needed)
        if pwr_state == 2 {
            self.set_bits32(R_AX_FWS0IMR, 1 << 10)?;
            self.set_bits32(R_AX_GPIO_PH_CFG, 1 << 10)?;
            self.set_bits32(R_AX_GPIO_EXT_CTRL, (1 << 10) | (1 << 18) | (1 << 26))?;
            self.clear_bits32(R_AX_GPIO_EXT_CTRL, 1 << 10)?;
            self.set_bits32(R_AX_GPIO_EXT_CTRL, 1 << 10)?;

            for _ in 0..10000 {
                let state = (self.read32(R_AX_IC_PWR_STATE)? >> 8) & 0x3;
                if state != 2 { break; }
                thread::sleep(Duration::from_micros(50));
            }
        }

        // Phase 3: Power-on table
        self.write8_mask(0x0005, 0x18, 0x00)?;
        self.write8_mask(0x0005, 0x80, 0x00)?;
        self.write8_mask(0x0005, 0x04, 0x00)?;
        self.poll8(0x0006, 0x02, 0x02, 200)?;
        self.write8_mask(0x0006, 0x01, 0x01)?;
        self.write8_mask(0x0005, 0x01, 0x01)?;
        self.poll8(0x0005, 0x01, 0x00, 200)?;

        // MAC clock toggle sequence (stabilization)
        for _ in 0..2 {
            self.write8_mask(0x0088, 0x01, 0x01)?;
            self.write8_mask(0x0088, 0x01, 0x00)?;
        }
        self.write8_mask(0x0088, 0x01, 0x01)?;

        // Final init
        self.write8_mask(0x0083, 0x40, 0x00)?;
        self.write8_mask(0x0080, 0x20, 0x20)?;
        self.write8_mask(0x0024, 0x1F, 0x00)?;
        self.write8_mask(0x02A0, 0x02, 0x02)?;
        self.write8_mask(0x02A2, 0xE0, 0x00)?;

        // Phase 4: Post power-on
        self.clear_bits32(R_AX_FWS0IMR, 1 << 10)?;
        self.set_bits32(R_AX_FWS0ISR, 1 << 10)?;
        self.write8(R_AX_SCOREBOARD as u16 + 3, 0x01)?;

        Ok(())
    }

    fn power_off(&mut self) -> Result<()> {
        // Disable WCPU
        self.clear_bits32(R_AX_PLATFORM_ENABLE, B_AX_WCPU_EN)?;
        // Power off table (simplified)
        self.write8_mask(0x0005, 0x01, 0x01)?;
        let _ = self.poll8(0x0005, 0x01, 0x00, 200);
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  DMAC pre-init — required BEFORE firmware download
    //  Kept as reference — actual init uses pcap replay.
    //  Register values adapted for 8852B from the pcap capture.
    // ══════════════════════════════════════════════════════════════════════════

    fn dmac_pre_init_and_enable_cpu(&self) -> Result<()> {
        // ── SYS_CFG (0x0190/0x0194) — clear LDO boost ──
        let v = self.read32(0x0190)?;
        self.write32(0x0190, v & !0x00000400)?;
        let v = self.read32(0x0194)?;
        self.write32(0x0194, v)?;

        // ── HCI DMA enable (0x8380) ──
        self.write32(R_AX_HCI_FUNC_EN, 0x00000003)?;

        // ── DMAC_FUNC_EN + CLK_EN (0x8400/0x8404) ──
        self.write32(R_AX_DMAC_FUNC_EN, 0x60440000)?;
        self.write32(R_AX_DMAC_CLK_EN, 0x00040000)?;
        let _ = self.read32(R_AX_DMAC_FUNC_EN)?;
        self.write32(R_AX_DMAC_FUNC_EN, 0x60440000)?;
        let _ = self.read32(R_AX_DMAC_CLK_EN)?;
        self.write32(R_AX_DMAC_CLK_EN, 0x04840000)?;

        // ── DMA engine config (8852B values from pcap) ──
        let _ = self.read32(0x8C08)?;
        self.write32(0x8C08, 0)?;
        let _ = self.read32(0x9008)?;
        self.write32(0x9008, 0x00400801)?;  // 8852B: 0x00400801 (vs 8852A: 0x00402001)

        // ── TX/RX queue descriptors (DLE init — 8852B values from pcap) ──
        self.write32(0x8C40, 0)?;
        self.write32(0x8C44, 0x00000002)?;  // 8852B: 0x02 (vs 8852A: 0xC4)
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
                break;
            }
            if i == 4999 {
                return Err(Error::FirmwareError { chip: "RTL8852BU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed });
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

        // ── USB IO mode + clear TX/RX reset ──
        let v = self.read32(0x1078)?;
        self.write32(0x1078, v | (1 << 4))?;

        let v = self.read32(0x1174)?;
        self.write32(0x1174, v & !(0x300))?;

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
        let _ = self.read32(0x00FC)?;
        let _ = self.read32(0x00F0)?;

        // ── HPON writeback ──
        let v = self.read32(R_AX_PLATFORM_ENABLE)?;
        self.write32(R_AX_PLATFORM_ENABLE, v)?;

        // ── Clear FWDL control ──
        self.write32(R_AX_WCPU_FW_CTRL, 0)?;

        // ── SYS_CLK_CTRL writeback ──
        let v = self.read32(R_AX_SYS_CLK_CTRL)?;
        self.write32(R_AX_SYS_CLK_CTRL, v)?;

        // ── Pre-download config ──
        self.write32(0x01E8, 0)?;
        self.write32(R_AX_HALT_H2C_CTRL, 0)?;
        self.write32(R_AX_HALT_C2H_CTRL, 0)?;

        // ── SYS_CLK_CTRL — set bit 14 (CPU_CLK_EN) ──
        let v = self.read32(R_AX_SYS_CLK_CTRL)?;
        self.write32(R_AX_SYS_CLK_CTRL, v | B_AX_CPU_CLK_EN)?;

        // ── FWDL trigger ──
        let _ = self.read32(R_AX_WCPU_FW_CTRL)?;
        self.write32(R_AX_WCPU_FW_CTRL, 0x00000001)?;
        let _ = self.read32(0x01E4)?;
        self.write16(R_AX_BOOT_REASON, 0x0000)?;

        // ── HPON — set WCPU_EN (bit 1) ──
        let v = self.read32(R_AX_PLATFORM_ENABLE)?;
        self.write32(R_AX_PLATFORM_ENABLE, v | B_AX_WCPU_EN)?;

        // ── Poll 0x01E0 for H2C_PATH_RDY (bit 1) ──
        for _ in 0..FWDL_WAIT_US {
            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
            if ctrl & B_AX_H2C_PATH_RDY != 0 {
                return Ok(());
            }
            thread::sleep(Duration::from_micros(1));
        }
        Err(Error::FirmwareError { chip: "RTL8852BU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Firmware download — from fwdl.c
    // ══════════════════════════════════════════════════════════════════════════

    fn load_firmware(&mut self) -> Result<()> {
        let fw_data = self.find_firmware()?;

        if fw_data.len() < FWHDR_HDR_LEN {
            return Err(Error::FirmwareError { chip: "RTL8852BU".into(), kind: crate::core::error::FirmwareErrorKind::TooSmall });
        }

        let dw6 = u32::from_le_bytes([fw_data[24], fw_data[25], fw_data[26], fw_data[27]]);
        let section_num = ((dw6 >> 8) & 0xFF) as usize;
        let hdr_len = FWHDR_HDR_LEN + section_num * FWHDR_SECTION_LEN;

        let major = fw_data[4];
        let minor = fw_data[5];
        let sub = fw_data[6];
        self.fw_version = format!("{}.{}.{}", major, minor, sub);

        let mut sections: Vec<(u32, usize, usize)> = Vec::new();
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
                sec_size += 8;
            }
            sections.push((sec_dl_addr, data_offset, sec_size));
            data_offset += sec_size;
        }

        let mut fw_hdr = fw_data[..hdr_len].to_vec();
        let dw7 = u32::from_le_bytes([fw_hdr[28], fw_hdr[29], fw_hdr[30], fw_hdr[31]]);
        let dw7_new = (dw7 & !0x0000FFFF) | (FWDL_SECTION_PER_PKT_LEN as u32 & 0xFFFF);
        fw_hdr[28..32].copy_from_slice(&dw7_new.to_le_bytes());

        self.fwdl_send_h2c(&fw_hdr)?;

        for i in 0..FWDL_WAIT_US {
            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
            if ctrl & B_AX_FWDL_PATH_RDY != 0 {
                break;
            }
            if i == FWDL_WAIT_US - 1 {
                return Err(Error::FirmwareError { chip: "RTL8852BU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed });
            }
            thread::sleep(Duration::from_micros(1));
        }

        self.write32(R_AX_HALT_H2C_CTRL, 0)?;
        self.write32(R_AX_HALT_C2H_CTRL, 0)?;

        for &(_dl_addr, offset, size) in sections.iter() {
            let section_data = &fw_data[offset..offset + size];
            self.fwdl_send_section(section_data)?;
        }

        thread::sleep(Duration::from_millis(5));
        for _ in 0..FWDL_WAIT_US {
            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
            let sts = (ctrl >> B_AX_FWDL_STS_SH) & B_AX_FWDL_STS_MSK;
            if sts == FWDL_WCPU_FW_INIT_RDY {
                return Ok(());
            }
            thread::sleep(Duration::from_micros(1));
        }

        Err(Error::FirmwareError { chip: "RTL8852BU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })
    }

    /// Disable WCPU — 8852BU variant.
    ///
    /// CRITICAL DIFFERENCE from 8852AU: do NOT toggle PLATFORM_EN (bit 0 of 0x0088).
    /// The 8852BU ROM automatically re-enables WCPU when PLATFORM_EN cycles, which
    /// causes a race condition where the CPU re-boots before we can start our FWDL.
    /// Instead, just clear WCPU_EN, FW_CTRL, and CPU_CLK_EN.
    fn disable_cpu(&self) -> Result<()> {
        // Clear WCPU_EN (bit 1) — stop the CPU
        self.clear_bits32(R_AX_PLATFORM_ENABLE, B_AX_WCPU_EN)?;
        // Clear FWDL bits in FW_CTRL
        self.write32(R_AX_WCPU_FW_CTRL, 0)?;
        // Disable CPU clock
        self.clear_bits32(R_AX_SYS_CLK_CTRL, B_AX_CPU_CLK_EN)?;
        // DO NOT touch PLATFORM_EN — 8852BU ROM re-enables WCPU when it cycles
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
        Err(Error::FirmwareError { chip: "RTL8852BU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })
    }

    /// Send FW header via bulk OUT EP7 with H2C WD + H2C header prepended
    fn fwdl_send_h2c(&mut self, payload: &[u8]) -> Result<()> {
        let h2c_payload_len = FWCMD_HDR_LEN + payload.len();
        let total_len = WD_BODY_LEN + h2c_payload_len;
        let mut buf = vec![0u8; total_len];

        // Build WD (24 bytes) — H2C type, NO FWDL_EN
        let wd_dw0 = MAC_AX_DMA_H2C << AX_TXD_CH_DMA_SH;
        buf[0..4].copy_from_slice(&wd_dw0.to_le_bytes());
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

        buf[WD_BODY_LEN + FWCMD_HDR_LEN..].copy_from_slice(payload);

        self.handle.write_bulk(self.ep_fw, &buf, Duration::from_secs(2))
            .map_err(|_| Error::FirmwareError { chip: "RTL8852BU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })?;

        Ok(())
    }

    /// Send a generic H2C command via bulk OUT EP7.
    fn send_h2c_cmd(&mut self, cat: u32, class: u32, func: u32, payload: &[u8]) -> Result<()> {
        let h2c_payload_len = FWCMD_HDR_LEN + payload.len();
        let total_len = WD_BODY_LEN + h2c_payload_len;
        let mut buf = vec![0u8; total_len];
        let seq = self.h2c_seq;

        let wd_dw0 = MAC_AX_DMA_H2C << AX_TXD_CH_DMA_SH;
        buf[0..4].copy_from_slice(&wd_dw0.to_le_bytes());
        let wd_dw2 = h2c_payload_len as u32;
        buf[8..12].copy_from_slice(&wd_dw2.to_le_bytes());

        let h2c_dw0 = (FWCMD_TYPE_H2C << H2C_HDR_DEL_TYPE_SH)
            | (cat << H2C_HDR_CAT_SH)
            | (class << H2C_HDR_CLASS_SH)
            | (func << H2C_HDR_FUNC_SH)
            | ((seq as u32) << H2C_HDR_H2C_SEQ_SH);
        let h2c_dw1 = (h2c_payload_len as u32) << H2C_HDR_TOTAL_LEN_SH;
        buf[WD_BODY_LEN..WD_BODY_LEN+4].copy_from_slice(&h2c_dw0.to_le_bytes());
        buf[WD_BODY_LEN+4..WD_BODY_LEN+8].copy_from_slice(&h2c_dw1.to_le_bytes());
        self.h2c_seq = self.h2c_seq.wrapping_add(1);

        buf[WD_BODY_LEN + FWCMD_HDR_LEN..].copy_from_slice(payload);

        match self.handle.write_bulk(self.ep_fw, &buf, Duration::from_secs(2)) {
            Ok(_) => {}
            Err(_) => {
                let _ = self.handle.clear_halt(self.ep_fw);
                return Err(Error::FirmwareError {
                    chip: "RTL8852BU".into(),
                    kind: crate::core::error::FirmwareErrorKind::DownloadFailed,
                });
            }
        }

        Ok(())
    }

    // ── H2CREG registers (register-based H2C) ──

    const H2CREG_DATA0: u16 = 0x8140;
    const H2CREG_DATA1: u16 = 0x8144;
    const H2CREG_CTRL: u16  = 0x8160;
    const H2CREG_C2H: u16   = 0x8164;

    /// Send SCH_TX_EN — enable/disable the firmware TX scheduler.
    fn send_sch_tx_en(&self, tx_en: u16) -> Result<()> {
        for _ in 0..100 {
            if self.read8(Self::H2CREG_CTRL)? & 0x01 == 0 { break; }
            thread::sleep(Duration::from_micros(200));
        }

        let data0: u32 = 0x05
            | (0x03 << 8)
            | ((tx_en as u32) << 16);
        let data1: u32 = 0xFFFF;
        self.write32(Self::H2CREG_DATA0, data0)?;
        self.write32(Self::H2CREG_DATA1, data1)?;

        self.write8(Self::H2CREG_CTRL, 0x01)?;

        for _ in 0..100 {
            let c2h = self.read8(Self::H2CREG_C2H)?;
            if c2h != 0 {
                self.write8(Self::H2CREG_C2H, 0x00)?;
                return Ok(());
            }
            thread::sleep(Duration::from_micros(200));
        }

        Ok(())
    }

    /// Send FWROLE_MAINTAIN — tell firmware about our role.
    fn send_fwrole_maintain(&mut self, macid: u8, wifi_role: u8, upd_mode: u8) -> Result<()> {
        let dw0: u32 = (macid as u32)
            | ((upd_mode as u32 & 0x7) << 10)
            | ((wifi_role as u32 & 0xF) << 13);
        self.send_h2c_cmd(FWCMD_H2C_CAT_MAC, 8, 4, &dw0.to_le_bytes())
    }

    /// Send ADDR_CAM — register our MAC address with the firmware.
    fn send_addr_cam(&mut self, mac: &[u8; 6]) -> Result<()> {
        let mut payload = [0u8; 60];

        let dw1: u32 = 64u32 << 16;
        payload[4..8].copy_from_slice(&dw1.to_le_bytes());

        let sma_hash: u8 = mac.iter().fold(0u8, |acc, &b| acc ^ b);
        let dw2: u32 = 1
            | ((sma_hash as u32) << 16);
        payload[8..12].copy_from_slice(&dw2.to_le_bytes());

        let dw4: u32 = (mac[0] as u32)
            | ((mac[1] as u32) << 8)
            | ((mac[2] as u32) << 16)
            | ((mac[3] as u32) << 24);
        payload[16..20].copy_from_slice(&dw4.to_le_bytes());

        let dw5: u32 = (mac[4] as u32)
            | ((mac[5] as u32) << 8);
        payload[20..24].copy_from_slice(&dw5.to_le_bytes());

        let dw12: u32 = 8u32 << 16;
        payload[48..52].copy_from_slice(&dw12.to_le_bytes());

        let dw13: u32 = 1;
        payload[52..56].copy_from_slice(&dw13.to_le_bytes());

        self.send_h2c_cmd(FWCMD_H2C_CAT_MAC, 6, 0, &payload)
    }

    /// Complete firmware role setup: FWROLE_MAINTAIN(CREATE/MONITOR) + ADDR_CAM.
    pub fn setup_firmware_role(&mut self) -> Result<()> {
        let _ = self.send_fwrole_maintain(0, 7, 0);
        let mac = self.mac_addr.0;
        let _ = self.send_addr_cam(&mac);
        let _ = self.send_fwrole_maintain(0, 7, 1);

        let _ = self.send_sch_tx_en(0xFFFF);
        self.write16(0xC348, 0xFFFF)?;

        let sys_cfg5 = self.read32(0x0170).unwrap_or(0);
        self.write32(0x0170, sys_cfg5 | 0x03)?;

        Ok(())
    }

    /// Send FW section data via bulk OUT EP7 with FWDL WD prepended
    fn fwdl_send_section(&self, section: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < section.len() {
            let chunk_len = (section.len() - offset).min(FWDL_SECTION_PER_PKT_LEN);
            let total_len = WD_BODY_LEN + chunk_len;
            let mut buf = vec![0u8; total_len];

            let wd_dw0 = (MAC_AX_DMA_H2C << AX_TXD_CH_DMA_SH) | AX_TXD_FWDL_EN;
            buf[0..4].copy_from_slice(&wd_dw0.to_le_bytes());
            let wd_dw2 = chunk_len as u32;
            buf[8..12].copy_from_slice(&wd_dw2.to_le_bytes());

            buf[WD_BODY_LEN..].copy_from_slice(&section[offset..offset + chunk_len]);

            self.handle.write_bulk(self.ep_fw, &buf, Duration::from_secs(2))
                .map_err(|_| Error::FirmwareError { chip: "RTL8852BU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })?;

            offset += chunk_len;
        }
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Read MAC address from hardware
    // ══════════════════════════════════════════════════════════════════════════

    fn read_mac_address(&mut self) -> Result<()> {
        // Source 1: Autoloaded MAC (0x0036-0x003B)
        let auto_lo = self.read32(0x0036)?;
        let auto_hi = self.read16(0x003A)?;
        let mac_auto = [
            (auto_lo & 0xFF) as u8,
            ((auto_lo >> 8) & 0xFF) as u8,
            ((auto_lo >> 16) & 0xFF) as u8,
            ((auto_lo >> 24) & 0xFF) as u8,
            (auto_hi & 0xFF) as u8,
            ((auto_hi >> 8) & 0xFF) as u8,
        ];

        // Source 2: MACID register (0xC100-0xC105)
        let macid_lo = self.read32(R_AX_MACID_REG)?;
        let macid_hi = self.read16(R_AX_MACID_REG + 4)?;
        let mac_macid = [
            (macid_lo & 0xFF) as u8,
            ((macid_lo >> 8) & 0xFF) as u8,
            ((macid_lo >> 16) & 0xFF) as u8,
            ((macid_lo >> 24) & 0xFF) as u8,
            (macid_hi & 0xFF) as u8,
            ((macid_hi >> 8) & 0xFF) as u8,
        ];

        if mac_auto != [0x00; 6] && mac_auto != [0xFF; 6] {
            self.mac_addr = MacAddress::new(mac_auto);
        } else if mac_macid != [0x00; 6] && mac_macid != [0xFF; 6] {
            self.mac_addr = MacAddress::new(mac_macid);
        } else {
            self.mac_addr = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Chip init — pcap replay
    // ══════════════════════════════════════════════════════════════════════════

    fn chip_init(&mut self) -> Result<()> {
        let t0 = std::time::Instant::now();

        // ── Phase -1: Clean up dirty firmware state ──
        // 8852BU disable_cpu() does NOT toggle PLATFORM_EN (ROM re-enables WCPU)
        let fw_ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
        if fw_ctrl != 0 {
            eprintln!("  [init] cleaning dirty FW state (ctrl=0x{:02X})", fw_ctrl);
            self.disable_cpu()?;
            self.power_off()?;
            thread::sleep(Duration::from_millis(50));
        }

        // ── Background RX drain thread ──
        let drain_handle = Arc::clone(&self.handle);
        let drain_ep = self.ep_in;
        let drain_running = Arc::new(AtomicBool::new(true));
        let drain_flag = Arc::clone(&drain_running);
        let drain_thread = thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            let mut total = 0usize;
            let mut errors = 0u32;
            while drain_flag.load(Ordering::Relaxed) {
                match drain_handle.read_bulk(drain_ep, &mut buf, Duration::from_millis(1)) {
                    Ok(n) if n > 0 => { total += n; }
                    Err(_) => { errors += 1; }
                    _ => {}
                }
            }
            eprintln!("  [drain] stopped: {} bytes drained, {} timeouts", total, errors);
        });

        // ── Phase 0: Replay INIT segment (power on, DMAC, FWDL, H2C) ──
        self.replay_pcap_init()?;
        let t_init = t0.elapsed();
        eprintln!("  [init] phase 0 done in {:.1}s", t_init.as_secs_f64());

        // ── Phase 1: Replay MONITOR MODE segment ──
        self.replay_pcap_monitor()?;
        let t_mon = t0.elapsed();
        eprintln!("  [init] phase 1 (monitor) done in {:.1}s", t_mon.as_secs_f64());

        // ── Stop background drain ──
        drain_running.store(false, Ordering::Relaxed);
        let _ = drain_thread.join();

        // ── Clear EP5 halt — might be stale from pcap replay ──
        let _ = self.handle.clear_halt(self.ep_out);

        // ── Read MAC ──
        self.read_mac_address()?;

        // ── TX enable ──
        self.send_sch_tx_en(0xFFFF)?;
        self.write16(0xC348, 0xFFFF)?;
        let sys_cfg5 = self.read32(0x0170).unwrap_or(0);
        if sys_cfg5 & 0x03 != 0x03 {
            self.write32(0x0170, sys_cfg5 | 0x03)?;
        }

        // ── Max TX power ──
        self.set_tx_power(31)?;

        eprintln!("  [init] total: {:.1}s", t0.elapsed().as_secs_f64());

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Pcap segment replay — generic engine used by init, monitor, channel switch
    // ══════════════════════════════════════════════════════════════════════════

    /// Pcap file path and device filter for all segment replays.
    const PCAP_PATH: &'static str = "references/captures/rtl8852bu_full_20260407/full_capture.pcap";
    const TARGET_BUS: u8 = 1;
    const TARGET_DEV: u8 = 5;

    /// Phase boundary timestamps (from phases.log, epoch seconds).
    /// Each segment is [start, end) — operations at start are included, at end are not.
    const TS_INIT_START: f64       = 0.0;             // beginning of pcap
    const TS_MONITOR_START: f64    = 1775596262.803;  // MONITOR_START
    const TS_MONITOR_DONE: f64     = 1775596264.414;  // MONITOR_DONE
    const TS_FULL_CHBW_START: f64  = 1775596332.848;  // FULL_CHBW_START
    const TS_FULL_CHBW_DONE: f64   = 1775596365.585;  // FULL_CHBW_DONE

    /// Replay a time-bounded segment of the pcap capture.
    /// Replays ALL operations (register reads, writes, EP7 bulk) verbatim.
    /// Returns (reg_writes, reg_reads, ep7_sent, ep7_fail).
    fn replay_pcap_segment(&self, ts_start: f64, ts_end: f64, label: &str) -> Result<(u32, u32, u32, u32)> {
        let pcap_data = fs::read(Self::PCAP_PATH).map_err(|e| Error::ChipInitFailed {
            chip: "RTL8852BU".into(),
            stage: crate::core::error::InitStage::HardwareSetup,
            reason: format!("pcap read: {}", e),
        })?;

        let mut offset = 24; // skip pcap global header
        let mut reg_writes = 0u32;
        let mut reg_reads = 0u32;
        let mut ep7_sent = 0u32;
        let mut ep7_fail = 0u32;
        let started = ts_start == 0.0; // if start is 0, begin immediately
        let mut in_range = started;

        while offset + 16 <= pcap_data.len() {
            // Parse pcap packet header
            let ts_sec = u32::from_le_bytes([
                pcap_data[offset], pcap_data[offset + 1],
                pcap_data[offset + 2], pcap_data[offset + 3],
            ]) as f64;
            let ts_usec = u32::from_le_bytes([
                pcap_data[offset + 4], pcap_data[offset + 5],
                pcap_data[offset + 6], pcap_data[offset + 7],
            ]) as f64;
            let ts = ts_sec + ts_usec / 1_000_000.0;

            let incl_len = u32::from_le_bytes([
                pcap_data[offset + 8], pcap_data[offset + 9],
                pcap_data[offset + 10], pcap_data[offset + 11],
            ]) as usize;
            offset += 16;

            // Stop if we've passed the end boundary
            if ts >= ts_end {
                break;
            }

            if offset + incl_len > pcap_data.len() || incl_len < 64 {
                offset += incl_len;
                continue;
            }

            let pkt = &pcap_data[offset..offset + incl_len];
            offset += incl_len;

            // Enter range once we reach start timestamp
            if !in_range {
                if ts >= ts_start {
                    in_range = true;
                } else {
                    continue;
                }
            }

            let pkt_type = pkt[8];
            let xfer_type = pkt[9];
            let ep = pkt[10];
            let devnum = pkt[11];
            let busnum = u16::from_le_bytes([pkt[12], pkt[13]]);
            let ep_num = ep & 0x7F;
            let ep_dir_in = ep & 0x80 != 0;
            let payload = &pkt[64..];

            if busnum != Self::TARGET_BUS as u16 || devnum != Self::TARGET_DEV || pkt_type != 0x53 {
                continue;
            }

            // ── Register WRITE ──
            if xfer_type == 2 && !ep_dir_in && !payload.is_empty() {
                let setup = &pkt[40..48];
                let (bm_req_type, b_req) = (setup[0], setup[1]);
                let w_val = u16::from_le_bytes([setup[2], setup[3]]);
                let w_idx = u16::from_le_bytes([setup[4], setup[5]]);
                let w_len = u16::from_le_bytes([setup[6], setup[7]]);

                if b_req == 0x05 && bm_req_type == 0x40 {
                    let write_data = &payload[..std::cmp::min(w_len as usize, payload.len())];
                    let addr = (w_idx as u32) << 16 | w_val as u32;

                    // Detect WCPU enable — firmware is booting, EP7 needs halt clearing
                    if addr == 0x0088 && !write_data.is_empty() && (write_data[0] & 0x02) != 0 {
                        let _ = self.handle.write_control(0x40, 0x05, w_val, w_idx, write_data, USB_BULK_TIMEOUT);
                        reg_writes += 1;

                        // Wait for firmware ready
                        for _ in 0..2000 {
                            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
                            let fwdl_sts = (ctrl >> B_AX_FWDL_STS_SH) & B_AX_FWDL_STS_MSK;
                            if fwdl_sts == FWDL_WCPU_FW_INIT_RDY {
                                break;
                            }
                            if ctrl & B_AX_H2C_PATH_RDY != 0 {
                                break;
                            }
                            thread::sleep(Duration::from_millis(1));
                        }
                        // Clear EP7 halt — firmware boot resets endpoint state
                        let _ = self.handle.clear_halt(self.ep_fw);
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }

                    let _ = self.handle.write_control(0x40, 0x05, w_val, w_idx, write_data, USB_BULK_TIMEOUT);
                    reg_writes += 1;
                }
            }
            // ── Register READ ──
            else if xfer_type == 2 && ep_dir_in {
                let setup = &pkt[40..48];
                let (bm_req_type, b_req) = (setup[0], setup[1]);
                let w_val = u16::from_le_bytes([setup[2], setup[3]]);
                let w_idx = u16::from_le_bytes([setup[4], setup[5]]);
                let w_len = u16::from_le_bytes([setup[6], setup[7]]);

                if b_req == 0x05 && bm_req_type == 0xC0 {
                    let mut buf = vec![0u8; w_len as usize];
                    let _ = self.handle.read_control(0xC0, 0x05, w_val, w_idx, &mut buf, USB_BULK_TIMEOUT);
                    reg_reads += 1;
                }
            }
            // ── EP7 bulk OUT (firmware + H2C) ──
            else if xfer_type == 3 && !ep_dir_in && ep_num == 7 && !payload.is_empty() {
                let is_fwdl = if payload.len() >= 4 {
                    let dw0 = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    dw0 & AX_TXD_FWDL_EN != 0
                } else {
                    false
                };

                if !is_fwdl {
                    // Post-FWDL H2C: replay verbatim
                    match self.handle.write_bulk(self.ep_fw, payload, Duration::from_secs(2)) {
                        Ok(_) => { ep7_sent += 1; }
                        Err(_) => {
                            ep7_fail += 1;
                            let _ = self.handle.clear_halt(self.ep_fw);
                        }
                    }
                    continue;
                }

                // FWDL chunk — replay verbatim
                let result = match self.handle.write_bulk(self.ep_fw, payload, Duration::from_secs(2)) {
                    Ok(_) => Ok(()),
                    Err(_) => {
                        let _ = self.handle.clear_halt(self.ep_fw);
                        thread::sleep(Duration::from_millis(50));
                        self.handle.write_bulk(self.ep_fw, payload, Duration::from_secs(2)).map(|_| ())
                    }
                };
                match result {
                    Ok(()) => ep7_sent += 1,
                    Err(_) => {
                        ep7_fail += 1;
                        let _ = self.handle.clear_halt(self.ep_fw);
                    }
                }
            }
        }

        eprintln!("  [{}] {} reg writes, {} reg reads, {} EP7 sent, {} EP7 fail",
            label, reg_writes, reg_reads, ep7_sent, ep7_fail);

        Ok((reg_writes, reg_reads, ep7_sent, ep7_fail))
    }

    /// Replay INIT segment: power on, DMAC, firmware download, post-FWDL H2C.
    fn replay_pcap_init(&self) -> Result<(u32, u32, u32, u32)> {
        self.replay_pcap_segment(Self::TS_INIT_START, Self::TS_MONITOR_START, "init")
    }

    /// Replay MONITOR MODE segment: sets up promiscuous monitor mode.
    fn replay_pcap_monitor(&self) -> Result<(u32, u32, u32, u32)> {
        self.replay_pcap_segment(Self::TS_MONITOR_START, Self::TS_MONITOR_DONE, "monitor")
    }

    /// Channel+BW pcap segments from FULL_CHBW capture.
    /// Each entry: (channel, bw, ts_start, ts_end)
    /// BW: 0=HT20, 1=HT40+, 2=HT40-, 3=VHT80
    const CHBW_SEGMENTS: &'static [(u8, u8, f64, f64)] = &[
        (  1, 0, 1775596332.908864395, 1775596333.170284271),
        (  1, 1, 1775596333.170284184, 1775596333.373017311),
        (  2, 0, 1775596333.632770713, 1775596333.894255400),
        (  2, 1, 1775596333.894255502, 1775596334.096474171),
        (  3, 0, 1775596334.358960376, 1775596334.617320538),
        (  3, 1, 1775596334.617320483, 1775596334.820274115),
        (  4, 0, 1775596335.085452874, 1775596335.353895903),
        (  4, 1, 1775596335.353895822, 1775596335.556023836),
        (  5, 0, 1775596335.819600075, 1775596336.082224131),
        (  5, 1, 1775596336.082224078, 1775596336.349431038),
        (  5, 2, 1775596336.349430937, 1775596336.615684509),
        (  6, 0, 1775596336.615684458, 1775596336.881898880),
        (  6, 1, 1775596336.881898811, 1775596337.141617775),
        (  6, 2, 1775596337.141617717, 1775596337.408353567),
        (  7, 0, 1775596337.408353490, 1775596337.674333334),
        (  7, 1, 1775596337.674333259, 1775596337.937716484),
        (  7, 2, 1775596337.937716516, 1775596338.204191685),
        (  8, 0, 1775596338.204191704, 1775596338.406512022),
        (  8, 2, 1775596338.667822406, 1775596338.932904720),
        (  9, 0, 1775596338.932904796, 1775596339.136530399),
        (  9, 2, 1775596339.402302818, 1775596339.665889263),
        ( 10, 0, 1775596339.665889284, 1775596339.869635105),
        ( 10, 2, 1775596340.136416436, 1775596340.404635668),
        ( 11, 0, 1775596340.404635675, 1775596340.608325958),
        ( 11, 2, 1775596340.872214313, 1775596341.148038149),
        ( 36, 0, 1775596341.148038089, 1775596341.407796860),
        ( 36, 1, 1775596341.407796828, 1775596341.610356092),
        ( 36, 3, 1775596341.875606883, 1775596342.137137175),
        ( 40, 0, 1775596342.137137172, 1775596342.399474859),
        ( 40, 1, 1775596342.399474757, 1775596342.661221743),
        ( 40, 2, 1775596342.661221839, 1775596342.921890974),
        ( 40, 3, 1775596342.921890999, 1775596343.183625221),
        ( 44, 0, 1775596343.183625331, 1775596343.445971012),
        ( 44, 1, 1775596343.445971040, 1775596343.703505516),
        ( 44, 2, 1775596343.703505601, 1775596343.967738628),
        ( 44, 3, 1775596343.967738570, 1775596344.230040312),
        ( 48, 0, 1775596344.230040197, 1775596344.494866848),
        ( 48, 1, 1775596344.494866877, 1775596344.760896206),
        ( 48, 2, 1775596344.760896313, 1775596345.019484520),
        ( 48, 3, 1775596345.019484463, 1775596345.279819489),
        ( 52, 0, 1775596345.279819371, 1775596345.543138504),
        ( 52, 1, 1775596345.543138502, 1775596345.801921129),
        ( 52, 2, 1775596345.801921028, 1775596346.061734915),
        ( 52, 3, 1775596346.061734808, 1775596346.322884560),
        ( 56, 0, 1775596346.322884595, 1775596346.587063789),
        ( 56, 1, 1775596346.587063856, 1775596346.851374149),
        ( 56, 2, 1775596346.851374075, 1775596347.112600803),
        ( 56, 3, 1775596347.112600696, 1775596347.370870590),
        ( 60, 0, 1775596347.370870552, 1775596347.629253626),
        ( 60, 1, 1775596347.629253534, 1775596347.893676281),
        ( 60, 2, 1775596347.893676171, 1775596348.158324957),
        ( 60, 3, 1775596348.158325059, 1775596348.417471170),
        ( 64, 0, 1775596348.417471128, 1775596348.619863510),
        ( 64, 2, 1775596348.882854213, 1775596349.145229340),
        ( 64, 3, 1775596349.145229298, 1775596349.404724836),
        (100, 0, 1775596349.404724827, 1775596349.666203499),
        (100, 1, 1775596349.666203574, 1775596349.868188620),
        (100, 3, 1775596350.128576937, 1775596350.393667698),
        (104, 0, 1775596350.393667785, 1775596350.651686668),
        (104, 1, 1775596350.651686682, 1775596350.917639732),
        (104, 2, 1775596350.917639659, 1775596351.179428339),
        (104, 3, 1775596351.179428325, 1775596351.441644192),
        (108, 0, 1775596351.441644284, 1775596351.700927973),
        (108, 1, 1775596351.700927978, 1775596351.964344263),
        (108, 2, 1775596351.964344193, 1775596352.226789236),
        (108, 3, 1775596352.226789237, 1775596352.483227968),
        (112, 0, 1775596352.483228001, 1775596352.741564512),
        (112, 1, 1775596352.741564399, 1775596353.000677824),
        (112, 2, 1775596353.000677885, 1775596353.259730339),
        (112, 3, 1775596353.259730328, 1775596353.519711733),
        (116, 0, 1775596353.519711818, 1775596353.778317690),
        (116, 1, 1775596353.778317634, 1775596354.041471481),
        (116, 2, 1775596354.041471390, 1775596354.299799204),
        (116, 3, 1775596354.299799121, 1775596354.557022810),
        (120, 0, 1775596354.557022722, 1775596354.818121910),
        (120, 1, 1775596354.818121884, 1775596355.080141068),
        (120, 2, 1775596355.080141051, 1775596355.339298725),
        (120, 3, 1775596355.339298828, 1775596355.598870039),
        (124, 0, 1775596355.598870108, 1775596355.859756708),
        (124, 1, 1775596355.859756810, 1775596356.120433569),
        (124, 2, 1775596356.120433678, 1775596356.379244089),
        (124, 3, 1775596356.379244162, 1775596356.642272711),
        (128, 0, 1775596356.642272709, 1775596356.905343056),
        (128, 1, 1775596356.905343047, 1775596357.165963888),
        (128, 2, 1775596357.165963832, 1775596357.429456472),
        (128, 3, 1775596357.429456547, 1775596357.689899206),
        (132, 0, 1775596357.689899247, 1775596357.955262423),
        (132, 1, 1775596357.955262389, 1775596358.217630148),
        (132, 2, 1775596358.217630265, 1775596358.421857595),
        (136, 0, 1775596358.682160388, 1775596358.945321321),
        (136, 1, 1775596358.945321394, 1775596359.204892159),
        (136, 2, 1775596359.204892090, 1775596359.407061100),
        (140, 0, 1775596359.673602692, 1775596359.875567675),
        (140, 2, 1775596360.135995762, 1775596360.338492632),
        (149, 0, 1775596360.598673710, 1775596360.860758543),
        (149, 1, 1775596360.860758501, 1775596361.063368082),
        (149, 3, 1775596361.321201521, 1775596361.581191063),
        (153, 0, 1775596361.581190969, 1775596361.837470293),
        (153, 1, 1775596361.837470316, 1775596362.100519896),
        (153, 2, 1775596362.100519904, 1775596362.361242294),
        (153, 3, 1775596362.361242314, 1775596362.620100260),
        (157, 0, 1775596362.620100270, 1775596362.877603769),
        (157, 1, 1775596362.877603771, 1775596363.136083603),
        (157, 2, 1775596363.136083610, 1775596363.395873070),
        (157, 3, 1775596363.395873081, 1775596363.657723904),
        (161, 0, 1775596363.657723852, 1775596363.920693159),
        (161, 1, 1775596363.920693254, 1775596364.185900927),
        (161, 2, 1775596364.185900833, 1775596364.452159405),
        (161, 3, 1775596364.452159292, 1775596364.712657213),
        (165, 0, 1775596364.712657182, 1775596364.918462038),
        (165, 2, 1775596365.176805737, 1775596365.383174181),
    ];

    /// Switch channel by replaying the corresponding pcap segment.
    /// bw: 0=HT20, 1=HT40+, 2=HT40-, 3=VHT80
    pub fn set_channel_pcap(&mut self, ch: u8, bw: u8) -> Result<()> {
        let seg = Self::CHBW_SEGMENTS.iter()
            .find(|(c, b, _, _)| *c == ch && *b == bw)
            .ok_or_else(|| Error::UnsupportedChannel {
                channel: ch,
                chip: format!("RTL8852BU (no pcap for ch{} bw{})", ch, bw),
            })?;

        let label = format!("ch{}bw{}", ch, bw);
        self.replay_pcap_segment(seg.2, seg.3, &label)?;
        self.channel.store(ch, Ordering::Relaxed);
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  RX frame reception (stub — needs init verification first)
    // ══════════════════════════════════════════════════════════════════════════

    fn recv_frame_internal(&mut self, timeout: Duration) -> Result<Option<RxFrame>> {
        // Stub: basic USB bulk read, no PPDU correlation yet.
        // The 8852B uses the same RX descriptor format as 8852A.
        // Full parsing will be ported once init is verified.
        let actual = match self.handle.read_bulk(self.ep_in, &mut self.rx_buf, timeout) {
            Ok(n) => n,
            Err(rusb::Error::Timeout) => return Ok(None),
            Err(e) => return Err(Error::Usb(e)),
        };

        if actual < RX_DESC_SHORT {
            return Ok(None);
        }

        // Parse DW0 for basic frame extraction
        let dw0 = u32::from_le_bytes([
            self.rx_buf[0], self.rx_buf[1], self.rx_buf[2], self.rx_buf[3],
        ]);
        let pkt_len = (dw0 & 0x3FFF) as usize;
        let shift = ((dw0 >> 14) & 0x3) as usize;
        let rpkt_type = ((dw0 >> 24) & 0xF) as u8;
        let drv_info_size = ((dw0 >> 28) & 0x7) as usize;
        let long_rxd = (dw0 >> 31) & 1 != 0;

        let desc_len = if long_rxd { RX_DESC_LONG } else { RX_DESC_SHORT };
        let payload_offset = desc_len + (drv_info_size * 8) + (shift * 2);

        // Only extract WiFi frames (rpkt_type=0)
        if rpkt_type != 0 || pkt_len == 0 {
            return Ok(None);
        }

        let mac_info_vld = (dw0 >> 23) & 1 != 0;
        let extra = if mac_info_vld { 4 } else { 0 };
        let data_start = payload_offset + extra;
        let frame_len = if pkt_len >= 4 + extra { pkt_len - 4 - extra } else { 0 };

        if frame_len == 0 || data_start + frame_len > actual {
            return Ok(None);
        }

        let ch = self.channel.load(Ordering::Relaxed);
        let frame = RxFrame {
            data: self.rx_buf[data_start..data_start + frame_len].to_vec(),
            channel: ch,
            band: if ch <= 14 { 0 } else { 1 },
            ..Default::default()
        };

        Ok(Some(frame))
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  TX frame injection (MAC AX WD format — same as 8852AU)
    // ══════════════════════════════════════════════════════════════════════════

    fn inject_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()> {
        if frame.len() < 10 {
            return Err(Error::TxFailed { retries: 0, reason: "frame too short".into() });
        }

        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        let frame_type = (fc >> 2) & 0x3;
        let is_multicast = frame[4] & 0x01 != 0;

        let mac_hdr_len: u32 = match frame_type {
            0 => 24,
            1 => 10,
            2 => if fc & (1 << 8) != 0 && fc & (1 << 9) != 0 { 30 } else { 24 },
            _ => 24,
        };

        let (dma_ch, qsel) = (MAC_AX_DMA_B0MG, MAC_AX_MG0_SEL);
        let hw_rate = ax_rate_to_hw(&opts.rate) as u32;
        let bw = (opts.bw as u32).min(2);

        let total_len = TX_WD_TOTAL_LEN + frame.len();
        let mut buf = vec![0u8; total_len];

        // WD_BODY DW0
        let dw0: u32 = AX_TXD_STF_MODE
            | ((mac_hdr_len & 0x1F) << AX_TXD_HDR_LLC_LEN_SH)
            | (dma_ch << AX_TXD_CH_DMA_SH)
            | AX_TXD_WDINFO_EN;
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());

        // WD_BODY DW2
        let dw2: u32 = (frame.len() as u32 & 0x3FFF)
            | ((qsel & 0x3F) << AX_TXD_QSEL_SH);
        buf[8..12].copy_from_slice(&dw2.to_le_bytes());

        // WD_BODY DW3
        if frame.len() >= 24 {
            let seq_ctrl = u16::from_le_bytes([frame[22], frame[23]]);
            let seq_num = (seq_ctrl >> 4) & 0x0FFF;
            let dw3: u32 = AX_TXD_BK | ((seq_num as u32) << AX_TXD_WIFI_SEQ_SH);
            buf[12..16].copy_from_slice(&dw3.to_le_bytes());
        }

        // WD_INFO DW0
        let mut info_dw0: u32 = AX_TXD_USERATE_SEL
            | ((hw_rate & 0x1FF) << AX_TXD_DATARATE_SH)
            | ((bw & 0x3) << AX_TXD_DATA_BW_SH)
            | (((opts.gi as u32) & 0x7) << AX_TXD_GI_LTF_SH);
        if opts.flags.contains(TxFlags::STBC)   { info_dw0 |= AX_TXD_DATA_STBC; }
        if opts.flags.contains(TxFlags::LDPC)   { info_dw0 |= AX_TXD_DATA_LDPC; }
        if opts.flags.contains(TxFlags::NO_RETRY) { info_dw0 |= AX_TXD_DISDATAFB; }
        buf[24..28].copy_from_slice(&info_dw0.to_le_bytes());

        // WD_INFO DW1
        let mut info_dw1: u32 = 0;
        if is_multicast { info_dw1 |= AX_TXD_BMC; }
        if opts.retries > 0 && !opts.flags.contains(TxFlags::NO_RETRY) {
            let retry_count = (opts.retries as u32).clamp(1, 63);
            info_dw1 |= AX_TXD_DATA_TXCNT_LMT_SEL
                | ((retry_count & 0x3F) << AX_TXD_DATA_TXCNT_LMT_SH);
        }
        buf[28..32].copy_from_slice(&info_dw1.to_le_bytes());

        // WD_INFO DW3 (SPE_RPT for TX status reports)
        let mut info_dw3: u32 = AX_TXD_SPE_RPT;
        if opts.ndpa != 0 {
            info_dw3 |= ((opts.ndpa as u32 & 0x3) << 1)
                      | ((opts.snd_pkt_sel as u32 & 0x7) << 3);
        }
        if opts.flags.contains(TxFlags::SIFS_TX) {
            info_dw3 |= 1 << 6;
        }
        buf[36..40].copy_from_slice(&info_dw3.to_le_bytes());

        // WD_INFO DW5 (NDPA duration)
        if opts.ndpa_duration_us > 0 {
            let info_dw5: u32 = (opts.ndpa_duration_us as u32) << 16;
            buf[44..48].copy_from_slice(&info_dw5.to_le_bytes());
        }

        // WD_INFO DW4 (RTS/CTS protection)
        if opts.flags.contains(TxFlags::PROTECT) {
            let info_dw4: u32 = AX_TXD_RTS_EN;
            buf[40..44].copy_from_slice(&info_dw4.to_le_bytes());
        }

        // 802.11 frame payload
        buf[TX_WD_TOTAL_LEN..].copy_from_slice(frame);

        // Send via USB bulk OUT EP5
        for retry in 0..opts.retries.max(1) {
            match self.handle.write_bulk(self.ep_out, &buf, USB_BULK_TIMEOUT) {
                Ok(_) => return Ok(()),
                Err(e) if retry < opts.retries.saturating_sub(1) => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => return Err(Error::TxFailed {
                    retries: opts.retries,
                    reason: format!("bulk OUT EP 0x{:02X}: {}", self.ep_out, e),
                }),
            }
        }

        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ChipDriver trait implementation
// ══════════════════════════════════════════════════════════════════════════════

impl ChipDriver for Rtl8852bu {
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
            name: "RTL8852BU",
            chip: ChipId::Rtl8852bu,
            caps: RTL8852BU_CAPS,
            vid: self.vid,
            pid: self.pid,
            rfe_type: 0,
            bands: vec![Band::Band2g, Band::Band5g],
            max_tx_power_dbm: 31,
            firmware_version: self.fw_version.clone(),
        }
    }

    fn set_channel(&mut self, channel: Channel) -> Result<()> {
        // Replay the matching pcap segment with full BB/PHY calibration.
        // Default to HT20 bandwidth.
        self.set_channel_pcap(channel.number, 0)
    }

    fn supported_channels(&self) -> &[Channel] {
        &self.channels
    }

    fn set_monitor_mode(&mut self) -> Result<()> {
        // Monitor mode is configured by init's pcap replay (RX_FLTR = 0x031644BF).
        self.write32(R_AX_RXAGG_0, 0x80202020)?;
        self.write32(R_AX_RXDMA_SETTING, 0x00046F00)?;
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
        self.send_addr_cam(&mac.0)?;
        Ok(())
    }

    fn tx_power(&self) -> i8 {
        self.tx_power_dbm
    }

    fn set_tx_power(&mut self, dbm: i8) -> Result<()> {
        let dbm = dbm.clamp(0, 31);
        let idx = (dbm as u8) * 2;

        let hi = idx;
        let mid = (idx as u16 * 85 / 100).min(0x3E) as u8;
        let lo = (idx as u16 * 70 / 100).min(0x3E) as u8;
        let vlo = (idx as u16 * 60 / 100).min(0x3E) as u8;

        let p4 = |v: u8| u32::from_le_bytes([v, v, v, v]);

        self.write32(0xD2C0, p4(hi))?;
        self.write32(0xD2C4, p4(hi))?;
        self.write32(0xD2C8, u32::from_le_bytes([mid, mid, hi, hi]))?;
        self.write32(0xD2CC, p4(hi))?;
        self.write32(0xD2D0, u32::from_le_bytes([lo, mid, mid, hi]))?;
        self.write32(0xD2D4, u32::from_le_bytes([vlo, vlo, lo, lo]))?;
        self.write32(0xD2D8, p4(hi))?;
        self.write32(0xD2DC, p4(hi))?;
        self.write32(0xD2E0, u32::from_le_bytes([lo, mid, mid, hi]))?;
        self.write32(0xD2E4, u32::from_le_bytes([vlo, vlo, lo, lo]))?;
        self.write32(0xD2E8, p4(hi))?;

        self.tx_power_dbm = dbm;
        Ok(())
    }

    fn calibrate(&mut self) -> Result<()> {
        Ok(())
    }

    fn channel_settle_time(&self) -> Duration {
        Duration::from_millis(10)
    }

    // RX pipeline stub — will be implemented after init verification
    fn start_rx_pipeline(
        &mut self,
        _gate: crate::pipeline::FrameGate,
        _alive: Arc<AtomicBool>,
        _tx_feedback: Arc<crate::core::chip::TxFeedback>,
    ) -> bool {
        false // fall back to take_rx_handle / rx_frame polling
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
        assert!(channels.len() >= 38);
        assert_eq!(channels[0].number, 1);
        assert_eq!(channels[0].center_freq_mhz, 2412);
        assert_eq!(channels[0].band, Band::Band2g);
        let ch36 = channels.iter().find(|c| c.number == 36).unwrap();
        assert_eq!(ch36.center_freq_mhz, 5180);
        assert_eq!(ch36.band, Band::Band5g);
    }

    #[test]
    fn test_caps() {
        assert!(RTL8852BU_CAPS.contains(ChipCaps::HE));
        assert!(RTL8852BU_CAPS.contains(ChipCaps::MONITOR));
        assert!(RTL8852BU_CAPS.contains(ChipCaps::INJECT));
        assert!(RTL8852BU_CAPS.contains(ChipCaps::BW80));
        assert!(!RTL8852BU_CAPS.contains(ChipCaps::BW160));
    }

    #[test]
    fn test_fw_wd_format() {
        let wd_dw0 = (MAC_AX_DMA_H2C << AX_TXD_CH_DMA_SH) | AX_TXD_FWDL_EN;
        assert_eq!(wd_dw0, 0x001C0000);
    }
}
