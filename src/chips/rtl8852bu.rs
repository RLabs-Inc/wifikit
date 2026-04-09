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
//! # Channel Switching
//!
//!   Pre-extracted register sequences from monitor-mode usbmon capture.
//!   111 channel+bandwidth combos (HT20/HT40+/HT40-/VHT80) as direct
//!   write32/read32 calls — zero pcap parsing at runtime.
//!   See rtl8852b_channel_switch.rs.
//!
//! # What's NOT Implemented
//!
//!   - TX power calibration from EFUSE
//!   - 160 MHz bandwidth

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

    fn dump_rx_regs(&self, label: &str) {
        use std::io::Write;
        let mut f = match std::fs::OpenOptions::new()
            .create(true).append(true)
            .open("/tmp/wifikit_8852bu_rx_stats.log") {
            Ok(f) => f,
            Err(_) => return,
        };
        let _ = writeln!(f, "\n=== REG DUMP: {} ===", label);
        for &(addr, name) in &[
            (0x8900u16, "RXAGG_0"), (0x8904, "RXAGG_1"), (0x8908, "RXDMA_SETTING"),
            (0x8380, "HCI_FUNC_EN"), (0x8400, "DMAC_FUNC_EN"), (0x8404, "DMAC_CLK_EN"),
            (0xC000, "CMAC_FUNC_EN"), (0xC004, "CMAC_CLK_EN"),
            (0xCE20, "RX_FLTR_OPT"), (0xCE24, "CTRL_FLTR"), (0xCE28, "MGNT_FLTR"), (0xCE2C, "DATA_FLTR"),
            (0x1060, "USB_EP_0"), (0x106C, "USB_EP_3"), (0x1078, "USB_HOST_REQ_2"), (0x1174, "USB_WLAN0_1"),
            (0x01E0, "WCPU_FW_CTRL"), (0x0088, "PLATFORM_EN"),
        ] {
            match self.read32(addr) {
                Ok(v) => { let _ = writeln!(f, "  0x{:04X} ({:16}) = 0x{:08X}", addr, name, v); }
                Err(_) => { let _ = writeln!(f, "  0x{:04X} ({:16}) = READ ERROR", addr, name); }
            }
        }
    }

    fn chip_init(&mut self) -> Result<()> {
        let t0 = std::time::Instant::now();

        // ── Phase -1: Clean up dirty firmware state (EXACT AU pattern) ──
        let fw_ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
        eprintln!("  [init] FW_CTRL=0x{:02X}", fw_ctrl);
        if fw_ctrl != 0 {
            self.disable_cpu()?;
            self.power_off()?;
            thread::sleep(Duration::from_millis(50));
        }

        // ── Background RX drain thread (EXACT AU pattern: 1ms timeout) ──
        let drain_handle = Arc::clone(&self.handle);
        let drain_ep = self.ep_in;
        let drain_running = Arc::new(AtomicBool::new(true));
        let drain_flag = Arc::clone(&drain_running);
        let drain_thread = thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            let mut total = 0usize;
            while drain_flag.load(Ordering::Relaxed) {
                if let Ok(n) = drain_handle.read_bulk(drain_ep, &mut buf, Duration::from_millis(1)) {
                    if n > 0 {
                        total += n;
                        let hex: String = buf[..std::cmp::min(n, 32)].iter()
                            .map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        eprintln!("  [drain] {} bytes [{}{}]", n, hex, if n > 32 { "..." } else { "" });
                    }
                }
            }
            eprintln!("  [drain] stopped: {} bytes total", total);
        });

        eprintln!("  [init] starting pcap replay...");
        // ── Phase 0: Replay INIT segment (power on, DMAC, FWDL, H2C) ──
        self.replay_pcap_init()?;
        let t_init = t0.elapsed();
        eprintln!("  [init] phase 0 done in {:.1}s", t_init.as_secs_f64());
        self.dump_rx_regs("after init (phase 0)");

        // ── Phase 1: Replay MONITOR MODE segment ──
        self.replay_pcap_monitor()?;
        let t_mon = t0.elapsed();
        eprintln!("  [init] phase 1 (monitor) done in {:.1}s", t_mon.as_secs_f64());
        self.dump_rx_regs("after monitor (phase 1)");

        // Stop background drain
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

    /// Pcap file paths for init/monitor replay (segmented monitor-mode captures).
    const PCAP_INIT: &'static str = "references/rtl8852bu_monitor_20260407/01_device_init.pcap";
    const PCAP_MONITOR: &'static str = "references/rtl8852bu_monitor_20260407/02_monitor_setup.pcap";
    const TARGET_BUS: u8 = 3;
    const TARGET_DEV: u8 = 5;

    /// Replay entire pcap file (no timestamp filtering needed — each file is one phase).
    const TS_ALL_START: f64 = 0.0;
    const TS_ALL_END: f64 = f64::MAX;

    /// Replay a pcap file (or time-bounded segment) verbatim.
    /// Handles rtw89 multi-section FWDL: WCPU enable writes just get a brief pause
    /// and EP7 halt clear. Full firmware-ready polling happens once when transitioning
    /// from FWDL chunks to H2C commands.
    /// Returns (reg_writes, reg_reads, ep7_sent, ep7_fail).
    fn replay_pcap_segment(&self, pcap_path: &str, ts_start: f64, ts_end: f64, label: &str) -> Result<(u32, u32, u32, u32)> {
        let pcap_data = fs::read(pcap_path).map_err(|e| Error::ChipInitFailed {
            chip: "RTL8852BU".into(),
            stage: crate::core::error::InitStage::HardwareSetup,
            reason: format!("pcap read: {}", e),
        })?;

        let mut offset = 24; // skip pcap global header
        let mut reg_writes = 0u32;
        let mut reg_reads = 0u32;
        let mut ep7_sent = 0u32;
        let mut ep7_fail = 0u32;
        let started = ts_start == 0.0;
        let mut in_range = started;
        // Pure verbatim replay — exact AU pattern

        while offset + 16 <= pcap_data.len() {
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

            if ts >= ts_end {
                break;
            }

            if offset + incl_len > pcap_data.len() || incl_len < 64 {
                offset += incl_len;
                continue;
            }

            let pkt = &pcap_data[offset..offset + incl_len];
            offset += incl_len;

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

                    // WCPU enable — EXACT AU pattern: write, poll FW ready, clear halt, 50ms
                    if addr == 0x0088 && !write_data.is_empty() && (write_data[0] & 0x02) != 0 {
                        let _ = self.handle.write_control(0x40, 0x05, w_val, w_idx, write_data, USB_BULK_TIMEOUT);
                        reg_writes += 1;
                        for _ in 0..2000 {
                            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
                            let fwdl_sts = (ctrl >> B_AX_FWDL_STS_SH) & B_AX_FWDL_STS_MSK;
                            if fwdl_sts == FWDL_WCPU_FW_INIT_RDY { break; }
                            if ctrl & B_AX_H2C_PATH_RDY != 0 { break; }
                            thread::sleep(Duration::from_millis(1));
                        }
                        let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
                        eprintln!("  [{}] WCPU enable (ctrl=0x{:02X})", label, ctrl);
                        let _ = self.handle.clear_halt(self.ep_fw);
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }

                    match self.handle.write_control(0x40, 0x05, w_val, w_idx, write_data, USB_BULK_TIMEOUT) {
                        Ok(_) => { reg_writes += 1; }
                        Err(e) => {
                            eprintln!("  [{}] REG WRITE FAIL @ 0x{:04X} ({} bytes): {}", label, addr, write_data.len(), e);
                            reg_writes += 1;
                        }
                    }
                    let total_ops = reg_writes + reg_reads + ep7_sent;
                    if total_ops % 500 == 0 {
                        eprintln!("  [{}] progress: {} writes, {} reads, {} EP7", label, reg_writes, reg_reads, ep7_sent);
                    }
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
                    match self.handle.read_control(0xC0, 0x05, w_val, w_idx, &mut buf, USB_BULK_TIMEOUT) {
                        Ok(_) => { reg_reads += 1; }
                        Err(e) => {
                            let addr = (w_idx as u32) << 16 | w_val as u32;
                            eprintln!("  [{}] REG READ FAIL @ 0x{:04X}: {}", label, addr, e);
                            reg_reads += 1;
                        }
                    }
                }
            }
            // ── EP7 bulk OUT (firmware + H2C) — EXACT AU pattern ──
            else if xfer_type == 3 && !ep_dir_in && ep_num == 7 && !payload.is_empty() {
                let is_fwdl = payload.len() >= 4 && (u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) & AX_TXD_FWDL_EN != 0);

                if !is_fwdl {
                    // H2C: replay verbatim
                    match self.handle.write_bulk(self.ep_fw, payload, Duration::from_secs(2)) {
                        Ok(_) => { ep7_sent += 1; }
                        Err(_) => {
                            ep7_fail += 1;
                            let _ = self.handle.clear_halt(self.ep_fw);
                        }
                    }
                    continue;
                }

                // FWDL: replay verbatim, retry with clear_halt + 50ms
                let result = match self.handle.write_bulk(self.ep_fw, payload, Duration::from_secs(2)) {
                    Ok(_) => Ok(()),
                    Err(_) => {
                        let _ = self.handle.clear_halt(self.ep_fw);
                        thread::sleep(Duration::from_millis(50));
                        self.handle.write_bulk(self.ep_fw, payload, Duration::from_secs(2)).map(|_| ())
                    }
                };
                match result {
                    Ok(()) => { ep7_sent += 1; }
                    Err(_) => {
                        ep7_fail += 1;
                        if ep7_fail <= 3 {
                            eprintln!("  [{}] EP7 fail #{} (sent={}, {} bytes)", label, ep7_fail, ep7_sent, payload.len());
                        }
                        let _ = self.handle.clear_halt(self.ep_fw);
                    }
                }
                if ep7_sent > 0 && ep7_sent % 50 == 0 {
                    eprintln!("  [{}] EP7 progress: {} sent, {} fail", label, ep7_sent, ep7_fail);
                }
            }
        }

        if label == "init" || label == "monitor" {
            eprintln!("  [{}] {} reg writes, {} reg reads, {} EP7 sent, {} EP7 fail",
                label, reg_writes, reg_reads, ep7_sent, ep7_fail);
        }

        Ok((reg_writes, reg_reads, ep7_sent, ep7_fail))
    }

    /// Replay INIT pcap: power on, DMAC, firmware download, post-FWDL H2C.
    fn replay_pcap_init(&self) -> Result<(u32, u32, u32, u32)> {
        self.replay_pcap_segment(Self::PCAP_INIT, Self::TS_ALL_START, Self::TS_ALL_END, "init")
    }

    /// Replay MONITOR MODE pcap: RX filters, CMAC, PHY setup.
    fn replay_pcap_monitor(&self) -> Result<(u32, u32, u32, u32)> {
        self.replay_pcap_segment(Self::PCAP_MONITOR, Self::TS_ALL_START, Self::TS_ALL_END, "monitor")
    }

    /// Switch channel using pre-extracted register sequences (no pcap parsing).
    /// bw: 0=HT20, 1=HT40+, 2=HT40-, 3=VHT80
    pub fn set_channel_pcap(&mut self, ch: u8, bw: u8) -> Result<()> {
        // Pre-extracted functions — direct register writes, zero file I/O
        self.pcap_channel_switch(ch, bw)?;
        self.channel.store(ch, Ordering::Relaxed);

        // Re-apply promiscuous RX filter — channel switch was captured in monitor mode
        // but the filter state may drift. Ensure we always receive all frame types.
        self.write32(0xCE20, 0x031644BF)?;  // RX_FLTR_OPT: promiscuous
        self.write32(0xCE24, 0x55555555)?;  // Frame type filter: accept all
        self.write32(0xCE28, 0x55555555)?;
        self.write32(0xCE2C, 0x55555555)?;

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
        let _ = self.handle.clear_halt(self.ep_in);
        // Promiscuous RX filter — accept all frame types for monitor mode
        self.write32(0xCE20, 0x031644BF)?;  // RX_FLTR_OPT: promiscuous sniffer
        self.write32(0xCE24, 0x55555555)?;  // Frame type filter: accept all
        self.write32(0xCE28, 0x55555555)?;
        self.write32(0xCE2C, 0x55555555)?;
        // Enable RX aggregation (Linux uses async URBs; we need aggregation for bulk reads)
        self.write32(R_AX_RXAGG_0, 0x80404040)?;
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

    fn start_rx_pipeline(
        &mut self,
        gate: crate::pipeline::FrameGate,
        alive: Arc<AtomicBool>,
        tx_feedback: Arc<crate::core::chip::TxFeedback>,
    ) -> bool {
        start_rx_pipeline_8852bu(
            Arc::clone(&self.handle),
            self.ep_in,
            Arc::clone(&self.channel),
            gate,
            alive,
            tx_feedback,
        );
        true
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  RX Pipeline — driver-managed stream parser
// ══════════════════════════════════════════════════════════════════════════════
//
//  Two threads:
//    [rx-usb-reader]    USB bulk IN → raw bytes → mpsc channel
//    [rx-stream-parser]  mpsc → parse MAC AX RX descriptors → FrameGate.submit()
//
//  Same architecture as 8852AU — the RX descriptor format is identical (MAC AX gen2).
//
// WiFi frames (rpkt_type=0) arrive with no embedded PHY status.
// RSSI/SNR/EVM/etc arrive in separate PPDU status packets (rpkt_type=1).
// Correlation is via ppdu_cnt (3-bit counter, 8 slots) in DW1[6:4].
//
// Flow:
//   1. WiFi frame → extract 802.11 data + RX descriptor metadata, park in slot[ppdu_cnt]
//   2. PPDU status → parse physts header + all IEs, match slot[ppdu_cnt], deliver complete frame
//   3. If slot is already occupied when new WiFi frame arrives → evict old frame (rssi=0)
//
// RX descriptor layout (from hal_trx_8852a.h):
//   Short RXD = 16 bytes (long_rxd=0): DW0-DW3
//   Long  RXD = 32 bytes (long_rxd=1): DW0-DW7
//
// All 11 rpkt_types are handled — nothing silently dropped.

use crate::core::frame::{RxBandwidth, GuardInterval, PpduType};

/// RX packet types (rpkt_type field, DW0[27:24])
const RPKT_WIFI: u8 = 0;
const RPKT_PPDU_STATUS: u8 = 1;
const RPKT_CHANNEL_INFO: u8 = 2;
const RPKT_BB_SCOPE: u8 = 3;
const RPKT_F2P_TX_CMD_RPT: u8 = 4;
const RPKT_SS2FW_RPT: u8 = 5;
const RPKT_TX_RPT: u8 = 6;
const RPKT_TX_PD_RELEASE_HOST: u8 = 7;
const RPKT_DFS_RPT: u8 = 8;
const RPKT_TX_PD_RELEASE_WLCPU: u8 = 9;
const RPKT_C2H: u8 = 10;

/// PPDU type (DW1[3:0])
const PPDU_T_LEGACY: u8 = 0;
const PPDU_T_HT: u8 = 1;
const PPDU_T_VHT: u8 = 2;
const PPDU_T_HE_SU: u8 = 3;
const PPDU_T_HE_ER_SU: u8 = 4;
const PPDU_T_HE_MU: u8 = 5;
const PPDU_T_HE_TB: u8 = 6;

/// PHY status header length (8 bytes)
const PHYSTS_HDR_LEN: usize = 8;

/// Maximum PPDU correlation slots (ppdu_cnt is 3 bits)
const PPDU_SLOT_COUNT: usize = 8;

/// IE fixed lengths in 8-byte units (0xFF = variable length)
const IE_LEN_TABLE: [u8; 32] = [
    2, 4, 3, 3, 1, 1, 1, 1,           // IE0-7
    0xFF, 1, 0xFF, 22, 0xFF, 0xFF, 0xFF, 0xFF, // IE8-15
    0xFF, 0xFF, 2, 3, 0xFF, 0xFF, 0xFF, 0,     // IE16-23
    3, 3, 3, 3, 4, 4, 4, 4,           // IE24-31
];

/// Pending WiFi frame stored in a correlation slot.
/// The frame data (Vec<u8>) is stored here because the USB buffer will be
/// overwritten by the next bulk read before the PPDU arrives.
struct PendingFrame {
    /// The 802.11 frame data (FCS already stripped).
    data: Vec<u8>,
    /// Current channel at time of receipt.
    channel: u8,
    /// Band index (0=2.4GHz, 1=5GHz).
    band: u8,
    /// RX data rate from DW1[24:16].
    data_rate: u16,
    /// PPDU type from DW1[3:0] — used to validate PPDU match.
    ppdu_type: u8,
    /// Bandwidth from DW1[31:30].
    bw: u8,
    /// GI/LTF from DW1[27:25].
    gi_ltf: u8,
    /// Freerun counter from DW2 (timestamp).
    freerun_cnt: u32,
    /// AMPDU flag from DW3.
    is_ampdu: bool,
    /// AMSDU flag from DW3.
    is_amsdu: bool,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl Default for PendingFrame {
    fn default() -> Self {
        Self {
            data: Vec::new(), channel: 0, band: 0,
            data_rate: 0, ppdu_type: 0, bw: 0, gi_ltf: 0,
            freerun_cnt: 0, is_ampdu: false, is_amsdu: false,
            occupied: false,
        }
    }
}

/// PHY status parsed from a PPDU status packet — all IEs.
#[derive(Default)]
struct PhyStatus {
    // --- Header ---
    rssi_avg: u8,       // U(8,1) — raw from physts header
    rssi_path: [u8; 4], // U(8,1) — raw per-path
    ie_bitmap_select: u8,

    // --- IE0 (CCK) ---
    ie0_present: bool,
    ie0_pop_idx: u8,
    ie0_rpl: u16,           // 9-bit received power level
    ie0_cca_time: u8,
    ie0_antwgt_gain_diff: u8,
    ie0_hw_antsw: [bool; 4],
    ie0_noise_pwr: u8,
    ie0_cfo: i16,           // 12-bit signed
    ie0_coarse_cfo: i16,    // 12-bit signed
    ie0_evm_hdr: u8,
    ie0_evm_pld: u8,
    ie0_sig_len: u16,
    ie0_antdiv_rslt: [bool; 4],
    ie0_preamble_type: u8,
    ie0_sync_mode: u8,
    ie0_dagc: [u8; 4],      // 5-bit each
    ie0_rx_path_en: u8,

    // --- IE1 (OFDM/HT/VHT/HE) ---
    ie1_present: bool,
    ie1_pop_idx: u8,
    ie1_rssi_avg_fd: u8,
    ie1_ch_idx: u8,
    ie1_rxsc: u8,
    ie1_rx_path_en: u8,
    ie1_noise_pwr: u8,
    ie1_cfo: i16,           // 12-bit signed
    ie1_cfo_preamble: i16,  // 12-bit signed
    ie1_snr: u8,            // 6-bit
    ie1_evm_max: u8,
    ie1_evm_min: u8,
    ie1_gi_type: u8,
    ie1_is_su: bool,
    ie1_is_ldpc: bool,
    ie1_is_ndp: bool,
    ie1_is_stbc: bool,
    ie1_grant_bt: bool,
    ie1_bf_gain_max: u8,
    ie1_is_awgn: bool,
    ie1_is_bf: bool,
    ie1_avg_cn: u8,
    ie1_sigval_below_th_cnt: u8,
    ie1_cn_excess_th_cnt: u8,
    ie1_pwr_to_cca: u16,
    ie1_cca_to_agc: u8,
    ie1_cca_to_sbd: u8,
    ie1_edcca_rpt_cnt: u8,
    ie1_edcca_total_smp_cnt: u8,
    ie1_edcca_bw_max: u8,
    ie1_edcca_bw_min: u8,
    ie1_bw_idx: u8,

    // --- IE2 (HE/AX extended) ---
    ie2_present: bool,
    ie2_max_nsts: u8,
    ie2_midamble: bool,
    ie2_ltf_type: u8,
    ie2_gi: u8,
    ie2_is_mu_mimo: bool,
    ie2_is_dl_ofdma: bool,
    ie2_is_dcm: bool,
    ie2_is_doppler: bool,
    ie2_pkt_extension: u8,
    ie2_coarse_cfo_i: i32,
    ie2_coarse_cfo_q: i32,
    ie2_fine_cfo_i: i32,
    ie2_fine_cfo_q: i32,
    ie2_est_cmped_phase: u8,
    ie2_n_ltf: u8,
    ie2_n_sym: u16,

    // --- IE4-7 (per-path) ---
    ie_path_present: [bool; 4],
    ie_path_sig_val: [u8; 4],
    ie_path_rf_gain_idx: [u8; 4],
    ie_path_tia_gain_idx: [u8; 4],
    ie_path_snr: [u8; 4],
    ie_path_evm: [u8; 4],
    ie_path_ant_weight: [u8; 4],
    ie_path_dc_re: [u8; 4],
    ie_path_dc_im: [u8; 4],
}

/// Thread-local PPDU correlation state.
/// Each thread (main driver + RxHandle) gets its own independent state.
struct PpduCorrelation {
    slots: [PendingFrame; PPDU_SLOT_COUNT],
    /// Completed frames ready for delivery (evicted from slots without PPDU match).
    completed: Vec<RxFrame>,
}

impl PpduCorrelation {
    fn new() -> Self {
        Self {
            slots: Default::default(),
            completed: Vec::new(),
        }
    }
}

/// Debug logger for RX packet parsing — writes to /tmp/wifikit_rx_parse_debug_8852bu.log
struct RxDebugLog {
    file: Option<std::fs::File>,
    count: u64,
    wifi_count: u64,
    ppdu_count: u64,
    match_count: u64,
    evict_count: u64,
    skip_count: u64,
}

impl RxDebugLog {
    fn new() -> Self {
        // Debug logging disabled for runtime performance.
        // To enable: uncomment the file open below.
        // let file = std::fs::OpenOptions::new()
        //     .create(true).write(true).truncate(true)
        //     .open("/tmp/wifikit_rx_parse_debug_8852bu.log").ok();
        Self { file: None, count: 0, wifi_count: 0, ppdu_count: 0, match_count: 0, evict_count: 0, skip_count: 0 }
    }

    fn log(&mut self, msg: &str) {
        use std::io::Write;
        if let Some(ref mut f) = self.file {
            let _ = writeln!(f, "{}", msg);
        }
    }

    fn log_summary(&mut self) {
        use std::io::Write;
        if let Some(ref mut f) = self.file {
            let _ = writeln!(f, "\n--- SUMMARY @ packet #{} ---", self.count);
            let _ = writeln!(f, "  WiFi frames:  {}", self.wifi_count);
            let _ = writeln!(f, "  PPDU status:  {}", self.ppdu_count);
            let _ = writeln!(f, "  Matched:      {} ({:.1}% of WiFi)",
                self.match_count,
                if self.wifi_count > 0 { self.match_count as f64 / self.wifi_count as f64 * 100.0 } else { 0.0 });
            let _ = writeln!(f, "  Evicted:      {} ({:.1}% of WiFi)",
                self.evict_count,
                if self.wifi_count > 0 { self.evict_count as f64 / self.wifi_count as f64 * 100.0 } else { 0.0 });
            let _ = writeln!(f, "  Other/Skip:   {}", self.skip_count);
            let _ = writeln!(f, "---");
        }
    }
}

thread_local! {
    static PPDU_STATE: std::cell::RefCell<PpduCorrelation> = std::cell::RefCell::new(PpduCorrelation::new());
    static RX_DEBUG: std::cell::RefCell<RxDebugLog> = std::cell::RefCell::new(RxDebugLog::new());
}

/// Parse one RX packet from a USB bulk read buffer.
///
/// This is the standalone parse function used by both `recv_frame_internal` (driver path)
/// and the RxHandle (dedicated RX thread). It handles all 11 rpkt_types, correlates
/// WiFi frames with PPDU status packets via ppdu_cnt, and returns complete frames
/// with full PHY status populated.
///
/// Returns (bytes_consumed, ParsedPacket).
fn parse_rx_packet_8852bu(buf: &[u8], channel: u8) -> (usize, crate::core::chip::ParsedPacket) {
    use crate::core::chip::ParsedPacket;
    use crate::core::frame::RxFrame;

    // First check if we have completed frames from previous evictions
    let evicted = PPDU_STATE.with(|state| {
        let mut s = state.borrow_mut();
        if !s.completed.is_empty() {
            Some(s.completed.remove(0))
        } else {
            None
        }
    });
    if let Some(frame) = evicted {
        return (0, ParsedPacket::Frame(frame));
    }

    // Need at least a short RX descriptor
    if buf.len() < RX_DESC_SHORT {
        return (0, ParsedPacket::Skip);
    }

    // ── DW0: packet length, type, descriptor format ──
    let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let pkt_len = (dw0 & 0x3FFF) as usize;
    let shift = ((dw0 >> 14) & 0x3) as usize;
    let mac_info_vld = (dw0 >> 23) & 1 != 0;
    let rpkt_type = ((dw0 >> 24) & 0xF) as u8;
    let drv_info_size = ((dw0 >> 28) & 0x7) as usize;
    let long_rxd = (dw0 >> 31) & 1 != 0;

    let desc_len = if long_rxd { RX_DESC_LONG } else { RX_DESC_SHORT };
    let payload_offset = desc_len + (drv_info_size * 8) + (shift * 2);

    if pkt_len == 0 {
        return (desc_len, ParsedPacket::Skip);
    }

    // Total consumed bytes for this packet
    let total_len = payload_offset + pkt_len;
    // Round up to 8-byte alignment (USB aggregation boundary)
    // Cap to buffer length to prevent overrun in stream drain
    let consumed = ((total_len + 7) & !7).min(buf.len());

    if total_len > buf.len() {
        return (0, ParsedPacket::Skip);
    }

    // ── DW1: rate/ppdu info (only for WiFi + PPDU types) ──
    let dw1 = if buf.len() >= 8 {
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]])
    } else {
        0
    };

    let ppdu_type_raw = (dw1 & 0xF) as u8;
    let ppdu_cnt = ((dw1 >> 4) & 0x7) as usize;
    let rx_rate = ((dw1 >> 16) & 0x1FF) as u16;
    let gi_ltf = ((dw1 >> 25) & 0x7) as u8;
    let bw = ((dw1 >> 30) & 0x3) as u8;

    // ── DW2: freerun counter (timestamp) ──
    let dw2 = if buf.len() >= 12 {
        u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]])
    } else {
        0
    };

    // ── DW3: flags (long RXD only, at offset 12) ──
    let dw3 = if long_rxd && buf.len() >= 16 {
        u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]])
    } else {
        0
    };

    let is_ampdu = (dw3 >> 3) & 1 != 0;
    let is_amsdu = (dw3 >> 5) & 1 != 0;
    let crc32_err = (dw3 >> 9) & 1 != 0;

    let band = if channel <= 14 { 0u8 } else { 1u8 };

    // Debug: log every packet's raw descriptor
    RX_DEBUG.with(|dbg| {
        let mut d = dbg.borrow_mut();
        d.count += 1;
        let pkt_num = d.count;
        // Log first 200 packets in full detail, then summary every 1000
        let detailed = pkt_num <= 200;
        let summary = pkt_num % 1000 == 0;

        if detailed {
            d.log(&format!(
                "[PKT #{}] rpkt_type={} pkt_len={} desc_len={} shift={} drv_info_sz={} long_rxd={} mac_info_vld={}",
                pkt_num, rpkt_type, pkt_len, desc_len, shift, drv_info_size, long_rxd, mac_info_vld));
            d.log(&format!(
                "  DW0=0x{:08X} DW1=0x{:08X} DW2=0x{:08X} DW3=0x{:08X}",
                dw0, dw1, dw2, dw3));
            d.log(&format!(
                "  ppdu_cnt={} ppdu_type={} rx_rate=0x{:03X} bw={} gi_ltf={} payload_offset={} consumed={}",
                ppdu_cnt, ppdu_type_raw, rx_rate, bw, gi_ltf, payload_offset, consumed));
            // Raw first 48 bytes of packet
            let hex_len = buf.len().min(48);
            let hex: String = buf[..hex_len].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
            d.log(&format!("  RAW[0..{}]: {}", hex_len, hex));
        }
        if summary {
            d.log_summary();
        }
    });

    match rpkt_type {
        // ═══════════════════════════════════════════════════════════════
        //  WiFi frame (rpkt_type=0) — park in pending slot
        // ═══════════════════════════════════════════════════════════════
        RPKT_WIFI => {
            // Extra offset for mac_info_vld on non-PPDU packets
            let extra = if mac_info_vld { 4 } else { 0 };
            let data_start = payload_offset + extra;
            // Strip FCS (4 bytes)
            let frame_len = if pkt_len >= 4 + extra { pkt_len - 4 - extra } else { 0 };

            if frame_len == 0 || data_start + frame_len > buf.len() {
                return (consumed, ParsedPacket::Skip);
            }

            // Skip CRC errors
            if crc32_err {
                return (consumed, ParsedPacket::Skip);
            }

            RX_DEBUG.with(|dbg| {
                let mut d = dbg.borrow_mut();
                d.wifi_count += 1;
                if d.wifi_count <= 200 {
                    // Show frame type from first 2 bytes of 802.11 header
                    let fc = if data_start + 2 <= buf.len() {
                        u16::from_le_bytes([buf[data_start], buf[data_start + 1]])
                    } else { 0 };
                    let ftype = (fc >> 2) & 0x3;
                    let fsub = (fc >> 4) & 0xF;
                    d.log(&format!(
                        "  → WIFI: frame_len={} fc=0x{:04X} type={} subtype={} ppdu_cnt={} data_start={} ampdu={} amsdu={}",
                        frame_len, fc, ftype, fsub, ppdu_cnt, data_start, is_ampdu, is_amsdu));
                    d.log(&format!(
                        "    ppdu_cnt extraction: DW1_raw=0x{:08X} → bits[6:4]=(0x{:08X} >> 4) & 0x7 = {}",
                        dw1, dw1, ppdu_cnt));
                }
            });

            // Copy frame data now — buffer will be overwritten by next USB read
            let frame_data = buf[data_start..data_start + frame_len].to_vec();

            PPDU_STATE.with(|state| {
                let mut s = state.borrow_mut();

                // Evict old frame if slot occupied (PPDU was lost for previous frame)
                if s.slots[ppdu_cnt].occupied {
                    let old_rate = s.slots[ppdu_cnt].data_rate;
                    RX_DEBUG.with(|dbg| {
                        let mut d = dbg.borrow_mut();
                        d.evict_count += 1;
                        if d.count <= 200 {
                            d.log(&format!("  → EVICT: slot[{}] was occupied (old rate=0x{:03X})",
                                ppdu_cnt, old_rate));
                        }
                    });
                    let evicted = evict_slot(&mut s.slots[ppdu_cnt]);
                    s.completed.push(evicted);
                }

                // Store new frame in slot
                let slot = &mut s.slots[ppdu_cnt];
                slot.data = frame_data;
                slot.channel = channel;
                slot.band = band;
                slot.data_rate = rx_rate;
                slot.ppdu_type = ppdu_type_raw;
                slot.bw = bw;
                slot.gi_ltf = gi_ltf;
                slot.freerun_cnt = dw2;
                slot.is_ampdu = is_ampdu;
                slot.is_amsdu = is_amsdu;
                slot.occupied = true;
            });

            (consumed, ParsedPacket::Skip)
        }

        // ═══════════════════════════════════════════════════════════════
        //  PPDU status (rpkt_type=1) — parse PHY status, match pending frame
        // ═══════════════════════════════════════════════════════════════
        RPKT_PPDU_STATUS => {
            RX_DEBUG.with(|dbg| {
                let mut d = dbg.borrow_mut();
                d.ppdu_count += 1;
            });

            let ppdu_payload = &buf[payload_offset..payload_offset + pkt_len];

            RX_DEBUG.with(|dbg| {
                let mut d = dbg.borrow_mut();
                if d.ppdu_count <= 200 {
                    let hex_len = ppdu_payload.len().min(32);
                    let hex: String = ppdu_payload[..hex_len].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                    d.log(&format!(
                        "  → PPDU: ppdu_cnt={} mac_info_vld={} payload_len={} payload[0..{}]: {}",
                        ppdu_cnt, mac_info_vld, ppdu_payload.len(), hex_len, hex));
                    d.log(&format!(
                        "    ppdu_cnt extraction: DW1_raw=0x{:08X} → bits[6:4]=(0x{:08X} >> 4) & 0x7 = {}",
                        dw1, dw1, ppdu_cnt));
                    // Show what's in each slot right now
                    PPDU_STATE.with(|state| {
                        let s = state.borrow();
                        let mut slot_info = String::from("    slots: ");
                        for i in 0..8 {
                            if s.slots[i].occupied {
                                slot_info.push_str(&format!("[{}:rate=0x{:03X},len={}] ", i, s.slots[i].data_rate, s.slots[i].data.len()));
                            } else {
                                slot_info.push_str(&format!("[{}:empty] ", i));
                            }
                        }
                        d.log(&slot_info);
                    });
                }
            });

            // Parse MAC info header if present, then physts.
            // MAC info struct is 2 DWORDs (8 bytes):
            //   DW0: usr_num[3:0], lsig_len[27:16], rx_cnt_vld[29]
            //   DW1: service[15:0], plcp_len[23:16] (in 8-byte units)
            let physts_data = if mac_info_vld && ppdu_payload.len() >= 8 {
                let mi_dw0 = u32::from_le_bytes([
                    ppdu_payload[0], ppdu_payload[1],
                    ppdu_payload[2], ppdu_payload[3],
                ]);
                let mi_dw1 = u32::from_le_bytes([
                    ppdu_payload[4], ppdu_payload[5],
                    ppdu_payload[6], ppdu_payload[7],
                ]);
                let usr_num = (mi_dw0 & 0xF) as usize;
                let rx_cnt_vld = mi_dw0 & (1 << 29) != 0;
                let plcp_len = (((mi_dw1 >> 16) & 0xFF) as usize) * 8; // DW1[23:16] * 8

                // Accumulate size: mac_info header (8B) + per-user (4B each, 8-byte aligned)
                let mut offset = 8; // sizeof(mac_ax_mac_info_t) = 2 DWORDs = 8 bytes
                let usr_size = usr_num * 4; // MAC_AX_MAC_INFO_USE_SIZE = 4
                offset += usr_size;
                // 8-byte align the user block
                if usr_num & 1 != 0 { offset += 4; }

                // RX count block (96 bytes if present — MAC_AX_RX_CNT_SIZE=96)
                if rx_cnt_vld { offset += 96; }

                // PLCP block
                offset += plcp_len;

                RX_DEBUG.with(|dbg| {
                    let mut d = dbg.borrow_mut();
                    if d.ppdu_count <= 200 {
                        d.log(&format!(
                            "    MAC_INFO: usr_num={} rx_cnt_vld={} plcp_len={} → physts_offset={} (payload_len={})",
                            usr_num, rx_cnt_vld, plcp_len, offset, ppdu_payload.len()));
                    }
                });

                if offset < ppdu_payload.len() {
                    &ppdu_payload[offset..]
                } else {
                    return (consumed, ParsedPacket::Skip);
                }
            } else {
                // No MAC info — entire payload is physts
                ppdu_payload
            };

            if physts_data.len() < PHYSTS_HDR_LEN {
                return (consumed, ParsedPacket::Skip);
            }

            // Parse physts header (8 bytes)
            let mut phy = PhyStatus::default();
            phy.ie_bitmap_select = physts_data[0] & 0x1F;
            let is_valid = (physts_data[0] >> 7) & 1 != 0;
            let total_length = (physts_data[1] as usize) * 8; // in bytes
            phy.rssi_avg = physts_data[3];
            phy.rssi_path[0] = physts_data[4];
            phy.rssi_path[1] = physts_data[5];
            phy.rssi_path[2] = physts_data[6];
            phy.rssi_path[3] = physts_data[7];

            RX_DEBUG.with(|dbg| {
                let mut d = dbg.borrow_mut();
                if d.ppdu_count <= 200 {
                    let rssi_dbm = if phy.rssi_avg != 0 { (phy.rssi_avg >> 1) as i16 - 110 } else { 0 };
                    let hex_len = physts_data.len().min(16);
                    let hex: String = physts_data[..hex_len].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                    d.log(&format!(
                        "  → PHYSTS HDR: valid={} total_len={} bitmap_sel={} rssi_avg_raw=0x{:02X}({} dBm) rssi_path=[0x{:02X},0x{:02X},0x{:02X},0x{:02X}]",
                        is_valid, total_length, phy.ie_bitmap_select, phy.rssi_avg, rssi_dbm,
                        phy.rssi_path[0], phy.rssi_path[1], phy.rssi_path[2], phy.rssi_path[3]));
                    d.log(&format!("    physts[0..{}]: {}", hex_len, hex));
                }
            });

            if !is_valid || total_length == 0 || total_length > physts_data.len() {
                RX_DEBUG.with(|dbg| {
                    let mut d = dbg.borrow_mut();
                    if d.ppdu_count <= 200 {
                        d.log(&format!("    → SKIP: invalid physts (valid={} total_len={} data_len={})",
                            is_valid, total_length, physts_data.len()));
                    }
                });
                return deliver_ppdu_match(ppdu_cnt, ppdu_type_raw, rx_rate, &phy, consumed);
            }

            // Parse IEs — walk from after header to total_length
            let ie_area = &physts_data[PHYSTS_HDR_LEN..total_length.min(physts_data.len())];
            parse_physts_ies(ie_area, &mut phy);

            deliver_ppdu_match(ppdu_cnt, ppdu_type_raw, rx_rate, &phy, consumed)
        }

        // ═══════════════════════════════════════════════════════════════
        //  Channel Info (rpkt_type=2) — raw CSI data
        //  Format: DW0 header + CSI matrix (I/Q per subcarrier per ant pair)
        //  RTL8852B: 2x2 MIMO, up to 256 subcarriers (80MHz)
        // ═══════════════════════════════════════════════════════════════
        RPKT_CHANNEL_INFO => {
            let payload = &buf[payload_offset..payload_offset + pkt_len];
            let raw = payload.to_vec();

            // CSI header: first 4 bytes contain metadata
            // DW0[1:0] = bandwidth (0=20, 1=40, 2=80, 3=160)
            // DW0[3:2] = Nr (RX chains - 1)
            // DW0[5:4] = Nc (TX chains - 1)
            // DW0[15:8] = num_sc (number of subcarriers / 4)
            let (csi_bw, nr, nc, num_sc) = if payload.len() >= 4 {
                let hdr = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let csi_bw = (hdr & 0x3) as u8;
                let nr = (((hdr >> 2) & 0x3) + 1) as u8;
                let nc = (((hdr >> 4) & 0x3) + 1) as u8;
                let num_sc = (((hdr >> 8) & 0xFF) as u16) * 4;
                (csi_bw, nr, nc, num_sc)
            } else {
                (0, 2, 2, 0)
            };

            // Parse I/Q pairs from payload after header
            let iq_offset = 4;
            let mut csi_raw = Vec::new();
            if payload.len() > iq_offset {
                let iq_data = &payload[iq_offset..];
                // Each I/Q value is 16-bit signed, packed as [I_lo, I_hi, Q_lo, Q_hi]
                let mut i = 0;
                while i + 3 < iq_data.len() {
                    let real = i16::from_le_bytes([iq_data[i], iq_data[i + 1]]);
                    let imag = i16::from_le_bytes([iq_data[i + 2], iq_data[i + 3]]);
                    csi_raw.push(real);
                    csi_raw.push(imag);
                    i += 4;
                }
            }

            (consumed, ParsedPacket::ChannelInfo(crate::core::chip::ChannelInfo {
                channel,
                bandwidth: csi_bw,
                nr,
                nc,
                num_subcarriers: num_sc,
                csi_raw,
                timestamp: dw2,
                raw,
            }))
        }

        // ═══════════════════════════════════════════════════════════════
        //  BB Scope (rpkt_type=3) — raw baseband I/Q waveform
        //  Digital samples straight from the ADC. Spectrum analyzer gold.
        // ═══════════════════════════════════════════════════════════════
        RPKT_BB_SCOPE => {
            let payload = &buf[payload_offset..payload_offset + pkt_len];
            let raw = payload.to_vec();

            // BB scope header: sample_rate_idx in first byte
            let sample_rate_idx = if !payload.is_empty() { payload[0] } else { 0 };

            // Parse I/Q sample pairs after 4-byte header
            let sample_offset = 4;
            let mut samples_iq = Vec::new();
            if payload.len() > sample_offset {
                let sample_data = &payload[sample_offset..];
                let mut i = 0;
                while i + 3 < sample_data.len() {
                    let ii = i16::from_le_bytes([sample_data[i], sample_data[i + 1]]);
                    let qq = i16::from_le_bytes([sample_data[i + 2], sample_data[i + 3]]);
                    samples_iq.push((ii, qq));
                    i += 4;
                }
            }

            (consumed, ParsedPacket::BbScope(crate::core::chip::BbScope {
                channel,
                sample_rate_idx,
                samples_iq,
                timestamp: dw2,
                raw,
            }))
        }

        // ═══════════════════════════════════════════════════════════════
        //  F2P TX Command Report (rpkt_type=4) — firmware TX scheduling
        // ═══════════════════════════════════════════════════════════════
        RPKT_F2P_TX_CMD_RPT => {
            let payload = &buf[payload_offset..payload_offset + pkt_len];
            let raw = payload.to_vec();

            // DW0[7:0] = mac_id, DW0[11:8] = queue_sel
            let (mac_id, queue_sel) = if payload.len() >= 4 {
                let dw = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                ((dw & 0xFF) as u8, ((dw >> 8) & 0xF) as u8)
            } else {
                (0, 0)
            };

            (consumed, ParsedPacket::F2pTxCmdReport(crate::core::chip::F2pTxCmdReport {
                mac_id,
                queue_sel,
                raw,
            }))
        }

        // ═══════════════════════════════════════════════════════════════
        //  SS2FW Report (rpkt_type=5) — spatial sounding / beamforming
        //  Contains V-matrix feedback from beamforming sounding frames.
        // ═══════════════════════════════════════════════════════════════
        RPKT_SS2FW_RPT => {
            let payload = &buf[payload_offset..payload_offset + pkt_len];
            let raw = payload.to_vec();

            // Sounding report header:
            // Bytes [0..6] = initiator MAC address
            // Byte [6] = NSS
            // Byte [7] = BW
            let mut initiator = [0u8; 6];
            let (nss, ss_bw) = if payload.len() >= 8 {
                initiator.copy_from_slice(&payload[0..6]);
                (payload[6], payload[7])
            } else if payload.len() >= 6 {
                initiator.copy_from_slice(&payload[0..6]);
                (0, 0)
            } else {
                (0, 0)
            };

            (consumed, ParsedPacket::SpatialSounding(crate::core::chip::SpatialSoundingReport {
                initiator,
                nss,
                bandwidth: ss_bw,
                raw,
            }))
        }

        // ═══════════════════════════════════════════════════════════════
        //  TX Report (rpkt_type=6) — ACK/NACK for injected frames
        //  MAC AX TX status format (RTL8852B):
        //  DW0: pkt_id[15:0], queue_sel[20:16], tx_state[23:21], tx_cnt[26:24]
        //  DW1: mac_id[7:0], final_rate[24:16], final_bw[29:28], final_gi_ltf[31:30]
        //  DW2: timestamp[31:0]
        //  DW3: total_airtime[15:0]
        // ═══════════════════════════════════════════════════════════════
        RPKT_TX_RPT => {
            let payload = &buf[payload_offset..payload_offset + pkt_len];
            let raw = payload.to_vec();

            let txs_dw0 = if payload.len() >= 4 {
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            } else { 0 };
            let txs_dw1 = if payload.len() >= 8 {
                u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
            } else { 0 };
            let txs_dw2 = if payload.len() >= 12 {
                u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]])
            } else { 0 };
            let txs_dw3 = if payload.len() >= 16 {
                u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]])
            } else { 0 };

            let pkt_id = (txs_dw0 & 0xFFFF) as u16;
            let queue_sel = ((txs_dw0 >> 16) & 0x1F) as u8;
            let tx_state = ((txs_dw0 >> 21) & 0x7) as u8;
            let tx_cnt = ((txs_dw0 >> 24) & 0x7) as u8;
            let acked = tx_state == 0;

            let mac_id = (txs_dw1 & 0xFF) as u8;
            let final_rate = ((txs_dw1 >> 16) & 0x1FF) as u16;
            let final_bw = ((txs_dw1 >> 28) & 0x3) as u8;
            let final_gi_ltf = ((txs_dw1 >> 30) & 0x3) as u8;

            let timestamp = txs_dw2;
            let total_airtime_us = (txs_dw3 & 0xFFFF) as u16;

            (consumed, ParsedPacket::TxStatus(crate::core::chip::TxReport {
                pkt_id,
                queue_sel,
                tx_state,
                tx_cnt,
                acked,
                final_rate,
                final_bw,
                final_gi_ltf,
                mac_id,
                timestamp,
                total_airtime_us,
                raw,
            }))
        }

        // ═══════════════════════════════════════════════════════════════
        //  TX PD Release Host (rpkt_type=7) — buffer release notification
        // ═══════════════════════════════════════════════════════════════
        RPKT_TX_PD_RELEASE_HOST => {
            let payload = &buf[payload_offset..payload_offset + pkt_len];
            let raw = payload.to_vec();

            // Each PD ID is 2 bytes
            let mut pd_ids = Vec::new();
            let mut i = 0;
            while i + 1 < payload.len() {
                pd_ids.push(u16::from_le_bytes([payload[i], payload[i + 1]]));
                i += 2;
            }

            (consumed, ParsedPacket::TxPdRelease(crate::core::chip::TxPdRelease {
                release_type: 7,
                pd_ids,
                raw,
            }))
        }

        // ═══════════════════════════════════════════════════════════════
        //  DFS Report (rpkt_type=8) — radar detection
        //  DW0: pulse_width[15:0], pri[31:16]
        //  DW1: pulse_count[7:0], radar_type[11:8], timestamp[31:16]
        // ═══════════════════════════════════════════════════════════════
        RPKT_DFS_RPT => {
            let payload = &buf[payload_offset..payload_offset + pkt_len];
            let raw = payload.to_vec();

            let dfs_dw0 = if payload.len() >= 4 {
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            } else { 0 };
            let dfs_dw1 = if payload.len() >= 8 {
                u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
            } else { 0 };

            let pulse_width_us = (dfs_dw0 & 0xFFFF) as u16;
            let pri_us = ((dfs_dw0 >> 16) & 0xFFFF) as u16;
            let pulse_count = (dfs_dw1 & 0xFF) as u8;
            let radar_type = ((dfs_dw1 >> 8) & 0xF) as u8;

            (consumed, ParsedPacket::DfsReport(crate::core::chip::DfsReport {
                channel,
                band,
                pulse_width_us,
                pri_us,
                pulse_count,
                radar_type,
                timestamp: dw2,
                raw,
            }))
        }

        // ═══════════════════════════════════════════════════════════════
        //  TX PD Release WLCPU (rpkt_type=9) — same as type 7 but WLCPU path
        // ═══════════════════════════════════════════════════════════════
        RPKT_TX_PD_RELEASE_WLCPU => {
            let payload = &buf[payload_offset..payload_offset + pkt_len];
            let raw = payload.to_vec();

            let mut pd_ids = Vec::new();
            let mut i = 0;
            while i + 1 < payload.len() {
                pd_ids.push(u16::from_le_bytes([payload[i], payload[i + 1]]));
                i += 2;
            }

            (consumed, ParsedPacket::TxPdRelease(crate::core::chip::TxPdRelease {
                release_type: 9,
                pd_ids,
                raw,
            }))
        }

        // ═══════════════════════════════════════════════════════════════
        //  C2H (rpkt_type=10) — firmware command response
        //  MAC AX C2H format:
        //  Byte 0: category (0=MAC, 1=BB, 2=RF, 3=BT, 4=FW)
        //  Byte 1: class
        //  Byte 2: function
        //  Byte 3: seq
        //  Byte 4+: payload
        // ═══════════════════════════════════════════════════════════════
        RPKT_C2H => {
            let payload = &buf[payload_offset..payload_offset + pkt_len];
            let raw = payload.to_vec();

            let category = if !payload.is_empty() { payload[0] } else { 0 };
            let class = if payload.len() > 1 { payload[1] } else { 0 };
            let function = if payload.len() > 2 { payload[2] } else { 0 };
            let seq = if payload.len() > 3 { payload[3] } else { 0 };
            let c2h_payload = if payload.len() > 4 { payload[4..].to_vec() } else { Vec::new() };

            (consumed, ParsedPacket::C2hEvent(crate::core::chip::C2hEvent {
                category,
                class,
                function,
                seq,
                payload: c2h_payload,
                raw,
            }))
        }

        // ═══════════════════════════════════════════════════════════════
        //  Unknown rpkt_type — preserve raw data, don't discard
        // ═══════════════════════════════════════════════════════════════
        _ => {
            (consumed, ParsedPacket::Skip)
        }
    }
}

/// Match a parsed PPDU to a pending WiFi frame and deliver it.
fn deliver_ppdu_match(
    ppdu_cnt: usize,
    ppdu_type_raw: u8,
    rx_rate: u16,
    phy: &PhyStatus,
    consumed: usize,
) -> (usize, crate::core::chip::ParsedPacket) {
    use crate::core::chip::ParsedPacket;

    PPDU_STATE.with(|state| {
        let mut s = state.borrow_mut();
        let slot = &mut s.slots[ppdu_cnt];

        if !slot.occupied {
            RX_DEBUG.with(|dbg| {
                let mut d = dbg.borrow_mut();
                if d.ppdu_count <= 200 {
                    d.log(&format!("    → NO MATCH: slot[{}] empty (PPDU arrived first)", ppdu_cnt));
                }
            });
            return (consumed, ParsedPacket::Skip);
        }

        // Build the complete frame — takes ownership of the stored data
        let data = std::mem::take(&mut slot.data);
        let mut frame = build_complete_frame(slot, phy);
        frame.data = data;

        RX_DEBUG.with(|dbg| {
            let mut d = dbg.borrow_mut();
            d.match_count += 1;
            if d.match_count <= 200 {
                d.log(&format!(
                    "    → MATCH: slot[{}] → rssi={} dBm, rate=0x{:03X}, frame_len={}",
                    ppdu_cnt, frame.rssi, frame.data_rate, frame.data.len()));
            }
        });

        slot.occupied = false;

        (consumed, ParsedPacket::Frame(frame))
    })
}

/// Build a complete RxFrame from pending slot + parsed PHY status.
fn build_complete_frame(slot: &PendingFrame, phy: &PhyStatus) -> RxFrame {
    use crate::core::frame::*;

    // Convert RSSI: U(8,1) format → dBm = (raw >> 1) - 110
    let rssi_avg_dbm = if phy.rssi_avg != 0 {
        ((phy.rssi_avg >> 1) as i16 - 110) as i8
    } else {
        0i8
    };
    let rssi_path_dbm: [i8; 4] = std::array::from_fn(|i| {
        if phy.rssi_path[i] != 0 {
            ((phy.rssi_path[i] >> 1) as i16 - 110) as i8
        } else {
            0i8
        }
    });

    let is_cck = phy.ie0_present && !phy.ie1_present;

    // Noise floor and SNR depend on CCK vs OFDM path
    let noise_floor = if is_cck {
        if phy.ie0_noise_pwr != 0 { (phy.ie0_noise_pwr as i16 - 110) as i8 } else { 0 }
    } else if phy.ie1_present {
        if phy.ie1_noise_pwr != 0 { (phy.ie1_noise_pwr as i16 - 110) as i8 } else { 0 }
    } else {
        0
    };

    let snr = if phy.ie1_present { phy.ie1_snr } else { 0 };

    // CFO: 12-bit signed value in the IE
    let cfo = if phy.ie1_present { phy.ie1_cfo } else if phy.ie0_present { phy.ie0_cfo } else { 0 };
    let cfo_preamble = if phy.ie1_present { phy.ie1_cfo_preamble } else { 0 };

    // SNR calculations (per Linux driver halbb_physts_rpt_gen)
    let snr_td_avg = if is_cck {
        phy.rssi_avg.saturating_sub(phy.ie0_noise_pwr)
    } else if phy.ie1_present {
        phy.rssi_avg.saturating_sub(phy.ie1_noise_pwr)
    } else {
        0
    };

    let snr_td: [u8; 4] = std::array::from_fn(|i| {
        let noise = if is_cck { phy.ie0_noise_pwr } else if phy.ie1_present { phy.ie1_noise_pwr } else { 0 };
        phy.rssi_path[i].saturating_sub(noise)
    });

    let snr_fd_avg = if phy.ie1_present { phy.ie1_snr } else { 0 };
    let snr_fd: [u8; 4] = std::array::from_fn(|i| {
        if snr_fd_avg > 0 && phy.rssi_avg > 0 && phy.rssi_path[i] > 0 {
            (((snr_fd_avg as u16) << 1).wrapping_add(phy.rssi_avg as u16).wrapping_sub(phy.rssi_path[i] as u16) >> 1) as u8
        } else {
            0
        }
    });

    RxFrame {
        data: Vec::new(), // Will be set by caller (stored separately)
        rssi: rssi_avg_dbm,
        channel: slot.channel,
        band: slot.band,
        timestamp: Duration::from_micros(slot.freerun_cnt as u64),
        rssi_path: rssi_path_dbm,
        noise_floor,
        snr,
        data_rate: slot.data_rate,
        ppdu_type: ppdu_type_from_raw(slot.ppdu_type),
        bandwidth: RxBandwidth::from_raw(slot.bw),
        gi_ltf: GuardInterval::from_raw(slot.gi_ltf),
        is_ldpc: if phy.ie1_present { phy.ie1_is_ldpc } else { false },
        is_stbc: if phy.ie1_present { phy.ie1_is_stbc } else { false },
        is_bf: if phy.ie1_present { phy.ie1_is_bf } else { false },
        is_ampdu: slot.is_ampdu,
        is_amsdu: slot.is_amsdu,
        // Extended IE1 fields
        rssi_fd: if phy.ie1_present { phy.ie1_rssi_avg_fd } else { 0 },
        evm_max: if phy.ie1_present { phy.ie1_evm_max } else { 0 },
        evm_min: if phy.ie1_present { phy.ie1_evm_min } else { 0 },
        cfo,
        cfo_preamble,
        rxsc: if phy.ie1_present { phy.ie1_rxsc } else { 0 },
        rx_path_en: if phy.ie1_present { phy.ie1_rx_path_en } else if phy.ie0_present { phy.ie0_rx_path_en } else { 0 },
        is_su: if phy.ie1_present { phy.ie1_is_su } else { true },
        is_ndp: if phy.ie1_present { phy.ie1_is_ndp } else { false },
        is_awgn: if phy.ie1_present { phy.ie1_is_awgn } else { false },
        grant_bt: if phy.ie1_present { phy.ie1_grant_bt } else { false },
        bf_gain_max: if phy.ie1_present { phy.ie1_bf_gain_max } else { 0 },
        condition_number: if phy.ie1_present { phy.ie1_avg_cn } else { 0 },
        sigval_below_th_cnt: if phy.ie1_present { phy.ie1_sigval_below_th_cnt } else { 0 },
        cn_excess_th_cnt: if phy.ie1_present { phy.ie1_cn_excess_th_cnt } else { 0 },
        pwr_to_cca: if phy.ie1_present { phy.ie1_pwr_to_cca } else { 0 },
        cca_to_agc: if phy.ie1_present { phy.ie1_cca_to_agc } else { 0 },
        cca_to_sbd: if phy.ie1_present { phy.ie1_cca_to_sbd } else { 0 },
        edcca_rpt_cnt: if phy.ie1_present { phy.ie1_edcca_rpt_cnt } else { 0 },
        edcca_total_smp_cnt: if phy.ie1_present { phy.ie1_edcca_total_smp_cnt } else { 0 },
        edcca_rpt_bw_max: if phy.ie1_present { phy.ie1_edcca_bw_max } else { 0 },
        edcca_rpt_bw_min: if phy.ie1_present { phy.ie1_edcca_bw_min } else { 0 },
        bw_from_phy: if phy.ie1_present { phy.ie1_bw_idx } else { 0 },
        pop_idx: if phy.ie1_present { phy.ie1_pop_idx } else if phy.ie0_present { phy.ie0_pop_idx } else { 0 },
        // CCK fields
        cck_rpl: if phy.ie0_present { phy.ie0_rpl } else { 0 },
        cck_cca_time: if phy.ie0_present { phy.ie0_cca_time } else { 0 },
        cck_evm_hdr: if phy.ie0_present { phy.ie0_evm_hdr } else { 0 },
        cck_evm_pld: if phy.ie0_present { phy.ie0_evm_pld } else { 0 },
        cck_sig_len: if phy.ie0_present { phy.ie0_sig_len } else { 0 },
        cck_preamble_type: if phy.ie0_present { phy.ie0_preamble_type } else { 0 },
        cck_dagc: if phy.ie0_present { phy.ie0_dagc } else { [0; 4] },
        cck_antdiv_rslt: if phy.ie0_present { phy.ie0_antdiv_rslt } else { [false; 4] },
        cck_hw_antsw: if phy.ie0_present { phy.ie0_hw_antsw } else { [false; 4] },
        cck_antwgt_gain_diff: if phy.ie0_present { phy.ie0_antwgt_gain_diff } else { 0 },
        cck_sync_mode: if phy.ie0_present { phy.ie0_sync_mode } else { 0 },
        // IE2 HE/AX fields
        max_nsts: if phy.ie2_present { phy.ie2_max_nsts } else { 0 },
        midamble: if phy.ie2_present { phy.ie2_midamble } else { false },
        ltf_type: if phy.ie2_present { phy.ie2_ltf_type } else { 0 },
        gi_from_phy: if phy.ie2_present { phy.ie2_gi } else { 0 },
        is_mu_mimo: if phy.ie2_present { phy.ie2_is_mu_mimo } else { false },
        is_dl_ofdma: if phy.ie2_present { phy.ie2_is_dl_ofdma } else { false },
        is_dcm: if phy.ie2_present { phy.ie2_is_dcm } else { false },
        is_doppler: if phy.ie2_present { phy.ie2_is_doppler } else { false },
        pkt_extension: if phy.ie2_present { phy.ie2_pkt_extension } else { 0 },
        coarse_cfo_i: if phy.ie2_present { phy.ie2_coarse_cfo_i } else { 0 },
        coarse_cfo_q: if phy.ie2_present { phy.ie2_coarse_cfo_q } else { 0 },
        fine_cfo_i: if phy.ie2_present { phy.ie2_fine_cfo_i } else { 0 },
        fine_cfo_q: if phy.ie2_present { phy.ie2_fine_cfo_q } else { 0 },
        est_cmped_phase: if phy.ie2_present { phy.ie2_est_cmped_phase } else { 0 },
        n_ltf: if phy.ie2_present { phy.ie2_n_ltf } else { 0 },
        n_sym: if phy.ie2_present { phy.ie2_n_sym } else { 0 },
        // Per-path IE4-7
        path_sig_val: phy.ie_path_sig_val,
        path_rf_gain_idx: phy.ie_path_rf_gain_idx,
        path_tia_gain_idx: phy.ie_path_tia_gain_idx,
        path_snr: phy.ie_path_snr,
        path_evm: phy.ie_path_evm,
        path_ant_weight: phy.ie_path_ant_weight,
        path_dc_re: phy.ie_path_dc_re,
        path_dc_im: phy.ie_path_dc_im,
        // Derived SNR
        snr_fd_avg,
        snr_fd,
        snr_td,
    }
}

/// Evict a pending frame from a slot, returning it with rssi=0.
fn evict_slot(slot: &mut PendingFrame) -> RxFrame {
    let frame = RxFrame {
        data: std::mem::take(&mut slot.data),
        channel: slot.channel,
        band: slot.band,
        data_rate: slot.data_rate,
        ppdu_type: ppdu_type_from_raw(slot.ppdu_type),
        bandwidth: RxBandwidth::from_raw(slot.bw),
        gi_ltf: GuardInterval::from_raw(slot.gi_ltf),
        timestamp: Duration::from_micros(slot.freerun_cnt as u64),
        is_ampdu: slot.is_ampdu,
        is_amsdu: slot.is_amsdu,
        ..Default::default()
    };
    slot.occupied = false;
    frame
}

/// Convert raw ppdu_type value to PpduType enum.
fn ppdu_type_from_raw(raw: u8) -> PpduType {
    match raw {
        PPDU_T_LEGACY => PpduType::Ofdm,  // Legacy — could be CCK or OFDM, use OFDM as generic
        PPDU_T_HT => PpduType::HT,
        PPDU_T_VHT => PpduType::VhtSu,
        PPDU_T_HE_SU | PPDU_T_HE_ER_SU => PpduType::HeSu,
        PPDU_T_HE_MU => PpduType::HeMu,
        PPDU_T_HE_TB => PpduType::HeTb,
        _ => PpduType::Cck,
    }
}

/// Parse all physts IEs from the IE area (after the 8-byte header).
fn parse_physts_ies(ie_area: &[u8], phy: &mut PhyStatus) {
    let mut pos = 0;
    let mut bitmap: u32 = 0;

    while pos < ie_area.len() {
        let ie_id = ie_area[pos] & 0x1F;

        // Prevent duplicate IEs
        if bitmap & (1 << ie_id) != 0 { break; }

        // Determine IE length
        let ie_len = if (ie_id as usize) < IE_LEN_TABLE.len() && IE_LEN_TABLE[ie_id as usize] != 0xFF {
            // Fixed length (in 8-byte units → bytes)
            (IE_LEN_TABLE[ie_id as usize] as usize) * 8
        } else if pos + 1 < ie_area.len() {
            // Variable length: 12-bit header
            let hi3 = ((ie_area[pos] >> 5) & 0x7) as usize;
            let lo4 = ((ie_area[pos + 1]) & 0xF) as usize;
            ((lo4 << 3) | hi3) * 8
        } else {
            break;
        };

        if ie_len == 0 || pos + ie_len > ie_area.len() { break; }

        let ie_data = &ie_area[pos..pos + ie_len];

        match ie_id {
            0 => parse_ie0_cck(ie_data, phy),
            1 => parse_ie1_ofdm(ie_data, phy),
            2 => parse_ie2_he(ie_data, phy),
            // IE3: segment 1 (80+80MHz) — skip for now (20MHz only)
            4..=7 => parse_ie4_7_path(ie_id - 4, ie_data, phy),
            // IE8-31: parsed structurally but fields stored as-is
            // These are less common (channel info, PLCP, debug) —
            // we walk past them correctly but don't extract every field yet.
            // The data is still consumed so we don't lose sync.
            _ => {}
        }

        bitmap |= 1 << ie_id;
        pos += ie_len;
    }
}

/// Parse IE0 — CCK common (16 bytes)
fn parse_ie0_cck(data: &[u8], phy: &mut PhyStatus) {
    if data.len() < 16 { return; }
    phy.ie0_present = true;

    // DW0
    phy.ie0_pop_idx = (data[0] >> 5) & 0x3;
    let rpl_l = (data[0] >> 7) & 1;
    let rpl_m = data[1];
    phy.ie0_rpl = ((rpl_m as u16) << 1) | (rpl_l as u16);
    phy.ie0_cca_time = data[2];
    phy.ie0_antwgt_gain_diff = data[3] & 0x1F;
    phy.ie0_hw_antsw[0] = (data[3] >> 5) & 1 != 0;
    phy.ie0_hw_antsw[1] = (data[3] >> 6) & 1 != 0;
    phy.ie0_hw_antsw[2] = (data[3] >> 7) & 1 != 0;

    // DW1
    phy.ie0_noise_pwr = data[4];
    let cfo_l = data[5];
    let cfo_m = data[6] & 0xF;
    phy.ie0_cfo = sign_extend_12(((cfo_m as u16) << 8) | (cfo_l as u16));
    let ccfo_l = (data[6] >> 4) & 0xF;
    let ccfo_m = data[7];
    phy.ie0_coarse_cfo = sign_extend_12(((ccfo_m as u16) << 4) | (ccfo_l as u16));

    // DW2
    phy.ie0_evm_hdr = data[8];
    phy.ie0_evm_pld = data[9];
    phy.ie0_sig_len = u16::from_le_bytes([data[10], data[11]]);

    // DW3
    phy.ie0_antdiv_rslt[0] = data[12] & 1 != 0;
    phy.ie0_antdiv_rslt[1] = (data[12] >> 1) & 1 != 0;
    phy.ie0_antdiv_rslt[2] = (data[12] >> 2) & 1 != 0;
    phy.ie0_antdiv_rslt[3] = (data[12] >> 3) & 1 != 0;
    phy.ie0_preamble_type = (data[12] >> 4) & 1;
    phy.ie0_sync_mode = (data[12] >> 5) & 1;
    phy.ie0_hw_antsw[3] = (data[12] >> 7) & 1 != 0;

    let dagc_a = data[13] & 0x1F;
    let dagc_b = ((data[13] >> 5) & 0x7) | ((data[14] & 0x3) << 3);
    let dagc_c = (data[14] >> 2) & 0x1F;
    let dagc_d = ((data[14] >> 7) & 0x1) | ((data[15] & 0xF) << 1);
    phy.ie0_dagc = [dagc_a, dagc_b, dagc_c, dagc_d];
    phy.ie0_rx_path_en = (data[15] >> 4) & 0xF;
}

/// Parse IE1 — OFDM/HT/VHT/HE common (32 bytes)
fn parse_ie1_ofdm(data: &[u8], phy: &mut PhyStatus) {
    if data.len() < 24 { return; } // minimum for DW0-DW5
    phy.ie1_present = true;

    // DW0
    phy.ie1_pop_idx = (data[0] >> 5) & 0x3;
    phy.ie1_rssi_avg_fd = data[1];
    phy.ie1_ch_idx = data[2];
    phy.ie1_rxsc = data[3] & 0xF;
    phy.ie1_rx_path_en = (data[3] >> 4) & 0xF;

    // DW1
    phy.ie1_noise_pwr = data[4];
    let cfo_l = data[5];
    let cfo_m = data[6] & 0xF;
    phy.ie1_cfo = sign_extend_12(((cfo_m as u16) << 8) | (cfo_l as u16));
    let pcfo_l = (data[6] >> 4) & 0xF;
    let pcfo_m = data[7];
    phy.ie1_cfo_preamble = sign_extend_12(((pcfo_m as u16) << 4) | (pcfo_l as u16));

    // DW2
    phy.ie1_snr = data[8] & 0x3F;
    phy.ie1_evm_max = data[9];
    phy.ie1_evm_min = data[10];
    phy.ie1_gi_type = data[11] & 0x7;
    phy.ie1_is_su = (data[11] >> 3) & 1 != 0;
    phy.ie1_is_ldpc = (data[11] >> 4) & 1 != 0;
    phy.ie1_is_ndp = (data[11] >> 5) & 1 != 0;
    phy.ie1_is_stbc = (data[11] >> 6) & 1 != 0;
    phy.ie1_grant_bt = (data[11] >> 7) & 1 != 0;

    // DW3
    phy.ie1_bf_gain_max = data[12] & 0x7F;
    phy.ie1_is_awgn = (data[12] >> 7) & 1 != 0;
    phy.ie1_is_bf = data[13] & 1 != 0;
    phy.ie1_avg_cn = (data[13] >> 1) & 0x7F;
    phy.ie1_sigval_below_th_cnt = data[14];
    phy.ie1_cn_excess_th_cnt = data[15];

    // DW4
    phy.ie1_pwr_to_cca = u16::from_le_bytes([data[16], data[17]]);
    phy.ie1_cca_to_agc = data[18];
    phy.ie1_cca_to_sbd = data[19];

    // DW5
    phy.ie1_edcca_rpt_cnt = (data[20] >> 1) & 0x7F;
    phy.ie1_edcca_total_smp_cnt = data[21] & 0x7F;
    let bw_max_l = (data[21] >> 7) & 1;
    let bw_max_m = data[22] & 0x3F;
    phy.ie1_edcca_bw_max = (bw_max_m << 1) | bw_max_l;
    let bw_min_l = (data[22] >> 6) & 0x3;
    let bw_min_m = data[23] & 0x1F;
    phy.ie1_edcca_bw_min = (bw_min_m << 2) | bw_min_l;
    phy.ie1_bw_idx = (data[23] >> 5) & 0x7;
}

/// Parse IE2 — HE/AX extended (24 bytes)
fn parse_ie2_he(data: &[u8], phy: &mut PhyStatus) {
    if data.len() < 16 { return; }
    phy.ie2_present = true;

    // DW0
    phy.ie2_max_nsts = (data[0] >> 5) & 0x7;
    phy.ie2_midamble = data[1] & 1 != 0;
    phy.ie2_ltf_type = (data[1] >> 1) & 0x3;
    phy.ie2_gi = (data[1] >> 3) & 0x3;
    phy.ie2_is_mu_mimo = (data[1] >> 5) & 1 != 0;
    // Coarse CFO I: 18-bit signed spread across bytes 1-3
    let c_cfo_i_l = ((data[1] >> 6) & 0x3) as u32;
    let c_cfo_i_m2 = data[2] as u32;
    let c_cfo_i_m1 = data[3] as u32;
    let c_cfo_i_raw = (c_cfo_i_m1 << 10) | (c_cfo_i_m2 << 2) | c_cfo_i_l;
    phy.ie2_coarse_cfo_i = sign_extend_18(c_cfo_i_raw);

    // DW1
    phy.ie2_is_dl_ofdma = (data[5] >> 5) & 1 != 0;
    let c_cfo_q_l = ((data[5] >> 6) & 0x3) as u32;
    let c_cfo_q_m2 = data[6] as u32;
    let c_cfo_q_m1 = data[7] as u32;
    let c_cfo_q_raw = (c_cfo_q_m1 << 10) | (c_cfo_q_m2 << 2) | c_cfo_q_l;
    phy.ie2_coarse_cfo_q = sign_extend_18(c_cfo_q_raw);

    // DW2
    phy.ie2_est_cmped_phase = data[8];
    phy.ie2_is_dcm = data[9] & 1 != 0;
    phy.ie2_is_doppler = (data[9] >> 1) & 1 != 0;
    phy.ie2_pkt_extension = (data[9] >> 2) & 0x7;
    let f_cfo_i_l = ((data[9] >> 6) & 0x3) as u32;
    let f_cfo_i_m2 = data[10] as u32;
    let f_cfo_i_m1 = data[11] as u32;
    let f_cfo_i_raw = (f_cfo_i_m1 << 10) | (f_cfo_i_m2 << 2) | f_cfo_i_l;
    phy.ie2_fine_cfo_i = sign_extend_18(f_cfo_i_raw);

    // DW3
    phy.ie2_n_ltf = data[12] & 0x7;
    let n_sym_l = ((data[12] >> 3) & 0x1F) as u16;
    let n_sym_m = (data[13] & 0x3F) as u16;
    phy.ie2_n_sym = (n_sym_m << 5) | n_sym_l;
    let f_cfo_q_l = ((data[13] >> 6) & 0x3) as u32;
    let f_cfo_q_m2 = data[14] as u32;
    let f_cfo_q_m1 = data[15] as u32;
    let f_cfo_q_raw = (f_cfo_q_m1 << 10) | (f_cfo_q_m2 << 2) | f_cfo_q_l;
    phy.ie2_fine_cfo_q = sign_extend_18(f_cfo_q_raw);
}

/// Parse IE4-7 — per-path stats (8 bytes each)
fn parse_ie4_7_path(path: u8, data: &[u8], phy: &mut PhyStatus) {
    if data.len() < 8 { return; }
    let p = path as usize;
    if p >= 4 { return; }
    phy.ie_path_present[p] = true;

    // DW0
    phy.ie_path_sig_val[p] = data[1];
    phy.ie_path_rf_gain_idx[p] = data[2];
    phy.ie_path_tia_gain_idx[p] = data[3] & 1;
    phy.ie_path_snr[p] = (data[3] >> 2) & 0x3F;

    // DW1
    phy.ie_path_evm[p] = data[4];
    phy.ie_path_ant_weight[p] = data[5] & 0x7F;
    phy.ie_path_dc_re[p] = data[6];
    phy.ie_path_dc_im[p] = data[7];
}

/// Sign-extend a 12-bit value to i16.
fn sign_extend_12(val: u16) -> i16 {
    if val & 0x800 != 0 {
        (val | 0xF000) as i16
    } else {
        val as i16
    }
}

/// Sign-extend an 18-bit value to i32.
fn sign_extend_18(val: u32) -> i32 {
    if val & 0x20000 != 0 {
        (val | 0xFFFC0000) as i32
    } else {
        val as i32
    }
}

fn start_rx_pipeline_8852bu(
    device: Arc<DeviceHandle<GlobalContext>>,
    ep_in: u8,
    channel: Arc<AtomicU8>,
    gate: crate::pipeline::FrameGate,
    alive: Arc<AtomicBool>,
    tx_feedback: Arc<crate::core::chip::TxFeedback>,
) {
    const USB_TIMEOUT: Duration = Duration::from_millis(100);

    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();

    // ── Thread 1: USB reader — reads endpoint, sends each read ──
    let device_clone = Arc::clone(&device);
    let alive_reader = Arc::clone(&alive);
    thread::Builder::new()
        .name("rx-usb-reader-8852bu".into())
        .spawn(move || {
            let mut buf = vec![0u8; RX_BUF_SIZE];
            let mut consecutive_errors = 0u32;
            let mut usb_reads = 0u64;
            let mut usb_bytes = 0u64;
            let mut last_log = std::time::Instant::now();
            let mut log = std::fs::OpenOptions::new()
                .create(true).append(true)
                .open("/tmp/wifikit_8852bu_rx_stats.log").ok();

            loop {
                if !alive_reader.load(Ordering::SeqCst) { break; }

                let actual = match device_clone.read_bulk(ep_in, &mut buf, USB_TIMEOUT) {
                    Ok(n) if n > 0 => {
                        consecutive_errors = 0;
                        n
                    }
                    Ok(_) => continue,
                    Err(rusb::Error::Timeout) => continue,
                    Err(rusb::Error::Interrupted) => continue,
                    Err(rusb::Error::Pipe) => {
                        consecutive_errors += 1;
                        let _ = device_clone.clear_halt(ep_in);
                        thread::sleep(Duration::from_millis(5));
                        if consecutive_errors >= 50 { break; }
                        continue;
                    }
                    Err(_) => {
                        consecutive_errors += 1;
                        thread::sleep(Duration::from_millis(10));
                        if consecutive_errors >= 50 { break; }
                        continue;
                    }
                };

                usb_reads += 1;
                usb_bytes += actual as u64;

                if last_log.elapsed() >= Duration::from_secs(5) {
                    if let Some(ref mut f) = log {
                        use std::io::Write;
                        let _ = writeln!(f, "[USB] reads={} bytes={} ({:.0} KB/s)",
                            usb_reads, usb_bytes,
                            usb_bytes as f64 / last_log.elapsed().as_secs_f64() / 1024.0);
                    }
                    usb_reads = 0;
                    usb_bytes = 0;
                    last_log = std::time::Instant::now();
                }

                if tx.send(buf[..actual].to_vec()).is_err() { break; }
            }
        })
        .expect("failed to spawn rx-usb-reader-8852bu");

    // ── Thread 2: Per-read parser — each USB read is self-contained ──
    thread::Builder::new()
        .name("rx-per-read-parser-8852bu".into())
        .spawn(move || {
            let mut packets_parsed = 0u64;
            let mut frames_submitted = 0u64;
            let mut last_log = std::time::Instant::now();
            let mut log = std::fs::OpenOptions::new()
                .create(true).append(true)
                .open("/tmp/wifikit_8852bu_rx_stats.log").ok();

            for read_buf in rx.iter() {
                let actual = read_buf.len();
                let mut pos = 0;

                while pos + 4 <= actual {
                    let dw0 = u32::from_le_bytes([
                        read_buf[pos], read_buf[pos+1], read_buf[pos+2], read_buf[pos+3],
                    ]);
                    let pkt_len = (dw0 & 0x3FFF) as usize;
                    let shift = ((dw0 >> 14) & 0x3) as usize;
                    let long_rxd = (dw0 >> 31) & 1 != 0;
                    let drv_info_size = ((dw0 >> 28) & 0x7) as usize;
                    let rpkt_type = ((dw0 >> 24) & 0xF) as u8;
                    let desc_len = if long_rxd { RX_DESC_LONG } else { RX_DESC_SHORT };

                    if pkt_len == 0 {
                        if pos + desc_len > actual { break; }
                        pos += desc_len;
                        continue;
                    }

                    let payload_offset = desc_len + (drv_info_size * 8) + (shift * 2);
                    let total_len = payload_offset + pkt_len;
                    let consumed = (total_len + 7) & !7;

                    if rpkt_type > 10 || pos + consumed > actual {
                        break;
                    }

                    let packet = &read_buf[pos..pos + consumed];
                    packets_parsed += 1;

                    // Parse — retry loop handles PPDU eviction (pc=0 means evicted frame ready)
                    let ch = channel.load(Ordering::Relaxed);
                    loop {
                        let (pc, result) = parse_rx_packet_8852bu(packet, ch);
                        match result {
                            crate::core::chip::ParsedPacket::Frame(frame) => {
                                frames_submitted += 1;
                                gate.submit(frame);
                            }
                            crate::core::chip::ParsedPacket::TxStatus(ref rpt) => {
                                tx_feedback.record(rpt);
                            }
                            _ => {}
                        }
                        if pc > 0 { break; }
                    }

                    pos += consumed;
                }

                if last_log.elapsed() >= Duration::from_secs(5) {
                    if let Some(ref mut f) = log {
                        use std::io::Write;
                        let _ = writeln!(f, "[PARSER] packets={} frames_to_gate={} ({:.1}% yield)",
                            packets_parsed, frames_submitted,
                            if packets_parsed > 0 { frames_submitted as f64 / packets_parsed as f64 * 100.0 } else { 0.0 });
                    }
                    packets_parsed = 0;
                    frames_submitted = 0;
                    last_log = std::time::Instant::now();
                }
            }
        })
        .expect("failed to spawn rx-per-read-parser-8852bu");
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
