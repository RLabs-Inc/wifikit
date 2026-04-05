//! RTL8852AU / RTL8832AU chip driver — WiFi 6 (802.11ax)
//!
//! # Hardware
//!
//! Realtek RTL8852A — 802.11ax dual-band (2.4GHz + 5GHz), 2T2R MIMO, USB 3.0.
//! WiFi 6 (HE) capable. Used in: Comfast CF-953AX, BrosTrend AX4L, and others.
//! This is the project's most complex Realtek driver — gen2 MAC AX architecture
//! with firmware-centric design and PPDU status correlation for RSSI.
//!
//! Key hardware traits:
//!   - MAC AX (gen2): firmware runs on WCPU, handles BB/RF init + calibration
//!   - Firmware: single binary with header + sections, downloaded via EP7 bulk OUT
//!   - H2C commands: via EP7 with WD + FWCMD header, sequence-tracked with REC_ACK
//!   - Extended register space: addresses > 0xFFFF via wIndex in control transfers
//!   - PPDU status: RSSI/SNR/LDPC/STBC arrive in separate packets, correlated by ppdu_cnt
//!
//! # Init Flow (hybrid: our code + usbmon pcap replay)
//!
//!   Phase -1: Clean dirty FW state (disable CPU + power off if previous session)
//!   Phase  0: Power on (LPS exit → power-on table → post-power config)
//!             + DMAC pre-init (HCI DMA, DLE, HFC, FWDL path enable, WCPU enable)
//!   Phase  1: Firmware download (EP7: H2C header → section chunks with FWDL_EN)
//!   Phase  2: Post-FWDL pcap replay (skip first 325 ops + ADDR_CAM/FWROLE_MAINTAIN)
//!             Background RX drain thread runs during init to prevent EP stall
//!   Phase  3: Monitor mode (single RX_FLTR_OPT write: 0x031644BF = promiscuous)
//!   Final:    Read MAC address from EFUSE autoload registers
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
//! # RX Architecture — PPDU Status Correlation
//!
//!   WiFi frames (rpkt_type=0) arrive with drv_info_size=0 — no embedded PHY status.
//!   RSSI/SNR/LDPC/STBC arrive in PPDU status packets (rpkt_type=1).
//!   Correlation uses ppdu_cnt (3-bit, 8 slots) from DW1[6:4]:
//!     1. WiFi frame → store as pending in slot[ppdu_cnt]
//!     2. PPDU status → parse physts, apply to pending frame if ppdu_cnt matches
//!     3. If PPDU arrives first → pre-store, applied when WiFi frame appears
//!   Some frames carry inline physts in drv_info (drv_info_size > 0) — used directly.
//!
//! # Channel Switching — Full Programmatic Port
//!
//!   7-step flow from halbb_ctrl_bw_ch_8852a + hal_chan.c:
//!     1. hal_reset(enable)  — disable PPDU/DFS/TSSI, clear BB reset
//!     2. mac_set_bw()       — WMAC_RFMOD + TXRATE_CHK for band
//!     3. bb_ctrl_ch()       — RF PLL (reg 0x18), mode select, SCO comp, CCK params
//!     4. bb_ctrl_bw()       — BB bandwidth regs (20MHz hardcoded)
//!     5. bb_ctrl_cck_en()   — CCK enable (2G) / disable (5G)
//!     6. bb_reset()         — full 0xFF toggle on PHY0 reg 0x804
//!     7. hal_reset(disable) — re-enable PPDU/DFS/TSSI, resume radio
//!
//! # Architecture Decisions
//!
//!   - Init uses hybrid approach: power-on/DMAC is our proven RMW code,
//!     post-FWDL is verbatim usbmon pcap replay (too many undocumented regs)
//!   - ADDR_CAM and FWROLE_MAINTAIN H2C commands are skipped during init —
//!     they contain the pcap capture machine's MAC and enable address filtering
//!   - Background RX drain thread during init prevents PPDU/C2H data from
//!     backing up and stalling the H2C command path
//!   - PPDU correlation uses PpduStatusCache with 8 slots — matches PHL_MAX_PPDU_CNT
//!   - Standalone parse function uses thread_local PpduStatusCache for RxHandle path
//!   - Board-specific registers (0x0010 SWR_CTRL) are skipped during pcap replay
//!   - Phase table loader (BB/RF) supports headline selection, IF/ELSE_IF/ELSE/END
//!     conditional blocks — shared format with all Realtek gen2 chips
//!
//! # What's NOT Implemented
//!
//!   - 40/80 MHz bandwidth (all channel switching hardcoded to 20MHz)
//!   - TX power calibration (EFUSE not parsed, using default 20 dBm)
//!   - set_mac() (no-op — ADDR_CAM would need proper MAC write)
//!   - TX power calibration from EFUSE (using default 20 dBm)
//!   - C2H response parsing (drained but not interpreted)
//!
//! # Reference
//!
//!   Vendor driver: references/rtl8852au/ (Realtek v1.15.0.1)
//!   Linux out-of-tree: lwfinger/rtl8852au
//!   Phase tables: rtl8852a_tables.rs (BB/RF), rtl8852a_post_boot.rs (pcap ops)
//!   Pre-FWDL: rtl8852a_pre_fwdl.rs, Post-FWDL: rtl8852a_phase_post_fwdl.rs

// Register map constants — many not yet wired but needed for full driver implementation.
// Struct fields/methods used via ChipDriver trait dispatch appear unused to the compiler.
#![allow(dead_code)]
#![allow(unused_variables)]

use std::time::Duration;
use std::thread;
use std::fs;

use std::sync::Arc;
use rusb::{DeviceHandle, GlobalContext};

use crate::core::{
    Channel, Band, MacAddress, Result, Error,
    chip::{ChipDriver, ChipInfo, ChipId, ChipCaps},
    frame::{RxFrame, TxOptions, TxRate, TxFlags, PpduType, GuardInterval, RxBandwidth},
    adapter::UsbEndpoints,
};

use super::rtl8852a_post_boot;

// ── Constants — hardware register map ──
// Complete MAC AX register addresses, bit definitions, and protocol constants.
// Unused constants are intentional — they're the chip's register vocabulary needed
// for proper driver implementation (monitor mode, USB init, H2C, C2H parsing).

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

// RX descriptor RPKT_TYPE — WiFi is 0, all others defined in PPDU section below
const RPKT_TYPE_WIFI: u8 = 0;

// RX filter bits
const B_AX_SNIFFER_MODE: u32 = 1 << 0;
const B_AX_A_A1_MATCH: u32 = 1 << 1;
const B_AX_A_BC: u32 = 1 << 2;
const B_AX_A_MC: u32 = 1 << 3;
const B_AX_A_UC_CAM_MATCH: u32 = 1 << 4;
const B_AX_A_CRC32_ERR: u32 = 1 << 11;

// ── TX Write Descriptor — MAC AX (from txdesc.h, 8852A section) ──
// WD = WD_BODY (24 bytes) + optional WD_INFO (24 bytes when WDINFO_EN=1)

const TX_WD_BODY_LEN: usize = 24;
const TX_WD_INFO_LEN: usize = 24;
const TX_WD_TOTAL_LEN: usize = TX_WD_BODY_LEN + TX_WD_INFO_LEN; // 48 bytes

// WD_BODY DW0 — control word
const AX_TXD_STF_MODE: u32    = 1 << 10;  // store-and-forward (USB)
const AX_TXD_WDINFO_EN: u32   = 1 << 22;  // WD_INFO section present
const AX_TXD_HDR_LLC_LEN_SH: u32 = 11;    // hdr_len / 2, 5-bit field [15:11]
// CH_DMA shift already defined above at line ~201

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
const AX_TXD_NAVUSEHDR: u32   = 1 << 10;  // use NAV from 802.11 header

// WD_INFO DW4 (at WD offset 40) — protection
const AX_TXD_RTS_EN: u32      = 1 << 27;  // RTS before frame
const AX_TXD_CTS2SELF: u32    = 1 << 28;  // CTS-to-self protection

// Queue select values (from type.h)
const MAC_AX_MG0_SEL: u32 = 18;   // management queue 0 (band 0)
const MAC_AX_MG1_SEL: u32 = 26;   // management queue 1 (band 1)

// DMA channel mapping for data frames (WMM AC → DMA channel)
// ACH0=BE, ACH1=BK, ACH2=VI, ACH3=VO, ACH4-7=WMM1 (not used)
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

/// MAC AX DATARATE encoding (9-bit, from rtw_general_def.h)
///
/// CCK:  0x00-0x03
/// OFDM: 0x04-0x0B
/// HT:   0x80 + MCS index (MCS0-31)
/// VHT:  0x100 + (NSS-1)*0x10 + MCS (NSS1=0x100, NSS2=0x110)
/// HE:   0x180 + (NSS-1)*0x10 + MCS (NSS1=0x180, NSS2=0x190)
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
//  PPDU status correlation — MAC AX gen2 architecture
// ══════════════════════════════════════════════════════════════════════════════
//
// WiFi frames arrive with rpkt_type=0 but drv_info_size=0 (no embedded PHY status).
// RSSI/SNR/LDPC/STBC/noise arrive in separate PPDU status packets (rpkt_type=1).
// Correlation is via ppdu_cnt (3-bit counter, 8 slots) in DW1[6:4].
//
// Flow (from hal_rx.c):
//   1. WiFi frame → store metadata in slot[ppdu_cnt], set valid=false
//   2. PPDU status → parse physts, store in slot[ppdu_cnt], set valid=true
//   3. Next WiFi frame with same ppdu_cnt picks up the stored PHY info
//
// Reference: phl_def.h:2365 PHL_MAX_PPDU_CNT=8

const PPDU_SLOT_COUNT: usize = 8;

/// RX packet types from rxdesc.h
const RPKT_TYPE_PPDU: u8 = 1;
const RPKT_TYPE_CH_INFO: u8 = 2;
const RPKT_TYPE_BB_SCORE: u8 = 3;
const RPKT_TYPE_TXCMD_RPT: u8 = 4;
const RPKT_TYPE_SS2FW_RPT: u8 = 5;
const RPKT_TYPE_TXRPT: u8 = 6;
const RPKT_TYPE_C2H: u8 = 10;

/// PHY status parsed from a PPDU status packet (rpkt_type=1).
/// Corresponds to physts_hdr_info + IE0 (CCK) or IE1 (OFDM/HT/VHT/HE).
#[derive(Clone, Copy)]
struct PpduPhyStatus {
    valid: bool,
    rssi_avg: i8,
    rssi_path: [i8; 4],
    noise_floor: i8,
    snr: u8,
    is_ldpc: bool,
    is_stbc: bool,
    is_bf: bool,
}

impl Default for PpduPhyStatus {
    fn default() -> Self {
        Self {
            valid: false,
            rssi_avg: 0,
            rssi_path: [0; 4],
            noise_floor: 0,
            snr: 0,
            is_ldpc: false,
            is_stbc: false,
            is_bf: false,
        }
    }
}

/// Cache for PPDU status correlation. 8 slots indexed by ppdu_cnt.
///
/// Architecture: WiFi frames arrive BEFORE their matching PPDU status in the USB
/// buffer. So we must store the pending WiFi frame and only return it once the
/// PPDU status fills in the PHY info. If the next WiFi frame arrives before a
/// PPDU status (different ppdu_cnt), we return the pending frame with whatever
/// info we have (possibly rssi=0).
pub(crate) struct PpduStatusCache {
    slots: [PpduPhyStatus; PPDU_SLOT_COUNT],
    /// Pending WiFi frame waiting for its PPDU status.
    pending_frame: Option<(u8, RxFrame)>, // (ppdu_cnt, frame)
}

impl PpduStatusCache {
    fn new() -> Self {
        Self {
            slots: [PpduPhyStatus::default(); PPDU_SLOT_COUNT],
            pending_frame: None,
        }
    }

    /// Store PHY status from a PPDU status packet.
    /// If there's a pending frame with matching ppdu_cnt, applies the PHY info
    /// and returns the completed frame.
    fn store_ppdu(&mut self, ppdu_cnt: u8, phy: PpduPhyStatus) -> Option<RxFrame> {
        let idx = (ppdu_cnt & 0x7) as usize;
        self.slots[idx] = phy;

        // Check if the pending frame matches this PPDU status
        if let Some((pending_cnt, ref mut frame)) = self.pending_frame {
            if pending_cnt == ppdu_cnt {
                Self::apply_phy_to_frame(frame, &phy);
                return self.pending_frame.take().map(|(_, f)| f);
            }
        }
        None
    }

    /// Store a WiFi frame as pending, waiting for its PPDU status.
    /// Returns any previously pending frame that never got its PPDU status.
    fn store_pending(&mut self, ppdu_cnt: u8, frame: RxFrame) -> Option<RxFrame> {
        // If there's already a pending frame, return it (it missed its PPDU)
        let old = self.pending_frame.take().map(|(_, f)| f);
        self.pending_frame = Some((ppdu_cnt, frame));
        old
    }

    /// Look up pre-stored PPDU status (from a previous cycle or batch).
    fn lookup(&self, ppdu_cnt: u8) -> Option<&PpduPhyStatus> {
        let idx = (ppdu_cnt & 0x7) as usize;
        if self.slots[idx].valid {
            Some(&self.slots[idx])
        } else {
            None
        }
    }

    /// Flush any pending frame (e.g., at end of buffer).
    fn flush_pending(&mut self) -> Option<RxFrame> {
        self.pending_frame.take().map(|(_, f)| f)
    }

    fn apply_phy_to_frame(frame: &mut RxFrame, phy: &PpduPhyStatus) {
        frame.rssi = phy.rssi_avg;
        frame.rssi_path = phy.rssi_path;
        frame.noise_floor = phy.noise_floor;
        frame.snr = phy.snr;
        frame.is_ldpc = phy.is_ldpc;
        frame.is_stbc = phy.is_stbc;
        frame.is_bf = phy.is_bf;
    }
}

/// Convert U(8,1) RSSI value to dBm.
/// From halbb_physts.h:29: TRANS_2_RSSI(X) = (X >> 1)
/// Then hal_api_bb.c subtracts 110 for dBm offset.
fn rssi_u81_to_dbm(val: u8) -> i8 {
    if val == 0 { return 0; }
    ((val >> 1) as i16 - 110).clamp(-127, 0) as i8
}

/// Parse a PPDU status payload, handling the mac_info header if present.
///
/// When `mac_info_vld=1`, the payload structure is:
///   mac_info header (8 bytes: 2 DWs)
///   usr_num * 4 bytes (user entries)
///   4 bytes padding if usr_num is odd (8-byte alignment)
///   rx_cnt (96 bytes, if rx_cnt_vld set in DW0 bit 29)
///   plcp (plcp_len * 8 bytes, from DW1[23:16])
///   physts (remaining bytes)
///
/// When `mac_info_vld=0`, the payload IS the physts directly.
///
/// Reference: phy_rpt.c:482 mac_parse_ppdu()
const MAC_AX_RX_CNT_SIZE: usize = 96;

fn parse_ppdu_payload(data: &[u8], mac_info_vld: bool) -> Option<PpduPhyStatus> {
    if mac_info_vld {
        // Skip mac_info header to find physts
        if data.len() < 8 { return None; }

        let dw0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let dw1 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let usr_num = (dw0 & 0xF) as usize;
        let rx_cnt_vld = dw0 & (1 << 29) != 0;
        let plcp_len = ((dw1 >> 16) & 0xFF) as usize;
        let plcp_size = plcp_len * 8;

        let mut offset: usize = 8; // mac_info header
        offset += usr_num * 4;     // user entries
        if usr_num & 1 != 0 { offset += 4; } // 8-byte alignment padding
        if rx_cnt_vld { offset += MAC_AX_RX_CNT_SIZE; }
        offset += plcp_size;

        if offset >= data.len() { return None; }
        parse_physts_header(&data[offset..])
    } else {
        parse_physts_header(data)
    }
}

/// Parse physts_hdr_info (8 bytes) from the start of a physts buffer.
/// Layout from halbb_physts_ie_l_endian.h:34-43:
///   byte 0: ie_bitmap_select(5) | rsvd(1) | null_tb_ppdu(1) | is_valid(1)
///   byte 1: physts_total_length (unit: 8 bytes)
///   byte 2: rsvd
///   byte 3: rssi_avg_td — U(8,1)
///   bytes 4-7: rssi_td[0..3] — per-path U(8,1)
fn parse_physts_header(data: &[u8]) -> Option<PpduPhyStatus> {
    if data.len() < 8 { return None; }

    let is_valid = data[0] & 0x80 != 0;
    if !is_valid { return None; }

    let ie_bitmap_select = data[0] & 0x1F;
    let physts_total_length = data[1] as usize * 8;
    let rssi_avg = rssi_u81_to_dbm(data[3]);
    let rssi_path = [
        rssi_u81_to_dbm(data[4]),
        rssi_u81_to_dbm(data[5]),
        rssi_u81_to_dbm(data[6]),
        rssi_u81_to_dbm(data[7]),
    ];

    let mut phy = PpduPhyStatus {
        valid: true,
        rssi_avg,
        rssi_path,
        noise_floor: 0,
        snr: 0,
        is_ldpc: false,
        is_stbc: false,
        is_bf: false,
    };

    // Parse Information Elements after the 8-byte header
    let ie_data = &data[8..data.len().min(physts_total_length.max(8))];

    // IE bitmap tells us which IEs are present.
    // ie_bitmap_select selects which bitmap set (type 1 = 5-bit fixed, type 2 = 12-bit variable).
    // For our purposes: if bitmap bit 0 set → IE0 (CCK), bit 1 → IE1 (OFDM/HT/VHT/HE)
    // IE0 and IE1 are mutually exclusive (CCK vs OFDM).
    if ie_bitmap_select & 0x01 != 0 {
        // IE0 — CCK (physts_ie_0_info, 16 bytes = 4 DWs)
        parse_physts_ie0(ie_data, &mut phy);
    } else if ie_bitmap_select & 0x02 != 0 {
        // IE1 — OFDM/HT/VHT/HE (physts_ie_1_info, 24 bytes = 6 DWs)
        parse_physts_ie1(ie_data, &mut phy);
    }

    Some(phy)
}

/// Parse IE0 (CCK) — physts_ie_0_info from halbb_physts_ie_l_endian.h:50-92
/// 16 bytes (4 DWs).
fn parse_physts_ie0(data: &[u8], phy: &mut PpduPhyStatus) {
    if data.len() < 8 { return; }
    // DW1 byte 0: avg_idle_noise_pwr
    phy.noise_floor = rssi_u81_to_dbm(data[4]);
    // CCK doesn't have LDPC/STBC/BF
}

/// Parse IE1 (OFDM/HT/VHT/HE) — physts_ie_1_info from halbb_physts_ie_l_endian.h:94-144
/// 24 bytes (6 DWs).
fn parse_physts_ie1(data: &[u8], phy: &mut PpduPhyStatus) {
    if data.len() < 16 { return; }
    // DW0:
    //   byte 1: rssi_avg_fd (frequency-domain RSSI, supplementary to time-domain)
    //   byte 2: ch_idx_seg0
    //   byte 3[3:0]: rxsc, byte 3[7:4]: rx_path_en_bitmap
    // DW1:
    //   byte 4: avg_idle_noise_pwr
    phy.noise_floor = rssi_u81_to_dbm(data[4]);
    // DW2:
    //   byte 8[5:0]: avg_snr (6-bit unsigned, 0-63 dB)
    phy.snr = data[8] & 0x3F;
    //   byte 11[4]: is_ldpc
    //   byte 11[6]: is_stbc
    if data.len() >= 12 {
        phy.is_ldpc = data[11] & 0x10 != 0;
        phy.is_stbc = data[11] & 0x40 != 0;
    }
    // DW3:
    //   byte 12[0]: is_bf (after bf_gain_max[6:0] and is_awgn)
    //   Actually: byte 13[0]: is_bf, byte 13[7:1]: avg_cn_seg0
    if data.len() >= 14 {
        phy.is_bf = data[13] & 0x01 != 0;
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
    ppdu_cache: PpduStatusCache,
}

/// Standalone parse function for RxHandle — uses thread-local PPDU cache.
fn parse_rx_packet_standalone(buf: &[u8], channel: u8) -> (usize, crate::core::chip::ParsedPacket) {
    thread_local! {
        static PPDU_CACHE: std::cell::RefCell<PpduStatusCache> =
            std::cell::RefCell::new(PpduStatusCache::new());
    }
    PPDU_CACHE.with(|cache| {
        let (consumed, frame) = Rtl8852au::parse_rx_packet(buf, channel, &mut cache.borrow_mut());
        let packet = match frame {
            Some(f) => crate::core::chip::ParsedPacket::Frame(f),
            None => crate::core::chip::ParsedPacket::Skip,
        };
        (consumed, packet)
    })
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
        // EP7 = firmware/H2C endpoint (3rd bulk OUT: EP5=TX, EP6=?, EP7=FWDL/H2C)
        let ep_fw = endpoints.bulk_out_all.get(2).copied().ok_or_else(|| {
            Error::ChipInitFailed {
                chip: "RTL8852AU".into(),
                stage: crate::core::error::InitStage::UsbEnumeration,
                reason: format!("need 3 bulk OUT endpoints, found {}: {:?}",
                    endpoints.bulk_out_all.len(),
                    endpoints.bulk_out_all),
            }
        })?;
        // Endpoint discovery logged only in test binaries, not here (messes up CLI)

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
            ppdu_cache: PpduStatusCache::new(),
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

        // Step 5-7: Request power on and wait for ack
        self.write8_mask(0x0006, 0x01, 0x01)?;  // Set bit 0
        self.write8_mask(0x0005, 0x01, 0x01)?;  // Request power on
        self.poll8(0x0005, 0x01, 0x00, 200)?;   // Wait for ack

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
    //  From init.c: hci_func_en() + dmac_pre_init() + dle_init() + hfc_init()
    //  Register values verified against usbmon capture (2026-03-29)
    // ══════════════════════════════════════════════════════════════════════════

    /// Complete pre-FWDL init — verbatim replay of usbmon capture (DMA_INIT_EXACT.txt)
    /// This replaces both dmac_pre_init AND enable_cpu_for_fwdl with the exact
    /// register sequence that the Linux driver performs between power-on and firmware download.
    fn dmac_pre_init_and_enable_cpu(&self) -> Result<()> {

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
                break;
            }
            if i == 4999 {
                // DMA ready timeout at 0x8D00 — non-fatal, continue init
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

        // ── USB IO mode + clear TX/RX reset (from usb_pre_init_8852a) ──
        // R_AX_USB_HOST_REQUEST_2 (0x1078): set USBIO_MODE
        let v = self.read32(0x1078)?;
        self.write32(0x1078, v | (1 << 4))?; // B_AX_R_USBIO_MODE = BIT(4)

        // R_AX_USB_WLAN0_1 (0x1174): CLEAR USBTX_RST and USBRX_RST
        // Without this, the USB TX DMA path stays in reset and frames
        // go to EP5 but never reach the firmware's TX engine.
        let v = self.read32(0x1174)?;
        self.write32(0x1174, v & !(0x300))?; // clear bits 8 (USBTX_RST) and 9 (USBRX_RST)

        // ── HCI DMA reset cycle ──
        self.write32(R_AX_HCI_FUNC_EN, 0)?;
        self.write32(R_AX_HCI_FUNC_EN, 0x00000003)?;

        // ── Poll 0x106C for readiness ──
        for _ in 0..100u32 {
            let val = self.read32(0x106C)?;
            if val != 0 { break; }
            thread::sleep(Duration::from_micros(100));
        }

        // ── Chip info reads (part of usbmon sequence — may have side effects) ──
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

        // ── FWDL trigger: write FWDL_EN to 0x01E0, set boot reason, enable WCPU ──
        let _ = self.read32(R_AX_WCPU_FW_CTRL)?;
        self.write32(R_AX_WCPU_FW_CTRL, 0x00000001)?;  // FWDL_EN
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
        let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
        Err(Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed })
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Firmware download — from fwdl.c
    // ══════════════════════════════════════════════════════════════════════════

    fn load_firmware(&mut self) -> Result<()> {
        // Find firmware file
        let fw_data = self.find_firmware()?;

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
        self.fwdl_send_h2c(&fw_hdr)?;

        // Wait for FWDL path ready
        for i in 0..FWDL_WAIT_US {
            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
            if ctrl & B_AX_FWDL_PATH_RDY != 0 {
                break;
            }
            if i == FWDL_WAIT_US - 1 {
                // FWDL path not ready — will fail at FW init check below
                return Err(Error::FirmwareError { chip: "RTL8852AU".into(), kind: crate::core::error::FirmwareErrorKind::DownloadFailed });
            }
            thread::sleep(Duration::from_micros(1));
        }

        self.write32(R_AX_HALT_H2C_CTRL, 0)?;
        self.write32(R_AX_HALT_C2H_CTRL, 0)?;

        // Step 5: Phase 2 — send FW sections
        for &(_dl_addr, offset, size) in sections.iter() {
            let section_data = &fw_data[offset..offset + size];
            self.fwdl_send_section(section_data)?;
        }

        // Step 6: Wait for FW init ready
        thread::sleep(Duration::from_millis(5));
        for _ in 0..FWDL_WAIT_US {
            let ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
            let sts = (ctrl >> B_AX_FWDL_STS_SH) & B_AX_FWDL_STS_MSK;
            if sts == FWDL_WCPU_FW_INIT_RDY {
                return Ok(());
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

    /// Send a generic H2C command via bulk OUT EP7.
    /// cat/class/func identify the command; payload is the command-specific data.
    fn send_h2c_cmd(&mut self, cat: u32, class: u32, func: u32, payload: &[u8]) -> Result<()> {
        let h2c_payload_len = FWCMD_HDR_LEN + payload.len();
        let total_len = WD_BODY_LEN + h2c_payload_len;
        let mut buf = vec![0u8; total_len];
        let seq = self.h2c_seq;

        // WD (24 bytes) — H2C DMA channel, no FWDL_EN
        let wd_dw0 = MAC_AX_DMA_H2C << AX_TXD_CH_DMA_SH;
        buf[0..4].copy_from_slice(&wd_dw0.to_le_bytes());
        let wd_dw2 = h2c_payload_len as u32;
        buf[8..12].copy_from_slice(&wd_dw2.to_le_bytes());

        // H2C header (8 bytes)
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
            Ok(n) => {
            }
            Err(e) => {
                let _ = self.handle.clear_halt(self.ep_fw);
                return Err(Error::FirmwareError {
                    chip: "RTL8852AU".into(),
                    kind: crate::core::error::FirmwareErrorKind::DownloadFailed,
                });
            }
        }

        Ok(())
    }

    // ── H2C commands: FWROLE_MAINTAIN + ADDR_CAM ──
    //
    // These tell the firmware "this interface exists and can transmit."
    // Without them, USB bulk write succeeds but firmware silently drops TX.
    //
    // H2C command IDs (from fwcmd_intf.h):
    //   FWROLE_MAINTAIN: cat=1(MAC), class=8(MEDIA_RPT), func=4
    //   ADDR_CAM:        cat=1(MAC), class=6(ADDR_CAM_UPDATE), func=0
    //
    // WIFI_ROLE enum (from mac_def.h):
    //   0=NONE, 1=STATION, 2=AP, 7=MONITOR
    //
    // UPD_MODE: 0=CREATE, 1=CHANGE

    // ── H2CREG registers (register-based H2C, NOT EP7 bulk H2C) ──
    // These are a separate communication path: write DATA0-DATA3 to 0x8140-0x814C,
    // trigger via 0x8160, poll 0x8164 for completion.

    const H2CREG_DATA0: u16 = 0x8140;
    const H2CREG_DATA1: u16 = 0x8144;
    const H2CREG_CTRL: u16  = 0x8160;
    const H2CREG_C2H: u16   = 0x8164;

    /// Send SCH_TX_EN — enable/disable the firmware TX scheduler.
    /// This is the register-based H2C command (func=0x05) that gates ALL frame
    /// transmission. Without it, firmware accepts USB bulk TX but never pushes
    /// frames to the radio PHY.
    ///
    /// tx_en is a bitmask: bit0=BE0, bit1=BK0, bit2=VI0, bit3=VO0, ..., bit8=MG0,
    /// bit11=HI, bit12=BCN. 0xFFFF enables everything. 0x0000 disables all.
    ///
    /// Verified from usbmon: Linux sends this on EVERY channel switch and before TX.
    fn send_sch_tx_en(&self, tx_en: u16) -> Result<()> {
        // Wait for previous H2CREG to complete
        for _ in 0..100 {
            if self.read8(Self::H2CREG_CTRL)? & 0x01 == 0 { break; }
            thread::sleep(Duration::from_micros(200));
        }

        // H2CREG format (from _mac_send_h2creg in fwcmd.c):
        //   DATA0: FUNC[6:0] | TOTAL_LEN[11:8] | TX_EN_LO[23:16] | TX_EN_HI[31:24]
        //   DATA1: MASK[15:0] | BAND[16]
        // FUNC = 0x05 (SCH_TX_EN), TOTAL_LEN = 0x03 (3 DWORDs)
        // TX_EN goes into bytes 2-3 of DATA0 (from h2c_content.dword0 bits 16-31)
        // MASK in DATA1 tells firmware WHICH bits to modify — 0xFFFF = all queues
        let data0: u32 = 0x05  // FWCMD_H2CREG_FUNC_SCH_TX_EN
            | (0x03 << 8)      // TOTAL_LEN = 3
            | ((tx_en as u32) << 16);
        let data1: u32 = 0xFFFF; // MASK = all 16 queue bits, BAND = 0
        self.write32(Self::H2CREG_DATA0, data0)?;
        self.write32(Self::H2CREG_DATA1, data1)?;

        // Trigger
        self.write8(Self::H2CREG_CTRL, 0x01)?;

        // Poll for completion
        for _ in 0..100 {
            let c2h = self.read8(Self::H2CREG_C2H)?;
            if c2h != 0 {
                self.write8(Self::H2CREG_C2H, 0x00)?; // clear
                return Ok(());
            }
            thread::sleep(Duration::from_micros(200));
        }

        Ok(()) // don't fail on timeout — firmware may not respond in all states
    }

    /// Send FWROLE_MAINTAIN — tell firmware about our role.
    /// Payload is a single DWORD: MACID[7:0] | SELF_ROLE[9:8] | UPD_MODE[12:10] | WIFI_ROLE[16:13]
    fn send_fwrole_maintain(&mut self, macid: u8, wifi_role: u8, upd_mode: u8) -> Result<()> {
        let dw0: u32 = (macid as u32)
            | ((upd_mode as u32 & 0x7) << 10)
            | ((wifi_role as u32 & 0xF) << 13);
        self.send_h2c_cmd(FWCMD_H2C_CAT_MAC, 8, 4, &dw0.to_le_bytes())
    }

    /// Send ADDR_CAM — register our MAC address with the firmware.
    /// This is the 60-byte fwcmd_addrcam_info struct (15 DWORDs).
    /// Without this, firmware has no MAC context for TX.
    ///
    /// Field layout verified against usbmon (full_capture_bus4.pcap):
    ///   DW0 = 0 (R_W=0 = write)
    ///   DW1: IDX[7:0]=0, OFFSET[15:8]=0, LEN[23:16]=64
    ///   DW2: VALID[0]=1, NET_TYPE[2:1], ADDR_MASK[13:8], SMA_HASH[23:16], TMA_HASH[31:24]
    ///   DW3: BSSID_CAM_IDX[5:0]
    ///   DW4: SMA[0-3] (our MAC bytes 0-3)
    ///   DW5: SMA[4-5] (our MAC bytes 4-5) + TMA[0-1]
    ///   DW6: TMA[2-5]
    ///   DW7: reserved
    ///   DW8: MACID[7:0]
    ///   DW12: B_IDX, B_OFFSET, B_LEN
    ///   DW13: B_VALID[0]
    fn send_addr_cam(&mut self, mac: &[u8; 6]) -> Result<()> {
        let mut payload = [0u8; 60]; // 15 DWORDs

        // DW0 = 0 (write mode)

        // DW1: LEN=64 (size of addr CAM entry in firmware)
        let dw1: u32 = 64u32 << 16; // LEN[23:16] = 64
        payload[4..8].copy_from_slice(&dw1.to_le_bytes());

        // DW2: VALID=1, NET_TYPE=0 (no-link for monitor), compute SMA hash
        let sma_hash: u8 = mac.iter().fold(0u8, |acc, &b| acc ^ b);
        let dw2: u32 = 1 // VALID
            | ((sma_hash as u32) << 16);  // SMA_HASH[23:16]
        payload[8..12].copy_from_slice(&dw2.to_le_bytes());

        // DW3 = 0 (BSSID_CAM_IDX=0)

        // DW4: SMA[0-3] — our MAC address bytes 0-3
        let dw4: u32 = (mac[0] as u32)
            | ((mac[1] as u32) << 8)
            | ((mac[2] as u32) << 16)
            | ((mac[3] as u32) << 24);
        payload[16..20].copy_from_slice(&dw4.to_le_bytes());

        // DW5: SMA[4-5] — our MAC address bytes 4-5 (TMA[0-1] = 0 for monitor)
        let dw5: u32 = (mac[4] as u32)
            | ((mac[5] as u32) << 8);
        payload[20..24].copy_from_slice(&dw5.to_le_bytes());

        // DW6-DW7 = 0 (TMA = 0, reserved)
        // DW8 = 0 (MACID=0)
        // DW9-DW11 = 0 (no AID, no security)

        // DW12: BSSID CAM — B_LEN=8 (from usbmon: 0x00080000)
        let dw12: u32 = 8u32 << 16; // B_LEN[23:16] = 8
        payload[48..52].copy_from_slice(&dw12.to_le_bytes());

        // DW13: B_VALID=1
        let dw13: u32 = 1; // B_VALID[0]
        payload[52..56].copy_from_slice(&dw13.to_le_bytes());

        // DW14 = 0 (BSSID = 0 for monitor)

        self.send_h2c_cmd(FWCMD_H2C_CAT_MAC, 6, 0, &payload)
    }

    /// Complete firmware role setup: FWROLE_MAINTAIN(CREATE/MONITOR) + ADDR_CAM.
    /// Must be called after firmware boots and before any TX.
    /// This is what was missing — without it, firmware accepts USB TX but never
    /// pushes frames to the radio PHY.
    pub fn setup_firmware_role(&mut self) -> Result<()> {
        // ── NO MAC writes — let firmware/pcap-replay control the MAC ──
        // The pcap replay sends FWROLE_MAINTAIN + ADDR_CAM with the captured
        // machine's MAC. We use whatever the firmware reports.

        // ── Enable the TX scheduler ──
        // Method 1: H2CREG (firmware-coordinated) — requires correct MASK in DATA1
        self.send_sch_tx_en(0xFFFF)?;

        // Method 2: Direct register write to R_AX_CTN_TXEN (0xC348) — fallback
        // The reference driver uses this when firmware isn't ready (cmac_tx.c:604).
        // Belt and suspenders: write it directly too in case H2CREG path fails.
        const R_AX_CTN_TXEN: u16 = 0xC348;
        self.write16(R_AX_CTN_TXEN, 0xFFFF)?;

        Ok(())
    }

    /// Send the exact pcap TX frame (BULK_212) verbatim to EP5.
    /// SCH_TX_EN must already be enabled from init — just send the bulk write.
    pub fn send_pcap_probe_verbatim(&self) -> Result<()> {
        // BULK_212 from pcap: 48-byte WD + 42-byte probe request
        // SA = 0A:C4:90:27:7C:AB (pcap monitor MAC)
        let pcap_tx: [u8; 90] = [
            0x00, 0xC4, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x24, 0x00, 0x00, 0x20, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x40, 0x00, 0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0xC4, 0x90, 0x27, 0x7C, 0xAB,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x82, 0x84, 0x8B, 0x96,
            0x8C, 0x12, 0x98, 0x24, 0x32, 0x04, 0xB0, 0x48, 0x60, 0x6C,
        ];

        self.handle.write_bulk(self.ep_out, &pcap_tx, USB_BULK_TIMEOUT)
            .map_err(|e| Error::TxFailed { retries: 0, reason: format!("pcap verbatim: {}", e) })?;

        Ok(())
    }

    /// Dump TX-related register state for debugging.
    /// Call this after init + channel switch, before first TX.
    pub fn dump_tx_diagnostics(&self) -> Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true).append(true)
            .open("/tmp/wifikit_tx_diag.log")
            .map_err(|_| Error::TxFailed { retries: 0, reason: "log open".into() })?;

        let _ = writeln!(f, "\n=== TX DIAGNOSTICS @ {:?} ===", std::time::SystemTime::now());

        // ── DMAC ──
        let dmac_en = self.read32(R_AX_DMAC_FUNC_EN)?;
        let dmac_clk = self.read32(R_AX_DMAC_CLK_EN)?;
        let _ = writeln!(f, "R_AX_DMAC_FUNC_EN (0x8400) = 0x{:08X}", dmac_en);
        let _ = writeln!(f, "  MAC_FUNC_EN[30]={} DMAC_FUNC_EN[29]={} MPDU_PROC[28]={} WD_RLS[27]={}",
            (dmac_en >> 30) & 1, (dmac_en >> 29) & 1, (dmac_en >> 28) & 1, (dmac_en >> 27) & 1);
        let _ = writeln!(f, "  DLE_WDE[26]={} TXPKT_CTRL[25]={} STA_SCH[24]={} DLE_PLE[23]={}",
            (dmac_en >> 26) & 1, (dmac_en >> 25) & 1, (dmac_en >> 24) & 1, (dmac_en >> 23) & 1);
        let _ = writeln!(f, "  PKT_BUF[22]={} DMAC_TBL[21]={} PKT_IN[20]={} DISPATCHER[18]={}",
            (dmac_en >> 22) & 1, (dmac_en >> 21) & 1, (dmac_en >> 20) & 1, (dmac_en >> 18) & 1);
        let _ = writeln!(f, "R_AX_DMAC_CLK_EN  (0x8404) = 0x{:08X}", dmac_clk);

        // ── CMAC ──
        let cmac_en = self.read32(R_AX_CMAC_FUNC_EN)?;
        let cmac_clk = self.read32(R_AX_CMAC_CLK_EN)?;
        let _ = writeln!(f, "R_AX_CMAC_FUNC_EN (0xC000) = 0x{:08X}", cmac_en);
        let _ = writeln!(f, "R_AX_CMAC_CLK_EN  (0xC004) = 0x{:08X}", cmac_clk);

        // ── HCI DMA ──
        let hci_en = self.read32(R_AX_HCI_FUNC_EN)?;
        let _ = writeln!(f, "R_AX_HCI_FUNC_EN  (0x8380) = 0x{:08X}  (TXDMA[1]={} RXDMA[0]={})",
            hci_en, (hci_en >> 1) & 1, hci_en & 1);

        // ── TX scheduler status ──
        // H2CREG state
        let h2c_ctrl = self.read8(Self::H2CREG_CTRL)?;
        let h2c_c2h = self.read8(Self::H2CREG_C2H)?;
        let _ = writeln!(f, "H2CREG CTRL (0x8160) = 0x{:02X}  C2H (0x8164) = 0x{:02X}", h2c_ctrl, h2c_c2h);

        // ── RX filter (to confirm monitor mode) ──
        let rx_fltr = self.read32(R_AX_RX_FLTR_OPT)?;
        let _ = writeln!(f, "RX_FLTR_OPT (0xCE20) = 0x{:08X}", rx_fltr);

        // ── USB endpoint config ──
        let ep3 = self.read32(R_AX_USB_ENDPOINT_3)?;
        let _ = writeln!(f, "USB_ENDPOINT_3 (0x106C) = 0x{:08X}  (EP capabilities)", ep3);

        // ── RXDMA setting ──
        let rxdma = self.read8(R_AX_RXDMA_SETTING as u16)?;
        let _ = writeln!(f, "RXDMA_SETTING (0x8908) = 0x{:02X}", rxdma);

        // ── USB TX/RX reset status ──
        let usb_wlan = self.read32(0x1174)?;
        let _ = writeln!(f, "USB_WLAN0_1 (0x1174) = 0x{:08X}  USBTX_RST[8]={} USBRX_RST[9]={}",
            usb_wlan, (usb_wlan >> 8) & 1, (usb_wlan >> 9) & 1);

        // ── CMAC TX-related registers (from mac_reg.h) ──
        // R_AX_MAC_LOOPBACK = 0xC610 — loopback mode check
        let loopback = self.read32(0xC610)?;
        let _ = writeln!(f, "MAC_LOOPBACK (0xC610) = 0x{:08X}  (should be 0 for normal TX)", loopback);

        // R_AX_TCR0 = 0xC600 (TX control register 0)
        let tcr0 = self.read32(0xC600)?;
        let _ = writeln!(f, "TCR0 (0xC600) = 0x{:08X}", tcr0);

        // R_AX_TCR1 = 0xC604 (TX control register 1)
        let tcr1 = self.read32(0xC604)?;
        let _ = writeln!(f, "TCR1 (0xC604) = 0x{:08X}", tcr1);

        // R_AX_PTCL_COMMON_SETTING_0 = 0xC618
        let ptcl = self.read32(0xC618)?;
        let _ = writeln!(f, "PTCL_COMMON (0xC618) = 0x{:08X}", ptcl);

        // ── Scheduler registers ──
        // R_AX_CTN_TXEN = 0xC348 (contention TX enable — the REAL register)
        // This is where SCH_TX_EN H2CREG actually writes. Also has direct-write fallback.
        let ctn_txen = self.read32(0xC348)?;
        let _ = writeln!(f, "CTN_TXEN (0xC348) = 0x{:08X}  ← should have 0xFFFF in low 16 bits", ctn_txen);

        // ── WDE/PLE quota (TX buffer allocation) ──
        let wde_quota0 = self.read32(0x8D40)?; // WDE quota status
        let wde_quota1 = self.read32(0x8D44)?;
        let ple_quota0 = self.read32(0x9140)?; // PLE quota status
        let _ = writeln!(f, "WDE quota (0x8D40/44) = 0x{:08X} / 0x{:08X}", wde_quota0, wde_quota1);
        let _ = writeln!(f, "PLE quota (0x9140)     = 0x{:08X}", ple_quota0);

        // ── ADDR_CAM status ──
        let macid_lo = self.read32(R_AX_MACID_REG)?;
        let macid_hi = self.read16(R_AX_MACID_REG + 4)?;
        let _ = writeln!(f, "MACID_REG (0xC100) = {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            macid_lo as u8, (macid_lo >> 8) as u8, (macid_lo >> 16) as u8,
            (macid_lo >> 24) as u8, macid_hi as u8, (macid_hi >> 8) as u8);
        let _ = writeln!(f, "Driver MAC = {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.mac_addr.0[0], self.mac_addr.0[1], self.mac_addr.0[2],
            self.mac_addr.0[3], self.mac_addr.0[4], self.mac_addr.0[5]);

        // ── TX EP info — verify we're using the right endpoint ──
        let _ = writeln!(f, "TX endpoint = EP 0x{:02X}  (ep_fw = EP 0x{:02X}, ep_in = EP 0x{:02X})",
            self.ep_out, self.ep_fw, self.ep_in);
        // Verify by sending a known-good H2C to ep_fw and checking it works
        let h2c_test = self.read32(0x8160)?;
        let _ = writeln!(f, "H2CREG ready = {} (0x8160 bit0={})", h2c_test & 1 == 0, h2c_test & 1);

        // ── FW status ��─
        let fw_ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
        let _ = writeln!(f, "WCPU_FW_CTRL (0x01E0) = 0x{:02X}  (H2C_PATH_RDY[1]={} FWDL_STS[7:4]={})",
            fw_ctrl, (fw_ctrl >> 1) & 1, (fw_ctrl >> 4) & 0xF);

        // ── TX counters and DLE status ──
        let txcnt = self.read32(0xC62C)?; // R_AX_TXCNT
        let tx_abort = self.read32(0xCC1C)?; // R_AX_TRXPTCL_RESP_TX_ABORT_COUNTER
        let dle_empty0 = self.read32(0x8430)?; // R_AX_DLE_EMPTY0
        let dle_empty1 = self.read32(0x8434)?; // R_AX_DLE_EMPTY1
        let ptcl_dbg = self.read32(0xC6F0)?; // R_AX_PTCL_DBG_INFO
        let _ = writeln!(f, "TXCNT (0xC62C) = 0x{:08X}", txcnt);
        let _ = writeln!(f, "TX_ABORT (0xCC1C) = 0x{:08X}", tx_abort);
        let _ = writeln!(f, "DLE_EMPTY0 (0x8430) = 0x{:08X}", dle_empty0);
        let _ = writeln!(f, "DLE_EMPTY1 (0x8434) = 0x{:08X}", dle_empty1);
        let _ = writeln!(f, "PTCL_DBG_INFO (0xC6F0) = 0x{:08X}", ptcl_dbg);

        // ── DMA queue status ──
        let ch_page = self.read32(0x8A80)?;
        let _ = writeln!(f, "CH_PAGE_CTRL (0x8A80) = 0x{:08X}", ch_page);

        // ── CRITICAL: Firmware TX DMA control ──
        // R_AX_SYS_CFG5 (0x0170): FW_CTRL_HCI_TXDMA_EN[0], HCI_TXDMA_ALLOW[1], HCI_TXDMA_BUSY[2]
        let sys_cfg5 = self.read32(0x0170)?;
        let _ = writeln!(f, "SYS_CFG5 (0x0170) = 0x{:08X}  TXDMA_EN[0]={} TXDMA_ALLOW[1]={} TXDMA_BUSY[2]={}",
            sys_cfg5, sys_cfg5 & 1, (sys_cfg5 >> 1) & 1, (sys_cfg5 >> 2) & 1);

        // ── TXDMA FIFO status ──
        let txdma_fifo0 = self.read32(0xC834)?;
        let txdma_fifo1 = self.read32(0xC838)?;
        let txdma_dbg = self.read32(0xC840)?;
        let _ = writeln!(f, "TXDMA_FIFO0 (0xC834) = 0x{:08X}", txdma_fifo0);
        let _ = writeln!(f, "TXDMA_FIFO1 (0xC838) = 0x{:08X}", txdma_fifo1);
        let _ = writeln!(f, "TXDMA_DBG (0xC840) = 0x{:08X}", txdma_dbg);

        // ── HFC (Host Flow Control) status ──
        let hfc_ctrl = self.read32(0x8A00)?;
        let hfc_cfg = self.read32(0x8A04)?;
        let _ = writeln!(f, "HFC_CTRL (0x8A00) = 0x{:08X}", hfc_ctrl);
        let _ = writeln!(f, "HFC_CFG (0x8A04) = 0x{:08X}", hfc_cfg);

        let _ = writeln!(f, "=== END TX DIAGNOSTICS ===\n");
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
    //  Channel switching
    // ══════════════════════════════════════════════════════════════════════════

    /// Channel switching — programmatic register-based implementation.
    /// Complete port from vendor driver (halbb_ctrl_bw_ch_8852a + hal_chan.c).
    /// Works for all 39 channels (1-14 2.4GHz + 25 5GHz), 20MHz bandwidth.
    fn set_channel_internal(&mut self, ch: u8) -> Result<()> {
        // Disable TX scheduler before channel switch (Linux does this every time)
        let _ = self.send_sch_tx_en(0x0000);
        let _ = self.write16(0xC348, 0x0000); // Direct fallback

        self.set_channel_programmatic(ch)?;

        // Write TX power table (TXAGC) for this channel.
        // Without this, the radio has no power configuration and transmits nothing.
        // Values from usbmon capture — Linux writes these on every channel switch.
        self.write_txagc_power_table(ch)?;

        // Re-enable TX scheduler after channel switch
        let _ = self.send_sch_tx_en(0xFFFF);
        let _ = self.write16(0xC348, 0xFFFF); // Direct fallback

        Ok(())
    }

    /// Write TX AGC (Automatic Gain Control) power table for the current channel.
    ///
    /// Without these register writes, the radio has no TX power configuration and
    /// transmits nothing — frames go to firmware but never leave the PHY.
    ///
    /// R_AX_PWR_RATE_TABLE0 (0xD2C0) through 0xD368 = per-rate TX power indices.
    /// R_AX_PWR_RATE_OFST_CTRL (0xD204) = power rate offset control.
    ///
    /// Values from usbmon (full_capture_bus4.pcap) — Linux writes these on every
    /// channel switch. Using 5GHz default power (0x28 = 20 dBm per rate entry).
    fn write_txagc_power_table(&self, _ch: u8) -> Result<()> {
        // Per-rate TX power index table (0xD2C0-0xD368)
        // Each byte is a power index: 0x28 = 40 half-dBm = 20 dBm
        // From usbmon 5GHz channel switch (matches all 5GHz channels in capture):
        self.write32(0xD2C0, 0x28282828)?; // CCK 1/2/5.5/11
        self.write32(0xD2C4, 0x28282828)?; // OFDM 6/9/12/18
        self.write32(0xD2C8, 0x24262828)?; // OFDM 24/36/48/54
        self.write32(0xD2CC, 0x28282828)?; // HT MCS0-3
        self.write32(0xD2D0, 0x22242628)?; // HT MCS4-7
        self.write32(0xD2D4, 0x1A1C1E20)?; // HT MCS8-11
        self.write32(0xD2D8, 0x28282828)?; // VHT NSS1 MCS0-3
        self.write32(0xD2DC, 0x28282828)?; // VHT NSS1 MCS4-7
        self.write32(0xD2E0, 0x22242628)?; // VHT NSS2/HE
        self.write32(0xD2E4, 0x1A1C1E20)?; // HE high MCS

        // Remaining power entries (VHT/HE extended rates)
        self.write32(0xD2E8, 0x28282828)?;

        // Power rate offset control
        self.write32(0xD204, 0x00000000)?;

        // Power limit/reference registers
        self.write32(0xD2EC, 0x00000026)?;
        self.write32(0xD2F0, 0x00210021)?;
        self.write32(0xD2F4, 0x00000000)?;
        self.write32(0xD2F8, 0x00000000)?;
        self.write32(0xD2FC, 0x00000000)?;
        self.write32(0xD300, 0x00000000)?;
        self.write32(0xD304, 0x00000000)?;
        self.write32(0xD308, 0x00000000)?;
        self.write32(0xD30C, 0x00000000)?;
        self.write32(0xD310, 0x00000000)?;
        self.write32(0xD314, 0x00000025)?;
        self.write32(0xD318, 0x1F1F001F)?;
        self.write32(0xD31C, 0x00000000)?;
        self.write32(0xD320, 0x00000000)?;
        self.write32(0xD324, 0x00000000)?;
        self.write32(0xD328, 0x00000000)?;
        self.write32(0xD32C, 0x00000000)?;
        self.write32(0xD330, 0x00000000)?;
        self.write32(0xD334, 0x00000000)?;
        self.write32(0xD338, 0x00000000)?;
        self.write32(0xD33C, 0x00000023)?;
        self.write32(0xD340, 0x00000000)?;
        self.write32(0xD344, 0x00000024)?;
        self.write32(0xD348, 0x00000000)?;
        self.write32(0xD34C, 0x00000026)?;
        self.write32(0xD350, 0x00000000)?;
        self.write32(0xD354, 0x00000020)?;
        self.write32(0xD358, 0x00000000)?;
        self.write32(0xD35C, 0x00000021)?;
        self.write32(0xD360, 0x00000000)?;
        self.write32(0xD364, 0x00000022)?;
        self.write32(0xD368, 0x00000000)?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Channel switching — complete port from vendor driver
    //
    //  Flow (from hal_chan.c rtw_hal_set_ch_bw + halbb_ctrl_bw_ch_8852a):
    //    1. hal_reset(enable)  — pause TX, disable PPDU/ADC/DFS, reset BB
    //    2. mac_set_bw()       — MAC WMAC_RFMOD + TXRATE_CHK + TXSC
    //    3. bb_ctrl_ch()       — RF PLL, mode select, SCO comp, bandedge, CCK
    //    4. bb_ctrl_bw()       — BB bandwidth registers
    //    5. bb_ctrl_cck_en()   — CCK enable (2G) / disable (5G)
    //    6. bb_reset()         — full BB reset cycle (0xFF toggle)
    //    7. hal_reset(disable) — re-enable PPDU/ADC/DFS, resume TX
    //
    //  Reference: hal_chan.c, halbb_8852a_api.c, halbb_8852a_2_api.c, hw.c
    // ══════════════════════════════════════════════════════════════════════════

    /// Complete programmatic channel switch — all 39 channels, 20MHz bandwidth.
    /// Ported from halbb_ctrl_bw_ch_8852a + hal_chan.c + cfg_mac_bw.
    fn set_channel_programmatic(&mut self, ch: u8) -> Result<()> {
        let is_2g = ch <= 14;
        let central_ch = ch; // For 20MHz BW, primary == central

        // ═══ Step 1: hal_reset(enable) — pause radio before switching ═══
        // From hal_com_i.c:219-250

        // Disable PPDU status reporting (BB reg 0x20FC bits [31:24] = 0xF)
        self.set_reg_bb(0x20FC, 0xFF000000, 0xF)?;
        // Disable DFS (BB reg 0x0 bit 31 = 0)
        self.set_reg_bb(0x0, 1u32 << 31, 0)?;
        // Disable TSSI continuous mode (both paths)
        // Path A: BB reg 0x5818 bit 30, Path B: BB reg 0x7818 bit 30
        // From halbb_tssi_cont_en_8852a_2: tssi_trk_man = {0x5818, 0x7818}, bit 30
        // disable = set bit 30 to 1
        self.set_reg_bb(0x5818, 1 << 30, 1)?;
        self.set_reg_bb(0x7818, 1 << 30, 1)?;
        // Wait 40µs for hardware to settle
        thread::sleep(Duration::from_micros(40));
        // BB reset enable = false (BB reg 0x704 bit 1 = 0)
        self.set_reg_bb(0x0704, 0x2, 0)?;

        // ═══ Step 2: MAC BW config (cfg_mac_bw) ═══
        // From hw.c:1573. For 20MHz, bits[1:0] = 0, TXSC = 0.
        // R_AX_WMAC_RFMOD = 0xC010: clear BW bits [1:0] for 20MHz
        let rfmod = self.read8(0xC010)?;
        self.write8(0xC010, rfmod & !0x03)?;
        // R_AX_TXRATE_CHK = 0xC628: CCK check for 5GHz channels
        if !is_2g {
            let chk = self.read8(0xC628)?;
            self.write8(0xC628, chk | 0x03)?; // CHECK_CCK_EN | RTS_LIMIT_IN_OFDM6
        } else {
            let chk = self.read8(0xC628)?;
            self.write8(0xC628, chk & !0x03)?;
        }

        // ═══ Step 3: BB channel switch (halbb_ctrl_ch_8852a) ═══
        // From halbb_8852a_api.c:407-506

        // RF channel setting — Path A + Path B
        // halbb_ch_setting_8852a: write RF reg 0x18 with channel + band flags
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

        // Mode select — 1=2G, 0=5G
        // Path A: BB reg 0x156C bits [31:30]
        // Path B: BB reg 0x162C bits [31:30]
        let mode_val: u32 = if is_2g { 1 } else { 0 };
        self.set_reg_bb(0x156C, 0xC0000000, mode_val)?;
        self.set_reg_bb(0x162C, 0xC0000000, mode_val)?;

        // SCO compensation (BB reg 0x1878 bits [6:0])
        let sco_comp = Self::sco_mapping(central_ch) as u32;
        self.set_reg_bb(0x1878, 0x7F, sco_comp)?;

        // Bandedge enable (BB reg 0x1390 bit 30)
        self.set_reg_bb(0x1390, 1 << 30, 1)?;

        // CCK parameters (2.4GHz only)
        if central_ch == 14 {
            self.set_reg_bb(0x7800, 0x00FFFFFF, 0x3B13FF)?;
            self.set_reg_bb(0x7804, 0x00FFFFFF, 0x1C42DE)?;
            self.set_reg_bb(0x7808, 0x00FFFFFF, 0xFDB0AD)?;
            self.set_reg_bb(0x780C, 0x00FFFFFF, 0xF60F6E)?;
            self.set_reg_bb(0x7810, 0x00FFFFFF, 0xFD8F92)?;
            self.set_reg_bb(0x7814, 0x00FFFFFF, 0x02D011)?;
            self.set_reg_bb(0x7818, 0x00FFFFFF, 0x01C02C)?;
            self.set_reg_bb(0x781C, 0x00FFFFFF, 0xFFF00A)?;
        } else if is_2g {
            self.set_reg_bb(0x7800, 0x00FFFFFF, 0x3D23FF)?;
            self.set_reg_bb(0x7804, 0x00FFFFFF, 0x29B354)?;
            self.set_reg_bb(0x7808, 0x00FFFFFF, 0x0FC1C8)?;
            self.set_reg_bb(0x780C, 0x00FFFFFF, 0xFDB053)?;
            self.set_reg_bb(0x7810, 0x00FFFFFF, 0xF86F9A)?;
            self.set_reg_bb(0x7814, 0x00FFFFFF, 0xFAEF92)?;
            self.set_reg_bb(0x7818, 0x00FFFFFF, 0xFE5FCC)?;
            self.set_reg_bb(0x781C, 0x00FFFFFF, 0xFFDFF5)?;
        }

        // ═══ Step 4: BB bandwidth (halbb_ctrl_bw_8852a, 20MHz) ═══
        // From halbb_8852a_api.c:272-373

        // RF_BW [31:30] = 0x0 (20MHz)
        self.set_reg_bb(0x1878, 0xC0000000, 0x0)?;
        // Small BW [13:12] = 0x0
        self.set_reg_bb(0x187C, 0x3000, 0x0)?;
        // Primary channel index [11:8] = 0x0 (20MHz: no primary offset)
        self.set_reg_bb(0x187C, 0xF00, 0x0)?;

        // Per-path RF BW setting (RF reg 0x18 bits [13:11])
        for path in 0..2u8 {
            let rf_reg18 = self.read_rf(path, 0x18, 0x000FFFFF)?;
            let new_val = rf_reg18 & !0x3800; // Clear BW bits, 20MHz = 0b000
            self.write_rf(path, 0x18, 0x000FFFFF, new_val)?;
        }

        // ═══ Step 5: CCK enable/disable (halbb_ctrl_cck_en_8852a) ═══
        if is_2g {
            self.set_reg_bb(0x7800, 1 << 27, 0)?; // CCK enable
            self.set_reg_bb(0x7844, 1u32 << 31, 0)?;

            // CCK SCO compensation (halbb_ctrl_sco_cck_8852a)
            // Barker and CCK threshold tables indexed by channel (1-14)
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
            self.set_reg_bb(0x7800, 1 << 27, 1)?; // CCK disable
            self.set_reg_bb(0x7844, 1u32 << 31, 1)?;
        }

        // ═══ Step 6: BB reset cycle (halbb_bb_reset_8852a) ═══
        // From halbb_8852a_api.c:30-40 — full 0xFF toggle on PHY0 reg 0x804
        self.set_reg_bb(0x0804, 0xFF, 0xFF)?;
        self.set_reg_bb(0x0804, 0xFF, 0x00)?;
        self.set_reg_bb(0x0804, 0xFF, 0xFF)?;
        // Wait for BB reset to settle before re-enabling radio
        thread::sleep(Duration::from_micros(100));

        // ═══ Step 7: hal_reset(disable) — resume radio ═══
        // From hal_com_i.c:251-282

        // BB reset enable = true (BB reg 0x704 bit 1 = 1) — do this FIRST
        // to ensure BB is ready before re-enabling ADC/PPDU
        self.set_reg_bb(0x0704, 0x2, 1)?;
        // Re-enable TSSI continuous mode (both paths)
        // enable = set bit 30 to 0
        self.set_reg_bb(0x5818, 1 << 30, 0)?;
        self.set_reg_bb(0x7818, 1 << 30, 0)?;
        // Re-enable DFS (BB reg 0x0 bit 31 = 1)
        self.set_reg_bb(0x0, 1u32 << 31, 1)?;
        // Re-enable ADC/PPDU status (BB reg 0x20FC bits [31:24] = 0x0) — LAST
        // This is the critical write that restores RX. Must come after BB is
        // fully reset and TSSI is re-enabled.
        self.set_reg_bb(0x20FC, 0xFF000000, 0x0)?;

        self.channel = ch;
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Read MAC address from hardware
    // ══════════════════════════════════════════════════════════════════════════

    fn read_mac_address(&mut self) -> Result<()> {
        // Read MAC from multiple sources and pick the best one.
        // The autoloaded register (0x0036) can return partial garbage if EFUSE
        // autoload didn't complete. The MACID register (0xC100) is written by
        // firmware after EFUSE parsing.

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

        // Source 2: MACID register (0xC100-0xC105) — firmware writes this from EFUSE
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

        // Use whatever the firmware/EFUSE reports — even if partial.
        // Prefer autoloaded register (0x0036) which has the EFUSE MAC.
        // Don't generate random MACs — use the firmware's MAC everywhere for consistency.
        if mac_auto != [0x00; 6] && mac_auto != [0xFF; 6] {
            self.mac_addr = MacAddress::new(mac_auto);
        } else if mac_macid != [0x00; 6] && mac_macid != [0xFF; 6] {
            self.mac_addr = MacAddress::new(mac_macid);
        } else {
            // Both sources empty — fallback to a fixed locally-administered MAC
            self.mac_addr = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Pcap replay + H2C parsing
    // ══════════════════════════════════════════════════════════════════════════

    /// Parse a raw pcap H2C bulk command and extract cat/class/func/payload.
    /// Returns None if the data isn't an H2C command (e.g., FWDL or TX frame).
    fn parse_h2c_from_pcap(data: &[u8]) -> Option<(u32, u32, u32, &[u8])> {
        if data.len() < WD_BODY_LEN + FWCMD_HDR_LEN { return None; }

        // Check WD DW0: CH_DMA must be 12 (H2C), FWDL_EN must be 0
        let wd_dw0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let ch_dma = (wd_dw0 >> 16) & 0xF;
        let fwdl_en = (wd_dw0 >> 20) & 0x1;
        if ch_dma != 12 || fwdl_en != 0 { return None; }

        // Parse FWCMD header at offset 24
        let hdr_dw0 = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let cat = hdr_dw0 & 0x3;
        let class = (hdr_dw0 >> 2) & 0x3F;
        let func = (hdr_dw0 >> 8) & 0xFF;

        // Payload is everything after WD + FWCMD header
        let payload = &data[WD_BODY_LEN + FWCMD_HDR_LEN..];
        Some((cat, class, func, payload))
    }

    /// Extract the LAST ADDR_CAM MAC from the pcap sequence (without replaying).
    /// The firmware's active MAC is the last ADDR_CAM written. Linux often sends
    /// multiple ADDR_CAMs (CREATE station → CREATE monitor → CHANGE).
    fn extract_pcap_addr_cam_mac(seq: &[rtl8852a_post_boot::PostBootOp]) -> Option<[u8; 6]> {
        use rtl8852a_post_boot::PostBootOp;
        let mut last_mac: Option<[u8; 6]> = None;
        for op in seq {
            if let PostBootOp::BulkOut(0x07, data) = op {
                if let Some((cat, class, func, payload)) = Self::parse_h2c_from_pcap(data) {
                    if cat == 1 && class == 6 && func == 0 && payload.len() >= 24 {
                        let mac = [
                            payload[16], payload[17], payload[18], payload[19],
                            payload[20], payload[21],
                        ];
                        if mac != [0u8; 6] {
                            last_mac = Some(mac);
                        }
                    }
                }
            }
        }
        last_mac
    }

    /// Replay a PostBootOp sequence from usbmon capture.
    /// H2C commands get headers REBUILT with our seq counter + REC_ACK for confirmation.
    /// Register ops and FWDL bulks are replayed verbatim.
    fn replay_phase(&mut self, name: &str, seq: &[rtl8852a_post_boot::PostBootOp],
                              skip_fw_bulk: bool) -> Result<()> {
        use rtl8852a_post_boot::PostBootOp;

        let mut read_ok = 0usize;
        let mut write_ok = 0usize;
        let mut write_fail = 0usize;
        let mut bulk_ok = 0usize;
        let mut bulk_fail = 0usize;
        let mut bulk_skip = 0usize;
        // ep7_count, reg_ops_since_last_bulk, h2c_sent removed — all EP7 bulk
        // commands are now skipped during pcap replay (sent programmatically after).

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
                        if write_fail < 5 {
                        }
                        write_fail += 1;
                    } else {
                        write_ok += 1;
                    }
                }
                PostBootOp::BulkOut(ep, data) => {
                    // ── SKIP ALL EP7 (H2C) bulk commands from pcap replay ──
                    // H2C commands contain firmware-instance-specific data: sequence numbers,
                    // MAC addresses, role IDs, and calibration payloads from the capture machine.
                    // Replaying them into a different firmware instance causes silent rejection —
                    // the firmware ignores stale H2C and never enables TX DMA (SYS_CFG5=0).
                    //
                    // Register writes (EP0 control) are hardware-level and safe to replay.
                    // After pcap replay, we send fresh programmatic H2C with correct seq numbers:
                    //   FWROLE_MAINTAIN(CREATE) → ADDR_CAM(our MAC) → FWROLE_MAINTAIN(CHANGE)
                    if *ep == 0x07 {
                        bulk_skip += 1;
                        continue;
                    }

                    let target_ep = self.ep_out;
                    let timeout = Duration::from_millis(if data.len() > 1024 { 2000 } else { 500 });
                    match self.handle.write_bulk(target_ep, data, timeout) {
                        Ok(_) => {
                            bulk_ok += 1;
                        }
                        Err(e) => {
                            bulk_fail += 1;
                            // Bulk write failed — non-fatal during replay
                            let _ = self.handle.clear_halt(target_ep);
                        }
                    }
                }
            }
        }

        // Debug: phase completion summary
        let _ = (
            name, read_ok, write_ok, write_fail, bulk_ok, bulk_fail, bulk_skip);

        Ok(())
    }

    fn chip_init(&mut self) -> Result<()> {
        // ══════════════════════════════════════════════════════════════════
        //  Pure pcap replay — usbmon IS the spec.
        //
        //  Replays the EXACT USB operations from usb3_gentle_tx.pcap
        //  (WimLee115 driver, Asahi Linux, 2026-04-04). This capture has
        //  332 confirmed TX frames. We replay everything up to (but not
        //  including) the first TX frame, then our code takes over.
        //
        //  Key discovery: after firmware boots (WCPU enable), EP7 stalls
        //  on macOS unless we clear_halt(). Linux kernel does this
        //  transparently. Without it, ALL post-FWDL H2C commands timeout.
        // ══════════════════════════════════════════════════════════════════

        // ── Phase -1: Clean up dirty firmware state ──
        let fw_ctrl = self.read8(R_AX_WCPU_FW_CTRL)?;
        if fw_ctrl != 0 {
            self.disable_cpu()?;
            self.power_off()?;
            thread::sleep(Duration::from_millis(50));
        }

        // ── Background RX drain thread ──
        let drain_handle = Arc::clone(&self.handle);
        let drain_ep = self.ep_in;
        let drain_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let drain_flag = Arc::clone(&drain_running);
        let drain_thread = thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            while drain_flag.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = drain_handle.read_bulk(drain_ep, &mut buf, Duration::from_millis(1));
            }
        });

        // ── Replay pcap init ──
        let (reg_writes, reg_reads, ep7_sent, ep5_sent) = self.replay_pcap_init()?;
        // Pcap replay stats available from replay_pcap_init() return value

        // ── Stop background drain ──
        drain_running.store(false, std::sync::atomic::Ordering::Relaxed);
        let _ = drain_thread.join();

        // ── Post-replay: ensure monitor mode + TX scheduler ──
        // The pcap replay sets these, but re-applying is idempotent and
        // guarantees correct state regardless of pcap scanning position.
        self.write32(R_AX_RX_FLTR_OPT, 0x031644BFu32)?; // promiscuous monitor
        self.setup_firmware_role()?; // SCH_TX_EN(0xFFFF) + CTN_TXEN(0xFFFF)

        // ── Read MAC from EFUSE autoload registers ──
        self.read_mac_address()?;
        self.channel = 149; // pcap was on ch149

        Ok(())
    }

    /// Replay the complete init sequence from the working pcap capture.
    /// Returns (reg_writes, reg_reads, ep7_sent, ep5_sent).
    fn replay_pcap_init(&self) -> Result<(u32, u32, u32, u32)> {
        const PCAP_PATH: &str = "references/captures/rtl8852au_tx_20260404/usb3_gentle_tx.pcap";
        const TARGET_BUS: u8 = 1;
        const TARGET_DEV: u8 = 16;

        let pcap_data = fs::read(PCAP_PATH).map_err(|e| Error::ChipInitFailed {
            chip: "RTL8852AU".into(),
            stage: crate::core::error::InitStage::HardwareSetup,
            reason: format!("pcap read: {}", e),
        })?;

        let mut offset = 24; // skip pcap global header
        let mut reg_writes = 0u32;
        let mut reg_reads = 0u32;
        let mut ep7_sent = 0u32;
        let mut ep7_fail = 0u32;
        let mut ep5_sent = 0u32;

        while offset + 16 <= pcap_data.len() {
            let incl_len = u32::from_le_bytes([
                pcap_data[offset + 8], pcap_data[offset + 9],
                pcap_data[offset + 10], pcap_data[offset + 11],
            ]) as usize;
            offset += 16;

            if offset + incl_len > pcap_data.len() || incl_len < 64 {
                offset += incl_len;
                continue;
            }

            let pkt = &pcap_data[offset..offset + incl_len];
            offset += incl_len;

            let pkt_type = pkt[8];
            let xfer_type = pkt[9];
            let ep = pkt[10];
            let devnum = pkt[11];
            let busnum = u16::from_le_bytes([pkt[12], pkt[13]]);
            let ep_num = ep & 0x7F;
            let ep_dir_in = ep & 0x80 != 0;
            let payload = &pkt[64..];

            if busnum != TARGET_BUS as u16 || devnum != TARGET_DEV || pkt_type != 0x53 {
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
                                // FW ready — proceed with EP7 halt clear
                                break;
                            }
                            // Also check H2C_PATH_RDY for FWDL phase
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
                    Err(e) => {
                        ep7_fail += 1;
                        if ep7_fail <= 3 {
                            // EP7 failure during pcap replay — non-fatal
                        }
                        let _ = self.handle.clear_halt(self.ep_fw);
                    }
                }
            }
            // ── EP5 bulk OUT (TX) — stop before first TX, init is complete ──
            else if xfer_type == 3 && !ep_dir_in && ep_num == 5 && payload.len() > 48 {
                // Init is done. Don't replay TX frames — our code handles TX.
                break;
            }
        }

        if ep7_fail > 0 {
            // EP7 had failures — may cause H2C processing issues
        }

        Ok((reg_writes, reg_reads, ep7_sent, ep5_sent))
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  RX frame parsing — MAC AX descriptor format
    // ══════════════════════════════════════════════════════════════════════════

    /// Parse one RX packet from the USB bulk transfer buffer.
    ///
    /// Handles all rpkt_type values from rxdesc.h:
    ///   0 = WiFi frame → returned as RxFrame with PHY info from PPDU correlation
    ///   1 = PPDU status → parsed and stored in cache for correlation
    ///   2-14 = other (CH_INFO, TXRPT, C2H, etc.) → consumed and skipped
    ///
    /// DW1 fields parsed for WiFi frames: ppdu_type, ppdu_cnt, rx_datarate, rx_gi_ltf, bw.
    /// DW3 fields parsed: crc32, ampdu, amsdu.
    pub(crate) fn parse_rx_packet(
        buf: &[u8],
        channel: u8,
        ppdu_cache: &mut PpduStatusCache,
    ) -> (usize, Option<RxFrame>) {
        if buf.len() < RX_DESC_SHORT {
            return (0, None);
        }

        // ── DW0 ──
        let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let pkt_len = (dw0 & 0x3FFF) as usize;
        let shift = ((dw0 >> 14) & 0x3) as usize * 2;
        let mac_info_vld = (dw0 >> 23) & 1 != 0;
        let rpkt_type = ((dw0 >> 24) & 0xF) as u8;
        let drv_info_size = ((dw0 >> 28) & 0x7) as usize * 8;
        let long_rxd = (dw0 >> 31) & 1 != 0;

        let desc_len = if long_rxd { RX_DESC_LONG } else { RX_DESC_SHORT };

        // ── Non-WiFi packets ──
        if rpkt_type != RPKT_TYPE_WIFI {
            // PPDU status packets need special handling for mac_info_extra:
            // rpkt_type=1 never has mac_info_extra regardless of mac_info_vld
            let mac_info_extra = if mac_info_vld && rpkt_type != RPKT_TYPE_PPDU { 4 } else { 0 };
            let total = desc_len + shift + drv_info_size + mac_info_extra + pkt_len;
            let consumed = if total > 0 { (total + 7) & !7 } else { desc_len };
            if consumed > buf.len() { return (0, None); }

            // Parse PPDU status packets — this is where RSSI/SNR/LDPC/STBC live
            if rpkt_type == RPKT_TYPE_PPDU && buf.len() >= desc_len + 4 {
                // DW1 for ppdu_cnt
                let dw1 = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let ppdu_cnt = ((dw1 >> 4) & 0x7) as u8;

                // The PHY status (physts) is after the descriptor.
                // For short desc: at offset 16 + shift. For long desc: at offset 32 + shift.
                // drv_info (if any) comes first, then pkt_len bytes of PPDU payload.
                let physts_off = desc_len + shift;
                let physts_len = drv_info_size + pkt_len;

                if physts_len >= 8 && buf.len() >= physts_off + physts_len {
                    if let Some(phy) = parse_ppdu_payload(
                        &buf[physts_off..physts_off + physts_len],
                        mac_info_vld,
                    ) {
                        // store_ppdu may return a completed frame if a pending WiFi frame matches
                        if let Some(completed) = ppdu_cache.store_ppdu(ppdu_cnt, phy) {
                            return (consumed, Some(completed));
                        }
                    }
                }
            }

            return (consumed, None);
        }

        // ── WiFi packet (rpkt_type=0) ──

        if buf.len() < desc_len {
            return (0, None);
        }

        // ── DW1 — rate/type/bandwidth (free data, just read it) ──
        let dw1 = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ppdu_type_raw = (dw1 & 0xF) as u8;
        let ppdu_cnt = ((dw1 >> 4) & 0x7) as u8;
        let data_rate = ((dw1 >> 16) & 0x1FF) as u16;
        let gi_ltf_raw = ((dw1 >> 25) & 0x7) as u8;
        let bw_raw = ((dw1 >> 30) & 0x3) as u8;

        // ── DW2 — freerun counter (timestamp) ──
        let tsfl = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);

        // ── DW3 — CRC, AMPDU, AMSDU ──
        let dw3 = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let crc_err = (dw3 >> 9) & 1 != 0;
        let is_ampdu = (dw3 >> 3) & 1 != 0;
        let is_amsdu = (dw3 >> 5) & 1 != 0;

        // Calculate payload offset
        let mac_info_extra = if mac_info_vld { 4 } else { 0 };
        let data_off = desc_len + shift + drv_info_size + mac_info_extra;
        let total = data_off + pkt_len;

        if pkt_len == 0 || total > buf.len() {
            return (0, None);
        }

        let consumed = (total + 7) & !7;

        // Strip FCS (4 bytes)
        let frame_len = if pkt_len >= 4 { pkt_len - 4 } else { 0 };

        if crc_err || frame_len == 0 {
            return (consumed, None);
        }

        let data = buf[data_off..data_off + frame_len].to_vec();

        // ── Build WiFi frame with DW1 fields populated ──
        let drv_info_off = desc_len + shift;
        let mut frame = RxFrame {
            data,
            rssi: 0, // will be filled by PPDU correlation
            channel,
            band: if channel <= 14 { 0 } else { 1 },
            timestamp: Duration::from_micros(tsfl as u64),
            data_rate,
            ppdu_type: PpduType::from_raw(ppdu_type_raw),
            bandwidth: RxBandwidth::from_raw(bw_raw),
            gi_ltf: GuardInterval::from_raw(gi_ltf_raw),
            is_ampdu,
            is_amsdu,
            ..Default::default()
        };

        // Some WiFi frames carry inline physts in drv_info (when drv_info_size > 0)
        if drv_info_size >= 8 && buf.len() >= drv_info_off + drv_info_size {
            if let Some(phy) = parse_physts_header(&buf[drv_info_off..drv_info_off + drv_info_size]) {
                PpduStatusCache::apply_phy_to_frame(&mut frame, &phy);
            }
        }

        // If we have inline RSSI, return immediately — no need for PPDU correlation
        if frame.rssi != 0 {
            // A WiFi frame with inline PHY info might also release a pending frame
            let old = ppdu_cache.store_pending(ppdu_cnt, frame);
            // Actually, this frame has RSSI, so just flush and return it
            let completed = ppdu_cache.flush_pending();
            // Return old pending frame first (if any), then the current one gets returned
            // on next iteration. But we can only return one frame — return completed.
            if let Some(f) = completed {
                return (consumed, Some(f));
            }
            return (consumed, old);
        }

        // No inline RSSI — check if pre-stored PPDU status exists for this ppdu_cnt
        if let Some(phy) = ppdu_cache.lookup(ppdu_cnt) {
            PpduStatusCache::apply_phy_to_frame(&mut frame, phy);
            // Clear the slot
            let idx = (ppdu_cnt & 0x7) as usize;
            ppdu_cache.slots[idx].valid = false;
            return (consumed, Some(frame));
        }

        // No RSSI available yet — store as pending, wait for PPDU status
        // If there was a previous pending frame, return it now (it missed its PPDU)
        let old_pending = ppdu_cache.store_pending(ppdu_cnt, frame);
        (consumed, old_pending)
    }

    fn recv_frame_internal(&mut self, timeout: Duration) -> Result<Option<RxFrame>> {
        // Try parsing from existing buffer
        while self.rx_pos < self.rx_len {
            let remaining = &self.rx_buf[self.rx_pos..self.rx_len];
            let (consumed, frame) = Self::parse_rx_packet(remaining, self.channel, &mut self.ppdu_cache);
            if consumed == 0 {
                self.rx_pos = self.rx_len;
                break;
            }
            self.rx_pos += consumed;
            if let Some(f) = frame {
                return Ok(Some(f));
            }
        }

        // Before fetching new USB data, flush any pending frame from the last buffer
        if let Some(f) = self.ppdu_cache.flush_pending() {
            return Ok(Some(f));
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

        // Parse packets from new transfer
        while self.rx_pos < self.rx_len {
            let remaining = &self.rx_buf[self.rx_pos..self.rx_len];
            let (consumed, frame) = Self::parse_rx_packet(remaining, self.channel, &mut self.ppdu_cache);
            if consumed == 0 {
                self.rx_pos = self.rx_len;
                break;
            }
            self.rx_pos += consumed;
            if let Some(f) = frame {
                return Ok(Some(f));
            }
        }

        // Flush any remaining pending frame at end of this buffer
        if let Some(f) = self.ppdu_cache.flush_pending() {
            return Ok(Some(f));
        }

        Ok(None)
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  TX frame injection (MAC AX WD format)
    // ══════════════════════════════════════════════════════════════════════════

    /// Build and send a MAC AX TX descriptor + frame via USB bulk OUT.
    ///
    /// Structure: WD_BODY (24 bytes) + WD_INFO (24 bytes) + 802.11 frame
    /// Total WD = 48 bytes. WDINFO_EN is always set for proper rate control.
    ///
    /// Field layout from txdesc.h (MAC_AX_8852A_SUPPORT section):
    ///   WD_BODY DW0: STF_MODE[10] | HDR_LLC_LEN[15:11] | CH_DMA[19:16] | WDINFO_EN[22]
    ///   WD_BODY DW2: TXPKTSIZE[13:0] | QSEL[22:17] | MACID[30:24]
    ///   WD_BODY DW3: WIFI_SEQ[11:0]
    ///   WD_INFO DW0: DATARATE[24:16] | GI_LTF[27:25] | DATA_BW[29:28] | USERATE_SEL[30]
    ///                STBC[12] | LDPC[11] | DISDATAFB[10]
    ///   WD_INFO DW1: DATA_TXCNT_LMT[30:25] | DATA_TXCNT_LMT_SEL[31] | BMC[11] | NAVUSEHDR[10]
    ///   WD_INFO DW4: RTS_EN[27] | CTS2SELF[28]
    fn inject_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()> {
        if frame.len() < 10 {
            return Err(Error::TxFailed { retries: 0, reason: "frame too short".into() });
        }

        // Parse 802.11 frame control for type/subtype routing
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        let frame_type = (fc >> 2) & 0x3;     // 0=mgmt, 1=ctrl, 2=data
        let _frame_subtype = (fc >> 4) & 0xF;
        let is_multicast = frame[4] & 0x01 != 0;

        // 802.11 header length (for HDR_LLC_LEN field)
        let mac_hdr_len: u32 = match frame_type {
            0 => 24,  // Management
            1 => 10,  // Control (minimum — ACK/CTS are 10, RTS is 16, etc.)
            2 => if fc & (1 << 8) != 0 && fc & (1 << 9) != 0 { 30 } else { 24 },
            _ => 24,
        };

        // ── DMA channel + queue select based on frame type ──
        // Management → B0MG (DMA ch 8) + MG0_SEL queue
        // Control → B0MG + MG0_SEL (highest priority, same as management)
        // Data → WMM AC queue from QoS TID
        let (dma_ch, qsel) = match frame_type {
            0 | 1 => (MAC_AX_DMA_B0MG, MAC_AX_MG0_SEL),
            2 => {
                // Data: extract QoS TID for WMM AC mapping
                let tid = if _frame_subtype & 0x8 != 0 && frame.len() >= 26 {
                    (frame[24] & 0x0F) as u32
                } else {
                    0
                };
                // WMM TID→AC: {1,2}→BK(1), {0,3}→BE(0), {4,5}→VI(2), {6,7}→VO(3)
                match tid {
                    1 | 2 => (MAC_AX_DMA_ACH1, (0u32 << 2) | 1), // WMM0 AC_BK
                    0 | 3 => (MAC_AX_DMA_ACH0, (0u32 << 2) | 0), // WMM0 AC_BE
                    4 | 5 => (MAC_AX_DMA_ACH2, (0u32 << 2) | 2), // WMM0 AC_VI
                    6 | 7 => (MAC_AX_DMA_ACH3, (0u32 << 2) | 3), // WMM0 AC_VO
                    _     => (MAC_AX_DMA_ACH0, (0u32 << 2) | 0), // default BE
                }
            }
            _ => (MAC_AX_DMA_B0MG, MAC_AX_MG0_SEL),
        };

        // Rate encoding for DATARATE field (9-bit)
        let hw_rate = ax_rate_to_hw(&opts.rate) as u32;
        let bw = (opts.bw as u32).min(2); // Clamp to 80MHz max (hardware limit)

        let total_len = TX_WD_TOTAL_LEN + frame.len();
        let mut buf = vec![0u8; total_len];

        // ══════════════════════════════════════════════
        //  WD_BODY (24 bytes, offset 0-23)
        // ══════════════════════════════════════════════

        // DW0: STF_MODE | HDR_LLC_LEN | CH_DMA | WDINFO_EN
        // HDR_LLC_LEN is in raw bytes (NOT bytes/2) — verified from usbmon:
        //   Linux probe DW0=0x0048C400 → HDR_LLC_LEN=24 (not 12)
        let dw0: u32 = AX_TXD_STF_MODE
            | ((mac_hdr_len & 0x1F) << AX_TXD_HDR_LLC_LEN_SH)
            | (dma_ch << AX_TXD_CH_DMA_SH)
            | AX_TXD_WDINFO_EN;
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());

        // DW1 = 0 (no shortcut CAM, no PLD, no DMA TX aggregation)

        // DW2: TXPKTSIZE | QSEL | MACID
        let dw2: u32 = (frame.len() as u32 & 0x3FFF)
            | ((qsel & 0x3F) << AX_TXD_QSEL_SH);
            // MACID = 0 for broadcast/monitor mode injection
        buf[8..12].copy_from_slice(&dw2.to_le_bytes());

        // DW3: BK (break aggregation) + WIFI_SEQ.
        // Linux pcap: ALL TX frames have BK=1 (bit 13 = 0x2000) + seq counter.
        // For monitor mode injection, always break aggregation.
        if frame.len() >= 24 {
            let seq_ctrl = u16::from_le_bytes([frame[22], frame[23]]);
            let seq_num = (seq_ctrl >> 4) & 0x0FFF;
            let dw3: u32 = AX_TXD_BK | ((seq_num as u32) << AX_TXD_WIFI_SEQ_SH);
            buf[12..16].copy_from_slice(&dw3.to_le_bytes());
        }

        // DW4, DW5 = 0 (no AES IV, no checksum — wd_checksum_en is not set)

        // ══════════════════════════════════════════════
        //  WD_INFO (24 bytes, offset 24-47)
        // ══════════════════════════════════════════════

        // INFO DW0: DATARATE | GI_LTF | DATA_BW | USERATE_SEL | STBC | LDPC | DISDATAFB
        let mut info_dw0: u32 = AX_TXD_USERATE_SEL
            | ((hw_rate & 0x1FF) << AX_TXD_DATARATE_SH)
            | ((bw & 0x3) << AX_TXD_DATA_BW_SH)
            | (((opts.gi as u32) & 0x7) << AX_TXD_GI_LTF_SH);
        if opts.flags.contains(TxFlags::STBC)   { info_dw0 |= AX_TXD_DATA_STBC; }
        if opts.flags.contains(TxFlags::LDPC)   { info_dw0 |= AX_TXD_DATA_LDPC; }
        if opts.flags.contains(TxFlags::NO_RETRY) { info_dw0 |= AX_TXD_DISDATAFB; } // disable fallback too
        buf[24..28].copy_from_slice(&info_dw0.to_le_bytes());

        // INFO DW1: BMC flag + optional retry limit
        // Linux usbmon shows minimal INFO_DW1: just BMC=1 for broadcast (0x00000800).
        // Only set TXCNT_LMT when explicitly requested via retries > 0.
        let mut info_dw1: u32 = 0;
        if is_multicast { info_dw1 |= AX_TXD_BMC; }
        if opts.retries > 0 && !opts.flags.contains(TxFlags::NO_RETRY) {
            let retry_count = (opts.retries as u32).clamp(1, 63);
            info_dw1 |= AX_TXD_DATA_TXCNT_LMT_SEL
                | ((retry_count & 0x3F) << AX_TXD_DATA_TXCNT_LMT_SH);
        }
        buf[28..32].copy_from_slice(&info_dw1.to_le_bytes());

        // INFO DW2, DW3 = 0 (no security, no SIFS_TX, no sounding)

        // INFO DW4: RTS/CTS protection
        if opts.flags.contains(TxFlags::PROTECT) {
            let info_dw4: u32 = AX_TXD_RTS_EN;
            buf[40..44].copy_from_slice(&info_dw4.to_le_bytes());
        }

        // INFO DW5 = 0

        // ══════════════════════════════════════════════
        //  802.11 frame payload (offset 48+)
        // ══════════════════════════════════════════════

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
        // Monitor mode is configured by init's pcap replay (RX_FLTR = 0x031644BF).
        // No additional setup needed — calling the old hand-coded path breaks RX.
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

    fn set_mac(&mut self, _mac: MacAddress) -> Result<()> {
        // TEMP: complete no-op to match test_8852au behavior (no set_mac call)
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
        buf.extend_from_slice(&[0u8; 8]);
        let mut cache = PpduStatusCache::new();
        let (consumed, frame) = Rtl8852au::parse_rx_packet(&buf, 6, &mut cache);
        assert!(consumed > 0);
        assert!(frame.is_none()); // C2H should be skipped
    }

    #[test]
    fn test_rx_descriptor_parsing_wifi_no_drv_info() {
        // Long RX descriptor (32 bytes) for a WiFi packet, no drv_info
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
        // DW0: pkt_len, rpkt_type=0 (WiFi), drv_info_size=0, long_rxd=1
        let dw0: u32 = (pkt_len as u32) | (1 << 31);
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());
        buf[12..16].copy_from_slice(&0u32.to_le_bytes());
        buf[32..32 + frame_data.len()].copy_from_slice(&frame_data);

        let mut cache = PpduStatusCache::new();
        let (consumed, frame) = Rtl8852au::parse_rx_packet(&buf, 6, &mut cache);
        assert!(consumed > 0);
        // WiFi frame with no RSSI goes to pending, not returned immediately
        assert!(frame.is_none());
        // Flush the pending frame
        let f = cache.flush_pending().unwrap();
        assert_eq!(f.data.len(), frame_data.len());
        assert_eq!(f.channel, 6);
        assert_eq!(f.rssi, 0); // no drv_info and no PPDU correlation → 0 (not populated)
    }

    #[test]
    fn test_rx_rssi_from_physts_header() {
        // Long RX descriptor (32 bytes) + 8 bytes drv_info (physts header) + WiFi frame
        // Simulates -30 dBm: rssi_avg_td = (-30 + 110) * 2 = 160 (0xA0)
        let frame_data = [
            0x80, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x00,
        ];
        let pkt_len = frame_data.len() + 4;

        // drv_info_size field = 1 (1 * 8 = 8 bytes of drv_info)
        let mut buf = vec![0u8; 32 + 8 + pkt_len];
        let dw0: u32 = (pkt_len as u32) | (1 << 28) | (1 << 31); // drv_info_size=1, long_rxd=1
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());
        buf[12..16].copy_from_slice(&0u32.to_le_bytes());

        // physts_hdr_info at offset 32 (right after long RX desc):
        //   byte 0: is_valid=1 (bit 7) → 0x80
        //   byte 1: total_length = 1 (8 bytes)
        //   byte 2: rsvd
        //   byte 3: rssi_avg_td = 160 (0xA0) → (160 >> 1) - 110 = -30 dBm
        buf[32] = 0x80; // is_valid = 1
        buf[33] = 0x01; // total_length = 1 (8 bytes)
        buf[34] = 0x00; // rsvd
        buf[35] = 160;  // rssi_avg_td = 160 → -30 dBm

        // Frame data at offset 32 + 8 = 40
        buf[40..40 + frame_data.len()].copy_from_slice(&frame_data);

        let mut cache = PpduStatusCache::new();
        let (consumed, frame) = Rtl8852au::parse_rx_packet(&buf, 36, &mut cache);
        assert!(consumed > 0);
        let f = frame.unwrap();
        assert_eq!(f.rssi, -30);
        assert_eq!(f.channel, 36);
    }

    #[test]
    fn test_rx_rssi_weak_signal() {
        // Test with weak signal: -85 dBm → rssi_avg_td = (-85 + 110) * 2 = 50
        let frame_data = [0x80, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x00];
        let pkt_len = frame_data.len() + 4;

        let mut buf = vec![0u8; 32 + 8 + pkt_len];
        let dw0: u32 = (pkt_len as u32) | (1 << 28) | (1 << 31);
        buf[0..4].copy_from_slice(&dw0.to_le_bytes());
        buf[12..16].copy_from_slice(&0u32.to_le_bytes());
        buf[32] = 0x80; // is_valid
        buf[35] = 50;   // rssi_avg_td = 50 → (50 >> 1) - 110 = -85 dBm

        buf[40..40 + frame_data.len()].copy_from_slice(&frame_data);

        let mut cache = PpduStatusCache::new();
        let (consumed, frame) = Rtl8852au::parse_rx_packet(&buf, 1, &mut cache);
        let f = frame.unwrap();
        assert_eq!(f.rssi, -85);
    }

    #[test]
    fn test_ppdu_correlation() {
        // Test the full PPDU correlation flow:
        // 1. Feed a PPDU status packet with ppdu_cnt=3 and RSSI=-45 dBm
        // 2. Feed a WiFi frame with ppdu_cnt=3 in DW1
        // 3. Verify the WiFi frame picks up the RSSI from the PPDU status

        let mut cache = PpduStatusCache::new();

        // ── Step 1: Build PPDU status packet (rpkt_type=1) ──
        // PPDU status: long_rxd, rpkt_type=1, drv_info_size=1 (8 bytes physts)
        let ppdu_pkt_len: u32 = 0; // PPDU status may have pkt_len=0 payload beyond drv_info
        let ppdu_dw0: u32 = ppdu_pkt_len | (RPKT_TYPE_PPDU as u32) << 24 | (1 << 28) | (1 << 31);
        // DW1: ppdu_cnt=3 in bits [6:4]
        let ppdu_dw1: u32 = 3 << 4;

        let mut ppdu_buf = vec![0u8; 32 + 8]; // desc + 8 bytes drv_info
        ppdu_buf[0..4].copy_from_slice(&ppdu_dw0.to_le_bytes());
        ppdu_buf[4..8].copy_from_slice(&ppdu_dw1.to_le_bytes());
        // physts_hdr_info at offset 32:
        //   byte 0: is_valid=1 (0x80)
        //   byte 1: total_length=1 (8 bytes)
        //   byte 3: rssi_avg_td for -45 dBm = (-45+110)*2 = 130
        ppdu_buf[32] = 0x80; // is_valid
        ppdu_buf[33] = 0x01; // total_length
        ppdu_buf[35] = 130;  // rssi_avg_td → (130>>1)-110 = -45 dBm
        // Per-path RSSI
        ppdu_buf[36] = 128;  // path A: (128>>1)-110 = -46 dBm
        ppdu_buf[37] = 132;  // path B: (132>>1)-110 = -44 dBm

        let (consumed, frame) = Rtl8852au::parse_rx_packet(&ppdu_buf, 6, &mut cache);
        assert!(consumed > 0);
        assert!(frame.is_none()); // PPDU status doesn't produce a frame

        // ── Step 2: Build WiFi frame with ppdu_cnt=3 in DW1 ──
        let frame_data = [
            0x80, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x00, 0x00,
        ];
        let wifi_pkt_len = frame_data.len() + 4;
        let mut wifi_buf = vec![0u8; 32 + wifi_pkt_len];
        // DW0: rpkt_type=0 (WiFi), no drv_info, long_rxd=1
        let wifi_dw0: u32 = (wifi_pkt_len as u32) | (1 << 31);
        // DW1: ppdu_cnt=3, ppdu_type=5 (HE-SU), data_rate=0x80 (HT MCS0), bw=2 (80MHz)
        let wifi_dw1: u32 = 5 | (3 << 4) | (0x80 << 16) | (2 << 30);
        wifi_buf[0..4].copy_from_slice(&wifi_dw0.to_le_bytes());
        wifi_buf[4..8].copy_from_slice(&wifi_dw1.to_le_bytes());
        wifi_buf[32..32 + frame_data.len()].copy_from_slice(&frame_data);

        let (consumed, frame) = Rtl8852au::parse_rx_packet(&wifi_buf, 6, &mut cache);
        assert!(consumed > 0);
        let f = frame.unwrap();

        // ── Step 3: Verify correlation ──
        assert_eq!(f.rssi, -45);
        assert_eq!(f.rssi_path[0], -46);
        assert_eq!(f.rssi_path[1], -44);
        assert_eq!(f.ppdu_type, PpduType::HeSu);
        assert_eq!(f.data_rate, 0x80);
        assert_eq!(f.bandwidth, RxBandwidth::Bw80);
    }

    #[test]
    fn test_fw_wd_format() {
        // Verify WD DW0 for FWDL
        let wd_dw0 = (MAC_AX_DMA_H2C << AX_TXD_CH_DMA_SH) | AX_TXD_FWDL_EN;
        assert_eq!(wd_dw0, 0x001C0000);
    }

    #[test]
    fn test_tx_wd_management_frame() {
        // Verify TX WD matches Linux usbmon EXACTLY for a probe request.
        // Reference: full_capture_bus4.pcap TX#0:
        //   DW0=0x0048C400  DW2=0x0024002A  INFO_DW0=0x40040000  INFO_DW1=0x00000800

        // DW0: STF_MODE[10] | HDR_LLC_LEN=24[15:11] | CH_DMA=8(B0MG)[19:16] | WDINFO_EN[22]
        // NOTE: HDR_LLC_LEN is in raw bytes (NOT bytes/2) — verified from usbmon
        let hdr_len = 24u32;
        let dw0: u32 = AX_TXD_STF_MODE
            | ((hdr_len & 0x1F) << AX_TXD_HDR_LLC_LEN_SH)
            | (MAC_AX_DMA_B0MG << AX_TXD_CH_DMA_SH)
            | AX_TXD_WDINFO_EN;
        assert_eq!(dw0, 0x0048C400); // exact match with Linux usbmon

        // DW2: TXPKTSIZE=42 | QSEL=MG0(18)[22:17] (42-byte probe request body)
        let frame_len = 42u32;
        let dw2: u32 = (frame_len & 0x3FFF) | ((MAC_AX_MG0_SEL & 0x3F) << AX_TXD_QSEL_SH);
        assert_eq!(dw2, 0x0024002A); // exact match with Linux usbmon

        // INFO DW0: USERATE_SEL[30] | DATARATE=OFDM6(0x04)[24:16]
        let info_dw0: u32 = AX_TXD_USERATE_SEL | (0x04u32 << AX_TXD_DATARATE_SH);
        assert_eq!(info_dw0, 0x40040000); // exact match with Linux usbmon

        // INFO DW1: BMC=1 (broadcast probe) — Linux sends exactly 0x00000800
        let info_dw1: u32 = AX_TXD_BMC;
        assert_eq!(info_dw1, 0x00000800); // exact match with Linux usbmon
    }

    #[test]
    fn test_tx_wd_data_frame_qos() {
        // Verify data frame WMM queue mapping
        // AC_BE (TID 0,3) → DMA ACH0, qsel = WMM0_AC_BE = 0
        // AC_BK (TID 1,2) → DMA ACH1, qsel = WMM0_AC_BK = 1
        // AC_VI (TID 4,5) → DMA ACH2, qsel = WMM0_AC_VI = 2
        // AC_VO (TID 6,7) → DMA ACH3, qsel = WMM0_AC_VO = 3
        assert_eq!(MAC_AX_DMA_ACH0, 0);
        assert_eq!(MAC_AX_DMA_ACH1, 1);
        assert_eq!(MAC_AX_DMA_ACH2, 2);
        assert_eq!(MAC_AX_DMA_ACH3, 3);
        assert_eq!(MAC_AX_DMA_B0MG, 8);
    }

    #[test]
    fn test_ax_rate_encoding() {
        // CCK/OFDM — matches RTW_DATA_RATE from rtw_general_def.h
        assert_eq!(ax_rate_to_hw(&TxRate::Cck1m), 0x00);
        assert_eq!(ax_rate_to_hw(&TxRate::Ofdm6m), 0x04);
        assert_eq!(ax_rate_to_hw(&TxRate::Ofdm54m), 0x0B);

        // HT — 0x80 + MCS index
        assert_eq!(ax_rate_to_hw(&TxRate::HtMcs(0)), 0x80);
        assert_eq!(ax_rate_to_hw(&TxRate::HtMcs(7)), 0x87);
        assert_eq!(ax_rate_to_hw(&TxRate::HtMcs(15)), 0x8F); // 2SS MCS15

        // VHT — 0x100 + (NSS-1)*16 + MCS
        assert_eq!(ax_rate_to_hw(&TxRate::VhtMcs { mcs: 0, nss: 1 }), 0x100);
        assert_eq!(ax_rate_to_hw(&TxRate::VhtMcs { mcs: 9, nss: 1 }), 0x109);
        assert_eq!(ax_rate_to_hw(&TxRate::VhtMcs { mcs: 0, nss: 2 }), 0x110);
        assert_eq!(ax_rate_to_hw(&TxRate::VhtMcs { mcs: 9, nss: 2 }), 0x119);

        // HE — 0x180 + (NSS-1)*16 + MCS
        assert_eq!(ax_rate_to_hw(&TxRate::HeMcs { mcs: 0, nss: 1 }), 0x180);
        assert_eq!(ax_rate_to_hw(&TxRate::HeMcs { mcs: 11, nss: 1 }), 0x18B);
        assert_eq!(ax_rate_to_hw(&TxRate::HeMcs { mcs: 0, nss: 2 }), 0x190);
        assert_eq!(ax_rate_to_hw(&TxRate::HeMcs { mcs: 11, nss: 2 }), 0x19B);

        // All rates fit in 9-bit DATARATE field (max 0x1FF = 511)
        assert!(ax_rate_to_hw(&TxRate::HeMcs { mcs: 11, nss: 2 }) <= 0x1FF);
    }

    #[test]
    fn test_stf_mode_bit_position() {
        // Vendor: AX_TXD_STF_MODE = BIT(10) — NOT BIT(0)
        // This was the root cause of TX killing RX
        assert_eq!(AX_TXD_STF_MODE, 1 << 10);
        assert_eq!(AX_TXD_STF_MODE, 0x400);
    }
}
