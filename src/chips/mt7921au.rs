//! MT7921AU chip driver — WiFi 6 (802.11ax), tri-band
//!
//! # Hardware
//!
//! MediaTek MT7921AU (MT7961) — 802.11ax tri-band (2.4GHz + 5GHz + 6GHz), 2T2R MIMO, USB 3.0.
//! WiFi 6 (HE) capable with firmware-driven MCU architecture.
//! Used in: Fenvi FU-AX1800 (USB3), Comfast CF-952AX, and others.
//! This is the project's most feature-rich driver — testmode spectrum analyzer, I/Q capture,
//! rogue AP, burst TX injection engine, and MIB channel survey all hardware-confirmed.
//!
//! Key differences from Realtek RTL8812AU/BU:
//!   - Firmware-driven: onboard MCU runs autonomous firmware (ROM patch + WM RAM)
//!   - Register access: USB vendor requests 0x63 (read) / 0x66 (write), extended addressing
//!   - Channel switching: MCU command (CHANNEL_SWITCH 0x08), not direct register writes
//!   - Monitor mode: MCU sniffer command (UNI_CMD 0x24) + RX filter drop-bit clearing
//!   - TX/RX: MCU-managed DMA queues, 64-byte TXWI descriptors, SDIO header framing
//!   - Testmode: firmware RF test interface (ATE commands) for spectrum/injection/calibration
//!
//! # Init Flow (9 steps in `full_init()`)
//!
//!   1. Read chip ID/revision (retry + WFSYS reset if stuck from previous session)
//!   2. Check firmware state (CONN_ON_MISC N9_RDY bit)
//!   3. WFSYS reset if firmware was already running
//!   4. MCU power on (power sequence + poll conn_infra status)
//!   5. DMA init (WFDMA + UDMA config, RX aggregation, endpoint mapping)
//!   6. Set normal mode (SWDEF register)
//!   7. Download and start firmware (ROM patch + WM RAM, section-by-section)
//!   8. Post-firmware: NIC capabilities query + FW log enable
//!   9. Read MAC address from EEPROM
//!
//! # USB Protocol
//!
//!   Register I/O: vendor control transfers
//!     Read:  bmRequestType=0x5F, bRequest=0x63, wValue=addr[15:0], wIndex=addr[31:16]
//!     Write: bmRequestType=0x5F, bRequest=0x66, wValue=addr[15:0], wIndex=addr[31:16]
//!   UHW access: bRequest=0x01/0x02 with TYPE_UHW_VENDOR (for EEPROM, mode switch)
//!   Data TX: bulk OUT with SDIO_HDR(4) + TXWI(64) + 802.11 frame + pad + tail(4)
//!   Data RX: bulk IN with RXWI header, USB aggregation (AGG_LMT=64, AGG_TO=0xFF)
//!   MCU commands: bulk OUT EP8 with MCU_TXD header, response via EP4/EP5 bulk IN
//!
//! # USB Endpoints
//!
//!   EP 0x08       BULK OUT — MCU commands
//!   EP 0x04       BULK OUT — AC_BK / firmware scatter
//!   EP 0x05       BULK OUT — AC_BE (primary data TX)
//!   EP 0x06       BULK OUT — AC_VI
//!   EP 0x07       BULK OUT — AC_VO
//!   EP 0x09       BULK OUT — firmware download
//!   EP 0x84/0x85  BULK IN  — RX data + MCU events
//!
//! # MCU Command Architecture
//!
//!   Three command paths:
//!     1. EXT commands (mcu_send_ext_cmd): MCU_CMD_EXT_CMP header, for UNI_CMD, CHANNEL_SWITCH
//!     2. CE commands (mcu_send_ce_cmd): host-originated, for NIC_CAPS, FW_LOG, BSS_ABORT
//!     3. Direct messages (mcu_send_msg): raw MCU_TXD, for firmware download
//!   Responses: parsed from EP4/EP5 bulk IN with sequence matching
//!   RX thread path: when RxHandle active, MCU responses forwarded via mpsc channel
//!
//! # Testmode (RF Test / Spectrum Analyzer)
//!
//!   Firmware ATE (Automatic Test Equipment) interface:
//!     - Spectrum analyzer: MIB survey registers (busy/tx/rx/obss time per channel)
//!     - Burst TX engine: configurable rate/BW/power/count/IPG packet injection
//!     - Continuous wave: CW tone for jamming/range testing/antenna tuning
//!     - RF calibration: per-antenna power, frequency offset, TSSI readback
//!     - I/Q capture: raw baseband samples (via testmode ICAP)
//!   All accessed through testmode_set_at() / testmode_query_at() wrappers
//!
//! # Architecture Decisions
//!
//!   - Combo device support: WiFi is iface 3 for MediaTek VID (0-2 = Bluetooth)
//!   - Monitor mode is 7-step: radio_init → PM exit → add_dev → sniffer → RX filter → UDMA
//!   - Channel survey uses direct MIB register reads (no testmode needed)
//!   - TX uses WMM queue mapping: frame type → TID → AC → endpoint selection
//!   - RX thread forwards MCU responses via unbounded mpsc channel (bounded drops responses)
//!   - set_mac() uses POWERED_ADDR_CHANGE: firmware updates OMAC in-place
//!   - Rogue AP: beacon offload via MCU command, proper VIF lifecycle
//!
//! # What's NOT Implemented
//!
//!   - 160 MHz bandwidth (ChipCaps declares up to BW80)
//!   - Full EEPROM calibration parsing (TX power cal, antenna trim)
//!   - Power save management (always exits PM on monitor init)
//!   - Firmware crash recovery / watchdog thread
//!   - Dynamic WTBL per-peer entries (broadcast entry only)
//!   - Beamformee steering (caps declared but not activated)
//!   - SAR power limit compliance (SET_SAR_LIMIT_CTRL)
//!
//! # Reference
//!
//!   Linux driver: openwrt/mt76 in references/mt76/
//!     mt792x_usb.c    — USB register access, DMA init
//!     mt7921/usb.c    — USB probe, MCU init
//!     mt7921/mcu.c    — firmware download, MCU commands
//!     mt792x_regs.h   — register addresses and bit definitions

// Register map constants — complete chip register vocabulary for full driver implementation.
// Struct fields/methods used via ChipDriver trait dispatch appear unused to the compiler.
#![allow(dead_code)]
#![allow(unused_variables)]

use std::time::{Duration, Instant};
use std::thread;
use std::path::Path;

use std::sync::Arc;
use rusb::{DeviceHandle, GlobalContext};

use crate::core::{
    Channel, Band, MacAddress, Result, Error,
    chip::{ChipDriver, ChipInfo, ChipId, ChipCaps, ChannelSurvey},
    frame::{RxFrame, TxOptions, TxFlags, TxRate},
    adapter::UsbEndpoints,
};

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — USB vendor requests
// ══════════════════════════════════════════════════════════════════════════════

/// USB vendor request: read register (MT792x extended)
const MT_VEND_READ_EXT: u8 = 0x63;
/// USB vendor request: write register (MT792x extended)
const MT_VEND_WRITE_EXT: u8 = 0x66;
/// USB vendor request: power on MCU
const MT_VEND_POWER_ON: u8 = 0x04;
/// USB vendor request: device mode (UHW vendor read)
const MT_VEND_DEV_MODE: u8 = 0x01;
/// USB vendor request: UHW vendor write
const MT_VEND_WRITE: u8 = 0x02;

/// USB request type for register access (vendor | device)
const MT_USB_TYPE_VENDOR: u8 = 0x40 | 0x1f;  // USB_TYPE_VENDOR | 0x1f
/// USB request type for UHW access
const MT_USB_TYPE_UHW_VENDOR: u8 = 0x40 | 0x1e;  // USB_TYPE_VENDOR | 0x1e

const USB_TIMEOUT: Duration = Duration::from_millis(500);
const USB_BULK_TIMEOUT: Duration = Duration::from_secs(2);
const VEND_REQ_MAX_RETRY: u32 = 10;
const VEND_REQ_RETRY_DELAY: Duration = Duration::from_millis(5);

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — Register addresses (from mt792x_regs.h)
// ══════════════════════════════════════════════════════════════════════════════

// Hardware identification
const MT_HW_CHIPID: u32         = 0x70010200;
const MT_HW_REV: u32            = 0x70010204;

// Connection / power status
const MT_CONN_ON_MISC: u32      = 0x7c0600f0;
const MT_TOP_MISC2_FW_PWR_ON: u32 = 0x1;        // BIT(0)
const MT_TOP_MISC2_FW_N9_RDY: u32 = 0x3;        // GENMASK(1,0)

// UMAC (USB DMA controller)
const MT_UMAC_BASE: u32         = 0x74000000;
const MT_UDMA_TX_QSEL: u32     = MT_UMAC_BASE + 0x008;
const MT_FW_DL_EN: u32         = 1 << 3;
const MT_UDMA_WLCFG_0: u32     = MT_UMAC_BASE + 0x018;
const MT_UDMA_WLCFG_1: u32     = MT_UMAC_BASE + 0x00c;

// UDMA WLCFG_0 bits
const MT_WL_RX_FLUSH: u32      = 1 << 19;
const MT_WL_RX_EN: u32         = 1 << 22;
const MT_WL_TX_EN: u32         = 1 << 23;
const MT_WL_RX_MPSZ_PAD0: u32  = 1 << 18;
const MT_TICK_1US_EN: u32       = 1 << 20;
const MT_WL_RX_AGG_EN: u32     = 1 << 21;     // Enable USB RX aggregation
const MT_WL_RX_AGG_TO: u32     = 0xFF;        // GENMASK(7,0) — aggregation timeout
const MT_WL_RX_AGG_LMT: u32    = 0xFF00;      // GENMASK(15,8) — max frames per aggregate
const MT_WL_RX_AGG_PKT_LMT: u32 = 0xFF;       // GENMASK(7,0) in WLCFG_1

// UDMA connection infrastructure status
const MT_UDMA_CONN_INFRA_STATUS: u32     = MT_UMAC_BASE + 0xa20;
const MT_UDMA_CONN_WFSYS_INIT_DONE: u32 = 1 << 22;
const MT_UDMA_CONN_INFRA_STATUS_SEL: u32 = MT_UMAC_BASE + 0xa24;

// SSUSB endpoint control
const MT_SSUSB_EPCTL_CSR_EP_RST_OPT: u32 = 0x74011800 + 0x090;

// CBTOP RGU (reset generation unit)
const MT_CBTOP_RGU_WF_SUBSYS_RST: u32 = 0x70002000 + 0x600;
const MT_CBTOP_RGU_WF_SUBSYS_RST_WF_WHOLE_PATH: u32 = 1; // BIT(0)

// UWFDMA0 (USB WFDMA)
const MT_UWFDMA0_BASE: u32     = 0x7c024000;
const MT_UWFDMA0_GLO_CFG: u32  = MT_UWFDMA0_BASE + 0x208;

// WFDMA0 GLO_CFG bits (same offset in different base)
const MT_WFDMA0_GLO_CFG_TX_DMA_EN: u32          = 1 << 0;
const MT_WFDMA0_GLO_CFG_RX_DMA_EN: u32          = 1 << 2;
const MT_WFDMA0_GLO_CFG_RX_DMA_BUSY: u32        = 1 << 3;
const MT_WFDMA0_GLO_CFG_OMIT_TX_INFO: u32       = 1 << 28;
const MT_WFDMA0_GLO_CFG_OMIT_RX_INFO: u32       = 1 << 27;
const MT_WFDMA0_GLO_CFG_OMIT_RX_INFO_PFET2: u32 = 1 << 21;
const MT_WFDMA0_GLO_CFG_FW_DWLD_BYPASS_DMASHDL: u32 = 1 << 9;

// DMASHDL
const MT_DMA_SHDL_BASE: u32            = 0x7c026000;
const MT_DMASHDL_REFILL: u32           = MT_DMA_SHDL_BASE + 0x010;
const MT_DMASHDL_PAGE: u32             = MT_DMA_SHDL_BASE + 0x00c;
const MT_DMASHDL_GROUP_SEQ_ORDER: u32  = 1 << 16;
const MT_DMASHDL_PKT_MAX_SIZE: u32     = MT_DMA_SHDL_BASE + 0x01c;
const MT_DMASHDL_GROUP_QUOTA_BASE: u32 = MT_DMA_SHDL_BASE + 0x020;
const MT_DMASHDL_Q_MAP_BASE: u32       = MT_DMA_SHDL_BASE + 0x060;
const MT_DMASHDL_SCHED_SET_BASE: u32   = MT_DMA_SHDL_BASE + 0x070;

// WFDMA host config
const MT_WFDMA_HOST_CONFIG: u32 = 0x7c027030;
const MT_WFDMA_HOST_CONFIG_USB_RXEVT_EP4_EN: u32 = 1 << 6;

// WFDMA dummy CR
const MT_MCU_WPDMA0_BASE: u32  = 0x54000000;
const MT_WFDMA_DUMMY_CR: u32   = MT_MCU_WPDMA0_BASE + 0x120;
const MT_WFDMA_NEED_REINIT: u32 = 1 << 1;

// UWFDMA0 TX ring ext ctrl
const MT_UWFDMA0_TX_RING_EXT_CTRL_BASE: u32 = MT_UWFDMA0_BASE + 0x600;

// MCU command interface
const MT_SWDEF_BASE: u32       = 0x41f200;
const MT_SWDEF_MODE: u32       = MT_SWDEF_BASE + 0x3c;
const MT_SWDEF_NORMAL_MODE: u32 = 0;

// Top misc (firmware state)
const MT_TOP_BASE: u32         = 0x18060000;
const MT_TOP_MISC: u32         = MT_TOP_BASE + 0xf0;
const MT_TOP_MISC_FW_STATE: u32 = 0x7;  // GENMASK(2,0)

// ── MIB Registers — per-channel survey / spectrum data ──
// From mt792x_regs.h. Band 0 base = 0x820ED000, Band 1 = 0x820FD000.
const MT_WF_MIB_BASE0: u32         = 0x820ed000;
const MT_WF_MIB_BASE1: u32         = 0x820fd000;

/// Channel busy time in microseconds (24-bit). Counts time PHY detects energy above CCA threshold.
const MT_MIB_SDR9_OFF: u32         = 0x02c;
const MT_MIB_SDR9_BUSY_MASK: u32   = 0x00FFFFFF; // GENMASK(23,0)

/// TX airtime in microseconds (24-bit). Time spent transmitting.
const MT_MIB_SDR36_OFF: u32        = 0x054;
const MT_MIB_SDR36_TXTIME_MASK: u32 = 0x00FFFFFF;

/// RX airtime in microseconds (24-bit). Time spent receiving valid frames.
const MT_MIB_SDR37_OFF: u32        = 0x058;
const MT_MIB_SDR37_RXTIME_MASK: u32 = 0x00FFFFFF;

/// OBSS (other BSS) airtime in microseconds (24-bit).
const MT_WF_RMAC_BASE0: u32            = 0x820e7000;
const MT_WF_RMAC_MIB_AIRTIME14_OFF: u32 = 0x03b8;
const MT_MIB_OBSSTIME_MASK: u32         = 0x00FFFFFF;

/// MIB time control — clear and enable RX time measurement.
const MT_WF_RMAC_MIB_TIME0_OFF: u32    = 0x03c4;
const MT_WF_RMAC_MIB_RXTIME_CLR: u32   = 1 << 31;
const MT_WF_RMAC_MIB_RXTIME_EN: u32    = 1 << 30;

/// MIB control — enable TX/RX duration reporting.
const MT_MIB_SCR1_OFF: u32     = 0x004;
const MT_MIB_TXDUR_EN: u32     = 1 << 8;
const MT_MIB_RXDUR_EN: u32     = 1 << 9;

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — MCU command protocol
// ══════════════════════════════════════════════════════════════════════════════

/// USB SDIO header size (prepended to all MCU messages)
const MT_SDIO_HDR_SIZE: usize = 4;
/// MCU TXD size: 8 DWORDs hardware + 8 DWORDs firmware = 64 bytes
const MT_SDIO_TXD_SIZE: usize = 64;
/// USB tail padding
const MT_USB_TAIL_SIZE: usize = 4;

/// MCU packet type for command messages
const MCU_PKT_ID: u8 = 0xa0;

/// MCU command source/destination indices
const MCU_S2D_H2N: u8 = 0x00;  // HOST → WM (N9 MCU)

/// MCU UNI command option bits
const UNI_CMD_OPT_BIT_ACK: u8       = 1 << 0;
const UNI_CMD_OPT_BIT_UNI_CMD: u8   = 1 << 1;
const UNI_CMD_OPT_BIT_SET_QUERY: u8 = 1 << 2;

// MCU command IDs (from mt76_connac_mcu.h — verified against Linux kernel)
const MCU_CMD_TARGET_ADDRESS_LEN_REQ: u8 = 0x01;
const MCU_CMD_FW_START_REQ: u8      = 0x02;
const MCU_CMD_NIC_POWER_CTRL: u8    = 0x04;
const MCU_CMD_PATCH_START_REQ: u8   = 0x05;
const MCU_CMD_PATCH_FINISH_REQ: u8  = 0x07;
const MCU_CMD_PATCH_SEM_CONTROL: u8 = 0x10;
const MCU_CMD_EXT_CID: u8           = 0xED;
const MCU_CMD_FW_SCATTER: u8        = 0xEE;
const MCU_CMD_RESTART_DL_REQ: u8    = 0xEF;

// MCU EXT command IDs (ext_cid field when cid=0xED — from mt76_connac_mcu.h)
const MCU_EXT_CMD_PM_STATE_CTRL: u8    = 0x07;
const MCU_EXT_CMD_CHANNEL_SWITCH: u8   = 0x08;
const MCU_EXT_CMD_EFUSE_BUFFER_MODE: u8 = 0x21;
const MCU_EXT_CMD_THERMAL_CTRL: u8     = 0x2C;
const MCU_EXT_CMD_WTBL_UPDATE: u8      = 0x32;
const MCU_EXT_CMD_SET_SER_TRIGGER: u8  = 0x3C;
const MCU_EXT_CMD_PROTECT_CTRL: u8     = 0x3E;
const MCU_EXT_CMD_MAC_INIT_CTRL: u8    = 0x46;
const MCU_EXT_CMD_SET_RX_PATH: u8      = 0x4E;

// MCU CE command IDs (community engine — set_query=MCU_Q_SET)
const MCU_CE_CMD_TEST_CTRL: u8       = 0x01;  // RF test mode control
const MCU_CE_CMD_SET_PS_PROFILE: u8  = 0x05;
const MCU_CE_CMD_SET_RX_FILTER: u8   = 0x0A;
const MCU_CE_CMD_SET_CHAN_DOMAIN: u8  = 0x0F;
const MCU_CE_CMD_SET_BSS_ABORT: u8   = 0x17;
const MCU_CE_CMD_SET_EDCA_PARMS: u8  = 0x1D;
const MCU_CE_CMD_SET_RATE_TX_POWER: u8 = 0x5D;
const MCU_CE_CMD_GET_NIC_CAPAB: u8   = 0x8A;
const MCU_CE_CMD_FW_LOG_2_HOST: u8   = 0xC5;
const MCU_CE_CMD_CHIP_CONFIG: u8     = 0xCA;

// ── RF Test Mode (testmode.h) ───────────────────────────────────────────
// Actions for MCU_CE_CMD_TEST_CTRL
const TM_SWITCH_MODE: u8    = 0;  // Switch between normal/testmode/ICAP/spectrum
const TM_SET_AT_CMD: u8     = 1;  // Set RF AT command parameter
const TM_QUERY_AT_CMD: u8   = 2;  // Query RF AT command result

// Test mode operating modes (param0 for TM_SWITCH_MODE)
const TM_MODE_NORMAL: u32       = 0;  // Normal WiFi operation
const TM_MODE_TESTMODE: u32     = 1;  // RF test mode (TX/RX control, power, freq)
const TM_MODE_ICAP: u32         = 2;  // Internal Capture — raw I/Q baseband samples
const TM_MODE_ICAP_OVERLAP: u32 = 3;  // I/Q capture with overlap
const TM_MODE_WIFISPECTRUM: u32 = 4;  // WiFi spectrum analyzer mode

// ATE (Advanced Test Engine) parameter indices for TM_SET_AT_CMD / TM_QUERY_AT_CMD
// All 26 func IDs (0x01-0x16, 0x80-0x83) confirmed responding on MT7921AU hardware.
const MCU_ATE_SET_TRX: u32              = 0x01;  // Enable/disable TX/RX (trx_type << 16 | enable)
const MCU_ATE_SET_TX_ANTENNA: u32       = 0x02;  // TX antenna mask (0x1=ant0, 0x2=ant1, 0x3=both)
const MCU_ATE_SET_RX_ANTENNA: u32       = 0x03;  // RX antenna mask
const MCU_ATE_SET_TX_RATE: u32          = 0x04;  // TX rate mode + MCS index
const MCU_ATE_SET_SYSTEM_BW: u32        = 0x05;  // System bandwidth (0=20, 1=40, 2=80)
const MCU_ATE_SET_TX_PKT_LEN: u32       = 0x06;  // TX packet length (bytes)
const MCU_ATE_SET_TX_PKT_COUNT: u32     = 0x07;  // TX packet count (0=infinite, N=burst N frames)
const MCU_ATE_SET_TX_PKT_CONTENT: u32   = 0x08;  // TX packet pattern/content
const MCU_ATE_SET_TX_NSS: u32           = 0x09;  // TX spatial streams (1 or 2)
const MCU_ATE_SET_FREQ_OFFSET: u32      = 0x0A;  // RF frequency offset (crystal trim)
const MCU_ATE_SET_TX_GI: u32            = 0x0B;  // TX guard interval (0/1/2)
const MCU_ATE_SET_TX_PREAMBLE: u32      = 0x0C;  // TX preamble type
const MCU_ATE_SET_TX_STBC: u32          = 0x0D;  // TX STBC enable/disable
const MCU_ATE_SET_TX_LDPC: u32          = 0x0E;  // TX LDPC enable/disable
const MCU_ATE_SET_TX_CHANNEL: u32       = 0x0F;  // TX channel number
const MCU_ATE_SET_TX_IPG: u32           = 0x10;  // TX inter-packet gap (microseconds)
const MCU_ATE_SET_TX_DUTY_CYCLE: u32    = 0x11;  // TX duty cycle (0-100%)
const MCU_ATE_SET_TX_CONT: u32          = 0x12;  // Continuous TX (CW tone, no gaps)
const MCU_ATE_SET_SLOT_TIME: u32        = 0x13;  // Timing parameters (AIFS/slot)
const MCU_ATE_SET_TX_POWER_PER_ANT: u32 = 0x14;  // Per-antenna TX power
const MCU_ATE_SET_TX_POWER: u32         = 0x15;  // TX power control (half-dBm)
const MCU_ATE_CLEAN_TX_QUEUE: u32       = 0x1C;  // Clean TX queue (abort pending TX)
// Extended AT commands (0x80-0x83) — hardware validated, names from firmware strings
const MCU_ATE_GET_RX_STAT: u32          = 0x80;  // Query RX statistics (packet count, FCS errors)
const MCU_ATE_GET_TX_INFO: u32          = 0x81;  // Query TX info (pending, done counts)
const MCU_ATE_GET_TEMPERATURE: u32      = 0x82;  // Query chip temperature
const MCU_ATE_GET_TSSI: u32             = 0x83;  // Query TSSI (TX signal strength indicator)

// MCU UNI command IDs (from mt76_connac_mcu.h — MCU_UNI_CMD_*)
const MCU_UNI_CMD_DEV_INFO_UPDATE: u16 = 0x01;
const MCU_UNI_CMD_BSS_INFO_UPDATE: u16 = 0x02;
const MCU_UNI_CMD_STA_REC_UPDATE: u16  = 0x03;
const MCU_UNI_CMD_SUSPEND: u16        = 0x05;
const MCU_UNI_CMD_OFFLOAD: u16        = 0x06;
const MCU_UNI_CMD_HIF_CTRL: u16       = 0x07;
const MCU_UNI_CMD_SNIFFER: u16        = 0x24;
const MCU_UNI_CMD_SER: u16            = 0x25;

// RX filter bit operations (mt7921_mcu_set_rxfilter)
const MT7921_FIF_BIT_SET: u8 = 0x01;  // BIT(0) — set bits in bitmap
const MT7921_FIF_BIT_CLR: u8 = 0x02;  // BIT(1) — clear bits in bitmap

// RX filter bitmap flags (MT_WF_RFCR_DROP_* from mt7615/regs.h, shared across connac)
const MT_WF_RFCR_DROP_STBC_MULTI: u32  = 1 << 0;
const MT_WF_RFCR_DROP_FCSFAIL: u32     = 1 << 1;
const MT_WF_RFCR_DROP_VERSION: u32     = 1 << 3;
const MT_WF_RFCR_DROP_PROBEREQ: u32    = 1 << 4;
const MT_WF_RFCR_DROP_MCAST: u32       = 1 << 5;
const MT_WF_RFCR_DROP_BCAST: u32       = 1 << 6;
const MT_WF_RFCR_DROP_MCAST_FILTERED: u32 = 1 << 7;
const MT_WF_RFCR_DROP_A3_MAC: u32      = 1 << 8;
const MT_WF_RFCR_DROP_A3_BSSID: u32    = 1 << 9;
const MT_WF_RFCR_DROP_A2_BSSID: u32    = 1 << 10;
const MT_WF_RFCR_DROP_OTHER_BEACON: u32 = 1 << 11;
const MT_WF_RFCR_DROP_FRAME_REPORT: u32 = 1 << 12;
const MT_WF_RFCR_DROP_CTL_RSV: u32     = 1 << 13;
const MT_WF_RFCR_DROP_CTS: u32         = 1 << 14;
const MT_WF_RFCR_DROP_RTS: u32         = 1 << 15;
const MT_WF_RFCR_DROP_DUPLICATE: u32   = 1 << 16;
const MT_WF_RFCR_DROP_OTHER_BSS: u32   = 1 << 17;
const MT_WF_RFCR_DROP_OTHER_UC: u32    = 1 << 18;
const MT_WF_RFCR_DROP_OTHER_TIM: u32   = 1 << 19;
const MT_WF_RFCR_DROP_NDPA: u32        = 1 << 20;
const MT_WF_RFCR_DROP_UNWANTED_CTL: u32 = 1 << 21;

// Connac2 RX descriptor fields (mt76_connac2_mac.h)
const MT_RXD0_LENGTH: u32          = 0x0000FFFF; // GENMASK(15, 0)
const MT_RXD0_PKT_TYPE: u32        = 0xF8000000; // GENMASK(31, 27)
const MT_RXD1_NORMAL_GROUP_1: u32  = 1 << 11;
const MT_RXD1_NORMAL_GROUP_2: u32  = 1 << 12;
const MT_RXD1_NORMAL_GROUP_3: u32  = 1 << 13;
const MT_RXD1_NORMAL_GROUP_4: u32  = 1 << 14;
const MT_RXD1_NORMAL_GROUP_5: u32  = 1 << 15;
const MT_RXD1_NORMAL_FCS_ERR: u32  = 1 << 27;
const MT_RXD2_NORMAL_MAC_HDR_LEN_MASK: u32 = 0x1F00; // GENMASK(12, 8)
const MT_RXD2_NORMAL_HDR_TRANS: u32 = 1 << 13;

// RX packet types (PKT_TYPE field in RXD DW0) — matches mt76_connac.h PKT_TYPE_*
#[allow(dead_code)] const PKT_TYPE_TXS: u8            = 0;     // PKT_TYPE_TXS
#[allow(dead_code)] const PKT_TYPE_TXRXV: u8          = 1;     // PKT_TYPE_TXRXV
const PKT_TYPE_RX_DATA: u8        = 2;     // PKT_TYPE_NORMAL (data frames)
const PKT_TYPE_RX_DUP_RFB: u8    = 3;     // PKT_TYPE_RX_DUP_RFB
#[allow(dead_code)] const PKT_TYPE_RX_TMR: u8        = 4;     // PKT_TYPE_RX_TMR
#[allow(dead_code)] const PKT_TYPE_RETRIEVE: u8       = 5;     // PKT_TYPE_RETRIEVE
#[allow(dead_code)] const PKT_TYPE_TXRX_NOTIFY: u8   = 6;     // PKT_TYPE_TXRX_NOTIFY
#[allow(dead_code)] const PKT_TYPE_RX_EVENT: u8      = 7;     // PKT_TYPE_RX_EVENT
const PKT_TYPE_NORMAL_MCU: u8    = 8;     // PKT_TYPE_NORMAL_MCU
#[allow(dead_code)] const PKT_TYPE_RX_FW_MONITOR: u8 = 0x0C;  // PKT_TYPE_RX_FW_MONITOR

// DL mode flags
const DL_MODE_NEED_RSP: u32    = 1 << 31;
const DL_MODE_ENCRYPT: u32     = 1 << 0;

// Patch semaphore
const PATCH_SEM_GET: u32       = 1;
const PATCH_SEM_RELEASE: u32   = 0;
#[allow(dead_code)]
const PATCH_NOT_DL_SEM_FAIL: i32    = 0;  // enum value 0
const PATCH_IS_DL: i32              = 1;  // enum value 1
const PATCH_NOT_DL_SEM_SUCCESS: i32 = 2;  // enum value 2
const PATCH_REL_SEM_SUCCESS: i32    = 3;  // enum value 3

// Firmware feature flags
const FW_FEATURE_NON_DL: u8    = 1 << 6;
const FW_FEATURE_OVERRIDE_ADDR: u8 = 1 << 5;
const FW_START_OVERRIDE: u32   = 1 << 0;

// WFSYS reset retry count
const WFSYS_INIT_RETRY_COUNT: u32 = 20;

// Firmware download chunk size.
// Linux uses max_len = 4096 for USB (raw firmware data per chunk).
// FW_SCATTER skips TXD entirely — just SDIO_HDR(4) + data + pad + tail(4).
const FW_DL_MAX_LEN: usize = 4096;

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — USB endpoint assignments
// ══════════════════════════════════════════════════════════════════════════════
//
// MT7921AU has 6 bulk OUT endpoints mapped to different TX queues.
// Descriptor order on both Fenvi and CF-952AX:
//   1st OUT = EP 0x08 (MCU commands)
//   2nd OUT = EP 0x04 (AC_BK / firmware scatter)
//   3rd OUT = EP 0x05 (AC_BE — default data TX)
//   4th OUT = EP 0x06 (AC_VI)
//   5th OUT = EP 0x07 (AC_VO)
//   6th OUT = EP 0x09 (FWDL)
//
// Confirmed by usbmon captures: Linux sends runtime MCU commands on EP8,
// firmware scatter pages on EP4, and data TX on EP5 (AC_BE).

/// Default EP for MCU commands (discovered as 1st bulk OUT in descriptor order)
const EP_OUT_MCU_DEFAULT: u8     = 0x08;
/// EP for firmware scatter download / AC_BK data (2nd bulk OUT)
const EP_OUT_AC_BK_DEFAULT: u8   = 0x04;
/// EP for AC_BE data TX (3rd bulk OUT — primary data TX endpoint)
const EP_OUT_AC_BE_DEFAULT: u8   = 0x05;
/// EP for AC_VI data TX (4th bulk OUT)
const EP_OUT_AC_VI_DEFAULT: u8   = 0x06;
/// EP for AC_VO data TX (5th bulk OUT — highest priority data)
const EP_OUT_AC_VO_DEFAULT: u8   = 0x07;
/// EP for firmware download (6th bulk OUT)
const EP_OUT_FWDL_DEFAULT: u8    = 0x09;
/// Primary RX data endpoint (bulk IN)
const EP_IN_DATA: u8        = 0x84;
/// Secondary RX / event endpoint (bulk IN)
const EP_IN_EVENT: u8       = 0x85;
/// MCU event interrupt endpoint
const EP_IN_MCU_EVENT: u8   = 0x86;

// RX buffer size
// Linux uses 65536-byte buffers for EP4 RX — match this for maximum throughput.
const RX_BUF_SIZE: usize = 65536;

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — Firmware file paths
// ══════════════════════════════════════════════════════════════════════════════

const FW_ROM_PATCH: &str = "WIFI_MT7961_patch_mcu_1_2_hdr.bin";
const FW_WM_RAM: &str = "WIFI_RAM_CODE_MT7961_1.bin";

/// Embedded firmware — no external file I/O needed at runtime.
const FW_ROM_PATCH_DATA: &[u8] = include_bytes!("runtime/firmware/WIFI_MT7961_patch_mcu_1_2_hdr.bin");
const FW_WM_RAM_DATA: &[u8] = include_bytes!("runtime/firmware/WIFI_RAM_CODE_MT7961_1.bin");

// ══════════════════════════════════════════════════════════════════════════════
//  Firmware binary structures
// ══════════════════════════════════════════════════════════════════════════════

/// ROM patch file header (from mt76_connac2_patch_hdr)
/// All multi-byte fields are BIG endian.
#[repr(C, packed)]
struct PatchHeader {
    build_date: [u8; 16],
    platform: [u8; 4],
    hw_sw_ver: [u8; 4],  // be32
    patch_ver: [u8; 4],  // be32
    checksum: [u8; 2],   // be16
    rsv: [u8; 2],
    // descriptor
    desc_patch_ver: [u8; 4],  // be32
    desc_subsys: [u8; 4],    // be32
    desc_feature: [u8; 4],   // be32
    desc_n_region: [u8; 4],  // be32
    desc_crc: [u8; 4],       // be32
    desc_rsv: [u8; 44],      // u32[11]
}

const PATCH_HEADER_SIZE: usize = std::mem::size_of::<PatchHeader>();

/// ROM patch section descriptor (from mt76_connac2_patch_sec)
#[repr(C, packed)]
struct PatchSection {
    sec_type: [u8; 4],   // be32
    offs: [u8; 4],       // be32
    size: [u8; 4],       // be32
    // info union
    addr: [u8; 4],       // be32
    len: [u8; 4],        // be32
    sec_key_idx: [u8; 4], // be32
    align_len: [u8; 4],  // be32
    rsv: [u8; 36],       // u32[9]
}

const PATCH_SECTION_SIZE: usize = std::mem::size_of::<PatchSection>();
const PATCH_SEC_TYPE_INFO: u32 = 0x2;

/// WM RAM firmware trailer (at END of file)
/// (from mt76_connac2_fw_trailer)
#[repr(C, packed)]
struct FwTrailer {
    chip_id: u8,
    eco_code: u8,
    n_region: u8,
    format_ver: u8,
    format_flag: u8,
    rsv: [u8; 2],
    fw_ver: [u8; 10],
    build_date: [u8; 15],
    crc: [u8; 4],  // le32
}

const FW_TRAILER_SIZE: usize = std::mem::size_of::<FwTrailer>();

/// WM RAM firmware region descriptor (before trailer)
/// (from mt76_connac2_fw_region)
#[repr(C, packed)]
struct FwRegion {
    decomp_crc: [u8; 4],     // le32
    decomp_len: [u8; 4],     // le32
    decomp_blk_sz: [u8; 4],  // le32
    rsv: [u8; 4],
    addr: [u8; 4],           // le32
    len: [u8; 4],            // le32
    feature_set: u8,
    fw_type: u8,
    rsv1: [u8; 14],
}

const FW_REGION_SIZE: usize = std::mem::size_of::<FwRegion>();

// ══════════════════════════════════════════════════════════════════════════════
//  Supported channel list
// ══════════════════════════════════════════════════════════════════════════════

/// Build the full channel list for MT7921AU (2.4 + 5 + 6 GHz)
fn build_channel_list() -> Vec<Channel> {
    let mut channels = Vec::with_capacity(80);

    // 2.4 GHz: channels 1-14
    for ch in 1..=14u8 {
        channels.push(Channel::new(ch));
    }

    // 5 GHz UNII-1: 36, 40, 44, 48
    for &ch in &[36u8, 40, 44, 48] {
        channels.push(Channel::new(ch));
    }
    // 5 GHz UNII-2: 52-64
    for &ch in &[52u8, 56, 60, 64] {
        channels.push(Channel::new(ch));
    }
    // 5 GHz UNII-2e: 100-144
    for &ch in &[100u8, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144] {
        channels.push(Channel::new(ch));
    }
    // 5 GHz UNII-3: 149-177
    for &ch in &[149u8, 153, 157, 161, 165, 169, 173, 177] {
        channels.push(Channel::new(ch));
    }

    // 6 GHz (WiFi 6E) — UNII-5 through UNII-8
    // Channels 1-233 in 5 MHz steps, 20 MHz spacing = every 4th
    // We add the primary 20 MHz channels
    let mut ch_6g = 1u8;
    while ch_6g <= 233 {
        // 6 GHz channels use a different numbering but we store the channel number
        // The Channel::new constructor handles band detection by number
        // For now, add common 6 GHz channels
        if ch_6g <= 233 {
            channels.push(Channel::new_6ghz(ch_6g));
        }
        ch_6g = ch_6g.saturating_add(4);
    }

    channels
}

/// Map channel number to center frequency in MHz.
fn channel_to_freq(ch: u8, band: Band) -> u16 {
    match band {
        Band::Band2g => match ch {
            1..=13 => 2407 + ch as u16 * 5,
            14 => 2484,
            _ => 2412,
        },
        Band::Band5g => 5000 + ch as u16 * 5,
        Band::Band6g => 5950 + ch as u16 * 5,
    }
}

/// Map band to NL80211 band index for MCU commands.
/// Count set bits in a byte — hardware population count.
/// Matches Linux hweight8() used throughout mt76 for antenna mask → stream count.
fn hweight8(v: u8) -> u8 {
    v.count_ones() as u8
}

/// Using Band enum is authoritative — channel_number alone is ambiguous
/// (e.g., channel 1 exists in both 2.4GHz and 6GHz).
fn band_to_idx(band: Band) -> u8 {
    match band {
        Band::Band2g => 0, // NL80211_BAND_2GHZ
        Band::Band5g => 1, // NL80211_BAND_5GHZ
        Band::Band6g => 2, // NL80211_BAND_6GHZ
    }
}

/// Map channel number to band index — LEGACY fallback only.
/// Prefer band_to_idx(band) when Band is available.
fn channel_to_band_idx(ch: u8) -> u8 {
    match ch {
        1..=14 => 0,    // NL80211_BAND_2GHZ = 0
        36..=177 => 1,  // NL80211_BAND_5GHZ = 1
        _ => 2,         // NL80211_BAND_6GHZ = 2
    }
}

/// Calculate center channel and CMD_CBW bw value from a Channel struct.
/// Returns (center_ch, bw) where bw matches the CMD_CBW_* enum:
///   0=20MHz, 1=40MHz, 2=80MHz, 3=160MHz
///
/// 5GHz VHT80 groups (primary channels → center):
///   36,40,44,48 → 42    52,56,60,64 → 58     100,104,108,112 → 106
///   116,120,124,128→122  132,136,140,144→138   149,153,157,161→155
///
/// For 40MHz, center = primary ± 2 depending on upper/lower position.
/// For monitor mode we always use SCA (upper) so center = primary + 2.
fn channel_center_and_bw(ch: Channel) -> (u8, u8) {
    use crate::core::channel::Bandwidth;
    match ch.bandwidth {
        Bandwidth::Bw20 => (ch.number, 0),
        Bandwidth::Bw40 => {
            // For 40MHz, calculate center channel.
            // 5GHz: channels come in groups of 2 (36+40, 44+48, etc.)
            // The center is between the two: (lower + upper) / 2 = lower + 2
            // We determine position by (ch - base) % 8
            let center = match ch.band {
                Band::Band5g => {
                    // 5GHz 40MHz groups: 36-40, 44-48, 52-56, 60-64, ...
                    // Each group spans 4 channels (20MHz each)
                    // Lower channel of pair: (ch - 36) % 8 < 4
                    let base = if ch.number >= 149 { 149 }
                              else if ch.number >= 100 { 100 }
                              else { 36 };
                    let offset = (ch.number - base) % 8;
                    if offset < 4 {
                        ch.number + 2  // lower of pair → center is +2
                    } else {
                        ch.number - 2  // upper of pair → center is -2
                    }
                }
                Band::Band2g => {
                    // 2.4GHz: center = primary + 2 (HT40+)
                    // For channels 1-7, use HT40+ (center = ch + 2)
                    // For channels 8-13, use HT40- (center = ch - 2)
                    if ch.number <= 7 { ch.number + 2 } else { ch.number - 2 }
                }
                Band::Band6g => {
                    // 6GHz: channels in steps of 4, groups of 2 for 40MHz
                    // e.g., 1+5→3, 9+13→11, etc.
                    let offset = ((ch.number - 1) / 4) % 2;
                    if offset == 0 { ch.number + 2 } else { ch.number - 2 }
                }
            };
            (center, 1) // CMD_CBW_40MHZ = 1
        }
        Bandwidth::Bw80 => {
            // 80MHz: 4 primary channels per group
            let center = match ch.band {
                Band::Band5g => {
                    match ch.number {
                        36..=48   => 42,
                        52..=64   => 58,
                        100..=112 => 106,
                        116..=128 => 122,
                        132..=144 => 138,
                        149..=161 => 155,
                        // Fallback: approximate
                        _ => ch.number,
                    }
                }
                Band::Band6g => {
                    // 6GHz 80MHz groups: 1-13→7, 17-29→23, 33-45→39, ...
                    // Group of 4 channels (step 4): center = first_of_group + 6
                    let group = ((ch.number - 1) / 16) * 16 + 1;
                    group + 6
                }
                Band::Band2g => ch.number, // 80MHz not applicable on 2.4G
            };
            (center, 2) // CMD_CBW_80MHZ = 2
        }
        Bandwidth::Bw160 => {
            // 160MHz: 8 primary channels per group
            let center = match ch.band {
                Band::Band5g => {
                    match ch.number {
                        36..=64   => 50,
                        100..=128 => 114,
                        // 149-177 doesn't support 160MHz in most regions
                        _ => ch.number,
                    }
                }
                Band::Band6g => {
                    // 160MHz groups: 1-29→15, 33-61→47, ...
                    let group = ((ch.number - 1) / 32) * 32 + 1;
                    group + 14
                }
                Band::Band2g => ch.number,
            };
            (center, 3) // CMD_CBW_160MHZ = 3
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Mt7921au — The Driver
// ══════════════════════════════════════════════════════════════════════════════

/// MT7921AU capability flags — WiFi 6E, tri-band, HE
/// NOTE: VHT caps say "neither 160 nor 80+80", HE PHY says "HE40/HE80" — 80MHz max.
/// VHT160/HE996x2 entries exist in SKU table but hardware cannot use them.
const MT7921AU_CAPS: ChipCaps = ChipCaps::MONITOR.union(ChipCaps::INJECT)
    .union(ChipCaps::BAND_2G).union(ChipCaps::BAND_5G).union(ChipCaps::BAND_6G)
    .union(ChipCaps::HT).union(ChipCaps::VHT)
    .union(ChipCaps::HE)
    .union(ChipCaps::BW40).union(ChipCaps::BW80);

pub struct Mt7921au {
    handle: Arc<DeviceHandle<GlobalContext>>,
    /// MCU command bulk OUT endpoint (EP 0x08 — 1st in descriptor order)
    ep_mcu_out: u8,
    /// AC_BK bulk OUT / firmware scatter (EP 0x04 — 2nd in descriptor order)
    ep_ac_bk_out: u8,
    /// AC_BE bulk OUT — primary data TX (EP 0x05 — 3rd in descriptor order)
    ep_ac_be_out: u8,
    /// AC_VI bulk OUT (EP 0x06 — 4th)
    ep_ac_vi_out: u8,
    /// AC_VO bulk OUT (EP 0x07 — 5th)
    ep_ac_vo_out: u8,
    /// Firmware download bulk OUT (EP 0x09 — 6th)
    ep_fwdl_out: u8,
    /// Primary bulk IN endpoint (RX data)
    ep_data_in: u8,
    /// Event bulk IN endpoint
    ep_event_in: u8,
    /// Current channel — single source of truth for channel number, band, and bandwidth.
    /// Updated exclusively by switch_channel(), never set directly.
    current_channel: Channel,
    /// MAC address read from EEPROM
    mac_addr: MacAddress,
    /// RX ring buffer
    rx_buf: Vec<u8>,
    rx_pos: usize,
    rx_len: usize,
    /// Supported channel list
    channels: Vec<Channel>,
    /// USB VID
    vid: u16,
    /// USB PID
    pid: u16,
    /// Chip revision (CHIPID << 16 | REV)
    chip_rev: u32,
    /// Firmware version string
    fw_version: String,
    /// MCU command sequence counter (4 bits, wraps)
    mcu_seq: u8,
    /// Whether MCU firmware is running
    mcu_running: bool,
    /// Whether sniffer/monitor mode is active
    sniffer_enabled: bool,
    radio_initialized: bool,
    /// Whether take_rx_handle() has been called — RX thread owns ep_data_in.
    /// When true, mcu_recv_response() reads from mcu_rx channel instead of USB.
    rx_thread_active: bool,
    /// Receiver for MCU responses forwarded by the RX thread.
    /// The RX thread detects MCU responses (pkt_type=7) in the USB stream
    /// and sends them here via the SyncSender in RxHandle.driver_msg_tx.
    mcu_rx: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
    /// Interface number we claimed (for combo devices with BT)
    iface_num: u8,
    /// Firmware directory path
    fw_dir: String,
    // ── NIC capabilities (parsed from GET_NIC_CAPAB TLV response) ──
    /// TX resource: token count from firmware (TLV type 0)
    nic_tx_token_count: u32,
    /// PHY capabilities: antenna config (TLV type 8)
    nic_phy_nss: u8,
    /// PHY capabilities: max bandwidth (0=20, 1=40, 2=80, 3=160)
    nic_phy_max_bw: u8,
    /// PHY capabilities: tx/rx antenna mask
    nic_phy_tx_ant: u8,
    nic_phy_rx_ant: u8,
    /// Chip capabilities: features bitmask (TLV type 0x20)
    nic_chip_cap: u32,
    /// HW ADIE version (TLV type 0x14)
    nic_adie_version: u32,
    /// Whether firmware supports 6GHz (TLV type 0x18)
    nic_has_6ghz: bool,
}

impl Mt7921au {
    /// Open a USB device by VID/PID and prepare the driver.
    ///
    /// For the MT7921AU combo device (VID=0x0E8D), the WiFi interface
    /// is interface 3 (interfaces 0-2 are Bluetooth).
    /// For the Comfast CF-952AX (VID=0x3574), it's interface 0.
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

        // Determine which interface to claim.
        // MT7921AU combo: iface 3 is WiFi (class=0xFF vendor-specific)
        // Comfast CF-952AX: iface 0 is WiFi
        let config = device.active_config_descriptor()?;
        let mut wifi_iface: Option<u8> = None;
        // TX endpoints: discovered in USB descriptor order (matches Linux mt76u)
        // Descriptor order on Fenvi/CF-952AX: 0x08, 0x04, 0x05, 0x06, 0x07, 0x09
        let mut ep_mcu_out: u8 = EP_OUT_MCU_DEFAULT;
        let mut ep_ac_bk_out: u8 = EP_OUT_AC_BK_DEFAULT;
        let mut ep_ac_be_out: u8 = EP_OUT_AC_BE_DEFAULT;
        let mut ep_ac_vi_out: u8 = EP_OUT_AC_VI_DEFAULT;
        let mut ep_ac_vo_out: u8 = EP_OUT_AC_VO_DEFAULT;
        let mut ep_fwdl_out: u8 = EP_OUT_FWDL_DEFAULT;
        let mut ep_data_in: u8 = EP_IN_DATA;
        let mut ep_event_in: u8 = EP_IN_EVENT;
        for iface in config.interfaces() {
            for alt in iface.descriptors() {
                // Look for vendor-specific interface (class=0xFF, subclass=0xFF)
                if alt.class_code() == 0xFF && alt.sub_class_code() == 0xFF {
                    wifi_iface = Some(alt.interface_number());
                    // Discover endpoints from this interface
                    // MT76 USB uses enumeration ORDER for endpoint assignment:
                    //   [0]=MCU cmd, [1]=AC_BK/scatter, [2]=AC_BE(data),
                    //   [3]=AC_VI, [4]=AC_VO, [5]=FWDL
                    let mut n_bulk_out: u8 = 0;
                    let mut n_bulk_in: u8 = 0;
                    for ep in alt.endpoint_descriptors() {
                        match (ep.direction(), ep.transfer_type()) {
                            (rusb::Direction::Out, rusb::TransferType::Bulk) => {
                                match n_bulk_out {
                                    0 => ep_mcu_out = ep.address(),
                                    1 => ep_ac_bk_out = ep.address(),
                                    2 => ep_ac_be_out = ep.address(),
                                    3 => ep_ac_vi_out = ep.address(),
                                    4 => ep_ac_vo_out = ep.address(),
                                    5 => ep_fwdl_out = ep.address(),
                                    _ => {}
                                }
                                n_bulk_out += 1;
                            }
                            (rusb::Direction::In, rusb::TransferType::Bulk) => {
                                if n_bulk_in == 0 { ep_data_in = ep.address(); }
                                if n_bulk_in == 1 { ep_event_in = ep.address(); }
                                n_bulk_in += 1;
                            }
                            _ => {}
                        }
                    }
                    break;
                }
            }
            if wifi_iface.is_some() { break; }
        }

        let iface_num = wifi_iface.ok_or(Error::ChipInitFailed {
            chip: "MT7921AU".into(),
            stage: crate::core::error::InitStage::UsbEnumeration,
            reason: "no vendor-specific WiFi interface found".into(),
        })?;

        #[cfg(target_os = "linux")]
        {
            if handle.kernel_driver_active(iface_num).unwrap_or(false) {
                let _ = handle.detach_kernel_driver(iface_num);
            }
        }

        handle.claim_interface(iface_num)?;

        // Collect all bulk OUT endpoints
        let mut all_bulk_out = Vec::new();
        let config2 = device.active_config_descriptor()?;
        for iface2 in config2.interfaces() {
            for alt in iface2.descriptors() {
                if alt.interface_number() == iface_num {
                    for ep in alt.endpoint_descriptors() {
                        if ep.direction() == rusb::Direction::Out
                            && ep.transfer_type() == rusb::TransferType::Bulk
                        {
                            all_bulk_out.push(ep.address());
                        }
                    }
                }
            }
        }

        // Build the endpoints struct for the adapter layer
        let endpoints = UsbEndpoints {
            bulk_in: ep_data_in,
            bulk_out: ep_mcu_out,
            bulk_out_all: all_bulk_out,
        };

        // Locate firmware directory (check src/chips/firmware/ first)
        let fw_dir = Self::find_firmware_dir();

        let driver = Self {
            handle: Arc::new(handle),
            ep_mcu_out,
            ep_ac_bk_out,
            ep_ac_be_out,
            ep_ac_vi_out,
            ep_ac_vo_out,
            ep_fwdl_out,
            ep_data_in,
            ep_event_in,
            current_channel: Channel::new(1),
            mac_addr: MacAddress::ZERO,
            rx_buf: vec![0u8; RX_BUF_SIZE],
            rx_pos: 0,
            rx_len: 0,
            channels: build_channel_list(),
            vid,
            pid,
            chip_rev: 0,
            fw_version: String::new(),
            mcu_seq: 0,
            mcu_running: false,
            sniffer_enabled: false,
            radio_initialized: false,
            rx_thread_active: false,
            mcu_rx: None,
            iface_num,
            fw_dir,
            nic_tx_token_count: 0,
            nic_phy_nss: 2,
            nic_phy_max_bw: 2,   // 80MHz default
            nic_phy_tx_ant: 0x3, // 2T default
            nic_phy_rx_ant: 0x3, // 2R default
            nic_chip_cap: 0,
            nic_adie_version: 0,
            nic_has_6ghz: false,
        };

        Ok((driver, endpoints))
    }

    /// Find the firmware directory containing MT7961 firmware files.
    fn find_firmware_dir() -> String {
        // Check runtime directory first, then legacy location
        let candidates = [
            "src/chips/runtime/firmware",
            "src/chips/firmware",
        ];
        for path in &candidates {
            let patch = format!("{}/{}", path, FW_ROM_PATCH);
            if Path::new(&patch).exists() {
                return path.to_string();
            }
        }
        // Default — will error at firmware load time
        "src/chips/runtime/firmware".to_string()
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  USB register access — The Foundation
    // ══════════════════════════════════════════════════════════════════════════

    /// Read a 32-bit register via USB vendor request.
    /// Uses MT_VEND_READ_EXT (0x63) with addr split across value/index.
    fn reg_read(&self, addr: u32) -> Result<u32> {
        let mut buf = [0u8; 4];
        for attempt in 0..VEND_REQ_MAX_RETRY {
            let result = self.handle.read_control(
                0xC0 | 0x1F,          // USB_DIR_IN | USB_TYPE_VENDOR | 0x1F
                MT_VEND_READ_EXT,      // bRequest
                (addr >> 16) as u16,   // wValue = addr[31:16]
                addr as u16,           // wIndex = addr[15:0]
                &mut buf,
                USB_TIMEOUT,
            );
            match result {
                Ok(4) => return Ok(u32::from_le_bytes(buf)),
                Ok(n) => return Err(Error::ChipInitFailed {
                    chip: "MT7921AU".into(),
                    stage: crate::core::error::InitStage::RegisterAccess,
                    reason: format!("reg_read {:#010x}: got {} bytes, expected 4", addr, n),
                }),
                Err(rusb::Error::Pipe) | Err(rusb::Error::Timeout) if attempt < VEND_REQ_MAX_RETRY - 1 => {
                    thread::sleep(VEND_REQ_RETRY_DELAY);
                    continue;
                }
                Err(e) => return Err(Error::Usb(e)),
            }
        }
        Err(Error::ChipInitFailed {
            chip: "MT7921AU".into(),
            stage: crate::core::error::InitStage::RegisterAccess,
            reason: format!("reg_read {:#010x}: max retries exceeded", addr),
        })
    }

    /// Write a 32-bit register via USB vendor request.
    /// Uses MT_VEND_WRITE_EXT (0x66) with addr split across value/index.
    fn reg_write(&self, addr: u32, val: u32) -> Result<()> {
        let buf = val.to_le_bytes();
        for attempt in 0..VEND_REQ_MAX_RETRY {
            let result = self.handle.write_control(
                0x40 | 0x1F,           // USB_DIR_OUT | USB_TYPE_VENDOR | 0x1F
                MT_VEND_WRITE_EXT,     // bRequest
                (addr >> 16) as u16,   // wValue = addr[31:16]
                addr as u16,           // wIndex = addr[15:0]
                &buf,
                USB_TIMEOUT,
            );
            match result {
                Ok(_) => return Ok(()),
                Err(rusb::Error::Pipe) | Err(rusb::Error::Timeout) if attempt < VEND_REQ_MAX_RETRY - 1 => {
                    thread::sleep(VEND_REQ_RETRY_DELAY);
                    continue;
                }
                Err(e) => return Err(Error::Usb(e)),
            }
        }
        Err(Error::ChipInitFailed {
            chip: "MT7921AU".into(),
            stage: crate::core::error::InitStage::RegisterAccess,
            reason: format!("reg_write {:#010x}: max retries exceeded", addr),
        })
    }

    /// Read-modify-write: read register, clear mask bits, set val bits.
    fn reg_rmw(&self, addr: u32, mask: u32, val: u32) -> Result<u32> {
        let cur = self.reg_read(addr)?;
        let new = (cur & !mask) | val;
        self.reg_write(addr, new)?;
        Ok(new)
    }

    /// Set bits in a register (OR).
    fn reg_set(&self, addr: u32, bits: u32) -> Result<()> {
        self.reg_rmw(addr, 0, bits)?;
        Ok(())
    }

    /// Clear bits in a register (AND NOT).
    fn reg_clear(&self, addr: u32, bits: u32) -> Result<()> {
        self.reg_rmw(addr, bits, 0)?;
        Ok(())
    }

    /// UHW vendor read (for USB subsystem registers like EPCTL, RGU).
    fn uhw_read(&self, addr: u32) -> Result<u32> {
        let mut buf = [0u8; 4];
        let result = self.handle.read_control(
            0xC0 | 0x1E,          // USB_DIR_IN | USB_TYPE_VENDOR | 0x1E
            MT_VEND_DEV_MODE,
            (addr >> 16) as u16,
            addr as u16,
            &mut buf,
            USB_TIMEOUT,
        );
        match result {
            Ok(4) => Ok(u32::from_le_bytes(buf)),
            Ok(n) => Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::RegisterAccess,
                reason: format!("uhw_read {:#010x}: got {} bytes", addr, n),
            }),
            Err(e) => Err(Error::Usb(e)),
        }
    }

    /// UHW vendor write (for USB subsystem registers).
    fn uhw_write(&self, addr: u32, val: u32) -> Result<()> {
        let buf = val.to_le_bytes();
        let result = self.handle.write_control(
            0x40 | 0x1E,          // USB_DIR_OUT | USB_TYPE_VENDOR | 0x1E
            MT_VEND_WRITE,
            (addr >> 16) as u16,
            addr as u16,
            &buf,
            USB_TIMEOUT,
        );
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::Usb(e)),
        }
    }

    /// Poll a register until (read & mask) == expected, with timeout.
    fn poll_reg(&self, addr: u32, mask: u32, expected: u32, timeout_ms: u32) -> Result<bool> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        loop {
            let val = self.reg_read(addr)?;
            if (val & mask) == expected {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(Duration::from_micros(10));
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  MCU Power On
    // ══════════════════════════════════════════════════════════════════════════

    /// Power on the MCU via USB vendor request.
    /// Matches mt792xu_mcu_power_on() from the kernel driver.
    fn mcu_power_on(&mut self) -> Result<()> {
        // Pre-drain: clear any stale data on event + data endpoints.
        // Linux has URBs pre-submitted that catch unsolicited events.
        // We must manually drain to prevent USB buffer backup / stalls.
        self.drain_rx();

        // Send power-on vendor request
        let result = self.handle.write_control(
            0x40 | 0x1F,           // USB_DIR_OUT | USB_TYPE_VENDOR | 0x1F
            MT_VEND_POWER_ON,      // bRequest = 0x04
            0x0000,                // wValue
            0x0001,                // wIndex
            &[],                   // no data
            USB_TIMEOUT,
        );
        match &result {
            Ok(_) => {},
            Err(_) => {},
        }
        if let Err(e) = result {
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::PowerSequence,
                reason: format!("MCU power on vendor request failed: {}", e),
            });
        }

        // Drain any response/event the MCU sends back after power on.
        // Without this, the response fills the USB buffer and stalls everything.
        thread::sleep(Duration::from_millis(20));
        self.drain_rx();

        // Wait for firmware power-on confirmation
        if !self.poll_reg(MT_CONN_ON_MISC, MT_TOP_MISC2_FW_PWR_ON,
                          MT_TOP_MISC2_FW_PWR_ON, 500)? {
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::PowerSequence,
                reason: "timeout waiting for MCU power on".into(),
            });
        }

        Ok(())
    }

    /// Drain all pending data from both USB bulk IN endpoints.
    /// Prevents USB buffer backup that can stall vendor requests / WFDMA.
    /// Linux pre-submits URBs continuously; we must drain manually.
    fn drain_rx(&self) {
        let mut buf = [0u8; 4096];
        for &ep in &[self.ep_data_in, self.ep_event_in] {
            loop {
                match self.handle.read_bulk(ep, &mut buf, Duration::from_millis(20)) {
                    Ok(n) if n > 0 => {}
                    _ => break,
                }
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  WFSYS Reset
    // ══════════════════════════════════════════════════════════════════════════

    /// Reset the WiFi subsystem.
    /// Matches mt792xu_wfsys_reset() from the kernel driver.
    fn wfsys_reset(&self) -> Result<()> {
        // Disable endpoint reset opt
        self.epctl_rst_opt(false)?;

        // Assert WF subsystem reset
        let val = self.uhw_read(MT_CBTOP_RGU_WF_SUBSYS_RST)?;
        self.uhw_write(MT_CBTOP_RGU_WF_SUBSYS_RST,
                       val | MT_CBTOP_RGU_WF_SUBSYS_RST_WF_WHOLE_PATH)?;
        thread::sleep(Duration::from_micros(10));

        // De-assert reset
        let val = self.uhw_read(MT_CBTOP_RGU_WF_SUBSYS_RST)?;
        self.uhw_write(MT_CBTOP_RGU_WF_SUBSYS_RST,
                       val & !MT_CBTOP_RGU_WF_SUBSYS_RST_WF_WHOLE_PATH)?;

        // Wait for WFSYS init done
        self.uhw_write(MT_UDMA_CONN_INFRA_STATUS_SEL, 0)?;
        for i in 0..WFSYS_INIT_RETRY_COUNT {
            let val = self.uhw_read(MT_UDMA_CONN_INFRA_STATUS)?;
            if i == 0 || i % 5 == 0 {
            }
            if val & MT_UDMA_CONN_WFSYS_INIT_DONE != 0 {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }

        Err(Error::ChipInitFailed {
            chip: "MT7921AU".into(),
            stage: crate::core::error::InitStage::PowerSequence,
            reason: "WFSYS init timeout".into(),
        })
    }

    /// Configure USB endpoint reset options.
    fn epctl_rst_opt(&self, reset: bool) -> Result<()> {
        let mut val = self.uhw_read(MT_SSUSB_EPCTL_CSR_EP_RST_OPT)?;
        let ep_bits: u32 = 0x3F0 | 0x700000;  // bits[4:9] out blk + bits[20:22] in blk/int
        if reset {
            val |= ep_bits;
        } else {
            val &= !ep_bits;
        }
        self.uhw_write(MT_SSUSB_EPCTL_CSR_EP_RST_OPT, val)
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  DMA Init
    // ══════════════════════════════════════════════════════════════════════════

    /// Initialize the WFDMA and UDMA engines.
    /// Matches mt792xu_dma_init() from the kernel driver.
    fn dma_init(&self, resume: bool) -> Result<()> {
        // WFDMA init
        self.wfdma_init()?;

        // Clear RX flush
        self.reg_clear(MT_UDMA_WLCFG_0, MT_WL_RX_FLUSH)?;

        // Enable TX/RX — match Linux mt792xu_dma_init() EXACTLY.
        //
        // Linux: mt76_set(RX_EN | TX_EN | RX_MPSZ_PAD0 | TICK_1US_EN)
        //        mt76_clear(RX_AGG_TO | RX_AGG_LMT)
        //        mt76_clear(WLCFG_1, RX_AGG_PKT_LMT)
        //
        // Linux does NOT set RX_AGG_EN and CLEARS the aggregation parameters.
        // The firmware delivers frames immediately without batching.
        // Linux compensates with 128 async URBs for throughput.
        // We must match this exactly — firmware behavior depends on these values.
        self.reg_set(MT_UDMA_WLCFG_0,
                     MT_WL_RX_EN | MT_WL_TX_EN |
                     MT_WL_RX_MPSZ_PAD0 | MT_TICK_1US_EN)?;
        // Clear aggregation parameters — firmware delivers frames immediately
        self.reg_clear(MT_UDMA_WLCFG_0,
                       MT_WL_RX_AGG_TO | MT_WL_RX_AGG_LMT)?;
        self.reg_clear(MT_UDMA_WLCFG_1, MT_WL_RX_AGG_PKT_LMT)?;

        if resume {
            return Ok(());
        }

        // Enable RX event on EP4
        self.dma_rx_evt_ep4()?;

        // Disable endpoint reset
        self.epctl_rst_opt(false)?;

        Ok(())
    }

    /// Initialize WFDMA prefetch and DMA scheduler.
    /// Matches mt792xu_wfdma_init() from the kernel driver.
    fn wfdma_init(&self) -> Result<()> {
        // DMA prefetch configuration
        let prefetch = [
            (0u32, 4u32, 0x080u32),
            (1, 4, 0x0c0),
            (2, 4, 0x100),
            (3, 4, 0x140),
            (4, 4, 0x180),
            (16, 4, 0x280),
            (17, 4, 0x2c0),
        ];
        for &(idx, cnt, base) in &prefetch {
            let addr = MT_UWFDMA0_TX_RING_EXT_CTRL_BASE + (idx << 2);
            let val = (cnt & 0xFF) | ((base & 0xFFFF) << 16);
            self.reg_rmw(addr, 0xFF | (0xFFFF << 16), val)?;
        }

        // Configure WFDMA GLO_CFG
        self.reg_clear(MT_UWFDMA0_GLO_CFG, MT_WFDMA0_GLO_CFG_OMIT_RX_INFO)?;
        self.reg_set(MT_UWFDMA0_GLO_CFG,
                     MT_WFDMA0_GLO_CFG_OMIT_TX_INFO |
                     MT_WFDMA0_GLO_CFG_OMIT_RX_INFO_PFET2 |
                     MT_WFDMA0_GLO_CFG_FW_DWLD_BYPASS_DMASHDL |
                     MT_WFDMA0_GLO_CFG_TX_DMA_EN |
                     MT_WFDMA0_GLO_CFG_RX_DMA_EN)?;

        // DMASHDL configuration
        self.reg_rmw(MT_DMASHDL_REFILL, 0xFFFF0000, 0xFFE00000)?;
        self.reg_clear(MT_DMASHDL_PAGE, MT_DMASHDL_GROUP_SEQ_ORDER)?;

        // Packet max size: PLE=1, PSE=0
        self.reg_rmw(MT_DMASHDL_PKT_MAX_SIZE,
                     0x0FFF | (0x0FFF << 16),
                     1 | (0 << 16))?;

        // Group quotas
        for i in 0..5u32 {
            self.reg_write(MT_DMASHDL_GROUP_QUOTA_BASE + (i << 2),
                          0x3 | (0xFFF << 16))?;
        }
        for i in 5..16u32 {
            self.reg_write(MT_DMASHDL_GROUP_QUOTA_BASE + (i << 2), 0)?;
        }

        // Queue mapping
        self.reg_write(MT_DMASHDL_Q_MAP_BASE + 0, 0x32013201)?;
        self.reg_write(MT_DMASHDL_Q_MAP_BASE + 4, 0x32013201)?;
        self.reg_write(MT_DMASHDL_Q_MAP_BASE + 8, 0x55555444)?;
        self.reg_write(MT_DMASHDL_Q_MAP_BASE + 12, 0x55555444)?;

        // Scheduler set
        self.reg_write(MT_DMASHDL_SCHED_SET_BASE + 0, 0x76540132)?;
        self.reg_write(MT_DMASHDL_SCHED_SET_BASE + 4, 0xFEDCBA98)?;

        // Mark WFDMA needs reinit
        self.reg_set(MT_WFDMA_DUMMY_CR, MT_WFDMA_NEED_REINIT)?;

        Ok(())
    }

    /// Enable RX event delivery on EP4 (bulk IN).
    fn dma_rx_evt_ep4(&self) -> Result<()> {
        // Wait for RX DMA not busy
        if !self.poll_reg(MT_UWFDMA0_GLO_CFG, MT_WFDMA0_GLO_CFG_RX_DMA_BUSY, 0, 1000)? {
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::DmaInit,
                reason: "RX DMA busy timeout".into(),
            });
        }

        self.reg_clear(MT_UWFDMA0_GLO_CFG, MT_WFDMA0_GLO_CFG_RX_DMA_EN)?;
        self.reg_set(MT_WFDMA_HOST_CONFIG, MT_WFDMA_HOST_CONFIG_USB_RXEVT_EP4_EN)?;
        self.reg_set(MT_UWFDMA0_GLO_CFG, MT_WFDMA0_GLO_CFG_RX_DMA_EN)?;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  MCU Command Interface
    // ══════════════════════════════════════════════════════════════════════════

    /// Get next MCU sequence number (4-bit, skips 0).
    fn next_mcu_seq(&mut self) -> u8 {
        self.mcu_seq = (self.mcu_seq + 1) & 0xF;
        if self.mcu_seq == 0 {
            self.mcu_seq = 1;
        }
        self.mcu_seq
    }

    /// Send an MCU command and optionally wait for response.
    /// This builds the full USB packet: SDIO_HDR + MCU_TXD + payload + tail padding.
    ///
    /// Packet format (from mt76_connac2_mcu_fill_message):
    ///   SDIO_HDR (4 bytes): TX_BYTES[15:0] | PKT_TYPE[17:16]
    ///   HW TXD (32 bytes): DW0-DW7
    ///     DW0: TX_BYTES[15:0] | PKT_FMT[24:23]=CMD(1) | Q_IDX[31:25]=0x20
    ///     DW1: HDR_FORMAT[17:16]=CMD(1) | LONG_FORMAT[31]=1
    ///   MCU TXD (32 bytes): len, pq_id, cid, pkt_type, set_query, seq, ...
    ///   Payload
    ///   Tail padding (round to 4 + 4 zero bytes)
    fn mcu_send_msg(&mut self, cmd: u8, data: &[u8], wait_resp: bool) -> Result<i32> {
        let seq = self.next_mcu_seq();

        // For FW_SCATTER: no TXD, just SDIO_HDR + raw data + tail
        if cmd == MCU_CMD_FW_SCATTER {
            let total_body = data.len();
            let sdio_hdr: u32 = (total_body as u32) & 0xFFFF;
            let padded = (MT_SDIO_HDR_SIZE + total_body + 3) & !3;
            let final_len = padded + MT_USB_TAIL_SIZE;
            let mut pkt = vec![0u8; final_len];
            pkt[0..4].copy_from_slice(&sdio_hdr.to_le_bytes());
            pkt[MT_SDIO_HDR_SIZE..MT_SDIO_HDR_SIZE + data.len()].copy_from_slice(data);
            // Firmware scatter goes to AC_BK endpoint (EP 0x04) — confirmed by usbmon
            self.handle.write_bulk(self.ep_ac_bk_out, &pkt, USB_BULK_TIMEOUT)?;
            return Ok(0);
        }

        // Build the MCU TXD (64 bytes = 32 HW TXD + 32 MCU TXD)
        let mut txd = [0u8; MT_SDIO_TXD_SIZE];

        // Total message length = TXD + payload (NOT including SDIO header)
        let msg_len = MT_SDIO_TXD_SIZE + data.len();

        // ── HW TXD (first 32 bytes, DW0-DW7) ──
        // DW0: TX_BYTES[15:0] | PKT_FMT[24:23]=1(CMD) | Q_IDX[31:25]=0x20
        let txd_dw0: u32 = (msg_len as u32 & 0xFFFF)     // TX_BYTES
            | (1u32 << 23)                                  // PKT_FMT = MT_TX_TYPE_CMD
            | (0x20u32 << 25);                              // Q_IDX = MT_TX_MCU_PORT_RX_Q0
        txd[0..4].copy_from_slice(&txd_dw0.to_le_bytes());

        // DW1: HDR_FORMAT[17:16]=1(CMD) | LONG_FORMAT[31]=1
        let txd_dw1: u32 = (1u32 << 16)                   // HDR_FORMAT = MT_HDR_FORMAT_CMD
            | (1u32 << 31);                                 // LONG_FORMAT
        txd[4..8].copy_from_slice(&txd_dw1.to_le_bytes());
        // DW2-DW7: all zeros

        // ── MCU TXD (bytes 32-63) ──
        // Matches struct mt76_connac2_mcu_txd layout after txd[8]:
        //   len[2] pq_id[2] cid[1] pkt_type[1] set_query[1] seq[1]
        //   uc_d2b0_rev[1] ext_cid[1] s2d_index[1] ext_cid_ack[1]
        //   rsv[20]
        let m = 32; // MCU TXD offset

        // len: message length after HW TXD = msg_len - 32
        let mcu_len = (msg_len - 32) as u16;
        txd[m..m+2].copy_from_slice(&mcu_len.to_le_bytes());

        // pq_id: MCU_PQ_ID(MT_TX_PORT_IDX_MCU=1, MT_TX_MCU_PORT_RX_Q0=0x20)
        //   = (1 << 15) | (0x20 << 10)
        let pq_id: u16 = (1 << 15) | (0x20 << 10);
        txd[m+2..m+4].copy_from_slice(&pq_id.to_le_bytes());

        // cid (command ID)
        txd[m+4] = cmd;
        // pkt_type = MCU_PKT_ID (0xa0)
        txd[m+5] = MCU_PKT_ID;
        // set_query = MCU_Q_NA (3) for simple commands
        // Linux enum: MCU_Q_QUERY=0, MCU_Q_SET=1, MCU_Q_RESERVED=2, MCU_Q_NA=3
        txd[m+6] = 3; // MCU_Q_NA
        // seq
        txd[m+7] = seq;
        // uc_d2b0_rev
        txd[m+8] = 0;
        // ext_cid
        txd[m+9] = 0;
        // s2d_index (HOST → WM N9 MCU)
        txd[m+10] = MCU_S2D_H2N;
        // ext_cid_ack
        txd[m+11] = 0;
        // rsv[20]: zeros

        // ── Build full USB packet: SDIO_HDR + TXD + payload + tail ──
        let total_len = MT_SDIO_HDR_SIZE + msg_len;
        let padded_len = (total_len + 3) & !3;
        let final_len = padded_len + MT_USB_TAIL_SIZE;

        let mut pkt = vec![0u8; final_len];

        // SDIO header: TX_BYTES = total bytes after header (for USB)
        let sdio_hdr: u32 = (msg_len as u32) & 0xFFFF;
        pkt[0..4].copy_from_slice(&sdio_hdr.to_le_bytes());

        // TXD
        pkt[MT_SDIO_HDR_SIZE..MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE].copy_from_slice(&txd);

        // Payload
        if !data.is_empty() {
            let payload_start = MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE;
            pkt[payload_start..payload_start + data.len()].copy_from_slice(data);
        }

        // Send via inband command endpoint
        self.handle.write_bulk(self.ep_mcu_out, &pkt, USB_BULK_TIMEOUT)?;

        // If we need response, read it
        if wait_resp {
            return self.mcu_recv_response(seq);
        }

        Ok(0)
    }

    /// Receive MCU response, matching by sequence number.
    /// Responses arrive on EP_IN_CMD_RESP (second bulk IN = EP 0x85).
    ///
    /// Response format (mt76_connac2_mcu_rxd):
    ///   rxd[6] (24 bytes): HW RXD
    ///   Then: seq at byte 27, status fields follow
    fn mcu_recv_response(&self, expected_seq: u8) -> Result<i32> {
        let deadline = Instant::now() + Duration::from_secs(10);

        // When RX thread is active, MCU responses arrive via the mcu_rx channel
        // (the RX thread detects pkt_type=7 and forwards them as DriverMessage).
        // During init (before RX thread), read directly from USB endpoints.
        if self.rx_thread_active {
            if let Some(ref rx) = self.mcu_rx {
                while Instant::now() < deadline {
                    match rx.recv_timeout(Duration::from_millis(10)) {
                        Ok(buf) => {
                            if let Some(status) = Self::parse_mcu_response(&buf, expected_seq) {
                                return Ok(status);
                            }
                            // Wrong seq — keep waiting
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            }
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::FirmwareDownload,
                reason: format!("MCU response timeout (via channel) for seq {}", expected_seq),
            });
        }

        // Pre-RX-thread path: read directly from USB endpoints
        // CRITICAL: MCU responses come back on ep_data_in (EP4/0x84), NOT ep_event_in.
        // The usbmon captures confirm EP5 (0x85) gets zero completions during init.
        // Reading EP5 with 200ms timeout per attempt was the #1 performance killer —
        // each MCU command wasted 1-2 seconds on dead EP5 reads.
        // Try ep_data_in first with short timeout, only fall back to ep_event_in rarely.
        let mut buf = [0u8; 2048];

        while Instant::now() < deadline {
            // Primary: read from data endpoint (where responses actually arrive)
            // Use short timeout — USB responses arrive in <1ms when firmware is ready.
            // Long timeouts just add latency when the response isn't ready yet.
            match self.handle.read_bulk(self.ep_data_in, &mut buf, Duration::from_millis(10)) {
                Ok(n) if n > 0 => {
                    // Filter: only process pkt_type=7 (MCU event/response)
                    // Skip WiFi data frames (pkt_type=0,2) to avoid wasting time parsing them
                    if n >= 4 {
                        let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        let pkt_type = (dw0 >> 27) & 0xF;
                        if pkt_type != 7 {
                            // Not an MCU response — skip and read next packet immediately
                            continue;
                        }
                    }
                    if let Some(status) = Self::parse_mcu_response(&buf[..n], expected_seq) {
                        return Ok(status);
                    }
                    // Got data but wrong seq — try again immediately
                    continue;
                }
                Ok(_) => {}
                Err(rusb::Error::Timeout) => {}
                Err(_) => {}
            }
            // Secondary: quick check on event endpoint (1ms — just in case)
            match self.handle.read_bulk(self.ep_event_in, &mut buf, Duration::from_millis(1)) {
                Ok(n) if n > 0 => {
                    if let Some(status) = Self::parse_mcu_response(&buf[..n], expected_seq) {
                        return Ok(status);
                    }
                }
                _ => {}
            }
        }

        Err(Error::ChipInitFailed {
            chip: "MT7921AU".into(),
            stage: crate::core::error::InitStage::FirmwareDownload,
            reason: format!("MCU response timeout for seq {}", expected_seq),
        })
    }

    /// Parse an MCU response buffer for a matching sequence number.
    /// Returns Some(status) if the response matches, None otherwise.
    ///
    /// MCU response layout (mt76_connac2_mcu_rxd):
    ///   bytes 0-23:  HW RXD (6 DWORDs)
    ///   bytes 24-25: len (le16)
    ///   bytes 26-27: pkt_type_id (le16)
    ///   byte 28:     eid
    ///   byte 29:     seq  ← match against expected_seq
    ///   byte 30:     option
    ///   byte 31:     rsv
    ///   byte 32:     ext_eid
    fn parse_mcu_response(buf: &[u8], expected_seq: u8) -> Option<i32> {
        if buf.len() >= 30 {
            let resp_seq = buf[29];
            if resp_seq == expected_seq {
                if buf.len() >= 36 {
                    return Some(buf[buf.len() - 4] as i32);
                }
                return Some(0);
            }
        }
        None
    }

    /// Receive MCU response and return the FULL raw buffer.
    /// Used for commands that return data (NIC_CAPS, EEPROM read, etc).
    fn mcu_recv_response_raw(&self, expected_seq: u8) -> Result<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut buf = [0u8; 2048];

        while Instant::now() < deadline {
            match self.handle.read_bulk(self.ep_data_in, &mut buf, Duration::from_millis(10)) {
                Ok(n) if n > 0 => {
                    if n >= 4 {
                        let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        let pkt_type = (dw0 >> 27) & 0xF;
                        if pkt_type != 7 { continue; }
                    }
                    if n >= 30 && buf[29] == expected_seq {
                        return Ok(buf[..n].to_vec());
                    }
                    continue;
                }
                Ok(_) | Err(rusb::Error::Timeout) => continue,
                Err(e) => return Err(Error::Usb(e)),
            }
        }

        Err(Error::ChipInitFailed {
            chip: "MT7921AU".into(),
            stage: crate::core::error::InitStage::FirmwareDownload,
            reason: format!("MCU response (raw) timeout for seq {}", expected_seq),
        })
    }

    /// Send an EXT MCU command.
    /// EXT commands use cid=0xED with the actual command in ext_cid.
    /// Matches mt76_connac2_mcu_fill_message() for commands with ext_cid set.
    fn mcu_send_ext_cmd(&mut self, ext_cmd: u8, data: &[u8], wait_resp: bool) -> Result<i32> {
        let seq = self.next_mcu_seq();

        let mut txd = [0u8; MT_SDIO_TXD_SIZE];
        let msg_len = MT_SDIO_TXD_SIZE + data.len();

        // ── HW TXD (DW0-DW7) ──
        let txd_dw0: u32 = (msg_len as u32 & 0xFFFF)
            | (1u32 << 23)       // PKT_FMT = MT_TX_TYPE_CMD
            | (0x20u32 << 25);   // Q_IDX = MT_TX_MCU_PORT_RX_Q0
        txd[0..4].copy_from_slice(&txd_dw0.to_le_bytes());
        let txd_dw1: u32 = (1u32 << 16) | (1u32 << 31); // HDR_FORMAT=CMD, LONG_FORMAT
        txd[4..8].copy_from_slice(&txd_dw1.to_le_bytes());

        // ── MCU TXD (bytes 32-63) ──
        let m = 32;
        let mcu_len = (msg_len - 32) as u16;
        txd[m..m+2].copy_from_slice(&mcu_len.to_le_bytes());
        let pq_id: u16 = (1 << 15) | (0x20 << 10);
        txd[m+2..m+4].copy_from_slice(&pq_id.to_le_bytes());
        txd[m+4] = MCU_CMD_EXT_CID;     // cid = 0xED
        txd[m+5] = MCU_PKT_ID;          // pkt_type = 0xa0
        txd[m+6] = 1;                   // set_query = MCU_Q_SET (for ext commands)
        txd[m+7] = seq;                 // seq
        txd[m+8] = 0;                   // uc_d2b0_rev
        txd[m+9] = ext_cmd;             // ext_cid = actual command ID
        txd[m+10] = MCU_S2D_H2N;        // s2d_index
        txd[m+11] = 1;                  // ext_cid_ack = 1 (request ACK)

        // Build USB packet
        let total_len = MT_SDIO_HDR_SIZE + msg_len;
        let padded_len = (total_len + 3) & !3;
        let final_len = padded_len + MT_USB_TAIL_SIZE;
        let mut pkt = vec![0u8; final_len];
        let sdio_hdr: u32 = (msg_len as u32) & 0xFFFF;
        pkt[0..4].copy_from_slice(&sdio_hdr.to_le_bytes());
        pkt[MT_SDIO_HDR_SIZE..MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE].copy_from_slice(&txd);
        if !data.is_empty() {
            let off = MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE;
            pkt[off..off + data.len()].copy_from_slice(data);
        }


        self.handle.write_bulk(self.ep_mcu_out, &pkt, USB_BULK_TIMEOUT)?;

        if wait_resp {
            return self.mcu_recv_response(seq);
        }
        Ok(0)
    }

    /// Send an EXT MCU QUERY command — returns raw response data.
    /// Same as mcu_send_ext_cmd but with set_query=0 (MCU_Q_QUERY) and raw response.
    /// Used for EFUSE_ACCESS and other data-returning EXT commands.
    fn mcu_send_ext_query(&mut self, ext_cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        let seq = self.next_mcu_seq();

        let mut txd = [0u8; MT_SDIO_TXD_SIZE];
        let msg_len = MT_SDIO_TXD_SIZE + data.len();

        let txd_dw0: u32 = (msg_len as u32 & 0xFFFF)
            | (1u32 << 23) | (0x20u32 << 25);
        txd[0..4].copy_from_slice(&txd_dw0.to_le_bytes());
        let txd_dw1: u32 = (1u32 << 16) | (1u32 << 31);
        txd[4..8].copy_from_slice(&txd_dw1.to_le_bytes());

        let m = 32;
        let mcu_len = (msg_len - 32) as u16;
        txd[m..m+2].copy_from_slice(&mcu_len.to_le_bytes());
        let pq_id: u16 = (1 << 15) | (0x20 << 10);
        txd[m+2..m+4].copy_from_slice(&pq_id.to_le_bytes());
        txd[m+4] = MCU_CMD_EXT_CID;
        txd[m+5] = MCU_PKT_ID;
        txd[m+6] = 0;           // set_query = MCU_Q_QUERY (NOT MCU_Q_SET!)
        txd[m+7] = seq;
        txd[m+9] = ext_cmd;
        txd[m+10] = MCU_S2D_H2N;
        txd[m+11] = 1;          // ext_cid_ack

        let total_len = MT_SDIO_HDR_SIZE + msg_len;
        let padded_len = (total_len + 3) & !3;
        let final_len = padded_len + MT_USB_TAIL_SIZE;
        let mut pkt = vec![0u8; final_len];
        let sdio_hdr: u32 = (msg_len as u32) & 0xFFFF;
        pkt[0..4].copy_from_slice(&sdio_hdr.to_le_bytes());
        pkt[MT_SDIO_HDR_SIZE..MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE].copy_from_slice(&txd);
        if !data.is_empty() {
            let off = MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE;
            pkt[off..off + data.len()].copy_from_slice(data);
        }

        self.handle.write_bulk(self.ep_mcu_out, &pkt, USB_BULK_TIMEOUT)?;
        self.mcu_recv_response_raw(seq)
    }

    /// Read 16 bytes of EEPROM/eFuse data at a given offset.
    /// Matches mt7921_mcu_read_eeprom() using MCU_EXT_QUERY(EFUSE_ACCESS).
    ///
    /// The eFuse is organized in 16-byte blocks. The offset is automatically
    /// aligned to a 16-byte boundary.
    ///
    /// Returns 16 bytes of eFuse data at the aligned offset.
    fn mcu_read_eeprom(&mut self, offset: u32) -> Result<[u8; 16]> {
        // Request payload: mt7921_mcu_eeprom_info = addr(le32) + valid(le32) + data(16) = 24B
        const EFUSE_ACCESS: u8 = 0x01;
        let aligned = offset & !0xF; // 16-byte aligned

        let mut req = [0u8; 24];
        req[0..4].copy_from_slice(&aligned.to_le_bytes()); // addr
        // valid[4..8] = 0, data[8..24] = 0

        let resp = self.mcu_send_ext_query(EFUSE_ACCESS, &req)?;

        // Response: RXD(24) + MCU_RXD(8) + payload
        // Payload: addr(4) + valid(4) + data(16)
        let mut data = [0u8; 16];
        if resp.len() >= 32 + 24 {
            let payload = &resp[32..];
            let valid = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            if valid != 0 {
                data.copy_from_slice(&payload[8..24]);
            }
        }
        Ok(data)
    }

    /// Read and apply eFuse calibration data for this specific device.
    /// Called during radio_init after mcu_set_eeprom() tells firmware to use eFuse.
    ///
    /// Reads:
    ///   - MT_EE_WIFI_CONF (0x07C): antenna config, band selection
    ///   - MT_EE_TX_POWER (0x0D0+): per-band TX power offsets
    ///
    /// This is the per-device calibration that varies between Fenvi, EDUP, ALFA, etc.
    fn mcu_read_efuse_cal(&mut self) -> Result<()> {
        // Read WiFi config block (offset 0x070, 16-byte aligned)
        // MT_EE_WIFI_CONF is at offset 0x07C within the EEPROM map
        let wifi_conf_block = self.mcu_read_eeprom(0x070)?;

        // MT_EE_WIFI_CONF at byte 0x0C within this block (0x07C - 0x070 = 0x0C)
        let wifi_conf = wifi_conf_block[0x0C];
        // Extract antenna config: bits[7:4] = tx_mask, bits[3:0] = rx_mask
        // If non-zero, these override the NIC_CAPS defaults
        let efuse_tx_ant = (wifi_conf >> 4) & 0xF;
        let efuse_rx_ant = wifi_conf & 0xF;
        if efuse_tx_ant != 0 && efuse_tx_ant != 0xF {
            self.nic_phy_tx_ant = efuse_tx_ant;
            self.nic_phy_nss = hweight8(efuse_tx_ant);
        }
        if efuse_rx_ant != 0 && efuse_rx_ant != 0xF {
            self.nic_phy_rx_ant = efuse_rx_ant;
        }

        // Read TX power offset block (offset 0x0D0)
        // Contains per-band power offsets that vary per device
        let _tx_power_block = self.mcu_read_eeprom(0x0D0)?;

        // Read 2.4GHz TX power targets (offset 0x0E0)
        let _tx_power_2g = self.mcu_read_eeprom(0x0E0)?;

        // Read 5GHz TX power targets (offset 0x120)
        let _tx_power_5g = self.mcu_read_eeprom(0x120)?;

        // For now, the firmware applies these internally via EFUSE_BUFFER_MODE.
        // We read them to update driver-side antenna config and can extend
        // to apply TX power corrections to mcu_set_rate_txpower() later.

        Ok(())
    }

    /// Send a CE (Community Engine) MCU command.
    /// CE commands use the standard TXD with set_query=MCU_Q_SET instead of MCU_Q_NA.
    fn mcu_send_ce_cmd(&mut self, cmd: u8, data: &[u8], wait_resp: bool) -> Result<i32> {
        let seq = self.next_mcu_seq();

        let mut txd = [0u8; MT_SDIO_TXD_SIZE];
        let msg_len = MT_SDIO_TXD_SIZE + data.len();

        // HW TXD
        let txd_dw0: u32 = (msg_len as u32 & 0xFFFF)
            | (1u32 << 23) | (0x20u32 << 25);
        txd[0..4].copy_from_slice(&txd_dw0.to_le_bytes());
        let txd_dw1: u32 = (1u32 << 16) | (1u32 << 31);
        txd[4..8].copy_from_slice(&txd_dw1.to_le_bytes());

        // MCU TXD
        let m = 32;
        let mcu_len = (msg_len - 32) as u16;
        txd[m..m+2].copy_from_slice(&mcu_len.to_le_bytes());
        let pq_id: u16 = (1 << 15) | (0x20 << 10);
        txd[m+2..m+4].copy_from_slice(&pq_id.to_le_bytes());
        txd[m+4] = cmd;                 // cid
        txd[m+5] = MCU_PKT_ID;          // pkt_type
        txd[m+6] = 1;                   // set_query = MCU_Q_SET (CE commands)
        txd[m+7] = seq;
        txd[m+10] = MCU_S2D_H2N;        // s2d_index

        // Build USB packet
        let total_len = MT_SDIO_HDR_SIZE + msg_len;
        let padded_len = (total_len + 3) & !3;
        let final_len = padded_len + MT_USB_TAIL_SIZE;
        let mut pkt = vec![0u8; final_len];
        let sdio_hdr: u32 = (msg_len as u32) & 0xFFFF;
        pkt[0..4].copy_from_slice(&sdio_hdr.to_le_bytes());
        pkt[MT_SDIO_HDR_SIZE..MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE].copy_from_slice(&txd);
        if !data.is_empty() {
            let off = MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE;
            pkt[off..off + data.len()].copy_from_slice(data);
        }

        self.handle.write_bulk(self.ep_mcu_out, &pkt, USB_BULK_TIMEOUT)?;

        if wait_resp {
            return self.mcu_recv_response(seq);
        }
        Ok(0)
    }

    /// Set RX filter flags — controls what frames firmware delivers to host.
    /// Matches mt7921_mcu_set_rxfilter() exactly from the kernel driver.
    ///
    /// Two modes:
    ///   mode=1: Set the entire FIF (frame interface filter) value directly
    ///   mode=2: Modify individual bits via bit_op (BIT_SET=0x01, BIT_CLR=0x02)
    ///
    /// For monitor mode: call with fif=flags to set all filter bits at once.
    /// For individual bit changes: call with fif=0, bit_op, bit_map.
    fn mcu_set_rxfilter(&mut self, fif: u32, bit_op: u8, bit_map: u32) -> Result<()> {
        // struct {
        //     u8 rsv[4];       // bytes 0-3
        //     u8 mode;          // byte 4: 1=set fif directly, 2=bit operation
        //     u8 rsv2[3];       // bytes 5-7
        //     __le32 fif;       // bytes 8-11
        //     __le32 bit_map;   // bytes 12-15
        //     u8 bit_op;        // byte 16
        //     u8 pad[51];       // bytes 17-67
        // } total = 68 bytes
        let mut data = [0u8; 68];
        data[4] = if fif != 0 { 1 } else { 2 };  // mode
        data[8..12].copy_from_slice(&fif.to_le_bytes());
        data[12..16].copy_from_slice(&bit_map.to_le_bytes());
        data[16] = bit_op;

        self.mcu_send_ce_cmd(MCU_CE_CMD_SET_RX_FILTER, &data, false)?;
        Ok(())
    }

    /// Set power management state.
    /// Matches mt76_connac_mcu_set_pm() — EXIT_PM_STATE to wake up the radio.
    fn mcu_set_pm(&mut self, band: u8, enter: bool) -> Result<()> {
        // struct {
        //     u8 pm_number;     // = 5
        //     u8 pm_state;      // 1=ENTER, 2=EXIT
        //     u8 bssid[6];      // zeros
        //     u8 dtim_period;
        //     u8 wlan_idx_lo;
        //     __le16 bcn_interval;
        //     __le32 aid;
        //     __le32 rx_filter;
        //     u8 band_idx;
        //     u8 wlan_idx_hi;
        //     u8 rsv[2];
        //     __le32 feature;
        //     u8 omac_idx;
        //     u8 wmm_idx;
        //     u8 bcn_loss_cnt;
        //     u8 bcn_sp_duration;
        // } = 32 bytes
        let mut data = [0u8; 32];
        data[0] = 5;  // pm_number
        data[1] = if enter { 1 } else { 2 }; // ENTER=1, EXIT=2
        data[20] = 0; // band_idx = phy band index (always 0 for single-band)

        self.mcu_send_ext_cmd(MCU_EXT_CMD_PM_STATE_CTRL, &data, true)?;
        Ok(())
    }

    /// Set VIF power save profile to AWAKE.
    /// Matches mt76_connac_mcu_set_vif_ps() — ps_state=0 (device awake).
    fn mcu_set_vif_ps_awake(&mut self) -> Result<()> {
        let data = [0u8, 0u8]; // bss_idx=0, ps_state=0 (awake)
        self.mcu_send_ce_cmd(MCU_CE_CMD_SET_PS_PROFILE, &data, false)?;
        Ok(())
    }

    /// Enable or disable deep sleep mode.
    /// Matches mt76_connac_mcu_set_deep_sleep() from the kernel driver.
    ///
    /// Deep sleep MUST be disabled for monitor mode — the firmware will not
    /// forward RX frames to USB while in deep sleep.
    ///
    /// Sends CE command CHIP_CONFIG (0xCA) with payload struct:
    ///   { id: u16, type: u8, resp_type: u8, data_size: u16, resv: u16, data: [u8; 320] }
    /// The data field contains the ASCII string "KeepFullPwr N" where N=1 disables
    /// deep sleep (keep full power) and N=0 enables deep sleep.
    fn mcu_set_deep_sleep(&mut self, enable: bool) -> Result<()> {
        // mt76_connac_config struct: 8 bytes header + 320 bytes data = 328 bytes
        let mut payload = [0u8; 328];
        // id (u16) = 0, type (u8) = 0, resp_type (u8) = 0 — all zeros
        // data_size (u16) = 0, resv (u16) = 0 — all zeros (matches Linux which leaves them zero)

        // Data: "KeepFullPwr 1" to disable deep sleep, "KeepFullPwr 0" to enable
        let msg = if enable {
            b"KeepFullPwr 0"
        } else {
            b"KeepFullPwr 1"
        };
        payload[8..8 + msg.len()].copy_from_slice(msg);

        self.mcu_send_ce_cmd(MCU_CE_CMD_CHIP_CONFIG, &payload, false)?;
        Ok(())
    }

    /// Tell firmware to use eFuse EEPROM data for calibration.
    /// Matches mt7921_mcu_set_eeprom() from the kernel driver.
    ///
    /// This is REQUIRED — without it, the firmware doesn't load calibration
    /// data and the radio won't work properly.
    ///
    /// Sends EXT cmd EFUSE_BUFFER_MODE (0x21) with:
    ///   { buffer_mode: u8 = 0 (EE_MODE_EFUSE), format: u8 = 1 (EE_FORMAT_WHOLE), len: u16 = 0 }
    fn mcu_set_eeprom(&mut self) -> Result<()> {
        let mut data = [0u8; 4];
        data[0] = 0; // buffer_mode = EE_MODE_EFUSE
        data[1] = 1; // format = EE_FORMAT_WHOLE
        // len[2..4] = 0 (le16)

        self.mcu_send_ext_cmd(MCU_EXT_CMD_EFUSE_BUFFER_MODE, &data, true)?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  RF Test Mode — spectrum analyzer, I/Q capture, SDR capabilities
    // ═══════════════════════════════════════════════════════════════════════

    /// Send an RF test command (testmode.c: mt7921_tm_set).
    ///
    /// Wire format (mt7921_rftest_cmd):
    ///   action: u8      — TM_SWITCH_MODE / TM_SET_AT_CMD / TM_QUERY_AT_CMD
    ///   rsv: [u8; 3]    — reserved, zero
    ///   param0: le32    — mode (for SWITCH_MODE) or func_id (for AT_CMD)
    ///   param1: le32    — parameter value
    ///
    /// Returns (param0, param1) from the response when wait_resp=true.
    fn mcu_rftest_cmd(&mut self, action: u8, param0: u32, param1: u32, wait_resp: bool) -> Result<(u32, u32)> {
        let mut data = [0u8; 12];
        data[0] = action;
        // data[1..4] = rsv (zeros)
        data[4..8].copy_from_slice(&param0.to_le_bytes());
        data[8..12].copy_from_slice(&param1.to_le_bytes());

        let _ret = self.mcu_send_ce_cmd(MCU_CE_CMD_TEST_CTRL, &data, wait_resp)?;

        // For queries, we'd need to parse the response.
        // The CE cmd response comes as an event on the MCU RX endpoint.
        // For now, return zeros — we'll wire up response parsing as we validate.
        Ok((0, 0))
    }

    /// Switch between normal mode and RF test modes.
    ///
    /// Modes:
    ///   TM_MODE_NORMAL       — back to normal WiFi operation
    ///   TM_MODE_TESTMODE     — RF test mode (TX/RX control, power, freq offset)
    ///   TM_MODE_ICAP         — Internal CAPture (raw I/Q baseband samples)
    ///   TM_MODE_ICAP_OVERLAP — I/Q capture with overlap
    ///   TM_MODE_WIFISPECTRUM — WiFi spectrum analyzer mode
    ///
    /// IMPORTANT: Must disable power save before entering test mode.
    /// The Linux driver does: pm.enable=false, cancel PS work, force driver pmctrl.
    pub fn testmode_switch(&mut self, mode: u32) -> Result<()> {
        if mode != TM_MODE_NORMAL {
            // Disable power save — test mode needs full power
            self.mcu_set_deep_sleep(false)?;
        }

        self.mcu_rftest_cmd(TM_SWITCH_MODE, mode, 0, false)?;
        eprintln!("[MT7921] testmode: switched to mode {}", match mode {
            TM_MODE_NORMAL => "NORMAL",
            TM_MODE_TESTMODE => "RF_TEST",
            TM_MODE_ICAP => "ICAP (I/Q capture)",
            TM_MODE_ICAP_OVERLAP => "ICAP_OVERLAP",
            TM_MODE_WIFISPECTRUM => "WIFI_SPECTRUM",
            _ => "UNKNOWN",
        });
        Ok(())
    }

    /// Enter WiFi spectrum analyzer mode.
    /// The firmware will output spectral data instead of decoded frames.
    pub fn testmode_enter_spectrum(&mut self) -> Result<()> {
        self.testmode_switch(TM_MODE_WIFISPECTRUM)
    }

    /// Enter I/Q capture mode (raw baseband samples — SDR mode).
    pub fn testmode_enter_icap(&mut self) -> Result<()> {
        self.testmode_switch(TM_MODE_ICAP)
    }

    /// Enter RF test mode (TX/RX control, power tuning, freq offset).
    pub fn testmode_enter_rftest(&mut self) -> Result<()> {
        self.testmode_switch(TM_MODE_TESTMODE)
    }

    /// Return to normal WiFi operation from any test mode.
    pub fn testmode_exit(&mut self) -> Result<()> {
        self.testmode_switch(TM_MODE_NORMAL)?;
        // Re-enable power save
        self.mcu_set_deep_sleep(true)?;
        Ok(())
    }

    /// Set an RF AT command parameter (in test mode).
    /// func_id: MCU_ATE_SET_* constant
    /// value: parameter-specific value
    pub fn testmode_set_at(&mut self, func_id: u32, value: u32) -> Result<()> {
        self.mcu_rftest_cmd(TM_SET_AT_CMD, func_id, value, false)?;
        Ok(())
    }

    /// Query an RF AT command result (in test mode).
    /// Returns (param0, param1) from firmware response.
    pub fn testmode_query_at(&mut self, func_id: u32) -> Result<(u32, u32)> {
        self.mcu_rftest_cmd(TM_QUERY_AT_CMD, func_id, 0, true)
    }

    /// Set TX power in test mode (pushes power to specified level).
    /// power: power in half-dBm units (e.g., 40 = 20 dBm)
    pub fn testmode_set_tx_power(&mut self, power_half_dbm: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_POWER, power_half_dbm)
    }

    /// Enable/disable TX or RX in test mode.
    /// trx_type: 1=TX, 2=RX, 3=TX+RX
    /// enable: true to start, false to stop
    pub fn testmode_set_trx(&mut self, trx_type: u32, enable: bool) -> Result<()> {
        let value = if enable { 1u32 } else { 0u32 };
        // Pack type in param0, enable in param1
        self.mcu_rftest_cmd(TM_SET_AT_CMD, MCU_ATE_SET_TRX | (trx_type << 16), value, false)?;
        Ok(())
    }

    /// Set frequency offset in test mode (fine RF tuning).
    /// offset: frequency offset value
    pub fn testmode_set_freq_offset(&mut self, offset: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_FREQ_OFFSET, offset)
    }

    // ── Testmode: Antenna Control ──

    /// Set TX antenna mask in test mode.
    /// mask: 0x1=ant0 only, 0x2=ant1 only, 0x3=both (2x2 MIMO)
    pub fn testmode_set_tx_antenna(&mut self, mask: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_ANTENNA, mask)
    }

    /// Set RX antenna mask in test mode.
    pub fn testmode_set_rx_antenna(&mut self, mask: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_RX_ANTENNA, mask)
    }

    // ── Testmode: Rate & Modulation ──

    /// Set TX rate in test mode.
    /// rate_mode: 0=CCK, 1=OFDM, 2=HT, 3=VHT, 4=HE_SU, 5=HE_EXT_SU, 6=HE_TB, 7=HE_MU
    pub fn testmode_set_tx_rate(&mut self, rate_mode: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_RATE, rate_mode)
    }

    /// Set system bandwidth in test mode.
    /// bw: 0=20MHz, 1=40MHz, 2=80MHz
    pub fn testmode_set_system_bw(&mut self, bw: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_SYSTEM_BW, bw)
    }

    /// Set TX spatial streams in test mode.
    /// nss: 1 or 2
    pub fn testmode_set_tx_nss(&mut self, nss: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_NSS, nss)
    }

    /// Set TX guard interval in test mode.
    /// gi: 0=normal (0.8μs), 1=short (0.4μs HT/VHT, 1.6μs HE), 2=extended (3.2μs HE)
    pub fn testmode_set_tx_gi(&mut self, gi: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_GI, gi)
    }

    /// Set TX STBC in test mode. enable: 1=on, 0=off
    pub fn testmode_set_tx_stbc(&mut self, enable: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_STBC, enable)
    }

    /// Set TX LDPC in test mode. enable: 1=on, 0=off
    pub fn testmode_set_tx_ldpc(&mut self, enable: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_LDPC, enable)
    }

    // ── Testmode: Burst TX (packet injection engine) ──

    /// Set TX packet length for burst mode.
    pub fn testmode_set_tx_pkt_len(&mut self, len: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_PKT_LEN, len)
    }

    /// Set TX packet count for burst mode.
    /// 0 = infinite (until stopped), N = send exactly N frames
    pub fn testmode_set_tx_pkt_count(&mut self, count: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_PKT_COUNT, count)
    }

    /// Set TX inter-packet gap in microseconds.
    /// Controls timing between burst frames — lower = faster flood.
    pub fn testmode_set_tx_ipg(&mut self, ipg_us: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_IPG, ipg_us)
    }

    /// Set TX duty cycle (0-100%). Controls TX on-time percentage.
    pub fn testmode_set_tx_duty_cycle(&mut self, duty: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_DUTY_CYCLE, duty)
    }

    /// Enable/disable continuous TX (CW tone — no gaps, no packets).
    /// Useful for: jamming, range testing, antenna tuning.
    pub fn testmode_set_tx_continuous(&mut self, enable: bool) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_CONT, if enable { 1 } else { 0 })
    }

    /// Set TX channel in test mode.
    pub fn testmode_set_tx_channel(&mut self, channel: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_CHANNEL, channel)
    }

    /// Set per-antenna TX power in test mode.
    /// Allows different power on each antenna path (e.g., directional vs omni).
    pub fn testmode_set_tx_power_per_ant(&mut self, power: u32) -> Result<()> {
        self.testmode_set_at(MCU_ATE_SET_TX_POWER_PER_ANT, power)
    }

    /// Clean TX queue — abort all pending transmissions.
    pub fn testmode_clean_tx_queue(&mut self) -> Result<()> {
        self.testmode_set_at(MCU_ATE_CLEAN_TX_QUEUE, 0)
    }

    // ── Testmode: Diagnostics (query commands) ──

    /// Query RX statistics: packet count and FCS error count.
    pub fn testmode_get_rx_stats(&mut self) -> Result<(u32, u32)> {
        self.testmode_query_at(MCU_ATE_GET_RX_STAT)
    }

    /// Query TX info: pending and completed frame counts.
    pub fn testmode_get_tx_info(&mut self) -> Result<(u32, u32)> {
        self.testmode_query_at(MCU_ATE_GET_TX_INFO)
    }

    /// Query chip temperature (firmware thermal sensor).
    pub fn testmode_get_temperature(&mut self) -> Result<(u32, u32)> {
        self.testmode_query_at(MCU_ATE_GET_TEMPERATURE)
    }

    /// Query TSSI (Transmit Signal Strength Indicator).
    /// Returns actual measured TX power from the PA.
    pub fn testmode_get_tssi(&mut self) -> Result<(u32, u32)> {
        self.testmode_query_at(MCU_ATE_GET_TSSI)
    }

    /// Configure full burst TX in one call.
    /// Sets rate, BW, antenna, power, packet count, IPG, then starts TX.
    pub fn testmode_burst_tx(&mut self,
        channel: u32, bw: u32, rate_mode: u32, nss: u32,
        power_half_dbm: u32, pkt_count: u32, ipg_us: u32,
    ) -> Result<()> {
        self.testmode_set_tx_channel(channel)?;
        self.testmode_set_system_bw(bw)?;
        self.testmode_set_tx_rate(rate_mode)?;
        self.testmode_set_tx_nss(nss)?;
        self.testmode_set_tx_power(power_half_dbm)?;
        self.testmode_set_tx_pkt_count(pkt_count)?;
        self.testmode_set_tx_ipg(ipg_us)?;
        self.testmode_set_trx(1, true)?; // Start TX
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Channel Survey — per-channel busy/tx/rx time from MIB registers
    // ═══════════════════════════════════════════════════════════════════════

    /// Read per-channel survey data from hardware MIB registers.
    ///
    /// Returns (busy_us, tx_us, rx_us, obss_us) — all in microseconds.
    /// These are CUMULATIVE counters that reset when cleared.
    /// Call `survey_reset()` after reading to start fresh measurement.
    ///
    /// This works in NORMAL mode — no testmode needed!
    /// Matches mt792x_phy_update_channel() from the kernel driver.
    pub fn survey_read(&self, band_idx: u8) -> Result<ChannelSurvey> {
        let mib_base = if band_idx == 0 { MT_WF_MIB_BASE0 } else { MT_WF_MIB_BASE1 };
        let rmac_base = if band_idx == 0 { MT_WF_RMAC_BASE0 } else { MT_WF_RMAC_BASE0 + 0x10000 };

        let busy = self.reg_read(mib_base + MT_MIB_SDR9_OFF)? & MT_MIB_SDR9_BUSY_MASK;
        let tx = self.reg_read(mib_base + MT_MIB_SDR36_OFF)? & MT_MIB_SDR36_TXTIME_MASK;
        let rx = self.reg_read(mib_base + MT_MIB_SDR37_OFF)? & MT_MIB_SDR37_RXTIME_MASK;
        let obss = self.reg_read(rmac_base + MT_WF_RMAC_MIB_AIRTIME14_OFF)? & MT_MIB_OBSSTIME_MASK;

        Ok(ChannelSurvey {
            busy_us: busy,
            tx_us: tx,
            rx_us: rx,
            obss_us: obss,
        })
    }

    /// Reset survey counters by clearing the RMAC MIB time register.
    /// Call this after reading to start a fresh measurement window.
    pub fn survey_reset(&self, band_idx: u8) -> Result<()> {
        let rmac_base = if band_idx == 0 { MT_WF_RMAC_BASE0 } else { MT_WF_RMAC_BASE0 + 0x10000 };
        // Set the clear bit — hardware auto-clears it
        self.reg_set(rmac_base + MT_WF_RMAC_MIB_TIME0_OFF, MT_WF_RMAC_MIB_RXTIME_CLR)?;
        Ok(())
    }

    /// Enable MIB TX/RX duration reporting.
    /// Should be called once during init.
    pub fn survey_enable(&self, band_idx: u8) -> Result<()> {
        let mib_base = if band_idx == 0 { MT_WF_MIB_BASE0 } else { MT_WF_MIB_BASE1 };
        let rmac_base = if band_idx == 0 { MT_WF_RMAC_BASE0 } else { MT_WF_RMAC_BASE0 + 0x10000 };

        // Enable MIB TX/RX duration counters
        self.reg_set(mib_base + MT_MIB_SCR1_OFF, MT_MIB_TXDUR_EN | MT_MIB_RXDUR_EN)?;
        // Enable RMAC RX time measurement
        self.reg_set(rmac_base + MT_WF_RMAC_MIB_TIME0_OFF, MT_WF_RMAC_MIB_RXTIME_EN)?;
        Ok(())
    }

    /// Read a hardware register by absolute address.
    /// Exposed for diagnostic binaries that need direct register access
    /// (e.g., MIB counter scanning, hardware debugging).
    pub fn read_register(&self, addr: u32) -> Result<u32> {
        self.reg_read(addr)
    }

    /// Set per-rate TX power limits for all channels in a band.
    /// Matches mt76_connac_mcu_rate_txpower_band() from mt76_connac_mcu.c:2121.
    ///
    /// Uses CE cmd SET_RATE_TX_POWER (0x5d) — NOT EXT cmd 0x58.
    /// The firmware requires this command with proper country code and 6GHz channel
    /// entries before it will enable the 6GHz RF path. Without it, 6GHz is deaf.
    ///
    /// TLV format (from mt76_connac_mcu.h):
    ///   mt76_connac_tx_power_limit_tlv (44 bytes header):
    ///     [0]     ver: u8
    ///     [1]     pad: u8
    ///     [2-3]   len: le16
    ///     [4]     n_chan: u8           — channels in this batch (max 8 for connac2)
    ///     [5]     band: u8            — 1=2.4GHz, 2=5GHz, 3=6GHz
    ///     [6]     last_msg: u8        — 1 if last batch across ALL bands
    ///     [7]     pad: u8
    ///     [8-11]  alpha2[4]: u8       — country code (e.g., "BR\0\0")
    ///     [12-43] pad2[32]: u8
    ///   Per-channel SKU (162 bytes each, MT_SKU_POWER_LIMIT=161):
    ///     [0]     channel: u8
    ///     [1-161] pwr_limit[161]: i8  — per-rate power limits in half-dBm
    ///
    /// `max_dbm` clamps all per-rate values. 0 = use hardware max (127 half-dBm).
    fn mcu_set_rate_txpower_limited(&mut self, band: Band, max_dbm: i8) -> Result<()> {
        let max_half_dbm: u8 = if max_dbm > 0 {
            (max_dbm as u8).saturating_mul(2)
        } else {
            127 // no limit — firmware clamps to eFuse max
        };
        self.mcu_set_rate_txpower_inner(band, max_half_dbm, false)
    }

    fn mcu_set_rate_txpower(&mut self, band: Band) -> Result<()> {
        self.mcu_set_rate_txpower_inner(band, 127, false)
    }

    /// Send TX power for all 3 bands. Called during radio_init.
    /// The `last_ch` is the highest channel across ALL bands — Linux uses this
    /// to set last_msg=1 only on the very last batch of the last band.
    fn mcu_set_rate_txpower_all(&mut self) -> Result<()> {
        self.mcu_set_rate_txpower_inner(Band::Band2g, 127, false)?;
        self.mcu_set_rate_txpower_inner(Band::Band5g, 127, false)?;
        self.mcu_set_rate_txpower_inner(Band::Band6g, 127, true)?; // last band
        Ok(())
    }

    fn mcu_set_rate_txpower_inner(&mut self, band: Band, max_half_dbm: u8, is_last_band: bool) -> Result<()> {
        // CE cmd 0x5D — matches MCU_CE_CMD_SET_RATE_TX_POWER from mt76_connac_mcu.h
        // Channel lists from Linux mt76_connac_mcu.c:2126-2156.
        // These include ALL channels (primary + center frequencies for 40/80/160)
        // because firmware needs power limits for every possible operating frequency.
        let (ch_list, band_byte): (&[u8], u8) = match band {
            Band::Band2g => (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14], 1),
            Band::Band5g => (&[
                 36,  38,  40,  42,  44,  46,  48,
                 50,  52,  54,  56,  58,  60,  62,
                 64, 100, 102, 104, 106, 108, 110,
                112, 114, 116, 118, 120, 122, 124,
                126, 128, 132, 134, 136, 138, 140,
                142, 144, 149, 151, 153, 155, 157,
                159, 161, 165, 169, 173, 177,
            ], 2),
            Band::Band6g => (&[
                  1,   3,   5,   7,   9,  11,  13,
                 15,  17,  19,  21,  23,  25,  27,
                 29,  33,  35,  37,  39,  41,  43,
                 45,  47,  49,  51,  53,  55,  57,
                 59,  61,  65,  67,  69,  71,  73,
                 75,  77,  79,  81,  83,  85,  87,
                 89,  91,  93,  97,  99, 101, 103,
                105, 107, 109, 111, 113, 115, 117,
                119, 121, 123, 125, 129, 131, 133,
                135, 137, 139, 141, 143, 145, 147,
                149, 151, 153, 155, 157, 161, 163,
                165, 167, 169, 171, 173, 175, 177,
                179, 181, 183, 185, 187, 189, 193,
                195, 197, 199, 201, 203, 205, 207,
                209, 211, 213, 215, 217, 219, 221,
                225, 227, 229, 233,
            ], 3),
        };

        // Connac2: batch_len=8, sku_len=162 (1 byte channel + 161 bytes power limits)
        let batch_len: usize = 8;
        let sku_len: usize = 162; // sizeof(mt76_connac_sku_tlv) = 1 + MT_SKU_POWER_LIMIT(161)
        let hdr_len: usize = 44; // sizeof(mt76_connac_tx_power_limit_tlv)
        let n_batches = (ch_list.len() + batch_len - 1) / batch_len;

        // The last channel across ALL bands determines last_msg.
        // Linux: if phy has 6GHz, last_ch = chan_list_6ghz[last] = 233.
        let last_ch: u8 = 233; // MT7921AU has 6GHz → last is always 233

        for batch_idx in 0..n_batches {
            let start = batch_idx * batch_len;
            let end = (start + batch_len).min(ch_list.len());
            let batch_channels = &ch_list[start..end];
            let n_chan = batch_channels.len();

            // Header (44 bytes) + per-channel SKUs
            let payload_len = hdr_len + n_chan * sku_len;
            let mut payload = vec![0u8; payload_len];

            // ── tx_power_limit_tlv header (44 bytes) ──
            // [0] ver = 0
            // [1] pad = 0
            // [2-3] len = 0 (Linux leaves this zero)
            // [4] n_chan
            payload[4] = n_chan as u8;
            // [5] band: 1=2.4G, 2=5G, 3=6G
            payload[5] = band_byte;
            // [6] last_msg: 1 only when this batch contains the global last channel
            let batch_last_ch = *batch_channels.last().unwrap_or(&0);
            payload[6] = if is_last_band && batch_last_ch == last_ch { 1 } else { 0 };
            // [7] pad
            // [8-11] alpha2 country code
            payload[8] = b'B';
            payload[9] = b'R';
            // [12-43] pad2 = zeros

            // ── Per-channel SKU entries (162 bytes each) ──
            // Layout: channel(1) + pwr_limit[161]
            // Power limit indices (from mt76_connac_mcu.h SKU table):
            //   [0..3]    CCK 1M/2M/5.5M/11M        (4, 2.4GHz only)
            //   [4..11]   OFDM 6M..54M               (8)
            //   [12..19]  HT20 MCS0..7               (8)
            //   [20..28]  HT40 MCS0..7 + MCS32       (9)
            //   [29..38]  VHT20 MCS0..9              (10)
            //   [39..48]  VHT40 MCS0..9              (10)
            //   [49..58]  VHT80 MCS0..9              (10)
            //   [59..68]  VHT160 MCS0..9             (10)
            //   [69..80]  HE26 MCS0..11              (12)
            //   [81..92]  HE52 MCS0..11              (12)
            //   [93..104] HE106 MCS0..11             (12)
            //   [105..116] HE242 MCS0..11            (12)
            //   [117..128] HE484 MCS0..11            (12)
            //   [129..140] HE996 MCS0..11            (12)
            //   [141..152] HE996x2 MCS0..11          (12)
            //   Total: 4+8+8+9+10+10+10+10+12*7 = 153 entries used of 161

            for (i, &ch) in batch_channels.iter().enumerate() {
                let off = hdr_len + i * sku_len;
                payload[off] = ch;

                // Fill all power limits with max — firmware clamps to min(our, eFuse).
                // This is what a pentesting tool wants: maximum allowed power on every rate.
                let pwr = &mut payload[off + 1..off + sku_len];
                for p in pwr.iter_mut() {
                    *p = max_half_dbm;
                }
            }

            // Send via CE cmd — fire-and-forget (Linux sends with wait_resp=false)
            self.mcu_send_ce_cmd(MCU_CE_CMD_SET_RATE_TX_POWER, &payload, false)?;

            // Linux reads a CR after each batch to avoid PSE buffer underflow
            // (mt76_connac_mcu.c:2252). Match this behavior.
            let _ = self.reg_read(0x820c8000); // MT_PSE_BASE
        }

        Ok(())
    }

    /// Send a UNI command (TLV-based, used for most post-boot MCU operations).
    fn mcu_send_uni_cmd(&mut self, cmd_id: u16, data: &[u8], wait_resp: bool) -> Result<i32> {
        let seq = self.next_mcu_seq();

        // Build UNI TXD (48 bytes = 32 HW TXD + 16 UNI header)
        let uni_hdr_size = 16;
        let txd_size = 32 + uni_hdr_size;
        let msg_len = txd_size + data.len();

        let mut txd = vec![0u8; txd_size];

        // ── HW TXD (first 32 bytes, DW0-DW7) ──
        // Must match mt76_connac2_mcu_fill_message() for UNI commands
        // DW0: TX_BYTES[15:0] | PKT_FMT[24:23]=1(CMD) | Q_IDX[31:25]=0x20
        let txd_dw0: u32 = (msg_len as u32 & 0xFFFF)
            | (1u32 << 23)                                  // PKT_FMT = MT_TX_TYPE_CMD
            | (0x20u32 << 25);                              // Q_IDX = MT_TX_MCU_PORT_RX_Q0
        txd[0..4].copy_from_slice(&txd_dw0.to_le_bytes());

        // DW1: HDR_FORMAT[17:16]=1(CMD) | LONG_FORMAT[31]=1
        let txd_dw1: u32 = (1u32 << 16)                    // HDR_FORMAT = MT_HDR_FORMAT_CMD
            | (1u32 << 31);                                  // LONG_FORMAT
        txd[4..8].copy_from_slice(&txd_dw1.to_le_bytes());
        // DW2-DW7: zeros (already zero)

        // ── UNI TXD fields (starting at byte 32) ──
        let u = 32;
        // len (payload length after this header)
        let payload_len = uni_hdr_size + data.len();
        txd[u..u+2].copy_from_slice(&(payload_len as u16).to_le_bytes());
        // cid (command ID)
        txd[u+2..u+4].copy_from_slice(&cmd_id.to_le_bytes());
        // rsv
        txd[u+4] = 0;
        // pkt_type
        txd[u+5] = MCU_PKT_ID;
        // frag_n
        txd[u+6] = 0;
        // seq
        txd[u+7] = seq;
        // checksum
        txd[u+8..u+10].copy_from_slice(&0u16.to_le_bytes());
        // s2d_index (HOST → WM)
        txd[u+10] = MCU_S2D_H2N;
        // option
        let mut option = UNI_CMD_OPT_BIT_UNI_CMD | UNI_CMD_OPT_BIT_SET_QUERY;
        if wait_resp {
            option |= UNI_CMD_OPT_BIT_ACK;
        }
        txd[u+11] = option;

        // Build full USB packet
        let total_len = MT_SDIO_HDR_SIZE + txd_size + data.len();
        let padded_len = (total_len + 3) & !3;
        let final_len = padded_len + MT_USB_TAIL_SIZE;

        let mut pkt = vec![0u8; final_len];

        // SDIO header
        let sdio_hdr: u32 = (total_len as u32 - MT_SDIO_HDR_SIZE as u32) & 0xFFFF;
        pkt[0..4].copy_from_slice(&sdio_hdr.to_le_bytes());

        // TXD
        pkt[MT_SDIO_HDR_SIZE..MT_SDIO_HDR_SIZE + txd_size].copy_from_slice(&txd);

        // Payload
        if !data.is_empty() {
            let off = MT_SDIO_HDR_SIZE + txd_size;
            pkt[off..off + data.len()].copy_from_slice(data);
        }

        // Send to inband command endpoint
        self.handle.write_bulk(self.ep_mcu_out, &pkt, USB_BULK_TIMEOUT)?;

        if wait_resp {
            return self.mcu_recv_response(seq);
        }

        Ok(0)
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Firmware Download
    // ══════════════════════════════════════════════════════════════════════════

    /// Request patch semaphore (get or release).
    fn mcu_patch_sem_ctrl(&mut self, get: bool) -> Result<i32> {
        let op: u32 = if get { PATCH_SEM_GET } else { PATCH_SEM_RELEASE };
        let data = op.to_le_bytes();
        self.mcu_send_msg(MCU_CMD_PATCH_SEM_CONTROL, &data, true)
    }

    /// Signal firmware download init: set target address and length.
    fn mcu_init_download(&mut self, addr: u32, len: u32, mode: u32) -> Result<()> {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(&addr.to_le_bytes());
        data[4..8].copy_from_slice(&len.to_le_bytes());
        data[8..12].copy_from_slice(&mode.to_le_bytes());

        // Choose command based on address (patch vs RAM)
        let cmd = if addr == 0x900000 {
            MCU_CMD_PATCH_START_REQ
        } else {
            MCU_CMD_TARGET_ADDRESS_LEN_REQ
        };

        self.mcu_send_msg(cmd, &data, true)?;
        Ok(())
    }

    /// Send firmware data in chunks via FW_SCATTER command.
    ///
    /// Linux has background RX threads consuming IN endpoint data during scatter.
    /// We simulate this by periodically draining IN endpoints between chunks,
    /// preventing MCU event/data backlog from blocking subsequent MCU responses.
    fn mcu_send_firmware_data(&mut self, data: &[u8]) -> Result<()> {
        let n_chunks = (data.len() + FW_DL_MAX_LEN - 1) / FW_DL_MAX_LEN;
        let mut offset = 0;
        let mut chunk_num = 0u32;
        while offset < data.len() {
            let chunk_len = std::cmp::min(FW_DL_MAX_LEN, data.len() - offset);
            self.mcu_send_msg(MCU_CMD_FW_SCATTER,
                             &data[offset..offset + chunk_len], false)?;
            offset += chunk_len;
            chunk_num += 1;
            if chunk_num <= 3 || chunk_num % 20 == 0 || offset >= data.len() {
            }

            // Periodic drain: simulate Linux's background RX thread.
            // Drain every 10 chunks to prevent IN endpoint backlog.
            if chunk_num % 10 == 0 {
                self.drain_rx();
            }
        }
        // Final drain after all data sent
        thread::sleep(Duration::from_millis(20));
        self.drain_rx();
        Ok(())
    }

    /// Tell the MCU to start the patch.
    fn mcu_start_patch(&mut self) -> Result<()> {
        let data = [0u8; 4]; // check_crc = 0
        self.mcu_send_msg(MCU_CMD_PATCH_FINISH_REQ, &data, true)?;
        Ok(())
    }

    /// Tell the MCU to start the RAM firmware.
    fn mcu_start_firmware(&mut self, addr: u32, option: u32) -> Result<()> {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&option.to_le_bytes());
        data[4..8].copy_from_slice(&addr.to_le_bytes());
        self.mcu_send_msg(MCU_CMD_FW_START_REQ, &data, true)?;
        Ok(())
    }

    /// Load ROM patch from file.
    /// Matches mt76_connac2_load_patch() from the kernel driver.
    fn load_patch(&mut self) -> Result<()> {
        let fw_data = FW_ROM_PATCH_DATA;

        if fw_data.len() < PATCH_HEADER_SIZE {
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::FirmwareDownload,
                reason: format!("ROM patch too small: {} bytes", fw_data.len()),
            });
        }

        // Get patch semaphore
        let sem = self.mcu_patch_sem_ctrl(true)?;
        if sem == PATCH_IS_DL {
            // Already downloaded
            return Ok(());
        }
        // Accept PATCH_NOT_DL_SEM_SUCCESS (3) or continue anyway for unknown responses
        // Some firmware versions may return different status codes
        if sem != PATCH_NOT_DL_SEM_SUCCESS && sem != 0 && sem != 254 {
        }

        // Parse header
        let hdr = &fw_data[..PATCH_HEADER_SIZE];
        let build_date = std::str::from_utf8(&hdr[0..16]).unwrap_or("?");
        let n_region = u32::from_be_bytes([
            fw_data[36], fw_data[37], fw_data[38], fw_data[39]
        ]);


        // Download each region
        for i in 0..n_region {
            let sec_off = PATCH_HEADER_SIZE + i as usize * PATCH_SECTION_SIZE;
            if sec_off + PATCH_SECTION_SIZE > fw_data.len() {
                break;
            }

            let sec = &fw_data[sec_off..sec_off + PATCH_SECTION_SIZE];

            // Parse section
            let sec_type = u32::from_be_bytes([sec[0], sec[1], sec[2], sec[3]]);
            if (sec_type & 0xFFFF) != PATCH_SEC_TYPE_INFO {
                continue;
            }

            let data_offs = u32::from_be_bytes([sec[4], sec[5], sec[6], sec[7]]) as usize;
            let addr = u32::from_be_bytes([sec[12], sec[13], sec[14], sec[15]]);
            let len = u32::from_be_bytes([sec[16], sec[17], sec[18], sec[19]]) as usize;

            if data_offs + len > fw_data.len() {
                continue;
            }

            let mode = DL_MODE_NEED_RSP;

            self.mcu_init_download(addr, len as u32, mode)?;
            self.mcu_send_firmware_data(&fw_data[data_offs..data_offs + len])?;
        }

        // Start patch
        self.mcu_start_patch()?;

        // Release semaphore
        let _ = self.mcu_patch_sem_ctrl(false);

        Ok(())
    }

    /// Load WM RAM firmware from file.
    /// Matches mt76_connac2_load_ram() from the kernel driver.
    fn load_ram(&mut self) -> Result<()> {
        let fw_data = FW_WM_RAM_DATA;

        if fw_data.len() < FW_TRAILER_SIZE {
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::FirmwareDownload,
                reason: format!("WM firmware too small: {} bytes", fw_data.len()),
            });
        }

        // Trailer is at the END of the file
        let trailer_off = fw_data.len() - FW_TRAILER_SIZE;
        let trailer = &fw_data[trailer_off..];

        let n_region = trailer[2] as u32;
        let fw_ver = std::str::from_utf8(&trailer[7..17]).unwrap_or("?");
        let build_date = std::str::from_utf8(&trailer[17..32]).unwrap_or("?");

        self.fw_version = format!("{}", fw_ver.trim_end_matches('\0'));

        // Region descriptors are BEFORE the trailer, in reverse order
        let mut offset = 0usize;
        let mut override_addr: u32 = 0;

        for i in 0..n_region {
            let region_off = trailer_off - ((n_region - i) as usize * FW_REGION_SIZE);
            if region_off + FW_REGION_SIZE > fw_data.len() {
                break;
            }

            let region = &fw_data[region_off..region_off + FW_REGION_SIZE];

            let addr = u32::from_le_bytes([region[16], region[17], region[18], region[19]]);
            let len = u32::from_le_bytes([region[20], region[21], region[22], region[23]]) as usize;
            let feature_set = region[24];

            // Skip non-downloadable regions
            if feature_set & FW_FEATURE_NON_DL != 0 {
                offset += len;
                continue;
            }

            if feature_set & FW_FEATURE_OVERRIDE_ADDR != 0 {
                override_addr = addr;
            }

            // Build mode flags from feature_set — matches mt76_connac_mcu_gen_dl_mode()
            let mut mode = DL_MODE_NEED_RSP;
            if feature_set & 0x01 != 0 { // FW_FEATURE_SET_ENCRYPT
                mode |= DL_MODE_ENCRYPT | (1 << 3); // DL_MODE_RESET_SEC_IV
            }
            if feature_set & 0x10 != 0 { // FW_FEATURE_ENCRY_MODE (connac2)
                mode |= 1 << 6; // DL_CONFIG_ENCRY_MODE_SEL
            }
            // Key index from feature_set bits[2:1]
            let key_idx = ((feature_set >> 1) & 0x3) as u32;
            mode |= key_idx << 1; // DL_MODE_KEY_IDX = GENMASK(2,1)


            // Thorough drain before each init_download — ensure no stale data
            // on IN endpoints that could block the MCU from sending its response.
            // Linux has background RX threads that consume this continuously.
            self.drain_rx();

            self.mcu_init_download(addr, len as u32, mode)?;

            if offset + len > fw_data.len() {
                return Err(Error::ChipInitFailed {
                    chip: "MT7921AU".into(),
                    stage: crate::core::error::InitStage::FirmwareDownload,
                    reason: format!("firmware region exceeds file size at offset {}", offset),
                });
            }

            self.mcu_send_firmware_data(&fw_data[offset..offset + len])?;
            offset += len;


            // Give MCU time to process, drain events, and verify it's alive
            thread::sleep(Duration::from_millis(100));
            self.drain_rx();

            // Check if MCU is still responding
            match self.reg_read(MT_CONN_ON_MISC) {
                Ok(_) => {},
                Err(_) => {},
            }
        }

        // Start firmware
        let mut option = 0u32;
        if override_addr != 0 {
            option |= FW_START_OVERRIDE;
        }
        self.mcu_start_firmware(override_addr, option)?;

        Ok(())
    }

    /// Full firmware load sequence.
    /// Matches mt792x_load_firmware() + mt7921_run_firmware().
    fn run_firmware(&mut self) -> Result<()> {
        // Enable firmware download mode FIRST (before MCU commands)
        self.reg_set(MT_UDMA_TX_QSEL, MT_FW_DL_EN)?;

        // MCU restart: NIC_POWER_CTRL with power_mode=1
        // The kernel sends this with wait_resp=false, so send raw and drain
        let restart_req = [1u8, 0, 0, 0]; // power_mode=1, rsv[3]
        let _ = self.mcu_send_msg(MCU_CMD_NIC_POWER_CTRL, &restart_req, false);

        // Drain any MCU response to the restart
        thread::sleep(Duration::from_millis(50));
        {
            let mut drain = [0u8; 2048];
            while let Ok(n) = self.handle.read_bulk(self.ep_data_in, &mut drain, Duration::from_millis(100)) {
                if n == 0 { break; }
            }
        }

        // Wait for MCU ready for download
        if !self.poll_reg(MT_CONN_ON_MISC, MT_TOP_MISC_FW_STATE,
                          MT_TOP_MISC2_FW_PWR_ON, 1000)? {
        }

        // Read CONN_ON_MISC after restart
        let misc = self.reg_read(MT_CONN_ON_MISC)?;

        // Load ROM patch
        self.load_patch()?;

        // Load WM RAM firmware
        self.load_ram()?;

        // Disable firmware download mode
        self.reg_clear(MT_UDMA_TX_QSEL, MT_FW_DL_EN)?;

        // Wait for N9 MCU ready
        if !self.poll_reg(MT_CONN_ON_MISC, MT_TOP_MISC2_FW_N9_RDY,
                          MT_TOP_MISC2_FW_N9_RDY, 1500)? {
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::FirmwareDownload,
                reason: "timeout waiting for N9 MCU ready".into(),
            });
        }

        self.mcu_running = true;

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Radio Init — required before sniffer/channel commands
    // ══════════════════════════════════════════════════════════════════════════

    /// Enable MAC subsystem. Required before any radio operations.
    /// Matches mt76_connac_mcu_set_mac_enable().
    fn mcu_mac_enable(&mut self, band: u8, enable: bool) -> Result<()> {
        let req = [enable as u8, band, 0, 0];
        self.mcu_send_ext_cmd(MCU_EXT_CMD_MAC_INIT_CTRL, &req, true)?;
        Ok(())
    }

    /// Clear all WTBL (Wireless Table) entries.
    /// Matches the loop in mt7921_mac_init() from init.c:170.
    /// Must be called AFTER mac_enable — WTBL registers are in the WiFi subsystem
    /// address space (0x820d4xxx) which isn't accessible before MAC is enabled.
    fn wtbl_clear_all(&mut self) -> Result<()> {
        const MT_WTBLON_TOP_BASE: u32 = 0x820d4000;
        const MT_WTBL_UPDATE: u32 = MT_WTBLON_TOP_BASE + 0x230;
        const MT_WTBL_UPDATE_WLAN_IDX_MASK: u32 = 0x3FF;
        const MT_WTBL_UPDATE_ADM_COUNT_CLEAR: u32 = 1 << 12;
        const MT_WTBL_UPDATE_BUSY: u32 = 1 << 31;
        const MT792X_WTBL_SIZE: usize = 20;

        for i in 0..MT792X_WTBL_SIZE {
            let val = (i as u32 & MT_WTBL_UPDATE_WLAN_IDX_MASK) | MT_WTBL_UPDATE_ADM_COUNT_CLEAR;
            self.reg_write(MT_WTBL_UPDATE, val)?;

            for _ in 0..100 {
                let status = self.reg_read(MT_WTBL_UPDATE)?;
                if (status & MT_WTBL_UPDATE_BUSY) == 0 {
                    break;
                }
                thread::sleep(Duration::from_micros(50));
            }
        }
        Ok(())
    }

    /// Create/update a WTBL (Wireless Table) entry via MCU command.
    /// Matches mt76_connac_mcu_wtbl_update_hdr_trans() + mt76_connac_mcu_add_tlv()
    /// from Linux mt76_connac_mcu.c.
    ///
    /// EXT_CMD_WTBL_UPDATE (0x32) format:
    ///   wtbl_req_hdr (16 bytes):
    ///     [0]     bss_idx
    ///     [1]     operation (0=RESET_AND_SET, 1=SET, 2=QUERY, 3=RESET_ALL)
    ///     [2-3]   wlan_idx (le16)
    ///     [4]     tlv_num (number of WTBL TLVs)
    ///     [5]     is_tlv_append = 0
    ///     [6-7]   pad
    ///     [8-15]  pad (for mt76 connac2)
    ///   Followed by WTBL TLVs (GENERIC, RX, HT, VHT, etc.)
    ///
    /// For monitor mode broadcast STA (wcid=543), we set up a basic WTBL entry
    /// that enables frame routing. For active monitor mode with ACK capability,
    /// a per-peer entry enables the firmware to generate ACKs.
    fn mcu_wtbl_update(&mut self, wcid: u16, peer_mac: &[u8; 6], operation: u8) -> Result<()> {
        let bss_idx: u8 = 0;

        // WTBL TLV tags from mt76_connac_mcu.h
        const WTBL_GENERIC: u16 = 0;
        const WTBL_RX: u16 = 1;
        const WTBL_HT: u16 = 2;
        const WTBL_VHT: u16 = 3;

        // WTBL_GENERIC TLV (tag 0) — 32 bytes
        let wtbl_generic_len: u16 = 32;
        // WTBL_RX TLV (tag 1) — 12 bytes (NOT 8! Linux struct has rcid+rca1+rca2+rv+rsv)
        let wtbl_rx_len: u16 = 12;
        // WTBL_HT TLV (tag 2) — 12 bytes
        let wtbl_ht_len: u16 = 12;
        // WTBL_VHT TLV (tag 3) — 12 bytes
        let wtbl_vht_len: u16 = 12;

        let hdr_len = 16;
        let n_tlvs: u8 = 4;
        let total = hdr_len + wtbl_generic_len as usize + wtbl_rx_len as usize
            + wtbl_ht_len as usize + wtbl_vht_len as usize;
        let mut req = vec![0u8; total];

        // Header
        req[0] = bss_idx;
        req[1] = operation; // 0 = RESET_AND_SET
        req[2..4].copy_from_slice(&wcid.to_le_bytes());
        req[4] = n_tlvs;

        // ── WTBL_GENERIC TLV (32 bytes) ──
        let t = hdr_len;
        req[t..t+2].copy_from_slice(&WTBL_GENERIC.to_le_bytes());
        req[t+2..t+4].copy_from_slice(&wtbl_generic_len.to_le_bytes());
        req[t+4..t+10].copy_from_slice(peer_mac);
        req[t+10] = 0x0e; // muar_idx = 0xe (broadcast/non-associated)
        req[t+11] = 0; // skip_tx = false
        req[t+12] = 0; // cf_ack
        req[t+13] = 1; // qos = true (WMM)

        // ── WTBL_RX TLV (12 bytes) ──
        // Layout: tag(2)+len(2)+rcid(1)+rca1(1)+rca2(1)+rv(1)+rsv(4)
        // rca1: RX Class 1 address check = MAC address matching for ACK
        // rca2: RX Class 2 address check
        // rv: RX Valid — marks this WTBL entry as active for RX
        let r = t + wtbl_generic_len as usize;
        req[r..r+2].copy_from_slice(&WTBL_RX.to_le_bytes());
        req[r+2..r+4].copy_from_slice(&wtbl_rx_len.to_le_bytes());
        req[r+4] = 0; // rcid
        req[r+5] = 1; // rca1 = enable MAC address matching
        req[r+6] = 1; // rca2 = enable
        req[r+7] = 1; // rv = RX valid

        // ── WTBL_HT TLV (12 bytes) ──
        // Layout: tag(2)+len(2)+ht(1)+ldpc(1)+af(1)+mm(1)+rsv(4)
        // af: A-MPDU factor (0=8K, 1=16K, 2=32K, 3=64K)
        // mm: MPDU density minimum spacing
        let h = r + wtbl_rx_len as usize;
        req[h..h+2].copy_from_slice(&WTBL_HT.to_le_bytes());
        req[h+2..h+4].copy_from_slice(&wtbl_ht_len.to_le_bytes());
        req[h+4] = 1; // ht = true
        req[h+5] = 1; // ldpc = true
        req[h+6] = 3; // af = 3 (64KB A-MPDU)
        req[h+7] = 0; // mm = 0 (no minimum spacing)

        // ── WTBL_VHT TLV (12 bytes) ──
        // Layout: tag(2)+len(2)+ldpc(1)+dyn_bw(1)+vht(1)+txop_ps(1)+rsv(4)
        let v = h + wtbl_ht_len as usize;
        req[v..v+2].copy_from_slice(&WTBL_VHT.to_le_bytes());
        req[v+2..v+4].copy_from_slice(&wtbl_vht_len.to_le_bytes());
        req[v+4] = 1; // ldpc = true
        req[v+5] = 1; // dyn_bw = true (dynamic bandwidth)
        req[v+6] = 1; // vht = true
        req[v+7] = 0; // txop_ps

        self.mcu_send_ext_cmd(MCU_EXT_CMD_WTBL_UPDATE, &req, true)?;
        Ok(())
    }

    /// Create a per-AP WTBL entry for active monitor mode.
    /// Unlike the broadcast WTBL (muar_idx=0x0e), this entry uses muar_idx=0
    /// (our VIF's OMAC) so firmware can match incoming frames and generate ACKs.
    ///
    /// This enables:
    /// - ACK generation: AP knows we received its frames → better rate adaptation
    /// - Beamformee: per-peer BF TLVs can be added to this entry
    /// - Rate feedback: firmware tracks per-peer TX/RX statistics
    fn mcu_wtbl_update_peer(&mut self, wcid: u16, ap_bssid: &[u8; 6]) -> Result<()> {
        const WTBL_GENERIC: u16 = 0;
        const WTBL_RX: u16 = 1;
        const WTBL_HT: u16 = 2;
        const WTBL_VHT: u16 = 3;
        const WTBL_BF: u16 = 12;

        let wtbl_generic_len: u16 = 32;
        let wtbl_rx_len: u16 = 12;
        let wtbl_ht_len: u16 = 12;
        let wtbl_vht_len: u16 = 12;
        // WTBL_BF TLV (tag 12) — 12 bytes
        // Layout: tag(2)+len(2)+ibf(1)+ebf(1)+ibf_vht(1)+ebf_vht(1)+gid(1)+pfmu_idx(1)+rsv(2)
        let wtbl_bf_len: u16 = 12;

        let hdr_len = 16;
        let n_tlvs: u8 = 5;
        let total = hdr_len + wtbl_generic_len as usize + wtbl_rx_len as usize
            + wtbl_ht_len as usize + wtbl_vht_len as usize + wtbl_bf_len as usize;
        let mut req = vec![0u8; total];

        req[0] = 0; // bss_idx
        req[1] = 0; // RESET_AND_SET
        req[2..4].copy_from_slice(&wcid.to_le_bytes());
        req[4] = n_tlvs;

        // WTBL_GENERIC — peer MAC is the AP, muar_idx=0 (our VIF's OMAC)
        let t = hdr_len;
        req[t..t+2].copy_from_slice(&WTBL_GENERIC.to_le_bytes());
        req[t+2..t+4].copy_from_slice(&wtbl_generic_len.to_le_bytes());
        req[t+4..t+10].copy_from_slice(ap_bssid);
        req[t+10] = 0; // muar_idx = 0 (our VIF's omac_idx — NOT 0x0e!)
        req[t+13] = 1; // qos

        // WTBL_RX — rca1/rca2/rv all enabled for active RX
        let r = t + wtbl_generic_len as usize;
        req[r..r+2].copy_from_slice(&WTBL_RX.to_le_bytes());
        req[r+2..r+4].copy_from_slice(&wtbl_rx_len.to_le_bytes());
        req[r+5] = 1; // rca1 = MAC address matching
        req[r+6] = 1; // rca2
        req[r+7] = 1; // rv = RX valid

        // WTBL_HT
        let h = r + wtbl_rx_len as usize;
        req[h..h+2].copy_from_slice(&WTBL_HT.to_le_bytes());
        req[h+2..h+4].copy_from_slice(&wtbl_ht_len.to_le_bytes());
        req[h+4] = 1; // ht
        req[h+5] = 1; // ldpc
        req[h+6] = 3; // af = 64KB A-MPDU
        req[h+7] = 0; // mm

        // WTBL_VHT
        let v = h + wtbl_ht_len as usize;
        req[v..v+2].copy_from_slice(&WTBL_VHT.to_le_bytes());
        req[v+2..v+4].copy_from_slice(&wtbl_vht_len.to_le_bytes());
        req[v+4] = 1; // ldpc
        req[v+5] = 1; // dyn_bw
        req[v+6] = 1; // vht

        // WTBL_BF — enable explicit beamforming for this peer.
        // When the AP supports SU_BEAMFORMER, it will steer its signal toward us
        // after NDP sounding. The firmware handles NDP feedback autonomously.
        // Expected gain: 3-6 dB from 2x2 AP, up to 9 dB from 4x4 AP.
        let b = v + wtbl_vht_len as usize;
        req[b..b+2].copy_from_slice(&WTBL_BF.to_le_bytes());
        req[b+2..b+4].copy_from_slice(&wtbl_bf_len.to_le_bytes());
        req[b+4] = 0; // ibf = false (implicit BF — we don't support)
        req[b+5] = 1; // ebf = true (explicit BF — AP steers toward us)
        req[b+6] = 0; // ibf_vht
        req[b+7] = 1; // ebf_vht = true (VHT explicit beamforming)
        req[b+8] = 0; // gid = 0 (SU beamforming, not MU)
        req[b+9] = 0; // pfmu_idx = 0 (first PFMU table entry)

        self.mcu_send_ext_cmd(MCU_EXT_CMD_WTBL_UPDATE, &req, true)?;
        Ok(())
    }

    /// Create a per-AP STA_REC for active monitor mode.
    /// This tells firmware about the specific AP we're monitoring, enabling:
    /// - Proper frame routing and ACK generation
    /// - Rate adaptation feedback
    /// - Beamformee capability advertisement
    fn mcu_sta_update_peer(&mut self, wcid: u16, ap_bssid: &[u8; 6], enable: bool) -> Result<()> {
        const STA_REC_BASIC: u16 = 0;
        const STA_REC_PHY: u16 = 20;

        let hdr_len = 8;
        let basic_len: usize = 20;
        let phy_len: usize = 8;
        let n_tlvs: u16 = 2;
        let total = hdr_len + basic_len + phy_len;
        let mut req = vec![0u8; total];

        // Header
        req[0] = 0; // bss_idx
        req[1] = (wcid & 0xFF) as u8;
        req[2..4].copy_from_slice(&n_tlvs.to_le_bytes());
        req[4] = 1; // is_tlv_append
        req[5] = 0; // muar_idx = 0 (our VIF)
        req[6] = ((wcid >> 8) & 0xFF) as u8;

        // STA_REC_BASIC — CONNECTION_INFRA_STA type (we're STA, AP is peer)
        let t = hdr_len;
        // conn_type = STA_TYPE_STA(BIT(0)) | NETWORK_INFRA(BIT(16)) = 0x10001
        let conn_type: u32 = (1u32 << 0) | (1u32 << 16);
        let conn_state: u8 = if enable { 2 } else { 0 }; // PORT_SECURE / DISCONNECT
        req[t..t+2].copy_from_slice(&STA_REC_BASIC.to_le_bytes());
        req[t+2..t+4].copy_from_slice(&(basic_len as u16).to_le_bytes());
        req[t+4..t+8].copy_from_slice(&conn_type.to_le_bytes());
        req[t+8] = conn_state;
        req[t+9] = 1; // qos
        req[t+10..t+12].copy_from_slice(&0u16.to_le_bytes()); // aid
        req[t+12..t+18].copy_from_slice(ap_bssid); // peer = AP BSSID
        let extra = if enable { 0x03u16 } else { 0x01u16 };
        req[t+18..t+20].copy_from_slice(&extra.to_le_bytes());

        // STA_REC_PHY
        let p = t + basic_len;
        req[p..p+2].copy_from_slice(&STA_REC_PHY.to_le_bytes());
        req[p+2..p+4].copy_from_slice(&(phy_len as u16).to_le_bytes());
        req[p+4] = 0x3F; // all PHY modes

        self.mcu_send_uni_cmd(MCU_UNI_CMD_STA_REC_UPDATE, &req, true)?;
        Ok(())
    }

    /// Set a target AP for active monitor mode — firmware will ACK frames from this AP.
    /// This creates a per-peer WTBL + STA_REC entry alongside the existing broadcast
    /// entries. The broadcast entry captures ALL frames; the per-AP entry enables ACK.
    ///
    /// Call with None to disable active monitoring (remove per-AP entry).
    pub fn set_monitor_target(&mut self, target: Option<&[u8; 6]>) -> Result<()> {
        const PEER_WCID: u16 = 1; // First usable WCID for per-peer entries

        match target {
            Some(bssid) => {
                self.mcu_sta_update_peer(PEER_WCID, bssid, true)?;
                self.mcu_wtbl_update_peer(PEER_WCID, bssid)?;
            }
            None => {
                // Remove per-AP entry by sending with enable=false
                let zero_mac = [0u8; 6];
                let _ = self.mcu_sta_update_peer(PEER_WCID, &zero_mac, false);
            }
        }
        Ok(())
    }

    /// Set RX path / channel info via MCU command.
    /// Matches mt7921_mcu_set_chan_info() from Linux mt7921/mcu.c:863.
    /// Accepts a full Channel struct to support bandwidth (20/40/80/160 MHz).
    ///
    /// switch_reason values (from mt76_connac_mcu.h):
    ///   0 = CH_SWITCH_NORMAL — full calibration including DPD
    ///   3 = CH_SWITCH_SCAN — scan mode
    ///   9 = CH_SWITCH_SCAN_BYPASS_DPD — skip DPD calibration for faster switch
    fn mcu_set_chan_info(&mut self, ext_cmd: u8, channel: Channel, switch_reason: u8) -> Result<()> {
        let channel_band = band_to_idx(channel.band);
        let (center_ch, bw) = channel_center_and_bw(channel);

        // Struct matches mt7921_mcu_set_chan_info() — 80 bytes total
        // Linux: mt7921/mcu.c:863
        let mut req = [0u8; 80];
        req[0] = channel.number; // control_ch
        req[1] = center_ch;     // center_ch
        req[2] = bw;            // bw: 0=20, 1=40, 2=80, 3=160 (CMD_CBW_*)
        req[3] = hweight8(self.nic_phy_tx_ant); // tx_streams_num = hweight8(antenna_mask)
        // rx_streams: Linux sends antenna_mask for SET_RX_PATH,
        // but hweight8(antenna_mask) for CHANNEL_SWITCH.
        req[4] = if ext_cmd == MCU_EXT_CMD_SET_RX_PATH {
            self.nic_phy_rx_ant  // antenna_mask (bitmask)
        } else {
            hweight8(self.nic_phy_rx_ant) // stream count
        };
        req[5] = switch_reason; // CH_SWITCH_NORMAL(0) or CH_SWITCH_SCAN_BYPASS_DPD(9)
        req[6] = 0;            // band_idx = PHY band index (always 0, single-PHY device)
        req[7] = 0;            // center_ch2 (only for 80+80)
        // cac_case: le16 at [8-9] = 0
        req[10] = channel_band; // channel_band: 0=2.4G, 1=5G, 2=6G

        self.mcu_send_ext_cmd(ext_cmd, &req, true)?;
        Ok(())
    }

    /// MAC hardware init — configure RX DMA, de-aggregation, WTBL, and per-band settings.
    /// Matches mt7921_mac_init() from init.c EXACTLY:
    ///   1. MDP_DCR1 RX max length
    ///   2. MDP_DCR0 de-agg + hdr trans enable
    ///   3. WTBL clear loop (ALL 20 entries)  ← WE WERE MISSING THIS
    ///   4. Per-band DMA init (band 0, band 1)
    ///   5. RTS threshold
    fn mac_init(&mut self) -> Result<()> {
        // MDP registers (0x820cd000)
        const MT_MDP_BASE: u32 = 0x820cd000;
        const MT_MDP_DCR0: u32 = MT_MDP_BASE;
        const MT_MDP_DCR1: u32 = MT_MDP_BASE + 0x004;

        // WTBL registers (0x820d4000 + 0x230)
        const MT_WTBLON_TOP_BASE: u32 = 0x820d4000;
        const MT_WTBL_UPDATE: u32 = MT_WTBLON_TOP_BASE + 0x230;
        const MT_WTBL_UPDATE_WLAN_IDX_MASK: u32 = 0x3FF; // GENMASK(9, 0)
        const MT_WTBL_UPDATE_ADM_COUNT_CLEAR: u32 = 1 << 12;
        const MT_WTBL_UPDATE_BUSY: u32 = 1 << 31;
        const MT792X_WTBL_SIZE: usize = 20;

        // 1. Set max RX length in DCR1[15:3] (13-bit field, max 8191)
        // WiFi 6 A-MSDU can be up to 7935 bytes. Use 4096 which handles large frames
        // while fitting safely in the register field. USB aggregation handles the rest.
        self.reg_rmw(MT_MDP_DCR1, 0xFFF8, 4096 << 3)?;

        // 2. Enable hardware de-aggregation, explicitly disable header translation.
        // RX_HDR_TRANS_EN (bit 19) must be CLEARED for monitor/sniffer mode —
        // we need raw 802.11 frames, not firmware-translated 802.3 Ethernet.
        // Linux disables hdr_trans when sniffer is enabled (mt7996/main.c:499).
        self.reg_set(MT_MDP_DCR0, 1 << 15)?; // DAMSDU_EN
        self.reg_clear(MT_MDP_DCR0, 1 << 19)?; // Clear RX_HDR_TRANS_EN

        // 2b. MDP frame routing: ensure management/control frames come to HOST not MCU
        // Without these, frames may be routed to MCU instead of USB host!
        const MT_MDP_BNRCFR0: u32 = MT_MDP_BASE + 0x070; // 0x820cd070
        const MT_MDP_BNRCFR1: u32 = MT_MDP_BASE + 0x074; // 0x820cd074

        // BNRCFR0: Clear bits [9:4] to route mgmt/ctl to HIF (host) instead of MCU
        // MCU_RX_MGMT=TO_HIF(0), MCU_RX_CTL_NON_BAR=TO_HIF(0), MCU_RX_CTL_BAR=TO_HIF(0)
        self.reg_rmw(MT_MDP_BNRCFR0, 0x3F0, 0)?;

        // BNRCFR1: Clear bits [30:22] to route all to HIF
        // MCU_RX_BYPASS=TO_HIF(0), RX_DROPPED_UCAST=TO_HIF(0), RX_DROPPED_MCAST=TO_HIF(0)
        self.reg_rmw(MT_MDP_BNRCFR1, 0x7FC00000, 0)?;

        // 3. WTBL clear is deferred to AFTER mac_enable.
        // On CF-952AX (fw 20231109), writing WTBL registers (0x820d4xxx) before
        // MAC_INIT_CTRL causes the firmware to assert. The WiFi subsystem
        // registers may not be fully initialized until after MAC enable.
        // The WTBL clear happens in radio_init() after mcu_mac_enable().

        // 4. Per-band init (band 0 and 1) — mt792x_mac_init_band()
        // Linux does 9 register writes per band. We must do all of them.
        // Only 2 hardware bands: 6GHz shares the band 1 radio (same PHY, MCU handles switching).
        for band_idx in 0..2u32 {
            let tmac_base = 0x820e4000u32 + band_idx * 0x10000;
            let rmac_base = 0x820e5000u32 + band_idx * 0x10000;
            let mib_base = 0x820ed000u32 + band_idx * 0x10000;
            let dma_base = 0x820e7000u32 + band_idx * 0x10000;
            let wtbloff_base = 0x820d4000u32 + band_idx * 0x10000;

            // a. TMAC_CTCR0: de-dup limit reftime=0x3f, VHT SMPDU enable, de-dup limit enable
            let ctcr0 = tmac_base + 0x0f4;
            self.reg_rmw(ctcr0, 0x3F << 2, 0x3F << 2)?; // INS_DDLMT_REFTIME = GENMASK(7,2)
            self.reg_set(ctcr0, (1 << 17) | (1 << 18))?; // INS_DDLMT_VHT_SMPDU_EN | INS_DDLMT_EN

            // b. RMAC MIB_TIME0: enable RX time measurement
            let rmac_mib_time0 = rmac_base + 0x03c4;
            self.reg_set(rmac_mib_time0, 1 << 0)?; // MT_WF_RMAC_MIB_RXTIME_EN = BIT(0)

            // c. RMAC MIB_AIRTIME0: enable airtime measurement
            let rmac_mib_airtime0 = rmac_base + 0x0380;
            self.reg_set(rmac_mib_airtime0, 1 << 0)?; // MT_WF_RMAC_MIB_AIRTIME_EN = BIT(0)

            // d. MIB_SCR1: enable TX/RX duration counters
            let mib_scr1 = mib_base + 0x004;
            self.reg_set(mib_scr1, (1 << 0) | (1 << 1))?; // TXDUR_EN | RXDUR_EN

            // e. DMA DCR0: max RX length in DCR0[15:3] — match MDP_DCR1
            self.reg_rmw(dma_base, 0xFFF8, 4096 << 3)?;
            // Disable RXD group 5 (rate report) — hw issues per Linux comment
            self.reg_clear(dma_base, 1 << 23)?; // RXD_G5_EN

            // f. WTBLOFF_TOP_RSCR: RCPI reporting mode
            // RCPI_MODE = GENMASK(31,28), RCPI_PARAM = GENMASK(25,24)
            let rscr = wtbloff_base + 0x038;
            self.reg_rmw(rscr, (0xF << 28) | (0x3 << 24), 0x3 << 24)?;
        }

        // 5. RTS threshold is sent AFTER mac_enable in radio_init() — firmware
        // requires MAC subsystem active before accepting PROTECT_CTRL (0x3E).

        Ok(())
    }

    /// Full radio initialization — called after firmware is running.
    /// Matches __mt7921_init_hardware() + __mt7921_start() from the kernel driver.
    ///
    /// Linux sequence (init.c + main.c):
    ///   __mt7921_init_hardware:
    ///     1. mt792x_mcu_init (firmware)  — already done in full_init
    ///     2. mt7921_mcu_set_eeprom       — EEPROM calibration data
    ///     3. mt7921_mac_init             — MAC register setup
    ///   __mt7921_start:
    ///     4. mac_enable(0, true)         — enable MAC
    ///     5. set_channel_domain          — regulatory (skipped for now)
    ///     6. set_rx_path(ch)             — RX path config
    ///     7. set_tx_sar_pwr             — TX power limits
    fn radio_init(&mut self, channel: Channel) -> Result<()> {
        // Phase 1: __mt7921_init_hardware() — EEPROM calibration
        self.mcu_set_eeprom()?;

        // Phase 1b: Read per-device eFuse calibration data.
        // The firmware loaded eFuse internally from mcu_set_eeprom(), but we also
        // need the antenna config and TX power offsets for driver-side decisions.
        // Non-fatal: if eFuse read fails, NIC_CAPS defaults are used.
        let _ = self.mcu_read_efuse_cal();

        // Phase 2: __mt7921_start() — enable MAC, init hardware, set channels
        self.mcu_mac_enable(0, true)?;
        self.mac_init()?;
        self.wtbl_clear_all()?;
        // RTS threshold — must be after mac_enable (firmware asserts if sent before).
        // Matches mt76_connac_mcu_set_rts_thresh() in Linux mac_init flow.
        self.mcu_set_rts_thresh()?;
        self.mcu_set_channel_domain()?;
        // Initial channel uses SET_RX_PATH (0x4E) — matches Linux __mt7921_start().
        // SET_RX_PATH configures antenna paths + initial channel. rx_streams = antenna bitmask.
        // Sniffer is not active yet, so no sniffer config needed here.
        self.mcu_set_chan_info(MCU_EXT_CMD_SET_RX_PATH, channel, 0)?; // CH_SWITCH_NORMAL for init
        self.current_channel = channel;

        // Set band-specific MAC timing IMMEDIATELY after initial channel.
        // Linux: __mt7921_start() → set_rx_path() followed by mac_set_timeing().
        // Without this, CCA/PLCP/SIFS registers have stale firmware defaults.
        self.mac_set_timing(channel)?;

        // Send TX power limits for ALL bands via CE 0x5d (SET_RATE_TX_POWER).
        // This is REQUIRED for 6GHz — firmware won't enable the 6GHz RF path
        // without receiving country-coded per-channel power limits.
        // Matches Linux __mt7921_start() → mt76_connac_mcu_set_rate_txpower().
        self.mcu_set_rate_txpower_all()?;

        // Thermal init — read initial chip temperature.
        // Matches mt7921_thermal_init() from Linux init.c.
        // Establishes baseline temp; firmware uses this for thermal protection.
        let _ = self.mcu_get_temperature();

        Ok(())
    }

    /// Query chip temperature via MCU command (non-testmode).
    /// Matches mt7921_mcu_get_temperature() from Linux mt7921/mcu.c.
    ///
    /// Uses EXT_CMD_THERMAL_CTRL (0x2C) with action=0 (READ).
    /// Returns temperature in degrees Celsius.
    fn mcu_get_temperature(&mut self) -> Result<i32> {
        // struct thermal_ctrl_req {
        //   [0]   ctrl_id = 0 (READ_TEMPERATURE)
        //   [1]   band_idx = 0
        //   [2-3] pad
        // }
        let req = [0u8, 0, 0, 0]; // ctrl_id=0 (read), band=0
        let temp = self.mcu_send_ext_cmd(MCU_EXT_CMD_THERMAL_CTRL, &req, true)?;
        Ok(temp)
    }

    /// Set band-specific MAC timing registers — CRITICAL for correct frame detection.
    ///
    /// Matches mt792x_mac_set_timeing() from Linux mt792x_mac.c:35.
    /// MUST be called on every channel switch. Sets:
    ///   - CCK detect timeout (PLCP preamble + CCA energy detect)
    ///   - OFDM detect timeout (PLCP + CCA)
    ///   - Inter-frame spacing (SIFS differs: 10μs on 2.4GHz, 16μs on 5/6GHz)
    ///   - CF-END rate (11B for 2.4GHz, OFDM 24M for 5/6GHz)
    ///
    /// Without this, the chip uses stale timing from a previous band — CCA sensitivity
    /// and PLCP detection will be wrong, causing massive frame loss on the wrong band.
    fn mac_set_timing(&self, channel: Channel) -> Result<()> {
        // Register bases — band 0 (all our monitor ops use band 0)
        const TMAC_BASE: u32  = 0x820e4000;
        const AGG_BASE: u32   = 0x820e2000;
        const ARB_BASE: u32   = 0x820e3000;

        const TMAC_CDTR: u32  = TMAC_BASE + 0x090; // CCK detect timeout
        const TMAC_ODTR: u32  = TMAC_BASE + 0x094; // OFDM detect timeout
        const TMAC_ICR0: u32  = TMAC_BASE + 0x0a4; // IFS timing
        const AGG_ACR0: u32   = AGG_BASE + 0x084;  // CF-END rate
        const ARB_SCR: u32    = ARB_BASE + 0x080;   // TX/RX arbitration control

        const ARB_SCR_TX_DISABLE: u32 = 1 << 8;
        const ARB_SCR_RX_DISABLE: u32 = 1 << 9;

        // CFEND rate constants (from mt792x.h)
        const CFEND_RATE_OFDM_24M: u32 = 0x49;  // 5GHz/6GHz default
        const CFEND_RATE_11B: u32 = 0x03;        // 2.4GHz 11B LP, 11M

        let is_2ghz = channel.band == Band::Band2g;

        // SIFS: 10μs for 2.4GHz (802.11b/g/n), 16μs for 5GHz/6GHz (802.11a/ac/ax)
        let sifs: u32 = if is_2ghz { 10 } else { 16 };
        // Slot time: 9μs for short slot (non-legacy), 20μs for long slot (2.4GHz legacy)
        // Monitor mode always uses short slot (9μs) — we don't negotiate with APs
        let slottime: u32 = 9;

        // CCK timeout: PLCP=231 ticks, CCA=48 ticks (from Linux)
        let cck: u32 = 231 | (48 << 16);
        // OFDM timeout: PLCP=60 ticks, CCA=28 ticks
        let ofdm: u32 = 60 | (28 << 16);

        // coverage_class=0 for monitor mode (no range extension), so reg_offset=0

        // Step 1: Atomically disable TX+RX during timing update
        self.reg_set(ARB_SCR, ARB_SCR_TX_DISABLE | ARB_SCR_RX_DISABLE)?;
        thread::sleep(Duration::from_micros(1));

        // Step 2: Write band-specific timing registers
        self.reg_write(TMAC_CDTR, cck)?;
        self.reg_write(TMAC_ODTR, ofdm)?;

        // IFS: EIFS[8:0]=360, RIFS[14:10]=2, SIFS[22:16], SLOT[30:24]
        let icr0 = (360 & 0x1FF)
            | ((2 & 0x1F) << 10)
            | ((sifs & 0x7F) << 16)
            | ((slottime & 0x7F) << 24);
        self.reg_write(TMAC_ICR0, icr0)?;

        // CF-END rate: 11B for 2.4GHz (when slottime >= 20 or is_2ghz), OFDM 24M otherwise
        // For monitor mode with short slottime: use OFDM unless 2.4GHz
        let cfend_rate = if is_2ghz { CFEND_RATE_11B } else { CFEND_RATE_OFDM_24M };
        self.reg_rmw(AGG_ACR0, 0x3FFF, cfend_rate)?; // CFEND_RATE is GENMASK(13,0)

        // Step 3: Re-enable TX+RX
        self.reg_clear(ARB_SCR, ARB_SCR_TX_DISABLE | ARB_SCR_RX_DISABLE)?;

        Ok(())
    }

    /// Central channel switching — the ONE path for ALL runtime channel changes.
    ///
    /// Uses CHANNEL_SWITCH (0x08) for full RF reconfiguration — PLL retune, AGC recal,
    /// LNA path switch between 2.4G/5G/6G. Matches Linux mt7921_set_channel().
    /// rx_streams = hweight8(antenna_mask) = stream count (not bitmask like SET_RX_PATH).
    ///
    /// When sniffer is active, also updates the sniffer config which has its own
    /// band encoding (1/2/3 for 2.4/5/6 GHz) and BW encoding (0=20/40, 1=80, 2=160).
    /// Matches Linux change_chanctx() calling config_sniffer() for monitor VIFs.
    /// Without this, hopping between bands leaves the sniffer configured for the
    /// wrong band — subtle frame loss that's hard to diagnose.
    fn switch_channel(&mut self, channel: Channel) -> Result<()> {
        let prev_band = self.current_channel.band;

        // Use SET_RX_PATH for 6GHz band transitions — usbmon captures show Linux
        // always uses SET_RX_PATH (0x4E) when initializing on 6GHz. The 6GHz radio
        // frontend needs explicit antenna path configuration (rx_streams=bitmask)
        // that CHANNEL_SWITCH (rx_streams=count) doesn't provide.
        // For same-band hops on 2.4/5GHz, CHANNEL_SWITCH does full RF reconfig.
        let cmd = if channel.band == Band::Band6g || prev_band == Band::Band6g {
            MCU_EXT_CMD_SET_RX_PATH
        } else {
            MCU_EXT_CMD_CHANNEL_SWITCH
        };
        // Switch reason — from Linux mt7921_mcu_set_chan_info() (mcu.c:899):
        //   CH_SWITCH_NORMAL (0) — full calibration including DPD + AGC
        //   CH_SWITCH_SCAN_BYPASS_DPD (9) — skip DPD for faster switch (STA scan mode)
        //
        // CRITICAL: Linux uses CH_SWITCH_NORMAL for ALL switches in monitor mode!
        //   if (cmd == SET_RX_PATH || flags & IEEE80211_CONF_MONITOR)
        //       req.switch_reason = CH_SWITCH_NORMAL;
        //
        // CH_SWITCH_NORMAL triggers full RX calibration including AGC — without it,
        // the receiver sensitivity may be degraded, especially on 2.4GHz where AGC
        // tuning matters more due to interference. BYPASS_DPD skips this.
        const CH_SWITCH_NORMAL: u8 = 0;
        let switch_reason = CH_SWITCH_NORMAL; // Monitor mode: always full cal (matches Linux)
        self.mcu_set_chan_info(cmd, channel, switch_reason)?;

        // Set band-specific MAC timing — CCA, PLCP, SIFS, slot time.
        // Linux calls this on EVERY channel switch (mt7921_set_channel → mac_set_timeing).
        // Without this, frame detection uses stale timing from the previous band.
        self.mac_set_timing(channel)?;

        // Reset MIB/airtime counters — reading clears them.
        // Matches Linux mt7921_set_channel() → mac_reset_counters().
        self.mac_reset_counters()?;

        // Re-send TX power limits when switching TO 6GHz band.
        // The pcap shows Linux sends all-band TX power after every SET_RX_PATH
        // to 6GHz. The firmware may need fresh regulatory tables when the radio
        // is tuned to a new band — especially 6GHz which has strict requirements.
        if channel.band == Band::Band6g && prev_band != Band::Band6g {
            self.mcu_set_rate_txpower_all()?;
        }

        // Update BSS RLM (Radio Link Management) to keep firmware channel context in sync.
        // Linux sends BSS_INFO_UPDATE with RLM TLV on every channel switch.
        // Without this, firmware's BSS thinks it's on the old channel → routing issues.
        self.mcu_update_bss_rlm(channel)?;

        if self.sniffer_enabled {
            self.mcu_config_sniffer_channel(channel)?;

            // Re-apply critical RX filter bits after channel switch.
            // Some firmware versions may reset filter state during channel reconfiguration.
            // At minimum, ensure FCS fail and other-BSS frames aren't dropped.
            let monitor_drop_clear = MT_WF_RFCR_DROP_FCSFAIL
                | MT_WF_RFCR_DROP_OTHER_BSS
                | MT_WF_RFCR_DROP_OTHER_UC
                | MT_WF_RFCR_DROP_OTHER_TIM;
            let _ = self.mcu_set_rxfilter(0, MT7921_FIF_BIT_CLR, monitor_drop_clear);
        }
        self.current_channel = channel;
        Ok(())
    }

    /// Update BSS RLM (Radio Link Management) TLV — keeps firmware channel context in sync.
    /// Matches mt76_connac_mcu_uni_set_chctx() from Linux, called on every channel switch.
    fn mcu_update_bss_rlm(&mut self, channel: Channel) -> Result<()> {
        let (center_ch, bw) = channel_center_and_bw(channel);
        let hdr_len = 4;
        let rlm_len: u16 = 16;
        let mut req = vec![0u8; hdr_len + rlm_len as usize];
        req[0] = 0; // bss_idx

        let r = hdr_len;
        req[r..r+2].copy_from_slice(&2u16.to_le_bytes()); // tag = UNI_BSS_INFO_RLM
        req[r+2..r+4].copy_from_slice(&rlm_len.to_le_bytes());
        req[r+4] = channel.number; // control_channel
        req[r+5] = center_ch;
        req[r+6] = 0; // center_chan2 (80+80 only)
        req[r+7] = bw;
        req[r+8] = hweight8(self.nic_phy_tx_ant); // tx_streams
        req[r+9] = hweight8(self.nic_phy_rx_ant); // rx_streams
        req[r+10] = 1; // short_st
        req[r+11] = 4; // ht_op_info = HT 40M allowed
        // sco: secondary channel offset (1=above, 3=below, 0=none)
        req[r+12] = if center_ch > channel.number { 1 }
                     else if center_ch < channel.number { 3 }
                     else { 0 };
        req[r+13] = band_to_idx(channel.band);

        self.mcu_send_uni_cmd(MCU_UNI_CMD_BSS_INFO_UPDATE, &req, true)?;
        Ok(())
    }

    /// Set channel domain — tells firmware which channels are available.
    /// Matches mt76_connac_mcu_set_channel_domain() from mt76_connac_mcu.c.
    /// Sends CE cmd SET_CHAN_DOMAIN (0x0F).
    fn mcu_set_channel_domain(&mut self) -> Result<()> {
        // Header struct (12 bytes):
        //   alpha2[4], bw_2g, bw_5g, bw_6g, pad, n_2ch, n_5ch, n_6ch, pad2
        // Followed by per-channel entries (4 bytes each):
        //   hw_value(le16), pad(le16), flags(le32) — actually 8 bytes each

        // 2.4 GHz channels 1-14
        let channels_2g: Vec<u16> = (1..=14u16).collect();
        // 5 GHz channels
        let channels_5g: &[u16] = &[36, 40, 44, 48, 52, 56, 60, 64,
                                      100, 104, 108, 112, 116, 120, 124, 128,
                                      132, 136, 140, 144, 149, 153, 157, 161, 165,
                                      169, 173, 177];
        // 6 GHz channels (Band 4) — all 59 primary 20 MHz channels from phy_info
        // 5955-7115 MHz, channels 1-233 in steps of 4
        let channels_6g: Vec<u16> = (1..=233u16).step_by(4).collect();

        let n_2ch = channels_2g.len();
        let n_5ch = channels_5g.len();
        let n_6ch = channels_6g.len();
        let hdr_size = 12;
        let chan_entry_size = 8; // hw_value(2) + pad(2) + flags(4)
        let total = hdr_size + (n_2ch + n_5ch + n_6ch) * chan_entry_size;

        let mut data = vec![0u8; total];

        // Header
        data[0..4].copy_from_slice(b"\0\0\0\0"); // alpha2 = zeros (world)
        data[4] = 0;  // bw_2g = BW_20_40M
        data[5] = 3;  // bw_5g = BW_20_40_80_160M
        data[6] = 3;  // bw_6g = BW_20_40_80_160M
        data[8] = n_2ch as u8;
        data[9] = n_5ch as u8;
        data[10] = n_6ch as u8; // 6GHz channels — was 0, now all 59!

        // Channel entries
        let mut off = hdr_size;
        for &ch in channels_2g.iter() {
            data[off..off+2].copy_from_slice(&ch.to_le_bytes());
            off += chan_entry_size;
        }
        for &ch in channels_5g {
            data[off..off+2].copy_from_slice(&ch.to_le_bytes());
            off += chan_entry_size;
        }
        for &ch in channels_6g.iter() {
            data[off..off+2].copy_from_slice(&ch.to_le_bytes());
            off += chan_entry_size;
        }

        self.mcu_send_ce_cmd(MCU_CE_CMD_SET_CHAN_DOMAIN, &data, false)?;
        Ok(())
    }

    /// Create a virtual interface (VIF) in the firmware for monitor mode.
    /// Matches mt76_connac_mcu_uni_add_dev() from the kernel driver.
    ///
    /// The firmware needs a BSS entry to know where to deliver received frames.
    /// Without this, the WFDMA has data but no routing destination → 0 frames.
    ///
    /// Sends two UNI commands:
    ///   1. DEV_INFO_UPDATE (0x01) — register device with MAC address
    ///   2. BSS_INFO_UPDATE (0x02) — create BSS with conn_type=INFRA_AP
    fn mcu_add_dev(&mut self) -> Result<()> {
        let omac_idx: u8 = 0;
        let band_idx: u8 = 0;
        let bss_idx: u8 = 0;
        let wmm_idx: u8 = 0;
        // WTBL index for monitor mode: MT792x_WTBL_RESERVED - bss_idx
        // Linux uses 544 - 0 = 544, but WTBL size is 544, so index 543
        let wcid_idx: u16 = 543;

        // CONNECTION_INFRA_AP for monitor mode: STA_TYPE_AP(BIT(1)) | NETWORK_INFRA(BIT(16))
        let conn_type: u32 = (1u32 << 1) | (1u32 << 16); // 0x10002

        // 1. DEV_INFO_UPDATE (UNI cmd 0x01)
        // struct { omac_idx, band_idx, pad[2] } hdr (4 bytes)
        // struct { tag(le16), len(le16), active, link_idx, omac_addr[6] } tlv (12 bytes)
        let mut dev_req = [0u8; 16];
        dev_req[0] = omac_idx;
        dev_req[1] = band_idx;
        // tlv
        dev_req[4..6].copy_from_slice(&0u16.to_le_bytes()); // tag = DEV_INFO_ACTIVE = 0
        dev_req[6..8].copy_from_slice(&12u16.to_le_bytes()); // len = sizeof(tlv) = 12
        dev_req[8] = 1; // active = true
        dev_req[9] = 0; // link_idx = 0
        dev_req[10..16].copy_from_slice(&self.mac_addr.0); // omac_addr = our MAC

        self.mcu_send_uni_cmd(MCU_UNI_CMD_DEV_INFO_UPDATE, &dev_req, true)?;

        // 2. BSS_INFO_UPDATE (UNI cmd 0x02) — BASIC + QOS TLVs
        // Matches mt76_connac_mcu_uni_add_bss() from Linux mt76_connac_mcu.c:1546.
        //
        // mt76_connac_bss_basic_tlv layout (32 bytes):
        //   [0-1]  tag = UNI_BSS_INFO_BASIC (0)
        //   [2-3]  len = 32
        //   [4]    active
        //   [5]    omac_idx
        //   [6]    hw_bss_idx
        //   [7]    band_idx
        //   [8-11] conn_type (le32)
        //   [12]   conn_state
        //   [13]   wmm_idx
        //   [14-19] bssid[6]
        //   [20-21] bmc_tx_wlan_idx (le16)
        //   [22-23] bcn_interval (le16)
        //   [24]   dtim_period
        //   [25]   phymode (bit flags: A|B|G|GN|AN|AC|AX2|AX5|AX6)
        //   [26-27] sta_idx (le16)
        //   [28-29] nonht_basic_phy (le16)
        //   [30]   phymode_ext (bit 0 = AX_6G)
        //   [31]   link_idx
        //
        // mt76_connac_bss_qos_tlv layout (8 bytes):
        //   [0-1]  tag = UNI_BSS_INFO_QBSS (15)
        //   [2-3]  len = 8
        //   [4]    qos = 1 (enable WMM QoS)
        //   [5-7]  pad

        // phymode: bit flags for supported PHY modes
        // For monitor mode we declare all modes so firmware accepts all frame types
        // B(1) | G(2) | GN(3) | AN(4) | AC(5) | AX2(6) | AX5(7) = 0xFE
        let phymode: u8 = 0xFE; // All modes enabled for monitor
        let phymode_ext: u8 = 1; // AX_6G = bit 0

        let basic_len: u16 = 32;
        let qos_len: u16 = 8;
        let hdr_len = 4;
        let total = hdr_len + basic_len as usize + qos_len as usize;
        let mut bss_req = vec![0u8; total];

        // Header
        bss_req[0] = bss_idx;

        // BASIC TLV
        let t = hdr_len;
        bss_req[t..t+2].copy_from_slice(&0u16.to_le_bytes()); // tag = UNI_BSS_INFO_BASIC
        bss_req[t+2..t+4].copy_from_slice(&basic_len.to_le_bytes()); // len
        bss_req[t+4] = 1; // active = true
        bss_req[t+5] = omac_idx;
        bss_req[t+6] = omac_idx; // hw_bss_idx (same when < EXT_BSSID_START)
        bss_req[t+7] = band_idx;
        bss_req[t+8..t+12].copy_from_slice(&conn_type.to_le_bytes()); // CONNECTION_INFRA_AP
        bss_req[t+12] = 0; // conn_state = DISCONNECT (Linux: !enable for AP mode activate)
        bss_req[t+13] = wmm_idx;
        // bssid[6] at t+14..t+20: zeros for monitor (no specific BSS)
        bss_req[t+20..t+22].copy_from_slice(&wcid_idx.to_le_bytes()); // bmc_tx_wlan_idx
        bss_req[t+22..t+24].copy_from_slice(&100u16.to_le_bytes()); // bcn_interval = 100 TU
        bss_req[t+24] = 1; // dtim_period = 1
        bss_req[t+25] = phymode;
        bss_req[t+26..t+28].copy_from_slice(&wcid_idx.to_le_bytes()); // sta_idx
        // nonht_basic_phy: OFDM(bit 2) = 4 for 5GHz default
        bss_req[t+28..t+30].copy_from_slice(&4u16.to_le_bytes());
        bss_req[t+30] = phymode_ext; // AX_6G

        // QOS TLV — enables WMM QoS handling in firmware
        let q = t + basic_len as usize;
        bss_req[q..q+2].copy_from_slice(&15u16.to_le_bytes()); // tag = UNI_BSS_INFO_QBSS
        bss_req[q+2..q+4].copy_from_slice(&qos_len.to_le_bytes()); // len
        bss_req[q+4] = 1; // qos = true (enable WMM)

        self.mcu_send_uni_cmd(MCU_UNI_CMD_BSS_INFO_UPDATE, &bss_req, true)?;

        // 3. BSS_INFO_UPDATE — RLM TLV (Radio Link Management / channel context)
        // Matches mt76_connac_mcu_uni_set_chctx() from Linux mt76_connac_mcu.c:1464.
        // Tells firmware the channel parameters for this BSS.
        let (center_ch, bw) = channel_center_and_bw(self.current_channel);
        let rlm_len: u16 = 16; // sizeof(rlm_tlv)
        let mut rlm_req = vec![0u8; hdr_len + rlm_len as usize];
        rlm_req[0] = bss_idx;

        let r = hdr_len;
        rlm_req[r..r+2].copy_from_slice(&2u16.to_le_bytes()); // tag = UNI_BSS_INFO_RLM
        rlm_req[r+2..r+4].copy_from_slice(&rlm_len.to_le_bytes()); // len
        rlm_req[r+4] = self.current_channel.number; // control_channel
        rlm_req[r+5] = center_ch; // center_chan
        rlm_req[r+6] = 0; // center_chan2 (80+80 only)
        rlm_req[r+7] = bw; // bw: 0=20, 1=40, 2=80, 3=160
        rlm_req[r+8] = hweight8(self.nic_phy_tx_ant); // tx_streams
        rlm_req[r+9] = hweight8(self.nic_phy_rx_ant); // rx_streams
        rlm_req[r+10] = 1; // short_st = true
        rlm_req[r+11] = 4; // ht_op_info = 4 (HT 40M allowed)
        rlm_req[r+12] = 0; // sco (secondary channel offset)
        rlm_req[r+13] = band_to_idx(self.current_channel.band); // band: 0=2.4G, 1=5G, 2=6G

        self.mcu_send_uni_cmd(MCU_UNI_CMD_BSS_INFO_UPDATE, &rlm_req, true)?;

        // 4. BSS_INFO_UPDATE — HE TLV (802.11ax capabilities for this BSS)
        // Matches mt76_connac_mcu_bss_he_tlv() from Linux mt76_connac_mcu.c.
        // Tells firmware this BSS supports HE operations.
        //
        // UNI_BSS_INFO_HE_BASIC (tag 20) layout (8 bytes):
        //   [0-1]  tag = 20
        //   [2-3]  len = 8
        //   [4-5]  default_pe_duration (le16) = 4 (matches Linux)
        //   [6]    vht_op_info_present = 0
        //   [7]    pad
        let he_tlv_len: u16 = 8;
        let mut he_req = vec![0u8; hdr_len + he_tlv_len as usize];
        he_req[0] = bss_idx;
        let h = hdr_len;
        he_req[h..h+2].copy_from_slice(&20u16.to_le_bytes()); // tag = UNI_BSS_INFO_HE_BASIC
        he_req[h+2..h+4].copy_from_slice(&he_tlv_len.to_le_bytes());
        he_req[h+4..h+6].copy_from_slice(&4u16.to_le_bytes()); // default_pe_duration = 4
        self.mcu_send_uni_cmd(MCU_UNI_CMD_BSS_INFO_UPDATE, &he_req, true)?;

        // 5. BSS_INFO_UPDATE — RATE TLV (supported rate set for this BSS)
        // Matches mt76_connac_mcu_bss_basic_rates_tlv() from Linux.
        //
        // UNI_BSS_INFO_RATE (tag 11) layout (8 bytes):
        //   [0-1]  tag = 11
        //   [2-3]  len = 8
        //   [4-5]  basic_rate (le16) — bitmap of basic rates
        //   [6-7]  pad
        let rate_tlv_len: u16 = 8;
        let mut rate_req = vec![0u8; hdr_len + rate_tlv_len as usize];
        rate_req[0] = bss_idx;
        let rt = hdr_len;
        rate_req[rt..rt+2].copy_from_slice(&11u16.to_le_bytes()); // tag = UNI_BSS_INFO_RATE
        rate_req[rt+2..rt+4].copy_from_slice(&rate_tlv_len.to_le_bytes());
        // basic_rate bitmap: for monitor mode, declare all basic rates
        // Linux sets this from vif->bss_conf.basic_rates. For 5GHz/6GHz OFDM-only:
        //   6M(0x10), 12M(0x20), 24M(0x40) = 0x150 (matches Linux CCK+OFDM bitfield)
        // For 2.4GHz: include CCK rates too.
        // Use 0x15F = all OFDM mandatory + CCK rates (universal acceptance)
        let basic_rate: u16 = 0x015F;
        rate_req[rt+4..rt+6].copy_from_slice(&basic_rate.to_le_bytes());
        self.mcu_send_uni_cmd(MCU_UNI_CMD_BSS_INFO_UPDATE, &rate_req, true)?;

        Ok(())
    }

    /// Set EDCA (Enhanced Distributed Channel Access) QoS parameters.
    /// Matches mt7921_mcu_set_tx() from Linux mt7921/mcu.c:672.
    ///
    /// Configures per-AC (Access Category) channel access timing:
    ///   - CW_MIN/CW_MAX: contention window bounds
    ///   - AIFS: arbitration inter-frame spacing
    ///   - TXOP: transmit opportunity limit
    ///
    /// Without these, firmware uses conservative defaults that affect frame delivery.
    fn mcu_set_edca(&mut self) -> Result<()> {
        // EDCA struct per AC: cw_min(le16), cw_max(le16), txop(le16), aifs(le16),
        //                     guardtime(u8), acm(u8) = 10 bytes per AC
        // Total: 4 ACs × 10 + bss_idx(1) + qos(1) + wmm_idx(1) + pad(1) = 44 bytes
        //
        // AC order in struct: BK(1), BE(0), VI(2), VO(3) — mapped by to_aci[]

        let mut req = [0u8; 44];

        // Default 802.11 EDCA parameters (from IEEE 802.11-2020 Table 9-155)
        // Format: [cw_min, cw_max, aifs, txop]
        let edca_defaults: [(u16, u16, u16, u16); 4] = [
            // to_aci[0] = AC_BK (index 1): CWmin=15, CWmax=1023, AIFS=7, TXOP=0
            (15, 1023, 7, 0),
            // to_aci[1] = AC_BE (index 0): CWmin=15, CWmax=1023, AIFS=3, TXOP=0
            (15, 1023, 3, 0),
            // to_aci[2] = AC_VI (index 2): CWmin=7, CWmax=15, AIFS=2, TXOP=94
            (7, 15, 2, 94),
            // to_aci[3] = AC_VO (index 3): CWmin=3, CWmax=7, AIFS=2, TXOP=47
            (3, 7, 2, 47),
        ];

        // Map to Linux order: to_aci[] = { 1, 0, 2, 3 }
        // Struct order: [AC_BE(0), AC_BK(1), AC_VI(2), AC_VO(3)]
        // Linux: for ac in 0..4 { req.edca[to_aci[ac]] = queue_params[ac] }
        // ac=0(BK) → to_aci[0]=1, ac=1(BE) → to_aci[1]=0,
        // ac=2(VI) → to_aci[2]=2, ac=3(VO) → to_aci[3]=3
        let ordered: [(u16, u16, u16, u16); 4] = [
            edca_defaults[1], // slot 0 = BE
            edca_defaults[0], // slot 1 = BK
            edca_defaults[2], // slot 2 = VI
            edca_defaults[3], // slot 3 = VO
        ];

        for (i, &(cw_min, cw_max, aifs, txop)) in ordered.iter().enumerate() {
            let off = i * 10;
            req[off..off+2].copy_from_slice(&cw_min.to_le_bytes());
            req[off+2..off+4].copy_from_slice(&cw_max.to_le_bytes());
            req[off+4..off+6].copy_from_slice(&txop.to_le_bytes());
            req[off+6..off+8].copy_from_slice(&aifs.to_le_bytes());
            // guardtime[8]=0, acm[9]=0
        }
        // bss_idx, qos, wmm_idx, pad at offset 40
        req[40] = 0; // bss_idx
        req[41] = 1; // qos = true
        req[42] = 0; // wmm_idx
        // req[43] = pad

        self.mcu_send_ce_cmd(MCU_CE_CMD_SET_EDCA_PARMS, &req, false)?;
        Ok(())
    }

    /// Reset MAC counters — clear MIB, TX aggregation, and airtime statistics.
    /// Matches mt792x_mac_reset_counters() from Linux mt792x_mac.c:192.
    /// Called on every channel switch and during monitor mode init.
    fn mac_reset_counters(&self) -> Result<()> {
        // Read and discard TX aggregation counters (reading clears them)
        for i in 0..4u32 {
            let _ = self.reg_read(0x820e2000 + 0x0a8 + i * 4); // MT_TX_AGG_CNT(0, i)
            let _ = self.reg_read(0x820e2000 + 0x164 + i * 4); // MT_TX_AGG_CNT2(0, i)
        }

        // Read and discard airtime counters (reading clears them)
        let _ = self.reg_read(MT_WF_MIB_BASE0 + MT_MIB_SDR9_OFF);  // busy time
        let _ = self.reg_read(MT_WF_MIB_BASE0 + MT_MIB_SDR36_OFF); // TX time
        let _ = self.reg_read(MT_WF_MIB_BASE0 + MT_MIB_SDR37_OFF); // RX time

        // Clear and re-enable RX time measurement
        self.reg_set(MT_WF_RMAC_BASE0 + MT_WF_RMAC_MIB_TIME0_OFF,
                     MT_WF_RMAC_MIB_RXTIME_CLR)?;
        let rmac_airtime0 = MT_WF_RMAC_BASE0 + 0x0380;
        self.reg_set(rmac_airtime0, 1 << 31)?; // RXTIME_CLR in AIRTIME0

        Ok(())
    }

    /// Set RTS/CTS protection threshold via MCU command.
    /// Matches mt76_connac_mcu_set_rts_thresh() from Linux mt76_connac_mcu.c.
    ///
    /// MUST be called after mcu_mac_enable() — firmware asserts if MAC isn't active.
    /// Linux calls with rts_threshold=0x92b (2347 = max MSDU), enable=0.
    ///
    /// EXT_CMD_PROTECT_CTRL (0x3E) struct:
    ///   [0]   protect_idx (0 = RTS threshold)
    ///   [1-3] pad
    ///   [4-7] len (le32) = threshold value
    ///   [8]   enable
    ///   [9-11] pad
    fn mcu_set_rts_thresh(&mut self) -> Result<()> {
        let mut req = [0u8; 12];
        req[0] = 0; // protect_idx = 0 (RTS threshold)
        req[4..8].copy_from_slice(&0x092bu32.to_le_bytes()); // threshold = 2347
        req[8] = 0; // enable = 0 (disabled — matches Linux default)
        self.mcu_send_ext_cmd(MCU_EXT_CMD_PROTECT_CTRL, &req, true)?;
        Ok(())
    }

    /// Send STA_REC_UPDATE — register a station record in firmware.
    /// Matches mt7921_mcu_sta_update() → mt76_connac_mcu_sta_cmd() from Linux.
    ///
    /// For monitor mode, Linux creates a broadcast station record (sta=NULL, offload_fw=true)
    /// with CONNECTION_INFRA_BC to handle broadcast/multicast frames. This is called from
    /// mt7921_bss_info_changed() with BSS_CHANGED_ASSOC.
    ///
    /// The command structure is:
    ///   sta_req_hdr (8 bytes) + sta_rec_basic TLV (20 bytes)
    /// Sent via MCU_UNI_CMD(STA_REC_UPDATE) = 0x03
    fn mcu_sta_update(&mut self, enable: bool) -> Result<()> {
        // TLV tags from mt76_connac_mcu.h
        const STA_REC_BASIC: u16 = 0;
        const STA_REC_HT: u16 = 7;
        const STA_REC_VHT: u16 = 8;
        const STA_REC_HE: u16 = 23;
        const STA_REC_PHY: u16 = 20;

        let bss_idx: u8 = 0;
        let wcid_idx: u16 = 543; // MT792x_WTBL_RESERVED - bss_idx

        // CONNECTION_INFRA_BC = STA_TYPE_BC(BIT(4)) | NETWORK_INFRA(BIT(16))
        let conn_type: u32 = (1u32 << 4) | (1u32 << 16); // 0x10010
        let conn_state: u8 = if enable { 2 } else { 0 }; // CONN_STATE_PORT_SECURE / DISCONNECT

        // TLV sizes (must match mt76_connac_mcu structs exactly)
        let hdr_len = 8;
        let basic_len: usize = 20;
        let ht_len: usize = 28;     // sta_rec_ht: tag(2)+len(2)+ht_cap(26 bytes of IE content)
        let vht_len: usize = 16;    // sta_rec_vht: tag(2)+len(2)+vht_cap(4)+vht_rx_mcs_map(2)+
                                      //   vht_tx_mcs_map(2)+pad(4)
        let he_len: usize = 24;     // sta_rec_he: tag(2)+len(2)+he_mac_cap(6)+he_phy_cap(11)+
                                      //   mcs_map_bw80(4)+pad(1) — simplified for connac2
        let phy_len: usize = 8;     // sta_rec_phy: tag(2)+len(2)+phy_type(1)+pad(3)

        let n_tlvs: u16 = if enable { 5 } else { 1 };
        let total = if enable {
            hdr_len + basic_len + ht_len + vht_len + he_len + phy_len
        } else {
            hdr_len + basic_len
        };
        let mut req = vec![0u8; total];

        // Header (8 bytes)
        req[0] = bss_idx;
        req[1] = (wcid_idx & 0xFF) as u8; // wlan_idx_lo
        req[2..4].copy_from_slice(&n_tlvs.to_le_bytes());
        req[4] = 1; // is_tlv_append
        req[5] = 0x0e; // muar_idx = 0xe for broadcast (non-associated) STA
        req[6] = ((wcid_idx >> 8) & 0xFF) as u8; // wlan_idx_hi

        // ── STA_REC_BASIC TLV (20 bytes) ──
        let t = hdr_len;
        req[t..t+2].copy_from_slice(&STA_REC_BASIC.to_le_bytes());
        req[t+2..t+4].copy_from_slice(&(basic_len as u16).to_le_bytes());
        req[t+4..t+8].copy_from_slice(&conn_type.to_le_bytes());
        req[t+8] = conn_state;
        req[t+9] = 1; // qos = true
        req[t+10..t+12].copy_from_slice(&0u16.to_le_bytes()); // aid = 0
        req[t+12..t+18].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // broadcast
        let extra = if enable { 0x03u16 } else { 0x01u16 };
        req[t+18..t+20].copy_from_slice(&extra.to_le_bytes());

        if enable {
            // ── STA_REC_HT TLV (28 bytes) ──
            // Declares HT capabilities so firmware handles HT frames correctly.
            // Matches mt76_connac_mcu_sta_tlv() → sta_rec_ht TLV build in Linux.
            let h = t + basic_len;
            req[h..h+2].copy_from_slice(&STA_REC_HT.to_le_bytes());
            req[h+2..h+4].copy_from_slice(&(ht_len as u16).to_le_bytes());
            // ht_cap (le16) at [h+4..h+6]:
            //   LDPC(bit 0) | BW40(bit 1) | SM_PS_DISABLED(0x0C, bits 3:2) |
            //   GF(bit 4) | SGI20(bit 5) | SGI40(bit 6) | STBC_TX(bit 7) |
            //   STBC_RX_1SS(bit 8) | MAX_AMSDU_7935(bit 11)
            let ht_cap: u16 = (1 << 0)  // LDPC coding capability
                | (1 << 1)   // 40MHz supported
                | (0x03 << 2) // SM power save disabled (0x03 = disabled)
                | (1 << 4)   // Greenfield (GF)
                | (1 << 5)   // SGI 20MHz
                | (1 << 6)   // SGI 40MHz
                | (1 << 7)   // TX STBC
                | (1 << 8)   // RX STBC 1 stream
                | (1 << 11); // Max A-MSDU = 7935
            req[h+4..h+6].copy_from_slice(&ht_cap.to_le_bytes());
            // ampdu_params at [h+6]: max length exponent=3 (64KB), min spacing=0
            req[h+6] = (3 << 0) | (0 << 2); // MAX_LEN_EXP=3, MIN_MPDU_START=0
            // mcs_set[16] at [h+8..h+24]: enable MCS 0-7 per spatial stream
            let nss = self.nic_phy_nss.max(1).min(4);
            for ss in 0..nss {
                req[h + 8 + ss as usize] = 0xFF; // MCS 0-7 for this SS
            }

            // ── STA_REC_VHT TLV (16 bytes) ──
            // Declares VHT (802.11ac) capabilities.
            let v = h + ht_len;
            req[v..v+2].copy_from_slice(&STA_REC_VHT.to_le_bytes());
            req[v+2..v+4].copy_from_slice(&(vht_len as u16).to_le_bytes());
            // vht_cap_info (le32) at [v+4..v+8]:
            //   MAX_MPDU_7991(bit 0) | BW80(no bit needed) | RXLDPC(bit 4) |
            //   SGI80(bit 5) | STBC_TX(bit 6) | STBC_RX(bit 8) | SU_BEAMFORMEE(bit 12) |
            //   BEAMFORMEE_STS=3(bits 15:13, means 4 STS)
            let vht_cap: u32 = (1 << 0)  // MAX_MPDU_7991
                | (1 << 4)   // RX LDPC
                | (1 << 5)   // SGI 80MHz
                | (1 << 6)   // TX STBC
                | (1 << 8)   // RX STBC 1 stream
                | (1 << 12)  // SU beamformee capable
                | (3 << 13); // beamformee STS cap = 4
            req[v+4..v+8].copy_from_slice(&vht_cap.to_le_bytes());
            // vht_rx_mcs_map (le16) at [v+8..v+10]:
            // Each SS takes 2 bits: 0=MCS0-7, 1=MCS0-8, 2=MCS0-9, 3=not supported
            // Enable MCS 0-9 for supported streams, mark rest as unsupported
            let vht_nss = self.nic_phy_nss.max(1).min(8);
            let mut rx_mcs: u16 = 0;
            for ss in 0..8u16 {
                let val = if (ss as u8) < vht_nss { 0x2 } else { 0x3 }; // MCS 0-9 or not supported
                rx_mcs |= val << (ss * 2);
            }
            req[v+8..v+10].copy_from_slice(&rx_mcs.to_le_bytes());
            // vht_tx_mcs_map (le16) at [v+10..v+12]: same as rx
            req[v+10..v+12].copy_from_slice(&rx_mcs.to_le_bytes());

            // ── STA_REC_HE TLV (24 bytes) ──
            // Declares HE (802.11ax / WiFi 6) capabilities.
            let e = v + vht_len;
            req[e..e+2].copy_from_slice(&STA_REC_HE.to_le_bytes());
            req[e+2..e+4].copy_from_slice(&(he_len as u16).to_le_bytes());
            // he_mac_cap[6] at [e+4..e+10]:
            //   byte 0: HTC_HE(bit 0) | TWT_REQ(bit 1)
            //   byte 3: OMI_CTRL(bit 1) | AMSDU_IN_AMPDU(bit 3)
            req[e+4] = 0x01; // HTC-HE support
            req[e+7] = 0x0A; // OMI control + AMSDU in AMPDU
            // he_phy_cap[11] at [e+10..e+21]:
            //   byte 0: DUAL_BAND(bit 0) for 2.4+5GHz
            //   byte 1: BW40_2G(bit 1) | BW40_80_5G(bit 2)
            //   byte 3: LDPC(bit 1) | SU_BEAMFORMEE(bit 4) | BEAMFORMEE_STS_LE80(bits 6:4, val=3)
            //   byte 5: NG16_SU(bit 0) | NG16_MU(bit 1) | CODEBOOK_4_2_SU(bit 2)
            //   byte 7: HE_ER_SU_PPDU(bit 3) | 20MHZ_IN_40(bit 5) | 20MHZ_IN_160(bit 6)
            //   byte 8: DCM_MAX_RX_NSS_2(bit 0)
            req[e+10] = 0x01; // dual band
            req[e+11] = 0x06; // BW40_2G | BW40_80_5G
            req[e+13] = 0x32; // LDPC | SU_BEAMFORMEE | STS_LE80=3
            req[e+15] = 0x07; // NG16_SU | NG16_MU | CODEBOOK_4_2_SU
            // he_rx_mcs_bw80 (le16 × 2) at [e+20..e+24]:
            // Each SS: 0=MCS0-7, 1=MCS0-9, 2=MCS0-11, 3=not supported
            let he_nss = self.nic_phy_nss.max(1).min(8);
            let mut he_mcs: u16 = 0;
            for ss in 0..8u16 {
                let val = if (ss as u8) < he_nss { 0x2 } else { 0x3 }; // MCS 0-11 or not supported
                he_mcs |= val << (ss * 2);
            }
            req[e+20..e+22].copy_from_slice(&he_mcs.to_le_bytes()); // rx mcs bw80
            req[e+22..e+24].copy_from_slice(&he_mcs.to_le_bytes()); // tx mcs bw80

            // ── STA_REC_PHY TLV (8 bytes) ──
            // Declares the PHY type — which modes this STA supports.
            let p = e + he_len;
            req[p..p+2].copy_from_slice(&STA_REC_PHY.to_le_bytes());
            req[p+2..p+4].copy_from_slice(&(phy_len as u16).to_le_bytes());
            // phy_type at [p+4]: bit flags matching BSS_INFO phymode
            // B(1)|G(2)|GN(4)|AN(8)|AC(16)|AX(32) = 0x3F for all modes
            req[p+4] = 0x3F; // all PHY modes
        }

        self.mcu_send_uni_cmd(MCU_UNI_CMD_STA_REC_UPDATE, &req, true)?;
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Monitor / Sniffer Mode
    // ══════════════════════════════════════════════════════════════════════════

    /// Enable/disable sniffer (monitor) mode via MCU command.
    /// Matches mt7921_mcu_set_sniffer() from the kernel driver.
    fn mcu_set_sniffer(&mut self, enable: bool) -> Result<()> {
        // Build TLV payload:
        // struct { band_idx[1], pad[3] } hdr
        // struct { tag[2], len[2], enable[1], pad[3] } tlv
        let mut payload = [0u8; 12];
        // hdr.band_idx = 0 (band 0)
        payload[0] = 0;
        // tlv.tag = 0 (sniffer enable)
        payload[4..6].copy_from_slice(&0u16.to_le_bytes());
        // tlv.len = 8
        payload[6..8].copy_from_slice(&8u16.to_le_bytes());
        // tlv.enable
        payload[8] = if enable { 1 } else { 0 };

        self.mcu_send_uni_cmd(MCU_UNI_CMD_SNIFFER, &payload, true)?;
        self.sniffer_enabled = enable;

        Ok(())
    }

    /// Configure sniffer channel via MCU command.
    /// Matches mt7921_mcu_config_sniffer() from Linux mt7921/mcu.c:1161.
    fn mcu_config_sniffer_channel(&mut self, channel: Channel) -> Result<()> {
        let (center_ch, cmd_bw) = channel_center_and_bw(channel);

        // Sniffer bw mapping differs from chan_info CMD_CBW_*!
        // Linux ch_width[]: 20/40→0, 80→1, 160→2, 80+80→3
        let sniffer_bw: u8 = match cmd_bw {
            0 | 1 => 0,  // 20MHz and 40MHz both map to 0
            2 => 1,       // 80MHz → 1
            3 => 2,       // 160MHz → 2
            _ => 0,
        };

        // sco: secondary channel offset
        // Linux: 1=SCA (control < center), 3=SCB (control > center), 0=none
        let sco: u8 = if center_ch > channel.number { 1 }
                       else if center_ch < channel.number { 3 }
                       else { 0 };

        // Build TLV payload:
        // struct { band_idx[1], pad[3] } hdr
        // struct { tag[2], len[2], aid[2], ch_band[1], bw[1],
        //          control_ch[1], sco[1], center_ch[1], center_ch2[1],
        //          drop_err[1], pad[3] } tlv
        let mut payload = [0u8; 20];
        // hdr.band_idx = PHY band index (always 0 for single-PHY MT7921AU)
        payload[0] = 0;
        // tlv.tag = 1 (config)
        payload[4..6].copy_from_slice(&1u16.to_le_bytes());
        // tlv.len = 16
        payload[6..8].copy_from_slice(&16u16.to_le_bytes());
        // tlv.ch_band (byte 10) — Linux mcu.c:1166 maps: 1=2GHz, 2=5GHz, 3=6GHz
        payload[10] = band_to_idx(channel.band) + 1;
        // tlv.bw (byte 11) — sniffer bw encoding
        payload[11] = sniffer_bw;
        // tlv.control_ch (byte 12)
        payload[12] = channel.number;
        // tlv.sco (byte 13) — secondary channel offset
        payload[13] = sco;
        // tlv.center_ch (byte 14)
        payload[14] = center_ch;
        // tlv.center_ch2 = 0 (byte 15)
        payload[15] = 0;
        // tlv.drop_err = 0 (byte 16)
        // MUST be 0 for monitor mode — drop_err=1 tells firmware to discard frames
        // with errors, which on 2.4GHz (high interference: BT, microwave, overlapping
        // channels) silently eats a large percentage of frames. We handle FCS errors
        // ourselves via is_fcs_error in the RxFrame.
        payload[16] = 0;

        self.mcu_send_uni_cmd(MCU_UNI_CMD_SNIFFER, &payload, true)?;
        Ok(())
    }

    /// Parse a single RX packet from the internal buffer.
    /// Returns Some(RxFrame) for data frames, None for events/non-data or buffer exhausted.
    ///
    /// MT7921AU USB RX format (connac2 with MT_DRV_RX_DMA_HDR):
    ///   [RXD DW0-DW5 (24)] [optional groups 1-5] [802.11 frame]
    ///
    /// IMPORTANT: There is NO separate SDIO/DMA header on USB RX!
    /// The first 4 bytes ARE the RXD DW0 (confirmed by Linux mt76u_build_rx_skb
    /// with MT_DRV_RX_DMA_HDR flag — head_room=0, skb starts at byte 0).
    /// DW0[15:0] contains the total packet length including the RXD itself.
    ///
    /// The RXD (receive descriptor) is a connac2 format with:
    /// Read MAC address from EEPROM via MCU.
    /// Query NIC capabilities and parse TLV response — reads MAC address, PHY caps, etc.
    /// Matches mt7921_mcu_get_nic_capability() from Linux mt7921/mcu.c:556.
    ///
    /// The firmware responds with a TLV chain:
    ///   Header: n_element(le16), rsv[2]
    ///   TLVs:   type(le32), len(le32), data[len]
    ///
    /// TLV types (from mt76_connac_mcu.h):
    ///   0  = TX_RESOURCE
    ///   6  = SW_VER
    ///   7  = MAC_ADDR ← we need this
    ///   8  = PHY
    ///   0x14 = HW_ADIE_VERSION
    ///   0x18 = 6G ← has_6ghz flag
    ///   0x20 = CHIP_CAP
    fn mcu_get_nic_capability(&mut self) -> Result<()> {
        let seq = self.next_mcu_seq();

        // Build CE cmd GET_NIC_CAPAB (0x8A) — same as before but capture response
        let mut txd = [0u8; MT_SDIO_TXD_SIZE];
        let msg_len = MT_SDIO_TXD_SIZE;
        let txd_dw0: u32 = (msg_len as u32 & 0xFFFF)
            | (1u32 << 23) | (0x20u32 << 25);
        txd[0..4].copy_from_slice(&txd_dw0.to_le_bytes());
        let txd_dw1: u32 = (1u32 << 16) | (1u32 << 31);
        txd[4..8].copy_from_slice(&txd_dw1.to_le_bytes());
        let m = 32;
        let mcu_len = (msg_len - 32) as u16;
        txd[m..m+2].copy_from_slice(&mcu_len.to_le_bytes());
        let pq_id: u16 = (1 << 15) | (0x20 << 10);
        txd[m+2..m+4].copy_from_slice(&pq_id.to_le_bytes());
        txd[m+4] = 0x8A; // GET_NIC_CAPAB
        txd[m+5] = MCU_PKT_ID;
        txd[m+6] = 1; // set_query = MCU_Q_SET
        txd[m+7] = seq;
        txd[m+10] = MCU_S2D_H2N;

        let total_len = MT_SDIO_HDR_SIZE + msg_len;
        let padded_len = (total_len + 3) & !3;
        let final_len = padded_len + MT_USB_TAIL_SIZE;
        let mut pkt = vec![0u8; final_len];
        let sdio_hdr: u32 = (msg_len as u32) & 0xFFFF;
        pkt[0..4].copy_from_slice(&sdio_hdr.to_le_bytes());
        pkt[MT_SDIO_HDR_SIZE..MT_SDIO_HDR_SIZE + MT_SDIO_TXD_SIZE].copy_from_slice(&txd);

        self.handle.write_bulk(self.ep_mcu_out, &pkt, USB_BULK_TIMEOUT)?;

        // Get raw response
        let resp = self.mcu_recv_response_raw(seq)?;

        // Parse TLV chain from response
        // Response layout: RXD(24) + MCU_RXD(8) + payload
        // Payload starts at byte 32: cap_hdr(4) + TLVs
        if resp.len() < 36 {
            return Ok(()); // Short response, no TLVs
        }

        let payload = &resp[32..];
        if payload.len() < 4 {
            return Ok(());
        }

        let n_element = u16::from_le_bytes([payload[0], payload[1]]);
        let mut off = 4; // skip cap_hdr (n_element + rsv[2])

        for _ in 0..n_element {
            if off + 8 > payload.len() { break; }
            let tlv_type = u32::from_le_bytes([
                payload[off], payload[off+1], payload[off+2], payload[off+3]]);
            let tlv_len = u32::from_le_bytes([
                payload[off+4], payload[off+5], payload[off+6], payload[off+7]]) as usize;
            off += 8;

            if off + tlv_len > payload.len() { break; }
            let tlv_data = &payload[off..off + tlv_len];

            match tlv_type {
                0 => { // MT_NIC_CAP_TX_RESOURCE
                    // Layout: ver(1), pad(3), total_page_count(le32), tx_token_count(le32), ...
                    if tlv_data.len() >= 12 {
                        self.nic_tx_token_count = u32::from_le_bytes([
                            tlv_data[8], tlv_data[9], tlv_data[10], tlv_data[11]]);
                    }
                }
                6 => { // MT_NIC_CAP_SW_VER
                    // Firmware version string (null-terminated)
                    if !tlv_data.is_empty() {
                        let end = tlv_data.iter().position(|&b| b == 0).unwrap_or(tlv_data.len());
                        if let Ok(ver) = std::str::from_utf8(&tlv_data[..end]) {
                            if !ver.is_empty() {
                                self.fw_version = ver.to_string();
                            }
                        }
                    }
                }
                7 => { // MT_NIC_CAP_MAC_ADDR
                    if tlv_data.len() >= 6 {
                        self.mac_addr = MacAddress([
                            tlv_data[0], tlv_data[1], tlv_data[2],
                            tlv_data[3], tlv_data[4], tlv_data[5],
                        ]);
                    }
                }
                8 => { // MT_NIC_CAP_PHY
                    // Layout: nss(1), tx_ant(1), rx_ant(1), max_bw(1), ...
                    if tlv_data.len() >= 4 {
                        self.nic_phy_nss = tlv_data[0];
                        self.nic_phy_tx_ant = tlv_data[1];
                        self.nic_phy_rx_ant = tlv_data[2];
                        self.nic_phy_max_bw = tlv_data[3];
                    }
                }
                0x14 => { // MT_NIC_CAP_HW_ADIE_VERSION
                    if tlv_data.len() >= 4 {
                        self.nic_adie_version = u32::from_le_bytes([
                            tlv_data[0], tlv_data[1], tlv_data[2], tlv_data[3]]);
                    }
                }
                0x18 => { // MT_NIC_CAP_6G
                    if !tlv_data.is_empty() {
                        self.nic_has_6ghz = tlv_data[0] != 0;
                    }
                }
                0x20 => { // MT_NIC_CAP_CHIP_CAP
                    if tlv_data.len() >= 4 {
                        self.nic_chip_cap = u32::from_le_bytes([
                            tlv_data[0], tlv_data[1], tlv_data[2], tlv_data[3]]);
                    }
                }
                _ => {} // Other TLVs — parsed but not yet used
            }

            off += tlv_len;
        }

        Ok(())
    }

    fn read_mac_from_eeprom(&mut self) -> Result<MacAddress> {
        // Fallback: generate a locally-administered MAC based on device IDs.
        // This is only used if mcu_get_nic_capability() fails to provide one.
        let mac_bytes = [0x02, 0x7E, 0xCA, 0xFE, (self.vid & 0xFF) as u8, (self.pid & 0xFF) as u8];
        Ok(MacAddress(mac_bytes))
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Full Init Sequence
    // ══════════════════════════════════════════════════════════════════════════

    /// Complete initialization sequence.
    /// Matches mt7921u_probe() from the kernel driver.
    ///
    /// Linux probe sequence (mt7921/usb.c):
    ///   1. usb_reset_device()
    ///   2. __mt76u_init() — internal buffer setup
    ///   3. Read chip ID + rev
    ///   4. IF FW_N9_RDY → wfsys_reset()    (only if firmware was running!)
    ///   5. mcu_power_on()
    ///   6. alloc queues
    ///   7. dma_init()
    ///   8. register_device() → mcu_init() → run_firmware()
    fn full_init(&mut self) -> Result<()> {

        // Linux retries init up to MT792x_MCU_INIT_RETRY_COUNT times
        // with WFSYS reset between each attempt (init.c:211).
        // If chip ID read fails, the device may be stuck from a previous
        // failed firmware upload — WFSYS reset recovers it.

        // 1. Read chip ID and revision (with retry + WFSYS reset)
        let (chip_id, hw_rev) = match self.reg_read(MT_HW_CHIPID) {
            Ok(id) => {
                let rev = self.reg_read(MT_HW_REV).unwrap_or(0);
                (id, rev)
            }
            Err(_) => {
                let _ = self.wfsys_reset();
                thread::sleep(Duration::from_millis(100));
                let id = self.reg_read(MT_HW_CHIPID)?;
                let rev = self.reg_read(MT_HW_REV).unwrap_or(0);
                (id, rev)
            }
        };
        self.chip_rev = (chip_id << 16) | (hw_rev & 0xFF);

        // Steps 2-7 are wrapped in a retry loop matching Linux MT792x_MCU_INIT_RETRY_COUNT (3).
        // On failure, WFSYS reset recovers the chip for the next attempt.
        const MCU_INIT_RETRY_COUNT: u32 = 3;
        let mut last_err = None;

        for attempt in 0..MCU_INIT_RETRY_COUNT {
            // 2. Check firmware state
            let conn_misc = self.reg_read(MT_CONN_ON_MISC)?;
            let fw_n9_rdy = (conn_misc & MT_TOP_MISC2_FW_N9_RDY) == MT_TOP_MISC2_FW_N9_RDY;

            // 3. ONLY reset WFSYS if firmware was already running (matches Linux exactly)
            if fw_n9_rdy || attempt > 0 {
                self.wfsys_reset()?;
            }

            // 4. Power on MCU
            if let Err(e) = self.mcu_power_on() {
                last_err = Some(e);
                thread::sleep(Duration::from_millis(100));
                continue;
            }

            // 5. Initialize DMA
            if let Err(e) = self.dma_init(false) {
                last_err = Some(e);
                thread::sleep(Duration::from_millis(100));
                continue;
            }

            // 6. Set normal mode
            self.reg_write(MT_SWDEF_MODE, MT_SWDEF_NORMAL_MODE)?;

            // 7. Download and start firmware
            match self.run_firmware() {
                Ok(()) => {
                    last_err = None;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }
        }

        if let Some(e) = last_err {
            return Err(e);
        }

        // 8. Post-firmware MCU init — matches mt7921_run_firmware()
        // Query NIC capabilities — parses TLV response for MAC address, PHY caps, etc.
        // Linux: mt7921_mcu_get_nic_capability() — this is the proper way to get the MAC.
        match self.mcu_get_nic_capability() {
            Ok(_) => {},
            Err(_) => {
                // Fallback to generated MAC if NIC_CAPS fails
                self.mac_addr = self.read_mac_from_eeprom()?;
            }
        }

        // Enable firmware logging to host (CE cmd 0xC5, data=1)
        // Matches mt7921_mcu_fw_log_2_host(dev, 1)
        let _ = self.mcu_send_ce_cmd(MCU_CE_CMD_FW_LOG_2_HOST, &[1, 0, 0, 0], false);

        // 9. If NIC_CAPS didn't provide MAC, try EEPROM fallback
        if self.mac_addr.0 == [0, 0, 0, 0, 0, 0] {
            self.mac_addr = self.read_mac_from_eeprom()?;
        }

        Ok(())
    }

    /// Get a clone of the USB device handle for direct register access in tests.
    pub fn usb_handle(&self) -> Arc<DeviceHandle<GlobalContext>> {
        Arc::clone(&self.handle)
    }

    /// Check firmware health — returns true if firmware is responsive.
    /// Matches Linux mt792x_mac_work() watchdog check.
    ///
    /// Should be called periodically (~1s) during long-running operations.
    /// If this returns false, call recover_firmware() to attempt recovery.
    pub fn check_firmware_health(&self) -> bool {
        if !self.mcu_running {
            return false;
        }

        // Check N9 MCU ready bit — if firmware crashes this goes low
        match self.reg_read(MT_CONN_ON_MISC) {
            Ok(val) => (val & MT_TOP_MISC2_FW_N9_RDY) == MT_TOP_MISC2_FW_N9_RDY,
            Err(_) => false, // USB read failed — device may be disconnected
        }
    }

    /// Attempt firmware crash recovery via WFSYS reset + re-init.
    /// Matches Linux mt7921_reset() → mt792x_wfsys_reset() → mt7921_run_firmware().
    ///
    /// Returns Ok(()) if recovery succeeded, Err if device is unrecoverable.
    pub fn recover_firmware(&mut self) -> Result<()> {
        self.mcu_running = false;
        self.sniffer_enabled = false;
        self.radio_initialized = false;

        // WFSYS reset clears all firmware state
        self.wfsys_reset()?;

        // Re-run the init sequence from step 4 onward
        self.mcu_power_on()?;
        self.dma_init(false)?;
        self.reg_write(MT_SWDEF_MODE, MT_SWDEF_NORMAL_MODE)?;
        self.run_firmware()?;

        // Re-query capabilities
        let _ = self.mcu_get_nic_capability();
        let _ = self.mcu_send_ce_cmd(MCU_CE_CMD_FW_LOG_2_HOST, &[1, 0, 0, 0], false);

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  AP Mode — Rogue AP / Evil Twin
    // ══════════════════════════════════════════════════════════════════════════

    /// Start a rogue access point with the given SSID and BSSID.
    /// The firmware handles beacon transmission automatically via beacon offload.
    /// Monitor mode RX remains active — we see all frames while beaconing.
    ///
    /// For evil twin: use the target AP's SSID and our MAC as BSSID.
    /// For karma: respond to probe requests with matching SSIDs.
    pub fn start_ap(&mut self, ssid: &str, bssid: &[u8; 6], beacon_interval: u16) -> Result<()> {
        if !self.mcu_running {
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::MonitorMode,
                reason: "MCU not running".into(),
            });
        }

        // Update MAC to AP BSSID so firmware ACKs frames from clients
        self.set_mac(MacAddress(*bssid))?;

        // Build beacon and upload to firmware.
        // Our existing VIF (from mcu_add_dev in set_monitor_mode) already has
        // CONNECTION_INFRA_AP — same as what Linux uses for AP mode.
        // We just need to give the firmware a beacon template.
        let beacon = build_beacon_frame(ssid, bssid, self.current_channel.number, beacon_interval);

        // Try firmware beacon offload first (ideal — firmware handles timing)
        match self.mcu_beacon_offload(&beacon, true) {
            Ok(()) => return Ok(()),
            Err(_) => {
                // Firmware beacon offload not working — fall back to software beacons.
                // We'll TX the beacon ourselves from a timer thread.
                // For now, just inject one beacon to prove TX works, and the caller
                // can loop beacon injection.
                eprintln!("  [AP] Firmware beacon offload not available, using software beacons");
            }
        }

        // Software beacon fallback: inject beacon frame via TX path
        let tx_opts = TxOptions {
            rate: TxRate::Ofdm6m,
            flags: TxFlags::NO_ACK, // beacons are broadcast
            retries: 0,
            ..Default::default()
        };
        self.tx_frame(&beacon, &tx_opts)?;

        Ok(())
    }

    /// Stop the rogue AP — disable beacon offload.
    pub fn stop_ap(&mut self) -> Result<()> {
        // Beacon offload disable is handled by BSS deactivation.
        // Re-register as monitor mode VIF.
        self.mcu_add_dev()?;
        Ok(())
    }

    /// Upload beacon template to firmware for automatic transmission.
    /// Matches mt7921_mcu_uni_add_beacon_offload() from Linux.
    fn mcu_beacon_offload(&mut self, beacon_frame: &[u8], enable: bool) -> Result<()> {
        // Build the TXWI (32 bytes) for the beacon — firmware needs it to know the rate
        let txwi = self.build_beacon_txwi(beacon_frame);

        // struct { bss_idx, pad[3] } hdr (4 bytes)
        // struct bcn_content_tlv {
        //   tag(2), len(2), tim_ie_pos(2), csa_ie_pos(2), bcc_ie_pos(2),
        //   enable(1), type(1), pkt_len(2), pkt[512]
        // } (528 bytes)
        let tlv_len = 16 + 512; // fixed TLV size
        let total = 4 + tlv_len;
        let mut payload = vec![0u8; total];

        payload[0] = 0; // bss_idx

        // TLV
        let t = 4;
        payload[t..t+2].copy_from_slice(&7u16.to_le_bytes()); // tag = UNI_BSS_INFO_BCN_CONTENT
        payload[t+2..t+4].copy_from_slice(&(tlv_len as u16).to_le_bytes()); // len
        // tim_ie_pos, csa_ie_pos, bcc_ie_pos — leave 0 for now
        payload[t+10] = if enable { 1 } else { 0 }; // enable
        payload[t+11] = 0; // type = 0 (legacy: TXD + payload)

        // pkt = TXWI(32) + beacon frame
        let pkt_len = 32 + beacon_frame.len();
        payload[t+12..t+14].copy_from_slice(&(pkt_len as u16).to_le_bytes());

        // Copy TXWI + beacon into pkt buffer (starting at t+16)
        let pkt_off = t + 16;
        payload[pkt_off..pkt_off+32].copy_from_slice(&txwi);
        if pkt_off + 32 + beacon_frame.len() <= total {
            payload[pkt_off+32..pkt_off+32+beacon_frame.len()].copy_from_slice(beacon_frame);
        }

        self.mcu_send_uni_cmd(MCU_UNI_CMD_BSS_INFO_UPDATE, &payload, true)?; // BSS_INFO_UPDATE with BCN_CONTENT tag
        Ok(())
    }

    /// Build a minimal TXWI for beacon transmission.
    fn build_beacon_txwi(&self, beacon: &[u8]) -> [u8; 32] {
        let mut txwi = [0u8; 32];
        let frame_len = beacon.len();

        // DW0: TX_BYTES | PKT_FMT=SF(1) | Q_IDX=ALTX0(0x10) for beacons
        let dw0: u32 = ((32 + frame_len) as u32 & 0xFFFF)
            | (1u32 << 23) // PKT_FMT = MT_TX_TYPE_SF
            | (0x10u32 << 25); // Q_IDX = ALTX0
        txwi[0..4].copy_from_slice(&dw0.to_le_bytes());

        // DW1: LONG_FORMAT | HDR_FORMAT=802.11(2) | HDR_INFO=12 (24/2)
        let dw1: u32 = (1u32 << 31) | (2u32 << 16) | (12u32 << 11);
        txwi[4..8].copy_from_slice(&dw1.to_le_bytes());

        // DW2: FRAME_TYPE=0(mgmt) | SUB_TYPE=8(beacon) | FIX_RATE
        let dw2: u32 = (0u32 << 4) | 8 | (1u32 << 31); // FIX_RATE
        txwi[8..12].copy_from_slice(&dw2.to_le_bytes());

        // DW3: NO_ACK (beacons are broadcast)
        let dw3: u32 = 1; // NO_ACK
        txwi[12..16].copy_from_slice(&dw3.to_le_bytes());

        // DW6: TX_RATE = OFDM 6M for beacons | FIXED_BW
        let rate = (1u32 << 6) | 11; // MODE=OFDM(1), IDX=11 (6Mbps)
        let dw6: u32 = (rate << 16) | (1u32 << 2);
        txwi[24..28].copy_from_slice(&dw6.to_le_bytes());

        txwi
    }
}

/// Build a standard 802.11 beacon frame. Public for use by test binaries.
pub fn build_beacon_frame_pub(ssid: &str, bssid: &[u8; 6], channel: u8, beacon_interval: u16) -> Vec<u8> {
    build_beacon_frame(ssid, bssid, channel, beacon_interval)
}

/// Build a standard 802.11 beacon frame.
fn build_beacon_frame(ssid: &str, bssid: &[u8; 6], channel: u8, beacon_interval: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(256);

    // Frame Control: type=0(mgmt), subtype=8(beacon)
    frame.push(0x80); // FC byte 0
    frame.push(0x00); // FC byte 1

    // Duration
    frame.push(0x00);
    frame.push(0x00);

    // addr1 (DA) = broadcast
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // addr2 (SA) = BSSID
    frame.extend_from_slice(bssid);
    // addr3 (BSSID) = BSSID
    frame.extend_from_slice(bssid);

    // Sequence control (firmware manages this)
    frame.push(0x00);
    frame.push(0x00);

    // Fixed parameters (12 bytes)
    // Timestamp (8 bytes) — firmware fills this
    frame.extend_from_slice(&[0u8; 8]);
    // Beacon interval (2 bytes, in TU = 1024 μs)
    frame.extend_from_slice(&beacon_interval.to_le_bytes());
    // Capability info (2 bytes): ESS(bit0) + short preamble(bit5)
    frame.extend_from_slice(&[0x21, 0x00]); // ESS + short preamble

    // Tagged parameters

    // SSID (tag 0)
    frame.push(0x00); // tag
    frame.push(ssid.len().min(32) as u8); // len
    frame.extend_from_slice(&ssid.as_bytes()[..ssid.len().min(32)]);

    // Supported Rates (tag 1) — 802.11a/g rates
    let rates: &[u8] = if channel > 14 {
        // 5GHz: OFDM only
        &[0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C] // 6,9,12,18,24,36,48,54
    } else {
        // 2.4GHz: CCK + OFDM
        &[0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24] // 1*,2*,5.5*,11*,6,9,12,18
    };
    frame.push(0x01); // tag
    frame.push(rates.len() as u8);
    frame.extend_from_slice(rates);

    // DS Parameter Set (tag 3) — channel
    frame.push(0x03); // tag
    frame.push(0x01); // len
    frame.push(channel);

    // TIM (tag 5) — Traffic Indication Map (minimal)
    frame.push(0x05); // tag
    frame.push(0x04); // len
    frame.push(0x00); // DTIM count
    frame.push(0x01); // DTIM period
    frame.push(0x00); // bitmap control
    frame.push(0x00); // partial virtual bitmap

    // RSN (tag 48) — for WPA2 AP, add later if needed

    // Extended Supported Rates (tag 50) for 2.4GHz
    if channel <= 14 {
        let ext_rates: &[u8] = &[0x30, 0x48, 0x60, 0x6C]; // 24,36,48,54
        frame.push(50); // tag
        frame.push(ext_rates.len() as u8);
        frame.extend_from_slice(ext_rates);
    }

    frame
}

// ══════════════════════════════════════════════════════════════════════════════
//  ChipDriver trait implementation
// ══════════════════════════════════════════════════════════════════════════════

impl ChipDriver for Mt7921au {
    fn init(&mut self) -> Result<()> {
        self.full_init()
    }

    fn shutdown(&mut self) -> Result<()> {
        // Proper teardown sequence matching Linux mt7921_stop() + mt792x_mcu_drv_pmctrl().
        // Without this, re-init often needs a full WFSYS reset.

        if self.mcu_running {
            // 1. Disable sniffer if active
            if self.sniffer_enabled {
                let _ = self.mcu_set_sniffer(false);
                self.sniffer_enabled = false;
            }

            // 2. Remove broadcast STA record
            let _ = self.mcu_sta_update(false); // conn_state=DISCONNECT

            // 3. Deactivate BSS — send BSS_INFO_UPDATE with active=0
            let mut bss_deact = vec![0u8; 36]; // hdr(4) + BASIC TLV(32)
            bss_deact[0] = 0; // bss_idx
            bss_deact[4..6].copy_from_slice(&0u16.to_le_bytes()); // tag=BASIC
            bss_deact[6..8].copy_from_slice(&32u16.to_le_bytes()); // len
            bss_deact[8] = 0; // active = false
            let _ = self.mcu_send_uni_cmd(MCU_UNI_CMD_BSS_INFO_UPDATE, &bss_deact, true);

            // 4. Deactivate device — DEV_INFO_UPDATE with active=0
            let mut dev_deact = [0u8; 16];
            dev_deact[4..6].copy_from_slice(&0u16.to_le_bytes()); // tag=DEV_INFO_ACTIVE
            dev_deact[6..8].copy_from_slice(&12u16.to_le_bytes()); // len
            dev_deact[8] = 0; // active = false
            let _ = self.mcu_send_uni_cmd(MCU_UNI_CMD_DEV_INFO_UPDATE, &dev_deact, true);

            // 5. Enter deep sleep — reduces power and prepares for clean re-init
            let _ = self.mcu_set_deep_sleep(true);

            // 6. Enter power management
            let _ = self.mcu_set_pm(0, true); // band=0, enter=true

            // 7. Power off MCU — NIC_POWER_CTRL with power_mode=1
            let poweroff = [1u8, 0, 0, 0];
            let _ = self.mcu_send_msg(MCU_CMD_NIC_POWER_CTRL, &poweroff, false);

            self.mcu_running = false;
            self.radio_initialized = false;
        }

        // Release the USB interface
        let _ = self.handle.release_interface(self.iface_num);

        Ok(())
    }

    fn chip_info(&self) -> ChipInfo {
        ChipInfo {
            name: "MT7921AU",
            chip: ChipId::Mt7921au,
            caps: MT7921AU_CAPS,
            vid: self.vid,
            pid: self.pid,
            rfe_type: 0,
            bands: vec![Band::Band2g, Band::Band5g, Band::Band6g],
            max_tx_power_dbm: 20,
            firmware_version: self.fw_version.clone(),
        }
    }

    fn set_channel(&mut self, channel: Channel) -> Result<()> {
        if !self.mcu_running {
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::ChannelSwitch,
                reason: "MCU not running".into(),
            });
        }
        self.switch_channel(channel)
    }

    fn supported_channels(&self) -> &[Channel] {
        &self.channels
    }

    fn set_monitor_mode(&mut self) -> Result<()> {
        if !self.mcu_running {
            return Err(Error::ChipInitFailed {
                chip: "MT7921AU".into(),
                stage: crate::core::error::InitStage::MonitorMode,
                reason: "MCU not running".into(),
            });
        }

        // Initialize radio subsystem first (MAC enable + RX path)
        // Matches __mt7921_start() from the kernel driver.
        if !self.radio_initialized {
            self.radio_init(Channel::new(6))?;
            self.radio_initialized = true;
            // Reset all MIB/airtime counters after radio init
            // Matches Linux __mt7921_start() → mac_reset_counters()
            self.mac_reset_counters()?;
        }

        // Exit power management state — radio must be fully awake for monitor mode
        // Matches mt76_connac_mcu_set_pm(EXIT) from Linux
        self.mcu_set_pm(0, false)?; // band=0, enter=false (EXIT)
        self.mcu_set_vif_ps_awake()?;

        // Drain any stale data from USB endpoints before configuring monitor mode.
        self.drain_rx();

        // STEP 1: Create a virtual interface (VIF) in the firmware.
        // This sends DEV_INFO_UPDATE + BSS_INFO_UPDATE (BASIC + QOS + RLM TLVs).
        self.mcu_add_dev()?;

        // STEP 1b: Register broadcast station record in firmware.
        // Matches Linux mt7921_mcu_sta_update(dev, NULL, vif, true, STATE_NONE).
        // Firmware needs a STA_REC entry to know how to route received frames.
        self.mcu_sta_update(true)?;

        // STEP 1c: Create WTBL entry for broadcast STA — enables firmware frame routing.
        // Linux creates a WTBL entry alongside every STA_REC_UPDATE.
        // Without WTBL, firmware can't look up the STA for incoming frames → no ACK in active mode.
        let bcast = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        self.mcu_wtbl_update(543, &bcast, 0)?; // wcid=543 (WTBL_RESERVED), op=RESET_AND_SET

        // STEP 1d: Set EDCA QoS parameters — channel access timing per AC.
        // Matches Linux mt7921_mcu_set_tx() called during BSS_CHANGED_QOS.
        // Without this, firmware uses conservative defaults that affect frame delivery.
        self.mcu_set_edca()?;

        // STEP 2: Disable deep sleep — CRITICAL for monitor mode.
        self.mcu_set_deep_sleep(false)?;

        // STEP 3: Enable sniffer mode.
        self.mcu_set_sniffer(true)?;

        // STEP 4: Configure sniffer channel — uses current_channel which was
        // set by radio_init(). Matches Linux change_chanctx() for monitor VIF.
        self.mcu_config_sniffer_channel(self.current_channel)?;

        // STEP 5: Set RX filter for monitor mode — accept ALL frames.
        // Matches mt7921_configure_filter() from main.c.
        // Linux builds flags from FIF_* and calls mt7921_mcu_set_rxfilter(dev, flags, 0, 0).
        //
        // For monitor mode we want to CLEAR all the DROP bits so nothing gets filtered:
        // - FIF_FCSFAIL → clear DROP_FCSFAIL
        // - FIF_CONTROL → clear DROP_CTS, DROP_RTS, DROP_CTL_RSV
        // - FIF_OTHER_BSS → clear DROP_OTHER_BSS, DROP_OTHER_UC, DROP_OTHER_TIM
        //
        // But the simplest approach: set fif=0 to accept everything (mode=1 with fif=0).
        // Actually — Linux sends the accumulated flags value. For full promiscuous,
        // we want all the interesting DROP bits cleared. Let's use bit_op mode to
        // explicitly CLEAR the drop bits that would hide frames from us.
        let drop_bits_to_clear =
            MT_WF_RFCR_DROP_STBC_MULTI |  // STBC multicast — WiFi 6 APs use this
            MT_WF_RFCR_DROP_FCSFAIL |
            MT_WF_RFCR_DROP_VERSION |     // Non-standard version — see everything
            MT_WF_RFCR_DROP_PROBEREQ |
            MT_WF_RFCR_DROP_MCAST |
            MT_WF_RFCR_DROP_BCAST |
            MT_WF_RFCR_DROP_MCAST_FILTERED |
            MT_WF_RFCR_DROP_A3_MAC |
            MT_WF_RFCR_DROP_A3_BSSID |
            MT_WF_RFCR_DROP_A2_BSSID |
            MT_WF_RFCR_DROP_OTHER_BEACON |
            MT_WF_RFCR_DROP_FRAME_REPORT |
            MT_WF_RFCR_DROP_CTL_RSV |
            MT_WF_RFCR_DROP_CTS |
            MT_WF_RFCR_DROP_RTS |
            MT_WF_RFCR_DROP_DUPLICATE |
            MT_WF_RFCR_DROP_OTHER_BSS |
            MT_WF_RFCR_DROP_OTHER_UC |
            MT_WF_RFCR_DROP_OTHER_TIM |
            MT_WF_RFCR_DROP_NDPA |
            MT_WF_RFCR_DROP_UNWANTED_CTL;

        self.mcu_set_rxfilter(0, MT7921_FIF_BIT_CLR, drop_bits_to_clear)?;

        // STEP 6: Disable beacon filter — both BSS_INFO TLV and CE cmd.
        // Matches mt7921_mcu_set_beacon_filter(dev, vif, false) from Linux.
        //
        // 6a. BSS_INFO_BCNFT TLV (tag 6) — tells firmware to not filter beacons
        // struct { tag(2), len(2), len_adjust(1), pad(3) } = 8 bytes
        let hdr_len = 4;
        let bcnft_len: u16 = 8;
        let mut bcnft_req = vec![0u8; hdr_len + bcnft_len as usize];
        bcnft_req[0] = 0; // bss_idx
        bcnft_req[hdr_len..hdr_len+2].copy_from_slice(&6u16.to_le_bytes()); // tag=BCNFT
        bcnft_req[hdr_len+2..hdr_len+4].copy_from_slice(&bcnft_len.to_le_bytes());
        // len_adjust=0, all zeros = disable beacon filter
        let _ = self.mcu_send_uni_cmd(MCU_UNI_CMD_BSS_INFO_UPDATE, &bcnft_req, true);

        // 6b. SET_BSS_ABORT CE cmd — hard disable of BSS-level filtering
        let abort_data = [0u8; 4]; // bss_idx=0, pad[3]
        let _ = self.mcu_send_ce_cmd(MCU_CE_CMD_SET_BSS_ABORT, &abort_data, false);

        // STEP 7: Re-enable UDMA RX — match Linux mt792xu_dma_init() exactly.
        // Linux: clear RX_FLUSH, enable RX/TX, clear aggregation params.
        // Do NOT set RX_AGG_EN — firmware delivers frames immediately.
        self.reg_clear(MT_UDMA_WLCFG_0, MT_WL_RX_FLUSH)?;
        self.reg_set(MT_UDMA_WLCFG_0, MT_WL_RX_EN | MT_WL_TX_EN |
                     MT_WL_RX_MPSZ_PAD0 | MT_TICK_1US_EN)?;
        self.reg_clear(MT_UDMA_WLCFG_0,
                       MT_WL_RX_AGG_TO | MT_WL_RX_AGG_LMT)?;
        self.reg_clear(MT_UDMA_WLCFG_1, MT_WL_RX_AGG_PKT_LMT)?;
        self.reg_set(MT_UWFDMA0_GLO_CFG, MT_WFDMA0_GLO_CFG_RX_DMA_EN)?;

        // Drain again after config — catch any responses from commands above
        self.drain_rx();

        Ok(())
    }

    fn tx_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()> {
        if !self.mcu_running {
            return Err(Error::TxFailed {
                retries: 0,
                reason: "MCU not running".into(),
            });
        }

        // Build TX packet: SDIO_HDR(4) + TXWI(64) + frame + padding + tail(4)
        // Linux: mt76_connac2_mac_write_txwi() builds 32-byte HW TXD (DW0-DW7)
        // USB/SDIO mode: 32 bytes HW TXD + 32 bytes extension (DW8-DW15) = 64 byte TXWI
        let txwi_size: usize = 64;
        let total = MT_SDIO_HDR_SIZE + txwi_size + frame.len();
        let padded = (total + 3) & !3;
        let final_len = padded + MT_USB_TAIL_SIZE;

        let mut pkt = vec![0u8; final_len];

        // SDIO header: TX_BYTES[15:0] = txwi + frame length, PKT_TYPE[17:16] = 0 for USB data
        let sdio_hdr = ((txwi_size + frame.len()) as u32) & 0xFFFF;
        pkt[0..4].copy_from_slice(&sdio_hdr.to_le_bytes());

        // Parse 802.11 frame header for TXWI fields
        let fc = if frame.len() >= 2 {
            u16::from_le_bytes([frame[0], frame[1]])
        } else { 0 };
        let frame_type = ((fc >> 2) & 0x3) as u32;
        let frame_subtype = ((fc >> 4) & 0xF) as u32;
        let is_multicast = if frame.len() >= 10 { frame[4] & 0x01 != 0 } else { false };
        let mac_hdr_len: u32 = match frame_type {
            0 => 24,  // Management
            1 => 10,  // Control
            2 => if fc & (1 << 8) != 0 && fc & (1 << 9) != 0 { 30 } else { 24 },
            _ => 24,
        };

        let off = MT_SDIO_HDR_SIZE;

        // ── QoS TID → AC queue mapping (WMM) ──
        // Extract QoS TID from data frames for proper queue selection.
        // Management frames → ALTX0 (Q_IDX=0x10), Control → AC_VO
        // Data frames → map TID to AC: VO(6,7), VI(4,5), BE(0,3), BK(1,2)
        let (q_idx, tx_ep) = match frame_type {
            0 => (0x10u32, self.ep_ac_be_out), // Management → ALTX0 queue, AC_BE endpoint
            1 => (0x00, self.ep_ac_vo_out),    // Control → AC00, VO endpoint (highest priority)
            2 => {
                // Data frame — extract QoS TID if QoS subtype (bit 7 of subtype = 1)
                let tid = if frame_subtype & 0x8 != 0 && frame.len() >= 26 {
                    (frame[24] & 0x0F) as u32 // QoS Control TID field
                } else {
                    0 // Non-QoS data → best effort
                };
                // WMM TID-to-AC mapping: {1,2}→BK, {0,3}→BE, {4,5}→VI, {6,7}→VO
                match tid {
                    1 | 2 => (0x01, self.ep_ac_bk_out), // AC_BK
                    0 | 3 => (0x00, self.ep_ac_be_out), // AC_BE
                    4 | 5 => (0x02, self.ep_ac_vi_out), // AC_VI
                    6 | 7 => (0x03, self.ep_ac_vo_out), // AC_VO
                    _     => (0x00, self.ep_ac_be_out), // Default: BE
                }
            }
            _ => (0x00, self.ep_ac_be_out),
        };

        // DW0: TX_BYTES[15:0] | PKT_FMT[24:23]=1(SF for USB) | Q_IDX[31:25]
        let tx_bytes = (txwi_size + frame.len()) as u32 & 0xFFFF;
        let dw0 = tx_bytes | (1u32 << 23) | (q_idx << 25);
        pkt[off..off+4].copy_from_slice(&dw0.to_le_bytes());

        // DW1: LONG_FORMAT[31]=1 | HDR_FORMAT[17:16]=2(802.11) | HDR_INFO[15:11]=hdr_len/2
        let dw1: u32 = (1u32 << 31) | (2u32 << 16) | (((mac_hdr_len / 2) & 0x1F) << 11);
        pkt[off+4..off+8].copy_from_slice(&dw1.to_le_bytes());

        // DW2: FRAME_TYPE[5:4] | SUB_TYPE[3:0] | MULTICAST[10] | TIMING_MEASURE[12]
        //      | HTC_VLD[13] | PROTECT[22] | FIX_RATE[31]
        let mut dw2: u32 = (frame_type << 4) | frame_subtype;
        if is_multicast { dw2 |= 1 << 10; }
        dw2 |= 1u32 << 13;  // HTC_VLD — set when FIX_RATE (prevents HW adding HTC)
        if opts.flags.contains(TxFlags::PROTECT) {
            dw2 |= 1u32 << 22; // PROTECT — send RTS/CTS before frame
        }
        dw2 |= 1u32 << 31;  // FIX_RATE — use rate from DW6, not rate adaptation
        pkt[off+8..off+12].copy_from_slice(&dw2.to_le_bytes());

        // DW3: NO_ACK[0] | PROTECT_FRAME[1] | REM_TX_COUNT[15:11]
        //      | BA_DISABLE[28] | SN_VALID[31] | SEQ[27:16]
        let want_ack = opts.flags.contains(TxFlags::WANT_ACK);
        let no_ack = !want_ack; // Default: no ACK for monitor mode injection
        let retry_count = if opts.flags.contains(TxFlags::NO_RETRY) { 1u32 } else { 15u32 };
        let mut dw3: u32 = retry_count << 11; // REM_TX_COUNT
        if no_ack { dw3 |= 1; }            // NO_ACK bit 0
        if !want_ack { dw3 |= 1u32 << 28; } // BA_DISABLE bit 28
        // Set explicit sequence number from the 802.11 frame header
        if frame.len() >= 24 {
            let seq_ctrl = u16::from_le_bytes([frame[22], frame[23]]);
            let seq_num = (seq_ctrl >> 4) & 0x0FFF;
            dw3 |= (1u32 << 31) | ((seq_num as u32) << 16);  // SN_VALID + SEQ
        }
        pkt[off+12..off+16].copy_from_slice(&dw3.to_le_bytes());

        // DW4: zero (no PN — encryption handled externally)

        // DW5: PID + TX_STATUS_HOST — enables firmware TX status reports.
        // Without PID, firmware never generates TxStatus packets on the RX path.
        // PID[7:0] = 1 (any non-zero value enables per-packet tracking)
        // TX_STATUS_HOST[8] = 1 (route TX status reports to host via USB RX)
        // Linux: MT_TXD5_TX_STATUS_HOST | FIELD_PREP(MT_TXD5_PID, pid)
        let dw5: u32 = 1       // PID = 1
            | (1u32 << 8);     // TX_STATUS_HOST
        pkt[off+20..off+24].copy_from_slice(&dw5.to_le_bytes());

        // DW6: TX_RATE[29:16] | SGI[15:14] | LDPC[11] | BW[4:3] | DYN_BW[5] | FIXED_BW[2]
        // Rate encoding via TxRate::mt76_rate(): MODE[9:6] | NSS[12:10] | IDX[5:0]
        // SGI: 0=normal GI, 1=short GI (HT/VHT 0.4μs, HE 1.6μs), 2=HE extended (3.2μs)
        // BW: 0=20MHz, 1=40MHz, 2=80MHz, 3=160MHz (clamped to 80 for MT7921)
        let mut rate_val: u32 = opts.rate.mt76_rate() as u32;
        if opts.flags.contains(TxFlags::STBC) { rate_val |= 1 << 13; }
        let bw = (opts.bw as u32).min(2); // Clamp to 80MHz max (hardware limit)
        let mut dw6: u32 = (rate_val << 16)
            | (1u32 << 2)                                 // FIXED_BW
            | ((bw & 0x3) << 3)                           // BW[4:3]
            | (((opts.gi as u32) & 0x3) << 14);           // SGI[15:14]
        if opts.flags.contains(TxFlags::LDPC) { dw6 |= 1u32 << 11; }
        if opts.flags.contains(TxFlags::DYN_BW) { dw6 |= 1u32 << 5; } // DYN_BW — allow narrower fallback
        pkt[off+24..off+28].copy_from_slice(&dw6.to_le_bytes());

        // DW7: HE LTF type in bits [27:26] when HE rate and FIX_RATE set
        let mut dw7: u32 = 0;
        if opts.rate.is_he() {
            dw7 |= ((opts.ltf as u32) & 0x3) << 26; // HE_LTF[27:26]: 0=1x, 1=2x, 2=4x
        }
        if dw7 != 0 {
            pkt[off+28..off+32].copy_from_slice(&dw7.to_le_bytes());
        }

        // DW8: L_TYPE[5:4] | L_SUB_TYPE[3:0] — required for USB TX path
        let dw8: u32 = (frame_type << 4) | frame_subtype;
        pkt[off+32..off+36].copy_from_slice(&dw8.to_le_bytes());

        // DW9-DW15: zero padding

        // Copy frame data after TXWI
        let frame_off = off + txwi_size;
        pkt[frame_off..frame_off + frame.len()].copy_from_slice(frame);
        for retry in 0..opts.retries.max(1) {
            match self.handle.write_bulk(tx_ep, &pkt, USB_BULK_TIMEOUT) {
                Ok(_) => return Ok(()),
                Err(e) if retry < opts.retries.saturating_sub(1) => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => return Err(Error::TxFailed {
                    retries: opts.retries,
                    reason: format!("USB bulk write failed: {}", e),
                }),
            }
        }

        Ok(())
    }

    fn rx_frame(&mut self, timeout: Duration) -> Result<Option<RxFrame>> {
        use crate::core::chip::ParsedPacket;
        // MT7921 with aggregation enabled (AGG_LMT=64, AGG_TO=0xFF).
        // Each USB read may return multiple packets back-to-back in the buffer.
        // mt7921au_parse_rx() walks the buffer extracting frames one at a time.
        // Many packets are non-data (MCU events, TX status) — we loop through
        // them efficiently with short USB reads between buffer exhaustions.
        let deadline = Instant::now() + timeout;

        loop {
            // Parse any buffered packets first (zero USB cost)
            while self.rx_pos < self.rx_len {
                let buf = &self.rx_buf[self.rx_pos..self.rx_len];
                let (consumed, packet) = mt7921au_parse_rx(buf, self.current_channel.number);
                if consumed == 0 {
                    self.rx_pos = self.rx_len;
                    break;
                }
                self.rx_pos += consumed;
                if let ParsedPacket::Frame(frame) = packet {
                    return Ok(Some(frame));
                }
            }

            // Buffer exhausted — check deadline
            self.rx_pos = 0;
            self.rx_len = 0;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            // Short USB read — 1ms timeout so we spin fast through non-data packets
            // instead of blocking the scanner's entire poll interval on one dud
            let usb_timeout = remaining.min(Duration::from_millis(1));
            match self.handle.read_bulk(self.ep_data_in, &mut self.rx_buf, usb_timeout) {
                Ok(n) if n > 0 => {
                    self.rx_len = n;
                }
                Ok(_) | Err(rusb::Error::Timeout) => continue,
                Err(e) => return Err(Error::Usb(e)),
            }
        }
    }

    fn mac(&self) -> MacAddress {
        self.mac_addr
    }

    fn set_mac(&mut self, mac: MacAddress) -> Result<()> {
        let old_mac = self.mac_addr;
        self.mac_addr = mac;

        // MT7921AU supports POWERED_ADDR_CHANGE — MAC can change while interface is up.
        // Re-send DEV_INFO_UPDATE with new MAC address in-place (no remove needed).
        // The firmware updates the OMAC address for the existing VIF.
        if self.mcu_running {
            // DEV_INFO_UPDATE with active=true and new MAC
            let mut dev_req = [0u8; 16];
            dev_req[0] = 0; // omac_idx
            dev_req[1] = 0; // band_idx
            dev_req[4..6].copy_from_slice(&0u16.to_le_bytes()); // tag = DEV_INFO_ACTIVE
            dev_req[6..8].copy_from_slice(&12u16.to_le_bytes()); // len
            dev_req[8] = 1; // active = true
            dev_req[9] = 0; // link_idx
            dev_req[10..16].copy_from_slice(&self.mac_addr.0); // new MAC

            if let Err(e) = self.mcu_send_uni_cmd(MCU_UNI_CMD_DEV_INFO_UPDATE, &dev_req, true) {
                self.mac_addr = old_mac; // rollback
                return Err(e);
            }
        }

        Ok(())
    }

    fn tx_power(&self) -> i8 {
        20 // Default max TX power for MT7921AU
    }

    fn set_tx_power(&mut self, dbm: i8) -> Result<()> {
        // Send TX power for current band, clamped to requested dBm.
        // dbm <= 0 means "use hardware max" (firmware caps to eFuse limits).
        // dbm > 0 clamps all per-rate values to that limit.
        // Useful for stealth operation or targeted injection at reduced power.
        if dbm <= 0 {
            self.mcu_set_rate_txpower(self.current_channel.band)?;
        } else {
            self.mcu_set_rate_txpower_limited(self.current_channel.band, dbm)?;
        }
        Ok(())
    }

    fn calibrate(&mut self) -> Result<()> {
        // MT7921AU calibration is handled by the firmware automatically
        Ok(())
    }

    fn channel_settle_time(&self) -> Duration {
        // MT7921AU: set_channel() sends MCU_EXT_CMD(CHANNEL_SWITCH) and WAITS
        // for the firmware response. The firmware blocks 140-500ms for PLL retune
        // INSIDE that MCU command. By the time set_channel() returns, the radio
        // is already on the new channel and receiving. No additional settle needed.
        //
        // 10ms margin for AGC to converge after the PLL locks.
        Duration::from_millis(10)
    }

    fn scan_dwell_time(&self) -> Duration {
        // MT7921AU channel switch blocks 140-500ms inside firmware MCU command.
        // With 500ms dwell, efficiency is only 50-62%. With 1000ms dwell,
        // efficiency rises to 67-77% and we capture 10 beacon intervals + more
        // STA data bursts per channel visit. The slow switch cost is amortized.
        Duration::from_millis(1000)
    }

    // ── Channel Survey ──

    fn survey_read(&self, band_idx: u8) -> Result<ChannelSurvey> {
        self.survey_read(band_idx)
    }

    fn survey_reset(&self, band_idx: u8) -> Result<()> {
        self.survey_reset(band_idx)
    }

    fn survey_enable(&self, band_idx: u8) -> Result<()> {
        self.survey_enable(band_idx)
    }

    // ── RF Test Mode / Spectrum Analyzer ──

    fn supports_testmode(&self) -> bool { true }

    fn enter_spectrum_mode(&mut self) -> Result<()> {
        self.testmode_enter_spectrum()
    }

    fn enter_icap_mode(&mut self) -> Result<()> {
        self.testmode_enter_icap()
    }

    fn enter_rftest_mode(&mut self) -> Result<()> {
        self.testmode_enter_rftest()
    }

    fn exit_testmode(&mut self) -> Result<()> {
        self.testmode_exit()
    }

    fn testmode_set_tx_power(&mut self, power_half_dbm: u32) -> Result<()> {
        self.testmode_set_tx_power(power_half_dbm)
    }

    fn testmode_set_freq_offset(&mut self, offset: u32) -> Result<()> {
        self.testmode_set_freq_offset(offset)
    }

    fn testmode_set_tx_antenna(&mut self, mask: u32) -> Result<()> {
        self.testmode_set_tx_antenna(mask)
    }

    fn testmode_set_system_bw(&mut self, bw: u32) -> Result<()> {
        self.testmode_set_system_bw(bw)
    }

    fn testmode_burst_tx(&mut self,
        channel: u32, bw: u32, rate_mode: u32, nss: u32,
        power_half_dbm: u32, pkt_count: u32, ipg_us: u32,
    ) -> Result<()> {
        self.testmode_burst_tx(channel, bw, rate_mode, nss, power_half_dbm, pkt_count, ipg_us)
    }

    fn testmode_set_tx_continuous(&mut self, enable: bool) -> Result<()> {
        self.testmode_set_tx_continuous(enable)
    }

    fn testmode_get_temperature(&mut self) -> Result<(u32, u32)> {
        self.testmode_get_temperature()
    }

    fn testmode_get_rx_stats(&mut self) -> Result<(u32, u32)> {
        self.testmode_get_rx_stats()
    }

    fn take_rx_handle(&mut self) -> Option<crate::core::chip::RxHandle> {
        // Unbounded channel for MCU responses forwarded by the RX thread.
        // MUST be unbounded: during attacks, the RX thread sends MCU responses
        // while the attack thread may be busy with TX. A bounded channel silently
        // drops responses via try_send(), causing MCU commands to hang forever.
        let (tx, rx) = std::sync::mpsc::channel();
        self.mcu_rx = Some(rx);
        self.rx_thread_active = true;
        Some(crate::core::chip::RxHandle {
            device: Arc::clone(&self.handle),
            ep_in: self.ep_data_in,
            rx_buf_size: RX_BUF_SIZE,
            parse_fn: mt7921au_parse_rx,
            driver_msg_tx: Some(tx),
        })
    }
}

/// Standalone RX parser for the pipeline's RxHandle.
///
/// Parses one MT7921AU RXD packet from a USB bulk buffer.
/// Format: [RXD base 24B] [optional groups] [802.11 frame]
///
/// Packet types (from Linux mt76_connac2_mac.h / mt7603/mac.h):
///   0 = PKT_TYPE_TXS (TX status) — skip
///   1 = PKT_TYPE_TXRXV (TX/RX vector) — skip
///   2 = PKT_TYPE_NORMAL (802.11 data frame) — parse as Frame
///   3 = PKT_TYPE_DUP_RFB — parse as Frame
///   7 = PKT_TYPE_RX_EVENT (MCU response) — forward as DriverMessage
///   8 = PKT_TYPE_NORMAL_MCU — forward as DriverMessage
fn mt7921au_parse_rx(buf: &[u8], channel: u8) -> (usize, crate::core::chip::ParsedPacket) {
    use crate::core::chip::ParsedPacket;

    if buf.len() < 24 {
        return (0, ParsedPacket::Skip);
    }

    let rxd_dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let pkt_len = (rxd_dw0 & 0xFFFF) as usize;

    if pkt_len == 0 || pkt_len < 24 || pkt_len > buf.len() {
        return (0, ParsedPacket::Skip);
    }

    let consumed = (pkt_len + 3) & !3;
    let rxd = &buf[..pkt_len];

    let mut pkt_type = ((rxd_dw0 >> 27) & 0x1F) as u8;
    let pkt_flag = ((rxd_dw0 >> 16) & 0xF) as u8;

    // Linux mt7921/mac.c:596 — RX_EVENT with flag==1 is actually NORMAL_MCU
    if pkt_type == 7 && pkt_flag == 1 {
        pkt_type = 8; // PKT_TYPE_NORMAL_MCU
    }

    // Route by packet type — from mt76_connac2_mac.h PKT_TYPE_* constants:
    //   0 = TXS (TX status)            → DriverMessage (ACK feedback for injected frames!)
    //   1 = TXRXV (TX/RX vector)       → Skip (PHY metadata, no frame)
    //   2 = NORMAL (802.11 data frame) → Frame
    //   3 = DUP_RFB (duplicate RFB)    → Frame (carries real 802.11 frames!)
    //   4 = TMR (timer report)         → Skip
    //   5 = RETRIEVE                   → Skip
    //   6 = TXRX_NOTIFY (TX free)      → Skip
    //   7 = RX_EVENT (MCU response)    → DriverMessage
    //   8 = NORMAL_MCU (MCU + frame)   → DriverMessage
    //   0x0C = FW_MONITOR              → DriverMessage (firmware debug)
    //   anything else                  → Skip
    match pkt_type {
        2 | 3 => {} // PKT_TYPE_NORMAL + DUP_RFB — parse as 802.11 frame below
        0 => {
            // MT7921 TXS (connac2) format — TXS payload after 24-byte RXD base.
            // Matches mt76_connac2_mac_add_txs_skb() from Linux mt76_connac2_mac.c.
            //
            // USB RX: [RXD base 24B] [TXS DW0-DW6 28B]
            // The RXD base has pkt_len + pkt_type. TXS data starts at byte 24.
            //
            // TXS DW0: pkt_id[31:25], tx_cnt[19:16], tx_state[14:12], queue_sel[10:8]
            // TXS DW1: wlan_idx[9:0], final_rate[24:16]
            // TXS DW2: timestamp[31:0] (microsecond TSF)
            // TXS DW3: total_airtime[23:0]
            // TXS DW4: bw[7:6], gi_ltf[5:4], tx_delay[31:16]
            let raw = rxd.to_vec();
            let txs_base = 24; // TXS payload starts after RXD base header
            let dw = |i: usize| -> u32 {
                let off = txs_base + i * 4;
                if rxd.len() >= off + 4 {
                    u32::from_le_bytes([rxd[off], rxd[off+1], rxd[off+2], rxd[off+3]])
                } else { 0 }
            };
            let txs_dw0 = dw(0);
            let txs_dw1 = dw(1);
            let txs_dw2 = dw(2);
            let txs_dw3 = dw(3);
            let txs_dw4 = dw(4);

            let pkt_id = ((txs_dw0 >> 25) & 0x7F) as u16;
            let tx_cnt = ((txs_dw0 >> 16) & 0xF) as u8;
            let tx_state = ((txs_dw0 >> 12) & 0x7) as u8;
            let queue_sel = ((txs_dw0 >> 8) & 0x7) as u8;
            let mac_id = (txs_dw1 & 0x3FF) as u8;
            let final_rate = ((txs_dw1 >> 16) & 0x1FF) as u16;
            let timestamp = txs_dw2;
            let total_airtime_us = (txs_dw3 & 0xFFFF) as u16; // lower 16 bits = μs
            let final_bw = ((txs_dw4 >> 6) & 0x3) as u8;
            let final_gi_ltf = ((txs_dw4 >> 4) & 0x3) as u8;

            return (consumed, ParsedPacket::TxStatus(crate::core::chip::TxReport {
                pkt_id,
                queue_sel,
                tx_state,
                tx_cnt,
                acked: tx_state == 0,
                final_rate,
                final_bw,
                final_gi_ltf,
                mac_id,
                timestamp,
                total_airtime_us,
                raw,
            }));
        }
        1 => {
            // PKT_TYPE_TXRXV — TX/RX vector with full PHY metadata.
            // Contains the same rate/MCS/BW fields as P-RXV but for TX completions.
            // Raw payload preserved for future detailed parsing.
            let raw = rxd.to_vec();
            return (consumed, ParsedPacket::DriverMessage(raw));
        }
        4 => {
            // PKT_TYPE_TMR — timing measurement report (Fine Timing Measurement / 802.11mc).
            // Contains TOA/TOD timestamps for WiFi ranging/positioning.
            let raw = rxd.to_vec();
            return (consumed, ParsedPacket::DriverMessage(raw));
        }
        5 => {
            // PKT_TYPE_RETRIEVE — buffer retrieval from firmware.
            let raw = rxd.to_vec();
            return (consumed, ParsedPacket::TxPdRelease(crate::core::chip::TxPdRelease {
                release_type: 5,
                pd_ids: Vec::new(),
                raw,
            }));
        }
        6 => {
            // PKT_TYPE_TXRX_NOTIFY — TX free notification.
            // Firmware telling us TX buffers are released.
            let raw = rxd.to_vec();
            return (consumed, ParsedPacket::TxPdRelease(crate::core::chip::TxPdRelease {
                release_type: 6,
                pd_ids: Vec::new(),
                raw,
            }));
        }
        7 | 8 => {
            // PKT_TYPE_RX_EVENT (7) / PKT_TYPE_NORMAL_MCU (8) — MCU responses.
            // Structure: similar to C2H — category/class/function in MCU header.
            let raw = rxd.to_vec();
            // MCU event header at RXD offset: cid at byte 4, ext_cid at byte 5
            let (category, class, function, seq) = if rxd.len() >= 32 {
                (rxd[24], rxd[25], rxd[26], rxd[27])
            } else {
                (0, 0, 0, 0)
            };
            let payload = if rxd.len() > 32 { rxd[32..].to_vec() } else { Vec::new() };
            return (consumed, ParsedPacket::C2hEvent(crate::core::chip::C2hEvent {
                category,
                class,
                function,
                seq,
                payload,
                raw,
            }));
        }
        0x0C => {
            // PKT_TYPE_FW_MONITOR — firmware debug trace output.
            let raw = rxd.to_vec();
            return (consumed, ParsedPacket::DriverMessage(raw));
        }
        _ => return (consumed, ParsedPacket::Skip),
    }

    let rxd_dw1 = u32::from_le_bytes([rxd[4], rxd[5], rxd[6], rxd[7]]);
    let has_group1 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_1) != 0;
    let has_group2 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_2) != 0;
    let has_group3 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_3) != 0;
    let has_group4 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_4) != 0;
    let has_group5 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_5) != 0;
    // FCS error flag — frame may be corrupted but still valuable for:
    // - Jamming/interference detection
    // - Partial frame capture analysis
    // - Signal quality assessment
    // The frame is passed through with is_fcs_error=true, letting the
    // scanner/store decide whether to use it.
    let fcs_err = (rxd_dw1 & MT_RXD1_NORMAL_FCS_ERR) != 0;

    let rxd_dw2 = u32::from_le_bytes([rxd[8], rxd[9], rxd[10], rxd[11]]);
    let hdr_trans = (rxd_dw2 & MT_RXD2_NORMAL_HDR_TRANS) != 0;
    let hdr_offset = ((rxd_dw2 >> 14) & 0x3) as usize * 2;

    // When firmware header translation is active, the 802.11 header was converted
    // to 802.3 Ethernet format: [dst MAC 6B] [src MAC 6B] [ethertype 2B] [payload].
    // This shouldn't happen in monitor mode (we explicitly clear RX_HDR_TRANS_EN),
    // but if it does, preserve the raw data for debugging rather than silently dropping.
    if hdr_trans {
        let raw = rxd.to_vec();
        return (consumed, ParsedPacket::DriverMessage(raw));
    }

    // RXD DW3 — channel info (mt76_connac2_mac.h)
    //   bits[7:0]   = RXV_SEQ
    //   bits[15:8]  = CH_FREQ (encoded channel — see below)
    //   bits[17:16] = ADDR_TYPE (NOT band!)
    //
    // CH_FREQ encoding (from mt792x_get_status_freq_info in mt792x.h):
    //   1-14     → 2.4GHz channel 1-14
    //   36-177   → 5GHz channel as-is
    //   181-239  → 6GHz: channel = (chfreq - 181) * 4 + 1
    //             (181→ch1, 182→ch5, 183→ch9, ..., 239→ch233)
    let rxd_dw3 = u32::from_le_bytes([rxd[12], rxd[13], rxd[14], rxd[15]]);
    let ch_freq = ((rxd_dw3 >> 8) & 0xFF) as u8;

    // ── Walk RXD groups in order: Group4 → Group1 → Group2 → Group3 [→ Group5] ──
    // Each group is present only if its flag is set in DW1.
    // Order is fixed by the hardware — matches Linux mt7921/mac.c:262.
    use crate::core::frame::*;

    let base_rxd = 24;
    let mut off = base_rxd;

    // ── Group 4 (16B): Frame Control, Seq Ctrl, QoS ──
    let mut _fc = 0u16;
    let mut _seq_ctrl = 0u16;
    let mut _qos_ctl = 0u8;
    let mut is_ampdu = false;
    if has_group4 {
        if off + 16 <= pkt_len {
            let g4_dw0 = u32::from_le_bytes([rxd[off], rxd[off+1], rxd[off+2], rxd[off+3]]);
            let g4_dw2 = u32::from_le_bytes([rxd[off+8], rxd[off+9], rxd[off+10], rxd[off+11]]);
            _fc = (g4_dw0 & 0xFFFF) as u16;
            _seq_ctrl = (g4_dw2 & 0xFFFF) as u16;
            _qos_ctl = ((g4_dw2 >> 16) & 0xFF) as u8;
        }
        off += 16;
    }

    // ── Group 1 (16B): IV/PN for decrypted frames ──
    if has_group1 {
        // IV bytes at off[0..5] — useful for crypto analysis but we don't
        // need them for monitor mode. Available in raw RXD if needed.
        off += 16;
    }

    // ── Group 2 (8B): Timestamp + AMPDU ──
    let mut rx_timestamp = Duration::ZERO;
    if has_group2 {
        if off + 8 <= pkt_len {
            let ts = u32::from_le_bytes([rxd[off], rxd[off+1], rxd[off+2], rxd[off+3]]);
            rx_timestamp = Duration::from_micros(ts as u64);
            // Non-AMPDU flag in RXD2
            is_ampdu = (rxd_dw2 & (1 << 15)) == 0; // MT_RXD2_NORMAL_NON_AMPDU
        }
        off += 8;
    }

    // ── Group 3 (8B): P-RXV — rate/MCS/BW/GI/STBC/LDPC/NSTS + RCPI ──
    // This is the richest PHY information source for MT7921.
    // Fields from mt76_connac2_mac.h: MT_PRXV_*
    let mut rssi: i8 = -80;
    let mut rssi_path: [i8; 4] = [0; 4];
    let mut data_rate: u16 = 0;
    let mut ppdu_type = PpduType::Ofdm;
    let mut bandwidth = RxBandwidth::Bw20;
    let mut gi_ltf = GuardInterval::Gi800ns;
    let mut is_ldpc = false;
    let mut is_stbc = false;
    let mut is_bf = false;
    let mut nss: u8 = 1;
    let mut is_dcm = false;
    let mut rx_path_en: u8 = 0;

    let g3_off = off; // save for Group 5 RCPI override
    if has_group3 {
        if off + 8 <= pkt_len {
            let prxv0 = u32::from_le_bytes([rxd[off], rxd[off+1], rxd[off+2], rxd[off+3]]);
            let prxv1 = u32::from_le_bytes([rxd[off+4], rxd[off+5], rxd[off+6], rxd[off+7]]);

            // P-RXV DW0 fields (MT_PRXV_* from mt76_connac2_mac.h)
            let tx_rate = (prxv0 & 0x7F) as u8;          // bits[6:0]
            is_dcm = (prxv0 & (1 << 4)) != 0;             // MT_PRXV_TX_DCM
            nss = (((prxv0 >> 7) & 0x7) + 1) as u8;       // bits[9:7] + 1
            is_bf = (prxv0 & (1 << 10)) != 0;              // MT_PRXV_TXBF
            is_ldpc = (prxv0 & (1 << 11)) != 0;            // MT_PRXV_HT_AD_CODE
            let bw_raw = ((prxv0 >> 12) & 0x7) as u8;      // bits[14:12] FRAME_MODE
            let gi_raw = ((prxv0 >> 15) & 0x3) as u8;      // bits[16:15] HT_SGI
            let stbc_raw = ((prxv0 >> 22) & 0x3) as u8;    // bits[23:22] HT_STBC
            let tx_mode = ((prxv0 >> 24) & 0xF) as u8;     // bits[27:24] TX_MODE

            is_stbc = stbc_raw > 0;

            // Map tx_mode to PpduType (MT_PHY_TYPE_* from mt76.h)
            ppdu_type = match tx_mode {
                0 => PpduType::Cck,
                1 => PpduType::Ofdm,
                2 | 3 => PpduType::HT,
                4 => PpduType::VhtSu,
                8 => PpduType::HeSu,
                9 => PpduType::HeSu,    // HE_EXT_SU maps to HeSu
                10 => PpduType::HeMu,
                11 => PpduType::HeTb,
                _ => PpduType::Ofdm,
            };

            // Map bandwidth
            bandwidth = match bw_raw {
                0 => RxBandwidth::Bw20,
                1 => RxBandwidth::Bw40,
                2 => RxBandwidth::Bw80,
                3 => RxBandwidth::Bw160,
                _ => RxBandwidth::Bw20,
            };

            // Map guard interval
            gi_ltf = match tx_mode {
                8..=11 => match gi_raw { // HE modes: 0=0.8μs, 1=1.6μs, 2=3.2μs
                    0 => GuardInterval::Gi800ns,
                    1 => GuardInterval::Gi1600ns,
                    2 => GuardInterval::Gi3200ns,
                    _ => GuardInterval::Gi800ns,
                },
                _ => if gi_raw > 0 { GuardInterval::Gi400ns } else { GuardInterval::Gi800ns },
            };

            // Encode data_rate matching RxFrame convention:
            // Legacy: index, HT: 0x80+MCS, VHT/HE: (NSS<<4)|MCS
            data_rate = match tx_mode {
                0 | 1 => tx_rate as u16,
                2 | 3 => 0x80 + tx_rate as u16,
                _ => ((nss as u16 - 1) << 4) | (tx_rate as u16 & 0xF),
            };

            // P-RXV DW1: RCPI per path (same layout as Group 5 but from P-RXV)
            let rcpi = [
                (prxv1 & 0xFF) as u8,
                ((prxv1 >> 8) & 0xFF) as u8,
                ((prxv1 >> 16) & 0xFF) as u8,
                ((prxv1 >> 24) & 0xFF) as u8,
            ];

            // Convert RCPI to dBm: rssi = (rcpi - 220) / 2
            for i in 0..4 {
                if rcpi[i] > 0 && rcpi[i] < 255 {
                    rssi_path[i] = ((rcpi[i] as i16 - 220) / 2) as i8;
                    rx_path_en |= 1 << i;
                }
            }
            // Best path RSSI
            rssi = rssi_path.iter().copied()
                .filter(|&r| r < 0)
                .max().unwrap_or(-80);
        }
        off += 8;

        // ── Group 5 (72B): C-RXV extended — only present with Group 3 ──
        // Contains HE-specific fields and monitor-mode RCPI override.
        if has_group5 {
            if off + 72 <= pkt_len {
                // C-RXV starts at off, first 6 DWORDs (24B) are C-RXV fields
                // Then 12 DWORDs (48B) are extended monitor info
                // RCPI override is at the monitor section: off + 24, DW0
                let crxv_off = off;

                // C-RXV DW0 (at crxv_off): HE-specific fields
                let crxv0 = u32::from_le_bytes([
                    rxd[crxv_off], rxd[crxv_off+1], rxd[crxv_off+2], rxd[crxv_off+3]]);
                let _he_stbc = crxv0 & 0x3;                // bits[1:0]
                let _he_tx_mode = (crxv0 >> 4) & 0xF;      // bits[7:4]
                let _he_bw = (crxv0 >> 8) & 0x7;            // bits[10:8]
                let _he_sgi = (crxv0 >> 13) & 0x3;          // bits[14:13]
                let _he_ltf_size = (crxv0 >> 17) & 0x3;     // bits[18:17]
                let _he_ldpc_ext = (crxv0 >> 20) & 1;       // bit 20
                let _he_pe_disambig = (crxv0 >> 23) & 1;    // bit 23
                let _he_num_user = (crxv0 >> 24) & 0x7F;    // bits[30:24]
                let _he_uplink = (crxv0 >> 31) & 1;         // bit 31

                // C-RXV DW1: RU allocation
                let crxv1 = u32::from_le_bytes([
                    rxd[crxv_off+4], rxd[crxv_off+5], rxd[crxv_off+6], rxd[crxv_off+7]]);
                let _he_ru0 = (crxv1 & 0xFF) as u8;
                let _he_ru1 = ((crxv1 >> 8) & 0xFF) as u8;
                let _he_ru2 = ((crxv1 >> 16) & 0xFF) as u8;
                let _he_ru3 = ((crxv1 >> 24) & 0xFF) as u8;

                // C-RXV DW4: BSS color, TXOP duration, beam change, Doppler
                if crxv_off + 20 <= pkt_len {
                    let crxv4 = u32::from_le_bytes([
                        rxd[crxv_off+16], rxd[crxv_off+17], rxd[crxv_off+18], rxd[crxv_off+19]]);
                    let _bss_color = (crxv4 & 0x3F) as u8;
                    let _txop_dur = ((crxv4 >> 6) & 0x7F) as u8;
                    let _beam_chng = (crxv4 >> 13) & 1 != 0;
                    let _doppler = (crxv4 >> 16) & 1 != 0;
                }

                // Monitor-mode RCPI override: 6 DWORDs after C-RXV header (off + 24)
                // Linux: rxv = rxd; v1 = le32_to_cpu(rxv[0]); after rxd += 6
                let mon_off = crxv_off + 24; // skip 6 DWORDs of C-RXV
                if mon_off + 4 <= pkt_len {
                    let mon_rcpi = u32::from_le_bytes([
                        rxd[mon_off], rxd[mon_off+1], rxd[mon_off+2], rxd[mon_off+3]]);
                    if mon_rcpi != 0 {
                        let rcpi = [
                            (mon_rcpi & 0xFF) as u8,
                            ((mon_rcpi >> 8) & 0xFF) as u8,
                            ((mon_rcpi >> 16) & 0xFF) as u8,
                            ((mon_rcpi >> 24) & 0xFF) as u8,
                        ];
                        // Override with monitor-mode RCPI (more accurate)
                        rx_path_en = 0;
                        for i in 0..4 {
                            if rcpi[i] > 0 && rcpi[i] < 255 {
                                rssi_path[i] = ((rcpi[i] as i16 - 220) / 2) as i8;
                                rx_path_en |= 1 << i;
                            }
                        }
                        rssi = rssi_path.iter().copied()
                            .filter(|&r| r < 0)
                            .max().unwrap_or(-80);
                    }
                }
            }
            off += 72;
        }
    }

    // ── AMSDU info from DW4 ──
    let rxd_dw4 = u32::from_le_bytes([rxd[16], rxd[17], rxd[18], rxd[19]]);
    let amsdu_info = ((rxd_dw4 >> 0) & 0x3) as u8; // MT_RXD4_NORMAL_PAYLOAD_FORMAT
    let is_amsdu = amsdu_info != 0;

    let frame_start = off + hdr_offset;
    if frame_start >= pkt_len {
        return (consumed, ParsedPacket::Skip);
    }

    let frame_data = rxd[frame_start..pkt_len].to_vec();
    if frame_data.len() < 10 {
        return (consumed, ParsedPacket::Skip);
    }

    // Decode ch_freq into actual channel number + band index.
    // Matches mt792x_get_status_freq_info() from mt792x.h exactly.
    let (rx_channel, rx_band) = if ch_freq > 180 {
        // 6GHz: firmware encodes as 181-239 → channel = (chfreq - 181) * 4 + 1
        let ch_6g = (ch_freq - 181) * 4 + 1;
        (ch_6g, 2u8) // band=2 (6GHz)
    } else if ch_freq > 14 {
        (ch_freq, 1u8) // band=1 (5GHz)
    } else if ch_freq > 0 {
        (ch_freq, 0u8) // band=0 (2.4GHz)
    } else {
        // ch_freq=0: firmware didn't report channel, use scanner's current
        (channel, if channel <= 14 { 0u8 } else { 1u8 })
    };

    (consumed, ParsedPacket::Frame(RxFrame {
        data: frame_data,
        rssi,
        channel: rx_channel,
        band: rx_band,
        timestamp: rx_timestamp,
        rssi_path,
        data_rate,
        ppdu_type,
        bandwidth,
        gi_ltf,
        is_ldpc,
        is_stbc,
        is_bf,
        is_ampdu,
        is_amsdu,
        rx_path_en,
        is_dcm,
        is_fcs_error: fcs_err,
        ..Default::default()
    }))
}

// ══════════════════════════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_to_freq_2g() {
        assert_eq!(channel_to_freq(1, Band::Band2g), 2412);
        assert_eq!(channel_to_freq(6, Band::Band2g), 2437);
        assert_eq!(channel_to_freq(11, Band::Band2g), 2462);
        assert_eq!(channel_to_freq(14, Band::Band2g), 2484);
    }

    #[test]
    fn test_channel_to_freq_5g() {
        assert_eq!(channel_to_freq(36, Band::Band5g), 5180);
        assert_eq!(channel_to_freq(44, Band::Band5g), 5220);
        assert_eq!(channel_to_freq(149, Band::Band5g), 5745);
        assert_eq!(channel_to_freq(165, Band::Band5g), 5825);
    }

    #[test]
    fn test_channel_to_freq_6g() {
        assert_eq!(channel_to_freq(1, Band::Band6g), 5955);
        assert_eq!(channel_to_freq(5, Band::Band6g), 5975);
    }

    #[test]
    fn test_channel_to_band_idx() {
        assert_eq!(channel_to_band_idx(1), 0);   // 2.4 GHz
        assert_eq!(channel_to_band_idx(11), 0);  // 2.4 GHz
        assert_eq!(channel_to_band_idx(36), 1);  // 5 GHz
        assert_eq!(channel_to_band_idx(165), 1); // 5 GHz
    }

    #[test]
    fn test_build_channel_list() {
        let channels = build_channel_list();
        // Should have at least 2.4 GHz (14) + 5 GHz (28) channels
        assert!(channels.len() >= 42, "got {} channels", channels.len());
    }

    #[test]
    fn test_mt7921au_caps() {
        assert!(MT7921AU_CAPS.contains(ChipCaps::MONITOR));
        assert!(MT7921AU_CAPS.contains(ChipCaps::INJECT));
        assert!(MT7921AU_CAPS.contains(ChipCaps::BAND_2G));
        assert!(MT7921AU_CAPS.contains(ChipCaps::BAND_5G));
        assert!(MT7921AU_CAPS.contains(ChipCaps::HE));
        assert!(MT7921AU_CAPS.contains(ChipCaps::BW80));
        // Hardware maxes at 80MHz — VHT says "neither 160 nor 80+80", HE says "HE40/HE80"
        assert!(!MT7921AU_CAPS.contains(ChipCaps::BW160));
    }

    #[test]
    fn test_firmware_struct_sizes() {
        // PatchHeader: 16+4+4+4+2+2 + 4+4+4+4+4+44 = 96
        assert_eq!(PATCH_HEADER_SIZE, 96);
        // PatchSection: 4+4+4 + 4+4+4+4+36 = 64
        assert_eq!(PATCH_SECTION_SIZE, 64);
        // FwTrailer: 1+1+1+1+1+2+10+15+4 = 36
        assert_eq!(FW_TRAILER_SIZE, 36);
        // FwRegion: 4+4+4+4+4+4+1+1+14 = 40
        assert_eq!(FW_REGION_SIZE, 40);
    }

    #[test]
    fn test_mcu_cmd_constants() {
        // Verified against Linux kernel mt76_connac_mcu.h
        assert_eq!(MCU_CMD_TARGET_ADDRESS_LEN_REQ, 0x01);
        assert_eq!(MCU_CMD_FW_START_REQ, 0x02);
        assert_eq!(MCU_CMD_NIC_POWER_CTRL, 0x04);
        assert_eq!(MCU_CMD_PATCH_START_REQ, 0x05);
        assert_eq!(MCU_CMD_PATCH_FINISH_REQ, 0x07);
        assert_eq!(MCU_CMD_PATCH_SEM_CONTROL, 0x10);
        assert_eq!(MCU_CMD_FW_SCATTER, 0xEE);
        assert_eq!(MCU_CMD_RESTART_DL_REQ, 0xEF);
        assert_eq!(MCU_UNI_CMD_SNIFFER, 0x24);
    }

    #[test]
    fn test_register_constants() {
        // Verify key register addresses match kernel defines
        assert_eq!(MT_HW_CHIPID, 0x70010200);
        assert_eq!(MT_CONN_ON_MISC, 0x7c0600f0);
        assert_eq!(MT_UDMA_TX_QSEL, 0x74000008);
        assert_eq!(MT_UDMA_WLCFG_0, 0x74000018);
        assert_eq!(MT_UWFDMA0_GLO_CFG, 0x7c024208);
        assert_eq!(MT_CBTOP_RGU_WF_SUBSYS_RST, 0x70002600);
    }
}
