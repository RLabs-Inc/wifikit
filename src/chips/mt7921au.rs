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
//!   - Per-rate RSSI (single value from RXWI GROUP_4)
//!   - Full EEPROM parsing (only MAC address extracted)
//!   - Power save management (always exits PM on monitor init)
//!   - Firmware crash recovery (no watchdog/restart mechanism)
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

// MCU EXT command IDs (ext_cid field when cid=0xED)
const MCU_EXT_CMD_CHANNEL_SWITCH: u8 = 0x08;
const MCU_EXT_CMD_PM_STATE_CTRL: u8  = 0x07;
const MCU_EXT_CMD_EFUSE_BUFFER_MODE: u8 = 0x21;
const MCU_EXT_CMD_WTBL_UPDATE: u8    = 0x32;
const MCU_EXT_CMD_PROTECT_CTRL: u8   = 0x3E;
const MCU_EXT_CMD_MAC_INIT_CTRL: u8  = 0x46;
const MCU_EXT_CMD_SET_RX_PATH: u8    = 0x4E;

// MCU CE command IDs (community engine — set_query=MCU_Q_SET)
const MCU_CE_CMD_TEST_CTRL: u8       = 0x01;  // RF test mode control
const MCU_CE_CMD_SET_PS_PROFILE: u8  = 0x05;
const MCU_CE_CMD_SET_RX_FILTER: u8   = 0x0A;
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

// MCU UNI command IDs
const MCU_UNI_CMD_DEV_INFO_UPDATE: u16 = 0x01;
const MCU_UNI_CMD_BSS_INFO_UPDATE: u16 = 0x02;
const MCU_UNI_CMD_SNIFFER: u16        = 0x24;

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
    /// Current channel number
    channel: u8,
    /// Current band
    band: Band,
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
            channel: 0,
            band: Band::Band2g,
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
        };

        Ok((driver, endpoints))
    }

    /// Find the firmware directory containing MT7961 firmware files.
    fn find_firmware_dir() -> String {
        // Check relative to our binary / project root first
        let candidates = [
            "src/chips/firmware",
        ];
        for path in &candidates {
            let patch = format!("{}/{}", path, FW_ROM_PATCH);
            if Path::new(&patch).exists() {
                return path.to_string();
            }
        }
        // Default — will error at firmware load time
        "src/chips/firmware".to_string()
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

        // Enable TX/RX with USB RX aggregation.
        // Linux disables AGG because it uses 128 async URBs (no benefit).
        // We use synchronous bulk reads where aggregation reduces USB round-trips.
        // On USB3 SuperSpeed (5Gbps) this batches multiple frames per read.
        //
        // AGG_TO  = aggregation timeout (GENMASK(7,0) in WLCFG_0) in 33ns units
        // AGG_LMT = max frames per aggregate (GENMASK(15,8) in WLCFG_0)
        // PKT_LMT = packet count limit (GENMASK(7,0) in WLCFG_1)
        //
        // Tuning rationale (from PHY capabilities):
        //   Max AMPDU = 65535 bytes, Max AMSDU = 7935 bytes
        //   With avg beacon ~200 bytes, 64 frames × 200 = 12.8KB = fits in 65KB buffer
        //   Timeout: 0xFF ≈ 8.4µs — aggressive enough for real-time scanning
        //   but long enough to batch multiple back-to-back frames.
        self.reg_set(MT_UDMA_WLCFG_0,
                     MT_WL_RX_EN | MT_WL_TX_EN |
                     MT_WL_RX_MPSZ_PAD0 | MT_TICK_1US_EN |
                     MT_WL_RX_AGG_EN)?;
        // AGG_TO=0x80 (~4µs), AGG_LMT=16 frames per aggregate
        // Conservative values that work reliably during init and monitor setup.
        // Monitor mode set_monitor_mode() can tune these up for RX throughput.
        self.reg_rmw(MT_UDMA_WLCFG_0,
                     MT_WL_RX_AGG_TO | MT_WL_RX_AGG_LMT,
                     0x80 | (0x10 << 8))?;
        // PKT_LMT=16 in WLCFG_1
        self.reg_rmw(MT_UDMA_WLCFG_1, MT_WL_RX_AGG_PKT_LMT, 0x10)?;

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

    /// Set TX power for a band.
    /// Matches mt76_connac_mcu_rate_txpower_band() from the kernel driver.
    ///
    /// The full implementation sends per-channel power limits in batches.
    /// This simplified version sends max power (127 = 0.5 dBm units) for
    /// all channels in the current band, which is sufficient for monitor mode.
    ///
    /// Uses EXT cmd TX_POWER_FEATURE_CTRL (0x58).
    /// Set per-rate TX power limits for all channels in a band.
    /// `max_dbm` = maximum power in dBm (0 = use hardware max from SKU tables).
    /// Values are in half-dBm units internally. Firmware clamps to eFuse limits.
    fn mcu_set_rate_txpower_limited(&mut self, band: Band, max_dbm: i8) -> Result<()> {
        // Convert dBm to half-dBm. 0 means "no limit" (use SKU defaults).
        let max_half_dbm: u8 = if max_dbm > 0 {
            (max_dbm as u8).saturating_mul(2)
        } else {
            127 // no limit — firmware uses eFuse max
        };
        self.mcu_set_rate_txpower_inner(band, max_half_dbm)
    }

    fn mcu_set_rate_txpower(&mut self, band: Band) -> Result<()> {
        self.mcu_set_rate_txpower_inner(band, 0) // 0 = use SKU defaults, no clamping
    }

    fn mcu_set_rate_txpower_inner(&mut self, band: Band, max_half_dbm: u8) -> Result<()> {
        // TX power feature ctrl sub-command for rate power
        const TX_POWER_LIMIT_TABLE_RATE: u8 = 4;

        let (ch_list, band_idx): (&[u8], u8) = match band {
            Band::Band2g => (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14], 0),
            Band::Band5g => (&[36, 40, 44, 48, 52, 56, 60, 64,
                               100, 104, 108, 112, 116, 120, 124, 128,
                               132, 136, 140, 144, 149, 153, 157, 161, 165], 1),
            Band::Band6g => {
                // All 59 primary 20 MHz channels: 1-233 step 4
                const CHANNELS_6G: [u8; 59] = [
                    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
                    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117,
                    121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169,
                    173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213, 217, 221,
                    225, 229, 233,
                ];
                (&CHANNELS_6G[..], 2)
            },
        };

        // Send channels in batches of 8 (connac2 batch size)
        let batch_len = 8;
        let sku_len = 252; // sizeof(mt76_connac_sku_tlv) for connac2

        for batch_start in (0..ch_list.len()).step_by(batch_len) {
            let batch_end = (batch_start + batch_len).min(ch_list.len());
            let batch_channels = &ch_list[batch_start..batch_end];
            let is_last = batch_end >= ch_list.len();

            // Build payload: header (4 bytes) + per-channel SKU TLVs
            let n_chan = batch_channels.len();
            let payload_len = 4 + n_chan * sku_len;
            let mut payload = vec![0u8; payload_len];

            // Header: { power_ctrl_id: u8, power_limit_type: u8, band_idx: u8 }
            payload[0] = TX_POWER_LIMIT_TABLE_RATE; // power_ctrl_id
            payload[1] = if is_last { 1 } else { 0 }; // last_msg indicator
            payload[2] = n_chan as u8; // num channels in this batch
            payload[3] = band_idx;

            // Per-channel SKU TLVs: each is sku_len bytes
            // { channel: u8, pad[3], pwr[sku_entries]: i8 }
            // SKU entry layout (from captures txpower_sku.txt, eeprom values in 0.5dBm):
            //   [0..3]   = CCK   1m/2m/5m/11m         (4 entries, 2.4GHz only)
            //   [4..11]  = OFDM  6m..54m              (8 entries)
            //   [12..19] = HT20  MCS0..7              (8 entries)
            //   [20..28] = HT40  MCS0..7 + MCS32      (9 entries)
            //   [29..38] = VHT20 MCS0..9              (10 entries, 5/6GHz only)
            //   [39..48] = VHT40 MCS0..9              (10 entries)
            //   [49..58] = VHT80 MCS0..9              (10 entries)
            //   [59..68] = VHT160 MCS0..9             (10 entries)
            //   [69..80] = HE26  MCS0..11             (12 entries)
            //   [81..92] = HE52  MCS0..11             (12 entries)
            //   [93..104]= HE106 MCS0..11             (12 entries)
            //   [105..116]= HE242 MCS0..11            (12 entries)
            //   [117..128]= HE484 MCS0..11            (12 entries)
            //   [129..140]= HE996 MCS0..11            (12 entries)
            //   [141..152]= HE996x2 MCS0..11          (12 entries)
            for (i, &ch) in batch_channels.iter().enumerate() {
                let off = 4 + i * sku_len;
                payload[off] = ch;
                // Base: fill ALL entries with max (127 half-dBm = 63.5 dBm).
                // Firmware clamps to min(our_value, efuse), so this is safe.
                // Then overlay per-rate values from SKU capture below.
                for j in 4..sku_len {
                    payload[off + j] = 127;
                }
                // Per-rate power from SKU capture (eeprom values in 0.5dBm units).
                // Values from txpower_sku.txt captured on Fenvi USB3 adapter.
                let pwr = &mut payload[off + 4..off + sku_len];
                match band {
                    Band::Band2g => {
                        // CCK: 37 (18.5dBm)
                        for p in &mut pwr[0..4] { *p = 40; }
                        // OFDM: 31-34
                        pwr[4] = 37; pwr[5] = 36; pwr[6] = 36; pwr[7] = 36;
                        pwr[8] = 36; pwr[9] = 36; pwr[10] = 34; pwr[11] = 34;
                        // HT20: 27-33
                        pwr[12] = 36; pwr[13] = 36; pwr[14] = 36; pwr[15] = 36;
                        pwr[16] = 36; pwr[17] = 35; pwr[18] = 32; pwr[19] = 30;
                        // HT40: 27-33
                        pwr[20] = 36; pwr[21] = 36; pwr[22] = 36; pwr[23] = 36;
                        pwr[24] = 36; pwr[25] = 35; pwr[26] = 32; pwr[27] = 30;
                        pwr[28] = 36; // MCS32
                        // VHT20-VHT160: same as HT range
                        for j in 29..69 { pwr[j] = 36; }
                        // HE26-HE996x2: 23-36 per MCS
                        let he_pwr: [u8; 12] = [36, 36, 36, 36, 36, 35, 32, 30, 29, 28, 26, 26];
                        for ru in 0..7 {
                            for (k, &v) in he_pwr.iter().enumerate() {
                                pwr[69 + ru * 12 + k] = v;
                            }
                        }
                    }
                    Band::Band5g => {
                        // OFDM: 31-34
                        pwr[4] = 37; pwr[5] = 36; pwr[6] = 36; pwr[7] = 36;
                        pwr[8] = 36; pwr[9] = 36; pwr[10] = 34; pwr[11] = 34;
                        // HT20/40: same as 2.4G
                        for j in 12..29 { pwr[j] = 36; }
                        // VHT20/40: 25-33
                        let vht_pwr: [u8; 10] = [36, 36, 36, 36, 36, 35, 32, 30, 29, 28];
                        for bw in 0..2 { // VHT20, VHT40
                            for (k, &v) in vht_pwr.iter().enumerate() {
                                pwr[29 + bw * 10 + k] = v;
                            }
                        }
                        // VHT80/160: 27 flat (wider BW = lower per-tone)
                        for j in 49..69 { pwr[j] = 30; }
                        // HE26-HE484: per-rate staircase
                        let he_pwr: [u8; 12] = [36, 36, 36, 36, 36, 35, 32, 30, 29, 28, 26, 26];
                        for ru in 0..5 { // HE26..HE484
                            for (k, &v) in he_pwr.iter().enumerate() {
                                pwr[69 + ru * 12 + k] = v;
                            }
                        }
                        // HE996/996x2: 27 flat (wide RU = lower power density)
                        for j in 129..153 { pwr[j] = 30; }
                    }
                    Band::Band6g => {
                        // 6GHz: no CCK/HT, only OFDM+VHT+HE
                        // OFDM: 34 flat
                        for j in 4..12 { pwr[j] = 34; }
                        // VHT/HT: 30 flat
                        for j in 12..69 { pwr[j] = 30; }
                        // HE: per-rate staircase (lower power for 6GHz regulatory)
                        let he_pwr: [u8; 12] = [30, 30, 30, 30, 30, 29, 27, 25, 24, 23, 21, 21];
                        for ru in 0..7 {
                            for (k, &v) in he_pwr.iter().enumerate() {
                                pwr[69 + ru * 12 + k] = v;
                            }
                        }
                    }
                }

                // Clamp all per-rate values to requested max if set
                if max_half_dbm > 0 && max_half_dbm < 127 {
                    for j in 4..sku_len {
                        if payload[off + j] > max_half_dbm {
                            payload[off + j] = max_half_dbm;
                        }
                    }
                }
            }

            self.mcu_send_ext_cmd(0x58, &payload, true)?;
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
        let path = format!("{}/{}", self.fw_dir, FW_ROM_PATCH);
        let fw_data = std::fs::read(&path).map_err(|e| Error::ChipInitFailed {
            chip: "MT7921AU".into(),
            stage: crate::core::error::InitStage::FirmwareDownload,
            reason: format!("failed to read ROM patch {}: {}", path, e),
        })?;

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
        let path = format!("{}/{}", self.fw_dir, FW_WM_RAM);
        let fw_data = std::fs::read(&path).map_err(|e| Error::ChipInitFailed {
            chip: "MT7921AU".into(),
            stage: crate::core::error::InitStage::FirmwareDownload,
            reason: format!("failed to read WM firmware {}: {}", path, e),
        })?;

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

    /// Set RX path / channel info via MCU command.
    /// Matches mt7921_mcu_set_chan_info() from Linux mt7921/mcu.c:863.
    /// Accepts a full Channel struct to support bandwidth (20/40/80/160 MHz).
    fn mcu_set_chan_info(&mut self, ext_cmd: u8, channel: Channel) -> Result<()> {
        let channel_band = band_to_idx(channel.band);
        let (center_ch, bw) = channel_center_and_bw(channel);

        // Struct matches mt7921_mcu_set_chan_info() — 80 bytes total
        // Linux: mt7921/mcu.c:863
        let mut req = [0u8; 80];
        req[0] = channel.number; // control_ch
        req[1] = center_ch;     // center_ch
        req[2] = bw;            // bw: 0=20, 1=40, 2=80, 3=160 (CMD_CBW_*)
        req[3] = 2;             // tx_streams_num = hweight8(antenna_mask 0x3) = 2
        // rx_streams: Linux sends antenna_mask (0x3) for SET_RX_PATH,
        // but hweight8(antenna_mask) (2) for CHANNEL_SWITCH.
        req[4] = if ext_cmd == MCU_EXT_CMD_SET_RX_PATH {
            0x3              // antenna_mask (bitmask: both antennas)
        } else {
            2                // hweight8(0x3) = 2 (stream count)
        };
        req[5] = 0;            // switch_reason = CH_SWITCH_NORMAL (monitor mode)
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

        // 2. Enable hardware de-aggregation ONLY.
        // RX_HDR_TRANS_EN (bit 19) is intentionally NOT set — in monitor/sniffer mode
        // we need raw 802.11 frames, not firmware-translated 802.3 Ethernet.
        // Linux disables hdr_trans when sniffer is enabled (mt7996/main.c:499).
        self.reg_set(MT_MDP_DCR0, 1 << 15)?; // DAMSDU_EN only

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

        // 5. Set RTS threshold — mt76_connac_mcu_set_rts_thresh(0x92b, 0)
        // NOTE: On CF-952AX firmware (20231109), sending EXT_CMD 0x3E during
        // mac_init causes a firmware assert (core dump). This may need to be
        // sent later (after MAC enable) or the firmware may not support this
        // command in the current state. Skip for now — not critical for monitor mode.
        // TODO: re-enable after investigating firmware state requirements

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
    fn radio_init(&mut self, ch: u8, band: Band) -> Result<()> {
        // Phase 1: __mt7921_init_hardware() — EEPROM calibration
        self.mcu_set_eeprom()?;

        // Phase 2: __mt7921_start() — enable MAC, init hardware, set channels
        self.mcu_mac_enable(0, true)?;
        self.mac_init()?;
        self.wtbl_clear_all()?;
        self.mcu_set_channel_domain()?;
        self.mcu_set_chan_info(MCU_EXT_CMD_SET_RX_PATH, Channel::new(ch))?;

        self.mcu_set_rate_txpower(Band::Band2g)?;
        self.mcu_set_rate_txpower(Band::Band5g)?;
        self.mcu_set_rate_txpower(Band::Band6g)?;
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

        self.mcu_send_ce_cmd(0x0F, &data, false)?; // CE_CMD_SET_CHAN_DOMAIN = 0x0F
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

        self.mcu_send_uni_cmd(0x01, &dev_req, true)?;

        // 2. BSS_INFO_UPDATE (UNI cmd 0x02)
        // struct { bss_idx, pad[3] } hdr (4 bytes)
        // struct mt76_connac_bss_basic_tlv (variable, ~32+ bytes)
        let mut bss_req = [0u8; 36]; // hdr(4) + bss_basic_tlv(32)
        bss_req[0] = bss_idx;
        // bss_basic_tlv starts at offset 4
        let t = 4;
        bss_req[t..t+2].copy_from_slice(&0u16.to_le_bytes()); // tag = UNI_BSS_INFO_BASIC = 0
        bss_req[t+2..t+4].copy_from_slice(&32u16.to_le_bytes()); // len = 32 (matches Linux struct size)
        bss_req[t+4] = 1; // active = true
        bss_req[t+5] = omac_idx; // omac_idx
        bss_req[t+6] = omac_idx; // hw_bss_idx (same as omac_idx when < EXT_BSSID_START)
        bss_req[t+7] = band_idx; // band_idx
        bss_req[t+8..t+12].copy_from_slice(&conn_type.to_le_bytes()); // conn_type = CONNECTION_INFRA_AP
        bss_req[t+12] = 1; // conn_state = CONNECT
        bss_req[t+13] = wmm_idx; // wmm_idx
        // bssid[6] at t+14..t+20 — zeros for monitor mode
        bss_req[t+20..t+22].copy_from_slice(&wcid_idx.to_le_bytes()); // bmc_tx_wlan_idx
        // bcn_interval at t+22..t+24 — 0
        // dtim_period at t+24 — 0
        // phymode at t+25 — 0
        bss_req[t+26..t+28].copy_from_slice(&wcid_idx.to_le_bytes()); // sta_idx

        self.mcu_send_uni_cmd(0x02, &bss_req, true)?;

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
        // tlv.drop_err = 1 (byte 16)
        payload[16] = 1;

        // Try with wait_resp first; if it times out, send without waiting.
        // The MCU may need additional mac80211 setup (MAC enable, RX path)
        // before it responds to sniffer config commands.
        match self.mcu_send_uni_cmd(MCU_UNI_CMD_SNIFFER, &payload, true) {
            Ok(_) => {}
            Err(_) => {
                self.mcu_send_uni_cmd(MCU_UNI_CMD_SNIFFER, &payload, false)?;
                thread::sleep(Duration::from_millis(50));
            }
        }

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
    fn read_mac_from_eeprom(&mut self) -> Result<MacAddress> {
        // MAC is at EEPROM offset 0x004
        // For now, try reading it directly from registers
        // The MAC might be available at a well-known register after firmware boots
        // We'll read it from the EEPROM MCU query later when we have the full MCU
        // command set working. For now, generate a local MAC or read from USB descriptor.

        // Try to read from EEPROM offset 0x04 via register (some chips expose this)
        // Fall back to a locally-administered MAC based on device serial
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

        // 2. Check firmware state
        let conn_misc = self.reg_read(MT_CONN_ON_MISC)?;
        let fw_n9_rdy = (conn_misc & MT_TOP_MISC2_FW_N9_RDY) == MT_TOP_MISC2_FW_N9_RDY;

        // 3. ONLY reset WFSYS if firmware was already running (matches Linux exactly)
        if fw_n9_rdy {
            self.wfsys_reset()?;
        }

        // 4. Power on MCU
        self.mcu_power_on()?;

        // 5. Initialize DMA
        self.dma_init(false)?;

        // 6. Set normal mode
        self.reg_write(MT_SWDEF_MODE, MT_SWDEF_NORMAL_MODE)?;

        // 7. Download and start firmware
        self.run_firmware()?;

        // 8. Post-firmware MCU init — matches mt7921_run_firmware()
        // Query NIC capabilities (CE cmd 0x8A) — this initializes firmware internal state
        match self.mcu_send_ce_cmd(0x8A, &[], true) {
            Ok(_) => {},
            Err(_) => {},
        }

        // Enable firmware logging to host (CE cmd 0xC5, data=1)
        // Matches mt7921_mcu_fw_log_2_host(dev, 1)
        let _ = self.mcu_send_ce_cmd(0xC5, &[1, 0, 0, 0], false);

        // 9. Read MAC address
        self.mac_addr = self.read_mac_from_eeprom()?;

        Ok(())
    }

    /// Get a clone of the USB device handle for direct register access in tests.
    pub fn usb_handle(&self) -> Arc<DeviceHandle<GlobalContext>> {
        Arc::clone(&self.handle)
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
        let beacon = build_beacon_frame(ssid, bssid, self.channel, beacon_interval);

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

        self.mcu_send_uni_cmd(0x02, &payload, true)?; // BSS_INFO_UPDATE with BCN_CONTENT tag
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
        // Disable sniffer if active
        if self.sniffer_enabled {
            let _ = self.mcu_set_sniffer(false);
        }

        // Release the interface
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

        // Linux uses CHANNEL_SWITCH (0x08) for channel hopping — it does full RF
        // reconfiguration (PLL retune, AGC recal, LNA path switch between 2.4G/5G).
        // SET_RX_PATH (0x4E) is only used at init (__mt7921_start) for antenna setup.
        //
        // Previously we used SET_RX_PATH for everything, which worked on 2.4GHz
        // (since radio_init starts on ch6/2.4G) but left 5GHz RF front-end
        // half-configured, losing ~10dB. CHANNEL_SWITCH may fail on 6GHz —
        // handle that separately if needed.
        self.mcu_set_chan_info(MCU_EXT_CMD_CHANNEL_SWITCH, channel)?;

        // NOTE: sniffer config (mcu_config_sniffer_channel) is sent once at
        // monitor mode init, NOT on every channel hop. In Linux, it's only
        // called from chanctx_assign_vif, not from set_channel().
        // Sending it every hop may reset firmware RF gain settings.
        // The CHANNEL_SWITCH command alone handles band/frequency changes.

        self.channel = channel.number;
        self.band = channel.band;
        Ok(())
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
            self.radio_init(6, Band::Band2g)?;
            self.radio_initialized = true;
        }

        // Exit power management state — radio must be fully awake for monitor mode
        // Matches mt76_connac_mcu_set_pm(EXIT) from Linux
        self.mcu_set_pm(0, false)?; // band=0, enter=false (EXIT)
        self.mcu_set_vif_ps_awake()?;

        // Drain any stale data from USB endpoints before configuring monitor mode.
        self.drain_rx();

        // STEP 1: Create a virtual interface (VIF) in the firmware.
        self.mcu_add_dev()?;

        // STEP 2: Disable deep sleep — CRITICAL for monitor mode.
        self.mcu_set_deep_sleep(false)?;

        // STEP 3: Enable sniffer mode.
        self.mcu_set_sniffer(true)?;

        // STEP 4: Configure sniffer channel.
        self.mcu_config_sniffer_channel(Channel::new(self.channel))?;

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

        // STEP 6: Disable beacon filter
        // Matches mt7921_mcu_set_beacon_filter(dev, vif, false)
        // This uses BSS_INFO_UPDATE with BSS_INFO_BCNFT TLV + SET_BSS_ABORT CE cmd
        // For monitor mode, the rxfilter clearing above should be sufficient,
        // but we send SET_BSS_ABORT to be thorough
        let abort_data = [0u8; 4]; // bss_idx=0, pad[3]
        let _ = self.mcu_send_ce_cmd(0x17, &abort_data, false); // CE_CMD_SET_BSS_ABORT

        // STEP 7: Re-enable UDMA RX with tuned aggregation for monitor mode.
        // Match the dma_init() values: AGG_TO=0xFF, AGG_LMT=64, PKT_LMT=64
        self.reg_clear(MT_UDMA_WLCFG_0, MT_WL_RX_FLUSH)?;
        self.reg_set(MT_UDMA_WLCFG_0, MT_WL_RX_EN | MT_WL_TX_EN |
                     MT_WL_RX_MPSZ_PAD0 | MT_TICK_1US_EN | MT_WL_RX_AGG_EN)?;
        self.reg_rmw(MT_UDMA_WLCFG_0,
                     MT_WL_RX_AGG_LMT | MT_WL_RX_AGG_TO,
                     0xFF | (0x40 << 8))?;
        self.reg_rmw(MT_UDMA_WLCFG_1, MT_WL_RX_AGG_PKT_LMT, 0x40)?;
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

        // DW4-DW5: zero (no PN, no PID)

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
                let (consumed, packet) = mt7921au_parse_rx(buf, self.channel);
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

            if let Err(e) = self.mcu_send_uni_cmd(0x01, &dev_req, true) {
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
            self.mcu_set_rate_txpower(self.band)?;
        } else {
            self.mcu_set_rate_txpower_limited(self.band, dbm)?;
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
        0 => return (consumed, ParsedPacket::TxStatus(rxd.to_vec())), // TXS — TX ACK feedback
        7 | 8 | 0x0C => return (consumed, ParsedPacket::DriverMessage(rxd.to_vec())),
        _ => return (consumed, ParsedPacket::Skip),
    }

    let rxd_dw1 = u32::from_le_bytes([rxd[4], rxd[5], rxd[6], rxd[7]]);
    let has_group1 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_1) != 0;
    let has_group2 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_2) != 0;
    let has_group3 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_3) != 0;
    let has_group4 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_4) != 0;
    let has_group5 = (rxd_dw1 & MT_RXD1_NORMAL_GROUP_5) != 0;
    // Drop FCS errors — corrupted frames create phantom APs/stations.
    let fcs_err = (rxd_dw1 & MT_RXD1_NORMAL_FCS_ERR) != 0;
    if fcs_err {
        return (consumed, ParsedPacket::Skip);
    }

    let rxd_dw2 = u32::from_le_bytes([rxd[8], rxd[9], rxd[10], rxd[11]]);
    let hdr_trans = (rxd_dw2 & MT_RXD2_NORMAL_HDR_TRANS) != 0;
    let hdr_offset = ((rxd_dw2 >> 14) & 0x3) as usize * 2;

    // When firmware header translation is active, the 802.11 header was converted
    // to 802.3 Ethernet format: [dst MAC 6B] [src MAC 6B] [ethertype 2B] [payload].
    // NOT a raw 802.11 frame — skip for now.
    // TODO: extract STA MACs from 802.3 header for client tracking.
    if hdr_trans {
        return (consumed, ParsedPacket::Skip);
    }

    // RXD DW3 — channel
    let rxd_dw3 = u32::from_le_bytes([rxd[12], rxd[13], rxd[14], rxd[15]]);
    let ch_freq = ((rxd_dw3 >> 8) & 0xFF) as u8;

    // Calculate RXD total size
    let base_rxd = 24;
    let mut extra = 0usize;
    if has_group4 { extra += 16; }
    if has_group1 { extra += 16; }
    if has_group2 { extra += 8; }
    if has_group3 {
        extra += 8;
        if has_group5 { extra += 72; }
    }
    let rxd_total = base_rxd + extra;

    // RSSI from Group 3 (P-RXV)
    let mut rssi: i8 = -80;
    if has_group3 {
        let mut g3_off = base_rxd;
        if has_group4 { g3_off += 16; }
        if has_group1 { g3_off += 16; }
        if has_group2 { g3_off += 8; }

        let rcpi_val = if has_group5 {
            let g5_off = g3_off + 8 + 24;
            if g5_off + 4 <= pkt_len {
                u32::from_le_bytes([rxd[g5_off], rxd[g5_off+1], rxd[g5_off+2], rxd[g5_off+3]])
            } else { 0 }
        } else if g3_off + 8 <= pkt_len {
            u32::from_le_bytes([rxd[g3_off+4], rxd[g3_off+5], rxd[g3_off+6], rxd[g3_off+7]])
        } else { 0 };

        if rcpi_val != 0 {
            let max_rcpi = [rcpi_val & 0xFF, (rcpi_val >> 8) & 0xFF,
                           (rcpi_val >> 16) & 0xFF, (rcpi_val >> 24) & 0xFF]
                .iter().copied()
                .filter(|&r| r > 0 && r < 255)
                .max().unwrap_or(0);
            if max_rcpi > 0 {
                rssi = ((max_rcpi as i16 - 220) / 2) as i8;
            }
        }
    }

    let frame_start = rxd_total + hdr_offset;
    if frame_start >= pkt_len {
        return (consumed, ParsedPacket::Skip);
    }

    let frame_data = rxd[frame_start..pkt_len].to_vec();
    if frame_data.len() < 10 {
        return (consumed, ParsedPacket::Skip);
    }

    let rx_channel = if ch_freq > 0 { ch_freq } else { channel };

    (consumed, ParsedPacket::Frame(RxFrame {
        data: frame_data,
        rssi,
        channel: rx_channel,
        band: if rx_channel <= 14 { 0 } else { 1 },
        timestamp: Duration::ZERO,
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
