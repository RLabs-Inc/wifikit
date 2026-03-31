//! MT7612U chip driver
//!
//! The MT7612U (MediaTek MT7612UN) is an 802.11ac dual-band USB adapter.
//! 2x2 MIMO, 2.4 GHz + 5 GHz, up to 867 Mbps on 5 GHz.
//!
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
//! Key characteristics:
//!   - Firmware-driven: ROM patch + ILM/DLM firmware uploaded at init
//!   - Register access: USB vendor requests 0x06 (multi-write) / 0x07 (multi-read)
//!   - EEPROM access: USB vendor request 0x09
//!   - MCU commands: Bulk transfer with TXINFO header (4B + payload)
//!   - MCU responses: Bulk read with RXFCE header
//!   - RX frames: 20B RXWI + 802.11 frame + 4B RXINFO
//!   - Monitor mode: Promiscuous bit in RX filter register
//!
//! USB mode switch: This device presents as mass storage (0x0E8D:0x2870) and
//! needs a SCSI eject command to switch to WiFi mode (0x0E8D:0x7612).
//! The mode switch is handled by the separate `modeswitch` binary.
//!
//! USB endpoints (8 bulk on vendor interface):
//!   - EP 0x84/0x85 BULK IN  (RX data + MCU response)
//!   - EP 0x04-0x09 BULK OUT (TX queues + inband MCU commands)
//!
//! Reference: Linux mt76x2 driver in references/mt76/mt76x2/
//!   usb.c         — USB probe, device table
//!   usb_init.c    — USB-specific init, DMA
//!   usb_mcu.c     — MCU commands via USB bulk
//!   usb_mac.c     — MAC init, crystal fixup
//!   usb_phy.c     — PHY/RF calibration
//!   mcu.c         — Common MCU command definitions
//!   init.c        — Common init sequence
//!   eeprom.c      — EEPROM parsing
//!   mac.c         — MAC register init values

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::thread;

use rusb::{DeviceHandle, GlobalContext};

use crate::core::{
    Channel, Band, MacAddress, Result, Error,
    chip::{ChipDriver, ChipInfo, ChipId, ChipCaps},
    frame::{RxFrame, TxOptions},
    adapter::UsbEndpoints,
};

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — USB vendor requests
// ══════════════════════════════════════════════════════════════════════════════

/// USB vendor request: device mode (FW reset, IVB load)
const MT_VEND_DEV_MODE: u8   = 0x01;
/// USB vendor request: single register write
const MT_VEND_WRITE: u8      = 0x02;
/// USB vendor request: power on
const MT_VEND_POWER_ON: u8   = 0x04;
/// USB vendor request: multi-word register write
const MT_VEND_MULTI_WRITE: u8 = 0x06;
/// USB vendor request: multi-word register read
const MT_VEND_MULTI_READ: u8  = 0x07;
/// USB vendor request: EEPROM read
const MT_VEND_READ_EEPROM: u8 = 0x09;
/// USB vendor request: FCE DMA address/length
const MT_VEND_WRITE_FCE: u8   = 0x42;
/// USB vendor request: config space write
const MT_VEND_WRITE_CFG: u8   = 0x46;
/// USB vendor request: config space read
const MT_VEND_READ_CFG: u8    = 0x47;

const USB_TIMEOUT: Duration    = Duration::from_millis(500);
const USB_BULK_TIMEOUT: Duration = Duration::from_secs(2);

// Address space type bits
const MT_VEND_TYPE_EEPROM: u32 = 1 << 31;
const MT_VEND_TYPE_CFG: u32    = 1 << 30;

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — Register addresses
// ══════════════════════════════════════════════════════════════════════════════

// Hardware identification
const MT_ASIC_VERSION: u32     = 0x0000;

// WLAN function control
const MT_WLAN_FUN_CTRL: u32    = 0x0080;
const MT_WLAN_EN: u32          = 1 << 0;
const MT_WLAN_CLK_EN: u32      = 1 << 1;
const MT_WLAN_RESET_RF: u32    = 1 << 2;
const MT_FRC_WL_ANT_SEL: u32   = 1 << 5;

// WPDMA global config
const MT_WPDMA_GLO_CFG: u32    = 0x0208;
const MT_TX_DMA_BUSY: u32      = 1 << 1;
const MT_RX_DMA_BUSY: u32      = 1 << 3;

// WMM registers
const MT_WMM_AIFSN: u32        = 0x0214;
const MT_WMM_CWMIN: u32        = 0x0218;
const MT_WMM_CWMAX: u32        = 0x021c;

// Delay interrupt config
const MT_WPDMA_DELAY_INT_CFG: u32 = 0x0210;

// Timing
const MT_US_CYC_CFG: u32       = 0x02a4;

// Header translation
const MT_HEADER_TRANS_CTRL: u32 = 0x0260;
const MT_TSO_CTRL: u32         = 0x0250;

// PBF (packet buffer)
const MT_PBF_SYS_CTRL: u32     = 0x0400;
const MT_PBF_CFG: u32          = 0x0404;
const MT_PBF_TX_MAX_PCNT: u32  = 0x0408;
const MT_PBF_RX_MAX_PCNT: u32  = 0x040c;

// FCE (flow control engine)
const MT_FCE_PSE_CTRL: u32     = 0x0800;
const MT_FCE_L2_STUFF: u32     = 0x080c;
const MT_FCE_WLAN_FLOW_CTRL1: u32 = 0x0824;

// MCU semaphore
const MT_MCU_SEMAPHORE_03: u32  = 0x07BC;
// MCU common registers
const MT_MCU_COM_REG0: u32     = 0x0730;
const MT_MCU_CLOCK_CTL: u32    = 0x0708;

// FCE DMA registers
const MT_TX_CPU_FROM_FCE_BASE_PTR: u32 = 0x09a0;
const MT_TX_CPU_FROM_FCE_MAX_COUNT: u32 = 0x09a4;
const MT_TX_CPU_FROM_FCE_CPU_DESC_IDX: u32 = 0x09a8;
const MT_FCE_PDMA_GLOBAL_CONF: u32 = 0x09c4;
const MT_FCE_SKIP_FS: u32      = 0x0a6c;

// Pause enable
const MT_PAUSE_ENABLE_CONTROL1: u32 = 0x0a38;

// MAC registers
const MT_MAC_CSR0: u32         = 0x1000;
const MT_MAC_SYS_CTRL: u32     = 0x1004;
const MT_MAC_SYS_CTRL_ENABLE_TX: u32 = 1 << 2;
const MT_MAC_SYS_CTRL_ENABLE_RX: u32 = 1 << 3;
const MT_MAC_ADDR_DW0: u32     = 0x1008;
const MT_MAC_ADDR_DW1: u32     = 0x100c;
const MT_MAC_BSSID_DW0: u32    = 0x1010;
const MT_MAC_BSSID_DW1: u32    = 0x1014;
const MT_MAX_LEN_CFG: u32      = 0x1018;

const MT_AMPDU_MAX_LEN_20M1S: u32 = 0x1030;
const MT_AMPDU_MAX_LEN_20M2S: u32 = 0x1034;

const MT_XIFS_TIME_CFG: u32    = 0x1100;
const MT_BKOFF_SLOT_CFG: u32   = 0x1104;
const MT_TBTT_SYNC_CFG: u32    = 0x1118;

const MT_MAC_STATUS: u32       = 0x1200;
const MT_PWR_PIN_CFG: u32      = 0x1204;
const MT_AUX_CLK_CFG: u32      = 0x120c;

// TX power config
const MT_TX_PWR_CFG_0: u32     = 0x1314;
const MT_TX_SW_CFG0: u32       = 0x1330;
const MT_TX_SW_CFG1: u32       = 0x1334;
const MT_TX_SW_CFG2: u32       = 0x1338;
const MT_TX_BAND_CFG: u32      = 0x132c;

const MT_TXOP_CTRL_CFG: u32    = 0x1340;
const MT_TX_RTS_CFG: u32       = 0x1344;
const MT_TX_TIMEOUT_CFG: u32   = 0x1348;
const MT_TX_RETRY_CFG: u32     = 0x134c;
const MT_TX_LINK_CFG: u32      = 0x1350;
const MT_VHT_HT_FBK_CFG1: u32  = 0x1358;

const MT_CCK_PROT_CFG: u32     = 0x1364;
const MT_OFDM_PROT_CFG: u32    = 0x1368;
const MT_MM20_PROT_CFG: u32    = 0x136c;
const MT_MM40_PROT_CFG: u32    = 0x1370;
const MT_GF20_PROT_CFG: u32    = 0x1374;
const MT_GF40_PROT_CFG: u32    = 0x1378;
const MT_EXP_ACK_TIME: u32     = 0x1380;
const MT_HT_FBK_TO_LEGACY: u32 = 0x1384;

// RX filter
const MT_RX_FILTR_CFG: u32     = 0x1400;
const MT_RX_FILTR_CFG_PROMISC: u32 = 1 << 2;
const MT_RX_FILTR_CFG_OTHER_BSS: u32 = 1 << 3;
const MT_LEGACY_BASIC_RATE: u32 = 0x1408;
const MT_HT_BASIC_RATE: u32    = 0x140c;
const MT_HT_CTRL_CFG: u32      = 0x1410;
const MT_EXT_CCA_CFG: u32      = 0x141c;

const MT_TX_SW_CFG3: u32       = 0x1478;
const MT_PN_PAD_MODE: u32      = 0x150c;

const MT_TXOP_HLDR_ET: u32     = 0x1608;
const MT_PROT_AUTO_TX_CFG: u32  = 0x1648;

// TX protection config
const MT_TX_PROT_CFG6: u32     = 0x13e0;
const MT_TX_PROT_CFG7: u32     = 0x13e4;
const MT_TX_PROT_CFG8: u32     = 0x13e8;
const MT_PIFS_TX_CFG: u32      = 0x13ec;

// TX ALC (auto level control)
const MT_TX_ALC_CFG_0: u32     = 0x13b0;
const MT_TX_ALC_CFG_2: u32     = 0x13a8;
const MT_TX_ALC_CFG_3: u32     = 0x13ac;
const MT_TX_ALC_CFG_4: u32     = 0x13c0;
const MT_TX_ALC_VGA3: u32      = 0x13c8;
const MT_DACCLK_EN_DLY_CFG: u32 = 0x1264;

// TX PA mode and RF gain
const MT_BB_PA_MODE_CFG0: u32  = 0x1214;
const MT_BB_PA_MODE_CFG1: u32  = 0x1218;
const MT_RF_PA_MODE_CFG0: u32  = 0x121c;
const MT_RF_PA_MODE_CFG1: u32  = 0x1220;
const MT_RF_PA_MODE_ADJ0: u32  = 0x1228;
const MT_RF_PA_MODE_ADJ1: u32  = 0x122c;
const MT_TX0_RF_GAIN_CORR: u32 = 0x13a0;
const MT_TX1_RF_GAIN_CORR: u32 = 0x13a4;

// Statistics
const MT_RX_STA_CNT0: u32      = 0x1700;
const MT_RX_STA_CNT1: u32      = 0x1704;
const MT_RX_STA_CNT2: u32      = 0x1708;
const MT_TX_STA_CNT0: u32      = 0x170c;
const MT_TX_STA_CNT1: u32      = 0x1710;
const MT_TX_STA_CNT2: u32      = 0x1714;

// WCID table
const MT_WCID_ADDR_BASE: u32   = 0x1800;

// AUTO_RSP
const MT_AUTO_RSP_CFG: u32     = 0x1404;

// Coexistence
const MT_COEXCFG0: u32         = 0x0040;

// EFUSE
const MT_EFUSE_CTRL: u32       = 0x0024;

// BBP (baseband processor) registers — MT_BBP(group, reg) = base + group*0x100 + reg*4
const MT_BBP_CORE_BASE: u32    = 0x2000;
const MT_BBP_AGC_BASE: u32     = 0x2300;
const MT_BBP_TXO_BASE: u32     = 0x2600;
const MT_BBP_TXBE_BASE: u32    = 0x2700;
const MT_BBP_RXO_BASE: u32     = 0x2900;

// Specific BBP registers
const MT_BBP_CORE1: u32        = MT_BBP_CORE_BASE + 0x04;   // 0x2004 — bandwidth
const MT_BBP_CORE4: u32        = MT_BBP_CORE_BASE + 0x10;   // 0x2010 — BBP reset
const MT_BBP_IBI_BASE: u32     = 0x2100;
const MT_BBP_IBI12: u32        = MT_BBP_IBI_BASE + 0x30;    // 0x2130 — BBP(IBI, 12)
const MT_BBP_AGC0: u32         = MT_BBP_AGC_BASE;            // 0x2300 — RX path, BW, ctrl ch
const MT_BBP_AGC2: u32         = MT_BBP_AGC_BASE + 0x08;     // 0x2308
const MT_BBP_AGC7: u32         = MT_BBP_AGC_BASE + 0x1c;     // 0x231c
const MT_BBP_AGC8: u32         = MT_BBP_AGC_BASE + 0x20;     // 0x2320
const MT_BBP_AGC9: u32         = MT_BBP_AGC_BASE + 0x24;     // 0x2324
const MT_BBP_AGC11: u32        = MT_BBP_AGC_BASE + 0x2c;     // 0x232c
const MT_BBP_AGC61: u32        = MT_BBP_AGC_BASE + 0x184;    // 0x2484
const MT_BBP_TXO4: u32         = MT_BBP_TXO_BASE + 0x10;     // 0x2610
const MT_BBP_TXBE0: u32        = MT_BBP_TXBE_BASE;           // 0x2700
const MT_BBP_TXBE5: u32        = MT_BBP_TXBE_BASE + 0x14;    // 0x2714
const MT_BBP_RXO13: u32        = MT_BBP_RXO_BASE + 0x34;     // 0x2934

// MAC status bits
const MT_MAC_STATUS_TX: u32    = 1 << 0;
const MT_MAC_STATUS_RX: u32    = 1 << 1;

// USB DMA CFG register (MMIO at 0x0238, same bits as CFG space 0x9018)
const MT_USB_DMA_CFG: u32      = 0x0238;
const MT_USB_DMA_CFG_TX_BUSY: u32 = 1 << 31;
const MT_USB_DMA_CFG_RX_BUSY: u32 = 1 << 30;

// TXOP ED_CCA enable bit
const MT_TXOP_ED_CCA_EN: u32   = 1 << 20;
// TXOP_HLDR TX40M block enable
const MT_TXOP_HLDR_TX40M_BLK_EN: u32 = 1 << 1;

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — EEPROM offsets
// ══════════════════════════════════════════════════════════════════════════════

const MT7612U_EEPROM_SIZE: usize = 512;
const MT_EE_MAC_ADDR: u16       = 0x004;
const MT_EE_NIC_CONF_0: u16     = 0x034;
const MT_EE_NIC_CONF_1: u16     = 0x036;
const MT_EE_NIC_CONF_2: u16     = 0x042;
const MT_EE_XTAL_TRIM_1: u16    = 0x03a;
const MT_EE_XTAL_TRIM_2: u16    = 0x09e;
const MT_EE_LNA_GAIN: u16       = 0x044;
const MT_EE_RSSI_OFFSET_2G_0: u16 = 0x046;
const MT_EE_RSSI_OFFSET_2G_1: u16 = 0x048;
const MT_EE_LNA_GAIN_5GHZ_1: u16 = 0x049;
const MT_EE_RSSI_OFFSET_5G_0: u16 = 0x04a;
const MT_EE_RSSI_OFFSET_5G_1: u16 = 0x04c;
const MT_EE_LNA_GAIN_5GHZ_2: u16 = 0x04d;
const MT_EE_TX_POWER_DELTA_BW40: u16 = 0x050;
const MT_EE_TX_POWER_DELTA_BW80: u16 = 0x052;
const MT_EE_TX_POWER_EXT_PA_5G: u16 = 0x054;
const MT_EE_TX_POWER_0_START_2G: u16 = 0x056;
const MT_EE_TX_POWER_1_START_2G: u16 = 0x05c;
const MT_TX_POWER_GROUP_SIZE_5G: u16 = 5;
const MT_EE_TX_POWER_0_START_5G: u16 = 0x062;
const MT_EE_TSSI_SLOPE_2G: u16  = 0x06e;
const MT_EE_TX_POWER_1_START_5G: u16 = 0x080;
const MT_EE_TX_POWER_CCK: u16   = 0x0a0;
const MT_EE_TX_POWER_OFDM_2G_6M: u16 = 0x0a2;
const MT_EE_TX_POWER_OFDM_2G_24M: u16 = 0x0a4;
const MT_EE_TX_POWER_OFDM_5G_6M: u16 = 0x0b2;
const MT_EE_TX_POWER_OFDM_5G_24M: u16 = 0x0b4;
const MT_EE_TX_POWER_HT_MCS0: u16 = 0x0a6;
const MT_EE_TX_POWER_HT_MCS4: u16 = 0x0a8;
const MT_EE_TX_POWER_HT_MCS8: u16 = 0x0aa;
const MT_EE_TX_POWER_HT_MCS12: u16 = 0x0ac;
const MT_EE_TX_POWER_VHT_MCS8: u16 = 0x0be;
const MT_EE_2G_TARGET_POWER: u16 = 0x0d0;
const MT_EE_TEMP_OFFSET: u16    = 0x0d1;
const MT_EE_5G_TARGET_POWER: u16 = 0x0d2;
const MT_EE_RF_TEMP_COMP_SLOPE_5G: u16 = 0x0f2;
const MT_EE_RF_TEMP_COMP_SLOPE_2G: u16 = 0x0f4;
const MT_EE_RF_2G_TSSI_OFF_TXPOWER: u16 = 0x0f6;
const MT_EE_RF_2G_RX_HIGH_GAIN: u16 = 0x0f8;
const MT_EE_RF_5G_GRP0_1_RX_HIGH_GAIN: u16 = 0x0fa;
const MT_EE_RF_5G_GRP2_3_RX_HIGH_GAIN: u16 = 0x0fc;
const MT_EE_RF_5G_GRP4_5_RX_HIGH_GAIN: u16 = 0x0fe;
const MT_EE_BT_RCAL_RESULT: u16 = 0x138;

// NIC_CONF_0 bit definitions
const MT_EE_NIC_CONF_0_PA_INT_2G: u16 = 1 << 8;
const MT_EE_NIC_CONF_0_PA_INT_5G: u16 = 1 << 9;
// NIC_CONF_1 bit definitions
const MT_EE_NIC_CONF_1_LNA_EXT_2G: u16 = 1 << 2;
const MT_EE_NIC_CONF_1_LNA_EXT_5G: u16 = 1 << 3;
const MT_EE_NIC_CONF_1_TEMP_TX_ALC: u16 = 1 << 1;
const MT_EE_NIC_CONF_1_TX_ALC_EN: u16 = 1 << 13;

// 5GHz calibration channel groups (Linux: enum mt76x2_cal_channel_group)
const MT_CH_5G_JAPAN: u8 = 0;
const MT_CH_5G_UNII_1: u8 = 1;
const MT_CH_5G_UNII_2: u8 = 2;
const MT_CH_5G_UNII_2E_1: u8 = 3;
const MT_CH_5G_UNII_2E_2: u8 = 4;
const MT_CH_5G_UNII_3: u8 = 5;

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — CFG space offsets (ORed with MT_VEND_TYPE_CFG)
// ══════════════════════════════════════════════════════════════════════════════

const CFG_USB_DMA: u32          = MT_VEND_TYPE_CFG | 0x9018;
const CFG_USB_DMA_RX_BULK_EN: u32   = 1 << 22;
const CFG_USB_DMA_TX_BULK_EN: u32   = 1 << 23;
const CFG_USB_DMA_RX_BULK_AGG_EN: u32 = 1 << 21;
const CFG_USB_DMA_RX_DROP_OR_PAD: u32 = 1 << 18;
// AGG timeout: bits [7:0] of USB_DMA_CFG register (units ~33us per Linux)
const CFG_USB_DMA_RX_BULK_AGG_TOUT: u32 = 0x20; // ~1ms timeout
// AGG limit: bits [15:8] — max frames per aggregated transfer
const CFG_USB_DMA_RX_BULK_AGG_LMT: u32 = 0x40;  // 64 frames max

// Power management CFG registers
const CFG_PMU: u32              = MT_VEND_TYPE_CFG | 0x0148;
const CFG_PMU_STATE_UP: u32     = 1 << 28;
const CFG_PMU_PWR_ACK: u32      = 1 << 12;
const CFG_PMU_PWR_ACK_S: u32    = 1 << 13;

const CFG_FUN_CTRL: u32         = MT_VEND_TYPE_CFG | 0x0080;
const CFG_CLKCTL: u32           = MT_VEND_TYPE_CFG | 0x0064;
const CFG_AD_CTRL: u32          = MT_VEND_TYPE_CFG | 0x1204;

// RF power config registers
const CFG_RF_BG_0: u32          = MT_VEND_TYPE_CFG | 0x0130;
const CFG_RF_BG_1: u32          = MT_VEND_TYPE_CFG | 0x014c;

// Crystal config
const CFG_XO_CTRL5: u32         = MT_VEND_TYPE_CFG | 0x0114;
const CFG_XO_CTRL6: u32         = MT_VEND_TYPE_CFG | 0x0118;
const CFG_XO_CTRL7: u32         = MT_VEND_TYPE_CFG | 0x011c;
const CFG_XO_1C: u32            = MT_VEND_TYPE_CFG | 0x001c;
const CFG_XO_14: u32            = MT_VEND_TYPE_CFG | 0x0014;

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — MCU command IDs
// ══════════════════════════════════════════════════════════════════════════════

const CMD_FUN_SET_OP: u8        = 1;
const CMD_LOAD_CR: u8           = 2;
const CMD_INIT_GAIN_OP: u8      = 3;
const CMD_DYNC_VGA_OP: u8       = 6;
const CMD_BURST_WRITE: u8       = 8;
const CMD_RANDOM_READ: u8       = 10;
const CMD_RANDOM_WRITE: u8      = 12;
const CMD_POWER_SAVING_OP: u8   = 20;
const CMD_SWITCH_CHANNEL_OP: u8  = 30;
const CMD_CALIBRATION_OP: u8    = 31;

// CMD_FUN_SET_OP sub-IDs
const FUN_SET_Q_SELECT: u32     = 1;
// CMD_POWER_SAVING_OP sub-IDs
const RADIO_ON: u32             = 0x31;

// Calibration sub-IDs
const MCU_CAL_R: u8             = 1;
const MCU_CAL_TEMP_SENSOR: u8   = 2;
const MCU_CAL_RXDCOC: u8        = 3;
const MCU_CAL_RC: u8            = 4;
const MCU_CAL_LC: u8            = 7;
const MCU_CAL_TX_LOFT: u8       = 8;
const MCU_CAL_TXIQ: u8          = 9;
const MCU_CAL_TSSI: u8          = 10;
const MCU_CAL_RXIQC_FI: u8      = 13;
const MCU_CAL_TX_SHAPING: u8    = 15;

// MCU TXINFO format
const MCU_TXINFO_PORT_CPU: u32  = 2 << 27;
const MCU_TXINFO_TYPE_CMD: u32  = 1 << 30;

// MCU response
const MCU_RESP_EVT_CMD_DONE: u8 = 0;

// Firmware DMA offsets
const MT76U_MCU_ILM_OFFSET: u32 = 0x80000;
const MT76U_MCU_DLM_OFFSET: u32 = 0x110000;
const MT76U_MCU_DLM_OFFSET_E3: u32 = 0x110800;
const MT76U_MCU_ROM_PATCH_OFFSET: u32 = 0x90000;

// Max chunk size for firmware upload
const FW_UPLOAD_MAX_CHUNK: usize = 0x38F8; // 0x3900 - 8

// RX endpoint (first bulk IN)
const EP_IN_DATA: u8            = 0x84;
/// MCU response/inband command endpoint
const EP_IN_CMD_RESP: u8        = 0x85;
/// TX data endpoint — VO/MGMT queue (EP 0x07 from usbmon capture 2026-03-22)
/// Linux mt76 maps 4 TX queues to EP 04-07: BE, BK, VI, VO.
/// Management frames (probes, deauths, etc.) use the VO queue = EP 0x07.
const EP_OUT_DATA: u8           = 0x07;
/// Inband MCU command endpoint (usually last bulk OUT, mapped by index)
const EP_OUT_INBAND_CMD: u8     = 0x08;

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — RX frame format (RXWI)
// ══════════════════════════════════════════════════════════════════════════════

// USB RX frame format (from Linux mt76 usb.c):
//   [4B DMA header: u16 dma_len, u16 pad]   ← MT_DMA_HDR_LEN
//   [32B RXWI]                                ← MT_RX_RXWI_LEN
//   [MPDU (802.11 frame)]
//   [4B FCE_INFO / RXINFO]                    ← MT_FCE_INFO_LEN
//
// RXWI layout (32 bytes, starting at offset 4):
//   offset 0:  rxinfo  (u32)
//   offset 4:  ctl     (u32) — MPDU len in bits[29:16]
//   offset 8:  tid_sn  (u16)
//   offset 10: rate    (u16)
//   offset 12: rssi[4] (4 bytes)
//   offset 16: bbp_rxinfo[4] (16 bytes)
const DMA_HDR_LEN: usize = 4;
const RXWI_SIZE: usize = 32;

fn rxwi_mpdu_len(ctl: u32) -> usize { ((ctl >> 16) & 0x3FFF) as usize }
fn rxwi_rssi0(rssi_bytes: &[u8]) -> i8 { rssi_bytes[0] as i8 }
fn rxwi_rssi1(rssi_bytes: &[u8]) -> i8 { rssi_bytes[1] as i8 }

// RXINFO flags (last 4 bytes of RX frame)
const MT_RXINFO_BA: u32         = 1 << 0;
const MT_RXINFO_DATA: u32       = 1 << 1;
const MT_RXINFO_NULLDATA: u32   = 1 << 2;
const MT_RXINFO_FRAG: u32       = 1 << 3;
const MT_RXINFO_UNICAST: u32    = 1 << 4;
const MT_RXINFO_MULTICAST: u32  = 1 << 5;
const MT_RXINFO_BROADCAST: u32  = 1 << 6;
const MT_RXINFO_MYBEACON: u32   = 1 << 7;
const MT_RXINFO_CRCERR: u32     = 1 << 8;
const MT_RXINFO_ICVERR: u32     = 1 << 9;
const MT_RXINFO_MICERR: u32     = 1 << 10;
const MT_RXINFO_AMSDU: u32      = 1 << 11;
const MT_RXINFO_HTC: u32        = 1 << 12;
const MT_RXINFO_RSSI: u32       = 1 << 13;
const MT_RXINFO_L2PAD: u32      = 1 << 14;
const MT_RXINFO_AMPDU: u32      = 1 << 15;
const MT_RXINFO_DECRYPT: u32    = 1 << 16;
const MT_RXINFO_BSSIDX3: u32    = 1 << 17;
const MT_RXINFO_WAPI_KEY: u32   = 1 << 18;
const MT_RXINFO_PN_LEN_MASK: u32 = 0x7 << 19;
const MT_RXINFO_SW_FTYPE0: u32  = 1 << 22;
const MT_RXINFO_SW_FTYPE1: u32  = 1 << 23;

// ══════════════════════════════════════════════════════════════════════════════
//  Channel definitions
// ══════════════════════════════════════════════════════════════════════════════

const CHANNELS_2GHZ: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
const CHANNELS_5GHZ: &[u8] = &[
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
];

fn channel_to_freq(ch: u8) -> u16 {
    match ch {
        1..=13 => 2407 + ch as u16 * 5,
        14 => 2484,
        36..=165 => 5000 + ch as u16 * 5,
        _ => 0,
    }
}

fn is_5ghz(ch: u8) -> bool { ch >= 36 }

// ══════════════════════════════════════════════════════════════════════════════
//  Driver struct
// ══════════════════════════════════════════════════════════════════════════════

/// Per-rate TX power offsets read from EEPROM.
/// Layout matches Linux struct mt76x02_rate_power.
#[derive(Clone, Debug, Default)]
struct RatePower {
    cck: [i8; 4],
    ofdm: [i8; 8],
    ht: [i8; 16],
    vht: [i8; 2],
}

impl RatePower {
    fn all(&self) -> [i8; 30] {
        let mut a = [0i8; 30];
        a[0..4].copy_from_slice(&self.cck);
        a[4..12].copy_from_slice(&self.ofdm);
        a[12..28].copy_from_slice(&self.ht);
        a[28..30].copy_from_slice(&self.vht);
        a
    }

    fn max_power(&self) -> i8 {
        self.all().iter().copied().max().unwrap_or(0)
    }

    fn min_nonzero_power(&self) -> i8 {
        self.all().iter().copied().filter(|&v| v != 0).min().unwrap_or(0)
    }

    fn add_offset(&mut self, offset: i8) {
        for v in &mut self.cck { *v += offset; }
        for v in &mut self.ofdm { *v += offset; }
        for v in &mut self.ht { *v += offset; }
        for v in &mut self.vht { *v += offset; }
    }

    fn limit(&mut self, max: i8) {
        for v in &mut self.cck { if *v > max { *v = max; } }
        for v in &mut self.ofdm { if *v > max { *v = max; } }
        for v in &mut self.ht { if *v > max { *v = max; } }
        for v in &mut self.vht { if *v > max { *v = max; } }
    }
}

/// Per-chain TX power info read from EEPROM.
/// Layout matches Linux struct mt76x2_tx_power_info.
#[derive(Clone, Debug, Default)]
struct TxPowerInfo {
    target_power: u8,
    delta_bw40: i8,
    delta_bw80: i8,
    chain: [ChainPowerInfo; 2],
}

#[derive(Clone, Debug, Default)]
struct ChainPowerInfo {
    tssi_slope: u8,
    tssi_offset: u8,
    target_power: u8,
    delta: i8,
}

/// RX frequency calibration state.
/// Layout matches Linux struct mt76x02_rx_freq_cal.
#[derive(Clone, Debug, Default)]
struct RxFreqCal {
    high_gain: [i8; 2],
    rssi_offset: [i8; 2],
    lna_gain: i8,
    mcu_gain: u32,
}

/// Calibration state tracking.
/// Layout matches Linux struct mt76x02_calibration.
#[derive(Clone, Debug, Default)]
struct CalState {
    rx: RxFreqCal,
    agc_gain_init: [u8; 2],
    agc_gain_cur: [u8; 2],
    agc_gain_adjust: i8,
    low_gain: i8,
    init_cal_done: bool,
    channel_cal_done: bool,
    tssi_cal_done: bool,
    tssi_comp_pending: bool,
    dpd_cal_done: bool,
    gain_init_done: bool,
}

pub struct Mt7612u {
    handle: Arc<DeviceHandle<GlobalContext>>,
    iface_num: u8,
    vid: u16,
    pid: u16,
    asic_rev: u32,
    mac_addr: MacAddress,
    eeprom: [u8; MT7612U_EEPROM_SIZE],
    // Discovered endpoints
    ep_data_in: u8,
    ep_cmd_resp_in: u8,
    ep_data_out: u8,
    ep_cmd_out: u8,
    // MCU command sequence counter (1-15, wraps)
    mcu_seq: u8,
    // Current channel
    current_channel: Channel,
    // RX filter saved value
    rxfilter: u32,
    // TX power config (dBm)
    tx_power: i8,
    txpower_conf: i8, // user-configured max
    target_power: i8,
    target_power_delta: [i8; 2],
    rate_power: RatePower,
    // Firmware loaded?
    fw_loaded: bool,
    // RX paths and TX paths from EEPROM
    rx_paths: u8,
    tx_paths: u8,
    chainmask: u16, // Linux: dev->mphy.chainmask
    // External PA/LNA flags from EEPROM NIC_CONF_0/1
    ext_pa_2g: bool,
    ext_pa_5g: bool,
    ext_lna_2g: bool,
    ext_lna_5g: bool,
    // Calibration state (matches Linux cal struct)
    cal: CalState,
    // RX aggregation buffer — multiple frames per USB read
    rx_agg_buf: Vec<u8>,
    rx_agg_offset: usize,
}

// ══════════════════════════════════════════════════════════════════════════════
//  USB open + endpoint discovery
// ══════════════════════════════════════════════════════════════════════════════

impl Mt7612u {
    /// Mode switch: if the device is in mass storage mode (0x2870), send SCSI
    /// eject to flip it to WiFi mode (0x7612). Blocks until re-enumeration.
    fn modeswitch_if_needed() {
        const VID: u16 = 0x0E8D;
        const PID_CDROM: u16 = 0x2870;
        const PID_WIFI: u16 = 0x7612;

        // SCSI TEST UNIT READY wrapped in CBW
        const TUR: [u8; 31] = [
            0x55, 0x53, 0x42, 0x43, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // SCSI START STOP UNIT (eject) wrapped in CBW
        const EJECT: [u8; 31] = [
            0x55, 0x53, 0x42, 0x43, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
            0x1B, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        use rusb::UsbContext;
        let ctx = match rusb::Context::new() {
            Ok(c) => c,
            Err(_) => return,
        };

        // Look for mass storage PID
        let device = match ctx.devices().ok().and_then(|devs| {
            devs.iter().find(|d| {
                d.device_descriptor()
                    .map(|dd| dd.vendor_id() == VID && dd.product_id() == PID_CDROM)
                    .unwrap_or(false)
            })
        }) {
            Some(d) => d,
            None => return, // not in CD-ROM mode, nothing to do
        };

        let handle = match device.open() {
            Ok(h) => h,
            Err(_) => return,
        };
        let config = match device.active_config_descriptor() {
            Ok(c) => c,
            Err(_) => return,
        };
        let iface_desc = match config.interfaces().next().and_then(|i| i.descriptors().next()) {
            Some(d) => d,
            None => return,
        };
        let iface_num = iface_desc.interface_number();

        let mut ep_out: u8 = 0;
        let mut ep_in: u8 = 0;
        for ep in iface_desc.endpoint_descriptors() {
            if ep.transfer_type() == rusb::TransferType::Bulk {
                match ep.direction() {
                    rusb::Direction::Out => ep_out = ep.address(),
                    rusb::Direction::In => ep_in = ep.address(),
                }
            }
        }
        if ep_out == 0 || ep_in == 0 { return; }

        if handle.kernel_driver_active(iface_num).unwrap_or(false) {
            let _ = handle.detach_kernel_driver(iface_num);
        }
        let _ = handle.clear_halt(ep_out);
        let _ = handle.clear_halt(ep_in);
        if handle.claim_interface(iface_num).is_err() { return; }

        let timeout = Duration::from_secs(3);

        // TUR → wake up, then EJECT → mode switch
        let _ = handle.write_bulk(ep_out, &TUR, timeout);
        let mut csw = [0u8; 13];
        let _ = handle.read_bulk(ep_in, &mut csw, timeout);

        let _ = handle.write_bulk(ep_out, &EJECT, timeout);
        let _ = handle.read_bulk(ep_in, &mut csw, timeout);

        let _ = handle.release_interface(iface_num);
        drop(handle);

        // Wait for re-enumeration as WiFi device
        for _ in 0..30 {
            thread::sleep(Duration::from_millis(200));
            if let Ok(devs) = ctx.devices() {
                if devs.iter().any(|d| {
                    d.device_descriptor()
                        .map(|dd| dd.vendor_id() == VID && dd.product_id() == PID_WIFI)
                        .unwrap_or(false)
                }) { break; }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }

    pub fn open_usb(vid: u16, pid: u16) -> Result<(Self, UsbEndpoints)> {
        // Auto mode-switch from mass storage if needed
        Self::modeswitch_if_needed();

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

        // Find vendor-specific interface (class=0xFF)
        let config = device.active_config_descriptor()?;
        let mut wifi_iface: Option<u8> = None;
        let mut ep_data_in: u8 = EP_IN_DATA;
        let mut ep_cmd_resp_in: u8 = EP_IN_CMD_RESP;
        let mut ep_data_out: u8 = EP_OUT_DATA;
        let mut ep_cmd_out: u8 = EP_OUT_INBAND_CMD;

        for iface in config.interfaces() {
            for alt in iface.descriptors() {
                if alt.class_code() == 0xFF {
                    wifi_iface = Some(alt.interface_number());
                    let mut n_out: u8 = 0;
                    let mut n_in: u8 = 0;
                    for ep in alt.endpoint_descriptors() {
                        let dir = match ep.direction() {
                            rusb::Direction::In => "IN ",
                            rusb::Direction::Out => "OUT",
                        };
                        let xfer = match ep.transfer_type() {
                            rusb::TransferType::Bulk => "BULK",
                            rusb::TransferType::Interrupt => "INTR",
                            rusb::TransferType::Isochronous => "ISOC",
                            rusb::TransferType::Control => "CTRL",
                        };
                        match (ep.direction(), ep.transfer_type()) {
                            (rusb::Direction::Out, rusb::TransferType::Bulk) => {
                                // Linux mt76u maps by descriptor order:
                                // [0] = inband CMD (EP 0x08)
                                // [1..4] = data TX queues (EP 04=BE, 05=BK, 06=VI, 07=VO/MGMT)
                                // [5] = extra (EP 0x09, unused for standard TX)
                                // For monitor mode injection, use VO/MGMT queue (last of 4 data queues)
                                if n_out == 0 { ep_cmd_out = ep.address(); }
                                if n_out >= 1 && n_out <= 4 { ep_data_out = ep.address(); }
                                n_out += 1;
                            }
                            (rusb::Direction::In, rusb::TransferType::Bulk) => {
                                if n_in == 0 { ep_data_in = ep.address(); }
                                if n_in == 1 { ep_cmd_resp_in = ep.address(); }
                                n_in += 1;
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
            chip: "MT7612U".into(),
            stage: crate::core::error::InitStage::UsbEnumeration,
            reason: "No vendor-specific interface found".into(),
        })?;

        // NOTE: Skipping usb_reset_device — on macOS, handle.reset() can cause
        // the device to re-enumerate and invalidate the handle, breaking EP reads.
        // Linux does this in probe, but macOS XHCI behaves differently.

        // Detach kernel driver if needed
        if handle.kernel_driver_active(iface_num).unwrap_or(false) {
            let _ = handle.detach_kernel_driver(iface_num);
        }

        handle.claim_interface(iface_num)?;

        // Clear halt on data endpoints to ensure clean state
        let _ = handle.clear_halt(ep_data_in);
        let _ = handle.clear_halt(ep_cmd_resp_in);
        let _ = handle.clear_halt(ep_data_out);



        let endpoints = UsbEndpoints {
            bulk_out: ep_data_out,
            bulk_in: ep_data_in,
            bulk_out_all: vec![ep_cmd_out, ep_data_out],
        };

        let driver = Mt7612u {
            handle: Arc::new(handle),
            iface_num,
            vid,
            pid,
            asic_rev: 0,
            mac_addr: MacAddress::new([0; 6]),
            eeprom: [0u8; MT7612U_EEPROM_SIZE],
            ep_data_in,
            ep_cmd_resp_in,
            ep_data_out,
            ep_cmd_out,
            mcu_seq: 0,
            current_channel: Channel { number: 1, band: Band::Band2g, bandwidth: crate::core::channel::Bandwidth::Bw20, center_freq_mhz: 2412 },
            rxfilter: 0,
            tx_power: 20,
            txpower_conf: 30, // max allowed, will be limited by EEPROM
            target_power: 0,
            target_power_delta: [0; 2],
            rate_power: RatePower::default(),
            fw_loaded: false,
            rx_paths: 2,
            tx_paths: 2,
            chainmask: 0x0202, // 2T2R default, Linux format: tx_chain | (rx_chain << 8)
            ext_pa_2g: false,
            ext_pa_5g: false,
            ext_lna_2g: false,
            ext_lna_5g: false,
            cal: CalState { low_gain: -1, ..CalState::default() },
            rx_agg_buf: Vec::new(),
            rx_agg_offset: 0,
        };

        Ok((driver, endpoints))
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Register I/O — USB vendor requests
    // ══════════════════════════════════════════════════════════════════════════

    /// Read a 32-bit register. Routes to EEPROM/CFG/normal based on address bits.
    fn reg_read(&self, addr: u32) -> Result<u32> {
        let (req_type, request, offset) = if addr & MT_VEND_TYPE_EEPROM != 0 {
            (0xC0u8, MT_VEND_READ_EEPROM, addr & !MT_VEND_TYPE_EEPROM)
        } else if addr & MT_VEND_TYPE_CFG != 0 {
            (0xC0, MT_VEND_READ_CFG, addr & !MT_VEND_TYPE_CFG)
        } else {
            (0xC0, MT_VEND_MULTI_READ, addr)
        };

        // Linux retries up to 10 times with 5ms sleep between
        let mut last_err = rusb::Error::Timeout;
        for _ in 0..10 {
            let mut buf = [0u8; 4];
            match self.handle.read_control(
                req_type, request,
                (offset >> 16) as u16, (offset & 0xFFFF) as u16,
                &mut buf, USB_TIMEOUT,
            ) {
                Ok(4) => return Ok(u32::from_le_bytes(buf)),
                Ok(_) => return Ok(u32::from_le_bytes(buf)), // partial read, return what we got
                Err(e) => {
                    last_err = e;
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
        Err(Error::Usb(last_err))
    }

    /// Write a 32-bit register. Routes to CFG/normal based on address bits.
    fn reg_write(&self, addr: u32, val: u32) -> Result<()> {
        let buf = val.to_le_bytes();
        let (req_type, request, offset) = if addr & MT_VEND_TYPE_CFG != 0 {
            (0x40u8, MT_VEND_WRITE_CFG, addr & !MT_VEND_TYPE_CFG)
        } else {
            (0x40, MT_VEND_MULTI_WRITE, addr)
        };

        // Linux retries up to 10 times with 5ms sleep between
        let mut last_err = rusb::Error::Timeout;
        for _ in 0..10 {
            match self.handle.write_control(
                req_type, request,
                (offset >> 16) as u16, (offset & 0xFFFF) as u16,
                &buf, USB_TIMEOUT,
            ) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    last_err = e;
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
        Err(Error::Usb(last_err))
    }

    /// Read-modify-write a register
    fn reg_rmw(&self, addr: u32, mask: u32, val: u32) -> Result<u32> {
        let cur = self.reg_read(addr)?;
        let new = (cur & !mask) | (val & mask);
        if new != cur {
            self.reg_write(addr, new)?;
        }
        Ok(new)
    }

    /// Set bits in a register
    fn reg_set(&self, addr: u32, bits: u32) -> Result<()> {
        self.reg_rmw(addr, bits, bits)?;
        Ok(())
    }

    /// Clear bits in a register
    fn reg_clear(&self, addr: u32, bits: u32) -> Result<()> {
        self.reg_rmw(addr, bits, 0)?;
        Ok(())
    }

    /// Poll a register until (value & mask) == expected, with timeout
    fn poll_reg(&self, addr: u32, mask: u32, expected: u32, timeout: Duration) -> Result<u32> {
        let start = Instant::now();
        loop {
            let val = self.reg_read(addr)?;
            if (val & mask) == expected {
                return Ok(val);
            }
            if start.elapsed() >= timeout {
                return Err(Error::ChipInitFailed {
                    chip: "MT7612U".into(),
                    stage: crate::core::error::InitStage::RegisterAccess,
                    reason: format!("poll timeout: reg={:#010x} val={:#010x} mask={:#010x} expected={:#010x}",
                        addr, val, mask, expected),
                });
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Send a USB vendor dev_mode request (used for FW reset, IVB load, WMT commands)
    fn vendor_dev_mode(&self, w_value: u16, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            self.handle.write_control(
                0x40, // USB_DIR_OUT | USB_TYPE_VENDOR
                MT_VEND_DEV_MODE,
                w_value,
                0,
                &[],
                USB_TIMEOUT,
            )?;
        } else {
            // Class request for WMT commands
            self.handle.write_control(
                0x21, // USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE
                MT_VEND_DEV_MODE,
                w_value,
                0,
                data,
                USB_TIMEOUT,
            )?;
        }
        Ok(())
    }

    /// Write to FCE register (used for firmware DMA setup)
    /// Write to FCE register via mt76u_single_wr pattern
    /// Linux sends TWO 16-bit vendor requests (no data buffer):
    ///   req(MT_VEND_WRITE_FCE, wValue=val_low16,  wIndex=offset)
    ///   req(MT_VEND_WRITE_FCE, wValue=val_high16, wIndex=offset+2)
    fn write_fce(&self, reg_offset: u16, val: u32) -> Result<()> {
        // Low 16 bits
        self.handle.write_control(
            0x40, // USB_DIR_OUT | USB_TYPE_VENDOR
            MT_VEND_WRITE_FCE,
            (val & 0xFFFF) as u16,
            reg_offset,
            &[],
            USB_TIMEOUT,
        )?;
        // High 16 bits
        self.handle.write_control(
            0x40,
            MT_VEND_WRITE_FCE,
            (val >> 16) as u16,
            reg_offset + 2,
            &[],
            USB_TIMEOUT,
        )?;
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  MCU command interface — bulk transfer with TXINFO header
    // ══════════════════════════════════════════════════════════════════════════

    fn next_mcu_seq(&mut self) -> u8 {
        self.mcu_seq = (self.mcu_seq % 15) + 1; // 1-15
        self.mcu_seq
    }

    /// Send an MCU command via USB bulk transfer
    /// Format: [4B TXINFO][payload][pad to 4B][4B zero]
    fn mcu_send_cmd(&mut self, cmd_id: u8, payload: &[u8], wait_resp: bool) -> Result<Option<Vec<u8>>> {
        let cmd_start = Instant::now();

        // Drain any stale MCU responses from previous commands (especially calibrations
        // that respond late). Without this, seq numbers get out of sync.
        // Only drain if we've already sent some commands (seq > 0 means not first cmd)
        if wait_resp && self.mcu_seq > 0 {
            let mut drain_buf = [0u8; 1024];
            for _ in 0..10 {
                match self.handle.read_bulk(self.ep_cmd_resp_in, &mut drain_buf, Duration::from_millis(1)) {
                    Ok(n) if n > 0 => continue,
                    _ => break,
                }
            }
        }

        let seq = if wait_resp { self.next_mcu_seq() } else { 0 };
        let payload_len = payload.len();
        let padded_len = (payload_len + 3) & !3; // round up to 4

        // Build TXINFO
        let txinfo: u32 = (padded_len as u32) & 0xFFFF
            | ((seq as u32) << 16)
            | ((cmd_id as u32) << 20)
            | MCU_TXINFO_PORT_CPU
            | MCU_TXINFO_TYPE_CMD;

        // Build packet: TXINFO + payload + padding + 4 zero bytes
        let total = 4 + padded_len + 4;
        let mut pkt = vec![0u8; total];
        pkt[0..4].copy_from_slice(&txinfo.to_le_bytes());
        pkt[4..4 + payload_len].copy_from_slice(payload);
        // padding bytes already zero
        // trailing 4 zero bytes already zero

        // Send via bulk OUT
        self.handle.write_bulk(self.ep_cmd_out, &pkt, USB_BULK_TIMEOUT)?;

        if !wait_resp {
            return Ok(None);
        }

        // Read response — Linux: mt76x02u_mcu_wait_resp retries up to 5 times, 300ms each
        // Calibration commands can take longer, so use 500ms per attempt
        let mut resp = vec![0u8; 1024];
        for attempt in 0..5 {
            match self.handle.read_bulk(self.ep_cmd_resp_in, &mut resp, Duration::from_millis(500)) {
                Ok(n) if n >= 4 => {
                    let rxfce = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
                    let resp_seq = ((rxfce >> 16) & 0xF) as u8;
                    let evt_type = ((rxfce >> 20) & 0xF) as u8;

                    if resp_seq == seq && evt_type == MCU_RESP_EVT_CMD_DONE {
                        resp.truncate(n);
                        return Ok(Some(resp));
                    }
                    // Wrong seq or event type — might be stale response, retry
                    continue;
                }
                Ok(_) => continue, // short read, retry
                Err(rusb::Error::Timeout) => continue,
                Err(e) => return Err(Error::Usb(e)),
            }
        }
        // All 5 retries exhausted
        Err(Error::Usb(rusb::Error::Timeout))
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  EEPROM reading
    // ══════════════════════════════════════════════════════════════════════════

    fn read_eeprom(&mut self) -> Result<()> {
        // Read full 512-byte EEPROM via USB vendor requests (Linux: mt76x2u_init_eeprom)
        for offset in (0..MT7612U_EEPROM_SIZE).step_by(4) {
            let addr = MT_VEND_TYPE_EEPROM | (offset as u32);
            let val = self.reg_read(addr)?;
            self.eeprom[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        }

        // ── NIC_CONF_0 (0x034): RX/TX paths, PA type, board type ──
        let nic_conf_0 = self.eeprom_u16(MT_EE_NIC_CONF_0);
        self.rx_paths = (nic_conf_0 & 0x0F) as u8;
        self.tx_paths = ((nic_conf_0 >> 4) & 0x0F) as u8;
        if self.rx_paths == 0 || self.rx_paths > 2 { self.rx_paths = 2; }
        if self.tx_paths == 0 || self.tx_paths > 2 { self.tx_paths = 2; }

        // Linux chainmask: rx_chain in high byte, tx_chain in low byte
        self.chainmask = (self.tx_paths as u16) | ((self.rx_paths as u16) << 8);

        // External PA detection — Linux: mt76x02_ext_pa_enabled()
        // PA_INT_2G/5G: if bit is SET, internal PA. If CLEAR, external PA.
        self.ext_pa_2g = (nic_conf_0 & MT_EE_NIC_CONF_0_PA_INT_2G) == 0;
        self.ext_pa_5g = (nic_conf_0 & MT_EE_NIC_CONF_0_PA_INT_5G) == 0;

        // ── NIC_CONF_1 (0x036): external LNA flags ──
        let nic_conf_1 = self.eeprom_u16(MT_EE_NIC_CONF_1);
        self.ext_lna_2g = (nic_conf_1 & MT_EE_NIC_CONF_1_LNA_EXT_2G) != 0;
        self.ext_lna_5g = (nic_conf_1 & MT_EE_NIC_CONF_1_LNA_EXT_5G) != 0;

        // ── Board type → band capability ──
        let board_type = (nic_conf_0 >> 12) & 0x3;
        // 0 = dual-band, 1 = 5GHz only, 2 = 2.4GHz only
        // We support both always for monitor mode, but log it
        if board_type == 1 {
        } else if board_type == 2 {
        }

        // ── MAC address (0x004) ──
        let mac_bytes = &self.eeprom[MT_EE_MAC_ADDR as usize..MT_EE_MAC_ADDR as usize + 6];
        self.mac_addr = MacAddress::from_slice(mac_bytes).unwrap_or(MacAddress::new([0; 6]));

        Ok(())
    }

    fn eeprom_u16(&self, offset: u16) -> u16 {
        let o = offset as usize;
        if o + 1 < self.eeprom.len() {
            u16::from_le_bytes([self.eeprom[o], self.eeprom[o + 1]])
        } else {
            0xFFFF
        }
    }

    fn eeprom_u8(&self, offset: u16) -> u8 {
        let o = offset as usize;
        if o < self.eeprom.len() { self.eeprom[o] } else { 0xFF }
    }

    /// Copy bytes from EEPROM. Linux: mt76x02_eeprom_copy
    fn eeprom_copy(&self, offset: u16, dest: &mut [u8]) {
        let o = offset as usize;
        let end = std::cmp::min(o + dest.len(), self.eeprom.len());
        let n = end - o;
        dest[..n].copy_from_slice(&self.eeprom[o..end]);
    }

    /// Check if a byte value is valid (not 0 and not 0xFF). Linux: mt76x02_field_valid
    fn field_valid(val: u8) -> bool {
        val != 0 && val != 0xFF
    }

    /// Sign extend a value. Linux: mt76x02_sign_extend
    fn sign_extend(val: u32, size: u32) -> i8 {
        let sign = (val & (1 << (size - 1))) != 0;
        let magnitude = (val & ((1 << (size - 1)) - 1)) as i8;
        if sign { magnitude } else { -magnitude }
    }

    /// Sign extend with enable bit. Linux: mt76x02_sign_extend_optional
    fn sign_extend_optional(val: u32, size: u32) -> i8 {
        let enable = (val & (1 << size)) != 0;
        if enable { Self::sign_extend(val, size) } else { 0 }
    }

    /// Rate power value from EEPROM byte. Linux: mt76x02_rate_power_val
    fn rate_power_val(val: u8) -> i8 {
        if !Self::field_valid(val) { return 0; }
        Self::sign_extend_optional(val as u32, 7)
    }

    /// Check if ext PA is enabled for a band
    fn ext_pa_enabled(&self, is_5ghz: bool) -> bool {
        if is_5ghz { self.ext_pa_5g } else { self.ext_pa_2g }
    }

    /// Check if device has ext LNA for current band. Linux: mt76x2_has_ext_lna
    fn has_ext_lna(&self, is_5ghz: bool) -> bool {
        if is_5ghz { self.ext_lna_5g } else { self.ext_lna_2g }
    }

    /// Check if temp TX ALC is enabled. Linux: mt76x2_temp_tx_alc_enabled
    fn temp_tx_alc_enabled(&self) -> bool {
        let val = self.eeprom_u16(MT_EE_TX_POWER_EXT_PA_5G);
        if (val & (1 << 15)) == 0 { return false; }
        (self.eeprom_u16(MT_EE_NIC_CONF_1) & MT_EE_NIC_CONF_1_TEMP_TX_ALC) != 0
    }

    /// Check if TSSI is enabled. Linux: mt76x2_tssi_enabled
    fn tssi_enabled(&self) -> bool {
        if self.temp_tx_alc_enabled() { return false; }
        (self.eeprom_u16(MT_EE_NIC_CONF_1) & MT_EE_NIC_CONF_1_TX_ALC_EN) != 0
    }

    /// Get 5GHz calibration channel group. Linux: mt76x2_get_cal_channel_group
    fn get_cal_channel_group(channel: u8) -> u8 {
        if channel >= 184 && channel <= 196 { MT_CH_5G_JAPAN }
        else if channel <= 48 { MT_CH_5G_UNII_1 }
        else if channel <= 64 { MT_CH_5G_UNII_2 }
        else if channel <= 114 { MT_CH_5G_UNII_2E_1 }
        else if channel <= 144 { MT_CH_5G_UNII_2E_2 }
        else { MT_CH_5G_UNII_3 }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  EEPROM-driven subsystems — RX gain, TX power, rate power
    // ══════════════════════════════════════════════════════════════════════════

    /// Read RX gain info from EEPROM. Linux: mt76x2_read_rx_gain (eeprom.c:254-289)
    fn read_rx_gain(&mut self, channel: u8, is_5ghz: bool) {
        // High gain per group
        let high_gain_val = if !is_5ghz {
            (self.eeprom_u16(MT_EE_RF_2G_RX_HIGH_GAIN) >> 8) as u8
        } else {
            let group = Self::get_cal_channel_group(channel);
            match group {
                0 => self.eeprom_u16(MT_EE_RF_5G_GRP0_1_RX_HIGH_GAIN) as u8,       // Japan
                1 => (self.eeprom_u16(MT_EE_RF_5G_GRP0_1_RX_HIGH_GAIN) >> 8) as u8, // UNII-1
                2 => self.eeprom_u16(MT_EE_RF_5G_GRP2_3_RX_HIGH_GAIN) as u8,        // UNII-2
                3 => (self.eeprom_u16(MT_EE_RF_5G_GRP2_3_RX_HIGH_GAIN) >> 8) as u8, // UNII-2E-1
                4 => self.eeprom_u16(MT_EE_RF_5G_GRP4_5_RX_HIGH_GAIN) as u8,        // UNII-2E-2
                _ => (self.eeprom_u16(MT_EE_RF_5G_GRP4_5_RX_HIGH_GAIN) >> 8) as u8, // UNII-3
            }
        };

        // Set RX gain group: split into two 4-bit signed values
        if Self::field_valid(high_gain_val) {
            self.cal.rx.high_gain[0] = Self::sign_extend(high_gain_val as u32, 4);
            self.cal.rx.high_gain[1] = Self::sign_extend((high_gain_val >> 4) as u32, 4);
        } else {
            self.cal.rx.high_gain = [0, 0];
        }

        // RSSI offset
        let rssi_offset = if !is_5ghz {
            self.eeprom_u16(MT_EE_RSSI_OFFSET_2G_0)
        } else {
            self.eeprom_u16(MT_EE_RSSI_OFFSET_5G_0)
        };
        let rssi0 = rssi_offset as u8;
        let rssi1 = (rssi_offset >> 8) as u8;
        self.cal.rx.rssi_offset[0] = if Self::field_valid(rssi0) {
            Self::sign_extend_optional(rssi0 as u32, 7)
        } else { 0 };
        self.cal.rx.rssi_offset[1] = if Self::field_valid(rssi1) {
            Self::sign_extend_optional(rssi1 as u32, 7)
        } else { 0 };

        // LNA gains for MCU
        let lna_val = self.eeprom_u16(MT_EE_LNA_GAIN);
        let lna_2g = (lna_val & 0xFF) as i8;
        let mut lna_5g = [0i8; 3];
        lna_5g[0] = (lna_val >> 8) as i8;

        let rssi_2g_1 = self.eeprom_u16(MT_EE_RSSI_OFFSET_2G_1);
        lna_5g[1] = (rssi_2g_1 >> 8) as i8;

        let rssi_5g_1 = self.eeprom_u16(MT_EE_RSSI_OFFSET_5G_1);
        lna_5g[2] = (rssi_5g_1 >> 8) as i8;

        if !Self::field_valid(lna_5g[1] as u8) { lna_5g[1] = lna_5g[0]; }
        if !Self::field_valid(lna_5g[2] as u8) { lna_5g[2] = lna_5g[0]; }

        // MCU gain word: lna_2g | lna_5g[0] | lna_5g[1] | lna_5g[2]
        self.cal.rx.mcu_gain = (lna_2g as u8 as u32)
            | ((lna_5g[0] as u8 as u32) << 8)
            | ((lna_5g[1] as u8 as u32) << 16)
            | ((lna_5g[2] as u8 as u32) << 24);

        // LNA gain for this channel (used if NOT ext LNA)
        let use_lna = !self.has_ext_lna(is_5ghz);
        let lna = if use_lna {
            if !is_5ghz {
                lna_2g
            } else if channel <= 64 {
                lna_5g[0]
            } else if channel <= 128 {
                lna_5g[1]
            } else {
                lna_5g[2]
            }
        } else {
            0
        };
        self.cal.rx.lna_gain = if (lna as u8) != 0xFF {
            Self::sign_extend(lna as u32 & 0xFF, 8)
        } else {
            0
        };
    }

    /// Read per-rate TX power offsets. Linux: mt76x2_get_rate_power (eeprom.c:292-340)
    fn get_rate_power(&self, is_5ghz: bool) -> RatePower {
        let mut t = RatePower::default();

        let val = self.eeprom_u16(MT_EE_TX_POWER_CCK);
        t.cck[0] = Self::rate_power_val(val as u8);
        t.cck[1] = t.cck[0];
        t.cck[2] = Self::rate_power_val((val >> 8) as u8);
        t.cck[3] = t.cck[2];

        let ofdm_6m = if is_5ghz {
            self.eeprom_u16(MT_EE_TX_POWER_OFDM_5G_6M)
        } else {
            self.eeprom_u16(MT_EE_TX_POWER_OFDM_2G_6M)
        };
        t.ofdm[0] = Self::rate_power_val(ofdm_6m as u8);
        t.ofdm[1] = t.ofdm[0];
        t.ofdm[2] = Self::rate_power_val((ofdm_6m >> 8) as u8);
        t.ofdm[3] = t.ofdm[2];

        let ofdm_24m = if is_5ghz {
            self.eeprom_u16(MT_EE_TX_POWER_OFDM_5G_24M)
        } else {
            self.eeprom_u16(MT_EE_TX_POWER_OFDM_2G_24M)
        };
        t.ofdm[4] = Self::rate_power_val(ofdm_24m as u8);
        t.ofdm[5] = t.ofdm[4];
        t.ofdm[6] = Self::rate_power_val((ofdm_24m >> 8) as u8);
        t.ofdm[7] = t.ofdm[6];

        let val = self.eeprom_u16(MT_EE_TX_POWER_HT_MCS0);
        t.ht[0] = Self::rate_power_val(val as u8); t.ht[1] = t.ht[0];
        t.ht[2] = Self::rate_power_val((val >> 8) as u8); t.ht[3] = t.ht[2];

        let val = self.eeprom_u16(MT_EE_TX_POWER_HT_MCS4);
        t.ht[4] = Self::rate_power_val(val as u8); t.ht[5] = t.ht[4];
        t.ht[6] = Self::rate_power_val((val >> 8) as u8); t.ht[7] = t.ht[6];

        let val = self.eeprom_u16(MT_EE_TX_POWER_HT_MCS8);
        t.ht[8] = Self::rate_power_val(val as u8); t.ht[9] = t.ht[8];
        t.ht[10] = Self::rate_power_val((val >> 8) as u8); t.ht[11] = t.ht[10];

        let val = self.eeprom_u16(MT_EE_TX_POWER_HT_MCS12);
        t.ht[12] = Self::rate_power_val(val as u8); t.ht[13] = t.ht[12];
        t.ht[14] = Self::rate_power_val((val >> 8) as u8); t.ht[15] = t.ht[14];

        let val = self.eeprom_u16(MT_EE_TX_POWER_VHT_MCS8);
        let vht_val = if !is_5ghz { val >> 8 } else { val };
        t.vht[0] = Self::rate_power_val((vht_val >> 8) as u8);
        t.vht[1] = t.vht[0];

        t
    }

    /// Get per-chain TX power info for 2GHz. Linux: mt76x2_get_power_info_2g
    fn get_power_info_2g(&self, _chain: usize, offset: u16, channel: u8) -> ChainPowerInfo {
        let delta_idx = if channel < 6 { 3 } else if channel < 11 { 4 } else { 5 };
        let mut data = [0u8; 6];
        self.eeprom_copy(offset, &mut data);

        let delta_val = data[delta_idx];
        ChainPowerInfo {
            tssi_slope: data[0],
            tssi_offset: data[1],
            target_power: data[2],
            delta: Self::sign_extend_optional(delta_val as u32, 7),
        }
    }

    /// Get per-chain TX power info for 5GHz. Linux: mt76x2_get_power_info_5g
    fn get_power_info_5g(&self, _chain: usize, offset: u16, channel: u8) -> ChainPowerInfo {
        let group = Self::get_cal_channel_group(channel);
        let actual_offset = offset + (group as u16) * MT_TX_POWER_GROUP_SIZE_5G;

        let delta_idx: usize = if channel >= 192 { 4 }
        else if channel >= 184 { 3 }
        else if channel < 44 { 3 }
        else if channel < 52 { 4 }
        else if channel < 58 { 3 }
        else if channel < 98 { 4 }
        else if channel < 106 { 3 }
        else if channel < 116 { 4 }
        else if channel < 130 { 3 }
        else if channel < 149 { 4 }
        else if channel < 157 { 3 }
        else { 4 };

        let mut data = [0u8; 5];
        self.eeprom_copy(actual_offset, &mut data);

        ChainPowerInfo {
            tssi_slope: data[0],
            tssi_offset: data[1],
            target_power: data[2],
            delta: Self::sign_extend_optional(data[delta_idx] as u32, 7),
        }
    }

    /// Get TX power info for a channel. Linux: mt76x2_get_power_info (eeprom.c:425-455)
    fn get_power_info(&self, channel: u8, is_5ghz: bool) -> TxPowerInfo {
        let mut t = TxPowerInfo::default();

        let bw40 = self.eeprom_u16(MT_EE_TX_POWER_DELTA_BW40);
        let bw80 = self.eeprom_u16(MT_EE_TX_POWER_DELTA_BW80);

        if is_5ghz {
            t.delta_bw40 = Self::rate_power_val((bw40 >> 8) as u8);
            t.chain[0] = self.get_power_info_5g(0, MT_EE_TX_POWER_0_START_5G, channel);
            t.chain[1] = self.get_power_info_5g(1, MT_EE_TX_POWER_1_START_5G, channel);
        } else {
            t.delta_bw40 = Self::rate_power_val(bw40 as u8);
            t.chain[0] = self.get_power_info_2g(0, MT_EE_TX_POWER_0_START_2G, channel);
            t.chain[1] = self.get_power_info_2g(1, MT_EE_TX_POWER_1_START_2G, channel);
        }
        t.delta_bw80 = Self::rate_power_val(bw80 as u8);

        // Target power: use TSSI-sourced value or chain[0] fallback
        if is_5ghz {
            let val = self.eeprom_u16(MT_EE_RF_2G_RX_HIGH_GAIN);
            t.target_power = (val & 0xFF) as u8;
        } else {
            let val = self.eeprom_u16(MT_EE_RF_2G_TSSI_OFF_TXPOWER);
            t.target_power = (val >> 8) as u8;
        }

        if self.tssi_enabled() || !Self::field_valid(t.target_power) {
            t.target_power = t.chain[0].target_power;
        }

        t
    }

    /// Apply gain adjustment to AGC registers. Linux: mt76x2_apply_gain_adj (phy.c:33-42)
    fn apply_gain_adj(&self) -> Result<()> {
        let gain_adj = &self.cal.rx.high_gain;

        // Adjust high LNA gain in AGC4/AGC5
        for &(reg_idx, adj) in &[(4u32, gain_adj[0]), (5u32, gain_adj[1])] {
            let reg = MT_BBP_AGC_BASE + (reg_idx << 2);
            let val = self.reg_read(reg)?;
            let gain = ((val >> 16) & 0x3F) as i8;
            let new_gain = gain - adj / 2;
            let new_val = (val & !0x003F0000) | (((new_gain as u8 as u32) & 0x3F) << 16);
            self.reg_write(reg, new_val)?;
        }

        // Adjust AGC gain in AGC8/AGC9
        for &(reg_idx, adj) in &[(8u32, gain_adj[0]), (9u32, gain_adj[1])] {
            let reg = MT_BBP_AGC_BASE + (reg_idx << 2);
            let val = self.reg_read(reg)?;
            let gain = ((val >> 8) & 0x7F) as i8;
            let new_gain = gain + adj;
            let new_val = (val & !0x00007F00) | (((new_gain as u8 as u32) & 0x7F) << 8);
            self.reg_write(reg, new_val)?;
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PHASE 2: Hardware init — WLAN reset + power on
    // ══════════════════════════════════════════════════════════════════════════

    fn wlan_reset(&self) -> Result<()> {
        let mut val = self.reg_read(MT_WLAN_FUN_CTRL)?;
        val &= !MT_FRC_WL_ANT_SEL;

        if val & MT_WLAN_EN != 0 {
            val |= MT_WLAN_RESET_RF;
            self.reg_write(MT_WLAN_FUN_CTRL, val)?;
            thread::sleep(Duration::from_micros(20));
            val &= !MT_WLAN_RESET_RF;
            self.reg_write(MT_WLAN_FUN_CTRL, val)?;
        }

        self.reg_write(MT_WLAN_FUN_CTRL, val)?;
        thread::sleep(Duration::from_micros(20));

        // Enable WLAN
        val |= MT_WLAN_EN | MT_WLAN_CLK_EN;
        self.reg_write(MT_WLAN_FUN_CTRL, val)?;
        thread::sleep(Duration::from_micros(20));

        Ok(())
    }

    /// RF patch — writes to GLOBAL registers (NOT per-unit). Called once from power_on_rf.
    /// Linux: mt76x2u_power_on_rf_patch() in usb_init.c:28-46
    fn power_on_rf_patch(&self) -> Result<()> {
        self.reg_set(CFG_RF_BG_0, (1 << 0) | (1 << 16))?;
        thread::sleep(Duration::from_micros(1));

        self.reg_clear(CFG_XO_1C, 0xFF)?;
        self.reg_set(CFG_XO_1C, 0x30)?;

        self.reg_write(CFG_XO_14, 0x484f)?;
        thread::sleep(Duration::from_micros(1));

        self.reg_set(CFG_RF_BG_0, 1 << 17)?;
        thread::sleep(Duration::from_micros(175));

        self.reg_clear(CFG_RF_BG_0, 1 << 16)?;
        thread::sleep(Duration::from_micros(75));

        self.reg_set(CFG_RF_BG_1, (1 << 19) | (1 << 20))?;
        Ok(())
    }

    /// Power on one RF unit. Linux: mt76x2u_power_on_rf() in usb_init.c:48-68
    fn power_on_rf(&self, unit: u8) -> Result<()> {
        let shift = if unit == 0 { 0 } else { 8 };
        let val = ((1 << 1) | (1 << 3) | (1 << 4) | (1 << 5)) << shift;

        // Enable RF BG
        self.reg_set(CFG_RF_BG_0, 1 << shift)?;
        thread::sleep(Duration::from_micros(15));

        // Enable RFDIG LDO/AFE/ABB/ADDA
        self.reg_set(CFG_RF_BG_0, val)?;
        thread::sleep(Duration::from_micros(15));

        // Switch to internal LDO (clear bit 2)
        self.reg_clear(CFG_RF_BG_0, (1 << 2) << shift)?;
        thread::sleep(Duration::from_micros(15));

        // Global RF patch (same for both units)
        self.power_on_rf_patch()?;

        // Set bits[3:0] at 0x530
        self.reg_set(0x0530, 0xF)?;

        Ok(())
    }

    fn power_on(&self) -> Result<()> {

        // Turn on WL MTCMOS
        self.reg_set(CFG_PMU, 1)?;

        // Poll for power up
        let mask = CFG_PMU_STATE_UP | CFG_PMU_PWR_ACK | CFG_PMU_PWR_ACK_S;
        self.poll_reg(CFG_PMU, mask, mask, Duration::from_millis(100))?;

        // Clear power bits
        let mut val = self.reg_read(CFG_PMU)?;
        val &= !(0x7F << 16); // clear bits[22:16]
        self.reg_write(CFG_PMU, val)?;
        thread::sleep(Duration::from_micros(15));

        val &= !(0xF << 24); // clear bits[27:24]
        self.reg_write(CFG_PMU, val)?;
        thread::sleep(Duration::from_micros(15));

        val |= 0xF << 24; // set bits[27:24]
        self.reg_write(CFG_PMU, val)?;

        val &= !0xFFF; // clear bits[11:0]
        self.reg_write(CFG_PMU, val)?;

        // Clear AD/DA power down
        self.reg_clear(CFG_AD_CTRL, 1 << 3)?;

        // Enable WLAN function
        self.reg_set(CFG_FUN_CTRL, 1)?;

        // Release BBP software reset
        self.reg_clear(CFG_CLKCTL, 1 << 18)?;

        // Power on RF units
        self.power_on_rf(0)?;
        self.power_on_rf(1)?;

        Ok(())
    }

    fn wait_for_mac(&self) -> Result<()> {
        for _i in 0..500 {
            let val = self.reg_read(MT_MAC_CSR0)?;
            if val != 0 && val != 0xFFFFFFFF {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err(Error::ChipInitFailed {
            chip: "MT7612U".into(),
            stage: crate::core::error::InitStage::RegisterAccess,
            reason: "MAC not ready after 500 polls".into(),
        })
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PHASE 3: Firmware load
    // ══════════════════════════════════════════════════════════════════════════

    fn setup_fce_for_dma(&self) -> Result<()> {
        self.reg_write(MT_FCE_PSE_CTRL, 0x01)?;
        self.reg_write(MT_TX_CPU_FROM_FCE_BASE_PTR, 0x400230)?;
        self.reg_write(MT_TX_CPU_FROM_FCE_MAX_COUNT, 0x01)?;
        self.reg_write(MT_FCE_PDMA_GLOBAL_CONF, 0x44)?;
        self.reg_write(MT_FCE_SKIP_FS, 0x03)?;
        Ok(())
    }

    fn enable_usb_dma(&self) -> Result<()> {
        // Match init_dma() values: aggregation enabled for USB 2.0 HS
        let val: u32 = 0x80                     // RxBulkAggTOut = 0x80
            | (21 << 8)                          // RxBulkAggLmt = 21
            | CFG_USB_DMA_RX_DROP_OR_PAD         // bit 18
            | CFG_USB_DMA_RX_BULK_AGG_EN         // bit 21
            | CFG_USB_DMA_RX_BULK_EN             // bit 22
            | CFG_USB_DMA_TX_BULK_EN;            // bit 23
        self.reg_write(CFG_USB_DMA, val)?;
        // Also write to MMIO register
        self.reg_write(MT_USB_DMA_CFG, val)?;
        Ok(())
    }

    /// Upload firmware data to device via FCE DMA
    /// Matches __mt76x02u_mcu_fw_send_data from Linux:
    ///   - TXINFO has PORT=CPU_TX_PORT(2), LEN=data_len, TYPE=CMD — NO seq/cmd_id
    ///   - FCE DMA addr/len set via MT_VEND_WRITE_FCE
    ///   - CPU_DESC_IDX incremented after each chunk
    fn upload_fw_data(&self, data: &[u8], dest_addr: u32, max_payload: usize) -> Result<()> {
        let max_data_per_chunk = max_payload - 8; // Linux: max_payload - 8

        let n_chunks = (data.len() + max_data_per_chunk - 1) / max_data_per_chunk;

        let mut offset = 0;
        let mut chunk_num = 0;
        while offset < data.len() {
            let chunk_len = std::cmp::min(data.len() - offset, max_data_per_chunk);
            let padded = (chunk_len + 3) & !3;

            // TXINFO: PORT=CPU_TX_PORT(2), LEN=chunk_len, TYPE=CMD
            let txinfo: u32 = (chunk_len as u32 & 0xFFFF) // bits[15:0] = length
                | (2u32 << 27)                              // bits[29:27] = CPU_TX_PORT
                | (1u32 << 30);                             // bit 30 = CMD type

            // Set FCE DMA destination address and length
            self.write_fce(0x0230, dest_addr + offset as u32)?;
            self.write_fce(0x0234, (padded as u32) << 16)?;

            // Build bulk transfer: [4B TXINFO][data][pad][4B zero]
            let total = 4 + padded + 4;
            let mut pkt = vec![0u8; total];
            pkt[0..4].copy_from_slice(&txinfo.to_le_bytes());
            pkt[4..4 + chunk_len].copy_from_slice(&data[offset..offset + chunk_len]);

            if chunk_num == 0 || chunk_num == n_chunks - 1 {
            }

            self.handle.write_bulk(self.ep_cmd_out, &pkt, Duration::from_secs(5))?;

            // Increment CPU descriptor index
            let idx = self.reg_read(MT_TX_CPU_FROM_FCE_CPU_DESC_IDX)?;
            self.reg_write(MT_TX_CPU_FROM_FCE_CPU_DESC_IDX, idx + 1)?;

            offset += chunk_len;
            chunk_num += 1;
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    fn load_rom_patch(&self) -> Result<()> {

        // Acquire semaphore
        let start = Instant::now();
        loop {
            let val = self.reg_read(MT_MCU_SEMAPHORE_03)?;
            if val & 1 != 0 { break; }
            if start.elapsed() > Duration::from_millis(600) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }

        // Check if patch already applied (E3+ uses clock_ctl bit 0, earlier uses com_reg0 bit 1)
        let asic = self.asic_rev & 0xFFFF;
        let already_patched = if asic >= 0x22 {
            self.reg_read(MT_MCU_CLOCK_CTL)? & 1 != 0
        } else {
            self.reg_read(MT_MCU_COM_REG0)? & 2 != 0
        };

        if already_patched {
            // Release semaphore
            self.reg_write(MT_MCU_SEMAPHORE_03, 1)?;
            return Ok(());
        }

        // Load firmware file
        let fw_path = "firmware/mt7662u_rom_patch.bin";
        let fw_data = std::fs::read(fw_path).map_err(|e| Error::ChipInitFailed {
            chip: "MT7612U".into(),
            stage: crate::core::error::InitStage::FirmwareDownload,
            reason: format!("Failed to read {}: {}", fw_path, e),
        })?;


        // Enable USB DMA
        self.enable_usb_dma()?;

        // Vendor FW reset
        self.vendor_dev_mode(0x01, &[])?;
        thread::sleep(Duration::from_millis(7));

        // Setup FCE
        self.setup_fce_for_dma()?;

        // Upload patch data (skip 32-byte header)
        let patch_data = if fw_data.len() > 32 { &fw_data[32..] } else { &fw_data };
        self.upload_fw_data(patch_data, MT76U_MCU_ROM_PATCH_OFFSET, 2048)?;

        // Enable patch via WMT command
        let enable_cmd: [u8; 11] = [0x6f, 0xfc, 0x08, 0x01, 0x20, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00];
        self.handle.write_control(
            0x21, // USB_DIR_OUT | USB_TYPE_CLASS
            MT_VEND_DEV_MODE,
            0x12, 0,
            &enable_cmd,
            USB_TIMEOUT,
        )?;

        // Reset WMT
        let reset_cmd: [u8; 8] = [0x6f, 0xfc, 0x05, 0x01, 0x07, 0x01, 0x00, 0x04];
        self.handle.write_control(
            0x21,
            MT_VEND_DEV_MODE,
            0x12, 0,
            &reset_cmd,
            USB_TIMEOUT,
        )?;
        thread::sleep(Duration::from_millis(20));

        // Verify patch applied
        let check_reg = if asic >= 0x22 { MT_MCU_CLOCK_CTL } else { MT_MCU_COM_REG0 };
        let check_mask = if asic >= 0x22 { 1 } else { 2 };
        let _ = self.poll_reg(check_reg, check_mask, check_mask, Duration::from_millis(100));

        // Release semaphore
        self.reg_write(MT_MCU_SEMAPHORE_03, 1)?;
        Ok(())
    }

    fn load_firmware(&mut self) -> Result<()> {

        let fw_path = "firmware/mt7662u.bin";
        let fw_data = std::fs::read(fw_path).map_err(|e| Error::ChipInitFailed {
            chip: "MT7612U".into(),
            stage: crate::core::error::InitStage::FirmwareDownload,
            reason: format!("Failed to read {}: {}", fw_path, e),
        })?;

        if fw_data.len() < 32 {
            return Err(Error::ChipInitFailed {
                chip: "MT7612U".into(),
                stage: crate::core::error::InitStage::FirmwareDownload,
                reason: "Firmware too small".into(),
            });
        }

        // Parse header (32 bytes)
        let ilm_len = u32::from_le_bytes([fw_data[0], fw_data[1], fw_data[2], fw_data[3]]) as usize;
        let dlm_len = u32::from_le_bytes([fw_data[4], fw_data[5], fw_data[6], fw_data[7]]) as usize;
        let _fw_ver = u16::from_le_bytes([fw_data[10], fw_data[11]]);
        let _build_ver = u16::from_le_bytes([fw_data[8], fw_data[9]]);
        let _build_time = std::str::from_utf8(&fw_data[16..32]).unwrap_or("?");


        let header_size = 32;
        let ilm_end = header_size + ilm_len;
        let dlm_end = ilm_end + dlm_len;

        if dlm_end > fw_data.len() {
            return Err(Error::ChipInitFailed {
                chip: "MT7612U".into(),
                stage: crate::core::error::InitStage::FirmwareDownload,
                reason: format!("FW data too short: need {} have {}", dlm_end, fw_data.len()),
            });
        }

        // Vendor FW reset
        self.vendor_dev_mode(0x01, &[])?;
        thread::sleep(Duration::from_millis(7));

        // Enable USB DMA + setup FCE
        self.enable_usb_dma()?;
        self.setup_fce_for_dma()?;

        // Upload ILM
        self.upload_fw_data(&fw_data[header_size..ilm_end], MT76U_MCU_ILM_OFFSET, 0x3900)?;

        // Upload DLM (E3+ uses different offset)
        let dlm_offset = if (self.asic_rev & 0xFFFF) >= 0x22 {
            MT76U_MCU_DLM_OFFSET_E3
        } else {
            MT76U_MCU_DLM_OFFSET
        };
        self.upload_fw_data(&fw_data[ilm_end..dlm_end], dlm_offset, 0x3900)?;

        // Load IVB (start firmware)
        self.handle.write_control(
            0x40, // USB_DIR_OUT | USB_TYPE_VENDOR
            MT_VEND_DEV_MODE,
            0x12, 0,
            &[],
            USB_TIMEOUT,
        )?;

        // Wait for FW start
        self.poll_reg(MT_MCU_COM_REG0, 1, 1, Duration::from_millis(1000))?;

        // Set COM_REG0 bit 1
        self.reg_set(MT_MCU_COM_REG0, 2)?;

        // Re-enable FCE
        self.reg_write(MT_FCE_PSE_CTRL, 0x01)?;

        self.fw_loaded = true;
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PHASE 4-5: MCU init + MAC init
    // ══════════════════════════════════════════════════════════════════════════

    fn mcu_init(&mut self) -> Result<()> {
        // Flush any stale MCU responses from previous session
        let mut flush_buf = [0u8; 1024];
        for _ in 0..5 {
            match self.handle.read_bulk(self.ep_cmd_resp_in, &mut flush_buf, Duration::from_millis(50)) {
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        // Function select: Q_SELECT
        // Linux sends with seq=0 (no response wait) — confirmed via usbmon capture
        let mut payload = [0u8; 8];
        payload[0..4].copy_from_slice(&FUN_SET_Q_SELECT.to_le_bytes());
        payload[4..8].copy_from_slice(&1u32.to_le_bytes());
        self.mcu_send_cmd(CMD_FUN_SET_OP, &payload, false)?;

        // Radio ON
        // Linux sends with seq=0 (no response wait) — confirmed via usbmon capture
        let mut payload = [0u8; 8];
        payload[0..4].copy_from_slice(&RADIO_ON.to_le_bytes());
        payload[4..8].copy_from_slice(&0u32.to_le_bytes());
        self.mcu_send_cmd(CMD_POWER_SAVING_OP, &payload, false)?;

        Ok(())
    }

    fn init_dma(&self) -> Result<()> {
        // Use kernel's minimal DMA during init (no aggregation).
        // We enable aggregation AFTER init completes — see end of init().
        // Kernel doesn't need AGG (128 async URBs), but we DO (userspace sync reads).
        let val: u32 = 0x00c40020;
        self.reg_write(CFG_USB_DMA, val)?;

        // ALSO write to MMIO register 0x0238 — on macOS, CFG space writes
        // may not propagate to the hardware DMA controller
        self.reg_write(MT_USB_DMA_CFG, val)?;

        Ok(())
    }

    fn mac_init(&self) -> Result<()> {

        // WPDMA config
        self.reg_write(MT_WPDMA_GLO_CFG, 0x30)?; // BIT(4) | BIT(5)

        // PBF init
        self.reg_write(MT_PBF_TX_MAX_PCNT, 0xefef3f1f)?;
        self.reg_write(MT_PBF_RX_MAX_PCNT, 0x0000febf)?;

        // Bulk register init — the massive table from Linux mt76_write_mac_initvals
        let init_vals: &[(u32, u32)] = &[
            (MT_PBF_SYS_CTRL,        0x00080c00),
            (MT_PBF_CFG,              0x1efebcff),
            (MT_FCE_PSE_CTRL,         0x00000001),
            (MT_MAC_SYS_CTRL,         0x00000000),
            (MT_MAX_LEN_CFG,          0x003e3f00),
            (MT_AMPDU_MAX_LEN_20M1S,  0xaaa99887),
            (MT_AMPDU_MAX_LEN_20M2S,  0x000000aa),
            (MT_XIFS_TIME_CFG,        0x33a40d0a),
            (MT_BKOFF_SLOT_CFG,       0x00000209),
            (MT_TBTT_SYNC_CFG,        0x00422010),
            (MT_PWR_PIN_CFG,          0x00000000),
            (0x1238,                   0x001700c8),
            (MT_TX_SW_CFG0,           0x00101001),
            (MT_TX_SW_CFG1,           0x00010000),
            (MT_TX_SW_CFG2,           0x00000000),
            (MT_TXOP_CTRL_CFG,        0x0400583f),
            (MT_TX_RTS_CFG,           0x00ffff20),
            (MT_TX_TIMEOUT_CFG,       0x000a2290),
            (MT_TX_RETRY_CFG,         0x47f01f0f),
            (MT_EXP_ACK_TIME,         0x002c00dc),
            (MT_TX_PROT_CFG6,         0xe3f42004),
            (MT_TX_PROT_CFG7,         0xe3f42084),
            (MT_TX_PROT_CFG8,         0xe3f42104),
            (MT_PIFS_TX_CFG,          0x00060fff),
            (MT_RX_FILTR_CFG,         0x00015f97),
            (MT_LEGACY_BASIC_RATE,    0x0000017f),
            (MT_HT_BASIC_RATE,        0x00004003),
            (MT_PN_PAD_MODE,          0x00000003),
            (MT_TXOP_HLDR_ET,         0x00000002),
            (0x0a44,                   0x00000000),
            (MT_HEADER_TRANS_CTRL,    0x00000000),
            (MT_TSO_CTRL,             0x00000000),
            (MT_AUX_CLK_CFG,          0x00000000),
            (MT_DACCLK_EN_DLY_CFG,    0x00000000),
            (MT_TX_ALC_CFG_4,         0x00000000),
            (MT_TX_ALC_VGA3,          0x00000000),
            // TX power defaults
            (MT_TX_PWR_CFG_0,         0x3a3a3a3a),
            (MT_TX_PWR_CFG_0 + 4,     0x3a3a3a3a), // CFG_1
            (MT_TX_PWR_CFG_0 + 8,     0x3a3a3a3a), // CFG_2
            (MT_TX_PWR_CFG_0 + 12,    0x3a3a3a3a), // CFG_3
            (MT_TX_PWR_CFG_0 + 16,    0x3a3a3a3a), // CFG_4
            (0x13d4,                   0x3a3a3a3a), // CFG_7
            (0x13d8,                   0x0000003a), // CFG_8
            (0x13dc,                   0x0000003a), // CFG_9
            (MT_EFUSE_CTRL,           0x0000d000),
            (MT_PAUSE_ENABLE_CONTROL1, 0x0000000a),
            (MT_FCE_WLAN_FLOW_CTRL1,  0x60401c18),
            (MT_WPDMA_DELAY_INT_CFG,  0x94ff0000),
            (MT_TX_SW_CFG3,           0x00000004),
            (MT_HT_FBK_TO_LEGACY,     0x00001818),
            (MT_VHT_HT_FBK_CFG1,      0xedcba980),
            (MT_PROT_AUTO_TX_CFG,      0x00830083),
            (MT_HT_CTRL_CFG,          0x000001ff),
            (MT_TX_LINK_CFG,          0x00001020),
        ];

        for &(reg, val) in init_vals {
            self.reg_write(reg, val)?;
        }

        // Protection configs — match kernel usbmon values exactly
        self.reg_write(MT_CCK_PROT_CFG,  0x07f40003)?;
        self.reg_write(MT_OFDM_PROT_CFG, 0x07f42004)?;
        self.reg_write(MT_MM20_PROT_CFG, 0x01752004)?;
        self.reg_write(MT_MM40_PROT_CFG, 0x03f52084)?;
        self.reg_write(MT_GF20_PROT_CFG, 0x01752004)?;
        self.reg_write(MT_GF40_PROT_CFG, 0x03f52084)?;

        // Additional MAC
        self.reg_write(MT_TX_LINK_CFG, 0x1020)?;
        self.reg_write(MT_AUTO_RSP_CFG, 0x13)?;
        self.reg_write(MT_MAX_LEN_CFG, 0x2f00)?;

        // WMM
        self.reg_write(MT_WMM_AIFSN, 0x2273)?;
        self.reg_write(MT_WMM_CWMIN, 0x2344)?;
        self.reg_write(MT_WMM_CWMAX, 0x34aa)?;

        // Clear MAC/BBP reset
        self.reg_clear(MT_MAC_SYS_CTRL, 0x3)?;

        // MT7612 specific: disable coex
        self.reg_clear(MT_COEXCFG0, 1)?;

        // Extended CCA
        self.reg_set(MT_EXT_CCA_CFG, 0xF000)?;

        // Clear TX ALC
        self.reg_clear(MT_TX_ALC_CFG_4, 1 << 31)?;

        Ok(())
    }

    fn mac_set_address(&self) -> Result<()> {
        let mac = self.mac_addr.as_bytes();
        let dw0 = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
        let dw1 = u16::from_le_bytes([mac[4], mac[5]]) as u32 | (0xFF << 16);

        self.reg_write(MT_MAC_ADDR_DW0, dw0)?;
        self.reg_write(MT_MAC_ADDR_DW1, dw1)?;
        self.reg_write(MT_MAC_BSSID_DW0, dw0)?;
        self.reg_write(MT_MAC_BSSID_DW1, dw1)?;

        Ok(())
    }

    fn crystal_fixup(&self) -> Result<()> {

        let trim2 = self.eeprom_u16(MT_EE_XTAL_TRIM_2);
        let offset = (trim2 & 0xFF) as i8;

        let xtal_val = if (trim2 >> 8) != 0xFF && (trim2 >> 8) != 0 {
            (trim2 >> 8) as u8
        } else {
            let trim1 = self.eeprom_u16(MT_EE_XTAL_TRIM_1);
            if (trim1 & 0xFF) != 0xFF && (trim1 & 0xFF) != 0 {
                (trim1 & 0xFF) as u8
            } else {
                0x14 // default
            }
        };

        let adjusted = (xtal_val as i16 + offset as i16).clamp(0, 0x7F) as u32;

        // Write to XO_CTRL5 bits[14:8]
        let mut val = self.reg_read(CFG_XO_CTRL5)?;
        val &= !(0x7F << 8);
        val |= adjusted << 8;
        self.reg_write(CFG_XO_CTRL5, val)?;

        // Set XO_CTRL6 bits[14:8]
        self.reg_set(CFG_XO_CTRL6, 0x7F << 8)?;

        // Timing adjustments
        self.reg_write(0x0504, 0x06000000)?;
        self.reg_write(0x050c, 0x08800000)?;
        thread::sleep(Duration::from_millis(5));
        self.reg_write(0x0504, 0)?;

        // Decrease OFDM SIFS to 13
        let mut val = self.reg_read(MT_XIFS_TIME_CFG)?;
        val &= !(0xFF << 8);
        val |= 0x0D << 8;
        self.reg_write(MT_XIFS_TIME_CFG, val)?;

        // CC_DELAY
        let mut val = self.reg_read(MT_BKOFF_SLOT_CFG)?;
        val &= !(0xF << 8);
        val |= 1 << 8;
        self.reg_write(MT_BKOFF_SLOT_CFG, val)?;

        // Disable WR_MPDU_LEN_EN
        self.reg_clear(MT_FCE_L2_STUFF, 1 << 4)?;

        // Crystal option from NIC_CONF_2
        let nic_conf_2 = self.eeprom_u16(MT_EE_NIC_CONF_2);
        let xtal_option = (nic_conf_2 >> 9) & 0x3;
        match xtal_option {
            0 => self.reg_write(CFG_XO_CTRL7, 0x5c1fee80)?,
            1 => self.reg_write(CFG_XO_CTRL7, 0x5c1feed0)?,
            _ => {} // use default
        }

        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PHASE 6-7: Post-init + start
    // ══════════════════════════════════════════════════════════════════════════

    fn init_rx_tx_paths(&mut self) -> Result<()> {
        // Load calibration registers — Linux: mt76x2_mcu_load_cr(dev, MT_RF_BBP_CR, 0, 0)
        // mcu.c:47-72 — struct has cr_mode, temp, ch, _pad, cfg (LE32)
        // cfg = BIT(31) | (NIC_CONF_0 >> 8) & 0xFF | (NIC_CONF_1 << 8) & 0xFF00
        let nic_conf_0 = self.eeprom_u16(MT_EE_NIC_CONF_0);
        let nic_conf_1 = self.eeprom_u16(MT_EE_NIC_CONF_1);
        let cfg: u32 = (1 << 31)
            | (((nic_conf_0 >> 8) as u32) & 0x00FF)
            | (((nic_conf_1 as u32) << 8) & 0xFF00);

        let mut payload = [0u8; 8];
        payload[0] = 2;  // cr_mode = MT_RF_BBP_CR
        payload[1] = 0;  // temp_level
        payload[2] = 0;  // channel
        payload[3] = 0;  // pad
        payload[4..8].copy_from_slice(&cfg.to_le_bytes());
        self.mcu_send_cmd(CMD_LOAD_CR, &payload, true)?;

        // Set RX path
        let mut agc0 = self.reg_read(MT_BBP_AGC0)?;
        if self.rx_paths >= 2 {
            agc0 |= 1 << 3;  // dual RX
        } else {
            agc0 &= !(1 << 3);
        }
        agc0 &= !(1 << 4);
        self.reg_write(MT_BBP_AGC0, agc0)?;

        // Set TX DAC
        let mut txbe5 = self.reg_read(MT_BBP_TXBE5)?;
        if self.tx_paths >= 2 {
            txbe5 |= 0x3; // dual TX
        } else {
            txbe5 &= !0x3;
        }
        self.reg_write(MT_BBP_TXBE5, txbe5)?;

        Ok(())
    }

    /// Stop TX+RX and wait for idle. Simplified sequence that works with USB.
    /// The full Linux mt76x2u_mac_stop polls many registers that may behave
    /// differently over USB vendor requests vs MMIO. Keep it simple but correct.
    /// Stop TX+RX — exact kernel usbmon sequence for channel switch.
    fn mac_stop(&self) -> Result<()> {
        // 1. RTS disable
        self.reg_write(MT_TX_RTS_CFG, 0x00ffff00)?;
        // 2. TXOP + TXOP_HLDR disable
        let txop = self.reg_read(MT_TXOP_CTRL_CFG).unwrap_or(0x04001b3f);
        self.reg_write(MT_TXOP_CTRL_CFG, txop)?;
        self.reg_write(MT_TXOP_HLDR_ET, 0x00000000)?;
        // 3. USB DMA settling — read CFG 12 times
        for _ in 0..12 { let _ = self.reg_read(CFG_USB_DMA); }
        // 4. TX STAT FIFO drain
        let _ = self.reg_read(0x0438);
        // 5. DMA watchdog reads
        let _ = self.reg_read(0x0a30);
        let _ = self.reg_read(0x0a34);
        // 6. Disable TX+RX
        self.reg_write(MT_MAC_SYS_CTRL, 0)?;
        // 7. MAC + BBP status check
        let _ = self.reg_read(MT_MAC_STATUS);
        let _ = self.reg_read(0x2130);
        // 8. DMA watchdog loop ×11
        for _ in 0..11 {
            let _ = self.reg_read(0x0430);
            let _ = self.reg_read(0x0a30);
            let _ = self.reg_read(0x0a34);
        }
        // 9. MAC STATUS again
        let _ = self.reg_read(MT_MAC_STATUS);
        // 10. USB DMA settling again
        for _ in 0..12 { let _ = self.reg_read(CFG_USB_DMA); }
        Ok(())
    }

    /// Start TX+RX — exact kernel usbmon sequence for channel switch.
    fn mac_start(&self) -> Result<()> {
        // 1. RTS restore
        self.reg_write(MT_TX_RTS_CFG, 0x00ffff20)?;
        // 2. Reset all counters (read-to-clear)
        let _ = self.reg_read(MT_RX_STA_CNT0);
        let _ = self.reg_read(MT_RX_STA_CNT1);
        let _ = self.reg_read(MT_RX_STA_CNT2);
        let _ = self.reg_read(MT_TX_STA_CNT0);
        let _ = self.reg_read(MT_TX_STA_CNT1);
        let _ = self.reg_read(MT_TX_STA_CNT2);
        for i in 0..16u32 { let _ = self.reg_read(0x1720 + i * 4); }
        // 3. TX stat drain ×16
        for _ in 0..16 { let _ = self.reg_read(0x1718); }
        // 4. RX only first
        self.reg_write(MT_MAC_SYS_CTRL, MT_MAC_SYS_CTRL_ENABLE_TX)?;
        let _ = self.reg_read(MT_WPDMA_GLO_CFG);
        // 5. RX filter — use kernel's exact value, NOT self.rxfilter
        self.reg_write(MT_RX_FILTR_CFG, 0x00017f97)?;
        // 6. TX + RX on
        self.reg_write(MT_MAC_SYS_CTRL,
            MT_MAC_SYS_CTRL_ENABLE_TX | MT_MAC_SYS_CTRL_ENABLE_RX)?;
        let _ = self.reg_read(MT_WPDMA_GLO_CFG);
        Ok(())
    }

    /// Reset WCID table (256 entries) and shared key table (16 vifs × 4 keys)
    /// Linux: usb_init.c:165-173
    fn reset_wcid_table(&self) -> Result<()> {
        // Clear WCID address table: 256 entries × 8 bytes at 0x1800
        for i in 0..256u32 {
            let addr = MT_WCID_ADDR_BASE + i * 8;
            self.reg_write(addr, 0)?;
            self.reg_write(addr + 4, 0)?;
        }

        // Clear WCID attribute table: 256 entries × 4 bytes at 0xa800
        // This is what the kernel trace shows (0xa800-0xabfc all zeroed)
        for i in 0..256u32 {
            self.reg_write(0xa800 + i * 4, 0)?;
        }

        // Shared key mode register: clear cipher for all 16 vifs × 4 keys
        for i in 0..16u32 {
            self.reg_write(0x7000 + i * 4, 0)?;
        }

        // Clear beacon offset table (kernel: 0xb000-0xb3fc, read-write pattern)
        // 5 groups × 8 entries: 0xb000, 0xb004, 0xb008, 0xb00c, 0xb3f0-0xb3fc
        for base in &[0xb000u32, 0xb004, 0xb008, 0xb00c, 0xb3f0, 0xb3f4, 0xb3f8, 0xb3fc] {
            for _ in 0..8 {
                let _ = self.reg_read(*base);
                self.reg_write(*base, 0)?;
            }
        }

        // Clear multicast filter (kernel zeros 0x1090-0x10cc twice)
        for _ in 0..2 {
            for addr in (0x1090..=0x10cc).step_by(4) {
                self.reg_write(addr, 0)?;
                let _ = self.reg_read(addr + 4);
                self.reg_write(addr + 4, 0)?;
            }
        }

        Ok(())
    }

    /// Init beacon config. Linux: mt76x02u_init_beacon_config()
    fn init_beacon_config(&self) -> Result<()> {
        // Disable beacon timer, TBTT, beacon TX
        let mt_beacon_time_cfg: u32 = 0x1114;
        let timer_en = 1 << 16;
        let tbtt_en = 1 << 19;
        let beacon_tx = 1 << 20;
        let sync_mode = 0x3 << 17; // sync mode bits
        self.reg_clear(mt_beacon_time_cfg, timer_en | tbtt_en | beacon_tx)?;
        self.reg_set(mt_beacon_time_cfg, sync_mode)?;
        // BCN bypass mask
        self.reg_write(0x108c, 0xFFFF)?;
        Ok(())
    }

    fn set_monitor_mode_internal(&mut self) -> Result<()> {
        // Monitor mode: accept ALL frames including other BSS traffic
        // Bit 2 = PROMISC (accept non-matching DA)
        // Bit 3 = OTHER_BSS (accept frames from other BSSIDs) — CRITICAL for scanning
        self.rxfilter |= MT_RX_FILTR_CFG_PROMISC | MT_RX_FILTR_CFG_OTHER_BSS;
        self.reg_write(MT_RX_FILTR_CFG, self.rxfilter)?;
        Ok(())
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Channel switch
    // ══════════════════════════════════════════════════════════════════════════

    /// Full channel switch matching Linux mt76x2u_phy_set_channel() exactly.
    /// Every register, every MCU command, every calibration — in the right order.
    fn switch_channel_internal(&mut self, ch: u8) -> Result<()> {

        // Linux: mt76x2u_set_channel calls mac_stop BEFORE phy_set_channel
        // The MAC must be stopped during register writes and calibrations
        self.mac_stop()?;

        let band_5g = is_5ghz(ch);
        let ext_pa = self.ext_pa_enabled(band_5g);
        self.cal.channel_cal_done = false;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 1: Read EEPROM RX gain for this channel
        //  Linux: mt76x2_read_rx_gain(dev)  — usb_phy.c:121
        // ══════════════════════════════════════════════════════════════════════
        self.read_rx_gain(ch, band_5g);

        // ══════════════════════════════════════════════════════════════════════
        //  Step 2: TX power register config
        //  Linux: mt76x2_phy_set_txpower_regs(dev, chan->band)  — phy.c:45-115
        // ══════════════════════════════════════════════════════════════════════
        self.phy_set_txpower_regs(band_5g)?;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 3: TX delay config
        //  Linux: mt76x2_configure_tx_delay(dev, chan->band, bw)  — phy.c:184-200
        // ══════════════════════════════════════════════════════════════════════
        let bw: u8 = 0; // 20MHz
        let (sw_cfg0, sw_cfg1) = if ext_pa {
            if bw != 0 { (0x000b0c01u32, 0x00011414u32) }
            else { (0x00101101u32, 0x00011414u32) }
        } else {
            if bw != 0 { (0x000b0b01u32, 0x00021414u32) }
            else { (0x00101001u32, 0x00021414u32) }
        };
        self.reg_write(MT_TX_SW_CFG0, sw_cfg0)?;
        self.reg_write(MT_TX_SW_CFG1, sw_cfg1)?;
        // OFDM SIFS = 15 (Linux line 199)
        let mut xifs = self.reg_read(MT_XIFS_TIME_CFG)?;
        xifs &= !(0xFF << 8);
        xifs |= 15 << 8;
        self.reg_write(MT_XIFS_TIME_CFG, xifs)?;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 4: Set TX power using EEPROM data
        //  Linux: mt76x2_phy_set_txpower(dev)  — phy.c:137-181
        // ══════════════════════════════════════════════════════════════════════
        self.phy_set_txpower(ch, band_5g)?;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 5: Set band
        //  Linux: mt76x02_phy_set_band(dev, chan->band, ch_group_index & 1)
        //  — mt76x02_phy.c:150-167
        // ══════════════════════════════════════════════════════════════════════
        if band_5g {
            self.reg_clear(MT_TX_BAND_CFG, 1 << 2)?; // clear 2G
            self.reg_set(MT_TX_BAND_CFG, 1 << 1)?;   // set 5G
        } else {
            self.reg_set(MT_TX_BAND_CFG, 1 << 2)?;   // set 2G
            self.reg_clear(MT_TX_BAND_CFG, 1 << 1)?;  // clear 5G
        }
        // primary_upper = false for 20MHz (ch_group_index & 1 = 0)
        let mut band_cfg = self.reg_read(MT_TX_BAND_CFG)?;
        band_cfg &= !(1 << 0); // upper_40m = 0
        self.reg_write(MT_TX_BAND_CFG, band_cfg)?;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 6: Set bandwidth 20MHz
        //  Linux: mt76x02_phy_set_bw(dev, width, ch_group_index)
        //  — mt76x02_phy.c:124-148
        // ══════════════════════════════════════════════════════════════════════
        // For 20MHz: core_val=0, agc_val=1, ctrl=0
        let mut core1 = self.reg_read(MT_BBP_CORE1)?;
        core1 &= !(0x3 << 3);  // CORE_R1_BW = 0
        self.reg_write(MT_BBP_CORE1, core1)?;

        let mut agc0 = self.reg_read(MT_BBP_AGC0)?;
        agc0 &= !(0x7 << 12); // AGC_R0_BW = 1
        agc0 |= 1 << 12;
        agc0 &= !(0x3 << 8);  // AGC_R0_CTRL_CHAN = 0
        self.reg_write(MT_BBP_AGC0, agc0)?;

        let mut txbe0 = self.reg_read(MT_BBP_TXBE0)?;
        txbe0 &= !0x3; // TXBE_R0_CTRL_CHAN = 0
        self.reg_write(MT_BBP_TXBE0, txbe0)?;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 7: EXT_CCA config
        //  Linux: ext_cca_chan[ch_group_index]  — usb_phy.c:63-84, line 129-135
        // ══════════════════════════════════════════════════════════════════════
        // For 20MHz, ch_group_index=0: CCA0=0,CCA1=1,CCA2=2,CCA3=3,MASK=BIT(0)
        let ext_cca: u32 = (0 << 0) | (1 << 2) | (2 << 4) | (3 << 6) | (1 << 8);
        let mut cca_cfg = self.reg_read(MT_EXT_CCA_CFG)?;
        cca_cfg &= !(0x3FF | (0xF << 8)); // clear CCA0-3 + CCA_MASK
        cca_cfg |= ext_cca;
        self.reg_write(MT_EXT_CCA_CFG, cca_cfg)?;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 8: MCU channel switch × 2
        //  Linux: mt76x2_mcu_set_channel(dev, channel, bw, bw_index, scan)
        //  — mcu.c:15-44  (called TWICE: first without ext_chan, then with)
        // ══════════════════════════════════════════════════════════════════════
        // Linux struct layout (8 bytes, packed, aligned(4)):
        //   u8 idx, u8 scan, u8 bw, u8 _pad0,
        //   u16 chainmask, u8 ext_chan, u8 _pad1
        let mut payload = [0u8; 8];
        payload[0] = ch;        // idx
        payload[1] = 0;         // scan = false
        payload[2] = 0;         // bw = 0 (20MHz)
        payload[3] = 0;         // pad
        payload[4..6].copy_from_slice(&self.chainmask.to_le_bytes()); // chainmask
        payload[6] = 0;         // ext_chan = 0 (first call)
        payload[7] = 0;         // pad

        // First call: without extension channel info
        self.mcu_send_cmd(CMD_SWITCH_CHANNEL_OP, &payload, true)?;
        thread::sleep(Duration::from_millis(5)); // Linux: usleep_range(5000, 10000)

        // Second call: with ext_chan = 0xE0 + bw_index (for 20MHz: 0xE0)
        payload[6] = 0xE0;      // ext_chan = 0xE0 + 0 (bw_index=0 for 20MHz)
        self.mcu_send_cmd(CMD_SWITCH_CHANNEL_OP, &payload, true)?;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 9: MCU init gain (using EEPROM-derived mcu_gain)
        //  Linux: mt76x2_mcu_init_gain(dev, channel, dev->cal.rx.mcu_gain, true)
        //  — mcu.c:75-92
        // ══════════════════════════════════════════════════════════════════════
        let mut gain_p = [0u8; 8];
        let ch_with_force = (ch as u32) | (1 << 31); // force=true → set BIT(31)
        gain_p[0..4].copy_from_slice(&ch_with_force.to_le_bytes());
        gain_p[4..8].copy_from_slice(&self.cal.rx.mcu_gain.to_le_bytes());
        self.mcu_send_cmd(CMD_INIT_GAIN_OP, &gain_p, true)?;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 10: LDPC RX enable for rev >= E3
        //  Linux: usb_phy.c:144-145
        // ══════════════════════════════════════════════════════════════════════
        if (self.asic_rev & 0xFFFF) >= 0x0022 {
            self.reg_set(MT_BBP_RXO13, 1 << 10)?;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  Step 11: Initial calibrations (first channel switch only)
        //  Linux: usb_phy.c:147-159
        // ══════════════════════════════════════════════════════════════════════
        if !self.cal.init_cal_done {
            let bt_rcal = self.eeprom_u8(MT_EE_BT_RCAL_RESULT);
            if bt_rcal != 0xFF {
                self.mcu_calibrate(MCU_CAL_R, 0)?;
            }
        }
        // Try calibrations with response waiting. If EP 0x85 dies, fall back
        // to fire-and-forget. The MCU needs these to calibrate the radio properly.
        let _ = self.mcu_calibrate(MCU_CAL_RXDCOC, ch as u32);
        if !self.cal.init_cal_done {
            let _ = self.mcu_calibrate(MCU_CAL_RC, 0);
        }
        self.cal.init_cal_done = true;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 12: Post-MCU BBP register writes
        //  Linux: usb_phy.c:161-168
        // ══════════════════════════════════════════════════════════════════════
        let _ = self.reg_write(MT_BBP_AGC_BASE + (61 << 2), 0xff64a4e2); // AGC(61)
        let _ = self.reg_write(MT_BBP_AGC_BASE + (7 << 2),  0x08081010); // AGC(7)
        let _ = self.reg_write(MT_BBP_AGC_BASE + (11 << 2), 0x00000404); // AGC(11)
        let _ = self.reg_write(MT_BBP_AGC_BASE + (2 << 2),  0x00007070); // AGC(2)
        let _ = self.reg_write(MT_TXOP_CTRL_CFG, 0x04101b3f);
        let _ = self.reg_set(MT_BBP_TXO_BASE + (4 << 2), 1 << 25);      // TXO(4)
        let _ = self.reg_set(MT_BBP_RXO_BASE + (13 << 2), 1 << 8);       // RXO(13)

        // ══════════════════════════════════════════════════════════════════════
        //  Step 13: Channel calibration (mac stopped for cal)
        //  Linux: mt76x2u_phy_channel_calibrate(dev, true)  — usb_phy.c:10-39
        //  This is called with mac_stopped=true since we haven't started yet
        // ══════════════════════════════════════════════════════════════════════
        let is_5g_param = if band_5g { 1u32 } else { 0 };
        // All calibrations are non-fatal — MCU may timeout on USB but radio still works
        let cal_cmds: &[(u8, u32, &str)] = if band_5g {
            &[(MCU_CAL_LC, 0, "LC"), (MCU_CAL_TX_LOFT, 1, "TX_LOFT"),
              (MCU_CAL_TXIQ, 1, "TXIQ"), (MCU_CAL_RXIQC_FI, 1, "RXIQC_FI"),
              (MCU_CAL_TEMP_SENSOR, 0, "TEMP"), (MCU_CAL_TX_SHAPING, 0, "TX_SHAPE")]
        } else {
            &[(MCU_CAL_TX_LOFT, 0, "TX_LOFT"), (MCU_CAL_TXIQ, 0, "TXIQ"),
              (MCU_CAL_RXIQC_FI, 0, "RXIQC_FI"), (MCU_CAL_TEMP_SENSOR, 0, "TEMP"),
              (MCU_CAL_TX_SHAPING, 0, "TX_SHAPE")]
        };
        // Wait for each calibration response. Non-fatal — if USB pipe dies,
        // the MCU still executes the calibration, we just can't confirm it.
        for &(cal_id, param, _name) in cal_cmds {
            let _ = self.mcu_calibrate(cal_id, param);
        }

        // Apply gain adjustment AFTER calibration (Linux: usb_phy.c:36)
        if let Err(e) = self.apply_gain_adj() {
        }

        // EDCCA init (Linux: mt76x02_edcca_init) — set ED CCA threshold
        // For monitor mode we just clear it
        let _ = self.reg_write(MT_TXOP_CTRL_CFG, 0x04101b3f);

        self.cal.channel_cal_done = true;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 14: Init AGC gain (Linux: mt76x02_init_agc_gain — usb_phy.c:174)
        // ══════════════════════════════════════════════════════════════════════
        self.cal.agc_gain_init[0] = ((self.reg_read(MT_BBP_AGC_BASE + (8 << 2)).unwrap_or(0) >> 8) & 0x7F) as u8;
        self.cal.agc_gain_init[1] = ((self.reg_read(MT_BBP_AGC_BASE + (9 << 2)).unwrap_or(0) >> 8) & 0x7F) as u8;
        self.cal.agc_gain_cur = self.cal.agc_gain_init;
        self.cal.low_gain = -1;
        self.cal.gain_init_done = true;

        // ══════════════════════════════════════════════════════════════════════
        //  Step 15: TSSI init (Linux: usb_phy.c:176-196)
        // ══════════════════════════════════════════════════════════════════════
        if self.tssi_enabled() {
            let mt_tx_alc_cfg_1: u32 = 0x13b4;
            let _ = self.reg_rmw(mt_tx_alc_cfg_1, 0x3F, 0x38);
            let _ = self.reg_rmw(MT_TX_ALC_CFG_2, 0x3F, 0x38);

            let mut flag: u32 = 0;
            if band_5g { flag |= 1; }
            if ext_pa { flag |= 1 << 8; }
            if let Err(e) = self.mcu_calibrate(MCU_CAL_TSSI, flag) {
            } else {
                self.cal.tssi_cal_done = true;
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        //  Step 16: MAC start — enable TX+RX
        // ══════════════════════════════════════════════════════════════════════
        let _ = self.mac_start();

        self.current_channel = Channel {
            number: ch,
            band: if band_5g { Band::Band5g } else { Band::Band2g },
            bandwidth: crate::core::channel::Bandwidth::Bw20,
            center_freq_mhz: channel_to_freq(ch),
        };

        Ok(())
    }

    /// Set TX power registers based on band and ext_pa.
    /// Linux: mt76x2_phy_set_txpower_regs (phy.c:45-115)
    fn phy_set_txpower_regs(&self, is_5ghz: bool) -> Result<()> {
        let ext_pa = self.ext_pa_enabled(is_5ghz);

        let (pa_mode0, pa_mode1) = if !is_5ghz {
            (0x010055ffu32, 0x00550055u32)
        } else {
            (0x0000ffffu32, 0x00ff00ffu32)
        };

        if !is_5ghz {
            self.reg_write(MT_TX_ALC_CFG_2, 0x35160a00)?;
            self.reg_write(MT_TX_ALC_CFG_3, 0x35160a06)?;
            if ext_pa {
                self.reg_write(MT_RF_PA_MODE_ADJ0, 0x0000ec00)?;
                self.reg_write(MT_RF_PA_MODE_ADJ1, 0x0000ec00)?;
            } else {
                self.reg_write(MT_RF_PA_MODE_ADJ0, 0xf4000200)?;
                self.reg_write(MT_RF_PA_MODE_ADJ1, 0xfa000200)?;
            }
        } else {
            if ext_pa {
                self.reg_write(MT_TX_ALC_CFG_2, 0x2f0f0400)?;
                self.reg_write(MT_TX_ALC_CFG_3, 0x2f0f0476)?;
            } else {
                self.reg_write(MT_TX_ALC_CFG_2, 0x1b0f0400)?;
                self.reg_write(MT_TX_ALC_CFG_3, 0x1b0f0476)?;
            }
            let pa_mode_adj = if ext_pa { 0x04000000u32 } else { 0 };
            self.reg_write(MT_RF_PA_MODE_ADJ0, pa_mode_adj)?;
            self.reg_write(MT_RF_PA_MODE_ADJ1, pa_mode_adj)?;
        }

        self.reg_write(MT_BB_PA_MODE_CFG0, pa_mode0)?;
        self.reg_write(MT_BB_PA_MODE_CFG1, pa_mode1)?;
        self.reg_write(MT_RF_PA_MODE_CFG0, pa_mode0)?;
        self.reg_write(MT_RF_PA_MODE_CFG1, pa_mode1)?;

        // RF gain correction and ALC_CFG_4
        if ext_pa {
            let corr_val = if !is_5ghz { 0x3c3c023cu32 } else { 0x363c023cu32 };
            self.reg_write(MT_TX0_RF_GAIN_CORR, corr_val)?;
            self.reg_write(MT_TX1_RF_GAIN_CORR, corr_val)?;
            self.reg_write(MT_TX_ALC_CFG_4, 0x00001818)?;
        } else {
            if !is_5ghz {
                self.reg_write(MT_TX0_RF_GAIN_CORR, 0x0f3c3c3c)?;
                self.reg_write(MT_TX1_RF_GAIN_CORR, 0x0f3c3c3c)?;
                self.reg_write(MT_TX_ALC_CFG_4, 0x00000606)?;
            } else {
                self.reg_write(MT_TX0_RF_GAIN_CORR, 0x383c023c)?;
                self.reg_write(MT_TX1_RF_GAIN_CORR, 0x24282e28)?;
                self.reg_write(MT_TX_ALC_CFG_4, 0)?;
            }
        }

        Ok(())
    }

    /// Set TX power using EEPROM-derived per-chain/per-rate values.
    /// Linux: mt76x2_phy_set_txpower (phy.c:137-181)
    fn phy_set_txpower(&mut self, channel: u8, is_5ghz: bool) -> Result<()> {
        let txp = self.get_power_info(channel, is_5ghz);

        // BW delta (we use 20MHz, so delta=0)
        let delta: i8 = 0;

        let mut t = self.get_rate_power(is_5ghz);
        t.add_offset((txp.target_power as i8) + delta);
        t.limit(self.txpower_conf);

        let base_power = t.min_nonzero_power();
        let rate_delta = base_power - (txp.target_power as i8);

        let mut txp_0 = (txp.chain[0].target_power as i8) + txp.chain[0].delta + rate_delta;
        let mut txp_1 = (txp.chain[1].target_power as i8) + txp.chain[1].delta + rate_delta;

        let gain = std::cmp::min(txp_0, txp_1);
        if gain < 0 {
            t.add_offset(-gain); // can't use, compensate in rate power
            txp_0 -= gain;
            txp_1 -= gain;
        } else if gain > 0x2f {
            let excess = gain - 0x2f;
            t.add_offset(-excess);
            txp_0 = 0x2f;
            txp_1 = 0x2f;
        }

        t.add_offset(-base_power);
        self.target_power = txp.target_power as i8;
        self.target_power_delta[0] = txp_0 - (txp.chain[0].target_power as i8);
        self.target_power_delta[1] = txp_1 - (txp.chain[0].target_power as i8);
        self.rate_power = t.clone();

        // Write to hardware: Linux mt76x02_phy_set_txpower (mt76x02_phy.c:93-121)
        let mt_tx_alc_cfg_0: u32 = 0x13b0;
        // CH_INIT_0 in bits[5:0], CH_INIT_1 in bits[13:8]
        let mut alc0 = self.reg_read(mt_tx_alc_cfg_0)?;
        alc0 &= !0x3F3F;
        alc0 |= ((txp_0 as u8 as u32) & 0x3F) | (((txp_1 as u8 as u32) & 0x3F) << 8);
        self.reg_write(mt_tx_alc_cfg_0, alc0)?;

        // Write per-rate power to TX_PWR_CFG registers
        let tx_power_mask = |v1: i8, v2: i8, v3: i8, v4: i8| -> u32 {
            ((v1 as u8 as u32) & 0x3F)
            | (((v2 as u8 as u32) & 0x3F) << 8)
            | (((v3 as u8 as u32) & 0x3F) << 16)
            | (((v4 as u8 as u32) & 0x3F) << 24)
        };

        self.reg_write(0x1314, tx_power_mask(t.cck[0], t.cck[2], t.ofdm[0], t.ofdm[2]))?; // CFG_0
        self.reg_write(0x1318, tx_power_mask(t.ofdm[4], t.ofdm[6], t.ht[0], t.ht[2]))?;   // CFG_1
        self.reg_write(0x131c, tx_power_mask(t.ht[4], t.ht[6], t.ht[8], t.ht[10]))?;       // CFG_2
        self.reg_write(0x1320, tx_power_mask(t.ht[12], t.ht[14], t.ht[0], t.ht[2]))?;      // CFG_3
        self.reg_write(0x1324, tx_power_mask(t.ht[4], t.ht[6], 0, 0))?;                     // CFG_4
        self.reg_write(0x13d4, tx_power_mask(t.ofdm[7], t.vht[0], t.ht[7], t.vht[1]))?;    // CFG_7
        self.reg_write(0x13d8, tx_power_mask(t.ht[14], 0, t.vht[0], t.vht[1]))?;            // CFG_8
        self.reg_write(0x13dc, tx_power_mask(t.ht[7], 0, t.vht[0], t.vht[1]))?;             // CFG_9

        Ok(())
    }

    /// Helper: send MCU calibration command.
    /// Calibrations take much longer than regular commands — the MCU runs the
    /// calibration procedure before responding. We use a dedicated long-timeout
    /// send to avoid blocking subsequent commands.
    fn mcu_calibrate(&mut self, cal_id: u8, param: u32) -> Result<()> {
        let mut p = [0u8; 8];
        p[0..4].copy_from_slice(&(cal_id as u32).to_le_bytes());
        p[4..8].copy_from_slice(&param.to_le_bytes());
        match self.mcu_send_cmd_timeout(CMD_CALIBRATION_OP, &p, Duration::from_millis(5000)) {
            Ok(_) => Ok(()),
            Err(e) => {
                // Clear stalled endpoints to prevent cascading pipe errors
                let _ = self.handle.clear_halt(self.ep_cmd_resp_in);
                let _ = self.handle.clear_halt(self.ep_cmd_out);

                // Check if the response ended up on the data endpoint instead
                let mut probe = [0u8; 256];
                if let Ok(n) = self.handle.read_bulk(self.ep_data_in, &mut probe, Duration::from_millis(50)) {
                    if n >= 4 {
                        let w0 = u32::from_le_bytes([probe[0], probe[1], probe[2], probe[3]]);
                    }
                }
                // Also check cmd resp endpoint one more time
                if let Ok(n) = self.handle.read_bulk(self.ep_cmd_resp_in, &mut probe, Duration::from_millis(50)) {
                    if n >= 4 {
                        let w0 = u32::from_le_bytes([probe[0], probe[1], probe[2], probe[3]]);
                    }
                }
                Err(e)
            }
        }
    }

    /// Send MCU command with a custom response timeout (for calibration commands).
    fn mcu_send_cmd_timeout(&mut self, cmd_id: u8, payload: &[u8], timeout: Duration) -> Result<Option<Vec<u8>>> {
        let cmd_start = Instant::now();

        // Drain stale responses
        if self.mcu_seq > 0 {
            let mut drain_buf = [0u8; 1024];
            for _ in 0..10 {
                match self.handle.read_bulk(self.ep_cmd_resp_in, &mut drain_buf, Duration::from_millis(1)) {
                    Ok(n) if n > 0 => continue,
                    _ => break,
                }
            }
        }

        let seq = {
            self.mcu_seq = (self.mcu_seq % 15) + 1;
            self.mcu_seq
        };
        let payload_len = payload.len();
        let padded_len = (payload_len + 3) & !3;

        let txinfo: u32 = (padded_len as u32) & 0xFFFF
            | ((seq as u32) << 16)
            | ((cmd_id as u32) << 20)
            | MCU_TXINFO_PORT_CPU
            | MCU_TXINFO_TYPE_CMD;

        let total = 4 + padded_len + 4;
        let mut pkt = vec![0u8; total];
        pkt[0..4].copy_from_slice(&txinfo.to_le_bytes());
        pkt[4..4 + payload_len].copy_from_slice(payload);

        self.handle.write_bulk(self.ep_cmd_out, &pkt, USB_BULK_TIMEOUT)?;

        // Wait for response with the provided timeout (longer for calibrations)
        let mut resp = vec![0u8; 1024];
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Usb(rusb::Error::Timeout));
            }
            let read_timeout = std::cmp::min(remaining, Duration::from_millis(500));
            match self.handle.read_bulk(self.ep_cmd_resp_in, &mut resp, read_timeout) {
                Ok(n) if n >= 4 => {
                    let rxfce = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
                    let resp_seq = ((rxfce >> 16) & 0xF) as u8;
                    let evt_type = ((rxfce >> 20) & 0xF) as u8;
                    if resp_seq == seq && evt_type == MCU_RESP_EVT_CMD_DONE {
                        resp.truncate(n);
                        return Ok(Some(resp));
                    }
                    // Stale response, keep waiting
                    continue;
                }
                Ok(_) => continue,
                Err(rusb::Error::Timeout) => continue, // keep waiting until deadline
                Err(rusb::Error::Pipe) => {
                    // Endpoint stalled — clear halt and retry
                    let _ = self.handle.clear_halt(self.ep_cmd_resp_in);
                    continue;
                }
                Err(e) => return Err(Error::Usb(e)),
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  RX frame parsing
    // ══════════════════════════════════════════════════════════════════════════

    /// Parse one RX frame from aggregated USB data. Returns (frame, bytes_consumed).
    /// Format per frame: [4B DMA hdr: u16 dma_len, u16 pad] [32B RXWI] [MPDU] [4B RXINFO]
    fn parse_one_rx(&self, raw: &[u8]) -> Option<(RxFrame, usize)> {
        let min_len = DMA_HDR_LEN + RXWI_SIZE;
        if raw.len() < min_len {
            return None;
        }

        let dma_len = u16::from_le_bytes([raw[0], raw[1]]) as usize;
        if dma_len == 0 || DMA_HDR_LEN + dma_len > raw.len() {
            return None;
        }

        let rxwi = &raw[DMA_HDR_LEN..];
        if rxwi.len() < RXWI_SIZE {
            return None;
        }

        let ctl = u32::from_le_bytes([rxwi[4], rxwi[5], rxwi[6], rxwi[7]]);
        let mpdu_len = rxwi_mpdu_len(ctl);

        if mpdu_len == 0 || RXWI_SIZE + mpdu_len > dma_len {
            return None;
        }

        let rssi0 = rxwi_rssi0(&rxwi[12..16]);
        let rssi1 = rxwi_rssi1(&rxwi[12..16]);
        let rssi = std::cmp::max(rssi0, rssi1);

        let frame_start = DMA_HDR_LEN + RXWI_SIZE;
        let frame_data = &raw[frame_start..frame_start + mpdu_len];

        // Consumed: DMA_HDR + dma_len, 4-byte aligned for next frame
        let consumed = (DMA_HDR_LEN + dma_len + 3) & !3;

        Some((RxFrame {
            data: frame_data.to_vec(),
            rssi,
            channel: self.current_channel.number,
            band: match self.current_channel.band { Band::Band2g => 0, Band::Band5g => 1, Band::Band6g => 2 },
            timestamp: Duration::ZERO,
        }, consumed))
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Minimal init — for debugging. No calibrations, no EEPROM config.
    // ══════════════════════════════════════════════════════════════════════════

    /// Bare-bones init: firmware + MAC + monitor mode. No channel calibrations,
    /// no EEPROM-based PHY config, no BBP writes. Just get frames flowing.
    pub fn init_minimal(&mut self) -> Result<()> {
        self.asic_rev = self.reg_read(MT_ASIC_VERSION)?;

        self.wlan_reset()?;
        self.power_on()?;
        self.wait_for_mac()?;

        self.load_rom_patch()?;
        self.load_firmware()?;

        self.poll_reg(MT_WPDMA_GLO_CFG, MT_TX_DMA_BUSY | MT_RX_DMA_BUSY, 0,
            Duration::from_millis(100))?;
        self.wait_for_mac()?;

        self.init_dma()?;
        self.mcu_init()?;

        self.mac_init()?;
        self.read_eeprom()?;
        self.mac_set_address()?;
        self.crystal_fixup()?;

        self.rxfilter = self.reg_read(MT_RX_FILTR_CFG)?;

        let _ = self.poll_reg(MT_MAC_STATUS, 0x3, 0, Duration::from_millis(100));
        self.reset_wcid_table()?;
        self.init_beacon_config()?;
        self.reg_rmw(MT_US_CYC_CFG, 0xFF, 0x1e)?;
        self.reg_write(MT_TXOP_CTRL_CFG, 0x583f)?;
        self.init_rx_tx_paths()?;
        self.mac_stop()?;

        // mac_start
        self.mac_start()?;

        // Bare MCU channel switch to ch1 — NO calibrations, NO BBP writes
        self.bare_channel_switch(1)?;

        // Monitor mode
        self.rxfilter |= MT_RX_FILTR_CFG_PROMISC | MT_RX_FILTR_CFG_OTHER_BSS;
        self.reg_write(MT_RX_FILTR_CFG, self.rxfilter)?;

        Ok(())
    }

    /// Get shared USB device handle for multi-threaded reads
    pub fn get_handle(&self) -> Arc<DeviceHandle<GlobalContext>> {
        Arc::clone(&self.handle)
    }

    /// Get data IN endpoint address
    pub fn get_ep_data_in(&self) -> u8 {
        self.ep_data_in
    }

    /// Public register read for diagnostics
    pub fn reg_read_pub(&self, addr: u32) -> Result<u32> {
        self.reg_read(addr)
    }

    /// Public register write for diagnostics
    pub fn reg_write_pub(&self, addr: u32, val: u32) -> Result<()> {
        self.reg_write(addr, val)
    }

    /// Public MCU command for diagnostics/replay tests
    pub fn mcu_cmd_pub(&mut self, cmd_id: u8, payload: &[u8], wait_resp: bool) -> Result<()> {
        self.mcu_send_cmd(cmd_id, payload, wait_resp)?;
        Ok(())
    }

    /// Replay exact Linux kernel mt76x2u init sequence (post-firmware).
    /// Captured from usbmon on Asahi Linux — 660 register operations.
    /// Proven: 364 frames in 10s on macOS with this exact sequence.
    fn kernel_init_replay(&mut self) -> Result<()> {
        let w = |s: &Self, addr: u32, val: u32| -> Result<()> { s.reg_write(addr, val) };
        let cw = |s: &Self, addr: u32, val: u32| -> Result<()> { s.reg_write(0x4000_0000 | addr, val) };

        // === Post-firmware init ===
        w(self, 0x0730, 0x001140fb)?;
        w(self, 0x0800, 0x00000001)?;
        cw(self, 0x9018, 0x00c40020)?;  // DMA: no agg during init

        // MCU: Q_SELECT + RADIO_ON (no response wait, seq=0)
        self.mcu_send_cmd(0x01, &[0x01,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], false)?;
        self.mcu_send_cmd(0x14, &[0x31,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], false)?;

        // === mac_init table ===
        let mac_vals: &[(u32, u32)] = &[
            (0x0208, 0x00000030), (0x0408, 0xefef3f1f), (0x040c, 0x0000febf),
            (0x0400, 0x00080c00), (0x0404, 0x1efebcff), (0x0800, 0x00000001),
            (0x1004, 0x00000000), (0x1018, 0x003e3f00), (0x1030, 0xaaa99887),
            (0x1034, 0x000000aa), (0x1100, 0x33a40d0a), (0x1104, 0x00000209),
            (0x1118, 0x00422010), (0x1204, 0x00000000), (0x1238, 0x001700c8),
            (0x1330, 0x00101001), (0x1334, 0x00010000), (0x1338, 0x00000000),
            (0x1340, 0x0400583f), (0x1344, 0x00ffff20), (0x1348, 0x000a2290),
            (0x134c, 0x47f01f0f), (0x1380, 0x002c00dc), (0x13e0, 0xe3f42004),
            (0x13e4, 0xe3f42084), (0x13e8, 0xe3f42104), (0x13ec, 0x00060fff),
            (0x1400, 0x00015f97), (0x1408, 0x0000017f), (0x140c, 0x00004003),
            (0x150c, 0x00000003), (0x1608, 0x00000002), (0x0a44, 0x00000000),
            (0x0260, 0x00000000), (0x0250, 0x00000000), (0x120c, 0x00000000),
            (0x1264, 0x00000000), (0x13c0, 0x00000000), (0x13c8, 0x00000000),
            (0x1314, 0x3a3a3a3a), (0x1318, 0x3a3a3a3a), (0x131c, 0x3a3a3a3a),
            (0x1320, 0x3a3a3a3a), (0x1324, 0x3a3a3a3a), (0x13d4, 0x3a3a3a3a),
            (0x13d8, 0x0000003a), (0x13dc, 0x0000003a), (0x0024, 0x0000d000),
            (0x0a38, 0x0000000a), (0x0824, 0x60401c18), (0x0210, 0x94ff0000),
            (0x1478, 0x00000004), (0x1384, 0x00001818), (0x1358, 0xedcba980),
            (0x1648, 0x00830083), (0x1410, 0x000001ff), (0x1350, 0x00001020),
            (0x1364, 0x07f40003), (0x1368, 0x07f42004), (0x136c, 0x01752004),
            (0x1370, 0x03f52084), (0x1374, 0x01752004), (0x1378, 0x03f52084),
            (0x1350, 0x00001020), (0x1404, 0x00000013), (0x1018, 0x00002f00),
            (0x0214, 0x00002273), (0x0218, 0x00002344), (0x021c, 0x000034aa),
        ];
        for &(reg, val) in mac_vals { w(self, reg, val)?; }

        // === Crystal/timing fixup ===
        w(self, 0x1004, 0x00000000)?;
        w(self, 0x0040, 0x0000a046)?;
        w(self, 0x141c, 0x0000f1e4)?;
        w(self, 0x13c0, 0x00000000)?;
        cw(self, 0x0114, 0x00002400)?;
        cw(self, 0x0118, 0x00007f00)?;
        w(self, 0x0504, 0x06000000)?;
        w(self, 0x050c, 0x08800000)?;
        w(self, 0x0504, 0x00000000)?;
        w(self, 0x1100, 0x33a40d0a)?;
        w(self, 0x1104, 0x00000109)?;
        w(self, 0x080c, 0x03ff0223)?;

        // === MAC address (from EEPROM) ===
        let mac = self.mac_addr.as_bytes();
        let dw0 = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
        let dw1_mac = u16::from_le_bytes([mac[4], mac[5]]) as u32;
        w(self, 0x1008, dw0)?;
        w(self, 0x100c, 0x00ff0000 | dw1_mac)?;
        w(self, 0x1010, dw0)?;
        w(self, 0x1014, 0x00230000 | dw1_mac)?;
        w(self, 0x1014, 0x003f0000 | dw1_mac)?;

        // === Multicast filter clear (2x) ===
        for _ in 0..2 {
            for addr in (0x1090u32..=0x10cc).step_by(4) {
                w(self, addr, 0)?;
            }
        }

        // === WCID attribute table clear: 0xa800-0xabfc ===
        for addr in (0xa800u32..=0xabfc).step_by(4) {
            w(self, addr, 0)?;
        }

        // === Beacon buffer clear ===
        for base in [0xb000u32, 0xb004, 0xb008, 0xb00c, 0xb3f0, 0xb3f4, 0xb3f8, 0xb3fc] {
            for _ in 0..8 { w(self, base, 0)?; }
        }

        // === Beacon config + timing ===
        w(self, 0x1114, 0x00060640)?;
        w(self, 0x1114, 0x00060640)?;
        w(self, 0x108c, 0x0000ffff)?;
        w(self, 0x041c, 0x4b321900)?;
        w(self, 0x0420, 0x00000064)?;
        w(self, 0x0424, 0x00000000)?;
        w(self, 0x0428, 0x00000000)?;
        w(self, 0x02a4, 0x0000001e)?;
        w(self, 0x1340, 0x0000583f)?;

        // === LOAD_CR (MCU cmd 0x02, with response) ===
        self.mcu_send_cmd(0x02, &[0x02,0x00,0x00,0x00, 0xff,0x80,0x00,0x80, 0x00,0x00,0x00,0x00], true)?;

        // === RX/TX path config ===
        w(self, 0x2300, 0x00001408)?;
        w(self, 0x2714, 0x00000003)?;
        w(self, 0x1344, 0x00ffff00)?;
        w(self, 0x1340, 0x0000583f)?;
        w(self, 0x1608, 0x00000000)?;

        // === mac_stop + mac_start sequence ===
        w(self, 0x1004, 0x00000000)?;
        w(self, 0x1344, 0x00ffff20)?;
        w(self, 0x1004, 0x00000004)?;  // RX only
        w(self, 0x1400, 0x00015f97)?;  // RX filter
        w(self, 0x1004, 0x0000000c)?;  // RX + TX

        // === Channel 1 config (first channel) ===
        let ch1_vals: &[(u32, u32)] = &[
            (0x1364, 0x07f40003), (0x1368, 0x07f42004), (0x136c, 0x01742004),
            (0x1370, 0x03f42084), (0x1374, 0x01742004), (0x1378, 0x03f42084),
            (0x13e0, 0xe3f42004), (0x13e4, 0xe3f42084), (0x13e8, 0xe3f42104),
            (0x1404, 0x00000003), (0x1104, 0x00000114), (0x1348, 0x000a2190),
            (0x130c, 0x000a4200),
        ];
        for &(reg, val) in ch1_vals { w(self, reg, val)?; }

        // WMM per-AC config
        w(self, 0x0224, 0x00000000)?;
        w(self, 0x0214, 0x00002273)?; w(self, 0x0218, 0x00004344)?; w(self, 0x021c, 0x0000a4aa)?;
        w(self, 0x1308, 0x000a4200)?;
        w(self, 0x0224, 0x00000000)?;
        w(self, 0x0214, 0x00002273)?; w(self, 0x0218, 0x00004444)?; w(self, 0x021c, 0x0000aaaa)?;
        w(self, 0x1300, 0x000a4200)?;
        w(self, 0x0220, 0x00000000)?;
        w(self, 0x0214, 0x00002272)?; w(self, 0x0218, 0x00004444)?; w(self, 0x021c, 0x0000aaaa)?;
        w(self, 0x1304, 0x000a4200)?;
        w(self, 0x0220, 0x00000000)?;
        w(self, 0x0214, 0x00002222)?; w(self, 0x0218, 0x00004444)?; w(self, 0x021c, 0x0000aaaa)?;

        w(self, 0x1400, 0x00015f97)?;

        // TX power per rate
        w(self, 0x13b0, 0x2f2f1b1f)?; w(self, 0x13b0, 0x2f2f1f1f)?;
        w(self, 0x1314, 0x04070606)?; w(self, 0x1318, 0x04060202)?;
        w(self, 0x131c, 0x04060101)?; w(self, 0x1320, 0x04060101)?;
        w(self, 0x1324, 0x00000101)?;
        w(self, 0x13d4, 0x00010002)?; w(self, 0x13d8, 0x00000001)?; w(self, 0x13dc, 0x00000001)?;

        // === Calibration MCU commands ===
        w(self, 0x1340, 0x0000583f)?;
        w(self, 0x1608, 0x00000000)?;
        w(self, 0x1004, 0x00000000)?;
        w(self, 0x1344, 0x00ffff00)?;
        w(self, 0x1344, 0x00ffff20)?;

        // TSSI / AGC config
        w(self, 0x13a8, 0x35160a00)?; w(self, 0x13ac, 0x35160a06)?;
        w(self, 0x1228, 0xf4000200)?; w(self, 0x122c, 0xfa000200)?;
        w(self, 0x1214, 0x010055ff)?; w(self, 0x1218, 0x00550055)?;
        w(self, 0x121c, 0x010055ff)?; w(self, 0x1220, 0x00550055)?;
        w(self, 0x13a0, 0x0f3c3c3c)?; w(self, 0x13a4, 0x0f3c3c3c)?;
        w(self, 0x13c0, 0x00000606)?;
        w(self, 0x1330, 0x00101001)?; w(self, 0x1334, 0x00021414)?;
        w(self, 0x1100, 0x33a40f0a)?;

        // TX power per rate (5GHz values from EEPROM)
        w(self, 0x13b0, 0x2f2f1f1b)?; w(self, 0x13b0, 0x2f2f1d1b)?;
        w(self, 0x1314, 0x05050505)?; w(self, 0x1318, 0x03050101)?;
        w(self, 0x131c, 0x03050000)?; w(self, 0x1320, 0x03050000)?;
        w(self, 0x1324, 0x00000000)?;
        w(self, 0x13d4, 0x01000101)?; w(self, 0x13d8, 0x01010000)?; w(self, 0x13dc, 0x01010000)?;

        // Band config
        w(self, 0x132c, 0x00000006)?; w(self, 0x132c, 0x00000004)?; w(self, 0x132c, 0x00000004)?;

        // BBP / AGC
        w(self, 0x2004, 0x00000042)?;
        w(self, 0x2300, 0x00001408)?; w(self, 0x2300, 0x00001408)?;
        w(self, 0x2700, 0x00000008)?;
        w(self, 0x141c, 0x0000f1e4)?;

        // === MCU calibration commands (ch_switch + calibrations) ===
        // CH_SWITCH (no ext_chan)
        self.mcu_send_cmd(0x1e, &[0x01,0x00,0x00,0x00, 0x02,0x02,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;
        // CH_SWITCH (ext_chan=0xE0)
        self.mcu_send_cmd(0x1e, &[0x01,0x00,0x00,0x00, 0x02,0x02,0xe0,0x00, 0x00,0x00,0x00,0x00], true)?;
        // INIT_GAIN
        self.mcu_send_cmd(0x03, &[0x01,0x00,0x00,0x80, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;

        w(self, 0x2934, 0x00000492)?;
        // RXDCOC
        self.mcu_send_cmd(0x1f, &[0x03,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;
        // RC cal
        self.mcu_send_cmd(0x1f, &[0x04,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;

        // Post-cal register config
        w(self, 0x23f4, 0xff64a4e2)?; w(self, 0x231c, 0x08081010)?;
        w(self, 0x232c, 0x00000404)?; w(self, 0x2308, 0x00007070)?;
        w(self, 0x1340, 0x04101b3f)?; w(self, 0x2610, 0x02000007)?;
        w(self, 0x2934, 0x00000592)?;

        // TX_LOFT, TXIQ, RXIQC_FI, TEMP, TX_SHAPE cals
        self.mcu_send_cmd(0x1f, &[0x07,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;
        self.mcu_send_cmd(0x1f, &[0x08,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;
        self.mcu_send_cmd(0x1f, &[0x0c,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;
        self.mcu_send_cmd(0x1f, &[0x02,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;
        self.mcu_send_cmd(0x1f, &[0x0f,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;

        // Post-calibration AGC/IQ — written by Linux kernel after MCU cals.
        // MCU calibrations above produce identical values, so these writes
        // are redundant but kept for fidelity with the captured sequence.
        w(self, 0x2310, 0x15e79544)?; w(self, 0x2314, 0x15e79544)?;
        w(self, 0x2320, 0x18365ef8)?; w(self, 0x2324, 0x18365ef8)?;

        // Final channel config
        w(self, 0x1350, 0x007f1020)?; w(self, 0x1340, 0x04001b3f)?;
        w(self, 0x2308, 0x00007070)?;
        w(self, 0x1608, 0x00000002)?;
        w(self, 0x1004, 0x00000004)?;
        w(self, 0x1404, 0x00000003)?;
        w(self, 0x1328, 0x33150f0f)?;
        w(self, 0x13b4, 0x89540038)?;
        w(self, 0x13a8, 0x35160a38)?;

        // TX_SHAPE cal
        self.mcu_send_cmd(0x1f, &[0x09,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00], true)?;

        w(self, 0x110c, 0x0000015f)?;
        w(self, 0x1004, 0x0000000c)?;  // TX + RX enabled
        w(self, 0x1400, 0x00017f97)?;  // Monitor-mode RX filter
        w(self, 0x1400, 0x00017f97)?;
        w(self, 0x1400, 0x00017f97)?;

        Ok(())
    }

    /// Load firmware only (no full init) — for kernel replay tests
    pub fn load_firmware_only(&mut self) -> Result<()> {
        self.asic_rev = self.reg_read(MT_ASIC_VERSION)?;
        self.wlan_reset()?;
        self.power_on()?;
        self.wait_for_mac()?;
        self.load_rom_patch()?;
        self.load_firmware()?;
        self.poll_reg(MT_WPDMA_GLO_CFG, MT_TX_DMA_BUSY | MT_RX_DMA_BUSY, 0,
            Duration::from_millis(100))?;
        self.wait_for_mac()?;
        self.fw_loaded = true;
        Ok(())
    }

    /// Raw bulk read for diagnostics — bypasses rx_frame parsing
    pub fn raw_bulk_read(&self, buf: &mut [u8], timeout: Duration) -> std::result::Result<usize, rusb::Error> {
        self.handle.read_bulk(self.ep_data_in, buf, timeout)
    }

    /// Bare MCU channel switch — just the two CH_SWITCH commands + INIT_GAIN.
    /// No calibrations, no BBP writes, no mac_stop/mac_start.
    /// Uses 300ms timeout per MCU command (fast scan mode).
    pub fn bare_channel_switch(&mut self, ch: u8) -> Result<()> {
        let fast = Duration::from_millis(300);

        // CH_SWITCH without ext_chan
        let mut payload = [0u8; 8];
        payload[0] = ch;
        payload[1] = if is_5ghz(ch) { 1 } else { 0 }; // band
        payload[2] = 0; // bw = 20MHz
        payload[3] = 0; // tx_stream = 0 (auto)
        payload[4] = 0; // rx_stream = 0 (auto)
        self.mcu_send_cmd_timeout(CMD_SWITCH_CHANNEL_OP, &payload, fast)?;

        // CH_SWITCH with ext_chan
        payload[6] = 0xE0;
        self.mcu_send_cmd_timeout(CMD_SWITCH_CHANNEL_OP, &payload, fast)?;

        // INIT_GAIN
        let mut gain_p = [0u8; 8];
        let ch_with_force = (ch as u32) | (1 << 31);
        gain_p[0..4].copy_from_slice(&ch_with_force.to_le_bytes());
        self.mcu_send_cmd_timeout(CMD_INIT_GAIN_OP, &gain_p, fast)?;

        self.current_channel = Channel {
            number: ch,
            band: if is_5ghz(ch) { Band::Band5g } else { Band::Band2g },
            bandwidth: crate::core::channel::Bandwidth::Bw20,
            center_freq_mhz: channel_to_freq(ch),
        };
        Ok(())
    }
}

/// Standalone RX parser for the pipeline's RxHandle.
///
/// Same logic as `Mt7612u::parse_one_rx` but takes `channel` as parameter
/// instead of reading from `self`, so it can be used as a `fn` pointer.
///
/// Format per frame: [4B DMA hdr: u16 dma_len, u16 pad] [32B RXWI] [MPDU] [4B RXINFO]
fn mt7612u_parse_rx(buf: &[u8], channel: u8) -> (usize, crate::core::chip::ParsedPacket) {
    let min_len = DMA_HDR_LEN + RXWI_SIZE;
    if buf.len() < min_len {
        return (0, crate::core::chip::ParsedPacket::Skip);
    }

    let dma_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if dma_len == 0 || DMA_HDR_LEN + dma_len > buf.len() {
        return (0, crate::core::chip::ParsedPacket::Skip);
    }

    let rxwi = &buf[DMA_HDR_LEN..];
    if rxwi.len() < RXWI_SIZE {
        return (0, crate::core::chip::ParsedPacket::Skip);
    }

    let ctl = u32::from_le_bytes([rxwi[4], rxwi[5], rxwi[6], rxwi[7]]);
    let mpdu_len = rxwi_mpdu_len(ctl);

    if mpdu_len == 0 || RXWI_SIZE + mpdu_len > dma_len {
        // Skip this chunk — advance past the DMA header to avoid infinite loop
        let consumed = (DMA_HDR_LEN + dma_len + 3) & !3;
        return (consumed, crate::core::chip::ParsedPacket::Skip);
    }

    let rssi0 = rxwi_rssi0(&rxwi[12..16]);
    let rssi1 = rxwi_rssi1(&rxwi[12..16]);
    let rssi = std::cmp::max(rssi0, rssi1);

    let frame_start = DMA_HDR_LEN + RXWI_SIZE;
    let frame_data = &buf[frame_start..frame_start + mpdu_len];

    // Consumed: DMA_HDR + dma_len, 4-byte aligned for next frame
    let consumed = (DMA_HDR_LEN + dma_len + 3) & !3;

    (consumed, crate::core::chip::ParsedPacket::Frame(RxFrame {
        data: frame_data.to_vec(),
        rssi,
        channel,
        band: if channel <= 14 { 0 } else { 1 },
        timestamp: Duration::ZERO,
    }))
}

// ══════════════════════════════════════════════════════════════════════════════
//  ChipDriver trait implementation
// ══════════════════════════════════════════════════════════════════════════════

impl ChipDriver for Mt7612u {
    fn init(&mut self) -> Result<()> {
        // ── Phase 1-3: Firmware load (our code, proven working) ──
        self.load_firmware_only()?;

        // Read EEPROM for MAC address (needed for mac_set_address later)
        self.read_eeprom()?;

        // ── Phase 4: Kernel init replay ──
        // Exact register sequence from Linux kernel mt76x2u driver, captured via
        // usbmon on Asahi Linux. This sequence is PROVEN to produce 364 frames/10s
        // on macOS. Every register, every value, every order — from the kernel.
        self.kernel_init_replay()?;

        // ── Phase 5: Enable RX aggregation for userspace ──
        // Kernel uses 128 async URBs so doesn't need aggregation.
        // We're in userspace with sync reads — AGG buffers frames for us.
        let agg_dma: u32 = 0xFF             // RxBulkAggTOut = 0xFF (~8.4µs, max)
            | (21 << 8)                      // RxBulkAggLmt = 21
            | (1 << 18)                      // RX_DROP_OR_PAD
            | (1 << 21)                      // RX_BULK_AGG_EN
            | (1 << 22)                      // RX_BULK_EN
            | (1 << 23);                     // TX_BULK_EN
        self.reg_write(CFG_USB_DMA, agg_dma)?;
        self.reg_write(MT_USB_DMA_CFG, agg_dma)?;
        let rb = self.reg_read(CFG_USB_DMA)?;

        // Save state for channel switching / monitor mode
        self.rxfilter = self.reg_read(MT_RX_FILTR_CFG).unwrap_or(0x00017f97);
        self.current_channel = Channel { number: 1, band: Band::Band2g, bandwidth: crate::core::channel::Bandwidth::Bw20, center_freq_mhz: 2412 };

        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        // Disable TX+RX
        self.reg_write(MT_MAC_SYS_CTRL, 0)?;
        let _ = self.handle.release_interface(self.iface_num);
        Ok(())
    }

    fn chip_info(&self) -> ChipInfo {
        ChipInfo {
            name: "MT7612U",
            chip: ChipId::Mt7612u,
            caps: ChipCaps::MONITOR | ChipCaps::INJECT | ChipCaps::BAND_2G | ChipCaps::BAND_5G
                | ChipCaps::HT | ChipCaps::VHT | ChipCaps::BW40 | ChipCaps::BW80 | ChipCaps::TX_POWER,
            vid: self.vid,
            pid: self.pid,
            rfe_type: 0,
            bands: vec![Band::Band2g, Band::Band5g],
            max_tx_power_dbm: 23,
            firmware_version: format!("rev:{:#06x}", self.asic_rev),
        }
    }

    fn set_channel(&mut self, channel: Channel) -> Result<()> {
        // Scan-mode channel switch: fast hop with minimal calibration.
        // Matches Linux behavior: during scanning, skip heavy TX/IQ cals.
        // Linux usb_phy.c:170: "if (scan) return 0;" — skips channel_calibrate.
        //
        // Fast path: mac_stop → CH_SWITCH + INIT_GAIN → RXDCOC → mac_start
        // Full calibration is done via calibrate_channel() when settling on a target.
        let ch = channel.number;

        self.mac_stop()?;
        self.bare_channel_switch(ch)?;

        // MCU_CAL_RXDCOC (3) — param = channel number. Essential for RX.
        // Use short timeout: if RXDCOC doesn't respond in 200ms, skip it.
        // The default mcu_calibrate uses 5000ms which kills scan performance.
        {
            let mut p = [0u8; 8];
            p[0..4].copy_from_slice(&3u32.to_le_bytes()); // CAL_RXDCOC
            p[4..8].copy_from_slice(&(ch as u32).to_le_bytes());
            if let Err(_) = self.mcu_send_cmd_timeout(CMD_CALIBRATION_OP, &p, Duration::from_millis(200)) {
                let _ = self.handle.clear_halt(self.ep_cmd_resp_in);
            }
        }

        self.mac_start()?;
        self.current_channel = channel;
        Ok(())
    }

    fn supported_channels(&self) -> &[Channel] {
        use crate::core::channel::Bandwidth;
        // Static channel list — 2.4 GHz + 5 GHz, 20 MHz BW
        // MT7612U is dual-band 2x2 MIMO
        static CHANNELS: std::sync::LazyLock<Vec<Channel>> = std::sync::LazyLock::new(|| {
            let mut chs = Vec::new();
            for &ch in CHANNELS_2GHZ {
                chs.push(Channel {
                    number: ch,
                    band: Band::Band2g,
                    bandwidth: Bandwidth::Bw20,
                    center_freq_mhz: channel_to_freq(ch),
                });
            }
            for &ch in CHANNELS_5GHZ {
                chs.push(Channel {
                    number: ch,
                    band: Band::Band5g,
                    bandwidth: Bandwidth::Bw20,
                    center_freq_mhz: channel_to_freq(ch),
                });
            }
            chs
        });
        &CHANNELS
    }

    fn set_monitor_mode(&mut self) -> Result<()> {
        // kernel replay already sets monitor filter — skip extra write
        Ok(())
    }

    fn tx_frame(&mut self, frame: &[u8], _opts: &TxOptions) -> Result<()> {
        // MT7612U TX format (from usbmon capture 2026-03-22, Asahi Linux mt76 driver):
        //   [4B TXD info header]  — LE u16 payload_len + 0x08 0x05
        //   [20B TXWI]           — TX WiFi Info (flags, rate, ack, iv, eiv)
        //   [802.11 frame]       — raw frame bytes
        //   [padding to 4B]      — zero-padded alignment
        //
        // Endpoint: EP 0x07 (VO/MGMT queue, confirmed from all 37 TX frames in capture)
        // All scan probes + inject test probes used EP 0x07 exclusively.

        if frame.len() < 10 {
            return Err(Error::TxFailed {
                retries: 0,
                reason: "frame too short".into(),
            });
        }

        const TXD_SIZE: usize = 4;
        const TXWI_SIZE: usize = 20;

        let payload_len = TXWI_SIZE + frame.len();
        let padded_payload = (payload_len + 3) & !3;
        let total = TXD_SIZE + padded_payload;
        let mut buf = vec![0u8; total];

        // ── TXD info header (4 bytes) ──
        // Bytes 0-1: LE u16 payload length (TXWI + frame, before padding)
        // Bytes 2-3: constant 0x08, 0x05 (from all 37 captured TX frames)
        buf[0] = (payload_len & 0xFF) as u8;
        buf[1] = ((payload_len >> 8) & 0xFF) as u8;
        buf[2] = 0x08;
        buf[3] = 0x05;

        // ── TXWI (20 bytes, kernel-replay from usbmon) ──
        // Two templates observed in capture:
        //   2.4GHz: 00000000 02fdd600 00000000 00000000 00130000
        //   5GHz:   00000020 02fddb00 00000000 00000000 00130000
        // Differences: flags byte[3] = 0x20 for 5GHz, rate byte[2] = 0xdb vs 0xd6
        let is_5ghz = self.current_channel.band == Band::Band5g;
        let txwi: [u8; TXWI_SIZE] = if is_5ghz {
            [
                0x00, 0x00, 0x00, 0x20, // flags: 5GHz band indicator
                0x02, 0xfd, 0xdb, 0x00, // rate: OFDM 6Mbps on 5GHz
                0x00, 0x00, 0x00, 0x00, // ack_ctl=0, wcid=0, len_ctl=0
                0x00, 0x00, 0x00, 0x00, // iv (no encryption)
                0x00, 0x13, 0x00, 0x00, // eiv
            ]
        } else {
            [
                0x00, 0x00, 0x00, 0x00, // flags: 2.4GHz
                0x02, 0xfd, 0xd6, 0x00, // rate: CCK/OFDM on 2.4GHz
                0x00, 0x00, 0x00, 0x00, // ack_ctl=0, wcid=0, len_ctl=0
                0x00, 0x00, 0x00, 0x00, // iv (no encryption)
                0x00, 0x13, 0x00, 0x00, // eiv
            ]
        };

        buf[TXD_SIZE..TXD_SIZE + TXWI_SIZE].copy_from_slice(&txwi);

        // ── 802.11 frame ──
        buf[TXD_SIZE + TXWI_SIZE..TXD_SIZE + TXWI_SIZE + frame.len()]
            .copy_from_slice(frame);

        // Send on EP 0x07 (management TX queue)
        self.handle.write_bulk(self.ep_data_out, &buf, Duration::from_millis(200))
            .map_err(|e| Error::TxFailed {
                retries: 0,
                reason: format!("USB write EP {:#04x}: {}", self.ep_data_out, e),
            })?;

        Ok(())
    }

    fn rx_frame(&mut self, timeout: Duration) -> Result<Option<RxFrame>> {
        // Drain aggregation buffer first
        if self.rx_agg_offset < self.rx_agg_buf.len() {
            if let Some((frame, consumed)) = self.parse_one_rx(&self.rx_agg_buf[self.rx_agg_offset..]) {
                self.rx_agg_offset += consumed;
                return Ok(Some(frame));
            }
            self.rx_agg_buf.clear();
            self.rx_agg_offset = 0;
        }

        // Fresh USB bulk read (64KB for aggregated transfers)
        let mut buf = vec![0u8; 65536];
        match self.handle.read_bulk(self.ep_data_in, &mut buf, timeout) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                match self.parse_one_rx(&buf) {
                    Some((frame, consumed)) => {
                        if consumed < n {
                            self.rx_agg_buf = buf;
                            self.rx_agg_offset = consumed;
                        }
                        Ok(Some(frame))
                    }
                    None => Ok(None),
                }
            }
            Ok(_) => Ok(None),
            Err(rusb::Error::Timeout) => Ok(None),
            Err(e) => Err(Error::Usb(e)),
        }
    }


    fn mac(&self) -> MacAddress {
        self.mac_addr
    }

    fn set_mac(&mut self, mac: MacAddress) -> Result<()> {
        self.mac_addr = mac;
        self.mac_set_address()?;
        Ok(())
    }

    fn tx_power(&self) -> i8 {
        self.tx_power
    }

    fn set_tx_power(&mut self, dbm: i8) -> Result<()> {
        self.tx_power = dbm;
        // TODO: MCU command to set TX power
        Ok(())
    }

    fn calibrate(&mut self) -> Result<()> {
        // Full per-channel calibration — run when settling on a target channel.
        // This is the heavy calibration that Linux skips during scanning.
        // Matches mt76x2u_phy_channel_calibrate + post-RXDCOC AGC setup.
        let ch = self.current_channel.number;
        let is_5g = self.current_channel.band == Band::Band5g;
        let is_5g_param = if is_5g { 1u32 } else { 0u32 };

        // AGC register setup
        self.reg_write(0x23f4, 0xff64a4e2)?;
        self.reg_write(0x231c, 0x08081010)?;
        self.reg_write(0x232c, 0x00000404)?;
        self.reg_write(0x2308, 0x00007070)?;
        self.reg_write(0x1340, 0x04101b3f)?;

        // Full channel calibrations
        if is_5g {
            self.mcu_calibrate(6, 0)?; // MCU_CAL_LC
        }
        self.mcu_calibrate(7, is_5g_param)?;  // MCU_CAL_TX_LOFT
        self.mcu_calibrate(8, is_5g_param)?;  // MCU_CAL_TXIQ
        self.mcu_calibrate(12, is_5g_param)?; // MCU_CAL_RXIQC_FI
        self.mcu_calibrate(2, 0)?;            // MCU_CAL_TEMP_SENSOR
        self.mcu_calibrate(15, 0)?;           // MCU_CAL_TX_SHAPING

        Ok(())
    }

    fn take_rx_handle(&mut self) -> Option<crate::core::chip::RxHandle> {
        Some(crate::core::chip::RxHandle {
            device: Arc::clone(&self.handle),
            ep_in: self.ep_data_in,
            rx_buf_size: 65536,
            parse_fn: mt7612u_parse_rx,
            driver_msg_tx: None,
        })
    }
}
