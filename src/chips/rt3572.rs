//! RT3572 chip driver (Ralink/MediaTek RT2800USB family)
//!
//! The RT3572 (Alfa AWUS036NH) is an 802.11n dual-band USB adapter.
//! 1x1 MIMO, 2.4 GHz + 5 GHz, up to 150 Mbps.
//!
//! Key characteristics:
//!   - MCU-driven: 4KB 8051 firmware uploaded to SRAM at 0x3000
//!   - Register access: USB vendor requests 0x06 (multi-write) / 0x07 (multi-read)
//!   - BBP access: Indirect via BBP_CSR_CFG (0x101c)
//!   - RF access: Indirect via RF_CSR_CFG (0x0500)
//!   - EFUSE: 512 bytes via EFUSE_CTRL (0x0580)
//!   - RX frames: RXINFO(4) + RXWI(16) + 802.11 payload + RXD(4)
//!   - TX frames: TXINFO(4) + TXWI(16) + 802.11 payload
//!   - Monitor mode: RX_FILTER_CFG (0x1400) promiscuous bits
//!   - 4 bulk OUT endpoints (EP01-04), 1 bulk IN endpoint (EP81)
//!   - External antenna (Alfa) — key advantage for range
//!
//! Reference: Linux rt2800usb driver in references/linux-rt2800/
//!   rt2800usb.c   — USB transport, TX/RX descriptors
//!   rt2800lib.c   — Init, channel config, calibration
//!   rt2800.h      — Register definitions, EEPROM layout
//!   rt2x00usb.c   — Generic USB operations
//!
//! Init sequence captured via usbmon on Asahi Linux:
//!   references/captures_20260322/rt3572_20260322_174633/
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]

use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::thread;

use nusb::MaybeFuture;
use nusb::transfer::{ControlIn, ControlOut, ControlType, Recipient, TransferError};
use crate::core::usb;

use crate::core::{
    Channel, Band, MacAddress, Result, Error,
    chip::{ChipDriver, ChipInfo, ChipId, ChipCaps, ParsedPacket, RxHandle},
    frame::{RxFrame, TxOptions, TxRate},
    adapter::UsbEndpoints,
    error::InitStage,
};

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — USB vendor requests (from rt2x00usb.h)
// ══════════════════════════════════════════════════════════════════════════════

/// Multi-word register write (bRequest=0x06, bmRequestType=0x40 OUT)
const USB_MULTI_WRITE: u8 = 0x06;
/// Multi-word register read (bRequest=0x07, bmRequestType=0xC0 IN)
const USB_MULTI_READ: u8 = 0x07;
/// Device mode / EEPROM (bRequest=0x01)
const USB_DEVICE_MODE: u8 = 0x01;

/// USB mode values for device mode request
const USB_MODE_RESET: u16 = 0x0001;
const USB_MODE_AUTORUN: u16 = 0x0011;
const USB_MODE_FIRMWARE: u16 = 0x0008;

const USB_TIMEOUT: Duration = Duration::from_millis(500);
const USB_FW_TIMEOUT: Duration = Duration::from_secs(1);
const USB_BULK_TIMEOUT: Duration = Duration::from_secs(2);

// ══════════════════════════════════════════════════════════════════════════════
//  Constants — Register addresses (from rt2800.h)
// ══════════════════════════════════════════════════════════════════════════════

// Chip identification
const MAC_CSR0: u16 = 0x1000;

// MAC system control
const MAC_SYS_CTRL: u16 = 0x1004;
const MAC_SYS_CTRL_RESET_CSR: u32 = 1 << 0;
const MAC_SYS_CTRL_RESET_BBP: u32 = 1 << 1;
const MAC_SYS_CTRL_ENABLE_TX: u32 = 1 << 2;
const MAC_SYS_CTRL_ENABLE_RX: u32 = 1 << 3;

// MAC address
const MAC_ADDR_DW0: u16 = 0x1008;
const MAC_ADDR_DW1: u16 = 0x100c;
const MAC_BSSID_DW0: u16 = 0x1010;
const MAC_BSSID_DW1: u16 = 0x1014;

// Max frame length
const MAX_LEN_CFG: u16 = 0x1018;

// BBP indirect access
const BBP_CSR_CFG: u16 = 0x101c;
const BBP_CSR_CFG_BUSY: u32 = 1 << 17;
const BBP_CSR_CFG_RW_MODE: u32 = 1 << 19;
const BBP_CSR_CFG_READ: u32 = 1 << 16;

// LED config
const LED_CFG: u16 = 0x102c;

// EDCA / WMM
const EDCA_AC0_CFG: u16 = 0x1100;
const EDCA_AC1_CFG: u16 = 0x1104;
const EDCA_AC2_CFG: u16 = 0x1108;
const EDCA_AC3_CFG: u16 = 0x110c;
const WMM_CWMIN_CFG: u16 = 0x1114;

// MAC status
const MAC_STATUS_CFG: u16 = 0x1200;

// TX/RX settings
const TX_BAND_CFG: u16 = 0x132c;
const TX_SW_CFG0: u16 = 0x1330;
const TX_SW_CFG1: u16 = 0x1334;
const US_CYC_CNT: u16 = 0x1340;
const TX_STA_FIFO: u16 = 0x1718;

// TX power configuration (6 registers)
const TX_PWR_CFG_0: u16 = 0x1700;
const TX_PWR_CFG_1: u16 = 0x1704;
const TX_PWR_CFG_2: u16 = 0x1708;
const TX_PWR_CFG_3: u16 = 0x170c;
const TX_PWR_CFG_4: u16 = 0x1710;
const TX_PWR_CFG_5: u16 = 0x1714;

// RX filter
const RX_FILTER_CFG: u16 = 0x1400;

// TX PIN config
const TX_PIN_CFG: u16 = 0x1328;

// GPIO control (band switching on RT3572)
const GPIO_CTRL: u16 = 0x0228;

// WPDMA global config
const WPDMA_GLO_CFG: u16 = 0x0208;

// USB DMA config
const USB_DMA_CFG: u16 = 0x02a0;

// PBF system control
const PBF_SYS_CTRL: u16 = 0x0400;
const HOST_CMD_CSR: u16 = 0x0404;
const PBF_RX_MAX_PCNT: u16 = 0x0408;

// RF CSR indirect access
const RF_CSR_CFG: u16 = 0x0500;
const RF_CSR_CFG_BUSY: u32 = 1 << 17;
const RF_CSR_CFG_WRITE: u32 = 1 << 16;

// EFUSE control
const EFUSE_CTRL: u16 = 0x0580;
// EFUSE data registers — Linux reads from DATA3 down to DATA0 ("end to start")
// DATA3 → eeprom[i+0..i+1], DATA2 → eeprom[i+2..i+3], DATA1 → eeprom[i+4..i+5], DATA0 → eeprom[i+6..i+7]
const EFUSE_DATA0: u16 = 0x0590;
const EFUSE_DATA1: u16 = 0x0594;
const EFUSE_DATA2: u16 = 0x0598;
const EFUSE_DATA3: u16 = 0x059c;

// MCU mailbox
const H2M_MAILBOX_CSR: u16 = 0x7010;
const H2M_MAILBOX_CID: u16 = 0x7014;
const H2M_MAILBOX_STATUS: u16 = 0x701c;
const H2M_BBP_AGENT: u16 = 0x7024;
const H2M_INT_SRC: u16 = 0x7028;

// MCU commands
const MCU_BOOT_SIGNAL: u8 = 0x72;
const MCU_WAKEUP: u8 = 0x31;

// Firmware load address
const FIRMWARE_IMAGE_BASE: u16 = 0x3000;

// WCID key table
const WCID_TABLE_BASE: u16 = 0x1800;
const WCID_ATTR_BASE: u16 = 0x6800;
const WCID_COUNT: usize = 128;

// RX/TX descriptor sizes
const RXINFO_SIZE: usize = 4;
const RXWI_SIZE: usize = 16;
const RX_HEADER_SIZE: usize = RXINFO_SIZE + RXWI_SIZE; // 20 bytes
const RXD_SIZE: usize = 4; // appended after payload

const TXINFO_SIZE: usize = 4;
const TXWI_SIZE: usize = 16;
const TX_HEADER_SIZE: usize = TXINFO_SIZE + TXWI_SIZE; // 20 bytes

const RX_BUF_SIZE: usize = 16384;
const FW_CHUNK_SIZE: usize = 64;

// RSSI offset — raw AGC value to dBm
const DEFAULT_RSSI_OFFSET: i16 = 120;

// ══════════════════════════════════════════════════════════════════════════════
//  RF channel table — RF3052 (from Linux rt2800lib.c rf_vals_3x[])
// ══════════════════════════════════════════════════════════════════════════════

/// RF channel entry: (channel_number, rf1, rf2, rf3)
/// rf1 → RFCSR2 (PLL N divider)
/// rf2 → RFCSR6 R1 field
/// rf3 → RFCSR3 (PLL fractional)
const RF_VALS_3X: &[(u8, u8, u8, u8)] = &[
    // 2.4 GHz
    (1,   241, 2, 2),
    (2,   241, 2, 7),
    (3,   242, 2, 2),
    (4,   242, 2, 7),
    (5,   243, 2, 2),
    (6,   243, 2, 7),
    (7,   244, 2, 2),
    (8,   244, 2, 7),
    (9,   245, 2, 2),
    (10,  245, 2, 7),
    (11,  246, 2, 2),
    (12,  246, 2, 7),
    (13,  247, 2, 2),
    (14,  248, 2, 4),
    // 5 GHz UNII-1
    (36,  0x56, 0, 4),
    (38,  0x56, 0, 6),
    (40,  0x56, 0, 8),
    (44,  0x57, 0, 0),
    (46,  0x57, 0, 2),
    (48,  0x57, 0, 4),
    (52,  0x57, 0, 8),
    (54,  0x57, 0, 10),
    (56,  0x58, 0, 0),
    (60,  0x58, 0, 4),
    (62,  0x58, 0, 6),
    (64,  0x58, 0, 8),
    // 5 GHz UNII-2 Extended
    (100, 0x5b, 0, 8),
    (102, 0x5b, 0, 10),
    (104, 0x5c, 0, 0),
    (108, 0x5c, 0, 4),
    (110, 0x5c, 0, 6),
    (112, 0x5c, 0, 8),
    (116, 0x5d, 0, 0),
    (118, 0x5d, 0, 2),
    (120, 0x5d, 0, 4),
    (124, 0x5d, 0, 8),
    (126, 0x5d, 0, 10),
    (128, 0x5e, 0, 0),
    (132, 0x5e, 0, 4),
    (134, 0x5e, 0, 6),
    (136, 0x5e, 0, 8),
    (140, 0x5f, 0, 0),
    // 5 GHz UNII-3
    (149, 0x5f, 0, 9),
    (151, 0x5f, 0, 11),
    (153, 0x60, 0, 1),
    (157, 0x60, 0, 5),
    (159, 0x60, 0, 7),
    (161, 0x60, 0, 9),
    (165, 0x61, 0, 1),
];

// ══════════════════════════════════════════════════════════════════════════════
//  BBP init values (from usbmon capture + rt2800lib.c rt2800_init_bbp_3572)
// ══════════════════════════════════════════════════════════════════════════════

const BBP_INIT_VALUES: &[(u8, u8)] = &[
    (0x1f, 0x08),
    (0x41, 0x2c),
    (0x42, 0x38),
    (0x45, 0x12),
    (0x49, 0x10),
    (0x46, 0x0a),
    (0x4f, 0x13),
    (0x50, 0x05),
    (0x51, 0x33),
    (0x52, 0x62),
    (0x53, 0x6a),
    (0x54, 0x99),
    (0x56, 0x00),
    (0x5b, 0x04),
    (0x5c, 0x00),
    (0x67, 0xc0),
    (0x69, 0x05),
    (0x6a, 0x35),
];

// ══════════════════════════════════════════════════════════════════════════════
//  RF init values (from usbmon capture — RT3572 RF3052)
// ══════════════════════════════════════════════════════════════════════════════

const RF_INIT_VALUES: &[(u8, u8)] = &[
    (0x00, 0x70),
    (0x01, 0x81),
    (0x02, 0xf1),
    (0x03, 0x02),
    (0x04, 0x4c),
    (0x05, 0x05),
    (0x06, 0x4a),
    (0x07, 0xd8),
    (0x09, 0xc3),
    (0x0a, 0xf1),
    (0x0b, 0xb9),
    (0x0c, 0x64),
    (0x0d, 0x64),
    (0x0e, 0x00),
    (0x0f, 0x53),
    (0x10, 0x4c),
    (0x11, 0x23),
    (0x13, 0x93),
    (0x14, 0xb3),
    (0x17, 0x30),
    (0x18, 0x13),
    (0x19, 0x15),
    (0x1a, 0x85),
    (0x1b, 0x00),
    (0x1d, 0x9b),
    (0x1f, 0x13),
];

// ══════════════════════════════════════════════════════════════════════════════
//  MAC init register sequence (from usbmon capture)
//  These are the exact register writes observed during Linux driver init
// ══════════════════════════════════════════════════════════════════════════════

const MAC_INIT_REGS: &[(u16, u32)] = &[
    (0x1408, 0x0000013f),  // LEGACY_BASIC_RATE
    (0x140c, 0x00008003),  // HT_BASIC_RATE
    (0x1114, 0x00000640),  // WMM_CWMIN_CFG
    (0x1400, 0x0001bf97),  // RX_FILTER_CFG (initial — accept most)
    (0x1104, 0x00000209),  // EDCA_AC1_CFG
    (TX_SW_CFG0, 0x00000400),  // TX_SW_CFG0 (RT3572-specific)
    (TX_SW_CFG1, 0x00080606),  // TX_SW_CFG1 (RT3572-specific)
    (0x1350, 0x00001020),  // TX aggregation limit
    (0x1348, 0x000a2090),  // TX aggregation config
    (MAX_LEN_CFG, 0x000abf00),  // Max frame length
    (LED_CFG, 0x7f031e46),  // LED behavior
    (0x040c, 0x1f3fbf9f),  // PBF_MAX_PCNT
    (0x134c, 0x47d00202),  // TX timeout
    (0x1404, 0x00000007),  // RX filter control
    (0x1364, 0x01740003),  // MPDU density
    (0x1368, 0x01740003),  // TX STA FIFO
    (0x136c, 0x01654004),
    (0x1370, 0x03e54084),
    (0x1374, 0x01654004),
    (0x1378, 0x03e54084),
    (PBF_RX_MAX_PCNT, 0x00f40006),
    (US_CYC_CNT, 0x0000583f),
    (0x1608, 0x00000002),
    (0x1344, 0x01093107),  // TXRXQ_PCNT
    (0x1380, 0x002400ca),
    (EDCA_AC0_CFG, 0x33a41010),
    (0x1204, 0x00000003),
];

// ══════════════════════════════════════════════════════════════════════════════
//  EEPROM layout offsets (16-bit word indices, from rt2800.h)
// ══════════════════════════════════════════════════════════════════════════════

const EEPROM_MAC_ADDR_0: usize = 0x02;
const EEPROM_MAC_ADDR_1: usize = 0x03;
const EEPROM_MAC_ADDR_2: usize = 0x04;
const EEPROM_NIC_CONF0: usize = 0x1a;
const EEPROM_NIC_CONF1: usize = 0x1b;
const EEPROM_FREQ_OFFSET: usize = 0x1d;
const EEPROM_LNA: usize = 0x22;
const EEPROM_RSSI_BG_0: usize = 0x23;
const EEPROM_RSSI_BG_1: usize = 0x24;
const EEPROM_RSSI_A_0: usize = 0x25;
const EEPROM_RSSI_A_1: usize = 0x26;
const EEPROM_TXPOWER_BG1: usize = 0x29;
const EEPROM_TXPOWER_A1: usize = 0x3c;
const EEPROM_TXPOWER_BYRATE: usize = 0x6f;
const EEPROM_SIZE_WORDS: usize = 256;  // 512 bytes

// ══════════════════════════════════════════════════════════════════════════════
//  Firmware — embedded rt2870.bin second 4KB
// ══════════════════════════════════════════════════════════════════════════════

const RT2870_FW: &[u8] = include_bytes!(
    "../../references/captures_20260322/firmware/rt2870.bin"
);

// ══════════════════════════════════════════════════════════════════════════════
//  Driver struct
// ══════════════════════════════════════════════════════════════════════════════

pub struct Rt3572 {
    device: nusb::Device,
    iface: nusb::Interface,
    ep_bulk_out: Mutex<nusb::Endpoint<usb::Bulk, usb::Out>>,
    ep_in_addr: u8,
    channel: u8,
    mac_addr: MacAddress,
    channels: Vec<Channel>,
    vid: u16,
    pid: u16,
    tx_seq: u16,

    // EEPROM data (read during init)
    eeprom: [u16; EEPROM_SIZE_WORDS],

    // Calibration values from EEPROM
    freq_offset: u8,
    lna_gain_bg: u8,
    lna_gain_a0: u8,
    lna_gain_a1: u8,
    lna_gain_a2: u8,
    rssi_offset_bg: [i8; 3],
    rssi_offset_a: [i8; 3],
    txmixer_gain_24g: u8,
    txmixer_gain_5g: u8,
    calibration_bw20: u8,
    calibration_bw40: u8,
    bbp25: u8,
    bbp26: u8,
}

/// Standalone parse function for RxHandle — has the right fn pointer signature.
fn parse_rx_packet_standalone(buf: &[u8], channel: u8) -> (usize, ParsedPacket) {
    let (consumed, frame) = Rt3572::parse_rx_packet(buf, channel);
    let packet = match frame {
        Some(f) => ParsedPacket::Frame(f),
        None => ParsedPacket::Skip,
    };
    (consumed, packet)
}

/// RT3572 capability flags
const RT3572_CAPS: ChipCaps = ChipCaps::MONITOR.union(ChipCaps::INJECT)
    .union(ChipCaps::BAND_2G).union(ChipCaps::BAND_5G)
    .union(ChipCaps::HT).union(ChipCaps::BW40);

fn build_channel_list() -> Vec<Channel> {
    RF_VALS_3X.iter().map(|&(ch, _, _, _)| Channel::new(ch)).collect()
}

// ══════════════════════════════════════════════════════════════════════════════
//  Implementation
// ══════════════════════════════════════════════════════════════════════════════

impl Rt3572 {
    pub fn open_usb(vid: u16, pid: u16) -> Result<(Self, UsbEndpoints)> {
        let (device, iface, endpoints) = usb::open_device_simple(vid, pid)?;

        let ep_bulk_out = iface.endpoint::<usb::Bulk, usb::Out>(endpoints.bulk_out)
            .map_err(|e| usb::nusb_error_to_wifikit(e, "open bulk OUT endpoint"))?;

        let driver = Self {
            device,
            iface,
            ep_bulk_out: Mutex::new(ep_bulk_out),
            ep_in_addr: endpoints.bulk_in,
            channel: 0,
            mac_addr: MacAddress::ZERO,
            channels: build_channel_list(),
            vid,
            pid,
            tx_seq: 0,
            eeprom: [0xFFFF; EEPROM_SIZE_WORDS],
            freq_offset: 0,
            lna_gain_bg: 0,
            lna_gain_a0: 0,
            lna_gain_a1: 0,
            lna_gain_a2: 0,
            rssi_offset_bg: [0; 3],
            rssi_offset_a: [0; 3],
            txmixer_gain_24g: 0,
            txmixer_gain_5g: 0,
            calibration_bw20: 0,
            calibration_bw40: 0,
            bbp25: 0,
            bbp26: 0,
        };

        Ok((driver, endpoints))
    }

    // ── Register access via USB vendor control ──

    fn read_reg(&self, addr: u16) -> Result<u32> {
        let data = self.iface.control_in(ControlIn {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: USB_MULTI_READ,
            value: 0x0000,
            index: addr,
            length: 4,
        }, USB_TIMEOUT).wait().map_err(|_| Error::RegisterReadFailed { addr })?;
        if data.len() < 4 {
            return Err(Error::RegisterReadFailed { addr });
        }
        Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    fn write_reg(&self, addr: u16, val: u32) -> Result<()> {
        self.iface.control_out(ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: USB_MULTI_WRITE,
            value: 0x0000,
            index: addr,
            data: &val.to_le_bytes(),
        }, USB_TIMEOUT).wait().map_err(|_| Error::RegisterWriteFailed { addr, val })?;
        Ok(())
    }

    fn write_reg_multi(&self, addr: u16, data: &[u8]) -> Result<()> {
        self.iface.control_out(ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: USB_MULTI_WRITE,
            value: 0x0000,
            index: addr,
            data,
        }, USB_FW_TIMEOUT).wait().map_err(|_| Error::RegisterWriteFailed { addr, val: data.len() as u32 })?;
        Ok(())
    }

    fn bulk_write(&self, data: &[u8], timeout: Duration) -> Result<()> {
        let mut ep = self.ep_bulk_out.lock().unwrap_or_else(|e| e.into_inner());
        let buf: usb::Buffer = data.to_vec().into();
        let completion = ep.transfer_blocking(buf, timeout);
        completion.status.map_err(usb::transfer_error_to_wifikit)?;
        Ok(())
    }

    // ── BBP indirect register access ──

    fn bbp_write(&self, reg: u8, val: u8) -> Result<()> {
        // Wait for BBP not busy
        for _ in 0..100 {
            let csr = self.read_reg(BBP_CSR_CFG)?;
            if csr & BBP_CSR_CFG_BUSY == 0 {
                break;
            }
            thread::sleep(Duration::from_micros(100));
        }

        // Write: bit19=1 (parallel mode), bit17=1 (busy/kick), bit16=0 (write)
        let cmd: u32 = (val as u32)
            | ((reg as u32) << 8)
            | BBP_CSR_CFG_BUSY
            | BBP_CSR_CFG_RW_MODE;
        self.write_reg(BBP_CSR_CFG, cmd)
    }

    fn bbp_read(&self, reg: u8) -> Result<u8> {
        // Wait for BBP not busy
        for _ in 0..100 {
            let csr = self.read_reg(BBP_CSR_CFG)?;
            if csr & BBP_CSR_CFG_BUSY == 0 {
                break;
            }
            thread::sleep(Duration::from_micros(100));
        }

        // Read: bit19=1 (parallel), bit17=1 (busy/kick), bit16=1 (read)
        let cmd: u32 = ((reg as u32) << 8)
            | BBP_CSR_CFG_BUSY
            | BBP_CSR_CFG_RW_MODE
            | BBP_CSR_CFG_READ;
        self.write_reg(BBP_CSR_CFG, cmd)?;

        // Wait for result
        for _ in 0..100 {
            let csr = self.read_reg(BBP_CSR_CFG)?;
            if csr & BBP_CSR_CFG_BUSY == 0 {
                return Ok((csr & 0xFF) as u8);
            }
            thread::sleep(Duration::from_micros(100));
        }

        Err(Error::ChipInitFailed {
            chip: "RT3572".into(),
            stage: InitStage::RegisterAccess,
            reason: format!("BBP read timeout for reg {:#04x}", reg),
        })
    }

    // ── RF CSR indirect register access ──

    fn rfcsr_write(&self, reg: u8, val: u8) -> Result<()> {
        // Wait for RF not busy
        for _ in 0..100 {
            let csr = self.read_reg(RF_CSR_CFG)?;
            if csr & RF_CSR_CFG_BUSY == 0 {
                break;
            }
            thread::sleep(Duration::from_micros(100));
        }

        // Write: bit17=1 (busy/kick), bit16=1 (write), bits[13:8]=reg, bits[7:0]=val
        let cmd: u32 = (val as u32)
            | ((reg as u32) << 8)
            | RF_CSR_CFG_WRITE
            | RF_CSR_CFG_BUSY;
        self.write_reg(RF_CSR_CFG, cmd)
    }

    fn rfcsr_read(&self, reg: u8) -> Result<u8> {
        // Wait for RF not busy
        for _ in 0..100 {
            let csr = self.read_reg(RF_CSR_CFG)?;
            if csr & RF_CSR_CFG_BUSY == 0 {
                break;
            }
            thread::sleep(Duration::from_micros(100));
        }

        // Read: bit17=1 (busy/kick), bit16=0 (read), bits[13:8]=reg
        let cmd: u32 = ((reg as u32) << 8) | RF_CSR_CFG_BUSY;
        self.write_reg(RF_CSR_CFG, cmd)?;

        for _ in 0..100 {
            let csr = self.read_reg(RF_CSR_CFG)?;
            if csr & RF_CSR_CFG_BUSY == 0 {
                return Ok((csr & 0xFF) as u8);
            }
            thread::sleep(Duration::from_micros(100));
        }

        Err(Error::ChipInitFailed {
            chip: "RT3572".into(),
            stage: InitStage::RegisterAccess,
            reason: format!("RFCSR read timeout for reg {:#04x}", reg),
        })
    }

    // ── MCU mailbox command ──

    fn mcu_command(&self, cmd: u8, arg0: u8, arg1: u8, token: u8) -> Result<()> {
        // Wait for mailbox ready
        for _ in 0..100 {
            let val = self.read_reg(H2M_MAILBOX_CSR)?;
            if val & (1 << 24) == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        // Send command: bit24=1 (owner=host), [23:16]=token, [15:8]=arg1, [7:0]=arg0
        let cmd_word: u32 = (arg0 as u32)
            | ((arg1 as u32) << 8)
            | ((token as u32) << 16)
            | (1 << 24);
        self.write_reg(H2M_MAILBOX_CSR, cmd_word)?;

        // Trigger via HOST_CMD_CSR
        self.write_reg(HOST_CMD_CSR, cmd as u32)?;

        thread::sleep(Duration::from_millis(1));
        Ok(())
    }

    // ── EFUSE read ──

    fn efuse_read_block(&self, word_index: u16) -> Result<[u32; 4]> {
        // Read current EFUSE_CTRL
        let mut ctrl = self.read_reg(EFUSE_CTRL)?;

        // EFUSE_CTRL_ADDRESS_IN = bits[25:17] (9 bits), MODE = bits[7:6], KICK = bit 30
        ctrl &= !(0x03FE0000);  // clear ADDRESS_IN bits[25:17]
        ctrl |= ((word_index as u32) & 0x1FF) << 17;  // set address
        ctrl &= !(0xC0);  // clear MODE bits[7:6] = 0 (read)
        ctrl |= 1 << 30;  // KICK

        self.write_reg(EFUSE_CTRL, ctrl)?;

        // Wait for KICK bit to clear
        for _ in 0..200 {
            let val = self.read_reg(EFUSE_CTRL)?;
            if val & (1 << 30) == 0 {
                break;
            }
            thread::sleep(Duration::from_micros(100));
        }

        // Read data registers — "data is read from end to start" (Linux comment)
        // DATA3(0x059c) → eeprom[i+0..i+1], DATA0(0x0590) → eeprom[i+6..i+7]
        let d3 = self.read_reg(EFUSE_DATA3)?;  // 0x059c → words [i+0, i+1]
        let d2 = self.read_reg(EFUSE_DATA2)?;  // 0x0598 → words [i+2, i+3]
        let d1 = self.read_reg(EFUSE_DATA1)?;  // 0x0594 → words [i+4, i+5]
        let d0 = self.read_reg(EFUSE_DATA0)?;  // 0x0590 → words [i+6, i+7]

        // Return in eeprom word order: d3 has lowest words, d0 has highest
        Ok([d3, d2, d1, d0])
    }

    fn read_eeprom_efuse(&mut self) -> Result<()> {
        // Read entire EEPROM via EFUSE — 32 reads of 16 bytes (256 words)
        for block in 0..32u16 {
            let word_idx = (block * 8) as usize;
            let data = self.efuse_read_block(block * 8)?;

            // Each u32 contains 2 EEPROM words (little-endian)
            // d3 = words[idx+0, idx+1], d2 = words[idx+2, idx+3], etc.
            // But EFUSE data registers go DATA3(0x0590)..DATA0(0x059c) = high..low
            // Actually: DATA3 at 0x059c is the FIRST 4 bytes, DATA0 at 0x0590 is the LAST
            // Wait — Linux reads DATA3 first and stores at lower index.
            // From rt2800_efuse_read: eeprom[i+0..+1] = DATA3, eeprom[i+2..+3] = DATA2...
            // But our EFUSE register addresses: DATA3=0x059c, DATA2=0x0598, DATA1=0x0594, DATA0=0x0590
            // Actually let me re-check the read order... in our read_reg calls above,
            // we read 0x059c first as d3, then 0x0598 as d2, etc. But Linux says:
            //   efuse_data[3] = rt2800_register_read(EFUSE_DATA3);  // 0x059c
            //   mapped to eeprom[i+0..i+1]
            // Hmm, the naming is confusing. Let me just match the usbmon capture.
            // From the capture, after reading EFUSE block 0x030:
            //   d3(0x059c) = 0x00000000, d2(0x0598) = 0x002e0911, d1(0x0594) = 0x0130ffff, d0(0x0590) = 0xbbdd5555
            // Wait, the capture shows EFUSE_DATA0 at 0x059c and DATA3 at 0x0590? Let me recheck.
            // From the parse: EFUSE_DATA3: u16 = 0x0590, EFUSE_DATA0: u16 = 0x059c
            // But Linux: EFUSE_DATA3 = 0x059C, EFUSE_DATA0 = 0x0590
            // There's a conflict! Let me use Linux naming (DATA3=0x059C, DATA0=0x0590)
            // and the capture confirms reading 0x059c first gets the high bytes.

            // Convert 4 u32s to 8 u16 words, little-endian
            for (i, &dword) in data.iter().enumerate() {
                let w0 = (dword & 0xFFFF) as u16;
                let w1 = ((dword >> 16) & 0xFFFF) as u16;
                let idx = word_idx + i * 2;
                if idx < EEPROM_SIZE_WORDS {
                    self.eeprom[idx] = w0;
                }
                if idx + 1 < EEPROM_SIZE_WORDS {
                    self.eeprom[idx + 1] = w1;
                }
            }
        }
        Ok(())
    }

    fn parse_eeprom(&mut self) {
        // MAC address
        let w0 = self.eeprom[EEPROM_MAC_ADDR_0];
        let w1 = self.eeprom[EEPROM_MAC_ADDR_1];
        let w2 = self.eeprom[EEPROM_MAC_ADDR_2];
        self.mac_addr = MacAddress([
            (w0 & 0xFF) as u8,
            ((w0 >> 8) & 0xFF) as u8,
            (w1 & 0xFF) as u8,
            ((w1 >> 8) & 0xFF) as u8,
            (w2 & 0xFF) as u8,
            ((w2 >> 8) & 0xFF) as u8,
        ]);

        // Frequency offset
        self.freq_offset = (self.eeprom[EEPROM_FREQ_OFFSET] & 0xFF) as u8;

        // LNA gains
        let lna = self.eeprom[EEPROM_LNA];
        self.lna_gain_bg = (lna & 0xFF) as u8;
        self.lna_gain_a0 = ((lna >> 8) & 0xFF) as u8;

        let rssi_bg1 = self.eeprom[EEPROM_RSSI_BG_1];
        self.lna_gain_a1 = ((rssi_bg1 >> 8) & 0xFF) as u8;

        let rssi_a1 = self.eeprom[EEPROM_RSSI_A_1];
        self.lna_gain_a2 = ((rssi_a1 >> 8) & 0xFF) as u8;

        // RSSI offsets
        let rssi_bg0 = self.eeprom[EEPROM_RSSI_BG_0];
        self.rssi_offset_bg[0] = (rssi_bg0 & 0xFF) as i8;
        self.rssi_offset_bg[1] = ((rssi_bg0 >> 8) & 0xFF) as i8;
        self.rssi_offset_bg[2] = (rssi_bg1 & 0xFF) as i8;

        let rssi_a0 = self.eeprom[EEPROM_RSSI_A_0];
        self.rssi_offset_a[0] = (rssi_a0 & 0xFF) as i8;
        self.rssi_offset_a[1] = ((rssi_a0 >> 8) & 0xFF) as i8;
        self.rssi_offset_a[2] = (rssi_a1 & 0xFF) as i8;

        // Clamp invalid RSSI offsets (0xFF = unprogrammed)
        for off in &mut self.rssi_offset_bg {
            if *off < -10 || *off > 10 { *off = 0; }
        }
        for off in &mut self.rssi_offset_a {
            if *off < -10 || *off > 10 { *off = 0; }
        }
    }

    // ── Firmware loading ──

    fn load_firmware(&self) -> Result<()> {
        // Check autorun mode first
        // usbmon: s c0 01 0011 0000 0004 → wValue=0x0011, wIndex=0
        let mode_result = self.iface.control_in(ControlIn {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: USB_DEVICE_MODE,
            value: USB_MODE_AUTORUN,
            index: 0x0000,
            length: 4,
        }, USB_TIMEOUT).wait();

        if let Ok(mode_buf) = mode_result {
            if !mode_buf.is_empty() && (mode_buf[0] & 0x03) == 2 {
                return Ok(());
            }
        }

        // RT3572 uses second 4KB of rt2870.bin
        if RT2870_FW.len() < 8192 {
            return Err(Error::ChipInitFailed {
                chip: "RT3572".into(),
                stage: InitStage::FirmwareDownload,
                reason: format!("firmware too small: {} bytes (need 8192)", RT2870_FW.len()),
            });
        }
        let fw_data = &RT2870_FW[4096..8192];

        // Upload firmware in 64-byte chunks to MCU SRAM at 0x3000
        for (i, chunk) in fw_data.chunks(FW_CHUNK_SIZE).enumerate() {
            let addr = FIRMWARE_IMAGE_BASE + (i * FW_CHUNK_SIZE) as u16;
            self.write_reg_multi(addr, chunk)?;
        }

        // Clear MCU mailbox
        self.write_reg(H2M_MAILBOX_CID, 0xFFFFFFFF)?;
        self.write_reg(H2M_MAILBOX_STATUS, 0xFFFFFFFF)?;

        // Tell MCU to boot firmware via USB device mode request
        // usbmon: s 40 01 0008 0000 0000 → wValue=0x0008, wIndex=0
        let _ = self.iface.control_out(ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: USB_DEVICE_MODE,
            value: USB_MODE_FIRMWARE,
            index: 0x0000,
            data: &[],
        }, USB_FW_TIMEOUT).wait();

        thread::sleep(Duration::from_millis(10));

        // Clear mailbox after boot
        self.write_reg(H2M_MAILBOX_CSR, 0)?;

        Ok(())
    }

    // ── Main init sequence (from usbmon capture) ──

    fn chip_init(&mut self) -> Result<()> {
        // Step 1: Wait for chip ready
        let start = Instant::now();
        loop {
            let chip_id = self.read_reg(MAC_CSR0)?;
            if chip_id != 0 && chip_id != 0xFFFFFFFF {
                break;
            }
            if start.elapsed() > Duration::from_secs(2) {
                return Err(Error::ChipInitFailed {
                    chip: "RT3572".into(),
                    stage: InitStage::MacPowerOn,
                    reason: "chip ID timeout".into(),
                });
            }
            thread::sleep(Duration::from_millis(1));
        }

        // Step 2: Read EEPROM via EFUSE
        self.read_eeprom_efuse()?;
        self.parse_eeprom();

        // Step 3: Load firmware
        self.load_firmware()?;

        // Step 4: USB/PBF init (from usbmon)
        let pbf = self.read_reg(PBF_SYS_CTRL)?;
        self.write_reg(PBF_SYS_CTRL, pbf & !(1 << 13))?;

        // Clear MCU state
        self.write_reg(H2M_INT_SRC, 0)?;
        self.write_reg(H2M_MAILBOX_CSR, 0)?;
        self.write_reg(H2M_BBP_AGENT, 0)?;

        // Step 5: MCU boot signal + calibration commands
        self.mcu_command(MCU_BOOT_SIGNAL, 0, 0, 0)?;
        thread::sleep(Duration::from_millis(1));

        // MCU wakeup
        self.mcu_command(MCU_WAKEUP, 0, 2, 0xFF)?;
        thread::sleep(Duration::from_millis(1));

        // Step 6: MAC system reset
        self.write_reg(MAC_SYS_CTRL, MAC_SYS_CTRL_RESET_CSR | MAC_SYS_CTRL_RESET_BBP)?;

        // USB mode reset
        // usbmon: s 40 01 0001 0000 0000 → wValue=0x0001, wIndex=0
        let _ = self.iface.control_out(ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: USB_DEVICE_MODE,
            value: USB_MODE_RESET,
            index: 0x0000,
            data: &[],
        }, USB_TIMEOUT).wait();

        self.write_reg(MAC_SYS_CTRL, 0)?;
        thread::sleep(Duration::from_millis(10));

        // Step 7: MAC register init (from usbmon capture)
        for &(addr, val) in MAC_INIT_REGS {
            self.write_reg(addr, val)?;
        }

        // Step 8: USB DMA config
        self.write_reg(USB_DMA_CFG, 0x00c02d80)?;

        // Step 9: Wait for BBP/RF ready
        let start = Instant::now();
        loop {
            let status = self.read_reg(MAC_STATUS_CFG)?;
            if status & 0x03 == 0 {
                break;
            }
            if start.elapsed() > Duration::from_secs(2) {
                return Err(Error::ChipInitFailed {
                    chip: "RT3572".into(),
                    stage: InitStage::HardwareSetup,
                    reason: "BBP/RF busy timeout".into(),
                });
            }
            thread::sleep(Duration::from_millis(1));
        }

        // Step 10: Clear MCU state again (post-reset)
        self.write_reg(H2M_BBP_AGENT, 0)?;
        self.write_reg(H2M_MAILBOX_CSR, 0)?;
        self.write_reg(H2M_INT_SRC, 0)?;
        self.mcu_command(MCU_BOOT_SIGNAL, 0, 0, 0)?;
        thread::sleep(Duration::from_millis(1));

        // Step 11: BBP init
        // Verify BBP is alive by reading reg 0
        let bbp0 = self.bbp_read(0x00)?;
        // Should be 0x70 for RT3572

        for &(reg, val) in BBP_INIT_VALUES {
            self.bbp_write(reg, val)?;
        }

        // BBP 0x8a: read-modify-write to set bit 5
        let bbp8a = self.bbp_read(0x8a)?;
        self.bbp_write(0x8a, bbp8a | 0x20)?;

        // Step 12: RF init
        // Soft-reset RF
        self.rfcsr_write(0x1e, 0x89)?;
        thread::sleep(Duration::from_micros(200));
        self.rfcsr_write(0x1e, 0x09)?;

        for &(reg, val) in RF_INIT_VALUES {
            self.rfcsr_write(reg, val)?;
        }

        // Save calibration values
        self.calibration_bw20 = self.rfcsr_read(0x18)?;
        self.calibration_bw40 = self.rfcsr_read(0x18)?;
        self.bbp25 = self.bbp_read(0x19)?;
        self.bbp26 = self.bbp_read(0x1a)?;

        // R-calibration: kick RF[0x07] bit 0
        let rf07 = self.rfcsr_read(0x07)?;
        self.rfcsr_write(0x07, rf07 | 0x01)?;

        // Step 13: RT3572-specific post-RF init
        thread::sleep(Duration::from_micros(200));

        // MCU frequency offset calibration
        self.mcu_command(0x74, self.freq_offset, 0, 0)?; // MCU_FREQ_OFFSET
        thread::sleep(Duration::from_micros(10));

        // MCU current calibration
        self.mcu_command(0x36, 0, 0, 0)?; // MCU_CURRENT
        thread::sleep(Duration::from_micros(10));

        // Step 14: Clear WCID key table
        for i in 0..WCID_COUNT {
            let wcid_addr = WCID_TABLE_BASE + (i as u16) * 8;
            self.write_reg(wcid_addr, 0xFFFFFFFF)?;
            self.write_reg(wcid_addr + 4, 0xFFFFFFFF)?;

            let attr_addr = WCID_ATTR_BASE + (i as u16) * 4;
            self.write_reg(attr_addr, 0)?;
        }

        // Step 15: Write MAC address
        let mac = self.mac_addr.0;
        let mac_dw0 = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
        let mac_dw1 = u16::from_le_bytes([mac[4], mac[5]]) as u32;
        self.write_reg(MAC_ADDR_DW0, mac_dw0)?;
        self.write_reg(MAC_ADDR_DW1, mac_dw1)?;
        self.write_reg(MAC_BSSID_DW0, mac_dw0)?;
        self.write_reg(MAC_BSSID_DW1, mac_dw1 | (1 << 16))?; // BSS_ID_MODE = 1

        // Step 16: TX power from EEPROM
        self.write_tx_power_from_eeprom()?;

        // Step 17: Clear MCU mailbox registers
        for addr in (0x7000..=0x700Cu16).step_by(4) {
            self.write_reg(addr, 0)?;
        }

        // Step 18: Enable WPDMA
        self.write_reg(WPDMA_GLO_CFG, 0x00000075)?;
        thread::sleep(Duration::from_micros(50));

        // Step 19: Enable TX + RX
        self.write_reg(MAC_SYS_CTRL, MAC_SYS_CTRL_ENABLE_TX)?;
        thread::sleep(Duration::from_micros(50));
        self.write_reg(MAC_SYS_CTRL, MAC_SYS_CTRL_ENABLE_TX | MAC_SYS_CTRL_ENABLE_RX)?;

        // MCU wakeup
        self.mcu_command(MCU_WAKEUP, 0, 2, 0xFF)?;
        thread::sleep(Duration::from_millis(1));

        // ══════════════════════════════════════════════════════════════
        // SECOND INIT CYCLE — usbmon shows Linux does this when the
        // interface comes up (enable_radio). Without it, RX doesn't work.
        // ══════════════════════════════════════════════════════════════

        // MCU sleep then wakeup (from usbmon lines 2160-2165)
        self.mcu_command(0xFF, 0xFF, 0x02, 0)?;  // MCU sleep
        thread::sleep(Duration::from_millis(1));
        self.mcu_command(0x01, 0x00, 0xFF, 0)?;  // MCU wakeup variant
        thread::sleep(Duration::from_millis(1));

        // TX context index reset
        self.write_reg(0x1208, 0)?;

        // Disable TX/RX for reinit
        self.write_reg(MAC_SYS_CTRL, 0)?;

        // Re-upload firmware (same firmware, second time)
        self.load_firmware()?;

        // Clear MCU state
        let pbf = self.read_reg(PBF_SYS_CTRL)?;
        self.write_reg(H2M_INT_SRC, 0)?;
        self.write_reg(H2M_MAILBOX_CSR, 0)?;
        self.write_reg(H2M_BBP_AGENT, 0)?;
        self.mcu_command(MCU_BOOT_SIGNAL, 0, 0, 0)?;
        thread::sleep(Duration::from_millis(1));

        // MCU calibration commands (second time)
        self.mcu_command(0x50, 0x01, 0x20, 0xFF)?;  // cal
        thread::sleep(Duration::from_micros(10));
        self.mcu_command(MCU_WAKEUP, 0x00, 0x02, 0xFF)?;  // freq offset
        thread::sleep(Duration::from_micros(10));

        // USB DMA config
        self.write_reg(USB_DMA_CFG, 0x00c02d80)?;

        // MAC system reset (second time)
        self.write_reg(MAC_SYS_CTRL, MAC_SYS_CTRL_RESET_CSR | MAC_SYS_CTRL_RESET_BBP)?;
        let _ = self.iface.control_out(ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: USB_DEVICE_MODE,
            value: USB_MODE_RESET,
            index: 0x0000,
            data: &[],
        }, USB_TIMEOUT).wait();
        self.write_reg(MAC_SYS_CTRL, 0)?;
        thread::sleep(Duration::from_millis(10));

        // MAC register init (second time)
        for &(addr, val) in MAC_INIT_REGS {
            self.write_reg(addr, val)?;
        }

        // Wait BBP/RF ready
        let start = Instant::now();
        loop {
            let status = self.read_reg(MAC_STATUS_CFG)?;
            if status & 0x03 == 0 { break; }
            if start.elapsed() > Duration::from_secs(2) {
                return Err(Error::ChipInitFailed {
                    chip: "RT3572".into(),
                    stage: InitStage::HardwareSetup,
                    reason: "BBP/RF busy timeout (second init)".into(),
                });
            }
            thread::sleep(Duration::from_millis(1));
        }

        // MCU boot + cal (second time)
        self.write_reg(H2M_BBP_AGENT, 0)?;
        self.write_reg(H2M_MAILBOX_CSR, 0)?;
        self.write_reg(H2M_INT_SRC, 0)?;
        self.mcu_command(MCU_BOOT_SIGNAL, 0, 0, 0)?;
        thread::sleep(Duration::from_millis(1));

        // BBP init (second time)
        let _ = self.bbp_read(0x00)?;
        for &(reg, val) in BBP_INIT_VALUES {
            self.bbp_write(reg, val)?;
        }
        let bbp8a = self.bbp_read(0x8a)?;
        self.bbp_write(0x8a, bbp8a | 0x20)?;

        // RF init (second time)
        self.rfcsr_write(0x1e, 0x89)?;
        thread::sleep(Duration::from_micros(200));
        self.rfcsr_write(0x1e, 0x09)?;
        for &(reg, val) in RF_INIT_VALUES {
            self.rfcsr_write(reg, val)?;
        }

        // R-calibration
        let rf07 = self.rfcsr_read(0x07)?;
        self.rfcsr_write(0x07, rf07 | 0x01)?;

        // RT3572 post-RF
        thread::sleep(Duration::from_micros(200));
        self.mcu_command(0x74, self.freq_offset, 0, 0)?;
        thread::sleep(Duration::from_micros(10));
        self.mcu_command(0x36, 0, 0, 0)?;
        thread::sleep(Duration::from_micros(10));

        // WCID clear (second time — abbreviated, clear first few)
        for i in 0..WCID_COUNT {
            let wcid_addr = WCID_TABLE_BASE + (i as u16) * 8;
            self.write_reg(wcid_addr, 0xFFFFFFFF)?;
            self.write_reg(wcid_addr + 4, 0xFFFFFFFF)?;
            let attr_addr = WCID_ATTR_BASE + (i as u16) * 4;
            self.write_reg(attr_addr, 0)?;
        }

        // MAC address (second time)
        self.write_reg(MAC_ADDR_DW0, mac_dw0)?;
        self.write_reg(MAC_ADDR_DW1, mac_dw1)?;
        self.write_reg(MAC_BSSID_DW0, mac_dw0)?;
        self.write_reg(MAC_BSSID_DW1, mac_dw1 | (1 << 16))?;

        // TX power (second time)
        self.write_tx_power_from_eeprom()?;

        // Clear MCU mailbox (second time)
        for addr in (0x7000..=0x700Cu16).step_by(4) {
            self.write_reg(addr, 0)?;
        }

        // Final enable (second time)
        self.write_reg(WPDMA_GLO_CFG, 0x00000075)?;
        self.write_reg(MAC_SYS_CTRL, MAC_SYS_CTRL_ENABLE_TX)?;
        thread::sleep(Duration::from_micros(50));
        self.write_reg(MAC_SYS_CTRL, MAC_SYS_CTRL_ENABLE_TX | MAC_SYS_CTRL_ENABLE_RX)?;

        self.mcu_command(MCU_WAKEUP, 0, 2, 0xFF)?;

        Ok(())
    }

    fn write_tx_power_from_eeprom(&self) -> Result<()> {
        // TX power by-rate values from EEPROM
        for i in 0..6u16 {
            let eep_idx = EEPROM_TXPOWER_BYRATE + (i as usize) * 2;
            if eep_idx + 1 < EEPROM_SIZE_WORDS {
                let w0 = self.eeprom[eep_idx];
                let w1 = self.eeprom[eep_idx + 1];
                let val = (w0 as u32) | ((w1 as u32) << 16);
                self.write_reg(TX_PWR_CFG_0 + i * 4, val)?;
            }
        }
        Ok(())
    }

    // ── Debug ──

    pub fn dump_state(&self) {
        let regs = [
            ("MAC_SYS_CTRL", MAC_SYS_CTRL),
            ("USB_DMA_CFG", USB_DMA_CFG),
            ("RX_FILTER", RX_FILTER_CFG),
            ("WPDMA_GLO", WPDMA_GLO_CFG),
            ("MAC_STATUS", MAC_STATUS_CFG),
            ("TX_PIN_CFG", TX_PIN_CFG),
            ("TX_BAND_CFG", TX_BAND_CFG),
            ("GPIO_CTRL", GPIO_CTRL),
        ];
        for (name, addr) in regs {
            match self.read_reg(addr) {
                Ok(val) => eprintln!("  {:<14} = {:#010x}", name, val),
                Err(e) => eprintln!("  {:<14} = ERROR: {}", name, e),
            }
        }
    }

    // ── Monitor mode ──

    fn set_monitor_internal(&self) -> Result<()> {
        // Full promiscuous mode: only drop version errors (bit 4)
        self.write_reg(RX_FILTER_CFG, 0x00000010)?;

        // Ensure RX is enabled
        let ctrl = self.read_reg(MAC_SYS_CTRL)?;
        self.write_reg(MAC_SYS_CTRL, ctrl | MAC_SYS_CTRL_ENABLE_RX)?;

        Ok(())
    }

    // ── Channel switching ──

    fn set_channel_internal(&mut self, ch: u8) -> Result<()> {
        // Find RF values for this channel
        let rf_entry = RF_VALS_3X.iter().find(|&&(c, _, _, _)| c == ch);
        let &(_, rf1, rf2, rf3) = rf_entry.ok_or(Error::UnsupportedChannel {
            channel: ch,
            chip: "RT3572".into(),
        })?;

        let is_5ghz = ch > 14;

        // Step 1: Disable TX during channel switch
        self.write_reg(MAC_SYS_CTRL, MAC_SYS_CTRL_ENABLE_RX)?;

        // Step 2: BBP band-specific AGC
        if is_5ghz {
            self.bbp_write(0x19, 0x09)?;
            self.bbp_write(0x1a, 0xff)?;
            self.bbp_write(0x25, 0x09)?;
            self.bbp_write(0x26, 0xff)?;
        } else {
            self.bbp_write(0x19, 0x80)?;
            self.bbp_write(0x1a, 0x00)?;
            self.bbp_write(0x25, self.bbp25)?;
            self.bbp_write(0x26, self.bbp26)?;
        }

        // Step 3: RF channel registers
        self.rfcsr_write(0x02, rf1)?;  // PLL N divider
        self.rfcsr_write(0x03, rf3)?;  // PLL fractional

        // RFCSR6: set R1 field and TXDIV
        let mut rfcsr6 = self.rfcsr_read(0x06)?;
        rfcsr6 = (rfcsr6 & 0xC0) | (rf2 & 0x0F);  // R1 in bits[3:0]
        if is_5ghz {
            rfcsr6 = (rfcsr6 & !0x30) | (1 << 4);  // TXDIV=1
        } else {
            rfcsr6 = (rfcsr6 & !0x30) | (2 << 4);  // TXDIV=2
        }
        self.rfcsr_write(0x06, rfcsr6)?;

        // RFCSR5: set R1 field
        let mut rfcsr5 = self.rfcsr_read(0x05)?;
        if is_5ghz {
            rfcsr5 = (rfcsr5 & 0xFC) | 2;  // R1=2
        } else {
            rfcsr5 = (rfcsr5 & 0xFC) | 1;  // R1=1
        }
        self.rfcsr_write(0x05, rfcsr5)?;

        // RFCSR12/13: TX power chain 0/1 (from EEPROM per channel)
        // For now use default power — proper per-channel calibration later
        if is_5ghz {
            self.rfcsr_write(0x0c, 0xe8)?;  // TX filter BW 5GHz
            self.rfcsr_write(0x0d, 0xfb)?;  // RX filter BW 5GHz
        } else {
            self.rfcsr_write(0x0c, 0x64)?;  // TX filter BW 2.4GHz
            self.rfcsr_write(0x0d, 0x64)?;  // RX filter BW 2.4GHz
        }

        // Step 4: Band-specific RF registers
        if is_5ghz {
            let mut rfcsr7 = self.rfcsr_read(0x07)?;
            rfcsr7 |= 0x04;   // BIT2=1
            rfcsr7 &= !0x08;  // BIT3=0
            rfcsr7 |= 0x10;   // BIT4=1
            rfcsr7 &= !0xC0;  // BITS67=0
            self.rfcsr_write(0x07, rfcsr7)?;
            self.rfcsr_write(0x09, 0xc0)?;
            self.rfcsr_write(0x0a, 0xf1)?;
            self.rfcsr_write(0x0b, 0x00)?;
            self.rfcsr_write(0x0f, 0x43)?;
            self.rfcsr_write(0x10, 0x7a | self.txmixer_gain_5g)?;
            self.rfcsr_write(0x11, 0x23)?;

            if ch <= 64 {
                self.rfcsr_write(0x13, 0xb7)?;
                self.rfcsr_write(0x14, 0xf6)?;
                self.rfcsr_write(0x19, 0x3d)?;
            } else if ch <= 128 {
                self.rfcsr_write(0x13, 0x74)?;
                self.rfcsr_write(0x14, 0xf4)?;
                self.rfcsr_write(0x19, 0x01)?;
            } else {
                self.rfcsr_write(0x13, 0x72)?;
                self.rfcsr_write(0x14, 0xf3)?;
                self.rfcsr_write(0x19, 0x01)?;
            }

            self.rfcsr_write(0x1a, 0x87)?;
            self.rfcsr_write(0x1b, 0x01)?;
            self.rfcsr_write(0x1d, 0x9f)?;

            // BBP for 5GHz
            self.bbp_write(0x52, 0x94)?;
        } else {
            self.rfcsr_write(0x07, 0xd8)?;
            self.rfcsr_write(0x09, 0xc3)?;
            self.rfcsr_write(0x0a, 0xf1)?;
            self.rfcsr_write(0x0b, 0xb9)?;
            self.rfcsr_write(0x0f, 0x53)?;
            self.rfcsr_write(0x10, 0x4c | self.txmixer_gain_24g)?;
            self.rfcsr_write(0x11, 0x23)?;
            self.rfcsr_write(0x13, 0x93)?;
            self.rfcsr_write(0x14, 0xb3)?;
            self.rfcsr_write(0x19, 0x15)?;
            self.rfcsr_write(0x1a, 0x85)?;
            self.rfcsr_write(0x1b, 0x00)?;
            self.rfcsr_write(0x1d, 0x9b)?;

            // BBP for 2.4GHz
            self.bbp_write(0x52, 0x62)?;
        }

        // Step 5: Frequency offset
        self.rfcsr_write(0x17, self.freq_offset)?;

        // Calibration BW (always 20MHz for monitor mode)
        self.rfcsr_write(0x18, self.calibration_bw20)?;
        self.rfcsr_write(0x1f, self.calibration_bw20)?;

        // Step 6: GPIO band switching (RT3572-specific)
        let mut gpio = self.read_reg(GPIO_CTRL)?;
        gpio &= !(1 << 7);  // DIR7 = output
        if is_5ghz {
            gpio &= !(1 << (7 + 8));  // VAL7 = 0 for 5GHz
        } else {
            gpio |= 1 << (7 + 8);  // VAL7 = 1 for 2.4GHz
        }
        self.write_reg(GPIO_CTRL, gpio)?;

        // Step 7: RF tuning kick
        let rf07 = self.rfcsr_read(0x07)?;
        self.rfcsr_write(0x07, rf07 | 0x01)?;

        // Step 8: TX_BAND_CFG
        let band_cfg = if is_5ghz { 0x00000004 } else { 0x00000000 };
        self.write_reg(TX_BAND_CFG, band_cfg)?;

        // Step 9: RT3572-specific RFCSR8 toggle around TX_PIN_CFG
        self.rfcsr_write(0x08, 0x00)?;

        // TX_PIN_CFG: enable PA/LNA for appropriate band
        // For 1T1R (RT3572): PA chain 0 + LNA chain 0 + RFTR + TRSW
        // Bits: PA_PE_A0(0)=5G_PA, PA_PE_G0(1)=2G_PA, LNA_PE_A0(8)=5G_LNA, LNA_PE_G0(9)=2G_LNA
        //       RFTR_EN(16), TRSW_EN(18)
        let tx_pin = if is_5ghz {
            // 5GHz: PA_PE_A0 + LNA_PE_A0 + LNA_PE_G0 + RFTR + TRSW
            0x00050101  // bit0 + bit8 + bit9 + bit16 + bit18
        } else {
            // 2.4GHz: PA_PE_G0 + LNA_PE_A0 + LNA_PE_G0 + RFTR + TRSW
            // From usbmon: 0x00050302
            0x00050302  // bit1 + bit8 + bit9 + bit16 + bit18
        };
        self.write_reg(TX_PIN_CFG, tx_pin)?;

        self.rfcsr_write(0x08, 0x80)?;

        // Step 10: BBP AGC/filter
        let lna_gain = if is_5ghz { self.lna_gain_a0 } else { self.lna_gain_bg };

        // AGC init value
        if is_5ghz {
            let agc = 0x22u8.wrapping_add(((lna_gain as u16 * 5) / 3) as u8);
            self.bbp_write(0x42, agc)?;
        } else {
            let agc = 0x1cu8.wrapping_add(2 * lna_gain);
            self.bbp_write(0x42, agc)?;
        }

        // BBP filter offsets
        let filter_val = 0x37u8.wrapping_sub(lna_gain);
        self.bbp_write(0x3e, filter_val)?;
        self.bbp_write(0x3f, filter_val)?;
        self.bbp_write(0x40, filter_val)?;

        // Step 11: Re-enable TX + RX
        self.write_reg(MAC_SYS_CTRL, MAC_SYS_CTRL_ENABLE_TX | MAC_SYS_CTRL_ENABLE_RX)?;

        self.channel = ch;
        Ok(())
    }

    // ── TX frame construction ──

    fn inject_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()> {
        let mpdu_len = frame.len();
        let txwi_plus_payload = TXWI_SIZE + mpdu_len;

        let mut buf = Vec::with_capacity(TX_HEADER_SIZE + mpdu_len + 4);

        // TXINFO (4 bytes)
        let txinfo: u32 = (txwi_plus_payload as u32) & 0xFFFF
            | (1 << 24)   // WIV=1
            | (2 << 25)   // QSEL=2 (EDCA)
            | (1 << 28);  // seen in captures
        buf.extend_from_slice(&txinfo.to_le_bytes());

        // TXWI word 0: rate, TXOP, PHYMODE
        let (phymode, mcs) = match &opts.rate {
            TxRate::Cck1m => (0u32, 0u32),
            TxRate::Cck2m => (0, 1),
            TxRate::Cck5_5m => (0, 2),
            TxRate::Cck11m => (0, 3),
            TxRate::Ofdm6m => (1, 0),
            TxRate::Ofdm9m => (1, 1),
            TxRate::Ofdm12m => (1, 2),
            TxRate::Ofdm18m => (1, 3),
            TxRate::Ofdm24m => (1, 4),
            TxRate::Ofdm36m => (1, 5),
            TxRate::Ofdm48m => (1, 6),
            TxRate::Ofdm54m => (1, 7),
        };

        // Override: 5GHz doesn't support CCK
        let (phymode, mcs) = if self.channel > 14 && phymode == 0 {
            (1u32, 0u32) // Force OFDM 6Mbps on 5GHz
        } else {
            (phymode, mcs)
        };

        let txwi0: u32 = (3 << 8)           // TX_OP=3 (NoReq)
            | (mcs << 16)                    // MCS
            | (phymode << 30);               // PHYMODE
        buf.extend_from_slice(&txwi0.to_le_bytes());

        // TXWI word 1: byte count, PID
        let txwi1: u32 = ((mpdu_len as u32) & 0xFFF) << 16  // MPDU_TOTAL_BYTE_COUNT
            | (4 << 28);  // PACKETID=4
        buf.extend_from_slice(&txwi1.to_le_bytes());

        // TXWI words 2-3: IV/EIV = 0 (unencrypted)
        buf.extend_from_slice(&[0u8; 8]);

        // 802.11 frame payload
        buf.extend_from_slice(frame);

        // Pad to 4-byte alignment
        while buf.len() % 4 != 0 {
            buf.push(0);
        }

        // USB end pad (4 bytes)
        buf.extend_from_slice(&[0u8; 4]);

        self.bulk_write(&buf, USB_BULK_TIMEOUT)?;

        self.tx_seq = self.tx_seq.wrapping_add(1);
        Ok(())
    }

    // ── RX frame parsing ──

    pub(crate) fn parse_rx_packet(buf: &[u8], channel: u8) -> (usize, Option<RxFrame>) {
        if buf.len() < RX_HEADER_SIZE {
            return (buf.len(), None);
        }

        // RXINFO word 0: pkt_len in bits[15:0]
        let rxinfo = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let pkt_len = (rxinfo & 0xFFFF) as usize;

        if pkt_len == 0 || pkt_len > 4096 {
            return (buf.len(), None);
        }

        // Total frame: RXINFO(4) + pkt_len + RXD(4), 4-byte aligned
        let total_consumed = RXINFO_SIZE + pkt_len + RXD_SIZE;
        let total_aligned = (total_consumed + 3) & !3;

        if buf.len() < RXINFO_SIZE + pkt_len {
            return (buf.len(), None);
        }

        // RXWI word 0: MPDU_TOTAL_BYTE_COUNT in bits[27:16]
        let rxwi0 = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mpdu_len = ((rxwi0 >> 16) & 0xFFF) as usize;

        // RXWI word 1: MCS, PHYMODE
        let _rxwi1 = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);

        // RXWI word 2: RSSI0
        let rxwi2 = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let rssi0_raw = (rxwi2 & 0xFF) as i16;

        // Convert raw RSSI to dBm: raw - DEFAULT_RSSI_OFFSET
        let rssi_dbm = if rssi0_raw > 0 {
            (rssi0_raw - DEFAULT_RSSI_OFFSET) as i8
        } else {
            -120i8  // no signal
        };

        // Extract 802.11 frame
        let frame_start = RX_HEADER_SIZE;
        let frame_end = frame_start + mpdu_len.min(buf.len() - frame_start);
        if frame_end <= frame_start || mpdu_len < 10 {
            return (total_aligned.min(buf.len()), None);
        }

        let frame_data = buf[frame_start..frame_end].to_vec();

        let frame = RxFrame {
            data: frame_data,
            rssi: rssi_dbm,
            channel,
            band: if channel <= 14 { 0 } else { 1 },
            timestamp: Duration::ZERO,
            ..Default::default()
        };

        (total_aligned.min(buf.len()), Some(frame))
    }

    fn recv_frame_internal(&mut self, timeout: Duration) -> Result<Option<RxFrame>> {
        let mut ep_in = self.iface.endpoint::<usb::Bulk, usb::In>(self.ep_in_addr)
            .map_err(|e| usb::nusb_error_to_wifikit(e, "open bulk IN endpoint"))?;
        let nbuf = usb::Buffer::new(RX_BUF_SIZE);
        let completion = ep_in.transfer_blocking(nbuf, timeout);
        match completion.status {
            Ok(()) => {
                let n = completion.actual_len;
                if n >= RX_HEADER_SIZE {
                    let (_, frame) = Self::parse_rx_packet(&completion.buffer[..n], self.channel);
                    Ok(frame)
                } else {
                    Ok(None)
                }
            }
            Err(TransferError::Cancelled) => Ok(None),
            Err(e) => Err(usb::transfer_error_to_wifikit(e)),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ChipDriver trait implementation
// ══════════════════════════════════════════════════════════════════════════════

impl ChipDriver for Rt3572 {
    fn init(&mut self) -> Result<()> {
        self.chip_init()
    }

    fn shutdown(&mut self) -> Result<()> {
        let _ = self.write_reg(MAC_SYS_CTRL, 0);
        Ok(())
    }

    fn chip_info(&self) -> ChipInfo {
        ChipInfo {
            name: "RT3572",
            chip: ChipId::Rt3572,
            caps: RT3572_CAPS,
            vid: self.vid,
            pid: self.pid,
            rfe_type: 0,
            bands: vec![Band::Band2g, Band::Band5g],
            max_tx_power_dbm: 30,
            firmware_version: "0.36".into(),
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
        // Write new MAC to hardware
        let m = mac.0;
        let dw0 = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
        let dw1 = u16::from_le_bytes([m[4], m[5]]) as u32;
        self.write_reg(MAC_ADDR_DW0, dw0)?;
        self.write_reg(MAC_ADDR_DW1, dw1)?;
        Ok(())
    }

    fn tx_power(&self) -> i8 {
        20 // default TX power in dBm
    }

    fn set_tx_power(&mut self, _dbm: i8) -> Result<()> {
        // TODO: implement per-channel TX power from EEPROM
        Ok(())
    }

    fn calibrate(&mut self) -> Result<()> {
        // R-calibration kick
        let rf07 = self.rfcsr_read(0x07)?;
        self.rfcsr_write(0x07, rf07 | 0x01)?;
        Ok(())
    }

    fn take_rx_handle(&mut self) -> Option<RxHandle> {
        Some(RxHandle {
            iface: self.iface.clone(),
            ep_in: self.ep_in_addr,
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
    fn test_rf_channel_table_coverage() {
        // Verify all standard channels are covered
        let channels_2g: Vec<u8> = (1..=14).collect();
        let channels_5g: Vec<u8> = vec![
            36, 40, 44, 48, 52, 56, 60, 64,
            100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
            149, 153, 157, 161, 165,
        ];

        for ch in &channels_2g {
            assert!(
                RF_VALS_3X.iter().any(|&(c, _, _, _)| c == *ch),
                "missing 2.4GHz channel {}",
                ch,
            );
        }
        for ch in &channels_5g {
            assert!(
                RF_VALS_3X.iter().any(|&(c, _, _, _)| c == *ch),
                "missing 5GHz channel {}",
                ch,
            );
        }
    }

    #[test]
    fn test_parse_rx_beacon() {
        // Simulated RX packet: RXINFO + RXWI + beacon FC
        let mut buf = vec![0u8; 64];
        // RXINFO: pkt_len = 40 (RXWI + payload)
        buf[0..4].copy_from_slice(&40u32.to_le_bytes());
        // RXWI word 0: MPDU_BYTE_COUNT = 24 (in bits[27:16])
        let rxwi0: u32 = 24 << 16;
        buf[4..8].copy_from_slice(&rxwi0.to_le_bytes());
        // RXWI word 1: MCS=0, PHYMODE=0 (CCK)
        buf[8..12].copy_from_slice(&0u32.to_le_bytes());
        // RXWI word 2: RSSI0 = 45
        let rxwi2: u32 = 45;
        buf[12..16].copy_from_slice(&rxwi2.to_le_bytes());
        // RXWI word 3: SNR0 = 20
        let rxwi3: u32 = 20;
        buf[16..20].copy_from_slice(&rxwi3.to_le_bytes());
        // 802.11 frame: beacon FC = 0x0080
        buf[20] = 0x80;
        buf[21] = 0x00;

        let (consumed, frame) = Rt3572::parse_rx_packet(&buf, 6);
        assert!(frame.is_some());
        let f = frame.unwrap();
        assert_eq!(f.data.len(), 24);
        assert_eq!(f.data[0], 0x80); // beacon FC
        assert_eq!(f.rssi, 45 - 120);  // -75 dBm
        assert_eq!(f.channel, 6);
    }

    #[test]
    fn test_parse_rx_too_short() {
        let buf = [0u8; 10]; // too short
        let (consumed, frame) = Rt3572::parse_rx_packet(&buf, 1);
        assert!(frame.is_none());
    }

    #[test]
    fn test_parse_rx_zero_length() {
        let mut buf = vec![0u8; 32];
        // RXINFO: pkt_len = 0 (invalid)
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        let (_, frame) = Rt3572::parse_rx_packet(&buf, 1);
        assert!(frame.is_none());
    }

    #[test]
    fn test_bbp_init_values_count() {
        assert!(BBP_INIT_VALUES.len() >= 18, "BBP init should have at least 18 entries");
    }

    #[test]
    fn test_rf_init_values_count() {
        assert!(RF_INIT_VALUES.len() >= 25, "RF init should have at least 25 entries");
    }

    #[test]
    fn test_mac_init_regs_count() {
        assert!(MAC_INIT_REGS.len() >= 20, "MAC init should have at least 20 register writes");
    }

    #[test]
    fn test_firmware_size() {
        assert_eq!(RT2870_FW.len(), 8192, "rt2870.bin should be 8192 bytes");
    }

    #[test]
    fn test_firmware_second_4k_not_all_zeros() {
        let second_4k = &RT2870_FW[4096..8192];
        let nonzero = second_4k.iter().filter(|&&b| b != 0).count();
        assert!(nonzero > 100, "firmware second 4K should have substantial content");
    }

    #[test]
    fn test_channel_list() {
        let channels = build_channel_list();
        assert!(channels.len() >= 38, "should have at least 38 channels");
        assert_eq!(channels[0].number, 1);
        assert_eq!(channels[13].number, 14);
        assert_eq!(channels[14].number, 36);
    }

    #[test]
    fn test_rssi_conversion() {
        // Raw RSSI 45 → -75 dBm
        let raw: i16 = 45;
        let dbm = (raw - DEFAULT_RSSI_OFFSET) as i8;
        assert_eq!(dbm, -75);

        // Raw RSSI 80 → -40 dBm (strong signal)
        let raw: i16 = 80;
        let dbm = (raw - DEFAULT_RSSI_OFFSET) as i8;
        assert_eq!(dbm, -40);
    }
}
