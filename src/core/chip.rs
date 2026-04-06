#![allow(dead_code)]

use std::fmt;
use std::time::Duration;

use super::{Channel, Band, MacAddress, Result};
use super::frame::{RxFrame, TxOptions};

// ── ChipId — Which chipset is this adapter? ──
// Matches wifikit_chip_t from C implementation

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChipId {
    Rtl8812au,
    Rtl8812bu,
    Rtl8852au,
    Mt7921au,
    Mt7612u,
    Mt76x1,
}

impl fmt::Display for ChipId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChipId::Rtl8812au => write!(f, "RTL8812AU"),
            ChipId::Rtl8812bu => write!(f, "RTL8812BU"),
            ChipId::Rtl8852au => write!(f, "RTL8852AU"),
            ChipId::Mt7921au => write!(f, "MT7921AU"),
            ChipId::Mt7612u  => write!(f, "MT7612U"),
            ChipId::Mt76x1   => write!(f, "MT76x1"),
        }
    }
}

// ── ChipCaps — Capability bitflags ──
// Matches wifikit_cap_t from C implementation

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChipCaps: u32 {
        const MONITOR  = 1 << 0;
        const INJECT   = 1 << 1;
        const BAND_2G  = 1 << 2;
        const BAND_5G  = 1 << 3;
        const HT       = 1 << 4;
        const VHT      = 1 << 5;
        const HE       = 1 << 6;
        const BW40     = 1 << 7;
        const BW80     = 1 << 8;
        const BW160    = 1 << 9;
        const CSI      = 1 << 10;
        const TX_POWER = 1 << 11;
        const BAND_6G  = 1 << 12;
    }
}

// ── AdapterState — Lifecycle states ──
// Matches wifikit_state_t from C implementation

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterState {
    Closed,
    Opened,
    FirmwareLoaded,
    Initialized,
    Monitor,
    Capturing,
    Scanning,
}

impl Default for AdapterState {
    fn default() -> Self {
        AdapterState::Closed
    }
}

impl fmt::Display for AdapterState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterState::Closed         => write!(f, "closed"),
            AdapterState::Opened         => write!(f, "opened"),
            AdapterState::FirmwareLoaded => write!(f, "firmware loaded"),
            AdapterState::Initialized   => write!(f, "initialized"),
            AdapterState::Monitor        => write!(f, "monitor"),
            AdapterState::Capturing      => write!(f, "capturing"),
            AdapterState::Scanning       => write!(f, "scanning"),
        }
    }
}

// ── KnownAdapter — Static registry entry ──
// Matches known_adapters[] from C implementation

#[derive(Debug, Clone)]
pub struct KnownAdapter {
    pub vid: u16,
    pub pid: u16,
    pub chip: ChipId,
    pub name: &'static str,
}

/// Static registry of known WiFi adapters.
/// To add a new adapter: add an entry here + implement ChipDriver for its chip.
/// Matches the known_adapters[] table from the C implementation.
pub const KNOWN_ADAPTERS: &[KnownAdapter] = &[
    // RTL8812AU adapters (USB 2.0, 802.11ac dual-band)
    KnownAdapter { vid: 0x0BDA, pid: 0x8812, chip: ChipId::Rtl8812au, name: "Realtek RTL8812AU" },
    KnownAdapter { vid: 0x0BDA, pid: 0x881A, chip: ChipId::Rtl8812au, name: "Realtek RTL8812AU" },
    KnownAdapter { vid: 0x0BDA, pid: 0x881B, chip: ChipId::Rtl8812au, name: "Realtek RTL8812AU" },
    KnownAdapter { vid: 0x0BDA, pid: 0x881C, chip: ChipId::Rtl8812au, name: "Realtek RTL8812AU" },
    KnownAdapter { vid: 0x050D, pid: 0x1106, chip: ChipId::Rtl8812au, name: "Belkin F9L1109v1 (RTL8812AU)" },
    KnownAdapter { vid: 0x050D, pid: 0x1109, chip: ChipId::Rtl8812au, name: "Belkin (RTL8812AU)" },
    KnownAdapter { vid: 0x0846, pid: 0x9051, chip: ChipId::Rtl8812au, name: "Netgear A6200 v2 (RTL8812AU)" },
    KnownAdapter { vid: 0x0411, pid: 0x025D, chip: ChipId::Rtl8812au, name: "Buffalo (RTL8812AU)" },
    KnownAdapter { vid: 0x04BB, pid: 0x0952, chip: ChipId::Rtl8812au, name: "I-O DATA (RTL8812AU)" },
    KnownAdapter { vid: 0x2357, pid: 0x0101, chip: ChipId::Rtl8812au, name: "TP-Link Archer T4U V1 (RTL8812AU)" },
    KnownAdapter { vid: 0x2357, pid: 0x0103, chip: ChipId::Rtl8812au, name: "TP-Link Archer T4UH (RTL8812AU)" },
    KnownAdapter { vid: 0x2357, pid: 0x010D, chip: ChipId::Rtl8812au, name: "TP-Link Archer T4U V2 (RTL8812AU)" },
    KnownAdapter { vid: 0x2357, pid: 0x010E, chip: ChipId::Rtl8812au, name: "TP-Link Archer T4UH V2 (RTL8812AU)" },
    KnownAdapter { vid: 0x2357, pid: 0x010F, chip: ChipId::Rtl8812au, name: "TP-Link (RTL8812AU)" },
    KnownAdapter { vid: 0x2357, pid: 0x0122, chip: ChipId::Rtl8812au, name: "TP-Link (RTL8812AU)" },
    KnownAdapter { vid: 0x2604, pid: 0x0012, chip: ChipId::Rtl8812au, name: "Tenda U12 (RTL8812AU)" },  // Note: same VID/PID may also be Tenda U18a on RTL8832AU — check chip ID
    KnownAdapter { vid: 0x7392, pid: 0xA822, chip: ChipId::Rtl8812au, name: "Edimax EW-7822UAC (RTL8812AU)" },
    KnownAdapter { vid: 0x0409, pid: 0x0408, chip: ChipId::Rtl8812au, name: "NEC (RTL8812AU)" },
    // RTL8812BU adapters (USB 3.0, 802.11ac dual-band)
    KnownAdapter { vid: 0x2357, pid: 0x0115, chip: ChipId::Rtl8812bu, name: "TP-Link Archer T4U V3 (RTL8812BU)" },
    KnownAdapter { vid: 0x0B05, pid: 0x1841, chip: ChipId::Rtl8812bu, name: "ASUS USB-AC53 Nano (RTL8812BU)" },
    KnownAdapter { vid: 0x0B05, pid: 0x184C, chip: ChipId::Rtl8812bu, name: "ASUS USB-AC55 B1 (RTL8812BU)" },
    KnownAdapter { vid: 0x0846, pid: 0x9052, chip: ChipId::Rtl8812bu, name: "Netgear A6100 (RTL8812BU)" },
    KnownAdapter { vid: 0x0BDA, pid: 0xB812, chip: ChipId::Rtl8812bu, name: "Realtek RTL8812BU (generic)" },
    // RTL8852AU adapters (WiFi 6, AX1800, USB 3.0, 2T2R dual-band)
    KnownAdapter { vid: 0x2357, pid: 0x013F, chip: ChipId::Rtl8852au, name: "TP-Link Archer TX20U Plus (RTL8852AU)" },
    KnownAdapter { vid: 0x2357, pid: 0x012F, chip: ChipId::Rtl8852au, name: "TP-Link Archer TX20U Plus (RTL8852AU)" },
    KnownAdapter { vid: 0x2357, pid: 0x012E, chip: ChipId::Rtl8852au, name: "TP-Link Archer TX20U Nano (RTL8852AU)" },
    KnownAdapter { vid: 0x0BDA, pid: 0x885A, chip: ChipId::Rtl8852au, name: "Realtek RTL8852AU" },
    KnownAdapter { vid: 0x0BDA, pid: 0x885C, chip: ChipId::Rtl8852au, name: "Realtek RTL8832AU" },
    KnownAdapter { vid: 0x0BDA, pid: 0x8832, chip: ChipId::Rtl8852au, name: "Realtek RTL8832AU" },
    KnownAdapter { vid: 0x0B05, pid: 0x1A62, chip: ChipId::Rtl8852au, name: "ASUS USB-AX56 (RTL8832AU)" },
    KnownAdapter { vid: 0x0B05, pid: 0x1997, chip: ChipId::Rtl8852au, name: "ASUS USB-AX56 (RTL8832AU)" },
    KnownAdapter { vid: 0x0411, pid: 0x0312, chip: ChipId::Rtl8852au, name: "BUFFALO WI-U3-1200AX2 (RTL8852AU)" },
    // MT7921AU adapters (USB 3.0, 802.11ax WiFi 6 dual-band)
    KnownAdapter { vid: 0x0E8D, pid: 0x7961, chip: ChipId::Mt7921au, name: "MediaTek MT7921AU (combo BT+WiFi)" },
    KnownAdapter { vid: 0x3574, pid: 0x6211, chip: ChipId::Mt7921au, name: "COMFAST CF-952AX (MT7921AU)" },
    KnownAdapter { vid: 0x0846, pid: 0x9060, chip: ChipId::Mt7921au, name: "Netgear A8000/AXE3000 (MT7921AU)" },
    KnownAdapter { vid: 0x0846, pid: 0x9065, chip: ChipId::Mt7921au, name: "Netgear A7500 (MT7921AU)" },
    KnownAdapter { vid: 0x35BC, pid: 0x0107, chip: ChipId::Mt7921au, name: "TP-Link TXE50UH (MT7921AU)" },
    // MT7612U adapters (USB 3.0, 802.11ac dual-band) — requires mode switch from 0x0E8D:0x2870
    KnownAdapter { vid: 0x0E8D, pid: 0x7612, chip: ChipId::Mt7612u, name: "MediaTek MT7612U" },
    KnownAdapter { vid: 0x0E8D, pid: 0x7632, chip: ChipId::Mt7612u, name: "MediaTek MT7632U" },
    KnownAdapter { vid: 0x0B05, pid: 0x1833, chip: ChipId::Mt7612u, name: "ASUS USB-AC54 (MT7612U)" },
    KnownAdapter { vid: 0x0B05, pid: 0x17EB, chip: ChipId::Mt7612u, name: "ASUS USB-AC55 (MT7612U)" },
    KnownAdapter { vid: 0x0B05, pid: 0x180B, chip: ChipId::Mt7612u, name: "ASUS USB-N53 B1 (MT7612U)" },
    KnownAdapter { vid: 0x057C, pid: 0x8503, chip: ChipId::Mt7612u, name: "AVM FRITZ!WLAN AC860 (MT7612U)" },
    KnownAdapter { vid: 0x7392, pid: 0xB711, chip: ChipId::Mt7612u, name: "Edimax EW-7722UAC (MT7612U)" },
    KnownAdapter { vid: 0x0846, pid: 0x9014, chip: ChipId::Mt7612u, name: "Netgear WNDA3100v3 (MT7612U)" },
    KnownAdapter { vid: 0x0846, pid: 0x9053, chip: ChipId::Mt7612u, name: "Netgear A6210 (MT7612U)" },
    KnownAdapter { vid: 0x045E, pid: 0x02E6, chip: ChipId::Mt7612u, name: "Xbox One Wireless (MT7612U)" },
    KnownAdapter { vid: 0x045E, pid: 0x02FE, chip: ChipId::Mt7612u, name: "Xbox One Wireless (MT7612U)" },
    KnownAdapter { vid: 0x2357, pid: 0x0137, chip: ChipId::Mt7612u, name: "TP-Link TL-WDN6200 (MT7612U)" },
];

/// Look up chip ID by USB vendor/product ID.
/// Matches identify_chip() from C implementation.
pub fn identify_chip(vid: u16, pid: u16) -> Option<ChipId> {
    KNOWN_ADAPTERS.iter()
        .find(|a| a.vid == vid && a.pid == pid)
        .map(|a| a.chip)
}

/// Look up human-readable adapter name by USB vendor/product ID.
/// Matches find_adapter_name() from C implementation.
pub fn find_adapter_name(vid: u16, pid: u16) -> Option<&'static str> {
    KNOWN_ADAPTERS.iter()
        .find(|a| a.vid == vid && a.pid == pid)
        .map(|a| a.name)
}

// ── ChannelSurvey — per-channel utilization data from MIB registers ──

/// Per-channel survey data read from hardware MIB registers.
/// All values are cumulative microseconds since last reset.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChannelSurvey {
    /// Total time PHY detected energy above CCA threshold (channel busy).
    pub busy_us: u32,
    /// Time spent transmitting frames.
    pub tx_us: u32,
    /// Time spent receiving valid frames from our BSS.
    pub rx_us: u32,
    /// Time spent receiving frames from other BSSes (OBSS).
    pub obss_us: u32,
}

impl ChannelSurvey {
    /// Channel utilization as percentage (0.0 - 100.0).
    /// Based on busy_us relative to a known dwell time.
    pub fn utilization_pct(&self, dwell_us: u32) -> f32 {
        if dwell_us == 0 { return 0.0; }
        (self.busy_us as f32 / dwell_us as f32 * 100.0).min(100.0)
    }

    /// Noise estimate: busy time that's neither TX nor RX (interference + noise).
    pub fn noise_us(&self) -> u32 {
        self.busy_us.saturating_sub(self.tx_us + self.rx_us)
    }
}

// ── ChipInfo — Runtime info from a live driver ──

pub struct ChipInfo {
    pub name: &'static str,
    pub chip: ChipId,
    pub caps: ChipCaps,
    pub vid: u16,
    pub pid: u16,
    pub rfe_type: u8,
    pub bands: Vec<Band>,
    pub max_tx_power_dbm: i8,
    pub firmware_version: String,
}

// ── ChipDriver — Hardware abstraction trait ──
// This IS the Rust equivalent of chip_ops_t.
// Each chipset implements this trait. The compiler enforces completeness.

pub trait ChipDriver: Send {
    // Lifecycle
    fn init(&mut self) -> Result<()>;
    fn shutdown(&mut self) -> Result<()>;
    fn chip_info(&self) -> ChipInfo;

    // Channel
    fn set_channel(&mut self, channel: Channel) -> Result<()>;
    fn supported_channels(&self) -> &[Channel];

    // Monitor mode
    fn set_monitor_mode(&mut self) -> Result<()>;

    // TX / RX
    fn tx_frame(&mut self, frame: &[u8], opts: &TxOptions) -> Result<()>;
    fn rx_frame(&mut self, timeout: Duration) -> Result<Option<RxFrame>>;

    // MAC
    fn mac(&self) -> MacAddress;
    fn set_mac(&mut self, mac: MacAddress) -> Result<()>;

    // Power
    fn tx_power(&self) -> i8;
    fn set_tx_power(&mut self, dbm: i8) -> Result<()>;

    // Calibration
    fn calibrate(&mut self) -> Result<()>;

    // ── Capabilities (adapters override these) ──

    /// Minimum time to wait after set_channel() before the radio is receiving.
    /// Accounts for PLL retune, AGC settling, and firmware processing.
    /// The scanner sleeps this duration after each channel switch.
    ///
    /// Default: 10ms (conservative for register-based chips).
    /// Override for MCU-based chips with longer firmware retune (e.g., MT7921: 200ms).
    fn channel_settle_time(&self) -> Duration {
        Duration::from_millis(10)
    }

    /// Recommended dwell time per channel during scanning.
    ///
    /// Fast-switching adapters (register-based PLL, <5ms switch) use 500ms.
    /// Slow-switching adapters (MCU firmware command, 140-500ms switch) use longer
    /// dwell to amortize the expensive switch cost and capture more STA traffic.
    ///
    /// Default: 500ms. Override for slow-switching chipsets.
    fn scan_dwell_time(&self) -> Duration {
        Duration::from_millis(500)
    }

    /// Which bands this adapter supports. Derived from supported_channels().
    /// Used by the scanner to auto-enable band scanning.
    fn supported_bands(&self) -> Vec<Band> {
        let mut bands = Vec::new();
        for ch in self.supported_channels() {
            if !bands.contains(&ch.band) {
                bands.push(ch.band);
            }
        }
        bands
    }

    // ── Channel Survey — per-channel utilization from MIB registers ──

    /// Read per-channel survey data (busy/tx/rx/obss time in microseconds).
    /// Works in normal mode — no testmode needed.
    fn survey_read(&self, _band_idx: u8) -> Result<ChannelSurvey> {
        Err(crate::core::Error::NotSupported("survey not supported by this chip".into()))
    }

    /// Reset survey counters to start fresh measurement.
    fn survey_reset(&self, _band_idx: u8) -> Result<()> {
        Err(crate::core::Error::NotSupported("survey not supported by this chip".into()))
    }

    /// Enable MIB duration reporting. Call once during init.
    fn survey_enable(&self, _band_idx: u8) -> Result<()> {
        Err(crate::core::Error::NotSupported("survey not supported by this chip".into()))
    }

    // ── RF Test Mode / Spectrum Analyzer ──

    /// Whether this adapter supports RF test mode (spectrum analyzer, I/Q capture).
    /// Only MediaTek ConnAC 2.0+ chips (MT7921, MT7925) support this.
    fn supports_testmode(&self) -> bool { false }

    /// Enter WiFi spectrum analyzer mode. Firmware outputs spectral data.
    fn enter_spectrum_mode(&mut self) -> Result<()> {
        Err(crate::core::Error::NotSupported("spectrum mode not supported by this chip".into()))
    }

    /// Enter I/Q capture mode (raw baseband samples — SDR mode).
    fn enter_icap_mode(&mut self) -> Result<()> {
        Err(crate::core::Error::NotSupported("ICAP mode not supported by this chip".into()))
    }

    /// Enter RF test mode (TX/RX control, power tuning, frequency offset).
    fn enter_rftest_mode(&mut self) -> Result<()> {
        Err(crate::core::Error::NotSupported("RF test mode not supported by this chip".into()))
    }

    /// Exit any test mode and return to normal WiFi operation.
    fn exit_testmode(&mut self) -> Result<()> {
        Err(crate::core::Error::NotSupported("test mode not supported by this chip".into()))
    }

    /// Set TX power in test mode. power_half_dbm = power in 0.5 dBm units.
    fn testmode_set_tx_power(&mut self, _power_half_dbm: u32) -> Result<()> {
        Err(crate::core::Error::NotSupported("test mode power control not supported".into()))
    }

    /// Set frequency offset in test mode (fine RF tuning).
    fn testmode_set_freq_offset(&mut self, _offset: u32) -> Result<()> {
        Err(crate::core::Error::NotSupported("test mode freq offset not supported".into()))
    }

    /// Set TX antenna mask in test mode. mask: 0x1=ant0, 0x2=ant1, 0x3=both
    fn testmode_set_tx_antenna(&mut self, _mask: u32) -> Result<()> {
        Err(crate::core::Error::NotSupported("test mode antenna control not supported".into()))
    }

    /// Set system bandwidth in test mode. bw: 0=20, 1=40, 2=80
    fn testmode_set_system_bw(&mut self, _bw: u32) -> Result<()> {
        Err(crate::core::Error::NotSupported("test mode BW control not supported".into()))
    }

    /// Configure and start burst TX in test mode.
    fn testmode_burst_tx(&mut self,
        _channel: u32, _bw: u32, _rate_mode: u32, _nss: u32,
        _power_half_dbm: u32, _pkt_count: u32, _ipg_us: u32,
    ) -> Result<()> {
        Err(crate::core::Error::NotSupported("test mode burst TX not supported".into()))
    }

    /// Enable/disable continuous TX (CW tone — no gaps).
    fn testmode_set_tx_continuous(&mut self, _enable: bool) -> Result<()> {
        Err(crate::core::Error::NotSupported("test mode continuous TX not supported".into()))
    }

    /// Query chip temperature from firmware thermal sensor.
    fn testmode_get_temperature(&mut self) -> Result<(u32, u32)> {
        Err(crate::core::Error::NotSupported("test mode temperature query not supported".into()))
    }

    /// Query RX statistics (packet count, FCS error count).
    fn testmode_get_rx_stats(&mut self) -> Result<(u32, u32)> {
        Err(crate::core::Error::NotSupported("test mode RX stats not supported".into()))
    }

    // ── RX split support (pipeline architecture) ──

    /// Start a driver-managed RX pipeline.
    ///
    /// Drivers that need custom RX handling (e.g., stream-based USB parsing)
    /// implement this to spawn their own internal threads. The driver reads
    /// USB, parses chip-specific packets, and submits clean RxFrames to the
    /// FrameGate — just like any other driver, but with full control over
    /// the RX path.
    ///
    /// `gate`: submit parsed RxFrames here via gate.submit().
    /// `alive`: check this flag — stop all threads when it becomes false.
    ///
    /// Returns true if the driver took over RX (SharedAdapter skips its own
    /// RX thread). Returns false to fall back to take_rx_handle().
    fn start_rx_pipeline(
        &mut self,
        _gate: crate::pipeline::FrameGate,
        _alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> bool {
        false
    }

    /// Extract the USB device handle for dedicated RX thread use.
    ///
    /// Returns (DeviceHandle as raw ptr, bulk_in endpoint, rx_buf_size).
    /// The RxThread will use this to read USB bulk IN independently
    /// of the main driver, enabling concurrent TX+RX.
    ///
    /// After calling this, the driver's own rx_frame() should NOT be used
    /// (the RxThread owns the RX endpoint).
    ///
    /// Default: None (driver doesn't support split RX yet).
    fn take_rx_handle(&mut self) -> Option<RxHandle> {
        None
    }
}

/// What the RX parser found in a USB bulk packet.
///
/// Adapters return different variants depending on what the packet contains:
/// - Register-based chips (RTL): only Frame and Skip
/// - MCU-based chips (MediaTek): Frame, DriverMessage, TxStatus, and Skip
// ── TX Status Report ──
// Structured TX completion feedback from firmware.

#[derive(Debug, Clone)]
pub struct TxReport {
    /// Packet ID assigned at TX time.
    pub pkt_id: u16,
    /// Queue that transmitted this frame (0=BE, 1=BK, 2=VI, 3=VO, 4+=special).
    pub queue_sel: u8,
    /// TX result: 0=success (ACKed), 1=retry limit, 2=lifetime expired, etc.
    pub tx_state: u8,
    /// Number of TX attempts (1 = succeeded first try).
    pub tx_cnt: u8,
    /// Whether the frame was ACKed by the receiver.
    pub acked: bool,
    /// Final data rate used (after any fallback). Same encoding as RxFrame.data_rate.
    pub final_rate: u16,
    /// Final bandwidth used.
    pub final_bw: u8,
    /// Final GI/LTF type.
    pub final_gi_ltf: u8,
    /// MAC ID of the peer.
    pub mac_id: u8,
    /// Timestamp from firmware (freerun counter).
    pub timestamp: u32,
    /// Total airtime consumed (μs) including retries.
    pub total_airtime_us: u16,
    /// Raw payload for driver-specific extended parsing.
    pub raw: Vec<u8>,
}

// ── Channel State Information (CSI) ──
// Raw channel frequency response per subcarrier per antenna pair.

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    /// Channel number this CSI was measured on.
    pub channel: u8,
    /// Bandwidth: 0=20MHz, 1=40MHz, 2=80MHz, 3=160MHz.
    pub bandwidth: u8,
    /// Number of RX chains (Nr).
    pub nr: u8,
    /// Number of TX chains (Nc) — from the sender's perspective.
    pub nc: u8,
    /// Number of subcarriers in the CSI matrix.
    pub num_subcarriers: u16,
    /// Raw CSI matrix: I/Q pairs per subcarrier per antenna pair.
    /// Layout: [subcarrier_0_ant_pair_0_I, _Q, subcarrier_0_ant_pair_1_I, _Q, ...]
    pub csi_raw: Vec<i16>,
    /// Timestamp from firmware (freerun counter).
    pub timestamp: u32,
    /// Raw payload for extended parsing.
    pub raw: Vec<u8>,
}

// ── DFS Radar Detection Report ──

#[derive(Debug, Clone)]
pub struct DfsReport {
    /// Channel the radar was detected on.
    pub channel: u8,
    /// Band index (0=2.4GHz, 1=5GHz).
    pub band: u8,
    /// Radar pulse width in μs.
    pub pulse_width_us: u16,
    /// Pulse repetition interval in μs.
    pub pri_us: u16,
    /// Number of pulses in this detection window.
    pub pulse_count: u8,
    /// Radar type classification (chipset-specific).
    pub radar_type: u8,
    /// Timestamp from firmware.
    pub timestamp: u32,
    /// Raw payload for extended analysis.
    pub raw: Vec<u8>,
}

// ── C2H (Command-to-Host) Firmware Event ──

#[derive(Debug, Clone)]
pub struct C2hEvent {
    /// Category: 0=MAC, 1=BB, 2=RF, 3=BT, 4=FW, etc.
    pub category: u8,
    /// Class within category.
    pub class: u8,
    /// Function within class.
    pub function: u8,
    /// Sequence number for matching request/response.
    pub seq: u8,
    /// Payload data (after header).
    pub payload: Vec<u8>,
    /// Raw packet including header.
    pub raw: Vec<u8>,
}

// ── BB Scope (Baseband I/Q Samples) ──

#[derive(Debug, Clone)]
pub struct BbScope {
    /// Channel this capture was taken on.
    pub channel: u8,
    /// Sample rate index (chipset-specific).
    pub sample_rate_idx: u8,
    /// I/Q sample pairs. Each pair is (I, Q) as signed 16-bit.
    pub samples_iq: Vec<(i16, i16)>,
    /// Timestamp from firmware.
    pub timestamp: u32,
    /// Raw payload.
    pub raw: Vec<u8>,
}

// ── Spatial Sounding Report (Beamforming) ──

#[derive(Debug, Clone)]
pub struct SpatialSoundingReport {
    /// MAC address of the sounding initiator (usually an AP).
    pub initiator: [u8; 6],
    /// Number of spatial streams.
    pub nss: u8,
    /// Channel bandwidth.
    pub bandwidth: u8,
    /// Raw sounding feedback data (V-matrix compressed).
    pub raw: Vec<u8>,
}

// ── TX PD Release ──

#[derive(Debug, Clone)]
pub struct TxPdRelease {
    /// Which release path: Host (7) or WLCPU (9).
    pub release_type: u8,
    /// Packet descriptor IDs being released.
    pub pd_ids: Vec<u16>,
    /// Raw payload.
    pub raw: Vec<u8>,
}

// ── F2P TX Command Report ──

#[derive(Debug, Clone)]
pub struct F2pTxCmdReport {
    /// MAC ID.
    pub mac_id: u8,
    /// Queue selection.
    pub queue_sel: u8,
    /// Raw payload.
    pub raw: Vec<u8>,
}

pub enum ParsedPacket {
    /// A valid 802.11 frame — feed to the FramePipeline.
    Frame(RxFrame),
    /// A driver-internal message (MCU response, firmware event, etc.).
    /// The RX thread forwards this to the driver via `driver_msg_tx`.
    DriverMessage(Vec<u8>),
    /// Structured TX completion report — ACK/NACK, retry count, final rate.
    TxStatus(TxReport),
    /// Raw channel state information — subcarrier-level I/Q response.
    ChannelInfo(ChannelInfo),
    /// DFS radar detection event.
    DfsReport(DfsReport),
    /// Firmware C2H (command-to-host) structured event.
    C2hEvent(C2hEvent),
    /// Raw baseband I/Q waveform capture.
    BbScope(BbScope),
    /// Beamforming spatial sounding measurement report.
    SpatialSounding(SpatialSoundingReport),
    /// F2P TX scheduling report from firmware.
    F2pTxCmdReport(F2pTxCmdReport),
    /// TX packet descriptor release notification.
    TxPdRelease(TxPdRelease),
    /// Uninteresting packet — drop silently.
    Skip,
}

/// Handle for the dedicated RX thread to read USB bulk IN independently.
///
/// Contains an Arc to the USB device handle (shared with the driver for TX),
/// the bulk IN endpoint address, and a function pointer to parse chip-specific
/// RX descriptors into ParsedPackets.
///
/// Since rusb's DeviceHandle is Send+Sync and read_bulk/write_bulk take &self,
/// concurrent reads (RX thread) and writes (attack TX) on different endpoints
/// are safe.
pub struct RxHandle {
    /// Shared USB device handle — same physical device as the driver uses for TX.
    pub device: std::sync::Arc<rusb::DeviceHandle<rusb::GlobalContext>>,
    /// Bulk IN endpoint address (e.g., 0x81).
    pub ep_in: u8,
    /// RX buffer size for USB bulk reads.
    pub rx_buf_size: usize,
    /// Parse function: takes (buffer, current_channel) → (bytes_consumed, ParsedPacket).
    /// Called repeatedly on the USB bulk read buffer to extract individual packets.
    pub parse_fn: fn(&[u8], u8) -> (usize, ParsedPacket),
    /// Optional channel for DriverMessage packets.
    /// Only MCU-based adapters (MediaTek) set this. Register-based adapters (RTL) leave it None.
    /// The driver's MCU response path reads from the corresponding Receiver.
    pub driver_msg_tx: Option<std::sync::mpsc::Sender<Vec<u8>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_chip_known_adapter() {
        assert_eq!(identify_chip(0x2357, 0x0115), Some(ChipId::Rtl8812bu));
        assert_eq!(identify_chip(0x0B05, 0x1841), Some(ChipId::Rtl8812bu));
        assert_eq!(identify_chip(0x0E8D, 0x7961), Some(ChipId::Mt7921au));
        assert_eq!(identify_chip(0x3574, 0x6211), Some(ChipId::Mt7921au));
    }

    #[test]
    fn test_identify_chip_unknown_adapter() {
        assert_eq!(identify_chip(0xDEAD, 0xBEEF), None);
        assert_eq!(identify_chip(0x0000, 0x0000), None);
    }

    #[test]
    fn test_find_adapter_name() {
        assert_eq!(find_adapter_name(0x2357, 0x0115), Some("TP-Link Archer T4U V3 (RTL8812BU)"));
        assert_eq!(find_adapter_name(0xDEAD, 0xBEEF), None);
    }

    #[test]
    fn test_chip_id_display() {
        assert_eq!(format!("{}", ChipId::Rtl8812bu), "RTL8812BU");
        assert_eq!(format!("{}", ChipId::Mt7921au), "MT7921AU");
        assert_eq!(format!("{}", ChipId::Mt76x1), "MT76x1");
    }

    #[test]
    fn test_chip_caps_flags() {
        let rtl_caps = ChipCaps::MONITOR | ChipCaps::INJECT | ChipCaps::BAND_2G
            | ChipCaps::BAND_5G | ChipCaps::HT | ChipCaps::VHT
            | ChipCaps::BW40 | ChipCaps::BW80;
        assert!(rtl_caps.contains(ChipCaps::MONITOR));
        assert!(rtl_caps.contains(ChipCaps::INJECT));
        assert!(!rtl_caps.contains(ChipCaps::HE));
        assert!(!rtl_caps.contains(ChipCaps::BW160));
    }

    #[test]
    fn test_adapter_state_display() {
        assert_eq!(format!("{}", AdapterState::Monitor), "monitor");
        assert_eq!(format!("{}", AdapterState::Initialized), "initialized");
    }

    #[test]
    fn test_known_adapters_no_duplicates() {
        for (i, a) in KNOWN_ADAPTERS.iter().enumerate() {
            for (j, b) in KNOWN_ADAPTERS.iter().enumerate() {
                if i != j {
                    assert!(
                        a.vid != b.vid || a.pid != b.pid,
                        "duplicate VID/PID: {:#06x}/{:#06x} at indices {} and {}",
                        a.vid, a.pid, i, j
                    );
                }
            }
        }
    }
}
