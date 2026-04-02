#![allow(dead_code)]

use std::path::PathBuf;
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════════
//  SUPPORTING ENUMS — Semantic sub-types for structured error variants
// ═══════════════════════════════════════════════════════════════════════════════

/// Stage during chip initialization where failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitStage {
    /// USB interface/descriptor enumeration
    UsbEnumeration,
    /// MAC power-on and register verification
    MacPowerOn,
    /// Thread spawn for adapter
    ThreadSpawn,
    /// PHY/RF calibration
    Calibration,
    /// General hardware setup
    HardwareSetup,
    /// Register read/write access
    RegisterAccess,
    /// Power sequence (MCU power on)
    PowerSequence,
    /// DMA engine initialization
    DmaInit,
    /// Firmware download
    FirmwareDownload,
    /// Channel switch
    ChannelSwitch,
    /// Monitor mode setup
    MonitorMode,
}

impl std::fmt::Display for InitStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UsbEnumeration => write!(f, "USB enumeration"),
            Self::MacPowerOn => write!(f, "MAC power-on"),
            Self::ThreadSpawn => write!(f, "thread spawn"),
            Self::Calibration => write!(f, "calibration"),
            Self::HardwareSetup => write!(f, "hardware setup"),
            Self::RegisterAccess => write!(f, "register access"),
            Self::PowerSequence => write!(f, "power sequence"),
            Self::DmaInit => write!(f, "DMA init"),
            Self::FirmwareDownload => write!(f, "firmware download"),
            Self::ChannelSwitch => write!(f, "channel switch"),
            Self::MonitorMode => write!(f, "monitor mode"),
        }
    }
}

/// Kind of firmware error encountered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareErrorKind {
    /// Firmware image is too small to contain valid header
    TooSmall,
    /// Section checksum verification failed
    ChecksumFailed,
    /// Section extends beyond firmware file boundary
    SectionOverflow,
    /// Firmware download to chip failed
    DownloadFailed,
    /// Firmware version mismatch
    VersionMismatch,
}

impl std::fmt::Display for FirmwareErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall => write!(f, "firmware too small"),
            Self::ChecksumFailed => write!(f, "section checksum failed"),
            Self::SectionOverflow => write!(f, "section extends beyond firmware file"),
            Self::DownloadFailed => write!(f, "firmware download failed"),
            Self::VersionMismatch => write!(f, "firmware version mismatch"),
        }
    }
}

/// Export file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// PCAP packet capture
    Pcap,
    /// Hashcat hccapx (legacy -m 2500)
    Hccapx,
    /// Hashcat hc22000 (modern -m 22000)
    Hc22000,
    /// EAP credential export
    EapCredentials,
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pcap => write!(f, "pcap"),
            Self::Hccapx => write!(f, "hccapx"),
            Self::Hc22000 => write!(f, "hc22000"),
            Self::EapCredentials => write!(f, "eap-credentials"),
        }
    }
}

/// What I/O operation failed during export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportOp {
    /// Creating/opening the output file
    Create,
    /// Writing header bytes
    WriteHeader,
    /// Writing record/packet data
    WriteData,
    /// Flushing to disk
    Flush,
}

impl std::fmt::Display for ExportOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::WriteHeader => write!(f, "write header"),
            Self::WriteData => write!(f, "write data"),
            Self::Flush => write!(f, "flush"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ERROR ENUM
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Error)]
pub enum Error {
    // === USB / Adapter ===
    #[error("USB error: {0}")]
    Usb(#[from] rusb::Error),

    #[error("adapter not found: VID={vid:#06x} PID={pid:#06x}")]
    AdapterNotFound { vid: u16, pid: u16 },

    #[error("no compatible adapter found")]
    NoAdapter,

    #[error("USB {direction} endpoint not found")]
    EndpointNotFound { direction: &'static str, vid: u16, pid: u16 },

    #[error("adapter not initialized")]
    AdapterNotInitialized,

    // === Chip Driver ===
    #[error("chip not supported: VID={vid:#06x} PID={pid:#06x}")]
    UnsupportedChip { vid: u16, pid: u16 },

    #[error("chip init failed [{chip}] at {stage}: {reason}")]
    ChipInitFailed {
        chip: String,
        stage: InitStage,
        reason: String,
    },

    #[error("firmware error [{chip}]: {kind}")]
    FirmwareError {
        chip: String,
        kind: FirmwareErrorKind,
    },

    #[error("poll timeout: addr={addr:#06x} mask={mask:#04x} expected={expected:#04x}")]
    PollTimeout { addr: u16, mask: u8, expected: u8 },

    #[error("USB transfer failed: endpoint={endpoint:#04x}: {reason}")]
    UsbTransferFailed { endpoint: u8, reason: String },

    #[error("channel {channel} not supported by {chip}")]
    UnsupportedChannel { channel: u8, chip: String },

    #[error("monitor mode failed [{chip}]: {reason}")]
    MonitorModeFailed { chip: String, reason: &'static str },

    // === TX / RX ===
    #[error("TX failed after {retries} retries: {reason}")]
    TxFailed { retries: u8, reason: String },

    #[error("TX timeout on channel {channel}")]
    TxTimeout { channel: u8 },

    #[error("RX timeout")]
    RxTimeout,

    #[error("timeout")]
    Timeout,

    // === Register ===
    #[error("register write failed: addr={addr:#06x} val={val:#010x}")]
    RegisterWriteFailed { addr: u16, val: u32 },

    #[error("register read failed: addr={addr:#06x}")]
    RegisterReadFailed { addr: u16 },

    // === Attack ===
    // === Capability ===
    #[error("not supported: {0}")]
    NotSupported(String),

    // === Attack ===
    #[error("attack already running: {name}")]
    AttackAlreadyRunning { name: &'static str },

    #[error("attack not running")]
    AttackNotRunning,

    #[error("attack thread panicked")]
    ThreadPanicked,

    #[error("attack timed out after {elapsed_ms}ms")]
    AttackTimeout { elapsed_ms: u64 },

    // === Channel ===
    #[error("channel {channel} locked by {holder}")]
    ChannelLocked { channel: u8, holder: String },

    // === Scan ===
    #[error("target not found: {ssid}")]
    TargetNotFound { ssid: String },

    // === Export ===
    #[error("export failed: {format} {op} '{path}': {source}")]
    ExportFailed {
        format: ExportFormat,
        op: ExportOp,
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // === CLI ===
    #[error("requires root privileges (run with sudo)")]
    RequiresRoot,

    #[error("invalid argument '{param}': got {value}, expected {expected}")]
    InvalidArgument {
        param: &'static str,
        value: String,
        expected: &'static str,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_adapter_not_found() {
        let e = Error::AdapterNotFound { vid: 0x0BDA, pid: 0xB812 };
        assert_eq!(e.to_string(), "adapter not found: VID=0x0bda PID=0xb812");
    }

    #[test]
    fn test_error_display_poll_timeout() {
        let e = Error::PollTimeout { addr: 0x0005, mask: 0x02, expected: 0x00 };
        let s = e.to_string();
        assert!(s.contains("poll timeout"));
        assert!(s.contains("0x0005"));
    }

    #[test]
    fn test_error_display_unsupported_channel() {
        let e = Error::UnsupportedChannel { channel: 14, chip: "RTL8812BU".into() };
        assert_eq!(e.to_string(), "channel 14 not supported by RTL8812BU");
    }

    #[test]
    fn test_error_display_tx_failed() {
        let e = Error::TxFailed { retries: 3, reason: "bulk write error".into() };
        assert!(e.to_string().contains("3 retries"));
    }

    #[test]
    fn test_error_display_endpoint_not_found() {
        let e = Error::EndpointNotFound { direction: "bulk IN", vid: 0x0BDA, pid: 0xB812 };
        assert!(e.to_string().contains("bulk IN"));
    }

    #[test]
    fn test_error_display_chip_init_failed() {
        let e = Error::ChipInitFailed {
            chip: "RTL8812BU".into(),
            stage: InitStage::MacPowerOn,
            reason: "timeout".into(),
        };
        let s = e.to_string();
        assert!(s.contains("RTL8812BU"));
        assert!(s.contains("MAC power-on"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let e: Error = io_err.into();
        assert!(matches!(e, Error::Io(_)));
    }
}
