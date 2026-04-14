#![allow(dead_code)]
//! StoreUpdate — the streaming delta type for all wifikit state changes.
//!
//! Every mutation in the system — from USB frame arrival to attack progress —
//! is expressed as a StoreUpdate variant. The pipeline thread produces these,
//! the FrameStore applies them, and consumers subscribe to the stream.
//!
//! This is the single contract between producers and consumers:
//!   Extractor → StoreUpdate → FrameStore::apply() + broadcast → subscribers
//!
//! Consumers include: CLI (terminal rendering), SwiftUI (native macOS),
//! attacks (semantic event filtering), and any future UI or export layer.

use std::time::Duration;

use crate::core::{Bandwidth, MacAddress, TxFeedbackSnapshot};
use crate::protocol::eapol::{HandshakeMessage, HandshakeQuality};
use crate::protocol::ie::RsnInfo;
use crate::protocol::ieee80211::{Security, WifiGeneration};
use crate::store::ap::{IeEntry, WpsState};
use crate::store::event::{EventDetail, ScanEventType};

// ═══════════════════════════════════════════════════════════════════════════════
//  StoreUpdate — the core streaming delta type
// ═══════════════════════════════════════════════════════════════════════════════

/// Every mutation that flows through the system.
///
/// Emitted by the extractor after each frame, by the scanner engine on channel
/// hops, by attack modules on state changes, and by the adapter layer on
/// lifecycle events.
///
/// Subscribers receive these in order and can maintain their own materialized
/// views of the data. The FrameStore itself is just one such subscriber
/// (the canonical one that also serves snapshot queries for backward compat).
#[derive(Debug, Clone)]
pub enum StoreUpdate {
    // ═══════════════════════════════════════════════════════════════════
    //  AP lifecycle
    // ═══════════════════════════════════════════════════════════════════

    /// Brand new AP discovered (first beacon/probe response).
    /// Contains the full initial state — subscriber builds local copy from this.
    ApDiscovered {
        bssid: MacAddress,
        ssid: String,
        ssid_raw: Vec<u8>,
        is_hidden: bool,
        rssi: i8,
        snr: u8,
        noise_floor: i8,
        channel: u8,
        channel_center: u16,
        bandwidth: Bandwidth,
        wifi_gen: WifiGeneration,
        freq_mhz: u16,
        max_nss: u8,
        max_rate_mbps: u16,
        security: Security,
        rsn: Option<RsnInfo>,
        beacon_interval: u16,
        capability: u16,
        tsf: u64,
        country: Option<[u8; 2]>,
        vendor: String,
        // Grouped optional capabilities
        qbss: Option<QbssInfo>,
        tim: Option<TimInfo>,
        supported_rates: Vec<u8>,
        ft: Option<FtInfo>,
        ext_cap: Option<ExtCapInfo>,
        erp: Option<ErpInfo>,
        he_oper: Option<HeOperInfo>,
        interworking: Option<InterworkingInfo>,
        mesh: Option<MeshInfo>,
        ds_channel: Option<u8>,
        qos_info: Option<u8>,
        csa: Option<CsaInfo>,
        operating_classes: Vec<u8>,
        rm: Option<RmCapInfo>,
        multi_bssid: Option<MultiBssidInfo>,
        rnr: Option<RnrInfo>,
        // Raw capabilities for fingerprinting
        ht_cap_raw: u16,
        vht_cap_raw: u32,
        ampdu_max_len_exp: u8,
        ampdu_min_spacing: u8,
        vht_sounding_dims: u8,
        ht_oper: Option<HtOperInfo>,
        vht_oper: Option<VhtOperInfo>,
        // Vendor features
        vendor_ie_ouis: Vec<[u8; 3]>,
        has_wmm: bool,
        has_p2p: bool,
        has_hs20: bool,
        // WPS
        wps: Option<WpsInfo>,
        // Raw IEs
        raw_ies: Vec<u8>,
        ie_inventory: Vec<IeEntry>,
    },

    /// Existing AP updated from a subsequent beacon.
    /// Only contains fields that can change between beacons.
    ApBeaconUpdate {
        bssid: MacAddress,
        rssi: Option<i8>,
        rssi_sample: Option<(Duration, i8)>,
        snr: Option<u8>,
        snr_sample: Option<(Duration, u8)>,
        channel: u8,
        freq_mhz: u16,
        tsf: u64,
        beacon_count: u32,
        security: Security,
        rsn: Option<RsnInfo>,
        bandwidth: Bandwidth,
        wifi_gen: WifiGeneration,
        channel_center: u16,
        max_nss: u8,
        max_rate_mbps: u16,
        qbss: Option<QbssInfo>,
        dtim_count: Option<u8>,
        csa: Option<CsaInfo>,
        ies_changed: Option<IesChanged>,
        wps: Option<WpsInfo>,
    },

    /// Hidden SSID revealed by a probe response or later beacon.
    ApSsidRevealed {
        bssid: MacAddress,
        ssid: String,
        ssid_raw: Vec<u8>,
    },

    /// AP's client count changed (derived from station tracking).
    ApClientCountChanged {
        bssid: MacAddress,
        client_count: u16,
    },

    /// AP's handshake/PMKID capture state changed.
    ApCaptureStateChanged {
        bssid: MacAddress,
        handshake_quality: HandshakeQuality,
        has_pmkid: bool,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  Station lifecycle
    // ═══════════════════════════════════════════════════════════════════

    /// Station seen for the first time (from any frame type).
    StationDiscovered {
        mac: MacAddress,
        vendor: String,
        is_randomized: bool,
        channel: u8,
        rssi: i8,
        snr: u8,
    },

    /// Station associated with an AP (from data frame or assoc response).
    StationAssociated {
        mac: MacAddress,
        bssid: MacAddress,
        channel: u8,
    },

    /// Station data frame activity (RSSI, bytes, sequence tracking, power save).
    StationDataUpdate {
        mac: MacAddress,
        bssid: MacAddress,
        rssi: Option<i8>,
        snr: Option<u8>,
        channel: u8,
        frame_count: u32,
        data_bytes: u64,
        seq_num: u16,
        seq_gap: bool,
        power_save: bool,
        power_save_changed: bool,
        qos_tid: Option<u8>,
    },

    /// Station seen via probe request.
    StationProbeUpdate {
        mac: MacAddress,
        rssi: Option<i8>,
        snr: Option<u8>,
        channel: u8,
        probe_ssid: String,
        probe_ssid_count: u16,
        avg_probe_interval_ms: u32,
    },

    /// Station fingerprinted from association/reassociation request IEs.
    StationFingerprinted {
        mac: MacAddress,
        channel: u8,
        listen_interval: u16,
        wifi_gen: WifiGeneration,
        max_nss: u8,
        max_rate_mbps: u16,
        has_ht: bool,
        has_vht: bool,
        has_he: bool,
        ht_cap_raw: u16,
        vht_cap_raw: u32,
        supported_rates: Vec<u8>,
        ie_tag_order: Vec<u8>,
        ampdu_max_len_exp: u8,
        ampdu_min_spacing: u8,
    },

    /// Station power save state changed (from PS-Poll control frame).
    StationPowerSaveChanged {
        mac: MacAddress,
        power_save: bool,
    },

    /// Station handshake progress updated.
    StationHandshakeProgress {
        mac: MacAddress,
        messages_captured: u8,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  Probe requests
    // ═══════════════════════════════════════════════════════════════════

    /// New probe request pair (MAC + SSID) first seen.
    ProbeDiscovered {
        sta_mac: MacAddress,
        ssid: String,
        rssi: i8,
        channel: u8,
    },

    /// Existing probe request pair updated (count/rssi).
    ProbeUpdated {
        sta_mac: MacAddress,
        ssid: String,
        rssi: i8,
        count: u32,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  Capture engine (EAPOL / Handshake / PMKID / EAP)
    // ═══════════════════════════════════════════════════════════════════

    /// EAPOL handshake message captured (M1/M2/M3/M4).
    EapolMessage {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        message: HandshakeMessage,
        quality: HandshakeQuality,
    },

    /// PMKID extracted from M1 key data.
    PmkidCaptured {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        pmkid: [u8; 16],
    },

    /// Full 4-way handshake completed.
    HandshakeComplete {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        quality: HandshakeQuality,
    },

    /// Handshake quality improved (e.g., M1M2 → M1M2M3).
    HandshakeQualityImproved {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        old_quality: HandshakeQuality,
        new_quality: HandshakeQuality,
    },

    /// EAP identity captured (enterprise auth).
    EapIdentityCaptured {
        sta_mac: MacAddress,
        identity: String,
    },

    /// EAP method negotiated (PEAP, EAP-TLS, etc.).
    EapMethodNegotiated {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        method: String,
    },

    /// Handshake data ready for export (nonces, MIC, raw frames).
    HandshakeExportReady {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        ssid: String,
        anonce: [u8; 32],
        snonce: [u8; 32],
        key_mic: [u8; 16],
        key_version: u16,
        quality: HandshakeQuality,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  802.11 events (discrete management/control events)
    // ═══════════════════════════════════════════════════════════════════

    /// Discrete 802.11 management/control event.
    /// Replaces EventRing + drain_events() polling.
    ScanEvent {
        seq: u64,
        event_type: ScanEventType,
        source: MacAddress,
        target: MacAddress,
        channel: u8,
        rssi: i8,
        detail: EventDetail,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  Beacon timing analysis
    // ═══════════════════════════════════════════════════════════════════

    /// Beacon timing stats updated for an AP.
    BeaconTimingUpdate {
        bssid: MacAddress,
        measured_mean: Duration,
        jitter_stddev: f64,
        beacon_loss_count: u32,
        beacon_loss_rate: f32,
        tsf_drift_ppm: f64,
        tsf_jumps: u32,
        samples: u32,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  Channel stats
    // ═══════════════════════════════════════════════════════════════════

    /// Per-channel frame/retry count incremented.
    ChannelFrameCounted {
        channel: u8,
        band: u8,
        frame_count: u64,
        retry_count: u64,
    },

    /// Channel dwell completed — FPS and utilization computed.
    ChannelDwellComplete {
        channel: u8,
        band: u8,
        dwell_time: Duration,
        fps: f32,
        retry_rate: f32,
        busy_us: u32,
        tx_us: u32,
        rx_us: u32,
        obss_us: u32,
        utilization_pct: f32,
    },

    /// Channel stats cleared (new scan started).
    ChannelStatsCleared,

    /// Dwell started on a channel (scanner just switched to it).
    ChannelDwellStarted {
        channel: u8,
        band: u8,
    },

    /// Dwell ended on a channel (scanner is about to leave it).
    ChannelDwellEnded {
        channel: u8,
        band: u8,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  Scanner engine state
    // ═══════════════════════════════════════════════════════════════════

    /// Scanner switched to a new channel.
    ScannerChannelChanged {
        channel: u8,
    },

    /// Scanner completed a full channel cycle.
    ScannerRoundComplete {
        round: u32,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  Frame accounting (per-frame type counters)
    // ═══════════════════════════════════════════════════════════════════

    /// Frame counted by type. Emitted for every frame processed.
    FrameCounted {
        frame_count: u64,
        eapol_frame_count: u64,
        accounting: FrameAccountingDelta,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  TX Feedback (from firmware ACK/NACK reports)
    // ═══════════════════════════════════════════════════════════════════

    /// Individual TX completion report from firmware.
    TxReportReceived {
        pkt_id: u16,
        queue_sel: u8,
        tx_state: u8,
        tx_cnt: u8,
        acked: bool,
        final_rate: u16,
        final_bw: u8,
        total_airtime_us: u16,
    },

    /// Aggregate TX feedback counters updated.
    TxFeedbackUpdate {
        acked: u64,
        nacked: u64,
        total_retries: u64,
        total_reports: u64,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  RX Thread / Pipeline diagnostics
    // ═══════════════════════════════════════════════════════════════════

    /// RX thread USB-level stats.
    RxStatsUpdate {
        usb_reads: u32,
        usb_bytes: u64,
        packets_parsed: u32,
        frames_submitted: u32,
        driver_messages: u32,
        tx_status: u32,
        c2h_events: u32,
        channel_info: u32,
        dfs_reports: u32,
        bb_scope: u32,
        spatial_sounding: u32,
        other_packets: u32,
        skipped: u32,
        consumed_zero: u32,
        max_read_size: u32,
        multi_frame_reads: u32,
    },

    /// Pipeline processing stats.
    PipelineStatsUpdate {
        frames_received: u64,
        frames_parsed: u64,
        frames_unparseable: u64,
        pcap_bytes_written: u64,
        pcap_frames_written: u64,
        subscriber_count: u64,
        pending: u64,
        peak_pending: u64,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  Adapter lifecycle
    // ═══════════════════════════════════════════════════════════════════

    /// Adapter connected and initialized.
    AdapterReady {
        name: String,
        mac: MacAddress,
        driver_mac: MacAddress,
        role: AdapterRole,
    },

    /// Adapter RX thread started/stopped.
    AdapterRxStateChanged {
        name: String,
        active: bool,
    },

    /// Adapter permanently shut down.
    AdapterShutdown {
        name: String,
    },

    /// Channel locked by an attack.
    ChannelLocked {
        channel: u8,
        holder: String,
    },

    /// Channel unlocked (attack finished).
    ChannelUnlocked,

    // ═══════════════════════════════════════════════════════════════════
    //  Sensor data (CSI, DFS, BB scope, spatial sounding)
    // ═══════════════════════════════════════════════════════════════════

    /// Channel State Information received (Wi-Fi sensing / positioning).
    CsiReceived {
        channel: u8,
        bandwidth: u8,
        nr: u8,
        nc: u8,
        num_subcarriers: u16,
        csi_raw: Vec<i16>,
        timestamp: u32,
    },

    /// DFS radar detection event.
    DfsRadarDetected {
        channel: u8,
        radar_type: u8,
        timestamp: u32,
    },

    /// Baseband I/Q scope data (spectrum analyzer).
    BbScopeReceived {
        channel: u8,
        bandwidth: u8,
        num_samples: u16,
        iq_data: Vec<i16>,
        timestamp: u32,
    },

    /// Spatial sounding / beamforming feedback.
    SpatialSoundingReceived {
        channel: u8,
        nr: u8,
        nc: u8,
        timestamp: u32,
    },

    // ═══════════════════════════════════════════════════════════════════
    //  Attack lifecycle
    // ═══════════════════════════════════════════════════════════════════

    /// An attack was launched.
    AttackStarted {
        id: AttackId,
        attack_type: AttackType,
        target_bssid: MacAddress,
        target_ssid: String,
        target_channel: u8,
    },

    /// Attack phase changed.
    AttackPhaseChanged {
        id: AttackId,
        phase: AttackPhase,
    },

    /// Attack counters updated (batched, not per-frame).
    AttackCountersUpdate {
        id: AttackId,
        frames_sent: u64,
        frames_received: u64,
        frames_per_sec: f64,
        elapsed: Duration,
        tx_feedback: TxFeedbackSnapshot,
    },

    /// Attack-specific discrete event.
    AttackEvent {
        id: AttackId,
        seq: u64,
        timestamp: Duration,
        event: AttackEventKind,
    },

    /// Attack finished with final results.
    AttackComplete {
        id: AttackId,
        attack_type: AttackType,
        result: AttackResult,
    },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AP sub-structs (keep ApDiscovered variant manageable)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct QbssInfo {
    pub station_count: u16,
    pub utilization: u8,
    pub admission_cap: u16,
}

#[derive(Debug, Clone)]
pub struct TimInfo {
    pub dtim_period: u8,
    pub dtim_count: u8,
}

#[derive(Debug, Clone)]
pub struct FtInfo {
    pub mdid: u16,
    pub over_ds: bool,
}

#[derive(Debug, Clone)]
pub struct ExtCapInfo {
    pub bss_transition: bool,
    pub wnm_sleep: bool,
    pub tfs: bool,
    pub proxy_arp: bool,
    pub fms: bool,
    pub tim_broadcast: bool,
    pub interworking: bool,
    pub tdls: bool,
}

#[derive(Debug, Clone)]
pub struct ErpInfo {
    pub use_protection: bool,
    pub barker_preamble: bool,
}

#[derive(Debug, Clone)]
pub struct HeOperInfo {
    pub bss_color: u8,
    pub default_pe_dur: u8,
    pub twt_required: bool,
}

#[derive(Debug, Clone)]
pub struct InterworkingInfo {
    pub access_network_type: u8,
    pub internet: bool,
}

#[derive(Debug, Clone)]
pub struct MeshInfo {
    pub mesh_id: String,
}

#[derive(Debug, Clone)]
pub struct CsaInfo {
    pub mode: u8,
    pub new_channel: u8,
    pub count: u8,
}

#[derive(Debug, Clone)]
pub struct RmCapInfo {
    pub link_meas: bool,
    pub neighbor_report: bool,
    pub beacon_passive: bool,
    pub beacon_active: bool,
    pub beacon_table: bool,
}

#[derive(Debug, Clone)]
pub struct MultiBssidInfo {
    pub max_bssid_indicator: u8,
}

#[derive(Debug, Clone)]
pub struct RnrInfo {
    pub ap_count: u8,
}

#[derive(Debug, Clone)]
pub struct HtOperInfo {
    pub primary_ch: u8,
    pub secondary_offset: u8,
    pub sta_ch_width: u8,
}

#[derive(Debug, Clone)]
pub struct VhtOperInfo {
    pub ch_width: u8,
    pub center_seg0: u8,
    pub center_seg1: u8,
}

/// WPS state for AP discovery and beacon updates.
#[derive(Debug, Clone)]
pub struct WpsInfo {
    pub state: WpsState,
    pub locked: bool,
    pub version: u8,
    pub device_name: String,
    pub model: String,
}

/// Raw IEs changed — carries the new blob + inventory.
#[derive(Debug, Clone)]
pub struct IesChanged {
    pub raw_ies: Vec<u8>,
    pub ie_inventory: Vec<IeEntry>,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Frame accounting delta
// ═══════════════════════════════════════════════════════════════════════════════

/// Which frame type was just counted — one variant per FrameAccounting field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAccountingDelta {
    Beacon,
    ProbeReq,
    Auth,
    Deauth,
    Disassoc,
    AssocReq,
    AssocResp,
    ReassocReq,
    ReassocResp,
    Action,
    DataEapol,
    DataNull,
    DataEncrypted,
    DataLlc,
    DataLlcEapolUnparsed,
    DataOther,
    CtrlRts,
    CtrlCts,
    CtrlAck,
    CtrlBar,
    CtrlBa,
    CtrlPsPoll,
    CtrlOther,
    Unparseable,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Adapter types
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterRole {
    Scanner,
    Attack,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Attack types
// ═══════════════════════════════════════════════════════════════════════════════

/// Unique identifier for a running attack instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttackId(pub u64);

/// Which attack module is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackType {
    Pmkid,
    Dos,
    Wps,
    Eap,
    Krack,
    Frag,
    Fuzz,
    Wpa3,
    Ap,
}

/// Normalized attack phase — works across all attack types.
#[derive(Debug, Clone)]
pub struct AttackPhase {
    /// Human-readable phase name ("Authenticating", "Flooding", "PixieCracking").
    pub label: &'static str,
    /// True if the attack is actively doing work (not idle or done).
    pub is_active: bool,
    /// True if the attack has finished (Done state).
    pub is_terminal: bool,
}

/// All attack events unified under one enum.
/// Each variant wraps the attack-specific EventKind type.
#[derive(Debug, Clone)]
pub enum AttackEventKind {
    Pmkid(crate::attacks::pmkid::PmkidEventKind),
    Dos(crate::attacks::dos::DosEventKind),
    Wps(crate::attacks::wps::WpsEventKind),
    Eap(crate::attacks::eap::EapEventKind),
    Krack(crate::attacks::krack::KrackEventKind),
    Frag(crate::attacks::frag::FragEventKind),
    Fuzz(crate::attacks::fuzz::FuzzEventKind),
    Wpa3(crate::attacks::wpa3::Wpa3EventKind),
    Ap(crate::attacks::ap::ApEventKind),
}

/// Final result when an attack completes.
#[derive(Debug, Clone)]
pub enum AttackResult {
    Pmkid {
        captured: u32,
        failed: u32,
        total: u32,
        results: Vec<crate::attacks::pmkid::PmkidResult>,
    },
    Dos {
        frames_sent: u64,
        stop_reason: crate::attacks::dos::StopReason,
    },
    Wps {
        pin_found: Option<String>,
        psk_found: Option<String>,
        attempts: u32,
        results: Vec<crate::attacks::wps::WpsResult>,
    },
    Eap {
        credentials_total: u32,
        credentials: Vec<crate::attacks::eap::EapCredential>,
    },
    Krack {
        tested: u32,
        vulnerable: u32,
        results: Vec<crate::attacks::krack::KrackTestResult>,
    },
    Frag {
        tested: u32,
        vulnerable: u32,
        results: Vec<crate::attacks::frag::FragTestResult>,
    },
    Fuzz {
        iterations: u64,
        crashes_found: u32,
        crashes_permanent: u32,
    },
    Wpa3 {
        tested: u32,
        vulnerable: u32,
        results: Vec<crate::attacks::wpa3::Wpa3TestResult>,
    },
    Ap {
        clients_total: u32,
        karma_ssids: u32,
    },
}
