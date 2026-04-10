#![allow(dead_code)]
//! FrameStore — the central data store for all scanner state.
//!
//! Uses RwLock per table for concurrent reads from CLI while the scanner
//! thread writes. The FrameStore is Clone (inner is Arc).

pub mod ap;
pub mod event;
pub mod probe;
pub mod station;
pub mod stats;
pub mod update;

// Re-export all public types
pub use ap::{Ap, IeEntry, WpsState, build_ie_inventory, MAX_RSSI_SAMPLES};
pub use event::{EventDetail, ScanEvent, ScanEventType};
pub use probe::ProbeReq;
pub use station::Station;
pub use stats::{BeaconTiming, ChannelStats, FrameAccounting, ScanStats};
pub use update::StoreUpdate;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::core::{EventRing, MacAddress};
use crate::engine::capture::CaptureDatabase;
use crate::protocol::ieee80211::Security;

/// Maximum number of scan events retained in the EventRing.
pub const SCAN_EVENT_RING_CAPACITY: usize = 10_000;

/// Maximum number of probe requests retained.
/// When this cap is reached, the oldest probe is removed before pushing a new one.
pub const MAX_PROBES: usize = 10_000;

// ═══════════════════════════════════════════════════════════════════════════════
//  FrameStore — the heart of wifikit
// ═══════════════════════════════════════════════════════════════════════════════

/// Central data store for all scanner state.
///
/// Each table has its own RwLock so the CLI can read AP data while the scanner
/// thread is writing station data (no global lock contention).
///
/// Clone is cheap — it clones the inner Arc.
#[derive(Clone)]
pub struct FrameStore {
    inner: Arc<Inner>,
}

struct Inner {
    aps: RwLock<HashMap<MacAddress, Ap>>,
    stations: RwLock<HashMap<MacAddress, Station>>,
    probes: RwLock<Vec<ProbeReq>>,
    capture_db: RwLock<CaptureDatabase>,
    events: EventRing<ScanEvent>,
    channel_stats: RwLock<HashMap<u16, ChannelStats>>,
    beacon_timing: RwLock<HashMap<MacAddress, BeaconTiming>>,
    frame_count: AtomicU64,
    eapol_frame_count: AtomicU64,
    event_seq: AtomicU64,
    round: AtomicU32,
    current_channel: AtomicU8,
    fa: RwLock<FrameAccounting>,
    start_time: Instant,
    /// FPS tracker: (previous frame_count, previous timestamp).
    /// Updated each time stats() is called. Computes real-time FPS
    /// from the delta rather than lifetime average.
    fps_tracker: Mutex<(u64, Instant)>,
}

impl FrameStore {
    /// Create a new empty FrameStore.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                aps: RwLock::new(HashMap::new()),
                stations: RwLock::new(HashMap::new()),
                probes: RwLock::new(Vec::new()),
                capture_db: RwLock::new(CaptureDatabase::new()),
                events: EventRing::new(SCAN_EVENT_RING_CAPACITY),
                channel_stats: RwLock::new(HashMap::new()),
                beacon_timing: RwLock::new(HashMap::new()),
                frame_count: AtomicU64::new(0),
                eapol_frame_count: AtomicU64::new(0),
                event_seq: AtomicU64::new(0),
                round: AtomicU32::new(0),
                current_channel: AtomicU8::new(0),
                fa: RwLock::new(FrameAccounting::default()),
                start_time: Instant::now(),
                fps_tracker: Mutex::new((0, Instant::now())),
            }),
        }
    }

    // ─── Accessors (read) ────────────────────────────────────────────────

    /// Get a snapshot of all APs.
    pub fn get_aps(&self) -> HashMap<MacAddress, Ap> {
        self.inner.aps.read().unwrap().clone()
    }

    /// Get a single AP by BSSID.
    pub fn get_ap(&self, bssid: &MacAddress) -> Option<Ap> {
        self.inner.aps.read().unwrap().get(bssid).cloned()
    }

    /// Get AP count without cloning the entire map.
    pub fn ap_count(&self) -> usize {
        self.inner.aps.read().unwrap().len()
    }

    /// Get a snapshot of all stations.
    pub fn get_stations(&self) -> HashMap<MacAddress, Station> {
        self.inner.stations.read().unwrap().clone()
    }

    /// Get a single station by MAC.
    pub fn get_station(&self, mac: &MacAddress) -> Option<Station> {
        self.inner.stations.read().unwrap().get(mac).cloned()
    }

    /// Get station count without cloning.
    pub fn station_count(&self) -> usize {
        self.inner.stations.read().unwrap().len()
    }

    /// Get clients associated to a specific AP.
    pub fn get_ap_clients(&self, bssid: &MacAddress) -> Vec<Station> {
        self.inner.stations.read().unwrap().values()
            .filter(|s| s.bssid.as_ref() == Some(bssid))
            .cloned()
            .collect()
    }

    /// Get a snapshot of all probe requests.
    pub fn get_probes(&self) -> Vec<ProbeReq> {
        self.inner.probes.read().unwrap().clone()
    }

    /// Get probe count without cloning.
    pub fn probe_count(&self) -> usize {
        self.inner.probes.read().unwrap().len()
    }

    /// Get a snapshot of channel stats.
    pub fn get_channel_stats(&self) -> HashMap<u16, ChannelStats> {
        self.inner.channel_stats.read().unwrap().clone()
    }

    /// Read-only access to channel stats.
    pub fn with_channel_stats_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&HashMap<u16, ChannelStats>) -> R,
    {
        let stats = self.inner.channel_stats.read().unwrap();
        f(&stats)
    }

    /// Get a snapshot of beacon timing data.
    pub fn get_beacon_timing(&self) -> HashMap<MacAddress, BeaconTiming> {
        self.inner.beacon_timing.read().unwrap().clone()
    }

    /// Get frame accounting snapshot.
    pub fn get_frame_accounting(&self) -> FrameAccounting {
        self.inner.fa.read().unwrap().clone()
    }

    /// Total frames received.
    pub fn frame_count(&self) -> u64 {
        self.inner.frame_count.load(Ordering::Relaxed)
    }

    /// Total EAPOL frames received.
    pub fn eapol_frame_count(&self) -> u64 {
        self.inner.eapol_frame_count.load(Ordering::Relaxed)
    }

    /// Time since store creation.
    pub fn elapsed(&self) -> std::time::Duration {
        self.inner.start_time.elapsed()
    }

    /// Current scan round (set by scanner after each full channel cycle).
    pub fn round(&self) -> u32 {
        self.inner.round.load(Ordering::Relaxed)
    }

    /// Set the scan round (called by scanner engine).
    pub fn set_round(&self, round: u32) {
        self.inner.round.store(round, Ordering::Relaxed);
    }

    /// Clear channel stats (called when starting a new scan to remove stale entries
    /// from a previous adapter's scan).
    pub fn clear_channel_stats(&self) {
        self.inner.channel_stats.write().unwrap().clear();
    }

    /// Current channel the scanner is on (set by scanner).
    pub fn current_channel(&self) -> u8 {
        self.inner.current_channel.load(Ordering::Relaxed)
    }

    /// Set current channel (called by scanner engine).
    pub fn set_current_channel(&self, ch: u8) {
        self.inner.current_channel.store(ch, Ordering::Relaxed);
    }

    /// Drain new events from the EventRing.
    pub fn drain_events(&self) -> Vec<ScanEvent> {
        self.inner.events.drain()
    }

    /// Get event overflow count.
    pub fn event_overflow_count(&self) -> u64 {
        self.inner.events.overflow_count()
    }

    /// Get the current event sequence number (for delta emission).
    pub fn event_seq(&self) -> u64 {
        self.inner.event_seq.load(Ordering::Relaxed)
    }

    // ─── Mutators (write) ────────────────────────────────────────────────

    /// Get mutable access to the AP table. Caller holds the write lock.
    pub fn with_aps_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<MacAddress, Ap>) -> R,
    {
        let mut aps = self.inner.aps.write().unwrap();
        f(&mut aps)
    }

    /// Get mutable access to a single AP, inserting a new one if absent.
    pub fn update_ap<F>(&self, bssid: MacAddress, f: F)
    where
        F: FnOnce(&mut Ap),
    {
        let mut aps = self.inner.aps.write().unwrap();
        let ap = aps
            .entry(bssid)
            .or_insert_with(|| Ap::new(bssid, Instant::now()));
        f(ap);
    }

    /// Get mutable access to the station table.
    pub fn with_stations_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<MacAddress, Station>) -> R,
    {
        let mut stations = self.inner.stations.write().unwrap();
        f(&mut stations)
    }

    /// Get mutable access to a single station, inserting a new one if absent.
    pub fn update_station<F>(&self, mac: MacAddress, f: F)
    where
        F: FnOnce(&mut Station),
    {
        let mut stations = self.inner.stations.write().unwrap();
        let station = stations
            .entry(mac)
            .or_insert_with(|| Station::new(mac, Instant::now()));
        f(station);
    }

    /// Get mutable access to the probe list.
    pub fn with_probes_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Vec<ProbeReq>) -> R,
    {
        let mut probes = self.inner.probes.write().unwrap();
        f(&mut probes)
    }

    /// Get mutable access to the capture database.
    pub fn with_capture_db<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut CaptureDatabase) -> R,
    {
        let mut db = self.inner.capture_db.write().unwrap();
        f(&mut db)
    }

    /// Read access to the capture database.
    pub fn with_capture_db_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&CaptureDatabase) -> R,
    {
        let db = self.inner.capture_db.read().unwrap();
        f(&db)
    }

    /// Get mutable access to channel stats.
    pub fn with_channel_stats_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<u16, ChannelStats>) -> R,
    {
        let mut stats = self.inner.channel_stats.write().unwrap();
        f(&mut stats)
    }

    /// Get mutable access to beacon timing.
    pub fn with_beacon_timing_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<MacAddress, BeaconTiming>) -> R,
    {
        let mut timing = self.inner.beacon_timing.write().unwrap();
        f(&mut timing)
    }

    /// Get mutable access to frame accounting.
    pub fn with_frame_accounting_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut FrameAccounting) -> R,
    {
        let mut fa = self.inner.fa.write().unwrap();
        f(&mut fa)
    }

    /// Increment frame count. Returns the new value.
    pub fn inc_frame_count(&self) -> u64 {
        self.inner.frame_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Increment EAPOL frame count. Returns the new value.
    pub fn inc_eapol_frame_count(&self) -> u64 {
        self.inner
            .eapol_frame_count
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    // ─── Apply deltas ─────────────────────────────────────────────────────

    /// Apply a batch of StoreUpdate deltas to the store.
    ///
    /// This is the single write path for all frame-derived state.
    /// The pipeline thread calls: extract_frame() → apply() → broadcast.
    pub fn apply(&self, deltas: &[StoreUpdate]) {
        let now = Instant::now();
        let elapsed = self.inner.start_time.elapsed();

        for delta in deltas {
            match delta {
                // ── AP lifecycle ──────────────────────────────────────────
                StoreUpdate::ApDiscovered {
                    bssid, ssid, ssid_raw, is_hidden, rssi, channel,
                    channel_center, bandwidth, wifi_gen, freq_mhz, max_nss,
                    max_rate_mbps, security, rsn, beacon_interval, capability,
                    tsf, country, vendor, qbss, tim, supported_rates, ft,
                    ext_cap, erp, he_oper, interworking, mesh, ds_channel,
                    qos_info, csa, operating_classes, rm, multi_bssid, rnr,
                    ht_cap_raw, vht_cap_raw, ampdu_max_len_exp, ampdu_min_spacing,
                    vht_sounding_dims, ht_oper, vht_oper, vendor_ie_ouis,
                    has_wmm, has_p2p, has_hs20, wps, raw_ies, ie_inventory,
                } => {
                    self.inc_frame_count();
                    let mut ap = Ap::new(*bssid, now);
                    ap.ssid = ssid.clone();
                    ap.ssid_raw = ssid_raw.clone();
                    ap.is_hidden = *is_hidden;
                    ap.rssi = *rssi;
                    ap.rssi_best = *rssi;
                    ap.rssi_worst = *rssi;
                    ap.rssi_samples.push_back((elapsed, *rssi));
                    ap.channel = *channel;
                    ap.channel_center = *channel_center;
                    ap.bandwidth = *bandwidth;
                    ap.wifi_gen = *wifi_gen;
                    ap.freq_mhz = *freq_mhz;
                    ap.max_nss = *max_nss;
                    ap.max_rate_mbps = *max_rate_mbps;
                    ap.security = *security;
                    ap.rsn = rsn.clone();
                    ap.beacon_interval = *beacon_interval;
                    ap.capability = *capability;
                    ap.beacon_count = 1;
                    ap.tsf = *tsf;
                    ap.country = *country;
                    ap.vendor = vendor.clone();

                    if let Some(q) = qbss {
                        ap.has_qbss = true;
                        ap.qbss_station_count = q.station_count;
                        ap.qbss_utilization = q.utilization;
                        ap.qbss_admission_cap = q.admission_cap;
                    }
                    if let Some(t) = tim {
                        ap.has_tim = true;
                        ap.dtim_period = t.dtim_period;
                        ap.dtim_count = t.dtim_count;
                    }
                    ap.supported_rates = supported_rates.clone();
                    if let Some(f) = ft {
                        ap.has_ft = true;
                        ap.ft_mdid = f.mdid;
                        ap.ft_over_ds = f.over_ds;
                    }
                    if let Some(e) = ext_cap {
                        ap.has_ext_cap = true;
                        ap.ext_cap_bss_transition = e.bss_transition;
                        ap.ext_cap_wnm_sleep = e.wnm_sleep;
                        ap.ext_cap_tfs = e.tfs;
                        ap.ext_cap_proxy_arp = e.proxy_arp;
                        ap.ext_cap_fms = e.fms;
                        ap.ext_cap_tim_broadcast = e.tim_broadcast;
                        ap.ext_cap_interworking = e.interworking;
                        ap.ext_cap_tdls = e.tdls;
                    }
                    if let Some(e) = erp {
                        ap.has_erp = true;
                        ap.erp_use_protection = e.use_protection;
                        ap.erp_barker_preamble = e.barker_preamble;
                    }
                    if let Some(h) = he_oper {
                        ap.has_he_oper = true;
                        ap.he_bss_color = h.bss_color;
                        ap.he_default_pe_dur = h.default_pe_dur;
                        ap.he_twt_required = h.twt_required;
                    }
                    if let Some(i) = interworking {
                        ap.has_interworking = true;
                        ap.interworking_type = i.access_network_type;
                        ap.has_internet = i.internet;
                    }
                    if let Some(m) = mesh {
                        ap.is_mesh = true;
                        ap.mesh_id = m.mesh_id.clone();
                    }
                    if let Some(d) = ds_channel {
                        ap.has_ds = true;
                        ap.ds_channel = *d;
                    }
                    if let Some(q) = qos_info {
                        ap.has_qos = true;
                        ap.qos_info = *q;
                    }
                    if let Some(c) = csa {
                        ap.has_csa = true;
                        ap.csa_mode = c.mode;
                        ap.csa_new_channel = c.new_channel;
                        ap.csa_count = c.count;
                    }
                    ap.operating_classes = operating_classes.clone();
                    if let Some(r) = rm {
                        ap.has_rm = true;
                        ap.rm_link_meas = r.link_meas;
                        ap.rm_neighbor_report = r.neighbor_report;
                        ap.rm_beacon_passive = r.beacon_passive;
                        ap.rm_beacon_active = r.beacon_active;
                        ap.rm_beacon_table = r.beacon_table;
                    }
                    if let Some(m) = multi_bssid {
                        ap.has_multi_bssid = true;
                        ap.max_bssid_indicator = m.max_bssid_indicator;
                    }
                    if let Some(r) = rnr {
                        ap.has_rnr = true;
                        ap.rnr_ap_count = r.ap_count;
                    }
                    ap.ht_cap_raw = *ht_cap_raw;
                    ap.vht_cap_raw = *vht_cap_raw;
                    ap.ampdu_max_len_exp = *ampdu_max_len_exp;
                    ap.ampdu_min_spacing = *ampdu_min_spacing;
                    ap.vht_sounding_dims = *vht_sounding_dims;
                    if let Some(h) = ht_oper {
                        ap.has_ht_oper = true;
                        ap.ht_oper_primary_ch = h.primary_ch;
                        ap.ht_oper_secondary_offset = h.secondary_offset;
                        ap.ht_oper_sta_ch_width = h.sta_ch_width;
                    }
                    if let Some(v) = vht_oper {
                        ap.has_vht_oper = true;
                        ap.vht_oper_ch_width = v.ch_width;
                        ap.vht_oper_center_seg0 = v.center_seg0;
                        ap.vht_oper_center_seg1 = v.center_seg1;
                    }
                    ap.vendor_ie_ouis = vendor_ie_ouis.clone();
                    ap.has_wmm = *has_wmm;
                    ap.has_p2p = *has_p2p;
                    ap.has_hs20 = *has_hs20;
                    if let Some(w) = wps {
                        ap.wps_state = w.state;
                        ap.wps_locked = w.locked;
                        ap.wps_version = w.version;
                        if !w.device_name.is_empty() { ap.wps_device_name = w.device_name.clone(); }
                        if !w.model.is_empty() { ap.wps_model = w.model.clone(); }
                    }
                    ap.raw_ies = raw_ies.clone();
                    ap.ie_inventory = ie_inventory.clone();

                    self.with_aps_mut(|aps| { aps.insert(*bssid, ap); });

                    // Initialize beacon timing
                    self.with_beacon_timing_mut(|timing| {
                        let bt = timing.entry(*bssid)
                            .or_insert_with(|| BeaconTiming::new(*bssid, *beacon_interval));
                        bt.record_beacon(*tsf);
                    });
                }

                StoreUpdate::ApBeaconUpdate {
                    bssid, rssi, rssi_sample, channel, freq_mhz, tsf,
                    beacon_count, security, rsn, bandwidth, wifi_gen,
                    channel_center, max_nss, max_rate_mbps, qbss,
                    dtim_count, csa, ies_changed, wps,
                } => {
                    self.update_ap(*bssid, |ap| {
                        if let Some(r) = rssi {
                            ap.rssi = *r;
                            if *r > ap.rssi_best { ap.rssi_best = *r; }
                            if *r < ap.rssi_worst && *r < -1 { ap.rssi_worst = *r; }
                        }
                        if let Some((ts, r)) = rssi_sample {
                            if ap.rssi_samples.len() >= crate::store::MAX_RSSI_SAMPLES {
                                ap.rssi_samples.pop_front();
                            }
                            ap.rssi_samples.push_back((*ts, *r));
                        }
                        ap.beacon_count = *beacon_count;
                        ap.last_seen = now;
                        ap.channel = *channel;
                        ap.freq_mhz = *freq_mhz;
                        ap.tsf = *tsf;
                        ap.security = *security;
                        if let Some(r) = rsn { ap.rsn = Some(r.clone()); }
                        ap.bandwidth = *bandwidth;
                        ap.wifi_gen = *wifi_gen;
                        ap.channel_center = *channel_center;
                        ap.max_nss = *max_nss;
                        ap.max_rate_mbps = *max_rate_mbps;
                        if let Some(q) = qbss {
                            ap.has_qbss = true;
                            ap.qbss_station_count = q.station_count;
                            ap.qbss_utilization = q.utilization;
                            ap.qbss_admission_cap = q.admission_cap;
                        }
                        if let Some(d) = dtim_count { ap.dtim_count = *d; }
                        if let Some(c) = csa {
                            ap.has_csa = true;
                            ap.csa_mode = c.mode;
                            ap.csa_new_channel = c.new_channel;
                            ap.csa_count = c.count;
                        } else {
                            ap.has_csa = false;
                        }
                        if let Some(ie) = ies_changed {
                            ap.raw_ies = ie.raw_ies.clone();
                            ap.ie_inventory = ie.ie_inventory.clone();
                        }
                        if let Some(w) = wps {
                            ap.wps_state = w.state;
                            ap.wps_locked = w.locked;
                            ap.wps_version = w.version;
                            if !w.device_name.is_empty() { ap.wps_device_name = w.device_name.clone(); }
                            if !w.model.is_empty() { ap.wps_model = w.model.clone(); }
                        }
                    });

                    // Update beacon timing
                    self.with_beacon_timing_mut(|timing| {
                        if let Some(bt) = timing.get_mut(bssid) {
                            bt.record_beacon(*tsf);
                        }
                    });
                }

                StoreUpdate::ApSsidRevealed { bssid, ssid, ssid_raw } => {
                    self.update_ap(*bssid, |ap| {
                        ap.ssid = ssid.clone();
                        ap.ssid_raw = ssid_raw.clone();
                        ap.is_hidden = false;
                    });
                }

                StoreUpdate::ApClientCountChanged { bssid, client_count } => {
                    self.update_ap(*bssid, |ap| {
                        ap.client_count = *client_count;
                    });
                }

                StoreUpdate::ApCaptureStateChanged { bssid, handshake_quality, has_pmkid } => {
                    self.update_ap(*bssid, |ap| {
                        ap.handshake_quality = *handshake_quality;
                        ap.has_pmkid = *has_pmkid;
                    });
                }

                // ── Station lifecycle ─────────────────────────────────────
                StoreUpdate::StationDiscovered { mac, vendor, is_randomized, channel, rssi } => {
                    self.with_stations_mut(|stations| {
                        stations.entry(*mac).or_insert_with(|| {
                            let mut sta = Station::new(*mac, now);
                            sta.vendor = vendor.clone();
                            sta.is_randomized = *is_randomized;
                            sta.last_channel = *channel;
                            sta.rssi = *rssi;
                            sta
                        });
                    });
                }

                StoreUpdate::StationAssociated { mac, bssid, channel } => {
                    self.update_station(*mac, |sta| {
                        sta.bssid = Some(*bssid);
                        sta.is_associated = true;
                        sta.last_channel = *channel;
                        sta.last_seen = now;
                    });
                }

                StoreUpdate::StationDataUpdate {
                    mac, bssid, rssi, channel, frame_count, data_bytes,
                    seq_num, seq_gap, power_save, power_save_changed, qos_tid,
                } => {
                    self.update_station(*mac, |sta| {
                        sta.bssid = Some(*bssid);
                        sta.is_associated = true;
                        sta.frame_count = *frame_count;
                        sta.data_bytes = *data_bytes;
                        if let Some(r) = rssi {
                            sta.rssi = *r;
                            if *r > sta.rssi_best { sta.rssi_best = *r; }
                        }
                        sta.last_channel = *channel;
                        sta.last_seen = now;

                        // Sequence tracking
                        if sta.seq_num_first == 0 && sta.frame_count == 1 {
                            sta.seq_num_first = *seq_num;
                        }
                        if *seq_num != sta.seq_num_last {
                            sta.seq_num_last = *seq_num;
                        }
                        if *seq_gap { sta.seq_num_gaps += 1; }

                        // Power save
                        if *power_save_changed {
                            sta.power_save = *power_save;
                            sta.power_save_transitions += 1;
                        }

                        // QoS TID
                        if let Some(tid) = qos_tid {
                            sta.tid_counts[*tid as usize] += 1;
                        }
                    });
                }

                StoreUpdate::StationProbeUpdate {
                    mac, rssi, channel, probe_ssid, probe_ssid_count, avg_probe_interval_ms,
                } => {
                    self.update_station(*mac, |sta| {
                        sta.frame_count += 1;
                        if let Some(r) = rssi { sta.rssi = *r; }
                        sta.last_channel = *channel;
                        sta.last_seen = now;
                        sta.probe_ssid_count = *probe_ssid_count;
                        sta.last_probe_ssid = probe_ssid.clone();
                        sta.avg_probe_interval_ms = *avg_probe_interval_ms;

                        // Probe interval tracking
                        if let Some(last) = sta.last_probe_time {
                            let interval_ms = last.elapsed().as_millis() as u32;
                            if interval_ms > 0 && interval_ms < 60_000 {
                                sta.probe_intervals.push(interval_ms);
                                if sta.probe_intervals.len() > 64 {
                                    sta.probe_intervals.remove(0);
                                }
                                let sum: u32 = sta.probe_intervals.iter().sum();
                                sta.avg_probe_interval_ms = sum / sta.probe_intervals.len() as u32;
                            }
                        }
                        sta.last_probe_time = Some(now);
                    });
                }

                StoreUpdate::StationFingerprinted {
                    mac, channel, listen_interval, wifi_gen, max_nss, max_rate_mbps,
                    has_ht, has_vht, has_he, ht_cap_raw, vht_cap_raw,
                    supported_rates, ie_tag_order, ampdu_max_len_exp, ampdu_min_spacing,
                } => {
                    self.update_station(*mac, |sta| {
                        sta.last_channel = *channel;
                        sta.listen_interval = *listen_interval;
                        sta.wifi_gen = *wifi_gen;
                        sta.max_nss = *max_nss;
                        sta.max_rate_mbps = *max_rate_mbps;
                        sta.has_ht = *has_ht;
                        sta.has_vht = *has_vht;
                        sta.has_he = *has_he;
                        sta.ht_cap_raw = *ht_cap_raw;
                        sta.vht_cap_raw = *vht_cap_raw;
                        sta.supported_rates = supported_rates.clone();
                        sta.ie_tag_order = ie_tag_order.clone();
                        sta.ie_tag_count = ie_tag_order.len() as u8;
                        sta.ampdu_max_len_exp = *ampdu_max_len_exp;
                        sta.ampdu_min_spacing = *ampdu_min_spacing;
                    });
                }

                StoreUpdate::StationPowerSaveChanged { mac, power_save } => {
                    self.update_station(*mac, |sta| {
                        if *power_save != sta.power_save {
                            sta.power_save = *power_save;
                            sta.power_save_transitions += 1;
                        }
                    });
                }

                StoreUpdate::StationHandshakeProgress { mac, messages_captured } => {
                    self.update_station(*mac, |sta| {
                        sta.handshake_state = *messages_captured;
                    });
                }

                // ── Probes ────────────────────────────────────────────────
                StoreUpdate::ProbeDiscovered { sta_mac, ssid, rssi, channel } => {
                    self.with_probes_mut(|probes| {
                        if probes.len() >= MAX_PROBES { probes.remove(0); }
                        probes.push(ProbeReq {
                            sta_mac: *sta_mac,
                            ssid: ssid.clone(),
                            rssi: *rssi,
                            channel: *channel,
                            count: 1,
                            first_seen: now,
                            last_seen: now,
                        });
                    });
                }

                StoreUpdate::ProbeUpdated { sta_mac, ssid, rssi, count } => {
                    self.with_probes_mut(|probes| {
                        if let Some(p) = probes.iter_mut().find(|p| p.sta_mac == *sta_mac && p.ssid == *ssid) {
                            p.count = *count;
                            p.rssi = *rssi;
                            p.last_seen = now;
                        }
                    });
                }

                // ── EAPOL / Capture (already processed by capture DB during extract) ──
                StoreUpdate::EapolMessage { .. } => {
                    self.inc_eapol_frame_count();
                }
                StoreUpdate::PmkidCaptured { .. }
                | StoreUpdate::HandshakeComplete { .. }
                | StoreUpdate::HandshakeQualityImproved { .. }
                | StoreUpdate::EapIdentityCaptured { .. }
                | StoreUpdate::EapMethodNegotiated { .. }
                | StoreUpdate::HandshakeExportReady { .. } => {
                    // Capture DB already updated during extract_frame().
                    // AP/Station capture state is handled by ApCaptureStateChanged
                    // and StationHandshakeProgress deltas.
                }

                // ── Scan Events ───────────────────────────────────────────
                StoreUpdate::ScanEvent { event_type, source, target, channel, rssi, detail, .. } => {
                    self.push_event(*event_type, *source, *target, *channel, *rssi, detail.clone());
                }

                // ── Beacon Timing ─────────────────────────────────────────
                StoreUpdate::BeaconTimingUpdate { .. } => {
                    // Beacon timing computation happens in ApDiscovered/ApBeaconUpdate
                    // handlers above (record_beacon). This delta is broadcast-only —
                    // subscribers use it to update their timing displays.
                }

                // ── Channel Stats ─────────────────────────────────────────
                StoreUpdate::ChannelFrameCounted { channel, band, frame_count, retry_count } => {
                    let key = stats::channel_key(*channel, *band);
                    self.with_channel_stats_mut(|cs_map| {
                        let cs = cs_map.entry(key).or_insert_with(|| ChannelStats::new(*channel, *band));
                        cs.frame_count = *frame_count;
                        cs.retry_count = *retry_count;
                    });
                }

                StoreUpdate::ChannelDwellComplete { channel, band, fps, retry_rate, .. } => {
                    let key = stats::channel_key(*channel, *band);
                    self.with_channel_stats_mut(|cs_map| {
                        if let Some(cs) = cs_map.get_mut(&key) {
                            cs.fps = *fps;
                            cs.retry_rate = *retry_rate;
                        }
                    });
                }

                StoreUpdate::ChannelStatsCleared => {
                    self.clear_channel_stats();
                }

                // ── Scanner engine ────────────────────────────────────────
                StoreUpdate::ScannerChannelChanged { channel } => {
                    self.set_current_channel(*channel);
                }

                StoreUpdate::ScannerRoundComplete { round } => {
                    self.set_round(*round);
                }

                // ── Scanner dwell tracking ────────────────────────────────
                StoreUpdate::ChannelDwellStarted { channel, band } => {
                    let key = stats::channel_key(*channel, *band);
                    self.with_channel_stats_mut(|cs_map| {
                        cs_map.entry(key)
                            .or_insert_with(|| ChannelStats::new(*channel, *band))
                            .start_dwell();
                    });
                }

                StoreUpdate::ChannelDwellEnded { channel, band } => {
                    let key = stats::channel_key(*channel, *band);
                    self.with_channel_stats_mut(|cs_map| {
                        if let Some(cs) = cs_map.get_mut(&key) {
                            cs.end_dwell();
                        }
                    });
                }

                // ── Frame accounting ──────────────────────────────────────
                StoreUpdate::FrameCounted { frame_count, eapol_frame_count, accounting } => {
                    // Update atomic counters to match extractor's tally
                    self.inner.frame_count.store(*frame_count, Ordering::Relaxed);
                    self.inner.eapol_frame_count.store(*eapol_frame_count, Ordering::Relaxed);

                    self.with_frame_accounting_mut(|fa| {
                        match accounting {
                            update::FrameAccountingDelta::Beacon => fa.beacon += 1,
                            update::FrameAccountingDelta::ProbeReq => fa.probe_req += 1,
                            update::FrameAccountingDelta::Auth => fa.auth += 1,
                            update::FrameAccountingDelta::Deauth => fa.deauth += 1,
                            update::FrameAccountingDelta::Disassoc => fa.disassoc += 1,
                            update::FrameAccountingDelta::AssocReq => fa.assoc_req += 1,
                            update::FrameAccountingDelta::AssocResp => fa.assoc_resp += 1,
                            update::FrameAccountingDelta::ReassocReq => fa.reassoc_req += 1,
                            update::FrameAccountingDelta::ReassocResp => fa.reassoc_resp += 1,
                            update::FrameAccountingDelta::Action => fa.action += 1,
                            update::FrameAccountingDelta::DataEapol => fa.data_eapol += 1,
                            update::FrameAccountingDelta::DataNull => fa.data_null += 1,
                            update::FrameAccountingDelta::DataEncrypted => fa.data_encrypted += 1,
                            update::FrameAccountingDelta::DataLlc => fa.data_llc += 1,
                            update::FrameAccountingDelta::DataLlcEapolUnparsed => fa.data_llc_eapol_unparsed += 1,
                            update::FrameAccountingDelta::DataOther => fa.data_other += 1,
                            update::FrameAccountingDelta::CtrlRts => fa.ctrl_rts += 1,
                            update::FrameAccountingDelta::CtrlCts => fa.ctrl_cts += 1,
                            update::FrameAccountingDelta::CtrlAck => fa.ctrl_ack += 1,
                            update::FrameAccountingDelta::CtrlBar => fa.ctrl_bar += 1,
                            update::FrameAccountingDelta::CtrlBa => fa.ctrl_ba += 1,
                            update::FrameAccountingDelta::CtrlPsPoll => fa.ctrl_pspoll += 1,
                            update::FrameAccountingDelta::CtrlOther => fa.ctrl_other += 1,
                            update::FrameAccountingDelta::Unparseable => fa.unparseable += 1,
                        }
                    });
                }

                // ── Subscriber-only deltas (no store mutation) ────────────
                StoreUpdate::TxReportReceived { .. }
                | StoreUpdate::TxFeedbackUpdate { .. }
                | StoreUpdate::RxStatsUpdate { .. }
                | StoreUpdate::PipelineStatsUpdate { .. }
                | StoreUpdate::AdapterReady { .. }
                | StoreUpdate::AdapterRxStateChanged { .. }
                | StoreUpdate::AdapterShutdown { .. }
                | StoreUpdate::ChannelLocked { .. }
                | StoreUpdate::ChannelUnlocked
                | StoreUpdate::CsiReceived { .. }
                | StoreUpdate::DfsRadarDetected { .. }
                | StoreUpdate::BbScopeReceived { .. }
                | StoreUpdate::SpatialSoundingReceived { .. }
                | StoreUpdate::AttackStarted { .. }
                | StoreUpdate::AttackPhaseChanged { .. }
                | StoreUpdate::AttackCountersUpdate { .. }
                | StoreUpdate::AttackEvent { .. }
                | StoreUpdate::AttackComplete { .. } => {
                    // These are broadcast-only — subscribers consume them,
                    // but the FrameStore has no state to update.
                }
            }
        }
    }

    // ─── Events ──────────────────────────────────────────────────────────

    /// Push a scan event with auto-incrementing sequence number.
    pub fn push_event(
        &self,
        event_type: ScanEventType,
        source: MacAddress,
        target: MacAddress,
        channel: u8,
        rssi: i8,
        detail: EventDetail,
    ) {
        let seq = self.inner.event_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let timestamp = self.inner.start_time.elapsed();

        self.inner.events.push(ScanEvent {
            seq,
            timestamp,
            event_type,
            source,
            target,
            channel,
            rssi,
            detail,
        });
    }

    // ─── Stats snapshot ──────────────────────────────────────────────────

    /// Build a complete ScanStats snapshot from all tables.
    pub fn stats(&self) -> ScanStats {
        let aps = self.inner.aps.read().unwrap();
        let stations = self.inner.stations.read().unwrap();
        let probes = self.inner.probes.read().unwrap();
        let fa = self.inner.fa.read().unwrap();
        let frame_count = self.inner.frame_count.load(Ordering::Relaxed);
        let eapol_frame_count = self.inner.eapol_frame_count.load(Ordering::Relaxed);
        let elapsed = self.inner.start_time.elapsed();

        // Real-time FPS: delta frames / delta time since last stats() call.
        // Smoothed over ~1s minimum to avoid jitter from 50ms render intervals.
        let fps = {
            let mut tracker = self.inner.fps_tracker.lock().unwrap_or_else(|e| e.into_inner());
            let (prev_count, prev_time) = *tracker;
            let now = Instant::now();
            let dt = now.duration_since(prev_time);

            // Only update after at least 1 second to get a stable reading
            if dt.as_secs_f64() >= 1.0 {
                let delta_frames = frame_count.saturating_sub(prev_count);
                let current_fps = (delta_frames as f64 / dt.as_secs_f64()) as u32;
                *tracker = (frame_count, now);
                current_fps
            } else if prev_count == 0 && elapsed.as_secs() > 0 {
                // First call — use lifetime average as bootstrap
                (frame_count as f64 / elapsed.as_secs_f64()) as u32
            } else {
                // Within the 1s window — return last computed value
                // (don't update tracker, let it accumulate to 1s)
                let delta_frames = frame_count.saturating_sub(prev_count);
                if dt.as_millis() > 0 {
                    (delta_frames as f64 / dt.as_secs_f64()) as u32
                } else {
                    0
                }
            }
        };

        // Band breakdown
        let mut aps_24ghz = 0usize;
        let mut aps_5ghz = 0usize;

        // Security breakdown
        let mut open_count = 0usize;
        let mut wep_count = 0usize;
        let mut wpa_count = 0usize;
        let mut wpa2_count = 0usize;
        let mut wpa3_count = 0usize;
        let mut enterprise_count = 0usize;
        let mut wps_count = 0usize;
        let mut hidden_count = 0usize;

        for ap in aps.values() {
            if ap.channel <= 14 {
                aps_24ghz += 1;
            } else {
                aps_5ghz += 1;
            }
            match ap.security {
                Security::Open => open_count += 1,
                Security::Wep => wep_count += 1,
                Security::Wpa => wpa_count += 1,
                Security::Wpa2 => wpa2_count += 1,
                Security::Wpa3 => wpa3_count += 1,
                Security::Wpa2Enterprise => {
                    enterprise_count += 1;
                    wpa2_count += 1;
                }
                Security::Wpa3Enterprise => {
                    enterprise_count += 1;
                    wpa3_count += 1;
                }
                _ => {}
            }
            if ap.wps_state != WpsState::None {
                wps_count += 1;
            }
            if ap.is_hidden {
                hidden_count += 1;
            }
        }

        // Capture stats
        let capture_db = self.inner.capture_db.read().unwrap();
        let cap_stats = capture_db.stats();

        ScanStats {
            ap_count: aps.len(),
            sta_count: stations.len(),
            probe_count: probes.len(),
            eapol_frame_count: eapol_frame_count as usize,
            frame_count,
            round: self.inner.round.load(Ordering::Relaxed),
            elapsed,
            frames_per_sec: fps,
            aps_24ghz,
            aps_5ghz,
            open_count,
            wep_count,
            wpa_count,
            wpa2_count,
            wpa3_count,
            enterprise_count,
            wps_count,
            hidden_count,
            handshake_count: cap_stats.total_handshakes,
            pmkid_count: cap_stats.pmkid_captures,
            crackable_count: cap_stats.crackable_handshakes,
            complete_handshake_count: cap_stats.complete_handshakes,
            eap_id_count: cap_stats.eap_identities,
            unique_capture_aps: cap_stats.unique_aps,
            best_handshake_quality: cap_stats.best_quality,
            event_count: self.inner.event_seq.load(Ordering::Relaxed) as usize,
            action_frame_count: fa.action as usize,
            control_frame_count: fa.ctrl_total() as usize,
            retry_frame_count: 0,
            retry_rate_pct: 0.0,
            unknown_mgmt_count: 0,
            probe_overflow_count: 0,
            event_overflow_count: self.inner.events.overflow_count(),
            frame_accounting: fa.clone(),
        }
    }
}

impl Default for FrameStore {
    fn default() -> Self {
        Self::new()
    }
}
