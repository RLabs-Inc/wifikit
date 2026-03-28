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

// Re-export all public types
pub use ap::{Ap, IeEntry, WpsState, build_ie_inventory, MAX_RSSI_SAMPLES};
pub use event::{EventDetail, ScanEvent, ScanEventType};
pub use probe::ProbeReq;
pub use station::Station;
pub use stats::{BeaconTiming, ChannelStats, FrameAccounting, ScanStats};

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
    channel_stats: RwLock<HashMap<u8, ChannelStats>>,
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
    pub fn get_channel_stats(&self) -> HashMap<u8, ChannelStats> {
        self.inner.channel_stats.read().unwrap().clone()
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
        F: FnOnce(&mut HashMap<u8, ChannelStats>) -> R,
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
