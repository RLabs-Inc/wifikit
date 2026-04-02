#![allow(dead_code)]
//! ChannelStats, BeaconTiming, FrameAccounting, ScanStats — scanner statistics types.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::core::MacAddress;
use crate::protocol::eapol::HandshakeQuality;

// ═══════════════════════════════════════════════════════════════════════════════
//  ChannelStats — per-channel frame statistics
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ChannelStats {
    pub channel: u8,
    pub band: u8,
    pub ap_count: u16,
    pub sta_count: u16,
    pub frame_count: u64,
    pub fps: f32,
    pub noise_floor: i8,
    pub retry_count: u64,
    pub retry_rate: f32,
    pub dwell_time: Duration,
    pub last_update: Instant,
    pub(crate) frame_count_at_dwell_start: u64,
    pub(crate) dwell_start: Instant,
    /// MIB survey: channel busy time in microseconds (last dwell).
    pub busy_us: u32,
    /// MIB survey: TX airtime in microseconds (last dwell).
    pub tx_us: u32,
    /// MIB survey: RX airtime in microseconds (last dwell).
    pub rx_us: u32,
    /// MIB survey: OBSS (other BSS) airtime in microseconds (last dwell).
    pub obss_us: u32,
    /// Channel utilization percentage (busy_us / dwell_time_us * 100).
    pub utilization_pct: f32,
}

/// Encode (channel, band) into a u16 key for HashMap lookups.
/// High byte = band (0=2.4G, 1=5G, 2=6G), low byte = channel number.
/// This distinguishes 6GHz channel 1 from 2.4GHz channel 1.
pub fn channel_key(channel: u8, band: u8) -> u16 {
    (band as u16) << 8 | channel as u16
}

impl ChannelStats {
    pub(crate) fn new(channel: u8, band: u8) -> Self {
        let now = Instant::now();
        Self {
            channel,
            band,
            ap_count: 0,
            sta_count: 0,
            frame_count: 0,
            fps: 0.0,
            noise_floor: -95,
            retry_count: 0,
            retry_rate: 0.0,
            dwell_time: Duration::ZERO,
            last_update: now,
            frame_count_at_dwell_start: 0,
            dwell_start: now,
            busy_us: 0,
            tx_us: 0,
            rx_us: 0,
            obss_us: 0,
            utilization_pct: 0.0,
        }
    }

    pub(crate) fn start_dwell(&mut self) {
        self.dwell_start = Instant::now();
        self.frame_count_at_dwell_start = self.frame_count;
    }

    pub(crate) fn end_dwell(&mut self) {
        let elapsed = self.dwell_start.elapsed();
        self.dwell_time += elapsed;
        let frames_this_dwell = self.frame_count.saturating_sub(self.frame_count_at_dwell_start);
        let dwell_secs = elapsed.as_secs_f32();
        if dwell_secs > 0.0 {
            // Per-dwell FPS for this channel (more accurate than cumulative average)
            self.fps = frames_this_dwell as f32 / dwell_secs;
        }
        if self.frame_count > 0 {
            self.retry_rate = self.retry_count as f32 / self.frame_count as f32 * 100.0;
        }
        self.last_update = Instant::now();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BeaconTiming — per-AP beacon jitter / TSF drift analysis
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct BeaconTiming {
    pub bssid: MacAddress,
    pub expected_interval: Duration,
    pub measured_mean: Duration,
    pub jitter_stddev: f64,
    pub beacon_loss_count: u32,
    pub beacon_loss_rate: f32,
    pub tsf_drift_ppm: f64,
    pub tsf_jumps: u32,
    pub samples: u32,
    pub(crate) last_tsf: u64,
    pub(crate) last_beacon: Instant,
    pub(crate) intervals: VecDeque<f64>,
    pub(crate) tsf_deltas: VecDeque<f64>,
}

impl BeaconTiming {
    pub(crate) fn new(bssid: MacAddress, beacon_interval_tu: u16) -> Self {
        Self {
            bssid,
            expected_interval: Duration::from_micros(beacon_interval_tu as u64 * 1024),
            measured_mean: Duration::ZERO,
            jitter_stddev: 0.0,
            beacon_loss_count: 0,
            beacon_loss_rate: 0.0,
            tsf_drift_ppm: 0.0,
            tsf_jumps: 0,
            samples: 0,
            last_tsf: 0,
            last_beacon: Instant::now(),
            intervals: VecDeque::with_capacity(256),
            tsf_deltas: VecDeque::with_capacity(256),
        }
    }

    pub(crate) fn record_beacon(&mut self, tsf: u64) {
        let now = Instant::now();

        if self.samples > 0 {
            // Measure actual inter-beacon interval
            let interval_us = self.last_beacon.elapsed().as_micros() as f64;
            self.intervals.push_back(interval_us);

            // Keep last 256 samples
            if self.intervals.len() > 256 {
                self.intervals.pop_front();
            }

            // Beacon loss: if interval > 1.5x expected, some beacons were lost
            let expected_us = self.expected_interval.as_micros() as f64;
            if expected_us > 0.0 && interval_us > expected_us * 1.5 {
                let missed = (interval_us / expected_us).round() as u32 - 1;
                self.beacon_loss_count += missed;
            }

            // TSF drift analysis
            if self.last_tsf > 0 && tsf > self.last_tsf {
                let tsf_delta_us = (tsf - self.last_tsf) as f64;
                let real_delta_us = interval_us;
                if real_delta_us > 0.0 {
                    let drift_ppm = (tsf_delta_us - real_delta_us) / real_delta_us * 1_000_000.0;
                    self.tsf_deltas.push_back(drift_ppm);
                    if self.tsf_deltas.len() > 256 {
                        self.tsf_deltas.pop_front();
                    }
                }
            }

            // TSF jump detection (non-monotonic or huge jump)
            if tsf < self.last_tsf || (tsf - self.last_tsf) > expected_us as u64 * 10 {
                self.tsf_jumps += 1;
            }

            // Recompute stats
            self.recompute();
        }

        self.samples += 1;
        self.last_tsf = tsf;
        self.last_beacon = now;
    }

    pub(crate) fn recompute(&mut self) {
        if self.intervals.is_empty() {
            return;
        }

        // Mean
        let sum: f64 = self.intervals.iter().sum();
        let mean = sum / self.intervals.len() as f64;
        self.measured_mean = Duration::from_micros(mean as u64);

        // Stddev (jitter)
        if self.intervals.len() > 1 {
            let variance: f64 = self.intervals.iter()
                .map(|x| (x - mean).powi(2))
                .sum::<f64>() / (self.intervals.len() - 1) as f64;
            self.jitter_stddev = variance.sqrt();
        }

        // Beacon loss rate
        let total_expected = self.samples;
        if total_expected > 0 {
            self.beacon_loss_rate = self.beacon_loss_count as f32
                / (total_expected + self.beacon_loss_count) as f32 * 100.0;
        }

        // TSF drift (mean ppm)
        if !self.tsf_deltas.is_empty() {
            self.tsf_drift_ppm = self.tsf_deltas.iter().sum::<f64>()
                / self.tsf_deltas.len() as f64;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Scan statistics
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub ap_count: usize,
    pub sta_count: usize,
    pub probe_count: usize,
    pub eapol_frame_count: usize,
    pub frame_count: u64,
    pub round: u32,
    pub elapsed: Duration,
    pub frames_per_sec: u32,

    // Band breakdown
    pub aps_24ghz: usize,
    pub aps_5ghz: usize,

    // Security breakdown
    pub open_count: usize,
    pub wep_count: usize,
    pub wpa_count: usize,
    pub wpa2_count: usize,
    pub wpa3_count: usize,
    pub enterprise_count: usize,
    pub wps_count: usize,
    pub hidden_count: usize,

    // Capture stats (from CaptureDatabase)
    pub handshake_count: usize,
    pub pmkid_count: usize,
    pub crackable_count: usize,
    pub complete_handshake_count: usize,
    pub eap_id_count: usize,
    pub unique_capture_aps: usize,
    pub best_handshake_quality: HandshakeQuality,

    // Event + frame stats
    pub event_count: usize,
    pub action_frame_count: usize,
    pub control_frame_count: usize,
    pub retry_frame_count: u64,
    pub retry_rate_pct: f32,
    pub unknown_mgmt_count: u64,

    // Overflow diagnostics
    pub probe_overflow_count: u64,
    pub event_overflow_count: u64,

    // ParsedFrame body variant accounting — what we received vs what was parsed
    pub frame_accounting: FrameAccounting,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FrameAccounting — real-time accounting of every frame by ParsedFrame body variant
// ═══════════════════════════════════════════════════════════════════════════════

/// Real-time accounting of every frame by its ParsedFrame body variant.
/// This is the "received vs parsed" diagnostic.
#[derive(Debug, Clone, Default)]
pub struct FrameAccounting {
    // Management
    pub beacon: u64,
    pub probe_req: u64,
    pub auth: u64,
    pub deauth: u64,
    pub disassoc: u64,
    pub assoc_req: u64,
    pub assoc_resp: u64,
    pub reassoc_req: u64,
    pub reassoc_resp: u64,
    pub action: u64,
    // Data
    pub data_eapol: u64,
    pub data_null: u64,
    pub data_encrypted: u64,
    pub data_llc: u64,
    pub data_llc_eapol_unparsed: u64,
    pub data_other: u64,
    // Control
    pub ctrl_rts: u64,
    pub ctrl_cts: u64,
    pub ctrl_ack: u64,
    pub ctrl_bar: u64,
    pub ctrl_ba: u64,
    pub ctrl_pspoll: u64,
    pub ctrl_other: u64,
    // Unparseable
    pub unparseable: u64,
}

impl FrameAccounting {
    pub fn total(&self) -> u64 {
        self.beacon + self.probe_req + self.auth + self.deauth
        + self.disassoc + self.assoc_req + self.assoc_resp
        + self.reassoc_req + self.reassoc_resp + self.action
        + self.data_eapol + self.data_null + self.data_encrypted
        + self.data_llc + self.data_llc_eapol_unparsed + self.data_other
        + self.ctrl_rts + self.ctrl_cts + self.ctrl_ack
        + self.ctrl_bar + self.ctrl_ba + self.ctrl_pspoll + self.ctrl_other
        + self.unparseable
    }

    pub fn mgmt_total(&self) -> u64 {
        self.beacon + self.probe_req + self.auth + self.deauth
        + self.disassoc + self.assoc_req + self.assoc_resp
        + self.reassoc_req + self.reassoc_resp + self.action
    }

    pub fn data_total(&self) -> u64 {
        self.data_eapol + self.data_null + self.data_encrypted
        + self.data_llc + self.data_llc_eapol_unparsed + self.data_other
    }

    pub fn ctrl_total(&self) -> u64 {
        self.ctrl_rts + self.ctrl_cts + self.ctrl_ack
        + self.ctrl_bar + self.ctrl_ba + self.ctrl_pspoll + self.ctrl_other
    }
}
