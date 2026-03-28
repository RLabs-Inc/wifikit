#![allow(dead_code)]
//! Station struct — one tracked WiFi client.

use std::time::Instant;

use crate::core::MacAddress;
use crate::protocol::ieee80211::WifiGeneration;
use crate::util::oui::oui_lookup;

// ═══════════════════════════════════════════════════════════════════════════════
//  Station — one tracked WiFi client
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct Station {
    pub mac: MacAddress,
    pub bssid: Option<MacAddress>,
    pub is_associated: bool,
    pub rssi: i8,
    pub rssi_best: i8,
    pub last_channel: u8,
    pub frame_count: u32,
    pub data_bytes: u64,
    pub probe_ssid_count: u16,
    pub last_probe_ssid: String,
    pub vendor: String,
    pub first_seen: Instant,
    pub last_seen: Instant,

    // Fingerprinting — WiFi generation + capabilities
    pub wifi_gen: WifiGeneration,
    pub max_nss: u8,
    pub max_rate_mbps: u16,
    pub has_ht: bool,
    pub has_vht: bool,
    pub has_he: bool,
    pub ht_cap_raw: u16,
    pub vht_cap_raw: u32,
    pub supported_rates: Vec<u8>,
    pub ie_tag_order: Vec<u8>,
    pub ie_tag_count: u8,
    pub listen_interval: u16,
    pub ampdu_max_len_exp: u8,
    pub ampdu_min_spacing: u8,

    // MAC randomization detection
    pub is_randomized: bool,

    // Sequence number tracking
    pub seq_num_first: u16,
    pub seq_num_last: u16,
    pub seq_num_gaps: u16,

    // Power save tracking
    pub power_save: bool,
    pub power_save_transitions: u32,

    // Noise floor (from channel stats)
    pub noise: i8,

    // Probe timing
    pub avg_probe_interval_ms: u32,
    pub(crate) last_probe_time: Option<Instant>,
    pub(crate) probe_intervals: Vec<u32>,

    // Handshake state
    pub handshake_state: u8,

    // QoS TID usage
    pub tid_counts: [u32; 8],
}

impl Station {
    pub(crate) fn new(mac: MacAddress, now: Instant) -> Self {
        let bytes = mac.as_bytes();
        let is_randomized = bytes[0] & 0x02 != 0; // locally administered bit
        Self {
            mac,
            bssid: None,
            is_associated: false,
            rssi: -100,
            rssi_best: -100,
            last_channel: 0,
            frame_count: 0,
            data_bytes: 0,
            probe_ssid_count: 0,
            last_probe_ssid: String::new(),
            vendor: oui_lookup(bytes).to_string(),
            first_seen: now,
            last_seen: now,
            wifi_gen: WifiGeneration::Legacy,
            max_nss: 1,
            max_rate_mbps: 0,
            has_ht: false,
            has_vht: false,
            has_he: false,
            ht_cap_raw: 0,
            vht_cap_raw: 0,
            supported_rates: Vec::new(),
            ie_tag_order: Vec::new(),
            ie_tag_count: 0,
            listen_interval: 0,
            ampdu_max_len_exp: 0,
            ampdu_min_spacing: 0,
            is_randomized,
            seq_num_first: 0,
            seq_num_last: 0,
            seq_num_gaps: 0,
            power_save: false,
            power_save_transitions: 0,
            noise: -95,
            avg_probe_interval_ms: 0,
            last_probe_time: None,
            probe_intervals: Vec::new(),
            handshake_state: 0,
            tid_counts: [0; 8],
        }
    }
}
