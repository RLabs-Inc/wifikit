#![allow(dead_code)]
//! Ap struct — one discovered access point with full IE-parsed state.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::core::{Bandwidth, MacAddress};
use crate::protocol::eapol::HandshakeQuality;
use crate::protocol::ie::RsnInfo;
use crate::protocol::ieee80211::{Security, WifiGeneration};
use crate::util::oui::oui_lookup;

/// Maximum number of RSSI samples kept per AP for sparkline rendering.
pub const MAX_RSSI_SAMPLES: usize = 100;

// ═══════════════════════════════════════════════════════════════════════════════
//  IeEntry — structured index into raw_ies blob
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct IeEntry {
    pub tag: u8,
    pub ext_id: Option<u8>,
    pub offset: u16,
    pub length: u16,
}

// ═══════════════════════════════════════════════════════════════════════════════
/// Build an IE inventory index from raw IE bytes.
pub fn build_ie_inventory(raw_ies: &[u8]) -> Vec<IeEntry> {
    let mut inventory = Vec::new();
    let mut offset = 0u16;
    while (offset as usize) + 2 <= raw_ies.len() {
        let tag = raw_ies[offset as usize];
        let len = raw_ies[offset as usize + 1] as u16;
        if (offset as usize) + 2 + len as usize > raw_ies.len() {
            break;
        }
        let ext_id = if tag == 255 && len > 0 {
            Some(raw_ies[offset as usize + 2])
        } else {
            None
        };
        inventory.push(IeEntry { tag, ext_id, offset, length: len });
        offset += 2 + len;
    }
    inventory
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WpsState
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WpsState {
    #[default]
    None,
    NotConfigured,
    Configured,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AP — one discovered access point
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct Ap {
    pub bssid: MacAddress,
    pub ssid: String,
    pub ssid_raw: Vec<u8>,
    pub is_hidden: bool,
    pub rssi: i8,
    pub rssi_best: i8,
    pub rssi_worst: i8,
    pub noise: i8,
    pub channel: u8,
    pub channel_center: u16,
    pub bandwidth: Bandwidth,
    pub wifi_gen: WifiGeneration,
    pub freq_mhz: u16,
    pub max_nss: u8,
    pub max_rate_mbps: u16,
    pub rsn: Option<RsnInfo>,
    pub security: Security,
    pub beacon_interval: u16,
    pub capability: u16,
    pub beacon_count: u32,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub tsf: u64,
    pub country: Option<[u8; 2]>,
    pub vendor: String,

    // QBSS Load (IE 11)
    pub has_qbss: bool,
    pub qbss_station_count: u16,
    pub qbss_utilization: u8,
    pub qbss_admission_cap: u16,

    // TIM / DTIM
    pub has_tim: bool,
    pub dtim_period: u8,
    pub dtim_count: u8,

    // Supported Rates (fingerprinting)
    pub supported_rates: Vec<u8>,

    // 802.11r Fast Transition
    pub has_ft: bool,
    pub ft_over_ds: bool,
    pub ft_mdid: u16,

    // Extended Capabilities (IE 127) — attack surface
    pub has_ext_cap: bool,
    pub ext_cap_bss_transition: bool,
    pub ext_cap_wnm_sleep: bool,
    pub ext_cap_tfs: bool,
    pub ext_cap_proxy_arp: bool,
    pub ext_cap_fms: bool,
    pub ext_cap_tim_broadcast: bool,
    pub ext_cap_interworking: bool,
    pub ext_cap_tdls: bool,

    // ERP (IE 42) — 802.11g protection
    pub has_erp: bool,
    pub erp_use_protection: bool,
    pub erp_barker_preamble: bool,

    // HE Operation (IE 255/36) — WiFi 6 BSS Color
    pub has_he_oper: bool,
    pub he_bss_color: u8,
    pub he_default_pe_dur: u8,
    pub he_twt_required: bool,

    // Interworking / Hotspot 2.0 (IE 107)
    pub has_interworking: bool,
    pub interworking_type: u8,
    pub has_internet: bool,

    // Mesh (IE 114)
    pub is_mesh: bool,
    pub mesh_id: String,

    // DS Parameter Set (IE 3)
    pub has_ds: bool,
    pub ds_channel: u8,

    // QoS (IE 46)
    pub has_qos: bool,
    pub qos_info: u8,

    // CSA (IE 37)
    pub has_csa: bool,
    pub csa_mode: u8,
    pub csa_new_channel: u8,
    pub csa_count: u8,

    // Operating Classes (IE 59)
    pub operating_classes: Vec<u8>,

    // RM Enabled Capabilities (IE 70) — 802.11k
    pub has_rm: bool,
    pub rm_link_meas: bool,
    pub rm_neighbor_report: bool,
    pub rm_beacon_passive: bool,
    pub rm_beacon_active: bool,
    pub rm_beacon_table: bool,

    // Multiple BSSID (IE 71)
    pub has_multi_bssid: bool,
    pub max_bssid_indicator: u8,

    // Reduced Neighbor Report (IE 201) — WiFi 6E
    pub has_rnr: bool,
    pub rnr_ap_count: u8,

    // Raw caps for fingerprinting
    pub ht_cap_raw: u16,
    pub vht_cap_raw: u32,

    // A-MPDU params (from HT Capabilities)
    pub ampdu_max_len_exp: u8,
    pub ampdu_min_spacing: u8,

    // VHT sounding dimensions
    pub vht_sounding_dims: u8,

    // HT Operation (IE 61) — for Radio tab display
    pub has_ht_oper: bool,
    pub ht_oper_primary_ch: u8,
    pub ht_oper_secondary_offset: u8,
    pub ht_oper_sta_ch_width: u8,

    // VHT Operation (IE 192)
    pub has_vht_oper: bool,
    pub vht_oper_ch_width: u8,
    pub vht_oper_center_seg0: u8,
    pub vht_oper_center_seg1: u8,

    // IE inventory — structured index into raw_ies
    pub ie_inventory: Vec<IeEntry>,

    // Vendor IE OUIs
    pub vendor_ie_ouis: Vec<[u8; 3]>,
    pub has_wmm: bool,
    pub has_p2p: bool,
    pub has_hs20: bool,

    // WPS state
    pub wps_state: WpsState,
    pub wps_locked: bool,
    pub wps_version: u8,
    pub wps_device_name: String,
    pub wps_model: String,

    // Handshake state (from capture engine)
    pub handshake_quality: HandshakeQuality,
    pub has_pmkid: bool,

    // Raw IE blob (for research / raw access)
    pub raw_ies: Vec<u8>,

    // Client count (derived from station tracking)
    pub client_count: u16,

    // RSSI history for sparkline rendering (timestamp since scan start, rssi)
    pub rssi_samples: VecDeque<(Duration, i8)>,
}

impl Ap {
    pub(crate) fn new(bssid: MacAddress, now: Instant) -> Self {
        Self {
            bssid,
            ssid: String::new(),
            ssid_raw: Vec::new(),
            is_hidden: false,
            rssi: -100,
            rssi_best: -100,
            rssi_worst: 0,
            noise: -95,
            channel: 0,
            channel_center: 0,
            bandwidth: Bandwidth::Bw20,
            wifi_gen: WifiGeneration::Legacy,
            freq_mhz: 0,
            max_nss: 1,
            max_rate_mbps: 0,
            rsn: None,
            security: Security::Open,
            beacon_interval: 100,
            capability: 0,
            beacon_count: 0,
            first_seen: now,
            last_seen: now,
            tsf: 0,
            country: None,
            vendor: oui_lookup(bssid.as_bytes()).to_string(),
            has_qbss: false,
            qbss_station_count: 0,
            qbss_utilization: 0,
            qbss_admission_cap: 0,
            has_tim: false,
            dtim_period: 0,
            dtim_count: 0,
            supported_rates: Vec::new(),
            has_ft: false,
            ft_over_ds: false,
            ft_mdid: 0,
            has_ext_cap: false,
            ext_cap_bss_transition: false,
            ext_cap_wnm_sleep: false,
            ext_cap_tfs: false,
            ext_cap_proxy_arp: false,
            ext_cap_fms: false,
            ext_cap_tim_broadcast: false,
            ext_cap_interworking: false,
            ext_cap_tdls: false,
            has_erp: false,
            erp_use_protection: false,
            erp_barker_preamble: false,
            has_he_oper: false,
            he_bss_color: 0,
            he_default_pe_dur: 0,
            he_twt_required: false,
            has_interworking: false,
            interworking_type: 0,
            has_internet: false,
            is_mesh: false,
            mesh_id: String::new(),
            has_ds: false,
            ds_channel: 0,
            has_qos: false,
            qos_info: 0,
            has_csa: false,
            csa_mode: 0,
            csa_new_channel: 0,
            csa_count: 0,
            operating_classes: Vec::new(),
            has_rm: false,
            rm_link_meas: false,
            rm_neighbor_report: false,
            rm_beacon_passive: false,
            rm_beacon_active: false,
            rm_beacon_table: false,
            has_multi_bssid: false,
            max_bssid_indicator: 0,
            has_rnr: false,
            rnr_ap_count: 0,
            ht_cap_raw: 0,
            vht_cap_raw: 0,
            ampdu_max_len_exp: 0,
            ampdu_min_spacing: 0,
            vht_sounding_dims: 0,
            has_ht_oper: false,
            ht_oper_primary_ch: 0,
            ht_oper_secondary_offset: 0,
            ht_oper_sta_ch_width: 0,
            has_vht_oper: false,
            vht_oper_ch_width: 0,
            vht_oper_center_seg0: 0,
            vht_oper_center_seg1: 0,
            ie_inventory: Vec::new(),
            vendor_ie_ouis: Vec::new(),
            has_wmm: false,
            has_p2p: false,
            has_hs20: false,
            wps_state: WpsState::None,
            wps_locked: false,
            wps_version: 0,
            wps_device_name: String::new(),
            wps_model: String::new(),
            handshake_quality: HandshakeQuality::None,
            has_pmkid: false,
            raw_ies: Vec::new(),
            client_count: 0,
            rssi_samples: VecDeque::with_capacity(MAX_RSSI_SAMPLES),
        }
    }

    /// Create a minimal AP target for blind attacks (no scan, just BSSID + SSID + channel).
    /// Used by PMKID attack when `scan_first=false`.
    ///
    /// Assumes WiFi5 (VHT) capability so the association request includes
    /// VHT IEs — necessary for some APs to include PMKID in M1.
    /// WMM is assumed since it's required for HT/VHT operation.
    pub fn new_blind_target(bssid: MacAddress, ssid: String, channel: u8) -> Self {
        let now = Instant::now();
        let mut ap = Self::new(bssid, now);
        ap.ssid = ssid;
        ap.channel = channel;
        ap.wifi_gen = WifiGeneration::Wifi5;
        ap.has_wmm = true;
        ap.max_nss = 2;
        // Derive bandwidth from band: 5 GHz → 80 MHz, 2.4 GHz → 40 MHz
        ap.bandwidth = if channel >= 36 {
            Bandwidth::Bw80
        } else {
            Bandwidth::Bw40
        };
        ap
    }
}
