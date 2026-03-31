//! Frame extractor — converts ParsedFrames into FrameStore intelligence.
//!
//! Called by the pipeline thread for every successfully parsed frame.
//! This is where beacons become AP entries, data frames become station
//! associations, and EAPOL frames become handshake progress.
//!
//! Ported from scanner_v1.rs process_* methods (~2000 lines).

#![allow(unused_imports)]

use std::time::Instant;

use crate::core::parsed_frame::{
    ActionDetail, ControlDetail, DataDirection, DataPayload, FrameBody, ParsedFrame,
};
use crate::core::{Bandwidth, MacAddress};
use crate::engine::capture::{self, CaptureEvent};
use crate::protocol::eapol::HandshakeMessage;
use crate::protocol::ie::{self, ParsedIes};
use crate::protocol::ieee80211::{
    action_category, frame_subtype, frame_type, ie_tag, ReasonCode, Security, WifiGeneration,
    BEACON_TAGS_OFFSET,
};
use crate::store::{
    build_ie_inventory, Ap, BeaconTiming, ChannelStats, EventDetail, FrameStore, ProbeReq,
    ScanEventType, Station, WpsState, MAX_PROBES,
};
use crate::util::oui::oui_lookup;

use crate::core::channel::Channel;

/// Process a parsed frame and update the FrameStore.
///
/// This is the single function that converts raw parsed frames into
/// structured intelligence (APs, stations, probes, handshakes, etc.).
///
/// Called once per frame by the pipeline thread. Must be fast —
/// the pipeline thread processes frames at 300+ fps.
pub fn process_frame(pf: &ParsedFrame, channel: u8, band: u8, store: &FrameStore) {
    // Unparseable frames — skip
    if matches!(&pf.body, FrameBody::Unparseable { .. }) {
        return;
    }

    store.inc_frame_count();

    // Channel stats: create entry on first frame, count every frame + retries.
    // Key is (band<<8 | channel) to distinguish 6GHz ch1 from 2.4GHz ch1.
    let key = crate::store::stats::channel_key(channel, band);
    store.with_channel_stats_mut(|stats| {
        let cs = stats.entry(key)
            .or_insert_with(|| ChannelStats::new(channel, band));
        cs.frame_count += 1;
        if pf.retry {
            cs.retry_count += 1;
        }
    });

    // ── Frame accounting — count every frame by its ParsedFrame body variant ──
    store.with_frame_accounting_mut(|fa| {
        match &pf.body {
            FrameBody::Beacon { .. } => fa.beacon += 1,
            FrameBody::ProbeReq { .. } => fa.probe_req += 1,
            FrameBody::Auth { .. } => fa.auth += 1,
            FrameBody::Deauth { .. } => fa.deauth += 1,
            FrameBody::Disassoc { .. } => fa.disassoc += 1,
            FrameBody::AssocReq { .. } => fa.assoc_req += 1,
            FrameBody::AssocResp { .. } => fa.assoc_resp += 1,
            FrameBody::ReassocReq { .. } => fa.reassoc_req += 1,
            FrameBody::ReassocResp { .. } => fa.reassoc_resp += 1,
            FrameBody::Action { .. } => fa.action += 1,
            FrameBody::Data { payload, .. } => match payload {
                DataPayload::Eapol(_) => fa.data_eapol += 1,
                DataPayload::Null => fa.data_null += 1,
                DataPayload::Encrypted => fa.data_encrypted += 1,
                DataPayload::Llc { ethertype } if *ethertype == 0x888E => {
                    fa.data_llc_eapol_unparsed += 1
                }
                DataPayload::Llc { .. } => fa.data_llc += 1,
                DataPayload::Other => fa.data_other += 1,
            },
            FrameBody::Control { detail } => match detail {
                ControlDetail::Rts { .. } => fa.ctrl_rts += 1,
                ControlDetail::Cts { .. } => fa.ctrl_cts += 1,
                ControlDetail::Ack { .. } => fa.ctrl_ack += 1,
                ControlDetail::BlockAckReq { .. } => fa.ctrl_bar += 1,
                ControlDetail::BlockAck { .. } => fa.ctrl_ba += 1,
                ControlDetail::PsPoll { .. } => fa.ctrl_pspoll += 1,
                _ => fa.ctrl_other += 1,
            },
            FrameBody::Unparseable { .. } => fa.unparseable += 1,
        }
    });

    let ftype = pf.frame_type;
    let subtype = pf.frame_subtype;

    match (ftype, subtype) {
        // Beacon or Probe Response
        (frame_type::MANAGEMENT, frame_subtype::BEACON)
        | (frame_type::MANAGEMENT, frame_subtype::PROBE_RESP) => {
            process_beacon(pf, channel, store);
        }
        // Probe Request
        (frame_type::MANAGEMENT, frame_subtype::PROBE_REQ) => {
            process_probe_req(pf, channel, store);
        }
        // Authentication
        (frame_type::MANAGEMENT, frame_subtype::AUTH) => {
            process_auth(pf, channel, store);
        }
        // Deauthentication
        (frame_type::MANAGEMENT, frame_subtype::DEAUTH) => {
            process_deauth(pf, channel, store);
        }
        // Association Request
        (frame_type::MANAGEMENT, frame_subtype::ASSOC_REQ) => {
            process_assoc_req(pf, channel, store);
        }
        // Association Response
        (frame_type::MANAGEMENT, frame_subtype::ASSOC_RESP) => {
            process_assoc_resp(pf, channel, store);
        }
        // Reassociation Request
        (frame_type::MANAGEMENT, frame_subtype::REASSOC_REQ) => {
            process_reassoc_req(pf, channel, store);
        }
        // Reassociation Response (same format as assoc resp)
        (frame_type::MANAGEMENT, frame_subtype::REASSOC_RESP) => {
            process_assoc_resp(pf, channel, store);
        }
        // Disassociation
        (frame_type::MANAGEMENT, frame_subtype::DISASSOC) => {
            process_disassoc(pf, channel, store);
        }
        // Action frame
        (frame_type::MANAGEMENT, frame_subtype::ACTION)
        | (frame_type::MANAGEMENT, frame_subtype::ACTION_NO_ACK) => {
            process_action(pf, channel, store);
        }
        // Data frame (any subtype)
        (frame_type::DATA, _) => {
            process_data(pf, channel, store);
        }
        // Control frames
        (frame_type::CONTROL, _) => {
            process_control(pf, channel, store);
        }
        // Unhandled management subtypes (Timing Advertisement, ATIM, etc.)
        (frame_type::MANAGEMENT, _) => {}
        _ => {} // reserved frame types
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Beacon / Probe Response processing — the big one
// ═══════════════════════════════════════════════════════════════════════════════

fn process_beacon(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    // Destructure pre-parsed beacon body — NO raw byte parsing
    let (bssid, tsf, bcn_interval, capability, privacy, parsed) = match &pf.body {
        FrameBody::Beacon {
            bssid,
            tsf,
            beacon_interval,
            capability,
            privacy,
            ies,
        } => (*bssid, *tsf, *beacon_interval, *capability, *privacy, ies),
        _ => return,
    };

    // Raw IE bytes from the original frame for ap.raw_ies storage
    let tags = if pf.raw.len() > BEACON_TAGS_OFFSET {
        &pf.raw[BEACON_TAGS_OFFSET..]
    } else {
        return;
    };
    let now = Instant::now();

    // SSID + hidden detection
    let hidden = parsed.ssid.is_none()
        || parsed.ssid_raw.is_empty()
        || parsed.ssid_raw.iter().all(|&b| b == 0);
    let ssid = if hidden {
        String::new()
    } else {
        match parsed.ssid {
            Some(ref s) => s.clone(),
            None => String::from_utf8_lossy(&parsed.ssid_raw).to_string(),
        }
    };
    let ssid_raw = parsed.ssid_raw.clone();

    // Security determination
    let security = if let Some(ref rsn) = parsed.rsn {
        rsn.security
    } else if parsed.wpa.is_some() {
        Security::Wpa
    } else if privacy {
        Security::Wep
    } else {
        Security::Open
    };

    // WiFi generation
    let wifi_gen = ie::derive_wifi_generation(parsed);

    // Bandwidth derivation
    let mut bandwidth = Bandwidth::Bw20;
    if let Some(ref ht) = parsed.ht_cap {
        if ht.channel_width_40 {
            bandwidth = Bandwidth::Bw40;
        }
    }
    if let Some(ref vht) = parsed.vht_cap {
        if vht.supported_channel_width >= 2 {
            bandwidth = Bandwidth::Bw160;
        } else if vht.supported_channel_width >= 1 {
            bandwidth = Bandwidth::Bw80;
        }
    }
    if let Some(ref vht_oper) = parsed.vht_oper {
        if vht_oper.channel_width >= 2 {
            bandwidth = Bandwidth::Bw160;
        } else if vht_oper.channel_width >= 1 {
            bandwidth = Bandwidth::Bw80;
        }
    }

    // Use DS Parameter Set channel if available (AP's actual channel),
    // otherwise fall back to the channel we're currently scanning on.
    let ap_channel = if let Some(ref ds) = parsed.ds {
        ds.channel
    } else {
        channel
    };
    let freq_mhz = Channel::new(ap_channel).center_freq_mhz;

    // Channel center frequency derivation (in MHz, not channel numbers)
    let base_freq = freq_mhz;
    let mut center_freq = base_freq;
    if let Some(ref ht_oper) = parsed.ht_oper {
        match ht_oper.secondary_channel_offset {
            1 => center_freq = base_freq + 10,                    // Secondary above
            3 => center_freq = base_freq.saturating_sub(10),      // Secondary below
            0 => bandwidth = Bandwidth::Bw20,                     // No secondary channel
            _ => {}                                               // reserved
        }
    }
    if let Some(ref vht_oper) = parsed.vht_oper {
        if vht_oper.channel_width > 0 && vht_oper.center_freq_seg0 > 0 {
            let seg0_ch = vht_oper.center_freq_seg0 as u16;
            center_freq = if seg0_ch <= 14 {
                2407 + seg0_ch * 5
            } else {
                5000 + seg0_ch * 5
            };
        }
    }
    let channel_center = center_freq;

    // Rates
    let mut rates = parsed.supported_rates.clone();
    rates.extend_from_slice(&parsed.extended_rates);

    // Mesh ID (IE 114) — not in ParsedIes, look up from raw_ies
    let mut is_mesh = false;
    let mut mesh_id = String::new();
    for rec in &parsed.raw_ies {
        if rec.tag == 114 {
            is_mesh = true;
            if !rec.data.is_empty() {
                mesh_id = String::from_utf8_lossy(&rec.data).to_string();
            }
            break;
        }
    }

    // Operating Classes (IE 59) — not in ParsedIes, look up from raw_ies
    let mut op_classes: Vec<u8> = Vec::new();
    for rec in &parsed.raw_ies {
        if rec.tag == 59 && !rec.data.is_empty() {
            op_classes = rec.data[..rec.data.len().min(16)].to_vec();
            break;
        }
    }

    // P2P and HS2.0 from vendor OUIs
    let mut has_p2p = false;
    let mut has_hs20 = false;
    for rec in &parsed.raw_ies {
        if rec.tag == ie_tag::VENDOR_SPECIFIC && rec.data.len() >= 4 {
            let oui = [rec.data[0], rec.data[1], rec.data[2]];
            if oui == [0x50, 0x6F, 0x9A] {
                if rec.data[3] == 0x09 {
                    has_p2p = true;
                }
                if rec.data[3] == 0x10 {
                    has_hs20 = true;
                }
            }
        }
    }

    let max_rate_mbps = compute_max_rate_mbps(wifi_gen, parsed.max_nss, bandwidth);

    // ── Update or insert AP via FrameStore ──
    store.with_aps_mut(|aps| {
        let start_time_elapsed = store.elapsed();

        if let Some(ap) = aps.get_mut(&bssid) {
            // ── Update existing AP ──
            ap.rssi = pf.rssi;
            if pf.rssi > ap.rssi_best {
                ap.rssi_best = pf.rssi;
            }
            if pf.rssi < ap.rssi_worst {
                ap.rssi_worst = pf.rssi;
            }
            // RSSI history for sparkline rendering
            if ap.rssi_samples.len() >= crate::store::MAX_RSSI_SAMPLES {
                ap.rssi_samples.pop_front();
            }
            ap.rssi_samples.push_back((start_time_elapsed, pf.rssi));
            ap.beacon_count += 1;
            ap.last_seen = now;
            ap.channel = ap_channel;
            ap.freq_mhz = freq_mhz;
            ap.tsf = tsf;

            // Security — always update (first beacon might lack RSN IE)
            ap.security = security;
            if let Some(ref rsn) = parsed.rsn {
                ap.rsn = Some(rsn.clone());
            }

            // Radio properties
            ap.bandwidth = bandwidth;
            ap.wifi_gen = wifi_gen;
            ap.channel_center = channel_center;
            ap.max_nss = parsed.max_nss;
            ap.max_rate_mbps = max_rate_mbps;

            // Dynamic fields that change between beacons
            if let Some(ref bss_load) = parsed.bss_load {
                ap.has_qbss = true;
                ap.qbss_station_count = bss_load.station_count;
                ap.qbss_utilization = bss_load.channel_utilization;
                ap.qbss_admission_cap = bss_load.admission_capacity;
            }
            if let Some(ref tim) = parsed.tim {
                ap.dtim_count = tim.dtim_count;
            }
            if let Some(ref csa) = parsed.csa {
                ap.has_csa = true;
                ap.csa_mode = csa.mode;
                ap.csa_new_channel = csa.new_channel;
                ap.csa_count = csa.count;
            } else {
                ap.has_csa = false;
            }

            // Update raw IEs if changed
            if ap.raw_ies.len() != tags.len() || ap.raw_ies != tags {
                ap.raw_ies = tags.to_vec();
                ap.ie_inventory = build_ie_inventory(&ap.raw_ies);
            }

            // WPS re-check (lock state can change)
            if let Some(ref wps) = parsed.wps {
                apply_wps_to_ap(wps, ap);
            }

            // Hidden SSID reveal
            if !hidden && !ssid.is_empty() && ap.is_hidden {
                ap.ssid = ssid.clone();
                ap.ssid_raw = ssid_raw.clone();
                ap.is_hidden = false;
            }
        } else {
            // ── New AP ──
            let mut ap = Ap::new(bssid, now);
            ap.ssid = ssid.clone();
            ap.ssid_raw = ssid_raw.clone();
            ap.is_hidden = hidden;
            ap.rssi = pf.rssi;
            ap.rssi_best = pf.rssi;
            ap.rssi_worst = pf.rssi;
            ap.rssi_samples.push_back((start_time_elapsed, pf.rssi));
            ap.channel = ap_channel;
            ap.channel_center = channel_center;
            ap.bandwidth = bandwidth;
            ap.wifi_gen = wifi_gen;
            ap.freq_mhz = freq_mhz;
            ap.max_nss = parsed.max_nss;
            ap.max_rate_mbps = max_rate_mbps;
            ap.rsn = parsed.rsn.clone();
            ap.security = security;
            ap.beacon_interval = bcn_interval;
            ap.capability = capability;
            ap.beacon_count = 1;
            ap.tsf = tsf;
            ap.country = parsed.country_code;

            // QBSS Load
            if let Some(ref bss_load) = parsed.bss_load {
                ap.has_qbss = true;
                ap.qbss_station_count = bss_load.station_count;
                ap.qbss_utilization = bss_load.channel_utilization;
                ap.qbss_admission_cap = bss_load.admission_capacity;
            }

            // TIM
            if let Some(ref tim) = parsed.tim {
                ap.has_tim = true;
                ap.dtim_period = tim.dtim_period;
                ap.dtim_count = tim.dtim_count;
            }

            ap.supported_rates = rates;

            // Fast Transition (802.11r)
            if let Some(ref md) = parsed.mobility_domain {
                ap.has_ft = true;
                ap.ft_mdid = md.mdid;
                ap.ft_over_ds = md.ft_over_ds;
            }

            // Extended Capabilities
            if let Some(ref ext) = parsed.ext_cap {
                ap.has_ext_cap = true;
                ap.ext_cap_bss_transition = ext.bss_transition;
                ap.ext_cap_wnm_sleep = ext.wnm_sleep;
                ap.ext_cap_tfs = ext.tfs;
                ap.ext_cap_proxy_arp = ext.proxy_arp;
                ap.ext_cap_fms = ext.fms;
                ap.ext_cap_tim_broadcast = ext.tim_broadcast;
                ap.ext_cap_interworking = ext.interworking;
                ap.ext_cap_tdls = ext.tdls_support && !ext.tdls_prohibited;
            }

            // ERP
            if let Some(ref erp) = parsed.erp {
                ap.has_erp = true;
                ap.erp_use_protection = erp.use_protection;
                ap.erp_barker_preamble = erp.barker_preamble;
            }

            // HE Operation
            if let Some(ref he_oper) = parsed.he_oper {
                ap.has_he_oper = true;
                ap.he_bss_color = he_oper.bss_color;
                ap.he_default_pe_dur = he_oper.default_pe_dur;
                ap.he_twt_required = he_oper.twt_required;
            }

            // Interworking
            if let Some(ref iw) = parsed.interworking_ie {
                ap.has_interworking = true;
                ap.interworking_type = iw.access_network_type;
                ap.has_internet = iw.internet;
            }

            ap.is_mesh = is_mesh;
            ap.mesh_id = mesh_id;

            // DS Parameter Set
            if let Some(ref ds) = parsed.ds {
                ap.has_ds = true;
                ap.ds_channel = ds.channel;
            }

            // QoS
            if let Some(ref qos) = parsed.qos {
                ap.has_qos = true;
                ap.qos_info = qos.raw;
            }

            // CSA
            if let Some(ref csa) = parsed.csa {
                ap.has_csa = true;
                ap.csa_mode = csa.mode;
                ap.csa_new_channel = csa.new_channel;
                ap.csa_count = csa.count;
            }

            ap.operating_classes = op_classes;

            // RM Enabled Capabilities
            if let Some(ref rm) = parsed.rm_cap {
                ap.has_rm = true;
                ap.rm_link_meas = rm.link_measurement;
                ap.rm_neighbor_report = rm.neighbor_report;
                ap.rm_beacon_passive = rm.beacon_passive;
                ap.rm_beacon_active = rm.beacon_active;
                ap.rm_beacon_table = rm.beacon_table;
            }

            // Multiple BSSID
            if let Some(ref mb) = parsed.multi_bssid {
                ap.has_multi_bssid = true;
                ap.max_bssid_indicator = mb.max_bssid_indicator;
            }

            // Reduced Neighbor Report
            if let Some(ref rnr) = parsed.rnr {
                ap.has_rnr = true;
                ap.rnr_ap_count = rnr.neighbor_count;
            }

            ap.ht_cap_raw = parsed.ht_cap_raw;
            ap.vht_cap_raw = parsed.vht_cap_raw;

            // A-MPDU params from HT Capabilities
            if let Some(ref ht) = parsed.ht_cap {
                ap.ampdu_max_len_exp = ht.ampdu_params & 0x03;
                ap.ampdu_min_spacing = (ht.ampdu_params >> 2) & 0x07;
            }

            // VHT sounding dimensions (bits 16-18 of VHT Cap Info)
            if let Some(ref vht) = parsed.vht_cap {
                ap.vht_sounding_dims = ((vht.vht_cap_info >> 16) & 0x07) as u8;
            }

            // HT Operation (IE 61) fields
            if let Some(ref ht_oper) = parsed.ht_oper {
                ap.has_ht_oper = true;
                ap.ht_oper_primary_ch = ht_oper.primary_channel;
                ap.ht_oper_secondary_offset = ht_oper.secondary_channel_offset;
                ap.ht_oper_sta_ch_width = ht_oper.channel_width;
            }

            // VHT Operation (IE 192) fields
            if let Some(ref vht_oper) = parsed.vht_oper {
                ap.has_vht_oper = true;
                ap.vht_oper_ch_width = vht_oper.channel_width;
                ap.vht_oper_center_seg0 = vht_oper.center_freq_seg0;
                ap.vht_oper_center_seg1 = vht_oper.center_freq_seg1;
            }

            ap.vendor_ie_ouis = parsed.vendor_ouis.clone();
            ap.has_wmm = parsed.has_wmm;
            ap.has_p2p = has_p2p;
            ap.has_hs20 = has_hs20;
            ap.raw_ies = tags.to_vec();
            ap.ie_inventory = build_ie_inventory(&ap.raw_ies);

            // WPS
            if let Some(ref wps) = parsed.wps {
                apply_wps_to_ap(wps, &mut ap);
            }

            aps.insert(bssid, ap);
        }
    });

    // Beacon timing analysis
    store.with_beacon_timing_mut(|timing| {
        let bt = timing
            .entry(bssid)
            .or_insert_with(|| BeaconTiming::new(bssid, bcn_interval));
        bt.record_beacon(tsf);
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Probe Request processing
// ═══════════════════════════════════════════════════════════════════════════════

fn process_probe_req(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    let (sta_mac, ssid, ies) = match &pf.body {
        FrameBody::ProbeReq { sta, ssid, ies } => (*sta, ssid.clone(), ies),
        _ => return,
    };

    let now = Instant::now();

    // Update or insert probe entry (same MAC + same SSID)
    store.with_probes_mut(|probes| {
        let found = probes
            .iter_mut()
            .find(|p| p.sta_mac == sta_mac && p.ssid == ssid);

        if let Some(probe) = found {
            probe.count += 1;
            probe.rssi = pf.rssi;
            probe.last_seen = now;
        } else {
            // Cap probes at MAX_PROBES — evict oldest when full
            if probes.len() >= MAX_PROBES {
                probes.remove(0);
            }
            probes.push(ProbeReq {
                sta_mac,
                ssid: ssid.clone(),
                rssi: pf.rssi,
                channel,
                count: 1,
                first_seen: now,
                last_seen: now,
            });
        }
    });

    // Also track this station (skip multicast MACs)
    if !sta_mac.is_multicast() {
        store.with_stations_mut(|stations| {
            let sta = stations
                .entry(sta_mac)
                .or_insert_with(|| Station::new(sta_mac, now));
            sta.frame_count += 1;
            sta.rssi = pf.rssi;
            sta.last_seen = now;
            sta.last_channel = channel;
            sta.probe_ssid_count += 1;
            sta.last_probe_ssid = ssid;

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

            // Fingerprint from probe request IEs — already parsed
            let mut tag_order = Vec::new();
            for raw_ie in &ies.raw_ies {
                tag_order.push(raw_ie.tag);
            }
            if sta.ie_tag_order.is_empty() {
                sta.ie_tag_order = tag_order;
                sta.ie_tag_count = sta.ie_tag_order.len() as u8;
            }
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Data frame processing — station tracking + EAPOL detection
// ═══════════════════════════════════════════════════════════════════════════════

fn process_data(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    // Extract pre-parsed data frame fields
    let (sta_mac, bssid_mac, direction, payload) = match &pf.body {
        FrameBody::Data {
            sta,
            bssid,
            direction,
            payload,
        } => (*sta, *bssid, *direction, payload),
        _ => return,
    };

    // Skip WDS and IBSS (only ToAp and FromAp are useful for station tracking)
    match direction {
        DataDirection::ToAp | DataDirection::FromAp => {}
        _ => return,
    }

    if sta_mac.is_multicast() {
        return;
    }

    let now = Instant::now();
    let seq_num = pf.seq_num;

    // Track station — all fields from pre-parsed ParsedFrame
    store.with_stations_mut(|stations| {
        let sta = stations
            .entry(sta_mac)
            .or_insert_with(|| Station::new(sta_mac, now));
        sta.bssid = Some(bssid_mac);
        sta.is_associated = true;
        sta.frame_count += 1;
        sta.rssi = pf.rssi;
        if pf.rssi > sta.rssi_best {
            sta.rssi_best = pf.rssi;
        }
        sta.last_channel = channel;
        sta.last_seen = now;
        if pf.raw.len() > 24 {
            sta.data_bytes += (pf.raw.len() - 24) as u64;
        }

        // Sequence number tracking — pre-parsed in ParsedFrame
        if sta.seq_num_first == 0 && sta.frame_count == 1 {
            sta.seq_num_first = seq_num;
        }
        if seq_num != sta.seq_num_last {
            if sta.seq_num_last > 0 {
                let expected = (sta.seq_num_last + 1) & 0x0FFF;
                if seq_num != expected && seq_num != sta.seq_num_last {
                    sta.seq_num_gaps += 1;
                }
            }
            sta.seq_num_last = seq_num;
        }

        // Power save tracking — pre-parsed in ParsedFrame
        if pf.power_mgmt != sta.power_save {
            sta.power_save = pf.power_mgmt;
            sta.power_save_transitions += 1;
        }

        // QoS TID counting — pre-parsed in ParsedFrame
        if pf.is_qos {
            let idx = (pf.qos_tid & 0x07) as usize;
            sta.tid_counts[idx] += 1;
        }
    });

    // Update AP client count
    store.with_aps_mut(|aps| {
        // Count clients from stations table — need read access
        // We'll update the count based on a quick lookup
        if let Some(ap) = aps.get_mut(&bssid_mac) {
            // We can't read stations here (would deadlock), so just
            // note that this station is associated. The actual client_count
            // is computed separately or incrementally.
            // For now, we do a simple increment approach: if this is a new
            // association (not already counted), we bump the count.
            // The full recount happens in stats().
            // Minimal approach: just mark AP as having clients.
            let _ = ap; // AP is updated by beacon processing
        }
    });

    // Update AP client count by reading stations table
    // (We do this outside with_aps_mut to avoid deadlock with stations lock)
    let client_count = {
        let stations = store.get_stations();
        stations
            .values()
            .filter(|s| s.bssid.as_ref() == Some(&bssid_mac) && s.is_associated)
            .count() as u16
    };
    store.with_aps_mut(|aps| {
        if let Some(ap) = aps.get_mut(&bssid_mac) {
            ap.client_count = client_count;
        }
    });

    // EAPOL detection — check for pre-classified EAPOL OR LLC with EAPOL ethertype
    let is_eapol = matches!(
        payload,
        DataPayload::Eapol(_) | DataPayload::Llc { ethertype: 0x888E }
    );

    if is_eapol {
        // Get the raw LLC payload for the capture engine
        let llc_off: usize = if pf.is_qos { 26 } else { 24 };
        if llc_off + 8 <= pf.raw.len() {
            let raw_payload = &pf.raw[llc_off..];

            let ssid = store
                .get_ap(&bssid_mac)
                .map(|ap| ap.ssid.clone())
                .unwrap_or_default();

            let timestamp_us = store.elapsed().as_micros() as u64;

            let events = store.with_capture_db(|db| {
                capture::process_data_payload(db, bssid_mac, sta_mac, &ssid, raw_payload, timestamp_us)
            });

            if !events.is_empty() {
                store.inc_eapol_frame_count();

                // Extract handshake state from capture_db (release lock before updating other tables)
                let hs_state = store.with_capture_db_read(|db| {
                    db.best_handshake(&bssid_mac).map(|hs| {
                        (hs.quality, hs.has_pmkid, hs.has_m1, hs.has_m2, hs.has_m3, hs.has_m4)
                    })
                });

                // Update AP handshake quality (capture_db lock released)
                if let Some((quality, has_pmkid, ..)) = hs_state {
                    store.with_aps_mut(|aps| {
                        if let Some(ap) = aps.get_mut(&bssid_mac) {
                            ap.handshake_quality = quality;
                            ap.has_pmkid = has_pmkid;
                        }
                    });
                }

                // Convert capture events to scan events
                for ev in &events {
                    let (evt_type, detail) = match ev {
                        CaptureEvent::HandshakeMessage { message, .. } => {
                            match message {
                                HandshakeMessage::M1 => (
                                    ScanEventType::EapolM1,
                                    EventDetail::Eapol { message_num: 1 },
                                ),
                                HandshakeMessage::M2 => (
                                    ScanEventType::EapolM2,
                                    EventDetail::Eapol { message_num: 2 },
                                ),
                                HandshakeMessage::M3 => (
                                    ScanEventType::EapolM3,
                                    EventDetail::Eapol { message_num: 3 },
                                ),
                                HandshakeMessage::M4 => (
                                    ScanEventType::EapolM4,
                                    EventDetail::Eapol { message_num: 4 },
                                ),
                                _ => continue,
                            }
                        }
                        CaptureEvent::PmkidCaptured { .. } => {
                            (ScanEventType::PmkidCaptured, EventDetail::Pmkid)
                        }
                        CaptureEvent::HandshakeComplete { quality, .. } => (
                            ScanEventType::HandshakeComplete,
                            EventDetail::HandshakeComplete { quality: *quality },
                        ),
                        CaptureEvent::EapIdentityCaptured { identity, .. } => (
                            ScanEventType::EapIdentity,
                            EventDetail::EapIdentity {
                                identity: identity.clone(),
                            },
                        ),
                        CaptureEvent::EapMethodNegotiated { method, .. } => (
                            ScanEventType::EapMethod,
                            EventDetail::EapMethod {
                                method: method.name().to_string(),
                            },
                        ),
                        CaptureEvent::HandshakeQualityImproved { .. } => continue,
                    };
                    store.push_event(evt_type, bssid_mac, sta_mac, channel, pf.rssi, detail);
                }

                // Update station handshake state (capture_db lock released)
                if let Some((_, _, has_m1, has_m2, has_m3, has_m4)) = hs_state {
                    let msgs = has_m1 as u8 + has_m2 as u8 + has_m3 as u8 + has_m4 as u8;
                    store.update_station(sta_mac, |sta| {
                        sta.handshake_state = msgs;
                    });
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Authentication frame processing
// ═══════════════════════════════════════════════════════════════════════════════

fn process_auth(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    let (source, target, algorithm, seq_num, status) = match &pf.body {
        FrameBody::Auth {
            source,
            target,
            algorithm,
            seq_num,
            status,
            ..
        } => (*source, *target, *algorithm, *seq_num, *status),
        _ => return,
    };

    store.push_event(
        ScanEventType::Auth,
        source,
        target,
        channel,
        pf.rssi,
        EventDetail::Auth {
            algorithm,
            seq_num,
            status,
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Deauthentication frame processing
// ═══════════════════════════════════════════════════════════════════════════════

fn process_deauth(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    let (source, target, reason_code) = match &pf.body {
        FrameBody::Deauth {
            source,
            target,
            reason,
            ..
        } => (*source, *target, *reason),
        _ => return,
    };

    let reason_str = ReasonCode::from_u16(reason_code)
        .map(|r| r.name())
        .unwrap_or("Unknown");

    store.push_event(
        ScanEventType::Deauth,
        source,
        target,
        channel,
        pf.rssi,
        EventDetail::Deauth {
            reason: reason_code,
            reason_str,
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Disassociation frame processing
// ═══════════════════════════════════════════════════════════════════════════════

fn process_disassoc(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    let (source, target, reason_code) = match &pf.body {
        FrameBody::Disassoc {
            source,
            target,
            reason,
            ..
        } => (*source, *target, *reason),
        _ => return,
    };

    let reason_str = ReasonCode::from_u16(reason_code)
        .map(|r| r.name())
        .unwrap_or("Unknown");

    store.push_event(
        ScanEventType::Disassoc,
        source,
        target,
        channel,
        pf.rssi,
        EventDetail::Disassoc {
            reason: reason_code,
            reason_str,
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Association Request processing — station fingerprinting gold mine
// ═══════════════════════════════════════════════════════════════════════════════

fn process_assoc_req(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    let (sta_mac, bssid, listen_interval, ies) = match &pf.body {
        FrameBody::AssocReq {
            sta,
            bssid,
            listen_interval,
            ies,
            ..
        } => (*sta, *bssid, *listen_interval, ies),
        _ => return,
    };

    // SSID from pre-parsed IEs
    let ssid = ies.ssid.clone().unwrap_or_default();

    // Fingerprint the station from its pre-parsed IEs
    if !sta_mac.is_multicast() {
        fingerprint_station_from_ies(store, sta_mac, ies, listen_interval, channel);
    }

    store.push_event(
        ScanEventType::AssocReq,
        sta_mac,
        bssid,
        channel,
        pf.rssi,
        EventDetail::AssocReq {
            ssid,
            listen_interval,
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Association Response processing
// ═══════════════════════════════════════════════════════════════════════════════

fn process_assoc_resp(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    let (sta_mac, bssid, status, aid) = match &pf.body {
        FrameBody::AssocResp {
            sta,
            bssid,
            status,
            aid,
            ..
        } => (*sta, *bssid, *status, *aid),
        FrameBody::ReassocResp {
            sta,
            bssid,
            status,
            aid,
            ..
        } => (*sta, *bssid, *status, *aid),
        _ => return,
    };

    // If status=0 (success), mark station as associated
    if status == 0 && !sta_mac.is_multicast() {
        let now = Instant::now();
        store.update_station(sta_mac, |sta| {
            sta.bssid = Some(bssid);
            sta.is_associated = true;
            sta.last_channel = channel;
            sta.last_seen = now;
        });
    }

    store.push_event(
        ScanEventType::AssocResp,
        bssid,
        sta_mac,
        channel,
        pf.rssi,
        EventDetail::AssocResp { status, aid },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Reassociation Request processing
// ═══════════════════════════════════════════════════════════════════════════════

fn process_reassoc_req(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    let (sta_mac, bssid, current_ap, listen_interval, ies) = match &pf.body {
        FrameBody::ReassocReq {
            sta,
            bssid,
            current_ap,
            listen_interval,
            ies,
            ..
        } => (*sta, *bssid, *current_ap, *listen_interval, ies),
        _ => return,
    };

    let ssid = ies.ssid.clone().unwrap_or_default();

    if !sta_mac.is_multicast() {
        fingerprint_station_from_ies(store, sta_mac, ies, listen_interval, channel);
    }

    store.push_event(
        ScanEventType::ReassocReq,
        sta_mac,
        bssid,
        channel,
        pf.rssi,
        EventDetail::ReassocReq { ssid, current_ap },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Action frame processing — category + action code parsing
// ═══════════════════════════════════════════════════════════════════════════════

fn process_action(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    let (source, target, category, action, action_detail) = match &pf.body {
        FrameBody::Action {
            source,
            target,
            category,
            action,
            detail,
            ..
        } => (*source, *target, *category, *action, detail),
        _ => return,
    };

    // Map pre-parsed ActionDetail to scanner EventDetail
    let (event_type, detail) = match action_detail {
        ActionDetail::SaQuery {
            transaction_id,
            is_request,
        } => {
            let et = if *is_request {
                ScanEventType::SaQueryReq
            } else {
                ScanEventType::SaQueryResp
            };
            (
                et,
                EventDetail::SaQuery {
                    transaction_id: *transaction_id,
                    is_request: *is_request,
                },
            )
        }
        ActionDetail::BssTransition {
            dialog_token,
            is_request,
            ..
        } => {
            let et = if *is_request {
                ScanEventType::BssTransitionReq
            } else {
                ScanEventType::BssTransitionResp
            };
            (
                et,
                EventDetail::BssTransition {
                    action,
                    dialog_token: *dialog_token,
                    status: Some(0),
                    target_bssid: None,
                },
            )
        }
        ActionDetail::FtAction {
            action_code,
            sta_addr,
            target_ap,
            status,
        } => {
            let et = match action_code {
                1 => ScanEventType::FtRequest,
                2 => ScanEventType::FtResponse,
                _ => ScanEventType::ActionOther,
            };
            (
                et,
                EventDetail::FtAction {
                    action: *action_code,
                    sta_addr: *sta_addr,
                    target_ap: *target_ap,
                    status: Some(*status),
                },
            )
        }
        ActionDetail::SpectrumMgmt {
            action_code,
            dialog_token,
        } => (
            ScanEventType::SpectrumAction,
            EventDetail::SpectrumMgmt {
                action: *action_code,
                dialog_token: *dialog_token,
            },
        ),
        ActionDetail::RadioMeasurement {
            action_code,
            dialog_token,
            repetitions,
            ..
        } => {
            let et = if *action_code == 0 {
                ScanEventType::RadioMeasurementReq
            } else {
                ScanEventType::RadioMeasurementResp
            };
            (
                et,
                EventDetail::RadioMeasurement {
                    action: *action_code,
                    dialog_token: *dialog_token,
                    num_repetitions: *repetitions,
                },
            )
        }
        ActionDetail::WnmSleep { is_request } => {
            let et = if *is_request {
                ScanEventType::WnmSleepReq
            } else {
                ScanEventType::WnmSleepResp
            };
            (
                et,
                EventDetail::Action {
                    category,
                    action,
                    category_name: "WNM",
                },
            )
        }
        ActionDetail::Tdls { action_code } => {
            let et = match *action_code {
                0..=2 => ScanEventType::TdlsSetup,
                3 => ScanEventType::TdlsTeardown,
                _ => ScanEventType::ActionOther,
            };
            (
                et,
                EventDetail::Action {
                    category,
                    action,
                    category_name: "TDLS",
                },
            )
        }
        ActionDetail::BlockAck { .. } => (
            ScanEventType::ActionOther,
            EventDetail::Action {
                category,
                action,
                category_name: "BlockAck",
            },
        ),
        ActionDetail::Other {
            category: cat,
            action: act,
        } => {
            let name = match *cat {
                c if c == action_category::QOS => "QoS",
                c if c == action_category::VENDOR_SPECIFIC => "Vendor",
                _ => "Unknown",
            };
            (
                ScanEventType::ActionOther,
                EventDetail::Action {
                    category: *cat,
                    action: *act,
                    category_name: name,
                },
            )
        }
    };

    store.push_event(event_type, source, target, channel, pf.rssi, detail);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Control frame processing — pre-parsed from FrameBody::Control
// ═══════════════════════════════════════════════════════════════════════════════

fn process_control(pf: &ParsedFrame, channel: u8, store: &FrameStore) {
    let detail = match &pf.body {
        FrameBody::Control { detail } => detail,
        _ => return,
    };

    match detail {
        ControlDetail::PsPoll { ta, .. } => {
            if !ta.is_multicast() {
                let now = Instant::now();
                store.update_station(*ta, |sta| {
                    if !sta.power_save {
                        sta.power_save = true;
                        sta.power_save_transitions += 1;
                    }
                    sta.last_seen = now;
                });
            }
        }
        ControlDetail::Rts { ta, ra, .. } => {
            store.push_event(
                ScanEventType::ControlRts,
                *ta,
                *ra,
                channel,
                pf.rssi,
                EventDetail::ControlFrame {
                    subtype_name: "RTS",
                },
            );
        }
        ControlDetail::Cts { ra, .. } => {
            store.push_event(
                ScanEventType::ControlCts,
                *ra,
                *ra,
                channel,
                pf.rssi,
                EventDetail::ControlFrame {
                    subtype_name: "CTS",
                },
            );
        }
        ControlDetail::BlockAckReq { ta, ra, .. } => {
            store.push_event(
                ScanEventType::ControlBlockAckReq,
                *ta,
                *ra,
                channel,
                pf.rssi,
                EventDetail::ControlFrame {
                    subtype_name: "BAR",
                },
            );
        }
        ControlDetail::BlockAck { ta, ra, .. } => {
            store.push_event(
                ScanEventType::ControlBlockAck,
                *ta,
                *ra,
                channel,
                pf.rssi,
                EventDetail::ControlFrame {
                    subtype_name: "BA",
                },
            );
        }
        _ => {} // ACK, CfEnd, Other — no event
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Station fingerprinting from Association Request IEs
// ═══════════════════════════════════════════════════════════════════════════════

fn fingerprint_station_from_ies(
    store: &FrameStore,
    sta_mac: MacAddress,
    parsed: &ParsedIes,
    listen_interval: u16,
    channel: u8,
) {
    let now = Instant::now();
    let wifi_gen = ie::derive_wifi_generation(parsed);

    // Derive station's max bandwidth from its capability IEs
    let has_vht = parsed.vht_cap.is_some();
    let has_ht = parsed.ht_cap.is_some();
    let has_he = parsed.has_he || parsed.he_cap.is_some();

    let sta_bandwidth = if has_vht {
        match parsed.vht_cap.as_ref().map(|v| v.supported_channel_width) {
            Some(1) | Some(2) => Bandwidth::Bw160,
            _ => Bandwidth::Bw80,
        }
    } else if has_ht {
        if parsed.ht_cap.as_ref().map_or(false, |h| h.channel_width_40) {
            Bandwidth::Bw40
        } else {
            Bandwidth::Bw20
        }
    } else {
        Bandwidth::Bw20
    };

    let max_rate_mbps = compute_max_rate_mbps(wifi_gen, parsed.max_nss, sta_bandwidth);

    // Supported rates
    let mut rates = parsed.supported_rates.clone();
    rates.extend_from_slice(&parsed.extended_rates);

    // IE tag order fingerprint
    let mut tag_order = Vec::new();
    for raw_ie in &parsed.raw_ies {
        tag_order.push(raw_ie.tag);
    }
    let ie_tag_count = tag_order.len() as u8;

    // HT cap fields
    let ht_cap_raw = parsed.ht_cap_raw;
    let vht_cap_raw = parsed.vht_cap_raw;
    let max_nss = parsed.max_nss;
    let ampdu_max_len_exp = parsed
        .ht_cap
        .as_ref()
        .map(|ht| ht.ampdu_params & 0x03)
        .unwrap_or(0);
    let ampdu_min_spacing = parsed
        .ht_cap
        .as_ref()
        .map(|ht| (ht.ampdu_params >> 2) & 0x07)
        .unwrap_or(0);

    store.update_station(sta_mac, |sta| {
        sta.last_seen = now;
        sta.last_channel = channel;
        sta.listen_interval = listen_interval;
        sta.ie_tag_order = tag_order;
        sta.ie_tag_count = ie_tag_count;
        sta.supported_rates = rates;
        sta.has_ht = has_ht;
        sta.ht_cap_raw = ht_cap_raw;
        sta.has_vht = has_vht;
        sta.vht_cap_raw = vht_cap_raw;
        sta.has_he = has_he;
        sta.wifi_gen = wifi_gen;
        sta.max_nss = max_nss;
        sta.max_rate_mbps = max_rate_mbps;
        sta.ampdu_max_len_exp = ampdu_max_len_exp;
        sta.ampdu_min_spacing = ampdu_min_spacing;
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Max rate estimation
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute maximum theoretical data rate in Mbps based on WiFi generation,
/// spatial streams, and channel bandwidth.
///
/// Rates are for the highest MCS index with short GI:
/// - WiFi 4 (HT):  MCS7  — 72.2/stream @20MHz, 150/stream @40MHz
/// - WiFi 5 (VHT): MCS9  — 96/stream @20MHz, 200 @40MHz, 433.3 @80MHz, 866.7 @160MHz
/// - WiFi 6 (HE):  MCS11 — 143.4/stream @20MHz, 286.8 @40MHz, 600.4 @80MHz, 1201 @160MHz
/// - Legacy (a/b/g): 54 Mbps max (no spatial streams or bandwidth scaling)
fn compute_max_rate_mbps(wifi_gen: WifiGeneration, max_nss: u8, bandwidth: Bandwidth) -> u16 {
    let nss = max_nss.max(1) as f64;

    let rate_per_stream = match wifi_gen {
        WifiGeneration::Wifi4 => match bandwidth {
            Bandwidth::Bw20 => 72.2,
            Bandwidth::Bw40 | Bandwidth::Bw80 | Bandwidth::Bw160 => 150.0,
        },
        WifiGeneration::Wifi5 => match bandwidth {
            Bandwidth::Bw20 => 96.0,
            Bandwidth::Bw40 => 200.0,
            Bandwidth::Bw80 => 433.3,
            Bandwidth::Bw160 => 866.7,
        },
        WifiGeneration::Wifi6 | WifiGeneration::Wifi6e | WifiGeneration::Wifi7 => match bandwidth {
            Bandwidth::Bw20 => 143.4,
            Bandwidth::Bw40 => 286.8,
            Bandwidth::Bw80 => 600.4,
            Bandwidth::Bw160 => 1201.0,
        },
        WifiGeneration::Legacy => return 54,
    };

    (nss * rate_per_stream) as u16
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper functions
// ═══════════════════════════════════════════════════════════════════════════════

/// Apply parsed WPS info from ie::WpsInfo to an Ap struct.
fn apply_wps_to_ap(wps: &ie::WpsInfo, ap: &mut Ap) {
    ap.wps_state = match wps.state {
        ie::WpsState::Configured => WpsState::Configured,
        ie::WpsState::NotConfigured => WpsState::NotConfigured,
        ie::WpsState::None => WpsState::None,
    };
    ap.wps_locked = wps.locked;
    ap.wps_version = wps.version;
    if !wps.device_name.is_empty() {
        ap.wps_device_name = wps.device_name.clone();
    }
    if !wps.model_name.is_empty() {
        ap.wps_model = wps.model_name.clone();
    }
}
