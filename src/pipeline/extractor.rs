//! Frame extractor — converts ParsedFrames into StoreUpdate deltas.
//!
//! Called by the pipeline thread for every successfully parsed frame.
//! This is where beacons become AP entries, data frames become station
//! associations, and EAPOL frames become handshake progress.
//!
//! The sole frame processing path is:
//!   extract_frame() → Vec<StoreUpdate> → store.apply() + broadcast

use crate::core::parsed_frame::{
    ActionDetail, ControlDetail, DataDirection, DataPayload, FrameBody, ParsedFrame,
};
use crate::core::{Bandwidth, MacAddress};
use crate::core::channel::Channel;
use crate::engine::capture::{self, CaptureEvent};
use crate::protocol::eapol::HandshakeMessage;
use crate::protocol::ie::{self, ParsedIes};
use crate::protocol::ieee80211::{
    action_category, frame_subtype, frame_type, ie_tag, ReasonCode, Security, WifiGeneration,
    BEACON_TAGS_OFFSET,
};
use crate::store::{
    build_ie_inventory, EventDetail, FrameStore, ScanEventType, WpsState,
};
use crate::store::update::{self, StoreUpdate, FrameAccountingDelta};
use crate::util::oui::oui_lookup;

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_frame — the sole frame processing entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Extract semantic deltas from a parsed frame.
///
/// Reads the current FrameStore state to determine what changed, and returns
/// a Vec<StoreUpdate> describing every mutation.
///
/// The pipeline thread calls this for every frame, then:
///   store.apply(&deltas)  — applies mutations to the FrameStore
///   broadcast(deltas)     — sends to all update subscribers
///
/// This is the sole frame processing path. Must be fast —
/// the pipeline thread processes frames at 300+ fps.
pub fn extract_frame(pf: &ParsedFrame, channel: u8, band: u8, store: &FrameStore) -> Vec<StoreUpdate> {
    // Unparseable frames produce no deltas
    if matches!(&pf.body, FrameBody::Unparseable { .. }) {
        return vec![StoreUpdate::FrameCounted {
            frame_count: store.frame_count(),
            eapol_frame_count: store.eapol_frame_count(),
            accounting: FrameAccountingDelta::Unparseable,
        }];
    }

    let mut deltas = Vec::with_capacity(4);

    // ── Frame accounting delta ──
    let accounting = match &pf.body {
        FrameBody::Beacon { .. } => FrameAccountingDelta::Beacon,
        FrameBody::ProbeReq { .. } => FrameAccountingDelta::ProbeReq,
        FrameBody::Auth { .. } => FrameAccountingDelta::Auth,
        FrameBody::Deauth { .. } => FrameAccountingDelta::Deauth,
        FrameBody::Disassoc { .. } => FrameAccountingDelta::Disassoc,
        FrameBody::AssocReq { .. } => FrameAccountingDelta::AssocReq,
        FrameBody::AssocResp { .. } => FrameAccountingDelta::AssocResp,
        FrameBody::ReassocReq { .. } => FrameAccountingDelta::ReassocReq,
        FrameBody::ReassocResp { .. } => FrameAccountingDelta::ReassocResp,
        FrameBody::Action { .. } => FrameAccountingDelta::Action,
        FrameBody::Data { payload, .. } => match payload {
            DataPayload::Eapol(_) => FrameAccountingDelta::DataEapol,
            DataPayload::Null => FrameAccountingDelta::DataNull,
            DataPayload::Encrypted => FrameAccountingDelta::DataEncrypted,
            DataPayload::Llc { ethertype } if *ethertype == 0x888E => {
                FrameAccountingDelta::DataLlcEapolUnparsed
            }
            DataPayload::Llc { .. } => FrameAccountingDelta::DataLlc,
            DataPayload::Other => FrameAccountingDelta::DataOther,
        },
        FrameBody::Control { detail } => match detail {
            ControlDetail::Rts { .. } => FrameAccountingDelta::CtrlRts,
            ControlDetail::Cts { .. } => FrameAccountingDelta::CtrlCts,
            ControlDetail::Ack { .. } => FrameAccountingDelta::CtrlAck,
            ControlDetail::BlockAckReq { .. } => FrameAccountingDelta::CtrlBar,
            ControlDetail::BlockAck { .. } => FrameAccountingDelta::CtrlBa,
            ControlDetail::PsPoll { .. } => FrameAccountingDelta::CtrlPsPoll,
            _ => FrameAccountingDelta::CtrlOther,
        },
        FrameBody::Unparseable { .. } => FrameAccountingDelta::Unparseable,
    };

    deltas.push(StoreUpdate::FrameCounted {
        frame_count: store.frame_count() + 1,
        eapol_frame_count: store.eapol_frame_count(),
        accounting,
    });

    // ── Channel stats delta ──
    let key = crate::store::stats::channel_key(channel, band);
    let (ch_frame_count, ch_retry_count) = store.with_channel_stats_read(|stats| {
        stats.get(&key).map(|cs| (cs.frame_count + 1, cs.retry_count + if pf.retry { 1 } else { 0 }))
            .unwrap_or((1, if pf.retry { 1 } else { 0 }))
    });
    deltas.push(StoreUpdate::ChannelFrameCounted {
        channel,
        band,
        frame_count: ch_frame_count,
        retry_count: ch_retry_count,
    });

    // ── Frame-type specific deltas ──
    let ftype = pf.frame_type;
    let subtype = pf.frame_subtype;

    match (ftype, subtype) {
        (frame_type::MANAGEMENT, frame_subtype::BEACON)
        | (frame_type::MANAGEMENT, frame_subtype::PROBE_RESP) => {
            extract_beacon(pf, channel, store, &mut deltas);
        }
        (frame_type::MANAGEMENT, frame_subtype::PROBE_REQ) => {
            extract_probe_req(pf, channel, store, &mut deltas);
        }
        (frame_type::MANAGEMENT, frame_subtype::AUTH) => {
            extract_auth(pf, channel, store, &mut deltas);
        }
        (frame_type::MANAGEMENT, frame_subtype::DEAUTH) => {
            extract_deauth(pf, channel, store, &mut deltas);
        }
        (frame_type::MANAGEMENT, frame_subtype::ASSOC_REQ) => {
            extract_assoc_req(pf, channel, store, &mut deltas);
        }
        (frame_type::MANAGEMENT, frame_subtype::ASSOC_RESP) => {
            extract_assoc_resp(pf, channel, store, &mut deltas);
        }
        (frame_type::MANAGEMENT, frame_subtype::REASSOC_REQ) => {
            extract_reassoc_req(pf, channel, store, &mut deltas);
        }
        (frame_type::MANAGEMENT, frame_subtype::REASSOC_RESP) => {
            extract_assoc_resp(pf, channel, store, &mut deltas);
        }
        (frame_type::MANAGEMENT, frame_subtype::DISASSOC) => {
            extract_disassoc(pf, channel, store, &mut deltas);
        }
        (frame_type::MANAGEMENT, frame_subtype::ACTION)
        | (frame_type::MANAGEMENT, frame_subtype::ACTION_NO_ACK) => {
            extract_action(pf, channel, store, &mut deltas);
        }
        (frame_type::DATA, _) => {
            extract_data(pf, channel, store, &mut deltas);
        }
        (frame_type::CONTROL, _) => {
            extract_control(pf, channel, store, &mut deltas);
        }
        _ => {}
    }

    deltas
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


/// Convert ie::WpsInfo to update::WpsInfo for delta emission.
fn wps_to_delta(wps: &ie::WpsInfo) -> update::WpsInfo {
    update::WpsInfo {
        state: match wps.state {
            ie::WpsState::Configured => WpsState::Configured,
            ie::WpsState::NotConfigured => WpsState::NotConfigured,
            ie::WpsState::None => WpsState::None,
        },
        locked: wps.locked,
        version: wps.version,
        device_name: wps.device_name.clone(),
        model: wps.model_name.clone(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_beacon — ApDiscovered / ApBeaconUpdate / BeaconTimingUpdate
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_beacon(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (bssid, tsf, bcn_interval, capability, privacy, parsed) = match &pf.body {
        FrameBody::Beacon {
            bssid, tsf, beacon_interval, capability, privacy, ies,
        } => (*bssid, *tsf, *beacon_interval, *capability, *privacy, ies),
        _ => return,
    };

    let tags = if pf.raw.len() > BEACON_TAGS_OFFSET {
        &pf.raw[BEACON_TAGS_OFFSET..]
    } else {
        return;
    };

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

    // Security
    let security = if let Some(ref rsn) = parsed.rsn {
        rsn.security
    } else if parsed.wpa.is_some() {
        Security::Wpa
    } else if privacy {
        Security::Wep
    } else {
        Security::Open
    };

    let wifi_gen = ie::derive_wifi_generation(parsed);

    // Bandwidth
    let mut bandwidth = Bandwidth::Bw20;
    if let Some(ref ht) = parsed.ht_cap {
        if ht.channel_width_40 { bandwidth = Bandwidth::Bw40; }
    }
    if let Some(ref vht) = parsed.vht_cap {
        if vht.supported_channel_width >= 2 { bandwidth = Bandwidth::Bw160; }
        else if vht.supported_channel_width >= 1 { bandwidth = Bandwidth::Bw80; }
    }
    if let Some(ref vht_oper) = parsed.vht_oper {
        if vht_oper.channel_width >= 2 { bandwidth = Bandwidth::Bw160; }
        else if vht_oper.channel_width >= 1 { bandwidth = Bandwidth::Bw80; }
    }

    let ap_channel = parsed.ds.as_ref().map(|ds| ds.channel).unwrap_or(channel);
    let freq_mhz = Channel::new(ap_channel).center_freq_mhz;

    // Channel center frequency
    let base_freq = freq_mhz;
    let mut center_freq = base_freq;
    if let Some(ref ht_oper) = parsed.ht_oper {
        match ht_oper.secondary_channel_offset {
            1 => center_freq = base_freq + 10,
            3 => center_freq = base_freq.saturating_sub(10),
            0 => bandwidth = Bandwidth::Bw20,
            _ => {}
        }
    }
    if let Some(ref vht_oper) = parsed.vht_oper {
        if vht_oper.channel_width > 0 && vht_oper.center_freq_seg0 > 0 {
            let seg0_ch = vht_oper.center_freq_seg0 as u16;
            center_freq = if seg0_ch <= 14 { 2407 + seg0_ch * 5 } else { 5000 + seg0_ch * 5 };
        }
    }
    let channel_center = center_freq;

    let mut rates = parsed.supported_rates.clone();
    rates.extend_from_slice(&parsed.extended_rates);

    // Mesh
    let mut is_mesh = false;
    let mut mesh_id = String::new();
    for rec in &parsed.raw_ies {
        if rec.tag == 114 {
            is_mesh = true;
            if !rec.data.is_empty() { mesh_id = String::from_utf8_lossy(&rec.data).to_string(); }
            break;
        }
    }

    // Operating Classes
    let mut op_classes: Vec<u8> = Vec::new();
    for rec in &parsed.raw_ies {
        if rec.tag == 59 && !rec.data.is_empty() {
            op_classes = rec.data[..rec.data.len().min(16)].to_vec();
            break;
        }
    }

    // P2P and HS2.0
    let mut has_p2p = false;
    let mut has_hs20 = false;
    for rec in &parsed.raw_ies {
        if rec.tag == ie_tag::VENDOR_SPECIFIC && rec.data.len() >= 4 {
            let oui = [rec.data[0], rec.data[1], rec.data[2]];
            if oui == [0x50, 0x6F, 0x9A] {
                if rec.data[3] == 0x09 { has_p2p = true; }
                if rec.data[3] == 0x10 { has_hs20 = true; }
            }
        }
    }

    let max_rate_mbps = compute_max_rate_mbps(wifi_gen, parsed.max_nss, bandwidth);
    let start_time_elapsed = store.elapsed();

    // Check if AP exists to decide ApDiscovered vs ApBeaconUpdate
    let ap_exists = store.get_ap(&bssid).is_some();

    if ap_exists {
        // ── ApBeaconUpdate ──
        let rssi_valid = pf.rssi != 0;

        // Check if raw IEs changed
        let ies_changed = store.get_ap(&bssid).and_then(|ap| {
            if ap.raw_ies.len() != tags.len() || ap.raw_ies != tags {
                Some(update::IesChanged {
                    raw_ies: tags.to_vec(),
                    ie_inventory: build_ie_inventory(tags),
                })
            } else {
                None
            }
        });

        // Check hidden SSID reveal
        let existing_hidden = store.get_ap(&bssid).map(|ap| ap.is_hidden).unwrap_or(false);
        if !hidden && !ssid.is_empty() && existing_hidden {
            deltas.push(StoreUpdate::ApSsidRevealed {
                bssid,
                ssid: ssid.clone(),
                ssid_raw: ssid_raw.clone(),
            });
        }

        let beacon_count = store.get_ap(&bssid).map(|ap| ap.beacon_count + 1).unwrap_or(1);

        deltas.push(StoreUpdate::ApBeaconUpdate {
            bssid,
            rssi: if rssi_valid { Some(pf.rssi) } else { None },
            rssi_sample: if rssi_valid { Some((start_time_elapsed, pf.rssi)) } else { None },
            channel: ap_channel,
            freq_mhz,
            tsf,
            beacon_count,
            security,
            rsn: parsed.rsn.clone(),
            bandwidth,
            wifi_gen,
            channel_center,
            max_nss: parsed.max_nss,
            max_rate_mbps,
            qbss: parsed.bss_load.as_ref().map(|bl| update::QbssInfo {
                station_count: bl.station_count,
                utilization: bl.channel_utilization,
                admission_cap: bl.admission_capacity,
            }),
            dtim_count: parsed.tim.as_ref().map(|t| t.dtim_count),
            csa: parsed.csa.as_ref().map(|c| update::CsaInfo {
                mode: c.mode, new_channel: c.new_channel, count: c.count,
            }),
            ies_changed,
            wps: parsed.wps.as_ref().map(|w| wps_to_delta(w)),
        });
    } else {
        // ── ApDiscovered ──
        deltas.push(StoreUpdate::ApDiscovered {
            bssid,
            ssid: ssid.clone(),
            ssid_raw: ssid_raw.clone(),
            is_hidden: hidden,
            rssi: pf.rssi,
            channel: ap_channel,
            channel_center,
            bandwidth,
            wifi_gen,
            freq_mhz,
            max_nss: parsed.max_nss,
            max_rate_mbps,
            security,
            rsn: parsed.rsn.clone(),
            beacon_interval: bcn_interval,
            capability,
            tsf,
            country: parsed.country_code,
            vendor: oui_lookup(bssid.as_bytes()).to_string(),
            qbss: parsed.bss_load.as_ref().map(|bl| update::QbssInfo {
                station_count: bl.station_count,
                utilization: bl.channel_utilization,
                admission_cap: bl.admission_capacity,
            }),
            tim: parsed.tim.as_ref().map(|t| update::TimInfo {
                dtim_period: t.dtim_period, dtim_count: t.dtim_count,
            }),
            supported_rates: rates,
            ft: parsed.mobility_domain.as_ref().map(|md| update::FtInfo {
                mdid: md.mdid, over_ds: md.ft_over_ds,
            }),
            ext_cap: parsed.ext_cap.as_ref().map(|ext| update::ExtCapInfo {
                bss_transition: ext.bss_transition,
                wnm_sleep: ext.wnm_sleep,
                tfs: ext.tfs,
                proxy_arp: ext.proxy_arp,
                fms: ext.fms,
                tim_broadcast: ext.tim_broadcast,
                interworking: ext.interworking,
                tdls: ext.tdls_support && !ext.tdls_prohibited,
            }),
            erp: parsed.erp.as_ref().map(|e| update::ErpInfo {
                use_protection: e.use_protection, barker_preamble: e.barker_preamble,
            }),
            he_oper: parsed.he_oper.as_ref().map(|he| update::HeOperInfo {
                bss_color: he.bss_color, default_pe_dur: he.default_pe_dur, twt_required: he.twt_required,
            }),
            interworking: parsed.interworking_ie.as_ref().map(|iw| update::InterworkingInfo {
                access_network_type: iw.access_network_type, internet: iw.internet,
            }),
            mesh: if is_mesh { Some(update::MeshInfo { mesh_id }) } else { None },
            ds_channel: parsed.ds.as_ref().map(|ds| ds.channel),
            qos_info: parsed.qos.as_ref().map(|q| q.raw),
            csa: parsed.csa.as_ref().map(|c| update::CsaInfo {
                mode: c.mode, new_channel: c.new_channel, count: c.count,
            }),
            operating_classes: op_classes,
            rm: parsed.rm_cap.as_ref().map(|rm| update::RmCapInfo {
                link_meas: rm.link_measurement,
                neighbor_report: rm.neighbor_report,
                beacon_passive: rm.beacon_passive,
                beacon_active: rm.beacon_active,
                beacon_table: rm.beacon_table,
            }),
            multi_bssid: parsed.multi_bssid.as_ref().map(|mb| update::MultiBssidInfo {
                max_bssid_indicator: mb.max_bssid_indicator,
            }),
            rnr: parsed.rnr.as_ref().map(|r| update::RnrInfo { ap_count: r.neighbor_count }),
            ht_cap_raw: parsed.ht_cap_raw,
            vht_cap_raw: parsed.vht_cap_raw,
            ampdu_max_len_exp: parsed.ht_cap.as_ref().map(|ht| ht.ampdu_params & 0x03).unwrap_or(0),
            ampdu_min_spacing: parsed.ht_cap.as_ref().map(|ht| (ht.ampdu_params >> 2) & 0x07).unwrap_or(0),
            vht_sounding_dims: parsed.vht_cap.as_ref().map(|v| ((v.vht_cap_info >> 16) & 0x07) as u8).unwrap_or(0),
            ht_oper: parsed.ht_oper.as_ref().map(|ho| update::HtOperInfo {
                primary_ch: ho.primary_channel,
                secondary_offset: ho.secondary_channel_offset,
                sta_ch_width: ho.channel_width,
            }),
            vht_oper: parsed.vht_oper.as_ref().map(|vo| update::VhtOperInfo {
                ch_width: vo.channel_width,
                center_seg0: vo.center_freq_seg0,
                center_seg1: vo.center_freq_seg1,
            }),
            vendor_ie_ouis: parsed.vendor_ouis.clone(),
            has_wmm: parsed.has_wmm,
            has_p2p,
            has_hs20,
            wps: parsed.wps.as_ref().map(|w| wps_to_delta(w)),
            raw_ies: tags.to_vec(),
            ie_inventory: build_ie_inventory(tags),
        });
    }

    // Beacon timing
    let bt_update = store.get_beacon_timing().get(&bssid).map(|bt| {
        StoreUpdate::BeaconTimingUpdate {
            bssid,
            measured_mean: bt.measured_mean,
            jitter_stddev: bt.jitter_stddev,
            beacon_loss_count: bt.beacon_loss_count,
            beacon_loss_rate: bt.beacon_loss_rate,
            tsf_drift_ppm: bt.tsf_drift_ppm,
            tsf_jumps: bt.tsf_jumps,
            samples: bt.samples + 1,
        }
    });
    // For new APs, emit initial timing with sample count 1
    deltas.push(bt_update.unwrap_or(StoreUpdate::BeaconTimingUpdate {
        bssid,
        measured_mean: std::time::Duration::ZERO,
        jitter_stddev: 0.0,
        beacon_loss_count: 0,
        beacon_loss_rate: 0.0,
        tsf_drift_ppm: 0.0,
        tsf_jumps: 0,
        samples: 1,
    }));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_probe_req — ProbeDiscovered/Updated + StationProbeUpdate
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_probe_req(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (sta_mac, ssid, _ies) = match &pf.body {
        FrameBody::ProbeReq { sta, ssid, ies } => (*sta, ssid.clone(), ies),
        _ => return,
    };

    // Probe entry: check if (mac, ssid) pair exists
    let existing_probe = store.get_probes().iter()
        .find(|p| p.sta_mac == sta_mac && p.ssid == ssid)
        .map(|p| p.count);

    if let Some(count) = existing_probe {
        deltas.push(StoreUpdate::ProbeUpdated {
            sta_mac, ssid: ssid.clone(), rssi: pf.rssi, count: count + 1,
        });
    } else {
        deltas.push(StoreUpdate::ProbeDiscovered {
            sta_mac, ssid: ssid.clone(), rssi: pf.rssi, channel,
        });
    }

    // Station tracking
    if !sta_mac.is_multicast() {
        let sta_exists = store.get_station(&sta_mac).is_some();
        if !sta_exists {
            deltas.push(StoreUpdate::StationDiscovered {
                mac: sta_mac,
                vendor: oui_lookup(sta_mac.as_bytes()).to_string(),
                is_randomized: sta_mac.as_bytes()[0] & 0x02 != 0,
                channel,
                rssi: pf.rssi,
            });
        }

        let sta = store.get_station(&sta_mac);
        let probe_ssid_count = sta.as_ref().map(|s| s.probe_ssid_count + 1).unwrap_or(1);
        let avg_probe_interval_ms = sta.as_ref().map(|s| s.avg_probe_interval_ms).unwrap_or(0);

        deltas.push(StoreUpdate::StationProbeUpdate {
            mac: sta_mac,
            rssi: if pf.rssi != 0 { Some(pf.rssi) } else { None },
            channel,
            probe_ssid: ssid,
            probe_ssid_count,
            avg_probe_interval_ms,
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_data — StationDataUpdate + ApClientCountChanged + EAPOL capture
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_data(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (sta_mac, bssid_mac, direction, payload) = match &pf.body {
        FrameBody::Data { sta, bssid, direction, payload } => (*sta, *bssid, *direction, payload),
        _ => return,
    };

    match direction {
        DataDirection::ToAp | DataDirection::FromAp => {}
        _ => return,
    }

    if sta_mac.is_multicast() { return; }

    let seq_num = pf.seq_num;
    let sta = store.get_station(&sta_mac);
    let sta_exists = sta.is_some();

    if !sta_exists {
        deltas.push(StoreUpdate::StationDiscovered {
            mac: sta_mac,
            vendor: oui_lookup(sta_mac.as_bytes()).to_string(),
            is_randomized: sta_mac.as_bytes()[0] & 0x02 != 0,
            channel,
            rssi: pf.rssi,
        });
    }

    // Association (data frame implies association)
    let was_associated = sta.as_ref().map(|s| s.is_associated).unwrap_or(false);
    if !was_associated {
        deltas.push(StoreUpdate::StationAssociated {
            mac: sta_mac, bssid: bssid_mac, channel,
        });
    }

    // Sequence gap detection
    let seq_gap = if let Some(ref s) = sta {
        if s.seq_num_last > 0 {
            let expected = (s.seq_num_last + 1) & 0x0FFF;
            seq_num != expected && seq_num != s.seq_num_last
        } else { false }
    } else { false };

    // Power save change
    let prev_ps = sta.as_ref().map(|s| s.power_save).unwrap_or(false);
    let ps_changed = pf.power_mgmt != prev_ps;

    let frame_count = sta.as_ref().map(|s| s.frame_count + 1).unwrap_or(1);
    let data_bytes_add = if pf.raw.len() > 24 { (pf.raw.len() - 24) as u64 } else { 0 };
    let data_bytes = sta.as_ref().map(|s| s.data_bytes + data_bytes_add).unwrap_or(data_bytes_add);

    deltas.push(StoreUpdate::StationDataUpdate {
        mac: sta_mac,
        bssid: bssid_mac,
        rssi: if pf.rssi != 0 { Some(pf.rssi) } else { None },
        channel,
        frame_count,
        data_bytes,
        seq_num,
        seq_gap,
        power_save: pf.power_mgmt,
        power_save_changed: ps_changed,
        qos_tid: if pf.is_qos { Some(pf.qos_tid & 0x07) } else { None },
    });

    // Client count update for the AP
    // Count from current station table + this new association
    let client_count = {
        let stations = store.get_stations();
        let mut count = stations.values()
            .filter(|s| s.bssid.as_ref() == Some(&bssid_mac) && s.is_associated)
            .count() as u16;
        // If this station wasn't previously associated, add 1
        if !was_associated { count += 1; }
        count
    };
    deltas.push(StoreUpdate::ApClientCountChanged {
        bssid: bssid_mac, client_count,
    });

    // EAPOL detection
    let is_eapol = matches!(
        payload,
        DataPayload::Eapol(_) | DataPayload::Llc { ethertype: 0x888E }
    );

    if is_eapol {
        let htc_len: usize = if pf.is_qos && pf.order { 4 } else { 0 };
        let llc_off: usize = if pf.is_qos { 26 + htc_len } else { 24 };
        if llc_off + 8 <= pf.raw.len() {
            let raw_payload = &pf.raw[llc_off..];
            let ssid = store.get_ap(&bssid_mac).map(|ap| ap.ssid.clone()).unwrap_or_default();
            let timestamp_us = store.elapsed().as_micros() as u64;

            let events = store.with_capture_db(|db| {
                capture::process_data_payload(db, bssid_mac, sta_mac, &ssid, raw_payload, timestamp_us)
            });

            if !events.is_empty() {
                // Convert CaptureEvents to StoreUpdate deltas
                for ev in &events {
                    match ev {
                        CaptureEvent::HandshakeMessage { ap_mac, sta_mac, message, quality } => {
                            deltas.push(StoreUpdate::EapolMessage {
                                ap_mac: *ap_mac, sta_mac: *sta_mac,
                                message: *message, quality: *quality,
                            });
                            // Also emit ScanEvent for backward compat
                            let (evt_type, detail) = match message {
                                HandshakeMessage::M1 => (ScanEventType::EapolM1, EventDetail::Eapol { message_num: 1 }),
                                HandshakeMessage::M2 => (ScanEventType::EapolM2, EventDetail::Eapol { message_num: 2 }),
                                HandshakeMessage::M3 => (ScanEventType::EapolM3, EventDetail::Eapol { message_num: 3 }),
                                HandshakeMessage::M4 => (ScanEventType::EapolM4, EventDetail::Eapol { message_num: 4 }),
                                _ => continue,
                            };
                            let seq = store.event_seq();
                            deltas.push(StoreUpdate::ScanEvent {
                                seq, event_type: evt_type, source: bssid_mac, target: *sta_mac,
                                channel, rssi: pf.rssi, detail,
                            });
                        }
                        CaptureEvent::PmkidCaptured { ap_mac, sta_mac, pmkid } => {
                            deltas.push(StoreUpdate::PmkidCaptured {
                                ap_mac: *ap_mac, sta_mac: *sta_mac, pmkid: *pmkid,
                            });
                            let seq = store.event_seq();
                            deltas.push(StoreUpdate::ScanEvent {
                                seq, event_type: ScanEventType::PmkidCaptured,
                                source: bssid_mac, target: *sta_mac, channel, rssi: pf.rssi,
                                detail: EventDetail::Pmkid,
                            });
                        }
                        CaptureEvent::HandshakeComplete { ap_mac, sta_mac, quality } => {
                            deltas.push(StoreUpdate::HandshakeComplete {
                                ap_mac: *ap_mac, sta_mac: *sta_mac, quality: *quality,
                            });
                            let seq = store.event_seq();
                            deltas.push(StoreUpdate::ScanEvent {
                                seq, event_type: ScanEventType::HandshakeComplete,
                                source: bssid_mac, target: *sta_mac, channel, rssi: pf.rssi,
                                detail: EventDetail::HandshakeComplete { quality: *quality },
                            });
                        }
                        CaptureEvent::HandshakeQualityImproved { ap_mac, sta_mac, old_quality, new_quality } => {
                            deltas.push(StoreUpdate::HandshakeQualityImproved {
                                ap_mac: *ap_mac, sta_mac: *sta_mac,
                                old_quality: *old_quality, new_quality: *new_quality,
                            });
                        }
                        CaptureEvent::EapIdentityCaptured { sta_mac, identity } => {
                            deltas.push(StoreUpdate::EapIdentityCaptured {
                                sta_mac: *sta_mac, identity: identity.clone(),
                            });
                            let seq = store.event_seq();
                            deltas.push(StoreUpdate::ScanEvent {
                                seq, event_type: ScanEventType::EapIdentity,
                                source: bssid_mac, target: *sta_mac, channel, rssi: pf.rssi,
                                detail: EventDetail::EapIdentity { identity: identity.clone() },
                            });
                        }
                        CaptureEvent::EapMethodNegotiated { ap_mac, sta_mac, method } => {
                            deltas.push(StoreUpdate::EapMethodNegotiated {
                                ap_mac: *ap_mac, sta_mac: *sta_mac, method: method.name().to_string(),
                            });
                            let seq = store.event_seq();
                            deltas.push(StoreUpdate::ScanEvent {
                                seq, event_type: ScanEventType::EapMethod,
                                source: bssid_mac, target: *sta_mac, channel, rssi: pf.rssi,
                                detail: EventDetail::EapMethod { method: method.name().to_string() },
                            });
                        }
                    }
                }

                // AP capture state
                let hs_state = store.with_capture_db_read(|db| {
                    db.best_handshake(&bssid_mac).map(|hs| (hs.quality, hs.has_pmkid))
                });
                if let Some((quality, has_pmkid)) = hs_state {
                    deltas.push(StoreUpdate::ApCaptureStateChanged {
                        bssid: bssid_mac, handshake_quality: quality, has_pmkid,
                    });
                }

                // Station handshake progress
                let hs_msgs = store.with_capture_db_read(|db| {
                    db.best_handshake(&bssid_mac).map(|hs| {
                        hs.has_m1 as u8 + hs.has_m2 as u8 + hs.has_m3 as u8 + hs.has_m4 as u8
                    })
                });
                if let Some(msgs) = hs_msgs {
                    deltas.push(StoreUpdate::StationHandshakeProgress {
                        mac: sta_mac, messages_captured: msgs,
                    });
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_auth — ScanEvent
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_auth(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (source, target, algorithm, seq_num, status) = match &pf.body {
        FrameBody::Auth { source, target, algorithm, seq_num, status, .. } =>
            (*source, *target, *algorithm, *seq_num, *status),
        _ => return,
    };
    let seq = store.event_seq();
    deltas.push(StoreUpdate::ScanEvent {
        seq, event_type: ScanEventType::Auth, source, target, channel, rssi: pf.rssi,
        detail: EventDetail::Auth { algorithm, seq_num, status },
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_deauth — ScanEvent
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_deauth(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (source, target, reason_code) = match &pf.body {
        FrameBody::Deauth { source, target, reason, .. } => (*source, *target, *reason),
        _ => return,
    };
    let reason_str = ReasonCode::from_u16(reason_code).map(|r| r.name()).unwrap_or("Unknown");
    let seq = store.event_seq();
    deltas.push(StoreUpdate::ScanEvent {
        seq, event_type: ScanEventType::Deauth, source, target, channel, rssi: pf.rssi,
        detail: EventDetail::Deauth { reason: reason_code, reason_str },
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_disassoc — ScanEvent
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_disassoc(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (source, target, reason_code) = match &pf.body {
        FrameBody::Disassoc { source, target, reason, .. } => (*source, *target, *reason),
        _ => return,
    };
    let reason_str = ReasonCode::from_u16(reason_code).map(|r| r.name()).unwrap_or("Unknown");
    let seq = store.event_seq();
    deltas.push(StoreUpdate::ScanEvent {
        seq, event_type: ScanEventType::Disassoc, source, target, channel, rssi: pf.rssi,
        detail: EventDetail::Disassoc { reason: reason_code, reason_str },
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_assoc_req — StationFingerprinted + ScanEvent
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_assoc_req(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (sta_mac, bssid, listen_interval, ies) = match &pf.body {
        FrameBody::AssocReq { sta, bssid, listen_interval, ies, .. } =>
            (*sta, *bssid, *listen_interval, ies),
        _ => return,
    };

    let ssid = ies.ssid.clone().unwrap_or_default();

    if !sta_mac.is_multicast() {
        extract_fingerprint(sta_mac, ies, listen_interval, channel, deltas);
    }

    let seq = store.event_seq();
    deltas.push(StoreUpdate::ScanEvent {
        seq, event_type: ScanEventType::AssocReq, source: sta_mac, target: bssid,
        channel, rssi: pf.rssi,
        detail: EventDetail::AssocReq { ssid, listen_interval },
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_assoc_resp — StationAssociated + ScanEvent
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_assoc_resp(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (sta_mac, bssid, status, aid) = match &pf.body {
        FrameBody::AssocResp { sta, bssid, status, aid, .. } => (*sta, *bssid, *status, *aid),
        FrameBody::ReassocResp { sta, bssid, status, aid, .. } => (*sta, *bssid, *status, *aid),
        _ => return,
    };

    if status == 0 && !sta_mac.is_multicast() {
        deltas.push(StoreUpdate::StationAssociated {
            mac: sta_mac, bssid, channel,
        });
    }

    let seq = store.event_seq();
    deltas.push(StoreUpdate::ScanEvent {
        seq, event_type: ScanEventType::AssocResp, source: bssid, target: sta_mac,
        channel, rssi: pf.rssi,
        detail: EventDetail::AssocResp { status, aid },
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_reassoc_req — StationFingerprinted + ScanEvent
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_reassoc_req(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (sta_mac, bssid, current_ap, listen_interval, ies) = match &pf.body {
        FrameBody::ReassocReq { sta, bssid, current_ap, listen_interval, ies, .. } =>
            (*sta, *bssid, *current_ap, *listen_interval, ies),
        _ => return,
    };

    let ssid = ies.ssid.clone().unwrap_or_default();

    if !sta_mac.is_multicast() {
        extract_fingerprint(sta_mac, ies, listen_interval, channel, deltas);
    }

    let seq = store.event_seq();
    deltas.push(StoreUpdate::ScanEvent {
        seq, event_type: ScanEventType::ReassocReq, source: sta_mac, target: bssid,
        channel, rssi: pf.rssi,
        detail: EventDetail::ReassocReq { ssid, current_ap },
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_action — ScanEvent
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_action(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let (source, target, category, action, action_detail) = match &pf.body {
        FrameBody::Action { source, target, category, action, detail, .. } =>
            (*source, *target, *category, *action, detail),
        _ => return,
    };

    let (event_type, detail) = match action_detail {
        ActionDetail::SaQuery { transaction_id, is_request } => {
            let et = if *is_request { ScanEventType::SaQueryReq } else { ScanEventType::SaQueryResp };
            (et, EventDetail::SaQuery { transaction_id: *transaction_id, is_request: *is_request })
        }
        ActionDetail::BssTransition { dialog_token, is_request, .. } => {
            let et = if *is_request { ScanEventType::BssTransitionReq } else { ScanEventType::BssTransitionResp };
            (et, EventDetail::BssTransition { action, dialog_token: *dialog_token, status: Some(0), target_bssid: None })
        }
        ActionDetail::FtAction { action_code, sta_addr, target_ap, status } => {
            let et = match action_code { 1 => ScanEventType::FtRequest, 2 => ScanEventType::FtResponse, _ => ScanEventType::ActionOther };
            (et, EventDetail::FtAction { action: *action_code, sta_addr: *sta_addr, target_ap: *target_ap, status: Some(*status) })
        }
        ActionDetail::SpectrumMgmt { action_code, dialog_token } =>
            (ScanEventType::SpectrumAction, EventDetail::SpectrumMgmt { action: *action_code, dialog_token: *dialog_token }),
        ActionDetail::RadioMeasurement { action_code, dialog_token, repetitions, .. } => {
            let et = if *action_code == 0 { ScanEventType::RadioMeasurementReq } else { ScanEventType::RadioMeasurementResp };
            (et, EventDetail::RadioMeasurement { action: *action_code, dialog_token: *dialog_token, num_repetitions: *repetitions })
        }
        ActionDetail::WnmSleep { is_request } => {
            let et = if *is_request { ScanEventType::WnmSleepReq } else { ScanEventType::WnmSleepResp };
            (et, EventDetail::Action { category, action, category_name: "WNM" })
        }
        ActionDetail::Tdls { action_code } => {
            let et = match *action_code { 0..=2 => ScanEventType::TdlsSetup, 3 => ScanEventType::TdlsTeardown, _ => ScanEventType::ActionOther };
            (et, EventDetail::Action { category, action, category_name: "TDLS" })
        }
        ActionDetail::BlockAck { .. } =>
            (ScanEventType::ActionOther, EventDetail::Action { category, action, category_name: "BlockAck" }),
        ActionDetail::Other { category: cat, action: act } => {
            let name = match *cat {
                c if c == action_category::QOS => "QoS",
                c if c == action_category::VENDOR_SPECIFIC => "Vendor",
                _ => "Unknown",
            };
            (ScanEventType::ActionOther, EventDetail::Action { category: *cat, action: *act, category_name: name })
        }
    };

    let seq = store.event_seq();
    deltas.push(StoreUpdate::ScanEvent { seq, event_type, source, target, channel, rssi: pf.rssi, detail });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_control — StationPowerSaveChanged + ScanEvents
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_control(pf: &ParsedFrame, channel: u8, store: &FrameStore, deltas: &mut Vec<StoreUpdate>) {
    let detail = match &pf.body {
        FrameBody::Control { detail } => detail,
        _ => return,
    };

    match detail {
        ControlDetail::PsPoll { ta, .. } => {
            if !ta.is_multicast() {
                let was_ps = store.get_station(ta).map(|s| s.power_save).unwrap_or(false);
                if !was_ps {
                    deltas.push(StoreUpdate::StationPowerSaveChanged { mac: *ta, power_save: true });
                }
            }
        }
        ControlDetail::Rts { ta, ra, .. } => {
            let seq = store.event_seq();
            deltas.push(StoreUpdate::ScanEvent {
                seq, event_type: ScanEventType::ControlRts, source: *ta, target: *ra,
                channel, rssi: pf.rssi, detail: EventDetail::ControlFrame { subtype_name: "RTS" },
            });
        }
        ControlDetail::Cts { ra, .. } => {
            let seq = store.event_seq();
            deltas.push(StoreUpdate::ScanEvent {
                seq, event_type: ScanEventType::ControlCts, source: *ra, target: *ra,
                channel, rssi: pf.rssi, detail: EventDetail::ControlFrame { subtype_name: "CTS" },
            });
        }
        ControlDetail::BlockAckReq { ta, ra, .. } => {
            let seq = store.event_seq();
            deltas.push(StoreUpdate::ScanEvent {
                seq, event_type: ScanEventType::ControlBlockAckReq, source: *ta, target: *ra,
                channel, rssi: pf.rssi, detail: EventDetail::ControlFrame { subtype_name: "BAR" },
            });
        }
        ControlDetail::BlockAck { ta, ra, .. } => {
            let seq = store.event_seq();
            deltas.push(StoreUpdate::ScanEvent {
                seq, event_type: ScanEventType::ControlBlockAck, source: *ta, target: *ra,
                channel, rssi: pf.rssi, detail: EventDetail::ControlFrame { subtype_name: "BA" },
            });
        }
        _ => {}
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  extract_fingerprint — StationFingerprinted (from assoc/reassoc IEs)
// ═══════════════════════════════════════════════════════════════════════════════

fn extract_fingerprint(
    sta_mac: MacAddress,
    parsed: &ParsedIes,
    listen_interval: u16,
    channel: u8,
    deltas: &mut Vec<StoreUpdate>,
) {
    let wifi_gen = ie::derive_wifi_generation(parsed);
    let has_vht = parsed.vht_cap.is_some();
    let has_ht = parsed.ht_cap.is_some();
    let has_he = parsed.has_he || parsed.he_cap.is_some();

    let sta_bandwidth = if has_vht {
        match parsed.vht_cap.as_ref().map(|v| v.supported_channel_width) {
            Some(1) | Some(2) => Bandwidth::Bw160,
            _ => Bandwidth::Bw80,
        }
    } else if has_ht {
        if parsed.ht_cap.as_ref().map_or(false, |h| h.channel_width_40) { Bandwidth::Bw40 } else { Bandwidth::Bw20 }
    } else {
        Bandwidth::Bw20
    };

    let max_rate_mbps = compute_max_rate_mbps(wifi_gen, parsed.max_nss, sta_bandwidth);

    let mut rates = parsed.supported_rates.clone();
    rates.extend_from_slice(&parsed.extended_rates);

    let tag_order: Vec<u8> = parsed.raw_ies.iter().map(|r| r.tag).collect();

    deltas.push(StoreUpdate::StationFingerprinted {
        mac: sta_mac,
        channel,
        listen_interval,
        wifi_gen,
        max_nss: parsed.max_nss,
        max_rate_mbps,
        has_ht,
        has_vht,
        has_he,
        ht_cap_raw: parsed.ht_cap_raw,
        vht_cap_raw: parsed.vht_cap_raw,
        supported_rates: rates,
        ie_tag_order: tag_order,
        ampdu_max_len_exp: parsed.ht_cap.as_ref().map(|ht| ht.ampdu_params & 0x03).unwrap_or(0),
        ampdu_min_spacing: parsed.ht_cap.as_ref().map(|ht| (ht.ampdu_params >> 2) & 0x07).unwrap_or(0),
    });
}
