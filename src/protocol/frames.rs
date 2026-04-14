//! 802.11 management frame builders and parsers.
//!
//! **Builders**: Construct complete management frames ready for injection.
//! Pure functions — no I/O, no adapter state. Return `Vec<u8>`.
//!
#![allow(dead_code)]
#![allow(unused_imports)]
//! **Parsers**: Extract structured fields from raw frame bytes.
//! Return `Option<T>` — None if frame is too short or malformed.
//!
//! In the C implementation, frame building was split across 6+ files
//! (wifikit_frames.c, attack_dos.c, attack_ap.c, wifikit_core.c, etc.)
//! with identical deauth/beacon patterns duplicated everywhere.
//! In Rust, this module is THE one place for all frame crafting.
//!
//! Reference: IEEE Std 802.11-2020 §9.3, wifi-map/libwifikit/wifikit_frames.c

use crate::core::MacAddress;
use super::ieee80211::{
    self, fc, csa, ReasonCode, StatusCode,
    MGMT_HEADER_LEN, AUTH_BODY_LEN, ASSOC_REQ_FIXED_LEN, ASSOC_RESP_FIXED_LEN,
    MAX_FRAME_LEN,
};

// auth_algo and cap_info are imported in the test module via `use super::ieee80211::*`

// ═══════════════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Default duration field value: 314 μs (0x013A), typical for management frames
const DEFAULT_DURATION: u16 = 0x013A;

/// Default beacon interval in TUs (1 TU = 1024 μs). 100 TUs ≈ 102.4 ms.
const DEFAULT_BEACON_INTERVAL: u16 = 100;

/// Default listen interval for association requests (in beacon intervals)
const DEFAULT_LISTEN_INTERVAL: u16 = 10;

// ═══════════════════════════════════════════════════════════════════════════════
//  Management frame header — shared by all management frames
// ═══════════════════════════════════════════════════════════════════════════════

/// Write the 24-byte management frame header.
///
/// Layout: FC(2) + Duration(2) + Addr1/DA(6) + Addr2/SA(6) + Addr3/BSSID(6) + SeqCtl(2)
fn write_mgmt_header(
    buf: &mut Vec<u8>,
    fc0: u8,
    da: &MacAddress,
    sa: &MacAddress,
    bssid: &MacAddress,
    duration: u16,
) {
    // Frame Control: byte 0 = type+subtype, byte 1 = flags (0 for most mgmt)
    buf.push(fc0);
    buf.push(0x00);
    // Duration
    buf.extend_from_slice(&duration.to_le_bytes());
    // Addr1 = DA (receiver)
    buf.extend_from_slice(da.as_bytes());
    // Addr2 = SA (transmitter)
    buf.extend_from_slice(sa.as_bytes());
    // Addr3 = BSSID
    buf.extend_from_slice(bssid.as_bytes());
    // Sequence Control (zeroed — hardware sets this if HW_SEQ enabled)
    buf.push(0x00);
    buf.push(0x00);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Builders — Client-side frames (STA → AP)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build an Authentication frame (client → AP).
///
/// Used by: PMKID attack (Open System auth triggers M1),
///          WPS attack, association sequences.
///
/// # Arguments
/// * `sa` — Source MAC (our adapter or spoofed MAC)
/// * `bssid` — Target AP BSSID (also the DA)
/// * `algo` — Auth algorithm (use `auth_algo::OPEN_SYSTEM`, `::SAE`, etc.)
/// * `seq` — Auth transaction sequence number (1 for initial request)
/// * `status` — Status code (usually `StatusCode::Success` for requests)
pub fn build_auth(
    sa: &MacAddress,
    bssid: &MacAddress,
    algo: u16,
    seq: u16,
    status: StatusCode,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MGMT_HEADER_LEN + AUTH_BODY_LEN);
    write_mgmt_header(&mut buf, fc::AUTH, bssid, sa, bssid, DEFAULT_DURATION);

    // Auth Algorithm Number (2 bytes LE)
    buf.extend_from_slice(&algo.to_le_bytes());
    // Auth Transaction Sequence Number (2 bytes LE)
    buf.extend_from_slice(&seq.to_le_bytes());
    // Status Code (2 bytes LE)
    buf.extend_from_slice(&(status as u16).to_le_bytes());

    buf
}

/// Build an Association Request frame (client → AP).
///
/// Caller provides pre-built IEs (from `ie::build_assoc_ies` or manual construction).
/// The SSID IE should be included in `ies`.
///
/// # Arguments
/// * `sa` — Source MAC
/// * `bssid` — Target AP BSSID
/// * `cap` — Capability info bits (use `cap_info::BASE | cap_info::PRIVACY` etc.)
/// * `listen_interval` — Listen interval in beacon intervals (0 = use default of 10)
/// * `ies` — Tagged parameters (SSID, Supported Rates, RSN, HT/VHT/HE, etc.)
pub fn build_assoc_request(
    sa: &MacAddress,
    bssid: &MacAddress,
    cap: u16,
    listen_interval: u16,
    ies: &[u8],
) -> Option<Vec<u8>> {
    let total = MGMT_HEADER_LEN + ASSOC_REQ_FIXED_LEN + ies.len();
    if total > MAX_FRAME_LEN {
        return None;
    }

    let mut buf = Vec::with_capacity(total);
    write_mgmt_header(&mut buf, fc::ASSOC_REQ, bssid, sa, bssid, DEFAULT_DURATION);

    // Capability Info (2 bytes LE)
    buf.extend_from_slice(&cap.to_le_bytes());
    // Listen Interval (2 bytes LE)
    let li = if listen_interval == 0 { DEFAULT_LISTEN_INTERVAL } else { listen_interval };
    buf.extend_from_slice(&li.to_le_bytes());
    // Tagged Parameters (IEs)
    buf.extend_from_slice(ies);

    Some(buf)
}

/// Build a Reassociation Request frame (client → AP, during roaming).
///
/// Same as Association Request but includes the Current AP address (6 bytes)
/// before the IEs. Used in 802.11r Fast Transition and normal roaming.
///
/// # Arguments
/// * `sa` — Source MAC
/// * `bssid` — New AP BSSID
/// * `current_ap` — MAC of the AP we're currently associated with
/// * `cap` — Capability info bits
/// * `listen_interval` — Listen interval (0 = default)
/// * `ies` — Tagged parameters
pub fn build_reassoc_request(
    sa: &MacAddress,
    bssid: &MacAddress,
    current_ap: &MacAddress,
    cap: u16,
    listen_interval: u16,
    ies: &[u8],
) -> Option<Vec<u8>> {
    let total = MGMT_HEADER_LEN + ASSOC_REQ_FIXED_LEN + 6 + ies.len();
    if total > MAX_FRAME_LEN {
        return None;
    }

    let mut buf = Vec::with_capacity(total);
    write_mgmt_header(&mut buf, fc::REASSOC_REQ, bssid, sa, bssid, DEFAULT_DURATION);

    // Capability Info (2 bytes LE)
    buf.extend_from_slice(&cap.to_le_bytes());
    // Listen Interval (2 bytes LE)
    let li = if listen_interval == 0 { DEFAULT_LISTEN_INTERVAL } else { listen_interval };
    buf.extend_from_slice(&li.to_le_bytes());
    // Current AP address (6 bytes)
    buf.extend_from_slice(current_ap.as_bytes());
    // Tagged Parameters (IEs)
    buf.extend_from_slice(ies);

    Some(buf)
}

/// Build a Deauthentication frame.
///
/// Used by: DoS attacks (broadcast + targeted), MitM engine (lure clients),
///          Evil Twin (kick clients off real AP), KRACK (force reassociation).
///
/// # Arguments
/// * `sa` — Source MAC (real or spoofed as AP)
/// * `da` — Destination (target client, or `MacAddress::BROADCAST` for broadcast)
/// * `bssid` — BSSID of the AP (real or spoofed)
/// * `reason` — Reason code
pub fn build_deauth(
    sa: &MacAddress,
    da: &MacAddress,
    bssid: &MacAddress,
    reason: ReasonCode,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MGMT_HEADER_LEN + 2);
    // Deauth uses duration=0 (no NAV reservation needed)
    write_mgmt_header(&mut buf, fc::DEAUTH, da, sa, bssid, 0);

    // Reason Code (2 bytes LE)
    buf.extend_from_slice(&(reason as u16).to_le_bytes());

    buf
}

/// Build a Disassociation frame.
///
/// Same structure as deauth but different frame subtype.
/// Used by: DoS attacks, graceful disconnection sequences.
///
/// # Arguments
/// * `sa` — Source MAC
/// * `da` — Destination
/// * `bssid` — BSSID
/// * `reason` — Reason code
pub fn build_disassoc(
    sa: &MacAddress,
    da: &MacAddress,
    bssid: &MacAddress,
    reason: ReasonCode,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MGMT_HEADER_LEN + 2);
    write_mgmt_header(&mut buf, fc::DISASSOC, da, sa, bssid, 0);

    // Reason Code (2 bytes LE)
    buf.extend_from_slice(&(reason as u16).to_le_bytes());

    buf
}

/// Build a Probe Request frame.
///
/// Used by: Scanner (active probing), PMKID attack (trigger responses).
///
/// # Arguments
/// * `sa` — Source MAC
/// * `ssid` — Target SSID (empty string for broadcast/wildcard probe)
/// * `extra_ies` — Additional IEs beyond SSID and Supported Rates
///                 (e.g., HT/VHT capabilities for WiFi 5/6 probing)
pub fn build_probe_request(
    sa: &MacAddress,
    ssid: &str,
    extra_ies: &[u8],
) -> Option<Vec<u8>> {
    // Probe requests go to broadcast, with wildcard BSSID
    let da = MacAddress::BROADCAST;
    let bssid = MacAddress::BROADCAST;

    // Calculate IE sizes: SSID IE + Supported Rates IE + extra
    let ssid_ie_len = 2 + ssid.len();
    // Standard supported rates: 1, 2, 5.5, 11, 6, 9, 12, 18 Mbps
    let rates_ie_len = 2 + 8;
    // Extended rates: 24, 36, 48, 54 Mbps
    let ext_rates_ie_len = 2 + 4;
    let total = MGMT_HEADER_LEN + ssid_ie_len + rates_ie_len + ext_rates_ie_len + extra_ies.len();

    if total > MAX_FRAME_LEN || ssid.len() > 32 {
        return None;
    }

    let mut buf = Vec::with_capacity(total);
    write_mgmt_header(&mut buf, fc::PROBE_REQ, &da, sa, &bssid, 0);

    // SSID IE (tag 0)
    buf.push(0x00); // SSID tag
    buf.push(ssid.len() as u8);
    buf.extend_from_slice(ssid.as_bytes());

    // Supported Rates IE (tag 1) — standard 802.11b/g rates
    buf.push(0x01); // Supported Rates tag
    buf.push(0x08); // 8 rates
    buf.extend_from_slice(&[0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]);
    // 0x82=1M*, 0x84=2M*, 0x8B=5.5M*, 0x96=11M*, 0x0C=6M, 0x12=9M, 0x18=12M, 0x24=18M

    // Extended Supported Rates IE (tag 50)
    buf.push(0x32); // Extended Rates tag
    buf.push(0x04); // 4 rates
    buf.extend_from_slice(&[0x30, 0x48, 0x60, 0x6C]);
    // 0x30=24M, 0x48=36M, 0x60=48M, 0x6C=54M

    // Extra IEs (HT caps, VHT caps, etc.)
    buf.extend_from_slice(extra_ies);

    Some(buf)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Builders — AP-side frames (AP → STA)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build an Authentication Response frame (AP → client).
///
/// Used by: Rogue AP (accept all auth), KARMA, Evil Twin.
///
/// # Arguments
/// * `client` — Client MAC (DA)
/// * `bssid` — Our AP BSSID (SA and BSSID fields)
/// * `algo` — Auth algorithm (echo back what client sent)
/// * `status` — Status code (usually `StatusCode::Success` to accept)
pub fn build_auth_response(
    client: &MacAddress,
    bssid: &MacAddress,
    algo: u16,
    status: StatusCode,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MGMT_HEADER_LEN + AUTH_BODY_LEN);
    write_mgmt_header(&mut buf, fc::AUTH, client, bssid, bssid, DEFAULT_DURATION);

    // Auth Algorithm Number
    buf.extend_from_slice(&algo.to_le_bytes());
    // Auth Transaction Sequence = 2 (response)
    buf.extend_from_slice(&2u16.to_le_bytes());
    // Status Code
    buf.extend_from_slice(&(status as u16).to_le_bytes());

    buf
}

/// Build an Association Response frame (AP → client).
///
/// Used by: Rogue AP (accept associations, assign AID), KARMA.
///
/// # Arguments
/// * `client` — Client MAC (DA)
/// * `bssid` — Our AP BSSID
/// * `status` — Status code
/// * `aid` — Association ID (1-2007). Bits 14-15 are set automatically per spec.
/// * `cap` — Capability info bits
/// * `ies` — Tagged parameters (Supported Rates, HT/VHT, etc.)
pub fn build_assoc_response(
    client: &MacAddress,
    bssid: &MacAddress,
    status: StatusCode,
    aid: u16,
    cap: u16,
    ies: &[u8],
) -> Option<Vec<u8>> {
    let total = MGMT_HEADER_LEN + ASSOC_RESP_FIXED_LEN + ies.len();
    if total > MAX_FRAME_LEN {
        return None;
    }

    let mut buf = Vec::with_capacity(total);
    write_mgmt_header(&mut buf, fc::ASSOC_RESP, client, bssid, bssid, DEFAULT_DURATION);

    // Capability Info (2 bytes LE)
    buf.extend_from_slice(&cap.to_le_bytes());
    // Status Code (2 bytes LE)
    buf.extend_from_slice(&(status as u16).to_le_bytes());
    // Association ID — bits 14-15 must be set per IEEE 802.11-2020 §9.4.1.8
    let aid_val = (aid & 0x3FFF) | 0xC000;
    buf.extend_from_slice(&aid_val.to_le_bytes());
    // Tagged Parameters
    buf.extend_from_slice(ies);

    Some(buf)
}

/// Build a Beacon frame.
///
/// Used by: Rogue AP (beacon loop), MANA Loud, Known Beacons, Evil Twin.
///
/// # Arguments
/// * `bssid` — AP BSSID (SA and BSSID fields, DA = broadcast)
/// * `tsf` — Timestamp (TSF) value, monotonically increasing
/// * `beacon_interval` — Beacon interval in TUs (0 = default 100)
/// * `cap` — Capability info bits
/// * `ies` — Tagged parameters (SSID, Rates, DS Params, RSN, HT/VHT, etc.)
pub fn build_beacon(
    bssid: &MacAddress,
    tsf: u64,
    beacon_interval: u16,
    cap: u16,
    ies: &[u8],
) -> Option<Vec<u8>> {
    // Beacon fixed fields: Timestamp(8) + Beacon Interval(2) + Capability(2) = 12
    let total = MGMT_HEADER_LEN + 12 + ies.len();
    if total > MAX_FRAME_LEN {
        return None;
    }

    let mut buf = Vec::with_capacity(total);
    // Beacons: DA = broadcast, SA = BSSID, BSSID = BSSID
    write_mgmt_header(&mut buf, fc::BEACON, &MacAddress::BROADCAST, bssid, bssid, 0);

    // Timestamp (8 bytes LE)
    buf.extend_from_slice(&tsf.to_le_bytes());
    // Beacon Interval (2 bytes LE)
    let bi = if beacon_interval == 0 { DEFAULT_BEACON_INTERVAL } else { beacon_interval };
    buf.extend_from_slice(&bi.to_le_bytes());
    // Capability Info (2 bytes LE)
    buf.extend_from_slice(&cap.to_le_bytes());
    // Tagged Parameters
    buf.extend_from_slice(ies);

    Some(buf)
}

/// Build a Probe Response frame.
///
/// Used by: Rogue AP (respond to probe requests), KARMA (respond to all SSIDs).
///
/// # Arguments
/// * `bssid` — AP BSSID
/// * `da` — Requesting station MAC
/// * `tsf` — Timestamp value
/// * `beacon_interval` — Beacon interval in TUs (0 = default 100)
/// * `cap` — Capability info bits
/// * `ies` — Tagged parameters (same as beacon IEs, minus TIM)
pub fn build_probe_response(
    bssid: &MacAddress,
    da: &MacAddress,
    tsf: u64,
    beacon_interval: u16,
    cap: u16,
    ies: &[u8],
) -> Option<Vec<u8>> {
    let total = MGMT_HEADER_LEN + 12 + ies.len();
    if total > MAX_FRAME_LEN {
        return None;
    }

    let mut buf = Vec::with_capacity(total);
    write_mgmt_header(&mut buf, fc::PROBE_RESP, da, bssid, bssid, 0);

    // Timestamp (8 bytes LE)
    buf.extend_from_slice(&tsf.to_le_bytes());
    // Beacon Interval (2 bytes LE)
    let bi = if beacon_interval == 0 { DEFAULT_BEACON_INTERVAL } else { beacon_interval };
    buf.extend_from_slice(&bi.to_le_bytes());
    // Capability Info (2 bytes LE)
    buf.extend_from_slice(&cap.to_le_bytes());
    // Tagged Parameters
    buf.extend_from_slice(ies);

    Some(buf)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Builders — Action frames
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a generic Action frame.
///
/// Used by: SA Query, Block Ack, Radio Measurement, WNM.
///
/// # Arguments
/// * `sa` — Source MAC
/// * `da` — Destination MAC
/// * `bssid` — BSSID
/// * `category` — Action category (use `action_category::*`)
/// * `action` — Action code within category
/// * `body` — Action body (category-specific payload)
pub fn build_action(
    sa: &MacAddress,
    da: &MacAddress,
    bssid: &MacAddress,
    category: u8,
    action: u8,
    body: &[u8],
) -> Option<Vec<u8>> {
    let total = MGMT_HEADER_LEN + 2 + body.len();
    if total > MAX_FRAME_LEN {
        return None;
    }

    let mut buf = Vec::with_capacity(total);
    write_mgmt_header(&mut buf, fc::ACTION, da, sa, bssid, 0);

    // Category
    buf.push(category);
    // Action
    buf.push(action);
    // Action body
    buf.extend_from_slice(body);

    Some(buf)
}

/// Build a CSA (Channel Switch Announcement) Action frame.
///
/// Used by: MitM engine (lure clients to rogue channel), KRACK.
/// The CSA element tells clients to switch to a new channel after `count` beacons.
///
/// # Arguments
/// * `sa` — Source MAC (spoofed as target AP)
/// * `da` — Destination (`MacAddress::BROADCAST` for all clients)
/// * `bssid` — Target AP BSSID (spoofed)
/// * `new_channel` — Channel to switch to
/// * `count` — Beacon count until switch (0 = immediate)
pub fn build_csa_action(
    sa: &MacAddress,
    da: &MacAddress,
    bssid: &MacAddress,
    new_channel: u8,
    count: u8,
) -> Vec<u8> {
    // CSA Action frame body:
    //   Category: Spectrum Management (0)
    //   Action: Channel Switch Announcement (4)
    //   CSA Element: ID(1) + Len(1) + Mode(1) + NewCh(1) + Count(1)
    let mut body = Vec::with_capacity(5);
    body.push(csa::ELEMENT_ID);    // Element ID = 37
    body.push(csa::ELEMENT_LEN);   // Length = 3
    body.push(1);                   // Channel Switch Mode: 1 = cease transmissions
    body.push(new_channel);
    body.push(count);

    let mut buf = Vec::with_capacity(MGMT_HEADER_LEN + 2 + body.len());
    write_mgmt_header(&mut buf, fc::ACTION, da, sa, bssid, 0);

    // Category: Spectrum Management (0)
    buf.push(ieee80211::action_category::SPECTRUM_MGMT);
    // Action: Channel Switch Announcement (4)
    buf.push(4);
    // CSA Element
    buf.extend_from_slice(&body);

    buf
}

/// Build a CSA Beacon — a beacon frame with an embedded CSA IE.
///
/// Used by: MitM engine CSA lure (sends beacons spoofed as target AP
/// with CSA element to force channel switch).
///
/// # Arguments
/// * `bssid` — Spoofed AP BSSID
/// * `tsf` — Timestamp value
/// * `beacon_interval` — Beacon interval in TUs (0 = default)
/// * `cap` — Capability info bits from target AP
/// * `new_channel` — Channel to switch to
/// * `count` — Beacon count until switch
/// * `ies` — Original AP's beacon IEs (SSID, rates, etc.)
pub fn build_csa_beacon(
    bssid: &MacAddress,
    tsf: u64,
    beacon_interval: u16,
    cap: u16,
    new_channel: u8,
    count: u8,
    ies: &[u8],
) -> Option<Vec<u8>> {
    // CSA IE: tag(1) + len(1) + mode(1) + channel(1) + count(1) = 5 bytes
    let csa_ie_len = 5;
    let total = MGMT_HEADER_LEN + 12 + ies.len() + csa_ie_len;
    if total > MAX_FRAME_LEN {
        return None;
    }

    let mut buf = Vec::with_capacity(total);
    write_mgmt_header(&mut buf, fc::BEACON, &MacAddress::BROADCAST, bssid, bssid, 0);

    // Timestamp (8 bytes LE)
    buf.extend_from_slice(&tsf.to_le_bytes());
    // Beacon Interval (2 bytes LE)
    let bi = if beacon_interval == 0 { DEFAULT_BEACON_INTERVAL } else { beacon_interval };
    buf.extend_from_slice(&bi.to_le_bytes());
    // Capability Info (2 bytes LE)
    buf.extend_from_slice(&cap.to_le_bytes());
    // Original IEs
    buf.extend_from_slice(ies);
    // Append CSA IE
    buf.push(csa::ELEMENT_ID);    // 37
    buf.push(csa::ELEMENT_LEN);   // 3
    buf.push(1);                   // Mode: cease transmissions
    buf.push(new_channel);
    buf.push(count);

    Some(buf)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Builders — Control frames (no management header, shorter format)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a CTS-to-self frame (10 bytes).
///
/// CTS (Clear To Send) silences all stations that hear it for the Duration/ID
/// field value (NAV reservation). Used for DoS: flood CTS with max duration
/// to keep the channel reserved.
///
/// Layout: FC(2) + Duration(2) + RA(6) = 10 bytes
///
/// # Arguments
/// * `target` — Receiver Address (the station that "requested" to send)
/// * `duration_us` — NAV duration in microseconds (max 32767 for ~32ms reservation)
pub fn build_cts(target: &MacAddress, duration_us: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    buf.push(fc::CTS);
    buf.push(0x00);
    buf.extend_from_slice(&duration_us.to_le_bytes());
    buf.extend_from_slice(target.as_bytes());
    buf
}

/// Build an RTS frame (16 bytes).
///
/// RTS (Request To Send) triggers CTS responses. Flood with random source MACs
/// and max duration to disrupt channel access.
///
/// Layout: FC(2) + Duration(2) + RA(6) + TA(6) = 16 bytes
///
/// # Arguments
/// * `target` — Receiver Address
/// * `source` — Transmitter Address (our MAC or random for flooding)
/// * `duration_us` — NAV duration in microseconds
pub fn build_rts(target: &MacAddress, source: &MacAddress, duration_us: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.push(fc::RTS);
    buf.push(0x00);
    buf.extend_from_slice(&duration_us.to_le_bytes());
    buf.extend_from_slice(target.as_bytes());
    buf.extend_from_slice(source.as_bytes());
    buf
}

/// Build a Null Data frame with Power Management bit set.
///
/// Spoofed as the victim client → AP. The AP thinks the client entered
/// power save mode and starts buffering frames instead of delivering them,
/// effectively denying service to the victim.
///
/// Layout: FC(2) + Duration(2) + Addr1/BSSID(6) + Addr2/SA(6) + Addr3/BSSID(6) + SeqCtl(2) = 24
///
/// # Arguments
/// * `victim_mac` — MAC of the client to impersonate (Addr2/SA)
/// * `bssid` — Target AP BSSID (Addr1 and Addr3)
pub fn build_power_save_null(victim_mac: &MacAddress, bssid: &MacAddress) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    // FC: Null Data (0x48) with ToDS=1 and PM=1 flags
    buf.push(fc::NULL_DATA);
    buf.push(ieee80211::fc_flags::TO_DS | ieee80211::fc_flags::POWER_MGMT); // 0x11
    // Duration
    buf.push(0x00);
    buf.push(0x00);
    // Addr1 = BSSID (receiver)
    buf.extend_from_slice(bssid.as_bytes());
    // Addr2 = spoofed victim MAC (transmitter)
    buf.extend_from_slice(victim_mac.as_bytes());
    // Addr3 = BSSID
    buf.extend_from_slice(bssid.as_bytes());
    // Sequence Control
    buf.push(0x00);
    buf.push(0x00);
    buf
}

/// Build a QoS Null Data frame for client stimulation.
///
/// Spoofed from AP (FromDS=1) with MoreData=1 flag. When a client receives this,
/// it thinks the AP has buffered frames and wakes its radio to poll for them.
/// The AP has no actual data — the client stays associated but becomes active.
///
/// This is a non-disruptive way to force sleeping mobile clients to transmit,
/// making them visible to the scanner and triggering association state checks.
/// Used by the CSA attack to wake clients before sending CSA beacons.
///
/// Frame structure (26 bytes):
///   FC(2) + Duration(2) + DA(6) + BSSID(6) + SA(6) + SeqCtl(2) + QoS(2)
///
/// # Arguments
/// * `da` — Destination: broadcast or specific client MAC
/// * `bssid` — AP BSSID to spoof as sender
pub fn build_qos_null_stimulation(da: &MacAddress, bssid: &MacAddress) -> Vec<u8> {
    let mut buf = Vec::with_capacity(26);
    // FC byte 0: QoS Null = Data type (0x08) | QoS Null subtype (0xC0) = 0xC8
    buf.push(0xC8);
    // FC byte 1: FromDS=1 (0x02) | MoreData=1 (0x20) = 0x22
    buf.push(ieee80211::fc_flags::FROM_DS | ieee80211::fc_flags::MORE_DATA);
    // Duration
    buf.extend_from_slice(&[0x00, 0x00]);
    // Addr1 = DA (receiver — broadcast or specific client)
    buf.extend_from_slice(da.as_bytes());
    // Addr2 = BSSID (transmitter — spoofed AP)
    buf.extend_from_slice(bssid.as_bytes());
    // Addr3 = SA (source = AP BSSID in FromDS frames)
    buf.extend_from_slice(bssid.as_bytes());
    // Sequence Control
    buf.extend_from_slice(&[0x00, 0x00]);
    // QoS Control (2 bytes) — TID 0, normal ack policy
    buf.extend_from_slice(&[0x00, 0x00]);
    buf
}

/// Build a QoS Data frame with intentionally bad TKIP MIC (Michael shutdown attack).
///
/// TKIP spec requires AP to shut down for 60 seconds after detecting 2 MIC failures
/// within 60 seconds (802.11-2020 §12.4.5.2). Craft QoS Data with garbage payload
/// that will fail MIC verification.
///
/// # Arguments
/// * `victim_mac` — Client MAC to spoof as sender
/// * `bssid` — Target AP BSSID
pub fn build_michael_shutdown(victim_mac: &MacAddress, bssid: &MacAddress) -> Vec<u8> {
    let mut buf = Vec::with_capacity(58);
    // FC: QoS Data with ToDS
    buf.push(fc::QOS_DATA);
    buf.push(ieee80211::fc_flags::TO_DS); // 0x01
    // Duration
    buf.push(0x00);
    buf.push(0x00);
    // Addr1 = BSSID
    buf.extend_from_slice(bssid.as_bytes());
    // Addr2 = spoofed victim
    buf.extend_from_slice(victim_mac.as_bytes());
    // Addr3 = BSSID
    buf.extend_from_slice(bssid.as_bytes());
    // Sequence Control
    buf.push(0x00);
    buf.push(0x00);
    // QoS Control (2 bytes)
    buf.push(0x00);
    buf.push(0x00);
    // Fake encrypted payload with intentionally bad MIC (32 bytes of garbage)
    // The AP will attempt TKIP decryption, detect MIC failure, and trigger countermeasures
    for i in 0u8..32 {
        buf.push(i.wrapping_mul(0x37).wrapping_add(0xAB));
    }
    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Builders — DoS action frames (SA Query, BSS Transition)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build an SA Query Request action frame (802.11w).
///
/// SA Query is part of Protected Management Frames (PMF/802.11w). Flooding
/// SA Query requests forces the AP to process each one, consuming resources.
/// If PMF is required, the AP must respond to each valid-looking request.
///
/// # Arguments
/// * `da` — Destination (target client or broadcast)
/// * `bssid` — Target AP BSSID (also spoofed as SA)
/// * `transaction_id` — 2-byte transaction ID (use random for each frame)
pub fn build_sa_query_request(
    da: &MacAddress,
    bssid: &MacAddress,
    transaction_id: u16,
) -> Option<Vec<u8>> {
    // SA Query body: transaction ID (2 bytes)
    let body = transaction_id.to_le_bytes();
    build_action(
        bssid,  // SA = spoofed as AP
        da,
        bssid,
        ieee80211::action_category::SA_QUERY,
        0, // action = 0 = SA Query Request
        &body,
    )
}

/// Build a BSS Transition Management Request (802.11v WNM).
///
/// Tells the client it must transition to another BSS (roam). With
/// "disassociation imminent" flag set, the client will disconnect.
/// Used for targeted client eviction without deauth frames.
///
/// # Arguments
/// * `da` — Target client MAC
/// * `bssid` — AP BSSID (spoofed as SA)
/// * `dialog_token` — Dialog sequence number
pub fn build_bss_transition_request(
    da: &MacAddress,
    bssid: &MacAddress,
    dialog_token: u8,
) -> Option<Vec<u8>> {
    // BSS Transition Management Request body:
    //   Dialog Token (1) + Request Mode (1) + Disassoc Timer (2) + Validity Interval (1)
    let mut body = Vec::with_capacity(5);
    body.push(dialog_token);
    // Request Mode: bit 2 = BSS Termination Included, bit 3 = Disassociation Imminent
    body.push(0x0C); // imminent + disassoc imminent
    // Disassociation Timer: 1 TU (minimum — immediate)
    body.extend_from_slice(&1u16.to_le_bytes());
    // Validity Interval: 0xFF (maximum)
    body.push(0xFF);

    build_action(
        bssid,  // SA = spoofed as AP
        da,
        bssid,
        ieee80211::action_category::WNM,
        ieee80211::wnm_action::BSS_TRANSITION_MGMT_REQ,
        &body,
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FrameBuilder — Research lab: craft ANY frame byte by byte
// ═══════════════════════════════════════════════════════════════════════════════

/// Fluent builder for arbitrary 802.11 frames.
///
/// The typed builders (`build_auth`, `build_deauth`, etc.) handle known frame types
/// with correct structure and field placement. `FrameBuilder` is for the research lab:
/// craft malformed frames, undocumented subtypes, custom payloads, protocol exploration.
///
/// Two modes of operation:
///
/// **Structured** — use field methods to set header fields, then append body:
/// ```rust
/// # use wifikit::protocol::frames::FrameBuilder;
/// # use wifikit::core::MacAddress;
/// let frame = FrameBuilder::new()
///     .fc(0xB0, 0x00)                        // auth frame
///     .duration(314)
///     .addr1(&MacAddress::BROADCAST)
///     .addr2(&MacAddress::BROADCAST)
///     .addr3(&MacAddress::BROADCAST)
///     .body(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
///     .build();
/// ```
///
/// **Raw** — append arbitrary bytes in order, no structure enforced:
/// ```rust
/// # use wifikit::protocol::frames::FrameBuilder;
/// let frame = FrameBuilder::new()
///     .raw(&[0xC0, 0x00])            // FC: deauth
///     .raw(&[0x00, 0x00])            // duration
///     .raw(&[0xFF; 6])               // DA: broadcast
///     .raw(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]) // SA
///     .raw(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]) // BSSID
///     .raw(&[0x00, 0x00])            // seq ctrl
///     .raw(&[0x07, 0x00])            // reason: Class3FromNonAssoc
///     .build();
/// ```
///
/// **Mixed** — set some fields structurally, override or extend with raw bytes:
/// ```rust
/// # use wifikit::protocol::frames::FrameBuilder;
/// # use wifikit::core::MacAddress;
/// let frame = FrameBuilder::mgmt(0xB0, &MacAddress::BROADCAST, &MacAddress::BROADCAST, &MacAddress::BROADCAST)
///     .body(&[0x03, 0x00])           // SAE auth algo
///     .u16_le(1)                     // seq = 1
///     .u16_le(0)                     // status = success
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct FrameBuilder {
    buf: Vec<u8>,
}

impl FrameBuilder {
    /// Create an empty frame builder.
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(128) }
    }

    /// Create a builder pre-filled with a management frame header (24 bytes).
    ///
    /// Sets FC, duration=0, addresses, seq_ctrl=0. Append body after.
    pub fn mgmt(fc0: u8, da: &MacAddress, sa: &MacAddress, bssid: &MacAddress) -> Self {
        let mut fb = Self::new();
        write_mgmt_header(&mut fb.buf, fc0, da, sa, bssid, 0);
        fb
    }

    /// Set Frame Control bytes (byte 0 = type+subtype, byte 1 = flags).
    /// Appends 2 bytes.
    pub fn fc(mut self, byte0: u8, byte1: u8) -> Self {
        self.buf.push(byte0);
        self.buf.push(byte1);
        self
    }

    /// Set Duration/ID field. Appends 2 bytes (little-endian).
    pub fn duration(mut self, dur: u16) -> Self {
        self.buf.extend_from_slice(&dur.to_le_bytes());
        self
    }

    /// Set Address 1 (DA/Receiver). Appends 6 bytes.
    pub fn addr1(mut self, mac: &MacAddress) -> Self {
        self.buf.extend_from_slice(mac.as_bytes());
        self
    }

    /// Set Address 2 (SA/Transmitter). Appends 6 bytes.
    pub fn addr2(mut self, mac: &MacAddress) -> Self {
        self.buf.extend_from_slice(mac.as_bytes());
        self
    }

    /// Set Address 3 (BSSID). Appends 6 bytes.
    pub fn addr3(mut self, mac: &MacAddress) -> Self {
        self.buf.extend_from_slice(mac.as_bytes());
        self
    }

    /// Set Sequence Control. Appends 2 bytes (little-endian).
    pub fn seq_ctrl(mut self, sc: u16) -> Self {
        self.buf.extend_from_slice(&sc.to_le_bytes());
        self
    }

    /// Set Address 4 (used in WDS/mesh frames). Appends 6 bytes.
    pub fn addr4(mut self, mac: &MacAddress) -> Self {
        self.buf.extend_from_slice(mac.as_bytes());
        self
    }

    /// Append arbitrary raw bytes. Use for custom payloads, malformed fields,
    /// or anything the typed methods don't cover.
    pub fn raw(mut self, bytes: &[u8]) -> Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a single byte.
    pub fn u8(mut self, val: u8) -> Self {
        self.buf.push(val);
        self
    }

    /// Append a u16 in little-endian byte order.
    pub fn u16_le(mut self, val: u16) -> Self {
        self.buf.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Append a u32 in little-endian byte order.
    pub fn u32_le(mut self, val: u32) -> Self {
        self.buf.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Append a u64 in little-endian byte order (used for TSF timestamps).
    pub fn u64_le(mut self, val: u64) -> Self {
        self.buf.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Append a MAC address (6 bytes).
    pub fn mac(mut self, addr: &MacAddress) -> Self {
        self.buf.extend_from_slice(addr.as_bytes());
        self
    }

    /// Append body bytes (alias for `raw` — clearer intent for frame body).
    pub fn body(self, bytes: &[u8]) -> Self {
        self.raw(bytes)
    }

    /// Append N zero bytes (padding, reserved fields).
    pub fn zeros(mut self, n: usize) -> Self {
        self.buf.resize(self.buf.len() + n, 0);
        self
    }

    /// Append a tagged IE: tag(1) + length(1) + value.
    pub fn ie(mut self, tag: u8, value: &[u8]) -> Self {
        self.buf.push(tag);
        self.buf.push(value.len() as u8);
        self.buf.extend_from_slice(value);
        self
    }

    /// Current length of the frame being built.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the builder has no bytes yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Peek at the bytes built so far (useful for debugging mid-build).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the builder and return the finished frame.
    pub fn build(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for FrameBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Parsers — Structured extraction from raw frame bytes
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed management frame header (24 bytes).
#[derive(Debug, Clone)]
pub struct MgmtHeader {
    /// Frame Control word (2 bytes, little-endian)
    pub fc: u16,
    /// Duration/ID field
    pub duration: u16,
    /// Address 1 — Receiver/DA
    pub addr1: MacAddress,
    /// Address 2 — Transmitter/SA
    pub addr2: MacAddress,
    /// Address 3 — BSSID (usually)
    pub addr3: MacAddress,
    /// Sequence Control (fragment + sequence number)
    pub seq_ctrl: u16,
}

impl MgmtHeader {
    /// Frame type (0=mgmt, 1=ctrl, 2=data)
    pub fn frame_type(&self) -> u8 {
        ieee80211::fc_type(self.fc)
    }

    /// Frame subtype (0-15)
    pub fn frame_subtype(&self) -> u8 {
        ieee80211::fc_subtype(self.fc)
    }

    /// Sequence number (upper 12 bits of seq_ctrl)
    pub fn sequence_number(&self) -> u16 {
        self.seq_ctrl >> 4
    }

    /// Fragment number (lower 4 bits of seq_ctrl)
    pub fn fragment_number(&self) -> u8 {
        (self.seq_ctrl & 0x0F) as u8
    }
}

/// Parse a management frame header from raw bytes.
///
/// Returns None if frame is shorter than 24 bytes.
pub fn parse_mgmt_header(frame: &[u8]) -> Option<MgmtHeader> {
    if frame.len() < MGMT_HEADER_LEN {
        return None;
    }

    Some(MgmtHeader {
        fc: u16::from_le_bytes([frame[0], frame[1]]),
        duration: u16::from_le_bytes([frame[2], frame[3]]),
        addr1: MacAddress::from_slice(&frame[4..10])?,
        addr2: MacAddress::from_slice(&frame[10..16])?,
        addr3: MacAddress::from_slice(&frame[16..22])?,
        seq_ctrl: u16::from_le_bytes([frame[22], frame[23]]),
    })
}

/// Parsed Authentication frame body.
#[derive(Debug, Clone)]
pub struct AuthBody {
    /// Authentication algorithm number
    pub algo: u16,
    /// Authentication transaction sequence number
    pub seq: u16,
    /// Status code
    pub status: u16,
}

/// Parse an Authentication frame (header + body).
///
/// Auth frame body: Auth Algo(2) + Auth Seq(2) + Status(2) = 6 bytes at offset 24.
/// Validates frame type=Management, subtype=Auth before parsing body.
pub fn parse_auth(frame: &[u8]) -> Option<(MgmtHeader, AuthBody)> {
    let min_len = MGMT_HEADER_LEN + AUTH_BODY_LEN;
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    // Validate frame is actually an Authentication frame
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || ieee80211::fc_subtype(hdr.fc) != ieee80211::frame_subtype::AUTH
    {
        return None;
    }
    let body_start = MGMT_HEADER_LEN;

    let body = AuthBody {
        algo: u16::from_le_bytes([frame[body_start], frame[body_start + 1]]),
        seq: u16::from_le_bytes([frame[body_start + 2], frame[body_start + 3]]),
        status: u16::from_le_bytes([frame[body_start + 4], frame[body_start + 5]]),
    };

    Some((hdr, body))
}

/// Parsed Association Request body.
#[derive(Debug, Clone)]
pub struct AssocRequestBody {
    /// Capability Information
    pub cap_info: u16,
    /// Listen Interval (in beacon intervals)
    pub listen_interval: u16,
    /// Byte offset where tagged parameters (IEs) start in the original frame
    pub ies_offset: usize,
    /// Number of IE bytes
    pub ies_len: usize,
}

/// Parse an Association Request frame.
///
/// Body: Capability(2) + Listen Interval(2) + IEs(variable) at offset 24.
/// Validates frame type=Management, subtype=AssocReq before parsing body.
pub fn parse_assoc_request(frame: &[u8]) -> Option<(MgmtHeader, AssocRequestBody)> {
    let min_len = MGMT_HEADER_LEN + ASSOC_REQ_FIXED_LEN;
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    // Validate frame is actually an Association Request
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || ieee80211::fc_subtype(hdr.fc) != ieee80211::frame_subtype::ASSOC_REQ
    {
        return None;
    }
    let body_start = MGMT_HEADER_LEN;
    let ies_offset = body_start + ASSOC_REQ_FIXED_LEN;

    let body = AssocRequestBody {
        cap_info: u16::from_le_bytes([frame[body_start], frame[body_start + 1]]),
        listen_interval: u16::from_le_bytes([frame[body_start + 2], frame[body_start + 3]]),
        ies_offset,
        ies_len: frame.len() - ies_offset,
    };

    Some((hdr, body))
}

/// Parsed Association Response body.
#[derive(Debug, Clone)]
pub struct AssocResponseBody {
    /// Capability Information
    pub cap_info: u16,
    /// Status Code
    pub status: u16,
    /// Association ID (bits 14-15 stripped)
    pub aid: u16,
    /// Byte offset where tagged parameters (IEs) start in the original frame
    pub ies_offset: usize,
    /// Number of IE bytes
    pub ies_len: usize,
}

/// Parse an Association Response frame.
///
/// Body: Capability(2) + Status(2) + AID(2) + IEs(variable) at offset 24.
/// Validates frame type=Management, subtype=AssocResp or ReassocResp before parsing.
pub fn parse_assoc_response(frame: &[u8]) -> Option<(MgmtHeader, AssocResponseBody)> {
    let min_len = MGMT_HEADER_LEN + ASSOC_RESP_FIXED_LEN;
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    // Validate frame is actually an Association Response or Reassociation Response
    // (both have identical body layout: Capability + Status + AID + IEs)
    let subtype = ieee80211::fc_subtype(hdr.fc);
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || (subtype != ieee80211::frame_subtype::ASSOC_RESP
            && subtype != ieee80211::frame_subtype::REASSOC_RESP)
    {
        return None;
    }
    let body_start = MGMT_HEADER_LEN;
    let ies_offset = body_start + ASSOC_RESP_FIXED_LEN;

    let raw_aid = u16::from_le_bytes([frame[body_start + 4], frame[body_start + 5]]);

    let body = AssocResponseBody {
        cap_info: u16::from_le_bytes([frame[body_start], frame[body_start + 1]]),
        status: u16::from_le_bytes([frame[body_start + 2], frame[body_start + 3]]),
        aid: raw_aid & 0x3FFF, // Strip bits 14-15
        ies_offset,
        ies_len: frame.len() - ies_offset,
    };

    Some((hdr, body))
}

/// Parsed Deauthentication/Disassociation frame body.
#[derive(Debug, Clone)]
pub struct ReasonBody {
    /// Reason code
    pub reason: u16,
}

/// Parse a Deauthentication frame (header + reason code).
/// Validates frame type=Management, subtype=Deauth before parsing.
pub fn parse_deauth(frame: &[u8]) -> Option<(MgmtHeader, ReasonBody)> {
    if frame.len() < MGMT_HEADER_LEN + 2 {
        return None;
    }
    let hdr = parse_mgmt_header(frame)?;

    // Validate frame is actually a Deauthentication
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || ieee80211::fc_subtype(hdr.fc) != ieee80211::frame_subtype::DEAUTH
    {
        return None;
    }
    let reason = u16::from_le_bytes([frame[MGMT_HEADER_LEN], frame[MGMT_HEADER_LEN + 1]]);
    Some((hdr, ReasonBody { reason }))
}

/// Parse a Disassociation frame (header + reason code).
/// Same body layout as deauth — only the frame subtype differs.
/// Validates frame type=Management, subtype=Disassoc before parsing.
pub fn parse_disassoc(frame: &[u8]) -> Option<(MgmtHeader, ReasonBody)> {
    if frame.len() < MGMT_HEADER_LEN + 2 {
        return None;
    }
    let hdr = parse_mgmt_header(frame)?;

    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || ieee80211::fc_subtype(hdr.fc) != ieee80211::frame_subtype::DISASSOC
    {
        return None;
    }
    let reason = u16::from_le_bytes([frame[MGMT_HEADER_LEN], frame[MGMT_HEADER_LEN + 1]]);
    Some((hdr, ReasonBody { reason }))
}

/// Parsed Beacon/Probe Response fixed fields.
#[derive(Debug, Clone)]
pub struct BeaconBody {
    /// Timestamp (TSF) — 8-byte microsecond counter
    pub tsf: u64,
    /// Beacon interval in TUs (1 TU = 1024 μs)
    pub beacon_interval: u16,
    /// Capability Information
    pub cap_info: u16,
    /// Byte offset where tagged parameters (IEs) start in the original frame
    pub ies_offset: usize,
    /// Number of IE bytes
    pub ies_len: usize,
}

/// Parse a Beacon or Probe Response frame.
///
/// Fixed fields: Timestamp(8) + Beacon Interval(2) + Capability(2) at offset 24.
/// Tagged parameters follow at offset 36.
pub fn parse_beacon(frame: &[u8]) -> Option<(MgmtHeader, BeaconBody)> {
    let min_len = MGMT_HEADER_LEN + 12; // 24 + 12 = 36
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    // Accept both Beacon (subtype 8) and Probe Response (subtype 5) —
    // identical fixed field layout (TSF + Beacon Interval + Capability)
    let subtype = ieee80211::fc_subtype(hdr.fc);
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || (subtype != ieee80211::frame_subtype::BEACON
            && subtype != ieee80211::frame_subtype::PROBE_RESP)
    {
        return None;
    }
    let bs = MGMT_HEADER_LEN;
    let ies_offset = bs + 12;

    let body = BeaconBody {
        tsf: u64::from_le_bytes([
            frame[bs], frame[bs + 1], frame[bs + 2], frame[bs + 3],
            frame[bs + 4], frame[bs + 5], frame[bs + 6], frame[bs + 7],
        ]),
        beacon_interval: u16::from_le_bytes([frame[bs + 8], frame[bs + 9]]),
        cap_info: u16::from_le_bytes([frame[bs + 10], frame[bs + 11]]),
        ies_offset,
        ies_len: frame.len() - ies_offset,
    };

    Some((hdr, body))
}

/// Parsed Action frame header (category + action code).
#[derive(Debug, Clone)]
pub struct ActionBody {
    /// Action category
    pub category: u8,
    /// Action code within the category
    pub action: u8,
    /// Byte offset where the action-specific body starts
    pub body_offset: usize,
    /// Number of action body bytes
    pub body_len: usize,
}

/// Parse an Action frame (header + category + action + body).
/// Validates frame type=Management, subtype=Action or ActionNoAck.
pub fn parse_action(frame: &[u8]) -> Option<(MgmtHeader, ActionBody)> {
    let min_len = MGMT_HEADER_LEN + 2; // at least category + action
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    // Validate frame is actually an Action frame
    let subtype = ieee80211::fc_subtype(hdr.fc);
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || (subtype != ieee80211::frame_subtype::ACTION
            && subtype != ieee80211::frame_subtype::ACTION_NO_ACK)
    {
        return None;
    }
    let body_offset = MGMT_HEADER_LEN + 2;

    let body = ActionBody {
        category: frame[MGMT_HEADER_LEN],
        action: frame[MGMT_HEADER_LEN + 1],
        body_offset,
        body_len: frame.len().saturating_sub(body_offset),
    };

    Some((hdr, body))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Probe Request RX parser
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed Probe Request body. IEs only (SSID + Rates + capabilities).
/// Use for client tracking, PNL analysis, KARMA attacks.
#[derive(Debug, Clone)]
pub struct ProbeRequestBody {
    /// Byte offset where tagged parameters (IEs) start in the original frame
    pub ies_offset: usize,
    /// Number of IE bytes
    pub ies_len: usize,
}

/// Parse a Probe Request frame.
///
/// Body: IEs(variable) starting at offset 24 (no fixed fields).
/// Validates frame type=Management, subtype=ProbeReq before parsing body.
pub fn parse_probe_request(frame: &[u8]) -> Option<(MgmtHeader, ProbeRequestBody)> {
    if frame.len() < MGMT_HEADER_LEN {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || ieee80211::fc_subtype(hdr.fc) != ieee80211::frame_subtype::PROBE_REQ
    {
        return None;
    }

    let body = ProbeRequestBody {
        ies_offset: MGMT_HEADER_LEN,
        ies_len: frame.len().saturating_sub(MGMT_HEADER_LEN),
    };

    Some((hdr, body))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Reassociation Request RX parser
// ═══════════════════════════════════════════════════════════════════════════════

/// Reassoc Request fixed body length: Capability(2) + Listen Interval(2) + Current AP(6) = 10 bytes
const REASSOC_REQ_FIXED_LEN: usize = 10;

/// Parsed Reassociation Request body.
/// Different from AssocRequest — has 6-byte Current AP address field.
/// Use for fast roaming analysis, FT testing.
#[derive(Debug, Clone)]
pub struct ReassocRequestBody {
    /// Capability Information
    pub cap_info: u16,
    /// Listen Interval (in beacon intervals)
    pub listen_interval: u16,
    /// Current AP address (the AP the client is roaming FROM)
    pub current_ap: MacAddress,
    /// Byte offset where tagged parameters (IEs) start in the original frame
    pub ies_offset: usize,
    /// Number of IE bytes
    pub ies_len: usize,
}

/// Parse a Reassociation Request frame.
///
/// Body: Capability(2) + Listen Interval(2) + Current AP(6) + IEs(variable) at offset 24.
/// Validates frame type=Management, subtype=ReassocReq before parsing body.
pub fn parse_reassoc_request(frame: &[u8]) -> Option<(MgmtHeader, ReassocRequestBody)> {
    let min_len = MGMT_HEADER_LEN + REASSOC_REQ_FIXED_LEN;
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || ieee80211::fc_subtype(hdr.fc) != ieee80211::frame_subtype::REASSOC_REQ
    {
        return None;
    }
    let body_start = MGMT_HEADER_LEN;
    let ies_offset = body_start + REASSOC_REQ_FIXED_LEN;

    let body = ReassocRequestBody {
        cap_info: u16::from_le_bytes([frame[body_start], frame[body_start + 1]]),
        listen_interval: u16::from_le_bytes([frame[body_start + 2], frame[body_start + 3]]),
        current_ap: MacAddress::from_slice(&frame[body_start + 4..body_start + 10])?,
        ies_offset,
        ies_len: frame.len().saturating_sub(ies_offset),
    };

    Some((hdr, body))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Action frame sub-parsers — typed parsing for specific action categories
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed SA Query action frame body.
/// IEEE 802.11-2020 §9.6.8
#[derive(Debug, Clone)]
pub struct SaQueryBody {
    /// 0 = Request, 1 = Response
    pub action: u8,
    /// Transaction identifier (2 bytes). Matches request to response.
    pub transaction_id: u16,
}

/// Parse an SA Query action frame from a raw Action frame.
///
/// Expects `frame` to be the full 802.11 frame (with management header).
/// Validates: management type, action subtype, category = SA_QUERY.
/// Body: Category(1) + Action(1) + Transaction ID(2) at offset 24.
pub fn parse_sa_query(frame: &[u8]) -> Option<(MgmtHeader, SaQueryBody)> {
    let min_len = MGMT_HEADER_LEN + 4; // cat(1) + action(1) + txid(2)
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    let subtype = ieee80211::fc_subtype(hdr.fc);
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || (subtype != ieee80211::frame_subtype::ACTION
            && subtype != ieee80211::frame_subtype::ACTION_NO_ACK)
    {
        return None;
    }

    let category = frame[MGMT_HEADER_LEN];
    if category != ieee80211::action_category::SA_QUERY {
        return None;
    }

    let action = frame[MGMT_HEADER_LEN + 1];
    let txid_offset = MGMT_HEADER_LEN + 2;
    let body = SaQueryBody {
        action,
        transaction_id: u16::from_le_bytes([frame[txid_offset], frame[txid_offset + 1]]),
    };

    Some((hdr, body))
}

/// Parsed BSS Transition Management action frame body.
/// IEEE 802.11-2020 §9.6.13 (WNM)
#[derive(Debug, Clone)]
pub struct BssTransitionBody {
    /// WNM action: 6=Query, 7=Request, 8=Response
    pub action: u8,
    /// Dialog token — correlates request/response
    pub dialog_token: u8,
    /// BSS Transition Query: query reason (only for action=6)
    pub query_reason: Option<u8>,
    /// BSS Transition Request: request mode bitfield (only for action=7)
    pub request_mode: Option<u8>,
    /// BSS Transition Request: disassociation timer in TUs (only for action=7)
    pub disassoc_timer: Option<u16>,
    /// BSS Transition Request: validity interval in TUs (only for action=7)
    pub validity_interval: Option<u8>,
    /// BSS Transition Response: status code (only for action=8)
    pub status: Option<u8>,
    /// BSS Transition Response: BSS termination delay (only for action=8)
    pub bss_term_delay: Option<u8>,
    /// BSS Transition Response: target BSSID (only for action=8, if status=0)
    pub target_bssid: Option<MacAddress>,
    /// Byte offset where optional subelements start
    pub body_offset: usize,
    /// Length of remaining body bytes
    pub body_len: usize,
}

/// Parse a BSS Transition Management action frame (WNM category).
///
/// Handles Query (action=6), Request (action=7), and Response (action=8).
pub fn parse_bss_transition(frame: &[u8]) -> Option<(MgmtHeader, BssTransitionBody)> {
    let min_len = MGMT_HEADER_LEN + 3; // cat(1) + action(1) + dialog_token(1)
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    let subtype = ieee80211::fc_subtype(hdr.fc);
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || (subtype != ieee80211::frame_subtype::ACTION
            && subtype != ieee80211::frame_subtype::ACTION_NO_ACK)
    {
        return None;
    }

    let category = frame[MGMT_HEADER_LEN];
    if category != ieee80211::action_category::WNM
        && category != ieee80211::action_category::UNPROTECTED_WNM
    {
        return None;
    }

    let action = frame[MGMT_HEADER_LEN + 1];
    let dialog_token = frame[MGMT_HEADER_LEN + 2];
    let after_token = MGMT_HEADER_LEN + 3;

    match action {
        // BTM Query: dialog_token(1) + query_reason(1) + optional candidate list
        ieee80211::wnm_action::BSS_TRANSITION_MGMT_QUERY => {
            let query_reason = frame.get(after_token).copied();
            let body_start = if query_reason.is_some() { after_token + 1 } else { after_token };
            Some((hdr, BssTransitionBody {
                action, dialog_token,
                query_reason,
                request_mode: None, disassoc_timer: None, validity_interval: None,
                status: None, bss_term_delay: None, target_bssid: None,
                body_offset: body_start,
                body_len: frame.len().saturating_sub(body_start),
            }))
        }
        // BTM Request: dialog_token(1) + request_mode(1) + disassoc_timer(2) + validity_interval(1) + optional BSS term duration + optional candidate list
        ieee80211::wnm_action::BSS_TRANSITION_MGMT_REQ => {
            if frame.len() < after_token + 4 {
                return None;
            }
            let request_mode = frame[after_token];
            let disassoc_timer = u16::from_le_bytes([frame[after_token + 1], frame[after_token + 2]]);
            let validity_interval = frame[after_token + 3];
            let body_start = after_token + 4;
            Some((hdr, BssTransitionBody {
                action, dialog_token,
                query_reason: None,
                request_mode: Some(request_mode),
                disassoc_timer: Some(disassoc_timer),
                validity_interval: Some(validity_interval),
                status: None, bss_term_delay: None, target_bssid: None,
                body_offset: body_start,
                body_len: frame.len().saturating_sub(body_start),
            }))
        }
        // BTM Response: dialog_token(1) + status(1) + bss_term_delay(1) + optional target_bssid(6)
        ieee80211::wnm_action::BSS_TRANSITION_MGMT_RESP => {
            if frame.len() < after_token + 2 {
                return None;
            }
            let status = frame[after_token];
            let bss_term_delay = frame[after_token + 1];
            let body_start = after_token + 2;
            let target_bssid = if status == 0 && frame.len() >= body_start + 6 {
                MacAddress::from_slice(&frame[body_start..body_start + 6])
            } else {
                None
            };
            let final_offset = if target_bssid.is_some() { body_start + 6 } else { body_start };
            Some((hdr, BssTransitionBody {
                action, dialog_token,
                query_reason: None,
                request_mode: None, disassoc_timer: None, validity_interval: None,
                status: Some(status),
                bss_term_delay: Some(bss_term_delay),
                target_bssid,
                body_offset: final_offset,
                body_len: frame.len().saturating_sub(final_offset),
            }))
        }
        _ => None,
    }
}

/// Parsed Fast BSS Transition action frame body.
/// IEEE 802.11-2020 §9.6.10
#[derive(Debug, Clone)]
pub struct FtActionBody {
    /// FT action: 1=Request, 2=Response, 3=Confirm, 4=Ack
    pub action: u8,
    /// STA address (6 bytes)
    pub sta_addr: MacAddress,
    /// Target AP address (6 bytes)
    pub target_ap: MacAddress,
    /// Status code (only in FT Response, action=2)
    pub status: Option<u16>,
    /// Byte offset where FT IEs start
    pub ies_offset: usize,
    /// Length of FT IE bytes
    pub ies_len: usize,
}

/// Parse a Fast BSS Transition action frame.
///
/// Body: Category(1) + Action(1) + STA Addr(6) + Target AP(6) + [Status(2)] + FT IEs
pub fn parse_ft_action(frame: &[u8]) -> Option<(MgmtHeader, FtActionBody)> {
    let min_len = MGMT_HEADER_LEN + 14; // cat(1)+action(1)+sta(6)+ap(6)
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    let subtype = ieee80211::fc_subtype(hdr.fc);
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || (subtype != ieee80211::frame_subtype::ACTION
            && subtype != ieee80211::frame_subtype::ACTION_NO_ACK)
    {
        return None;
    }

    let category = frame[MGMT_HEADER_LEN];
    if category != ieee80211::action_category::FAST_BSS_TRANSITION {
        return None;
    }

    let action = frame[MGMT_HEADER_LEN + 1];
    let sta_offset = MGMT_HEADER_LEN + 2;
    let ap_offset = sta_offset + 6;
    let sta_addr = MacAddress::from_slice(&frame[sta_offset..sta_offset + 6])?;
    let target_ap = MacAddress::from_slice(&frame[ap_offset..ap_offset + 6])?;

    // FT Response (action=2) has a 2-byte status code before IEs
    let (status, ies_offset) = if action == ieee80211::ft_action::FT_RESPONSE {
        if frame.len() < ap_offset + 6 + 2 {
            return None;
        }
        let s = u16::from_le_bytes([frame[ap_offset + 6], frame[ap_offset + 7]]);
        (Some(s), ap_offset + 8)
    } else {
        (None, ap_offset + 6)
    };

    let body = FtActionBody {
        action,
        sta_addr,
        target_ap,
        status,
        ies_offset,
        ies_len: frame.len().saturating_sub(ies_offset),
    };

    Some((hdr, body))
}

/// Parsed Spectrum Management action frame body.
/// IEEE 802.11-2020 §9.6.2
#[derive(Debug, Clone)]
pub struct SpectrumMgmtBody {
    /// Spectrum action code (0-4)
    pub action: u8,
    /// Dialog token
    pub dialog_token: u8,
    /// Byte offset where action-specific elements start
    pub elements_offset: usize,
    /// Length of element bytes
    pub elements_len: usize,
}

/// Parse a Spectrum Management action frame.
///
/// Body: Category(1) + Action(1) + Dialog Token(1) + Elements
pub fn parse_spectrum_mgmt(frame: &[u8]) -> Option<(MgmtHeader, SpectrumMgmtBody)> {
    let min_len = MGMT_HEADER_LEN + 3; // cat(1) + action(1) + dialog_token(1)
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    let subtype = ieee80211::fc_subtype(hdr.fc);
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || (subtype != ieee80211::frame_subtype::ACTION
            && subtype != ieee80211::frame_subtype::ACTION_NO_ACK)
    {
        return None;
    }

    let category = frame[MGMT_HEADER_LEN];
    if category != ieee80211::action_category::SPECTRUM_MGMT {
        return None;
    }

    let action = frame[MGMT_HEADER_LEN + 1];
    let dialog_token = frame[MGMT_HEADER_LEN + 2];
    let elements_offset = MGMT_HEADER_LEN + 3;

    let body = SpectrumMgmtBody {
        action,
        dialog_token,
        elements_offset,
        elements_len: frame.len().saturating_sub(elements_offset),
    };

    Some((hdr, body))
}

/// Parsed Radio Measurement action frame body.
/// IEEE 802.11-2020 §9.6.6
#[derive(Debug, Clone)]
pub struct RadioMeasurementBody {
    /// Radio measurement action code (0-5)
    pub action: u8,
    /// Dialog token
    pub dialog_token: u8,
    /// Number of repetitions (only for Measurement Request, action=0). 0=stop, 65535=indefinite.
    pub num_repetitions: Option<u16>,
    /// Byte offset where measurement elements start
    pub elements_offset: usize,
    /// Length of element bytes
    pub elements_len: usize,
}

/// Parse a Radio Measurement action frame.
///
/// Measurement Request: Category(1) + Action(1) + Dialog Token(1) + Num Repetitions(2) + Elements
/// Others: Category(1) + Action(1) + Dialog Token(1) + Elements
pub fn parse_radio_measurement(frame: &[u8]) -> Option<(MgmtHeader, RadioMeasurementBody)> {
    let min_len = MGMT_HEADER_LEN + 3;
    if frame.len() < min_len {
        return None;
    }

    let hdr = parse_mgmt_header(frame)?;

    let subtype = ieee80211::fc_subtype(hdr.fc);
    if ieee80211::fc_type(hdr.fc) != ieee80211::frame_type::MANAGEMENT
        || (subtype != ieee80211::frame_subtype::ACTION
            && subtype != ieee80211::frame_subtype::ACTION_NO_ACK)
    {
        return None;
    }

    let category = frame[MGMT_HEADER_LEN];
    if category != ieee80211::action_category::RADIO_MEASUREMENT {
        return None;
    }

    let action = frame[MGMT_HEADER_LEN + 1];
    let dialog_token = frame[MGMT_HEADER_LEN + 2];

    // Measurement Request (action=0) has a 2-byte num_repetitions field
    let (num_repetitions, elements_offset) = if action == ieee80211::radio_measurement_action::RADIO_MEASUREMENT_REQ {
        if frame.len() < MGMT_HEADER_LEN + 5 {
            return None;
        }
        let nr = u16::from_le_bytes([frame[MGMT_HEADER_LEN + 3], frame[MGMT_HEADER_LEN + 4]]);
        (Some(nr), MGMT_HEADER_LEN + 5)
    } else {
        (None, MGMT_HEADER_LEN + 3)
    };

    let body = RadioMeasurementBody {
        action,
        dialog_token,
        num_repetitions,
        elements_offset,
        elements_len: frame.len().saturating_sub(elements_offset),
    };

    Some((hdr, body))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Control frame parsers
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed RTS (Request to Send) frame.
/// Layout: FC(2) + Duration(2) + RA(6) + TA(6) = 16 bytes
#[derive(Debug, Clone)]
pub struct RtsFrame {
    pub fc: u16,
    pub duration: u16,
    /// Receiver Address
    pub ra: MacAddress,
    /// Transmitter Address
    pub ta: MacAddress,
}

/// Parse a RTS frame. Returns None if too short or wrong type.
pub fn parse_rts(frame: &[u8]) -> Option<RtsFrame> {
    if frame.len() < 16 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if ieee80211::fc_type(fc) != ieee80211::frame_type::CONTROL
        || ieee80211::fc_subtype(fc) != ieee80211::control_subtype::RTS
    {
        return None;
    }
    Some(RtsFrame {
        fc,
        duration: u16::from_le_bytes([frame[2], frame[3]]),
        ra: MacAddress::from_slice(&frame[4..10])?,
        ta: MacAddress::from_slice(&frame[10..16])?,
    })
}

/// Parsed CTS (Clear to Send) frame.
/// Layout: FC(2) + Duration(2) + RA(6) = 10 bytes
#[derive(Debug, Clone)]
pub struct CtsFrame {
    pub fc: u16,
    pub duration: u16,
    /// Receiver Address
    pub ra: MacAddress,
}

/// Parse a CTS frame. Returns None if too short or wrong type.
pub fn parse_cts(frame: &[u8]) -> Option<CtsFrame> {
    if frame.len() < 10 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if ieee80211::fc_type(fc) != ieee80211::frame_type::CONTROL
        || ieee80211::fc_subtype(fc) != ieee80211::control_subtype::CTS
    {
        return None;
    }
    Some(CtsFrame {
        fc,
        duration: u16::from_le_bytes([frame[2], frame[3]]),
        ra: MacAddress::from_slice(&frame[4..10])?,
    })
}

/// Parsed ACK frame.
/// Layout: FC(2) + Duration(2) + RA(6) = 10 bytes
#[derive(Debug, Clone)]
pub struct AckFrame {
    pub fc: u16,
    pub duration: u16,
    /// Receiver Address
    pub ra: MacAddress,
}

/// Parse an ACK frame. Returns None if too short or wrong type.
pub fn parse_ack(frame: &[u8]) -> Option<AckFrame> {
    if frame.len() < 10 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if ieee80211::fc_type(fc) != ieee80211::frame_type::CONTROL
        || ieee80211::fc_subtype(fc) != ieee80211::control_subtype::ACK
    {
        return None;
    }
    Some(AckFrame {
        fc,
        duration: u16::from_le_bytes([frame[2], frame[3]]),
        ra: MacAddress::from_slice(&frame[4..10])?,
    })
}

/// Parsed Block Ack Request frame.
/// Layout: FC(2) + Duration(2) + RA(6) + TA(6) + BAR Control(2) + Starting Seq Control(2) = 20 bytes
#[derive(Debug, Clone)]
pub struct BlockAckReqFrame {
    pub fc: u16,
    pub duration: u16,
    pub ra: MacAddress,
    pub ta: MacAddress,
    /// BAR Control: bit 12 = Multi-TID, bits 12-15 = TID info
    pub bar_control: u16,
    /// Starting Sequence Control: bits 4-15 = starting sequence number
    pub starting_seq_ctrl: u16,
}

impl BlockAckReqFrame {
    /// TID (Traffic Identifier) from BAR Control bits 12-15
    pub fn tid(&self) -> u8 {
        ((self.bar_control >> 12) & 0x0F) as u8
    }

    /// Starting sequence number (upper 12 bits)
    pub fn starting_seq(&self) -> u16 {
        self.starting_seq_ctrl >> 4
    }
}

/// Parse a Block Ack Request frame.
pub fn parse_block_ack_req(frame: &[u8]) -> Option<BlockAckReqFrame> {
    if frame.len() < 20 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if ieee80211::fc_type(fc) != ieee80211::frame_type::CONTROL
        || ieee80211::fc_subtype(fc) != ieee80211::control_subtype::BLOCK_ACK_REQ
    {
        return None;
    }
    Some(BlockAckReqFrame {
        fc,
        duration: u16::from_le_bytes([frame[2], frame[3]]),
        ra: MacAddress::from_slice(&frame[4..10])?,
        ta: MacAddress::from_slice(&frame[10..16])?,
        bar_control: u16::from_le_bytes([frame[16], frame[17]]),
        starting_seq_ctrl: u16::from_le_bytes([frame[18], frame[19]]),
    })
}

/// Parsed Block Ack frame.
/// Layout: FC(2) + Duration(2) + RA(6) + TA(6) + BA Control(2) + Block Ack Bitmap(8 or 128)
#[derive(Debug, Clone)]
pub struct BlockAckFrame {
    pub fc: u16,
    pub duration: u16,
    pub ra: MacAddress,
    pub ta: MacAddress,
    /// BA Control: bit 0 = BA policy, bits 12-15 = TID
    pub ba_control: u16,
    /// Block Ack Starting Sequence Control (2 bytes before bitmap)
    pub starting_seq_ctrl: u16,
    /// Bitmap length in bytes (8 for basic, 128 for compressed)
    pub bitmap_len: usize,
    /// Byte offset where bitmap starts in the original frame
    pub bitmap_offset: usize,
}

impl BlockAckFrame {
    /// TID (Traffic Identifier) from BA Control bits 12-15
    pub fn tid(&self) -> u8 {
        ((self.ba_control >> 12) & 0x0F) as u8
    }

    /// Starting sequence number (upper 12 bits)
    pub fn starting_seq(&self) -> u16 {
        self.starting_seq_ctrl >> 4
    }
}

/// Parse a Block Ack frame.
pub fn parse_block_ack(frame: &[u8]) -> Option<BlockAckFrame> {
    // Minimum: FC(2) + Dur(2) + RA(6) + TA(6) + BA Ctrl(2) + SSC(2) + Bitmap(8) = 28
    if frame.len() < 28 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if ieee80211::fc_type(fc) != ieee80211::frame_type::CONTROL
        || ieee80211::fc_subtype(fc) != ieee80211::control_subtype::BLOCK_ACK
    {
        return None;
    }
    let ba_control = u16::from_le_bytes([frame[16], frame[17]]);
    let starting_seq_ctrl = u16::from_le_bytes([frame[18], frame[19]]);
    let bitmap_offset = 20;
    let bitmap_len = frame.len().saturating_sub(bitmap_offset);

    Some(BlockAckFrame {
        fc,
        duration: u16::from_le_bytes([frame[2], frame[3]]),
        ra: MacAddress::from_slice(&frame[4..10])?,
        ta: MacAddress::from_slice(&frame[10..16])?,
        ba_control,
        starting_seq_ctrl,
        bitmap_len,
        bitmap_offset,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  QoS Data frame parser
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed QoS Control field from QoS Data frames.
/// QoS Data frames have subtype bit 7 set (0x80 | subtype).
/// QoS Control is 2 bytes at offset 24 (after management-sized header).
#[derive(Debug, Clone, Copy)]
pub struct QosControl {
    /// Raw QoS Control field
    pub raw: u16,
    /// Traffic Identifier (bits 0-3) — maps to Access Category
    pub tid: u8,
    /// End of Service Period (bit 4)
    pub eosp: bool,
    /// Ack Policy (bits 5-6): 0=normal, 1=no-ack, 2=no-explicit, 3=block-ack
    pub ack_policy: u8,
    /// A-MSDU present (bit 7) — when set, payload contains aggregated MSDUs
    pub amsdu_present: bool,
}

/// Parse QoS Control from a data frame.
///
/// Data frames with QoS have subtype & 0x08 set (subtypes 8-15).
/// QoS Control is 2 bytes at offset 24, making the MAC header 26 bytes instead of 24.
/// `frame` is the full 802.11 frame.
pub fn parse_qos_control(frame: &[u8]) -> Option<QosControl> {
    if frame.len() < 26 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if ieee80211::fc_type(fc) != ieee80211::frame_type::DATA {
        return None;
    }
    // QoS subtype has bit 3 set (subtypes 8-15)
    let subtype = ieee80211::fc_subtype(fc);
    if subtype & 0x08 == 0 {
        return None; // Not a QoS data frame
    }

    let raw = u16::from_le_bytes([frame[24], frame[25]]);
    Some(QosControl {
        raw,
        tid: (raw & 0x0F) as u8,
        eosp: (raw & 0x10) != 0,
        ack_policy: ((raw >> 5) & 0x03) as u8,
        amsdu_present: (raw & 0x80) != 0,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  A-MSDU deaggregation
// ═══════════════════════════════════════════════════════════════════════════════

/// A single subframe within an A-MSDU aggregate.
#[derive(Debug, Clone)]
pub struct AmsduSubframe {
    /// Destination Address
    pub da: MacAddress,
    /// Source Address
    pub sa: MacAddress,
    /// MSDU length
    pub length: u16,
    /// Byte offset of MSDU payload in the original frame
    pub payload_offset: usize,
    /// MSDU payload length
    pub payload_len: usize,
}

/// Deaggregate an A-MSDU payload into individual subframes.
///
/// `data` is the payload AFTER the QoS MAC header (offset 26 for QoS data, or after
/// the 4-addr header if To DS + From DS are both set).
///
/// Each subframe: DA(6) + SA(6) + Length(2) + MSDU(Length) + Padding(0-3 to 4-byte boundary)
/// Returns all parseable subframes. Stops at first malformed subframe.
pub fn amsdu_deaggregate(data: &[u8]) -> Vec<AmsduSubframe> {
    let mut subframes = Vec::new();
    let mut offset = 0;

    while offset + 14 <= data.len() { // DA(6) + SA(6) + Length(2) = 14 byte header
        let da = match MacAddress::from_slice(&data[offset..offset + 6]) {
            Some(m) => m,
            None => break,
        };
        let sa = match MacAddress::from_slice(&data[offset + 6..offset + 12]) {
            Some(m) => m,
            None => break,
        };
        let length = u16::from_be_bytes([data[offset + 12], data[offset + 13]]);
        let payload_offset = offset + 14;

        if payload_offset + length as usize > data.len() {
            break; // Truncated subframe — stop, don't error
        }

        subframes.push(AmsduSubframe {
            da,
            sa,
            length,
            payload_offset,
            payload_len: length as usize,
        });

        // Advance past payload + padding to 4-byte boundary
        let total = 14 + length as usize;
        let padded = (total + 3) & !3;
        offset += padded;
    }

    subframes
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ieee80211::{auth_algo, cap_info};

    // Known test MACs (from our hardware test environment)
    const AP_MAC: MacAddress = MacAddress([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
    const OUR_MAC: MacAddress = MacAddress([0x8C, 0x88, 0x2B, 0xAA, 0xBB, 0xCC]);
    const CLIENT_MAC: MacAddress = MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);

    // ── Auth frame tests ──

    #[test]
    fn test_build_auth_size_and_fc() {
        let frame = build_auth(&OUR_MAC, &AP_MAC, auth_algo::OPEN_SYSTEM, 1, StatusCode::Success);
        assert_eq!(frame.len(), 30); // 24 header + 6 body
        assert_eq!(frame[0], fc::AUTH);
        assert_eq!(frame[1], 0x00);
    }

    #[test]
    fn test_build_auth_addresses() {
        let frame = build_auth(&OUR_MAC, &AP_MAC, auth_algo::OPEN_SYSTEM, 1, StatusCode::Success);
        // DA = BSSID = AP
        assert_eq!(&frame[4..10], AP_MAC.as_bytes());
        // SA = our MAC
        assert_eq!(&frame[10..16], OUR_MAC.as_bytes());
        // Addr3 = BSSID = AP
        assert_eq!(&frame[16..22], AP_MAC.as_bytes());
    }

    #[test]
    fn test_build_auth_body_fields() {
        let frame = build_auth(&OUR_MAC, &AP_MAC, auth_algo::OPEN_SYSTEM, 1, StatusCode::Success);
        // Auth algo (LE) at offset 24
        assert_eq!(u16::from_le_bytes([frame[24], frame[25]]), auth_algo::OPEN_SYSTEM);
        // Auth seq at offset 26
        assert_eq!(u16::from_le_bytes([frame[26], frame[27]]), 1);
        // Status at offset 28
        assert_eq!(u16::from_le_bytes([frame[28], frame[29]]), 0); // Success
    }

    #[test]
    fn test_build_auth_sae_algo() {
        let frame = build_auth(&OUR_MAC, &AP_MAC, auth_algo::SAE, 1, StatusCode::Success);
        assert_eq!(u16::from_le_bytes([frame[24], frame[25]]), auth_algo::SAE);
    }

    #[test]
    fn test_build_auth_duration() {
        let frame = build_auth(&OUR_MAC, &AP_MAC, auth_algo::OPEN_SYSTEM, 1, StatusCode::Success);
        let dur = u16::from_le_bytes([frame[2], frame[3]]);
        assert_eq!(dur, DEFAULT_DURATION); // 314 μs
    }

    #[test]
    fn test_build_auth_roundtrip() {
        let frame = build_auth(&OUR_MAC, &AP_MAC, auth_algo::SAE, 2, StatusCode::AntiCloggingTokenRequired);
        let (hdr, body) = parse_auth(&frame).expect("parse_auth failed");
        assert_eq!(hdr.addr1, AP_MAC);
        assert_eq!(hdr.addr2, OUR_MAC);
        assert_eq!(hdr.addr3, AP_MAC);
        assert_eq!(body.algo, auth_algo::SAE);
        assert_eq!(body.seq, 2);
        assert_eq!(body.status, StatusCode::AntiCloggingTokenRequired as u16);
    }

    // ── Auth Response tests ──

    #[test]
    fn test_build_auth_response_addresses() {
        let frame = build_auth_response(&CLIENT_MAC, &AP_MAC, auth_algo::OPEN_SYSTEM, StatusCode::Success);
        assert_eq!(frame.len(), 30);
        // DA = client
        assert_eq!(&frame[4..10], CLIENT_MAC.as_bytes());
        // SA = BSSID = AP
        assert_eq!(&frame[10..16], AP_MAC.as_bytes());
        assert_eq!(&frame[16..22], AP_MAC.as_bytes());
    }

    #[test]
    fn test_build_auth_response_seq_is_2() {
        let frame = build_auth_response(&CLIENT_MAC, &AP_MAC, auth_algo::OPEN_SYSTEM, StatusCode::Success);
        // Auth seq = 2 (response)
        assert_eq!(u16::from_le_bytes([frame[26], frame[27]]), 2);
    }

    #[test]
    fn test_build_auth_response_status() {
        let frame = build_auth_response(&CLIENT_MAC, &AP_MAC, auth_algo::OPEN_SYSTEM, StatusCode::ApFull);
        assert_eq!(u16::from_le_bytes([frame[28], frame[29]]), StatusCode::ApFull as u16);
    }

    // ── Assoc Request tests ──

    #[test]
    fn test_build_assoc_request_no_ies() {
        let frame = build_assoc_request(&OUR_MAC, &AP_MAC, cap_info::BASE, 0, &[]).unwrap();
        assert_eq!(frame.len(), 28); // 24 + 4
        assert_eq!(frame[0], fc::ASSOC_REQ);
    }

    #[test]
    fn test_build_assoc_request_cap_info() {
        let cap = cap_info::BASE | cap_info::PRIVACY;
        let frame = build_assoc_request(&OUR_MAC, &AP_MAC, cap, 0, &[]).unwrap();
        let parsed_cap = u16::from_le_bytes([frame[24], frame[25]]);
        assert_eq!(parsed_cap, cap);
    }

    #[test]
    fn test_build_assoc_request_listen_interval_default() {
        let frame = build_assoc_request(&OUR_MAC, &AP_MAC, cap_info::BASE, 0, &[]).unwrap();
        let li = u16::from_le_bytes([frame[26], frame[27]]);
        assert_eq!(li, DEFAULT_LISTEN_INTERVAL);
    }

    #[test]
    fn test_build_assoc_request_with_ies() {
        let ies = [0x00, 0x04, b'T', b'e', b's', b't']; // SSID IE: "Test"
        let frame = build_assoc_request(&OUR_MAC, &AP_MAC, cap_info::BASE, 5, &ies).unwrap();
        assert_eq!(frame.len(), 34); // 24 + 4 + 6
        // IEs start at offset 28
        assert_eq!(&frame[28..34], &ies);
    }

    #[test]
    fn test_build_assoc_request_roundtrip() {
        let ies = [0x00, 0x03, b'A', b'B', b'C'];
        let cap = cap_info::BASE | cap_info::PRIVACY;
        let frame = build_assoc_request(&OUR_MAC, &AP_MAC, cap, 7, &ies).unwrap();
        let (hdr, body) = parse_assoc_request(&frame).expect("parse failed");
        assert_eq!(hdr.addr1, AP_MAC);
        assert_eq!(hdr.addr2, OUR_MAC);
        assert_eq!(body.cap_info, cap);
        assert_eq!(body.listen_interval, 7);
        assert_eq!(body.ies_len, ies.len());
        assert_eq!(&frame[body.ies_offset..body.ies_offset + body.ies_len], &ies);
    }

    #[test]
    fn test_build_assoc_request_overflow_returns_none() {
        let huge_ies = vec![0u8; MAX_FRAME_LEN]; // way too big
        assert!(build_assoc_request(&OUR_MAC, &AP_MAC, 0, 0, &huge_ies).is_none());
    }

    // ── Reassoc Request tests ──

    #[test]
    fn test_build_reassoc_request_has_current_ap() {
        let old_ap = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let frame = build_reassoc_request(&OUR_MAC, &AP_MAC, &old_ap, cap_info::BASE, 0, &[]).unwrap();
        assert_eq!(frame[0], fc::REASSOC_REQ);
        assert_eq!(frame.len(), 34); // 24 + 4 + 6 (current AP) + 0 (no IEs)
        // Current AP address at offset 28 (after cap_info + listen_interval)
        assert_eq!(&frame[28..34], old_ap.as_bytes());
    }

    // ── Assoc Response tests ──

    #[test]
    fn test_build_assoc_response_aid_bits() {
        let frame = build_assoc_response(
            &CLIENT_MAC, &AP_MAC, StatusCode::Success, 42, cap_info::BASE, &[],
        ).unwrap();
        assert_eq!(frame.len(), 30); // 24 + 6
        assert_eq!(frame[0], fc::ASSOC_RESP);

        // AID at offset 28-29 should have bits 14-15 set
        let raw_aid = u16::from_le_bytes([frame[28], frame[29]]);
        assert_eq!(raw_aid & 0xC000, 0xC000); // bits 14-15 set
        assert_eq!(raw_aid & 0x3FFF, 42);     // actual AID value
    }

    #[test]
    fn test_build_assoc_response_roundtrip() {
        let ies = [0x01, 0x02, 0x0C, 0x18]; // Supported Rates IE
        let frame = build_assoc_response(
            &CLIENT_MAC, &AP_MAC, StatusCode::Success, 100, cap_info::BASE, &ies,
        ).unwrap();
        let (hdr, body) = parse_assoc_response(&frame).expect("parse failed");
        assert_eq!(hdr.addr1, CLIENT_MAC);
        assert_eq!(hdr.addr2, AP_MAC);
        assert_eq!(body.cap_info, cap_info::BASE);
        assert_eq!(body.status, StatusCode::Success as u16);
        assert_eq!(body.aid, 100); // bits 14-15 stripped
        assert_eq!(&frame[body.ies_offset..body.ies_offset + body.ies_len], &ies);
    }

    // ── Deauth tests ──

    #[test]
    fn test_build_deauth_size_and_fc() {
        let frame = build_deauth(&AP_MAC, &MacAddress::BROADCAST, &AP_MAC, ReasonCode::DeauthLeaving);
        assert_eq!(frame.len(), 26); // 24 + 2
        assert_eq!(frame[0], fc::DEAUTH);
    }

    #[test]
    fn test_build_deauth_broadcast() {
        let frame = build_deauth(&AP_MAC, &MacAddress::BROADCAST, &AP_MAC, ReasonCode::Unspecified);
        // DA = broadcast
        assert_eq!(&frame[4..10], MacAddress::BROADCAST.as_bytes());
        // SA = AP
        assert_eq!(&frame[10..16], AP_MAC.as_bytes());
        // BSSID = AP
        assert_eq!(&frame[16..22], AP_MAC.as_bytes());
    }

    #[test]
    fn test_build_deauth_targeted() {
        let frame = build_deauth(&AP_MAC, &CLIENT_MAC, &AP_MAC, ReasonCode::Class2FromNonAuth);
        assert_eq!(&frame[4..10], CLIENT_MAC.as_bytes());
        let reason = u16::from_le_bytes([frame[24], frame[25]]);
        assert_eq!(reason, ReasonCode::Class2FromNonAuth as u16);
    }

    #[test]
    fn test_build_deauth_duration_zero() {
        let frame = build_deauth(&AP_MAC, &CLIENT_MAC, &AP_MAC, ReasonCode::Unspecified);
        // Deauth uses duration=0
        assert_eq!(u16::from_le_bytes([frame[2], frame[3]]), 0);
    }

    #[test]
    fn test_build_deauth_roundtrip() {
        let frame = build_deauth(&AP_MAC, &CLIENT_MAC, &AP_MAC, ReasonCode::MicFailure);
        let (hdr, body) = parse_deauth(&frame).expect("parse failed");
        assert_eq!(hdr.addr1, CLIENT_MAC);
        assert_eq!(hdr.addr2, AP_MAC);
        assert_eq!(body.reason, ReasonCode::MicFailure as u16);
    }

    // ── Disassoc tests ──

    #[test]
    fn test_build_disassoc_size_and_fc() {
        let frame = build_disassoc(&OUR_MAC, &AP_MAC, &AP_MAC, ReasonCode::DisassocLeaving);
        assert_eq!(frame.len(), 26);
        assert_eq!(frame[0], fc::DISASSOC);
    }

    #[test]
    fn test_build_disassoc_roundtrip() {
        let frame = build_disassoc(&OUR_MAC, &AP_MAC, &AP_MAC, ReasonCode::Inactivity);
        let (hdr, body) = parse_disassoc(&frame).expect("parse failed");
        assert_eq!(hdr.addr2, OUR_MAC);
        assert_eq!(body.reason, ReasonCode::Inactivity as u16);
    }

    // ── Probe Request tests ──

    #[test]
    fn test_build_probe_request_broadcast() {
        let frame = build_probe_request(&OUR_MAC, "TestNet", &[]).unwrap();
        assert_eq!(frame[0], fc::PROBE_REQ);
        // DA = broadcast
        assert_eq!(&frame[4..10], MacAddress::BROADCAST.as_bytes());
        // SA = our MAC
        assert_eq!(&frame[10..16], OUR_MAC.as_bytes());
        // BSSID = broadcast (wildcard)
        assert_eq!(&frame[16..22], MacAddress::BROADCAST.as_bytes());
    }

    #[test]
    fn test_build_probe_request_ssid_ie() {
        let frame = build_probe_request(&OUR_MAC, "Hello", &[]).unwrap();
        // SSID IE at offset 24: tag=0, len=5, "Hello"
        assert_eq!(frame[24], 0x00); // SSID tag
        assert_eq!(frame[25], 5);    // length
        assert_eq!(&frame[26..31], b"Hello");
    }

    #[test]
    fn test_build_probe_request_wildcard_ssid() {
        let frame = build_probe_request(&OUR_MAC, "", &[]).unwrap();
        // Wildcard: tag=0, len=0
        assert_eq!(frame[24], 0x00);
        assert_eq!(frame[25], 0x00);
    }

    #[test]
    fn test_build_probe_request_supported_rates() {
        let frame = build_probe_request(&OUR_MAC, "", &[]).unwrap();
        // After SSID IE (2 bytes for wildcard), Supported Rates IE at offset 26
        assert_eq!(frame[26], 0x01); // Supported Rates tag
        assert_eq!(frame[27], 0x08); // 8 rates
        // First rate: 1 Mbps mandatory (0x82)
        assert_eq!(frame[28], 0x82);
    }

    #[test]
    fn test_build_probe_request_extended_rates() {
        let frame = build_probe_request(&OUR_MAC, "", &[]).unwrap();
        // Extended Rates IE after SSID(2) + Rates(10) = offset 36
        assert_eq!(frame[36], 0x32); // Extended Rates tag (50)
        assert_eq!(frame[37], 0x04); // 4 rates
    }

    #[test]
    fn test_build_probe_request_too_long_ssid() {
        let long_ssid = "A".repeat(33);
        assert!(build_probe_request(&OUR_MAC, &long_ssid, &[]).is_none());
    }

    // ── Beacon tests ──

    #[test]
    fn test_build_beacon_structure() {
        let ies = [0x00, 0x04, b'T', b'e', b's', b't']; // SSID IE
        let frame = build_beacon(&AP_MAC, 1000, 100, cap_info::BASE, &ies).unwrap();

        assert_eq!(frame[0], fc::BEACON);
        // DA = broadcast
        assert_eq!(&frame[4..10], MacAddress::BROADCAST.as_bytes());
        // SA = BSSID
        assert_eq!(&frame[10..16], AP_MAC.as_bytes());
        assert_eq!(&frame[16..22], AP_MAC.as_bytes());
    }

    #[test]
    fn test_build_beacon_fixed_fields() {
        let frame = build_beacon(&AP_MAC, 0x123456789ABCDEF0, 200, cap_info::BASE, &[]).unwrap();

        // TSF at offset 24 (8 bytes LE)
        let tsf = u64::from_le_bytes(frame[24..32].try_into().unwrap());
        assert_eq!(tsf, 0x123456789ABCDEF0);

        // Beacon interval at offset 32 (2 bytes LE)
        let bi = u16::from_le_bytes([frame[32], frame[33]]);
        assert_eq!(bi, 200);

        // Cap info at offset 34 (2 bytes LE)
        let cap = u16::from_le_bytes([frame[34], frame[35]]);
        assert_eq!(cap, cap_info::BASE);
    }

    #[test]
    fn test_build_beacon_default_interval() {
        let frame = build_beacon(&AP_MAC, 0, 0, cap_info::BASE, &[]).unwrap();
        let bi = u16::from_le_bytes([frame[32], frame[33]]);
        assert_eq!(bi, DEFAULT_BEACON_INTERVAL);
    }

    #[test]
    fn test_build_beacon_roundtrip() {
        let ies = [0x00, 0x03, b'A', b'P', b'!'];
        let frame = build_beacon(&AP_MAC, 5000, 100, cap_info::BASE | cap_info::PRIVACY, &ies).unwrap();
        let (hdr, body) = parse_beacon(&frame).expect("parse failed");
        assert_eq!(hdr.addr2, AP_MAC);
        assert_eq!(hdr.addr3, AP_MAC);
        assert_eq!(body.tsf, 5000);
        assert_eq!(body.beacon_interval, 100);
        assert_eq!(body.cap_info, cap_info::BASE | cap_info::PRIVACY);
        assert_eq!(&frame[body.ies_offset..body.ies_offset + body.ies_len], &ies);
    }

    // ── Probe Response tests ──

    #[test]
    fn test_build_probe_response_addresses() {
        let frame = build_probe_response(&AP_MAC, &CLIENT_MAC, 0, 100, cap_info::BASE, &[]).unwrap();
        assert_eq!(frame[0], fc::PROBE_RESP);
        // DA = requesting station
        assert_eq!(&frame[4..10], CLIENT_MAC.as_bytes());
        // SA = BSSID
        assert_eq!(&frame[10..16], AP_MAC.as_bytes());
        assert_eq!(&frame[16..22], AP_MAC.as_bytes());
    }

    // ── Action frame tests ──

    #[test]
    fn test_build_action_generic() {
        let body = [0x01, 0x02, 0x03];
        let frame = build_action(
            &OUR_MAC, &AP_MAC, &AP_MAC,
            ieee80211::action_category::SA_QUERY, 0, &body,
        ).unwrap();
        assert_eq!(frame[0], fc::ACTION);
        assert_eq!(frame[24], ieee80211::action_category::SA_QUERY);
        assert_eq!(frame[25], 0); // action code
        assert_eq!(&frame[26..29], &body);
    }

    #[test]
    fn test_build_action_roundtrip() {
        let body = [0xAA, 0xBB];
        let frame = build_action(
            &OUR_MAC, &AP_MAC, &AP_MAC,
            ieee80211::action_category::WNM, 7, &body,
        ).unwrap();
        let (hdr, parsed) = parse_action(&frame).expect("parse failed");
        assert_eq!(hdr.addr2, OUR_MAC);
        assert_eq!(parsed.category, ieee80211::action_category::WNM);
        assert_eq!(parsed.action, 7);
        assert_eq!(&frame[parsed.body_offset..parsed.body_offset + parsed.body_len], &body);
    }

    // ── CSA Action frame tests ──

    #[test]
    fn test_build_csa_action_structure() {
        let frame = build_csa_action(&AP_MAC, &MacAddress::BROADCAST, &AP_MAC, 11, 3);
        assert_eq!(frame[0], fc::ACTION);
        // Category = Spectrum Management (0)
        assert_eq!(frame[24], ieee80211::action_category::SPECTRUM_MGMT);
        // Action = Channel Switch Announcement (4)
        assert_eq!(frame[25], 4);
        // CSA Element
        assert_eq!(frame[26], csa::ELEMENT_ID); // 37
        assert_eq!(frame[27], csa::ELEMENT_LEN); // 3
        assert_eq!(frame[28], 1);   // mode: cease transmissions
        assert_eq!(frame[29], 11);  // new channel
        assert_eq!(frame[30], 3);   // count
    }

    // ── CSA Beacon tests ──

    #[test]
    fn test_build_csa_beacon_appends_csa_ie() {
        let ies = [0x00, 0x02, b'A', b'P']; // SSID IE
        let frame = build_csa_beacon(&AP_MAC, 0, 100, cap_info::BASE, 6, 5, &ies).unwrap();
        assert_eq!(frame[0], fc::BEACON);

        // IEs start at offset 36 (24 header + 12 beacon fixed)
        let ies_start = 36;
        // Original IEs should be there
        assert_eq!(&frame[ies_start..ies_start + 4], &ies);
        // CSA IE appended after
        let csa_start = ies_start + ies.len();
        assert_eq!(frame[csa_start], csa::ELEMENT_ID);   // 37
        assert_eq!(frame[csa_start + 1], csa::ELEMENT_LEN); // 3
        assert_eq!(frame[csa_start + 2], 1);   // mode
        assert_eq!(frame[csa_start + 3], 6);   // new channel
        assert_eq!(frame[csa_start + 4], 5);   // count
    }

    // ── Parser edge cases ──

    #[test]
    fn test_parse_mgmt_header_too_short() {
        assert!(parse_mgmt_header(&[0; 23]).is_none());
        assert!(parse_mgmt_header(&[0; 24]).is_some());
    }

    #[test]
    fn test_parse_auth_too_short() {
        assert!(parse_auth(&[0; 29]).is_none()); // needs 30
        let frame = build_auth(&OUR_MAC, &AP_MAC, 0, 1, StatusCode::Success);
        assert!(parse_auth(&frame).is_some());
    }

    #[test]
    fn test_parse_assoc_request_too_short() {
        assert!(parse_assoc_request(&[0; 27]).is_none()); // needs 28
    }

    #[test]
    fn test_parse_assoc_response_too_short() {
        assert!(parse_assoc_response(&[0; 29]).is_none()); // needs 30
    }

    #[test]
    fn test_parse_beacon_too_short() {
        assert!(parse_beacon(&[0; 35]).is_none()); // needs 36
    }

    #[test]
    fn test_parse_deauth_too_short() {
        assert!(parse_deauth(&[0; 25]).is_none()); // needs 26
    }

    #[test]
    fn test_parse_action_too_short() {
        assert!(parse_action(&[0; 25]).is_none()); // needs 26
    }

    #[test]
    fn test_mgmt_header_sequence_number() {
        let mut frame = build_auth(&OUR_MAC, &AP_MAC, 0, 1, StatusCode::Success);
        // Set seq_ctrl to seq=42, frag=3 → (42 << 4) | 3 = 0x02A3
        frame[22] = 0xA3;
        frame[23] = 0x02;
        let hdr = parse_mgmt_header(&frame).unwrap();
        assert_eq!(hdr.sequence_number(), 42);
        assert_eq!(hdr.fragment_number(), 3);
    }

    // ── Byte-level verification: match C reference exactly ──

    #[test]
    fn test_auth_matches_c_reference() {
        // Verify our output matches wifikit_frames.c::wifikit_send_auth()
        let sa = MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);
        let bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        let frame = build_auth(&sa, &bssid, auth_algo::OPEN_SYSTEM, 1, StatusCode::Success);

        // FC
        assert_eq!(frame[0], 0xB0); // AUTH
        assert_eq!(frame[1], 0x00);
        // Duration = 0x013A
        assert_eq!(frame[2], 0x3A);
        assert_eq!(frame[3], 0x01);
        // DA = BSSID
        assert_eq!(&frame[4..10], bssid.as_bytes());
        // SA = our mac
        assert_eq!(&frame[10..16], sa.as_bytes());
        // Addr3 = BSSID
        assert_eq!(&frame[16..22], bssid.as_bytes());
        // SeqCtl = 0
        assert_eq!(frame[22], 0x00);
        assert_eq!(frame[23], 0x00);
        // Auth Algo = 0 (Open System)
        assert_eq!(frame[24], 0x00);
        assert_eq!(frame[25], 0x00);
        // Auth Seq = 1
        assert_eq!(frame[26], 0x01);
        assert_eq!(frame[27], 0x00);
        // Status = 0 (Success)
        assert_eq!(frame[28], 0x00);
        assert_eq!(frame[29], 0x00);
    }

    #[test]
    fn test_disassoc_matches_c_reference() {
        // Verify match with wifikit_frames.c::wifikit_send_disassoc()
        let sa = MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);
        let target = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        let frame = build_disassoc(&sa, &target, &bssid, ReasonCode::DeauthLeaving);

        // FC = Disassoc
        assert_eq!(frame[0], 0xA0);
        assert_eq!(frame[1], 0x00);
        // Duration = 0 (matches C)
        assert_eq!(frame[2], 0x00);
        assert_eq!(frame[3], 0x00);
        // DA = target
        assert_eq!(&frame[4..10], target.as_bytes());
        // SA = us
        assert_eq!(&frame[10..16], sa.as_bytes());
        // BSSID
        assert_eq!(&frame[16..22], bssid.as_bytes());
        // Reason = 3 (DeauthLeaving)
        assert_eq!(frame[24], 0x03);
        assert_eq!(frame[25], 0x00);
    }

    #[test]
    fn test_assoc_response_matches_c_reference() {
        // Verify match with wifikit_frames.c::wifikit_send_assoc_resp()
        let client = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        let frame = build_assoc_response(
            &client, &bssid, StatusCode::Success, 1, cap_info::BASE, &[],
        ).unwrap();

        // FC = Assoc Response
        assert_eq!(frame[0], 0x10);
        assert_eq!(frame[1], 0x00);
        // DA = client
        assert_eq!(&frame[4..10], client.as_bytes());
        // SA = BSSID
        assert_eq!(&frame[10..16], bssid.as_bytes());
        // BSSID
        assert_eq!(&frame[16..22], bssid.as_bytes());
        // Cap info
        let cap = u16::from_le_bytes([frame[24], frame[25]]);
        assert_eq!(cap, cap_info::BASE);
        // Status = 0
        assert_eq!(frame[26], 0x00);
        assert_eq!(frame[27], 0x00);
        // AID = 1 with bits 14-15 set: 0xC001
        assert_eq!(frame[28], 0x01);
        assert_eq!(frame[29], 0xC0);
    }

    // ── FrameBuilder tests ──

    #[test]
    fn test_frame_builder_raw_deauth() {
        // Build a deauth frame entirely with raw bytes
        let frame = FrameBuilder::new()
            .fc(fc::DEAUTH, 0x00)
            .duration(0)
            .addr1(&MacAddress::BROADCAST)
            .addr2(&AP_MAC)
            .addr3(&AP_MAC)
            .seq_ctrl(0)
            .u16_le(ReasonCode::DeauthLeaving as u16)
            .build();

        // Should produce identical bytes to build_deauth
        let reference = build_deauth(&AP_MAC, &MacAddress::BROADCAST, &AP_MAC, ReasonCode::DeauthLeaving);
        assert_eq!(frame, reference);
    }

    #[test]
    fn test_frame_builder_mgmt_shorthand() {
        // Use the mgmt() shorthand to get the header for free
        let frame = FrameBuilder::mgmt(fc::AUTH, &AP_MAC, &OUR_MAC, &AP_MAC)
            .u16_le(auth_algo::OPEN_SYSTEM)  // auth algo
            .u16_le(1)                        // seq
            .u16_le(0)                        // status = success
            .build();

        assert_eq!(frame.len(), 30);
        assert_eq!(frame[0], fc::AUTH);
        // Verify addresses
        assert_eq!(&frame[4..10], AP_MAC.as_bytes());
        assert_eq!(&frame[10..16], OUR_MAC.as_bytes());
        assert_eq!(&frame[16..22], AP_MAC.as_bytes());
        // Verify body
        assert_eq!(u16::from_le_bytes([frame[24], frame[25]]), 0); // open system
        assert_eq!(u16::from_le_bytes([frame[26], frame[27]]), 1); // seq
    }

    #[test]
    fn test_frame_builder_ie_helper() {
        let frame = FrameBuilder::mgmt(fc::PROBE_REQ, &MacAddress::BROADCAST, &OUR_MAC, &MacAddress::BROADCAST)
            .ie(0x00, b"TestSSID")               // SSID IE
            .ie(0x01, &[0x82, 0x84, 0x0C, 0x12]) // Supported Rates
            .build();

        // SSID IE at offset 24
        assert_eq!(frame[24], 0x00);   // tag
        assert_eq!(frame[25], 8);      // len
        assert_eq!(&frame[26..34], b"TestSSID");
        // Rates IE at offset 34
        assert_eq!(frame[34], 0x01);   // tag
        assert_eq!(frame[35], 4);      // len
        assert_eq!(frame[36], 0x82);   // 1 Mbps mandatory
    }

    #[test]
    fn test_frame_builder_zeros() {
        let frame = FrameBuilder::new()
            .raw(&[0xAA])
            .zeros(5)
            .raw(&[0xBB])
            .build();
        assert_eq!(frame, vec![0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBB]);
    }

    #[test]
    fn test_frame_builder_u32_u64() {
        let frame = FrameBuilder::new()
            .u32_le(0xDEADBEEF)
            .u64_le(0x123456789ABCDEF0)
            .build();
        assert_eq!(frame.len(), 12);
        assert_eq!(u32::from_le_bytes(frame[0..4].try_into().unwrap()), 0xDEADBEEF);
        assert_eq!(u64::from_le_bytes(frame[4..12].try_into().unwrap()), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_frame_builder_mixed_mode() {
        // Start with structured header, add raw research payload
        let frame = FrameBuilder::mgmt(fc::ACTION, &AP_MAC, &OUR_MAC, &AP_MAC)
            .u8(0xFF)                    // custom category
            .u8(0x42)                    // custom action
            .raw(&[0xDE, 0xAD, 0xBE, 0xEF]) // research payload
            .build();

        let (hdr, action) = parse_action(&frame).expect("should parse");
        assert_eq!(hdr.addr2, OUR_MAC);
        assert_eq!(action.category, 0xFF);
        assert_eq!(action.action, 0x42);
        assert_eq!(&frame[action.body_offset..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_frame_builder_completely_raw() {
        // Not even a valid 802.11 frame — just raw bytes for fuzzing/research
        let frame = FrameBuilder::new()
            .raw(&[0x00; 4])     // garbage FC + duration
            .raw(&[0xFF; 18])    // garbage addresses
            .raw(&[0xAB, 0xCD]) // garbage seq
            .build();
        assert_eq!(frame.len(), 24);
        // This is intentionally malformed — that's the point
    }

    #[test]
    fn test_frame_builder_len_and_empty() {
        let fb = FrameBuilder::new();
        assert!(fb.is_empty());
        assert_eq!(fb.len(), 0);

        let fb = fb.u8(0x42);
        assert!(!fb.is_empty());
        assert_eq!(fb.len(), 1);
    }

    #[test]
    fn test_frame_builder_as_bytes_peek() {
        let fb = FrameBuilder::new().fc(0xB0, 0x00);
        assert_eq!(fb.as_bytes(), &[0xB0, 0x00]);
        // Can still build after peeking
        let frame = fb.duration(314).build();
        assert_eq!(frame.len(), 4);
    }

    #[test]
    fn test_frame_builder_addr4_wds() {
        // WDS frame has 4 addresses (30-byte header)
        let addr4 = MacAddress::new([0x44, 0x44, 0x44, 0x44, 0x44, 0x44]);
        let frame = FrameBuilder::new()
            .fc(fc::DATA, 0x03)          // ToDS=1, FromDS=1 → WDS
            .duration(0)
            .addr1(&AP_MAC)
            .addr2(&OUR_MAC)
            .addr3(&CLIENT_MAC)
            .seq_ctrl(0)
            .addr4(&addr4)               // 4th address for WDS
            .raw(&[0xAA, 0xBB])          // payload
            .build();
        assert_eq!(frame.len(), 32); // 24 + 6 (addr4) + 2 (payload)
        assert_eq!(&frame[24..30], addr4.as_bytes());
    }

    #[test]
    fn test_frame_builder_beacon_with_custom_tsf() {
        // Build a beacon from scratch using FrameBuilder — the research way
        let frame = FrameBuilder::mgmt(fc::BEACON, &MacAddress::BROADCAST, &AP_MAC, &AP_MAC)
            .u64_le(0xCAFEBABE)          // custom TSF
            .u16_le(100)                 // beacon interval
            .u16_le(cap_info::BASE)      // capability
            .ie(0x00, b"Research")       // SSID
            .build();

        // Should be parseable by our beacon parser
        let (hdr, body) = parse_beacon(&frame).expect("should parse");
        assert_eq!(hdr.addr2, AP_MAC);
        assert_eq!(body.tsf, 0xCAFEBABE);
        assert_eq!(body.beacon_interval, 100);
        // SSID IE is in the IEs section
        assert_eq!(frame[body.ies_offset], 0x00);     // SSID tag
        assert_eq!(frame[body.ies_offset + 1], 8);    // "Research" length
    }

    // ── Control frame builder tests ──

    #[test]
    fn test_build_cts_length_and_fc() {
        let frame = build_cts(&AP_MAC, 32767);
        assert_eq!(frame.len(), 10);
        assert_eq!(frame[0], fc::CTS);
        assert_eq!(frame[1], 0x00);
    }

    #[test]
    fn test_build_cts_duration() {
        let frame = build_cts(&AP_MAC, 32767);
        assert_eq!(u16::from_le_bytes([frame[2], frame[3]]), 32767);
    }

    #[test]
    fn test_build_cts_receiver() {
        let frame = build_cts(&AP_MAC, 1000);
        assert_eq!(&frame[4..10], AP_MAC.as_bytes());
    }

    #[test]
    fn test_build_rts_length_and_fc() {
        let frame = build_rts(&AP_MAC, &CLIENT_MAC, 32767);
        assert_eq!(frame.len(), 16);
        assert_eq!(frame[0], fc::RTS);
        assert_eq!(frame[1], 0x00);
    }

    #[test]
    fn test_build_rts_addresses() {
        let frame = build_rts(&AP_MAC, &CLIENT_MAC, 32767);
        assert_eq!(&frame[4..10], AP_MAC.as_bytes());     // RA
        assert_eq!(&frame[10..16], CLIENT_MAC.as_bytes()); // TA
    }

    #[test]
    fn test_build_power_save_null_fc_flags() {
        let frame = build_power_save_null(&CLIENT_MAC, &AP_MAC);
        assert_eq!(frame.len(), 24);
        assert_eq!(frame[0], fc::NULL_DATA); // 0x48
        // FC byte 1: ToDS(0x01) | PM(0x10) = 0x11
        assert_eq!(frame[1] & 0x11, 0x11);
    }

    #[test]
    fn test_build_power_save_null_addresses() {
        let frame = build_power_save_null(&CLIENT_MAC, &AP_MAC);
        assert_eq!(&frame[4..10], AP_MAC.as_bytes());      // Addr1 = BSSID
        assert_eq!(&frame[10..16], CLIENT_MAC.as_bytes());  // Addr2 = victim (spoofed)
        assert_eq!(&frame[16..22], AP_MAC.as_bytes());      // Addr3 = BSSID
    }

    #[test]
    fn test_build_michael_shutdown_fc() {
        let frame = build_michael_shutdown(&CLIENT_MAC, &AP_MAC);
        assert_eq!(frame[0], fc::QOS_DATA); // 0x88
        assert_eq!(frame[1] & 0x01, 0x01);  // ToDS
    }

    #[test]
    fn test_build_michael_shutdown_addresses() {
        let frame = build_michael_shutdown(&CLIENT_MAC, &AP_MAC);
        assert_eq!(&frame[4..10], AP_MAC.as_bytes());      // Addr1 = BSSID
        assert_eq!(&frame[10..16], CLIENT_MAC.as_bytes());  // Addr2 = victim
    }

    #[test]
    fn test_build_michael_shutdown_has_payload() {
        let frame = build_michael_shutdown(&CLIENT_MAC, &AP_MAC);
        // 24 (header) + 2 (QoS) + 32 (fake payload) = 58
        assert_eq!(frame.len(), 58);
    }

    #[test]
    fn test_build_sa_query_request() {
        let frame = build_sa_query_request(&CLIENT_MAC, &AP_MAC, 0x1234).unwrap();
        assert_eq!(frame[0], fc::ACTION);
        // DA = client
        assert_eq!(&frame[4..10], CLIENT_MAC.as_bytes());
        // SA = AP (spoofed)
        assert_eq!(&frame[10..16], AP_MAC.as_bytes());
        // Category = 8 (SA Query)
        assert_eq!(frame[24], 8);
        // Action = 0 (Request)
        assert_eq!(frame[25], 0);
        // Transaction ID
        assert_eq!(u16::from_le_bytes([frame[26], frame[27]]), 0x1234);
    }

    #[test]
    fn test_build_bss_transition_request() {
        let frame = build_bss_transition_request(&CLIENT_MAC, &AP_MAC, 1).unwrap();
        assert_eq!(frame[0], fc::ACTION);
        // DA = client
        assert_eq!(&frame[4..10], CLIENT_MAC.as_bytes());
        // Category = 10 (WNM)
        assert_eq!(frame[24], 10);
        // Action = 7 (BSS Transition Management Request)
        assert_eq!(frame[25], 7);
        // Dialog token = 1
        assert_eq!(frame[26], 1);
        // Request mode: 0x0C (imminent + disassoc imminent)
        assert_eq!(frame[27], 0x0C);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  A. Negative tests — frame type mismatch validation
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_auth_rejects_data_frame() {
        // Build a data frame (FC byte 0 = 0x08 = data type)
        let mut frame = vec![0x08, 0x00]; // FC: data frame
        frame.extend_from_slice(&[0x00; 28]); // pad to 30 bytes
        assert!(parse_auth(&frame).is_none());
    }

    #[test]
    fn test_parse_assoc_response_rejects_data_frame() {
        let mut frame = vec![0x08, 0x00]; // data frame
        frame.extend_from_slice(&[0x00; 28]);
        assert!(parse_assoc_response(&frame).is_none());
    }

    #[test]
    fn test_parse_beacon_rejects_data_frame() {
        let mut frame = vec![0x08, 0x00]; // data frame
        frame.extend_from_slice(&[0x00; 60]);
        assert!(parse_beacon(&frame).is_none());
    }

    // LLC/SNAP confusion test — the bug that caused garbage status codes (0xAAAA)
    #[test]
    fn test_parse_assoc_response_rejects_llc_snap() {
        // Data frame with LLC/SNAP header at byte 24: 0xAA 0xAA 0x03 ...
        // This was the root cause of garbage status code 43690 (0xAAAA)
        let mut frame = vec![0x08, 0x00]; // FC: data frame
        frame.extend_from_slice(&[0x00; 22]); // pad header to 24 bytes
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]); // LLC/SNAP
        assert!(parse_assoc_response(&frame).is_none());
    }

    #[test]
    fn test_parse_auth_rejects_llc_snap() {
        let mut frame = vec![0x08, 0x00]; // data frame
        frame.extend_from_slice(&[0x00; 22]);
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]);
        assert!(parse_auth(&frame).is_none());
    }

    // Beacon accepts ProbeResp (intentional — same layout)
    #[test]
    fn test_parse_beacon_accepts_probe_response() {
        let mut frame = Vec::new();
        frame.push(fc::PROBE_RESP); // FC byte 0
        frame.push(0x00); // FC byte 1
        frame.extend_from_slice(&0x013Au16.to_le_bytes()); // duration
        frame.extend_from_slice(AP_MAC.as_bytes()); // addr1
        frame.extend_from_slice(AP_MAC.as_bytes()); // addr2
        frame.extend_from_slice(AP_MAC.as_bytes()); // addr3
        frame.extend_from_slice(&0u16.to_le_bytes()); // seq_ctrl
        // Beacon body: timestamp(8) + interval(2) + cap_info(2)
        frame.extend_from_slice(&[0u8; 8]); // timestamp
        frame.extend_from_slice(&100u16.to_le_bytes()); // beacon interval
        frame.extend_from_slice(&0x0411u16.to_le_bytes()); // cap_info
        assert!(parse_beacon(&frame).is_some());
    }

    // Disassoc rejects Deauth and vice versa
    #[test]
    fn test_parse_disassoc_rejects_deauth() {
        let frame = build_deauth(&AP_MAC, &CLIENT_MAC, &AP_MAC, ReasonCode::DeauthLeaving);
        assert!(parse_disassoc(&frame).is_none());
    }

    #[test]
    fn test_parse_deauth_rejects_disassoc() {
        let frame = build_disassoc(&AP_MAC, &CLIENT_MAC, &AP_MAC, ReasonCode::DisassocLeaving);
        assert!(parse_deauth(&frame).is_none());
    }

    // Action frame rejects non-action management frames
    #[test]
    fn test_parse_action_rejects_auth_frame() {
        let frame = build_auth(&OUR_MAC, &AP_MAC, 0, 1, StatusCode::Success);
        assert!(parse_action(&frame).is_none());
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  B. Probe Request parser tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_probe_request_basic() {
        let mut frame = Vec::new();
        frame.push(fc::PROBE_REQ); // FC byte 0
        frame.push(0x00);
        frame.extend_from_slice(&0u16.to_le_bytes()); // duration
        frame.extend_from_slice(&[0xFF; 6]); // addr1 = broadcast
        frame.extend_from_slice(CLIENT_MAC.as_bytes()); // addr2 = STA
        frame.extend_from_slice(&[0xFF; 6]); // addr3 = broadcast
        frame.extend_from_slice(&0u16.to_le_bytes()); // seq_ctrl
        // IEs: SSID "Test"
        frame.extend_from_slice(&[0x00, 0x04, b'T', b'e', b's', b't']);

        let (hdr, body) = parse_probe_request(&frame).unwrap();
        assert_eq!(hdr.addr2, CLIENT_MAC);
        assert_eq!(body.ies_offset, 24);
        assert_eq!(body.ies_len, 6);
    }

    #[test]
    fn test_parse_probe_request_rejects_beacon() {
        // Build a beacon and try to parse it as probe request
        let mut frame = Vec::new();
        frame.push(fc::BEACON);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]); // header
        frame.extend_from_slice(&[0x00; 12]); // beacon body
        assert!(parse_probe_request(&frame).is_none());
    }

    #[test]
    fn test_parse_probe_request_wildcard_ssid() {
        let mut frame = Vec::new();
        frame.push(fc::PROBE_REQ);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        // Wildcard SSID IE: tag=0, length=0
        frame.extend_from_slice(&[0x00, 0x00]);

        let (_, body) = parse_probe_request(&frame).unwrap();
        assert_eq!(body.ies_len, 2);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  C. Reassoc Request parser tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_reassoc_request_basic() {
        let old_ap = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let frame = build_reassoc_request(&OUR_MAC, &AP_MAC, &old_ap, cap_info::BASE, 0, &[]).unwrap();
        let (hdr, body) = parse_reassoc_request(&frame).unwrap();
        assert_eq!(hdr.addr2, OUR_MAC);
        assert_eq!(body.current_ap, old_ap);
        assert_eq!(body.cap_info, cap_info::BASE);
    }

    #[test]
    fn test_parse_reassoc_request_with_ies() {
        let old_ap = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let ies = [0x00, 0x03, b'A', b'B', b'C']; // SSID IE
        let frame = build_reassoc_request(&OUR_MAC, &AP_MAC, &old_ap, cap_info::BASE, 5, &ies).unwrap();
        let (_, body) = parse_reassoc_request(&frame).unwrap();
        assert_eq!(body.ies_len, 5);
        assert_eq!(&frame[body.ies_offset..body.ies_offset + body.ies_len], &ies);
    }

    #[test]
    fn test_parse_reassoc_request_rejects_assoc_request() {
        let frame = build_assoc_request(&OUR_MAC, &AP_MAC, cap_info::BASE, 0, &[]).unwrap();
        assert!(parse_reassoc_request(&frame).is_none());
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  D. SA Query parser tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_sa_query_request() {
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&0u16.to_le_bytes()); // duration
        frame.extend_from_slice(AP_MAC.as_bytes()); // addr1
        frame.extend_from_slice(CLIENT_MAC.as_bytes()); // addr2
        frame.extend_from_slice(AP_MAC.as_bytes()); // addr3
        frame.extend_from_slice(&0u16.to_le_bytes()); // seq_ctrl
        // Body: category=8 (SA Query), action=0 (Request), txid=0x1234
        frame.push(8); // SA_QUERY category
        frame.push(0); // Request
        frame.extend_from_slice(&0x1234u16.to_le_bytes()); // transaction_id

        let (hdr, body) = parse_sa_query(&frame).unwrap();
        assert_eq!(hdr.addr2, CLIENT_MAC);
        assert_eq!(body.action, 0);
        assert_eq!(body.transaction_id, 0x1234);
    }

    #[test]
    fn test_parse_sa_query_response() {
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]); // header padding
        frame.push(8); // SA_QUERY
        frame.push(1); // Response
        frame.extend_from_slice(&0xABCDu16.to_le_bytes());

        let (_, body) = parse_sa_query(&frame).unwrap();
        assert_eq!(body.action, 1);
        assert_eq!(body.transaction_id, 0xABCD);
    }

    #[test]
    fn test_parse_sa_query_rejects_wrong_category() {
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        frame.push(0); // SPECTRUM_MGMT, not SA_QUERY
        frame.push(0);
        frame.extend_from_slice(&0u16.to_le_bytes());
        assert!(parse_sa_query(&frame).is_none());
    }

    #[test]
    fn test_parse_sa_query_too_short() {
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        frame.push(8); // category only, missing rest
        assert!(parse_sa_query(&frame).is_none());
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  E. BSS Transition parser tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_bss_transition_request() {
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]); // header
        frame.push(ieee80211::action_category::WNM); // WNM category
        frame.push(ieee80211::wnm_action::BSS_TRANSITION_MGMT_REQ); // BSS Transition Mgmt Request
        frame.push(0x42); // dialog_token
        frame.push(0x03); // request_mode
        frame.extend_from_slice(&300u16.to_le_bytes()); // disassoc_timer
        frame.push(10); // validity_interval

        let (_, body) = parse_bss_transition(&frame).unwrap();
        assert_eq!(body.action, ieee80211::wnm_action::BSS_TRANSITION_MGMT_REQ);
        assert_eq!(body.dialog_token, 0x42);
        assert_eq!(body.request_mode, Some(0x03));
        assert_eq!(body.disassoc_timer, Some(300));
        assert_eq!(body.validity_interval, Some(10));
    }

    #[test]
    fn test_parse_bss_transition_response_with_target() {
        let target = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        frame.push(ieee80211::action_category::WNM); // WNM
        frame.push(ieee80211::wnm_action::BSS_TRANSITION_MGMT_RESP); // BSS Transition Mgmt Response
        frame.push(0x42); // dialog_token
        frame.push(0);    // status=0 (accept)
        frame.push(0);    // bss_term_delay
        frame.extend_from_slice(target.as_bytes()); // target BSSID (present when status=0)

        let (_, body) = parse_bss_transition(&frame).unwrap();
        assert_eq!(body.action, ieee80211::wnm_action::BSS_TRANSITION_MGMT_RESP);
        assert_eq!(body.status, Some(0));
        assert_eq!(body.target_bssid, Some(target));
    }

    #[test]
    fn test_parse_bss_transition_rejects_non_wnm() {
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        frame.push(ieee80211::action_category::SA_QUERY); // SA_QUERY, not WNM
        frame.push(7);
        frame.push(0);
        assert!(parse_bss_transition(&frame).is_none());
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  F. FT Action parser tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_ft_action_request() {
        let sta = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let target_ap = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]); // header
        frame.push(ieee80211::action_category::FAST_BSS_TRANSITION); // FT category
        frame.push(ieee80211::ft_action::FT_REQUEST); // FT Request
        frame.extend_from_slice(sta.as_bytes());
        frame.extend_from_slice(target_ap.as_bytes());

        let (_, body) = parse_ft_action(&frame).unwrap();
        assert_eq!(body.action, ieee80211::ft_action::FT_REQUEST);
        assert_eq!(body.sta_addr, sta);
        assert_eq!(body.target_ap, target_ap);
        assert!(body.status.is_none()); // No status in Request
    }

    #[test]
    fn test_parse_ft_action_response_has_status() {
        let sta = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let target_ap = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        frame.push(ieee80211::action_category::FAST_BSS_TRANSITION); // FT category
        frame.push(ieee80211::ft_action::FT_RESPONSE); // FT Response
        frame.extend_from_slice(sta.as_bytes());
        frame.extend_from_slice(target_ap.as_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes()); // status = Success

        let (_, body) = parse_ft_action(&frame).unwrap();
        assert_eq!(body.action, ieee80211::ft_action::FT_RESPONSE);
        assert_eq!(body.status, Some(0));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  G. Control frame parser tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_rts_basic() {
        let mut frame = Vec::new();
        frame.push(fc::RTS);
        frame.push(0x00);
        frame.extend_from_slice(&100u16.to_le_bytes()); // duration
        frame.extend_from_slice(AP_MAC.as_bytes()); // RA
        frame.extend_from_slice(CLIENT_MAC.as_bytes()); // TA

        let rts = parse_rts(&frame).unwrap();
        assert_eq!(rts.ra, AP_MAC);
        assert_eq!(rts.ta, CLIENT_MAC);
        assert_eq!(rts.duration, 100);
    }

    #[test]
    fn test_parse_rts_rejects_cts() {
        let mut frame = Vec::new();
        frame.push(fc::CTS);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 14]);
        assert!(parse_rts(&frame).is_none());
    }

    #[test]
    fn test_parse_cts_basic() {
        let mut frame = Vec::new();
        frame.push(fc::CTS);
        frame.push(0x00);
        frame.extend_from_slice(&200u16.to_le_bytes()); // duration
        frame.extend_from_slice(AP_MAC.as_bytes()); // RA

        let cts = parse_cts(&frame).unwrap();
        assert_eq!(cts.ra, AP_MAC);
        assert_eq!(cts.duration, 200);
    }

    #[test]
    fn test_parse_ack_basic() {
        let mut frame = Vec::new();
        frame.push(fc::ACK);
        frame.push(0x00);
        frame.extend_from_slice(&0u16.to_le_bytes()); // duration
        frame.extend_from_slice(CLIENT_MAC.as_bytes()); // RA

        let ack = parse_ack(&frame).unwrap();
        assert_eq!(ack.ra, CLIENT_MAC);
    }

    #[test]
    fn test_parse_ack_rejects_management_frame() {
        let frame = build_auth(&OUR_MAC, &AP_MAC, 0, 1, StatusCode::Success);
        assert!(parse_ack(&frame).is_none());
    }

    #[test]
    fn test_parse_block_ack_req_basic() {
        let mut frame = Vec::new();
        // BAR FC: control type (01) + subtype 8 (1000) = 0x84 for byte 0
        frame.push(0x84); // FC: control + BAR subtype
        frame.push(0x00);
        frame.extend_from_slice(&100u16.to_le_bytes()); // duration
        frame.extend_from_slice(AP_MAC.as_bytes()); // RA
        frame.extend_from_slice(CLIENT_MAC.as_bytes()); // TA
        // BAR Control: TID 3 in bits 12-15 = 0x3000
        frame.extend_from_slice(&0x3000u16.to_le_bytes());
        // Starting Sequence Control: seq 100 in bits 4-15 = 100 << 4 = 0x0640
        frame.extend_from_slice(&0x0640u16.to_le_bytes());

        let bar = parse_block_ack_req(&frame).unwrap();
        assert_eq!(bar.ra, AP_MAC);
        assert_eq!(bar.ta, CLIENT_MAC);
        assert_eq!(bar.tid(), 3);
        assert_eq!(bar.starting_seq(), 100);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  H. QoS Control parser tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_qos_control_basic() {
        let mut frame = Vec::new();
        // QoS Data: data type (0x08) + QoS subtype bit (0x80) = 0x88
        frame.push(0x88); // FC: QoS Data
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]); // header padding
        // QoS Control: TID=2, no EOSP, normal ack, no A-MSDU
        frame.extend_from_slice(&0x0002u16.to_le_bytes());

        let qos = parse_qos_control(&frame).unwrap();
        assert_eq!(qos.tid, 2);
        assert!(!qos.eosp);
        assert_eq!(qos.ack_policy, 0);
        assert!(!qos.amsdu_present);
    }

    #[test]
    fn test_parse_qos_control_amsdu_flag() {
        let mut frame = Vec::new();
        frame.push(0x88); // QoS Data
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        // QoS Control: TID=0, A-MSDU present (bit 7 = 0x80)
        frame.extend_from_slice(&0x0080u16.to_le_bytes());

        let qos = parse_qos_control(&frame).unwrap();
        assert!(qos.amsdu_present);
        assert_eq!(qos.tid, 0);
    }

    #[test]
    fn test_parse_qos_control_rejects_non_qos_data() {
        let mut frame = Vec::new();
        frame.push(0x08); // plain Data (no QoS bit)
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 24]);
        assert!(parse_qos_control(&frame).is_none());
    }

    #[test]
    fn test_parse_qos_control_rejects_management_frame() {
        let frame = build_auth(&OUR_MAC, &AP_MAC, 0, 1, StatusCode::Success);
        assert!(parse_qos_control(&frame).is_none());
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  I. A-MSDU deaggregation tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_amsdu_deaggregate_single_subframe() {
        let da = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sa = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let payload = b"Hello";
        let mut data = Vec::new();
        data.extend_from_slice(&da);
        data.extend_from_slice(&sa);
        data.extend_from_slice(&(payload.len() as u16).to_be_bytes()); // Length (big-endian!)
        data.extend_from_slice(payload);

        let subframes = amsdu_deaggregate(&data);
        assert_eq!(subframes.len(), 1);
        assert_eq!(subframes[0].da, MacAddress::new(da));
        assert_eq!(subframes[0].sa, MacAddress::new(sa));
        assert_eq!(subframes[0].length, 5);
        assert_eq!(&data[subframes[0].payload_offset..subframes[0].payload_offset + subframes[0].payload_len], payload.as_slice());
    }

    #[test]
    fn test_amsdu_deaggregate_two_subframes() {
        let da = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sa = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let mut data = Vec::new();
        // Subframe 1: 3-byte payload
        data.extend_from_slice(&da);
        data.extend_from_slice(&sa);
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(b"ABC");
        // Padding to 4-byte boundary: 14 + 3 = 17, next 4-byte = 20, pad = 3
        data.extend_from_slice(&[0x00; 3]);

        // Subframe 2: 4-byte payload (already aligned)
        data.extend_from_slice(&da);
        data.extend_from_slice(&sa);
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(b"DEFG");

        let subframes = amsdu_deaggregate(&data);
        assert_eq!(subframes.len(), 2);
        assert_eq!(subframes[0].length, 3);
        assert_eq!(subframes[1].length, 4);
    }

    #[test]
    fn test_amsdu_deaggregate_truncated_stops_gracefully() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x11; 6]); // DA
        data.extend_from_slice(&[0x22; 6]); // SA
        data.extend_from_slice(&100u16.to_be_bytes()); // Length = 100 (but we only have a few bytes)
        data.extend_from_slice(b"short"); // Only 5 bytes, not 100

        let subframes = amsdu_deaggregate(&data);
        assert!(subframes.is_empty()); // Truncated — should stop, not crash
    }

    #[test]
    fn test_amsdu_deaggregate_empty() {
        let subframes = amsdu_deaggregate(&[]);
        assert!(subframes.is_empty());
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  J. Spectrum Management and Radio Measurement tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_spectrum_mgmt_csa() {
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        frame.push(ieee80211::action_category::SPECTRUM_MGMT); // SPECTRUM_MGMT category
        frame.push(4); // Channel Switch Announcement
        frame.push(0x01); // dialog_token

        let (_, body) = parse_spectrum_mgmt(&frame).unwrap();
        assert_eq!(body.action, 4);
        assert_eq!(body.dialog_token, 1);
    }

    #[test]
    fn test_parse_radio_measurement_request_with_repetitions() {
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        frame.push(ieee80211::action_category::RADIO_MEASUREMENT); // RADIO_MEASUREMENT category
        frame.push(ieee80211::radio_measurement_action::RADIO_MEASUREMENT_REQ); // Measurement Request
        frame.push(0x10); // dialog_token
        frame.extend_from_slice(&5u16.to_le_bytes()); // num_repetitions = 5

        let (_, body) = parse_radio_measurement(&frame).unwrap();
        assert_eq!(body.action, ieee80211::radio_measurement_action::RADIO_MEASUREMENT_REQ);
        assert_eq!(body.dialog_token, 0x10);
        assert_eq!(body.num_repetitions, Some(5));
    }

    #[test]
    fn test_parse_radio_measurement_report_no_repetitions() {
        let mut frame = Vec::new();
        frame.push(fc::ACTION);
        frame.push(0x00);
        frame.extend_from_slice(&[0x00; 22]);
        frame.push(ieee80211::action_category::RADIO_MEASUREMENT); // RADIO_MEASUREMENT
        frame.push(1); // Measurement Report (no num_repetitions field)
        frame.push(0x20); // dialog_token

        let (_, body) = parse_radio_measurement(&frame).unwrap();
        assert_eq!(body.action, 1);
        assert_eq!(body.num_repetitions, None);
    }
}
