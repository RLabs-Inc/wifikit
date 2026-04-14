//! ParsedFrame — the single source of truth for all frame data.
//!
//! Every frame that comes off USB is parsed ONCE by `parse_frame()` in the RX thread.
//! The result is a `ParsedFrame` that carries all extracted fields. No consumer
//! ever re-parses raw bytes — they read pre-parsed fields.
//!
//! Architecture:
//!   USB RX → chip parse_rx_packet() → RxFrame (raw)
//!         → parse_frame() → ParsedFrame (fully parsed)
//!         → pcap file (raw bytes, never lost)
//!         → channel (ParsedFrame to all consumers)
//!
//! Consumers: Scanner, Attacks, CLI — all read ParsedFrame, never raw bytes.

use std::sync::Arc;
use std::time::Duration;

use crate::core::MacAddress;
use crate::protocol::eapol::{self, ParsedEapol};
use crate::protocol::frames::{self, MgmtHeader};
use crate::protocol::ie::{self, ParsedIes};
use crate::protocol::ieee80211::{self, frame_type, frame_subtype, fc_flags};

// ═══════════════════════════════════════════════════════════════════════════════
//  ParsedFrame — the unified frame type
// ═══════════════════════════════════════════════════════════════════════════════

/// A fully parsed 802.11 frame. Created once in the RX thread, consumed by all.
///
/// The `raw` field holds the original bytes for pcap export and any edge-case
/// inspection. All other fields are pre-extracted — consumers never touch `raw`.
#[derive(Debug, Clone)]
pub struct ParsedFrame {
    // === Raw data (for pcap, export, edge cases) ===
    /// Original 802.11 frame bytes as received from the adapter.
    pub raw: Arc<Vec<u8>>,

    // === Adapter-provided metadata ===
    /// Received signal strength in dBm.
    pub rssi: i8,
    /// Signal-to-noise ratio in dB (0-63). 0 = not available.
    pub snr: u8,
    /// Noise floor in dBm. 0 = not available.
    pub noise_floor: i8,
    /// Channel the frame was received on.
    pub channel: u8,
    /// Band: 0=2.4GHz, 1=5GHz, 2=6GHz.
    pub band: u8,
    /// Time since adapter init (from RX descriptor).
    pub timestamp: Duration,

    // === 802.11 header fields (common to all frames) ===
    /// Frame Control word (raw 2 bytes, little-endian).
    pub frame_control: u16,
    /// Frame type: 0=Management, 1=Control, 2=Data.
    pub frame_type: u8,
    /// Frame subtype (0-15).
    pub frame_subtype: u8,
    /// Duration/ID field.
    pub duration: u16,
    /// Address 1 (receiver/destination).
    pub addr1: Option<MacAddress>,
    /// Address 2 (transmitter/source).
    pub addr2: Option<MacAddress>,
    /// Address 3 (BSSID or other).
    pub addr3: Option<MacAddress>,
    /// Address 4 (WDS only).
    pub addr4: Option<MacAddress>,
    /// Sequence number (upper 12 bits of Sequence Control).
    pub seq_num: u16,
    /// Fragment number (lower 4 bits of Sequence Control).
    pub frag_num: u8,

    // === Frame Control flags ===
    /// Retry bit — frame is a retransmission.
    pub retry: bool,
    /// Protected bit — frame payload is encrypted.
    pub protected: bool,
    /// More Fragments bit.
    pub more_fragments: bool,
    /// More Data bit (AP has buffered frames for STA).
    pub more_data: bool,
    /// Power Management bit (STA entering power save).
    pub power_mgmt: bool,
    /// Order bit (HT Control field present).
    pub order: bool,
    /// To DS flag.
    pub to_ds: bool,
    /// From DS flag.
    pub from_ds: bool,

    // === QoS fields (data frames with subtype bit 3 set) ===
    /// Whether this is a QoS data frame.
    pub is_qos: bool,
    /// QoS Traffic Identifier (0-7), valid when is_qos=true.
    pub qos_tid: u8,

    // === Parsed body — type-specific payload ===
    pub body: FrameBody,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FrameBody — parsed payload per frame type
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed frame body. Each variant carries the fully-extracted payload
/// for that frame type. Consumers match on this — never parse raw bytes.
#[derive(Debug, Clone)]
pub enum FrameBody {
    // === Management frames ===

    /// Beacon or Probe Response — AP advertisement.
    Beacon {
        /// BSSID (addr3 in beacon).
        bssid: MacAddress,
        /// TSF timestamp (8-byte microsecond counter).
        tsf: u64,
        /// Beacon interval in TUs (1 TU = 1024 μs).
        beacon_interval: u16,
        /// Capability Information word.
        capability: u16,
        /// Privacy bit from capability (WEP/WPA/RSN).
        privacy: bool,
        /// All parsed Information Elements.
        ies: ParsedIes,
    },

    /// Probe Request — client looking for networks.
    ProbeReq {
        /// Source MAC (the requesting station).
        sta: MacAddress,
        /// Requested SSID (empty = wildcard).
        ssid: String,
        /// Parsed IEs (rates, HT caps, vendor, etc.).
        ies: ParsedIes,
    },

    /// Authentication frame.
    Auth {
        /// Source of the auth frame.
        source: MacAddress,
        /// Destination of the auth frame.
        target: MacAddress,
        /// BSSID.
        bssid: MacAddress,
        /// Auth algorithm (0=Open, 1=Shared, 3=SAE).
        algorithm: u16,
        /// Transaction sequence number (1=request, 2=response, etc.).
        seq_num: u16,
        /// Status code (0=success).
        status: u16,
    },

    /// Deauthentication frame.
    Deauth {
        source: MacAddress,
        target: MacAddress,
        bssid: MacAddress,
        /// Reason code.
        reason: u16,
    },

    /// Disassociation frame.
    Disassoc {
        source: MacAddress,
        target: MacAddress,
        bssid: MacAddress,
        reason: u16,
    },

    /// Association Request.
    AssocReq {
        /// Station requesting association.
        sta: MacAddress,
        /// AP being associated to.
        bssid: MacAddress,
        /// Capability Information.
        capability: u16,
        /// Listen interval.
        listen_interval: u16,
        /// Parsed IEs (SSID, rates, RSN, etc.).
        ies: ParsedIes,
    },

    /// Association Response.
    AssocResp {
        /// Station being responded to.
        sta: MacAddress,
        /// AP responding.
        bssid: MacAddress,
        /// Status code (0=success).
        status: u16,
        /// Association ID.
        aid: u16,
        /// Capability Information.
        capability: u16,
        /// Parsed IEs.
        ies: ParsedIes,
    },

    /// Reassociation Request.
    ReassocReq {
        sta: MacAddress,
        bssid: MacAddress,
        /// Current AP the station is moving from.
        current_ap: MacAddress,
        capability: u16,
        listen_interval: u16,
        ies: ParsedIes,
    },

    /// Reassociation Response (same structure as AssocResp).
    ReassocResp {
        sta: MacAddress,
        bssid: MacAddress,
        status: u16,
        aid: u16,
        capability: u16,
        ies: ParsedIes,
    },

    /// Action frame (802.11v/w/r/k/z and others).
    Action {
        source: MacAddress,
        target: MacAddress,
        bssid: MacAddress,
        /// Action category (e.g., 3=BA, 5=Radio Measurement, 6=FT, etc.).
        category: u8,
        /// Action code within the category.
        action: u8,
        /// Parsed action-specific data.
        detail: ActionDetail,
    },

    // === Data frames ===

    /// Data frame (any subtype: plain, QoS, null, CF-*).
    Data {
        /// Station MAC address.
        sta: MacAddress,
        /// AP/BSSID MAC address.
        bssid: MacAddress,
        /// Data frame direction.
        direction: DataDirection,
        /// Payload classification.
        payload: DataPayload,
    },

    // === Control frames ===

    /// Control frame (RTS, CTS, ACK, BA, BAR, PS-Poll).
    Control {
        detail: ControlDetail,
    },

    /// Frame too short or malformed to parse.
    Unparseable {
        /// Why parsing failed.
        reason: &'static str,
    },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Sub-types for FrameBody variants
// ═══════════════════════════════════════════════════════════════════════════════

/// Direction of a data frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    /// STA → AP (To-DS=1, From-DS=0).
    ToAp,
    /// AP → STA (To-DS=0, From-DS=1).
    FromAp,
    /// WDS (both To-DS and From-DS set).
    Wds,
    /// IBSS (neither flag set).
    Ibss,
}

/// Classified payload of a data frame.
#[derive(Debug, Clone)]
pub enum DataPayload {
    /// EAPOL frame detected (LLC/SNAP + 0x888E).
    Eapol(ParsedEapol),
    /// Null data frame (subtype 4 or 12) — no payload.
    Null,
    /// Encrypted payload (Protected bit set) — cannot inspect.
    Encrypted,
    /// Non-EAPOL LLC/SNAP frame.
    Llc {
        /// Ethertype from LLC/SNAP header.
        ethertype: u16,
    },
    /// Payload too short or no LLC/SNAP header.
    Other,
}

/// Parsed action frame detail.
#[derive(Debug, Clone)]
pub enum ActionDetail {
    /// SA Query (802.11w) request or response.
    SaQuery {
        transaction_id: u16,
        is_request: bool,
    },
    /// BSS Transition Management (802.11v).
    BssTransition {
        dialog_token: u8,
        is_request: bool,
        /// Candidate AP list from request/response.
        candidate_count: u8,
    },
    /// Fast Transition (802.11r) action.
    FtAction {
        action_code: u8,
        sta_addr: MacAddress,
        target_ap: MacAddress,
        status: u16,
    },
    /// Spectrum Management (802.11h).
    SpectrumMgmt {
        action_code: u8,
        dialog_token: u8,
    },
    /// Radio Measurement (802.11k).
    RadioMeasurement {
        action_code: u8,
        dialog_token: u8,
        is_request: bool,
        repetitions: Option<u16>,
    },
    /// Block Ack setup/teardown.
    BlockAck {
        action_code: u8,
    },
    /// TDLS (802.11z).
    Tdls {
        action_code: u8,
    },
    /// WNM Sleep Mode.
    WnmSleep {
        is_request: bool,
    },
    /// Unrecognized action category.
    Other {
        category: u8,
        action: u8,
    },
}

/// Parsed control frame detail.
#[derive(Debug, Clone)]
pub enum ControlDetail {
    Rts { ta: MacAddress, ra: MacAddress, duration: u16 },
    Cts { ra: MacAddress, duration: u16 },
    Ack { ra: MacAddress },
    BlockAckReq { ta: MacAddress, ra: MacAddress, tid: u8, ssn: u16 },
    BlockAck { ta: MacAddress, ra: MacAddress, tid: u8, ssn: u16 },
    PsPoll { bssid: MacAddress, ta: MacAddress },
    CfEnd { bssid: MacAddress, ta: MacAddress },
    /// Control frame we don't have a specific parser for.
    Other { subtype: u8 },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LLC/SNAP constants
// ═══════════════════════════════════════════════════════════════════════════════

/// LLC/SNAP header for EAPOL: AA:AA:03:00:00:00:88:8E
const LLC_SNAP_EAPOL: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];

/// LLC/SNAP header prefix (first 6 bytes, without ethertype).
const LLC_SNAP_PREFIX: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];

// ═══════════════════════════════════════════════════════════════════════════════
//  parse_frame() — THE central parser. Called once per frame in RX thread.
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse a raw 802.11 frame into a fully-typed ParsedFrame.
///
/// This is the ONLY place in the codebase where raw frame bytes are interpreted.
/// Called once in the RX thread for every frame. The result is broadcast to all
/// consumers via the pipeline channel.
///
/// Adapter-independent — works with any chipset's RxFrame output.
pub fn parse_frame(raw: &[u8], rssi: i8, snr: u8, noise_floor: i8, channel: u8, band: u8, timestamp: Duration) -> ParsedFrame {
    let raw_arc = Arc::new(raw.to_vec());

    // Minimum frame: FC(2) bytes
    if raw.len() < 2 {
        return ParsedFrame {
            raw: raw_arc,
            rssi, snr, noise_floor, channel, band, timestamp,
            frame_control: 0, frame_type: 0, frame_subtype: 0,
            duration: 0,
            addr1: None, addr2: None, addr3: None, addr4: None,
            seq_num: 0, frag_num: 0,
            retry: false, protected: false, more_fragments: false,
            more_data: false, power_mgmt: false, order: false,
            to_ds: false, from_ds: false,
            is_qos: false, qos_tid: 0,
            body: FrameBody::Unparseable { reason: "frame too short (<2 bytes)" },
        };
    }

    // ── Frame Control ──
    let fc = u16::from_le_bytes([raw[0], raw[1]]);
    let _fc0 = raw[0];
    let fc1 = raw[1];
    let ftype = ieee80211::fc_type(fc) as u8;
    let fsubtype = ieee80211::fc_subtype(fc) as u8;
    let duration = if raw.len() >= 4 {
        u16::from_le_bytes([raw[2], raw[3]])
    } else {
        0
    };

    // ── Flags ──
    let retry = fc1 & fc_flags::RETRY != 0;
    let protected = fc1 & fc_flags::PROTECTED != 0;
    let more_frag = fc1 & fc_flags::MORE_FRAG != 0;
    let more_data = fc1 & fc_flags::MORE_DATA != 0;
    let power_mgmt = fc1 & fc_flags::POWER_MGMT != 0;
    let order = fc1 & fc_flags::ORDER != 0;
    let to_ds = fc1 & fc_flags::TO_DS != 0;
    let from_ds = fc1 & fc_flags::FROM_DS != 0;

    // ── Addresses (layout depends on frame type) ──
    let addr1 = if raw.len() >= 10 { MacAddress::from_slice(&raw[4..10]) } else { None };
    let addr2 = if raw.len() >= 16 { MacAddress::from_slice(&raw[10..16]) } else { None };
    let addr3 = if raw.len() >= 22 { MacAddress::from_slice(&raw[16..22]) } else { None };
    let addr4 = if to_ds && from_ds && raw.len() >= 30 {
        MacAddress::from_slice(&raw[24..30])
    } else {
        None
    };

    // ── Sequence Control (bytes 22-23, management and data frames) ──
    let (seq_num, frag_num) = if ftype != frame_type::CONTROL as u8 && raw.len() >= 24 {
        let seq_ctl = u16::from_le_bytes([raw[22], raw[23]]);
        (seq_ctl >> 4, (seq_ctl & 0x0F) as u8)
    } else {
        (0, 0)
    };

    // ── QoS (data frames with subtype bit 3 set) ──
    let is_qos = ftype == frame_type::DATA as u8 && (fsubtype & 0x08) != 0;
    let qos_tid = if is_qos && raw.len() >= 26 {
        raw[24] & 0x0F
    } else {
        0
    };

    // ── Parse body based on frame type ──
    let body = match ftype {
        t if t == frame_type::MANAGEMENT as u8 => {
            parse_management(raw, fsubtype, protected)
        }
        t if t == frame_type::DATA as u8 => {
            parse_data(raw, fsubtype, to_ds, from_ds, protected, is_qos, order)
        }
        t if t == frame_type::CONTROL as u8 => {
            parse_control(raw, fsubtype)
        }
        _ => FrameBody::Unparseable { reason: "reserved frame type" },
    };

    ParsedFrame {
        raw: raw_arc,
        rssi, snr, noise_floor, channel, band, timestamp,
        frame_control: fc, frame_type: ftype, frame_subtype: fsubtype,
        duration,
        addr1, addr2, addr3, addr4,
        seq_num, frag_num,
        retry, protected, more_fragments: more_frag,
        more_data, power_mgmt, order,
        to_ds, from_ds,
        is_qos, qos_tid,
        body,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Management frame parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_management(raw: &[u8], subtype: u8, _protected: bool) -> FrameBody {
    match subtype {
        // Beacon or Probe Response
        frame_subtype::BEACON | frame_subtype::PROBE_RESP => {
            parse_beacon_body(raw)
        }
        // Probe Request
        frame_subtype::PROBE_REQ => {
            parse_probe_req_body(raw)
        }
        // Authentication
        frame_subtype::AUTH => {
            match frames::parse_auth(raw) {
                Some((hdr, body)) => FrameBody::Auth {
                    source: hdr.addr2,
                    target: hdr.addr1,
                    bssid: hdr.addr3,
                    algorithm: body.algo,
                    seq_num: body.seq,
                    status: body.status,
                },
                None => FrameBody::Unparseable { reason: "auth frame too short" },
            }
        }
        // Deauthentication
        frame_subtype::DEAUTH => {
            match frames::parse_deauth(raw) {
                Some((hdr, body)) => FrameBody::Deauth {
                    source: hdr.addr2,
                    target: hdr.addr1,
                    bssid: hdr.addr3,
                    reason: body.reason,
                },
                None => FrameBody::Unparseable { reason: "deauth frame too short" },
            }
        }
        // Disassociation
        frame_subtype::DISASSOC => {
            match frames::parse_disassoc(raw) {
                Some((hdr, body)) => FrameBody::Disassoc {
                    source: hdr.addr2,
                    target: hdr.addr1,
                    bssid: hdr.addr3,
                    reason: body.reason,
                },
                None => FrameBody::Unparseable { reason: "disassoc frame too short" },
            }
        }
        // Association Request
        frame_subtype::ASSOC_REQ => {
            match frames::parse_assoc_request(raw) {
                Some((hdr, body)) => {
                    let ies = if body.ies_len > 0 && body.ies_offset + body.ies_len <= raw.len() {
                        ie::parse_ies(&raw[body.ies_offset..body.ies_offset + body.ies_len])
                    } else {
                        ParsedIes::default()
                    };
                    FrameBody::AssocReq {
                        sta: hdr.addr2,
                        bssid: hdr.addr3,
                        capability: body.cap_info,
                        listen_interval: body.listen_interval,
                        ies,
                    }
                }
                None => FrameBody::Unparseable { reason: "assoc req too short" },
            }
        }
        // Association Response
        frame_subtype::ASSOC_RESP => {
            match frames::parse_assoc_response(raw) {
                Some((hdr, body)) => {
                    let ies = if body.ies_len > 0 && body.ies_offset + body.ies_len <= raw.len() {
                        ie::parse_ies(&raw[body.ies_offset..body.ies_offset + body.ies_len])
                    } else {
                        ParsedIes::default()
                    };
                    FrameBody::AssocResp {
                        sta: hdr.addr1,
                        bssid: hdr.addr2,
                        status: body.status,
                        aid: body.aid,
                        capability: body.cap_info,
                        ies,
                    }
                }
                None => FrameBody::Unparseable { reason: "assoc resp too short" },
            }
        }
        // Reassociation Request
        frame_subtype::REASSOC_REQ => {
            match frames::parse_reassoc_request(raw) {
                Some((hdr, body)) => {
                    let ies = if body.ies_len > 0 && body.ies_offset + body.ies_len <= raw.len() {
                        ie::parse_ies(&raw[body.ies_offset..body.ies_offset + body.ies_len])
                    } else {
                        ParsedIes::default()
                    };
                    FrameBody::ReassocReq {
                        sta: hdr.addr2,
                        bssid: hdr.addr3,
                        current_ap: body.current_ap,
                        capability: body.cap_info,
                        listen_interval: body.listen_interval,
                        ies,
                    }
                }
                None => FrameBody::Unparseable { reason: "reassoc req too short" },
            }
        }
        // Reassociation Response
        frame_subtype::REASSOC_RESP => {
            // Same format as AssocResp
            match frames::parse_assoc_response(raw) {
                Some((hdr, body)) => {
                    let ies = if body.ies_len > 0 && body.ies_offset + body.ies_len <= raw.len() {
                        ie::parse_ies(&raw[body.ies_offset..body.ies_offset + body.ies_len])
                    } else {
                        ParsedIes::default()
                    };
                    FrameBody::ReassocResp {
                        sta: hdr.addr1,
                        bssid: hdr.addr2,
                        status: body.status,
                        aid: body.aid,
                        capability: body.cap_info,
                        ies,
                    }
                }
                None => FrameBody::Unparseable { reason: "reassoc resp too short" },
            }
        }
        // Action / Action No Ack
        frame_subtype::ACTION | frame_subtype::ACTION_NO_ACK => {
            parse_action_body(raw)
        }
        // Unhandled management subtypes (Timing Advertisement, ATIM, etc.)
        _ => FrameBody::Unparseable { reason: "unhandled mgmt subtype" },
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Beacon / Probe Response parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_beacon_body(raw: &[u8]) -> FrameBody {
    match frames::parse_beacon(raw) {
        Some((hdr, body)) => {
            let ies = if body.ies_len > 0 && body.ies_offset + body.ies_len <= raw.len() {
                ie::parse_ies(&raw[body.ies_offset..body.ies_offset + body.ies_len])
            } else {
                ParsedIes::default()
            };
            let privacy = body.cap_info & crate::protocol::ieee80211::cap_info::PRIVACY != 0;
            FrameBody::Beacon {
                bssid: hdr.addr3,
                tsf: body.tsf,
                beacon_interval: body.beacon_interval,
                capability: body.cap_info,
                privacy,
                ies,
            }
        }
        None => FrameBody::Unparseable { reason: "beacon too short" },
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Probe Request parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_probe_req_body(raw: &[u8]) -> FrameBody {
    match frames::parse_probe_request(raw) {
        Some((hdr, body)) => {
            let ies = if body.ies_len > 0 && body.ies_offset + body.ies_len <= raw.len() {
                ie::parse_ies(&raw[body.ies_offset..body.ies_offset + body.ies_len])
            } else {
                ParsedIes::default()
            };
            let ssid = ies.ssid.clone().unwrap_or_default();
            FrameBody::ProbeReq {
                sta: hdr.addr2,
                ssid,
                ies,
            }
        }
        None => FrameBody::Unparseable { reason: "probe req too short" },
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Action frame parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_action_body(raw: &[u8]) -> FrameBody {
    let hdr = match frames::parse_mgmt_header(raw) {
        Some(h) => h,
        None => return FrameBody::Unparseable { reason: "action header too short" },
    };

    // Action frame body starts at offset 24 (after management header)
    if raw.len() < 26 {
        return FrameBody::Unparseable { reason: "action body too short" };
    }

    let category = raw[24];
    let action = raw[25];

    let detail = match category {
        // SA Query (category 8)
        8 => {
            let transaction_id = if raw.len() >= 28 {
                u16::from_le_bytes([raw[26], raw[27]])
            } else {
                0
            };
            ActionDetail::SaQuery {
                transaction_id,
                is_request: action == 0,
            }
        }
        // Radio Measurement (category 5)
        5 => {
            let dialog_token = if raw.len() > 26 { raw[26] } else { 0 };
            let repetitions = if action == 0 && raw.len() >= 29 {
                Some(u16::from_le_bytes([raw[27], raw[28]]))
            } else {
                None
            };
            ActionDetail::RadioMeasurement {
                action_code: action,
                dialog_token,
                is_request: action == 0,
                repetitions,
            }
        }
        // Fast Transition (category 6)
        6 => {
            match frames::parse_ft_action(raw) {
                Some((_hdr, ft)) => ActionDetail::FtAction {
                    action_code: ft.action,
                    sta_addr: ft.sta_addr,
                    target_ap: ft.target_ap,
                    status: ft.status.unwrap_or(0),
                },
                None => ActionDetail::Other { category, action },
            }
        }
        // Spectrum Management (category 0)
        0 => {
            let dialog_token = if raw.len() > 26 { raw[26] } else { 0 };
            ActionDetail::SpectrumMgmt {
                action_code: action,
                dialog_token,
            }
        }
        // WNM (category 10)
        10 => {
            match action {
                // BSS Transition Management Request (action 7)
                7 => {
                    let dialog_token = if raw.len() > 26 { raw[26] } else { 0 };
                    ActionDetail::BssTransition {
                        dialog_token,
                        is_request: true,
                        candidate_count: 0, // would need deeper parsing
                    }
                }
                // BSS Transition Management Response (action 8)
                8 => {
                    let dialog_token = if raw.len() > 26 { raw[26] } else { 0 };
                    ActionDetail::BssTransition {
                        dialog_token,
                        is_request: false,
                        candidate_count: 0,
                    }
                }
                // WNM Sleep Mode Request/Response (action 16/17)
                16 => ActionDetail::WnmSleep { is_request: true },
                17 => ActionDetail::WnmSleep { is_request: false },
                _ => ActionDetail::Other { category, action },
            }
        }
        // Block Ack (category 3)
        3 => ActionDetail::BlockAck { action_code: action },
        // TDLS (category 12)
        12 => ActionDetail::Tdls { action_code: action },
        // Everything else
        _ => ActionDetail::Other { category, action },
    };

    FrameBody::Action {
        source: hdr.addr2,
        target: hdr.addr1,
        bssid: hdr.addr3,
        category,
        action,
        detail,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Data frame parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_data(
    raw: &[u8],
    subtype: u8,
    to_ds: bool,
    from_ds: bool,
    protected: bool,
    is_qos: bool,
    order: bool,
) -> FrameBody {
    if raw.len() < 24 {
        return FrameBody::Unparseable { reason: "data frame too short" };
    }

    // Determine direction and extract STA/BSSID
    let (sta, bssid, direction) = if to_ds && !from_ds {
        // STA → AP: addr1=BSSID, addr2=STA
        let bssid = MacAddress::from_slice(&raw[4..10]).unwrap_or(MacAddress::ZERO);
        let sta = MacAddress::from_slice(&raw[10..16]).unwrap_or(MacAddress::ZERO);
        (sta, bssid, DataDirection::ToAp)
    } else if !to_ds && from_ds {
        // AP → STA: addr1=STA, addr2=BSSID
        let sta = MacAddress::from_slice(&raw[4..10]).unwrap_or(MacAddress::ZERO);
        let bssid = MacAddress::from_slice(&raw[10..16]).unwrap_or(MacAddress::ZERO);
        (sta, bssid, DataDirection::FromAp)
    } else if to_ds && from_ds {
        // WDS
        let addr1 = MacAddress::from_slice(&raw[4..10]).unwrap_or(MacAddress::ZERO);
        let addr2 = MacAddress::from_slice(&raw[10..16]).unwrap_or(MacAddress::ZERO);
        return FrameBody::Data {
            sta: addr2,
            bssid: addr1,
            direction: DataDirection::Wds,
            payload: DataPayload::Other,
        };
    } else {
        // IBSS
        let addr1 = MacAddress::from_slice(&raw[4..10]).unwrap_or(MacAddress::ZERO);
        let addr2 = MacAddress::from_slice(&raw[10..16]).unwrap_or(MacAddress::ZERO);
        return FrameBody::Data {
            sta: addr2,
            bssid: addr1,
            direction: DataDirection::Ibss,
            payload: DataPayload::Other,
        };
    };

    // Null data frames (subtype 4, 12) — no payload
    if subtype == 4 || subtype == 12 {
        return FrameBody::Data {
            sta, bssid, direction,
            payload: DataPayload::Null,
        };
    }

    // LLC/SNAP offset depends on QoS and HT Control field (Order bit)
    // QoS data: 24 (base) + 2 (QoS Control) = 26
    // QoS data + HTC: 24 + 2 + 4 (HT Control) = 30
    let htc_len: usize = if is_qos && order { 4 } else { 0 };
    let llc_off: usize = if is_qos { 26 + htc_len } else { 24 };

    if llc_off + 8 > raw.len() {
        return FrameBody::Data {
            sta, bssid, direction,
            payload: DataPayload::Other,
        };
    }

    let payload_bytes = &raw[llc_off..];

    // Check LLC/SNAP prefix
    if payload_bytes.len() >= 8 && payload_bytes[..6] == LLC_SNAP_PREFIX {
        let ethertype = u16::from_be_bytes([payload_bytes[6], payload_bytes[7]]);

        if ethertype == 0x888E {
            // EAPOL — parse it fully
            let parsed = eapol::parse_from_data_frame(payload_bytes);
            let payload = match parsed {
                Some(eapol) => DataPayload::Eapol(eapol),
                None => DataPayload::Llc { ethertype: 0x888E },
            };
            return FrameBody::Data { sta, bssid, direction, payload };
        }

        return FrameBody::Data {
            sta, bssid, direction,
            payload: DataPayload::Llc { ethertype },
        };
    }

    // If Protected bit was set but we didn't find valid LLC/SNAP, it's truly encrypted
    if protected {
        return FrameBody::Data {
            sta, bssid, direction,
            payload: DataPayload::Encrypted,
        };
    }

    FrameBody::Data {
        sta, bssid, direction,
        payload: DataPayload::Other,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Control frame parser
// ═══════════════════════════════════════════════════════════════════════════════

fn parse_control(raw: &[u8], subtype: u8) -> FrameBody {
    let detail = match subtype {
        // RTS (subtype 11)
        11 => {
            match frames::parse_rts(raw) {
                Some(rts) => ControlDetail::Rts {
                    ta: rts.ta, ra: rts.ra, duration: rts.duration,
                },
                None => ControlDetail::Other { subtype },
            }
        }
        // CTS (subtype 12)
        12 => {
            match frames::parse_cts(raw) {
                Some(cts) => ControlDetail::Cts {
                    ra: cts.ra, duration: cts.duration,
                },
                None => ControlDetail::Other { subtype },
            }
        }
        // ACK (subtype 13)
        13 => {
            match frames::parse_ack(raw) {
                Some(ack) => ControlDetail::Ack { ra: ack.ra },
                None => ControlDetail::Other { subtype },
            }
        }
        // Block Ack Request (subtype 8)
        8 => {
            match frames::parse_block_ack_req(raw) {
                Some(bar) => ControlDetail::BlockAckReq {
                    ta: bar.ta, ra: bar.ra, tid: bar.tid(), ssn: bar.starting_seq(),
                },
                None => ControlDetail::Other { subtype },
            }
        }
        // Block Ack (subtype 9)
        9 => {
            match frames::parse_block_ack(raw) {
                Some(ba) => ControlDetail::BlockAck {
                    ta: ba.ta, ra: ba.ra, tid: ba.tid(), ssn: ba.starting_seq(),
                },
                None => ControlDetail::Other { subtype },
            }
        }
        // PS-Poll (subtype 10)
        10 => {
            if raw.len() >= 16 {
                let bssid = MacAddress::from_slice(&raw[4..10]).unwrap_or(MacAddress::ZERO);
                let ta = MacAddress::from_slice(&raw[10..16]).unwrap_or(MacAddress::ZERO);
                ControlDetail::PsPoll { bssid, ta }
            } else {
                ControlDetail::Other { subtype }
            }
        }
        // CF-End (subtype 14)
        14 => {
            if raw.len() >= 16 {
                let bssid = MacAddress::from_slice(&raw[4..10]).unwrap_or(MacAddress::ZERO);
                let ta = MacAddress::from_slice(&raw[10..16]).unwrap_or(MacAddress::ZERO);
                ControlDetail::CfEnd { bssid, ta }
            } else {
                ControlDetail::Other { subtype }
            }
        }
        _ => ControlDetail::Other { subtype },
    };

    FrameBody::Control { detail }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_frame_too_short() {
        let frame = parse_frame(&[], -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(frame.body, FrameBody::Unparseable { .. }));
    }

    #[test]
    fn test_parse_frame_one_byte() {
        let frame = parse_frame(&[0x80], -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(frame.body, FrameBody::Unparseable { .. }));
    }

    #[test]
    fn test_parse_beacon_frame() {
        // Build a minimal beacon: FC(2) + Duration(2) + addr1(6) + addr2(6) + addr3(6) + seqctl(2)
        //   + TSF(8) + Beacon Interval(2) + Capability(2) + SSID IE(2+4)
        let mut frame = vec![0u8; 36 + 6]; // header + fixed + SSID IE
        frame[0] = 0x80; // FC: type=0 (mgmt), subtype=8 (beacon)
        frame[1] = 0x00;
        // addr1 = broadcast
        frame[4..10].copy_from_slice(&[0xFF; 6]);
        // addr2 = BSSID
        frame[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // addr3 = BSSID
        frame[16..22].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // TSF = 0, beacon_interval = 100 (0x64)
        frame[32] = 0x64;
        frame[33] = 0x00;
        // Capability = Privacy bit set (0x0010)
        frame[34] = 0x10;
        frame[35] = 0x00;
        // SSID IE: tag=0, len=4, "Test"
        frame[36] = 0x00; // SSID tag
        frame[37] = 0x04; // length
        frame[38] = b'T';
        frame[39] = b'e';
        frame[40] = b's';
        frame[41] = b't';

        let parsed = parse_frame(&frame, -42, 0, 0, 11, 0, Duration::from_millis(100));

        assert_eq!(parsed.frame_type, 0); // management
        assert_eq!(parsed.frame_subtype, 8); // beacon
        assert_eq!(parsed.rssi, -42);
        assert_eq!(parsed.channel, 11);

        match &parsed.body {
            FrameBody::Beacon { bssid, beacon_interval, privacy, ies, .. } => {
                assert_eq!(bssid.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                assert_eq!(*beacon_interval, 100);
                assert!(*privacy);
                assert_eq!(ies.ssid.as_deref(), Some("Test"));
            }
            other => panic!("expected Beacon, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_data_eapol_qos() {
        // Build a QoS Data frame with EAPOL payload
        // FC: type=2 (data), subtype=8 (QoS Data) → fc0 = 0x88
        let mut frame = vec![0u8; 26 + 8 + 4]; // header(26 for QoS) + LLC/SNAP(8) + EAPOL header(4)
        frame[0] = 0x88; // QoS Data
        frame[1] = 0x02; // From-DS
        // addr1 = STA
        frame[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        // addr2 = BSSID
        frame[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // addr3 = BSSID
        frame[16..22].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // QoS Control
        frame[24] = 0x00;
        frame[25] = 0x00;
        // LLC/SNAP for EAPOL
        frame[26..34].copy_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        // EAPOL header: version=2, type=0 (EAP-Packet), length=0
        frame[34] = 0x02; // version
        frame[35] = 0x00; // type = EAP-Packet
        frame[36] = 0x00; // body_len high
        frame[37] = 0x00; // body_len low

        let parsed = parse_frame(&frame, -55, 0, 0, 6, 0, Duration::from_millis(500));

        assert_eq!(parsed.frame_type, 2); // data
        assert!(parsed.is_qos);
        assert!(parsed.from_ds);
        assert!(!parsed.to_ds);

        match &parsed.body {
            FrameBody::Data { sta, bssid, direction, payload } => {
                assert_eq!(sta.0, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
                assert_eq!(bssid.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                assert_eq!(*direction, DataDirection::FromAp);
                // EAPOL was detected (even if body is too short for full EAPOL-Key parse)
                assert!(matches!(payload, DataPayload::Eapol(_) | DataPayload::Llc { ethertype: 0x888E }));
            }
            other => panic!("expected Data, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_deauth_frame() {
        // FC: type=0 (mgmt), subtype=12 (deauth) → fc0 = 0xC0
        let mut frame = vec![0u8; 26]; // header(24) + reason(2)
        frame[0] = 0xC0; // Deauth
        frame[1] = 0x00;
        frame[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]); // addr1 = target
        frame[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // addr2 = source
        frame[16..22].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // addr3 = BSSID
        frame[24] = 0x07; // reason = 7 (Class3FromNonAssoc)
        frame[25] = 0x00;

        let parsed = parse_frame(&frame, -60, 0, 0, 1, 0, Duration::ZERO);

        match &parsed.body {
            FrameBody::Deauth { source, target, reason, .. } => {
                assert_eq!(source.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                assert_eq!(target.0, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
                assert_eq!(*reason, 7);
            }
            other => panic!("expected Deauth, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_control_rts() {
        // RTS: FC(2) + Duration(2) + RA(6) + TA(6) = 16 bytes
        let mut frame = vec![0u8; 16];
        frame[0] = 0xB4; // type=1 (control), subtype=11 (RTS)
        frame[1] = 0x00;
        frame[2] = 0xFF; frame[3] = 0x7F; // duration = 32767
        frame[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]); // RA
        frame[10..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // TA

        let parsed = parse_frame(&frame, -70, 0, 0, 36, 1, Duration::ZERO);

        assert_eq!(parsed.frame_type, 1); // control
        assert_eq!(parsed.frame_subtype, 11); // RTS

        match &parsed.body {
            FrameBody::Control { detail: ControlDetail::Rts { ta, ra, duration } } => {
                assert_eq!(ra.0, [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]);
                assert_eq!(ta.0, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
                assert_eq!(*duration, 32767);
            }
            other => panic!("expected RTS, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_null_data() {
        // Null data: FC type=2, subtype=4
        let mut frame = vec![0u8; 24];
        frame[0] = 0x48; // type=2, subtype=4 (null)
        frame[1] = 0x01; // To-DS
        frame[4..10].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // addr1 = BSSID
        frame[10..16].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]); // addr2 = STA

        let parsed = parse_frame(&frame, -45, 0, 0, 6, 0, Duration::ZERO);

        match &parsed.body {
            FrameBody::Data { payload: DataPayload::Null, direction, .. } => {
                assert_eq!(*direction, DataDirection::ToAp);
            }
            other => panic!("expected null data, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_encrypted_data() {
        // Data frame with Protected bit set
        let mut frame = vec![0u8; 34]; // enough for LLC check
        frame[0] = 0x08; // type=2, subtype=0 (data)
        frame[1] = 0x42; // Protected=1, From-DS=1
        frame[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        frame[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let parsed = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);

        match &parsed.body {
            FrameBody::Data { payload: DataPayload::Encrypted, .. } => {}
            other => panic!("expected encrypted data, got {:?}", other),
        }
    }

    #[test]
    fn test_qos_all_subtypes_detected() {
        // QoS subtypes: 8, 9, 10, 11, 12 — all have bit 3 set
        for subtype in [8u8, 9, 10, 11, 12] {
            let mut frame = vec![0u8; 26];
            let fc0 = 0x08 | (subtype << 4); // type=2 (data) | subtype
            frame[0] = fc0;
            frame[1] = 0x01; // To-DS

            let parsed = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
            assert!(parsed.is_qos, "subtype {} should be QoS", subtype);
        }

        // Non-QoS subtypes: 0, 1, 2, 3, 4
        for subtype in [0u8, 1, 2, 3, 4] {
            let mut frame = vec![0u8; 24];
            let fc0 = 0x08 | (subtype << 4);
            frame[0] = fc0;
            frame[1] = 0x01;

            let parsed = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
            assert!(!parsed.is_qos, "subtype {} should NOT be QoS", subtype);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  COMPREHENSIVE ROUTING VERIFICATION
    //  Every frame type → correct FrameBody variant
    // ═══════════════════════════════════════════════════════════════════════════

    /// Build a minimal management frame with given subtype and body bytes.
    fn make_mgmt(subtype: u8, body: &[u8]) -> Vec<u8> {
        let fc0 = (subtype << 4) | 0x00; // type=0 (mgmt)
        let mut frame = vec![0u8; 24 + body.len()];
        frame[0] = fc0;
        frame[1] = 0x00;
        // addr1 (DA)
        frame[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        // addr2 (SA)
        frame[10..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // addr3 (BSSID)
        frame[16..22].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        frame[24..].copy_from_slice(body);
        frame
    }

    /// Build a data frame (QoS or not) with given payload after LLC offset.
    fn make_data_frame(to_ds: bool, from_ds: bool, is_qos: bool, protected: bool, payload: &[u8]) -> Vec<u8> {
        let subtype: u8 = if is_qos { 8 } else { 0 };
        let fc0 = (subtype << 4) | 0x08; // type=2 (data)
        let mut fc1: u8 = 0;
        if to_ds { fc1 |= 0x01; }
        if from_ds { fc1 |= 0x02; }
        if protected { fc1 |= 0x40; }

        let hdr_len = if is_qos { 26 } else { 24 };
        let mut frame = vec![0u8; hdr_len + payload.len()];
        frame[0] = fc0;
        frame[1] = fc1;
        // addr1
        frame[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        // addr2
        frame[10..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // addr3
        frame[16..22].copy_from_slice(&[0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC]);
        if is_qos {
            frame[24] = 0x00; // QoS Control
            frame[25] = 0x00;
        }
        frame[hdr_len..].copy_from_slice(payload);
        frame
    }

    /// Build a complete EAPOL-Key frame payload (LLC/SNAP + EAPOL header + key body).
    /// key_info determines which handshake message it represents.
    fn make_eapol_key(key_info: u16) -> Vec<u8> {
        make_eapol_key_with_data(key_info, &[])
    }

    fn make_eapol_key_with_data(key_info: u16, key_data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        // LLC/SNAP header
        payload.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        let body_len = 95 + key_data.len();
        // EAPOL header: version=2, type=3(Key), body_len
        payload.extend_from_slice(&[0x02, 0x03]);
        payload.extend_from_slice(&(body_len as u16).to_be_bytes());
        // EAPOL-Key body (95 bytes minimum):
        //   descriptor(1) + key_info(2) + key_length(2) + replay_counter(8)
        //   + nonce(32) + iv(16) + rsc(8) + reserved(8) + mic(16) + key_data_len(2)
        let mut body = vec![0u8; 95 + key_data.len()];
        body[0] = 0x02; // descriptor type = IEEE 802.11
        body[1] = (key_info >> 8) as u8; // key info high byte
        body[2] = (key_info & 0xFF) as u8; // key info low byte
        // key_length
        body[3] = 0x00;
        body[4] = 0x10; // 16 bytes
        // Fill nonce with non-zero (offset 13..45)
        for i in 13..45 {
            body[i] = (i & 0xFF) as u8;
        }
        // key_data_len at offset 93-94
        body[93..95].copy_from_slice(&(key_data.len() as u16).to_be_bytes());
        if !key_data.is_empty() {
            body[95..].copy_from_slice(key_data);
        }
        payload.extend_from_slice(&body);
        payload
    }

    // ── Management frame routing ──

    #[test]
    fn route_beacon() {
        let mut body = vec![0u8; 12]; // TSF(8) + interval(2) + cap(2)
        body.extend_from_slice(&[0x00, 0x04]); // SSID IE: tag=0, len=4
        body.extend_from_slice(b"Test");
        let frame = make_mgmt(8, &body); // subtype 8 = beacon
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Beacon { .. }), "beacon → FrameBody::Beacon");
    }

    #[test]
    fn route_probe_response() {
        let mut body = vec![0u8; 12];
        body.extend_from_slice(&[0x00, 0x04]);
        body.extend_from_slice(b"Test");
        let frame = make_mgmt(5, &body); // subtype 5 = probe response
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Beacon { .. }), "probe resp → FrameBody::Beacon");
    }

    #[test]
    fn route_probe_request() {
        let body = vec![0x00, 0x03, b'F', b'o', b'o']; // SSID IE
        let frame = make_mgmt(4, &body); // subtype 4 = probe request
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::ProbeReq { .. }), "probe req → FrameBody::ProbeReq");
    }

    #[test]
    fn route_auth() {
        let body = [0x00, 0x00, 0x01, 0x00, 0x00, 0x00]; // algo=0, seq=1, status=0
        let frame = make_mgmt(11, &body); // subtype 11 = auth
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Auth { .. }), "auth → FrameBody::Auth");
    }

    #[test]
    fn route_deauth() {
        let body = [0x03, 0x00]; // reason=3
        let frame = make_mgmt(12, &body); // subtype 12 = deauth
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Deauth { .. }), "deauth → FrameBody::Deauth");
    }

    #[test]
    fn route_disassoc() {
        let body = [0x08, 0x00]; // reason=8
        let frame = make_mgmt(10, &body); // subtype 10 = disassoc
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Disassoc { .. }), "disassoc → FrameBody::Disassoc");
    }

    #[test]
    fn route_assoc_req() {
        let mut body = vec![0u8; 4]; // cap_info(2) + listen_interval(2)
        body.extend_from_slice(&[0x00, 0x04]); // SSID IE
        body.extend_from_slice(b"Test");
        let frame = make_mgmt(0, &body); // subtype 0 = assoc req
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::AssocReq { .. }), "assoc req → FrameBody::AssocReq");
    }

    #[test]
    fn route_assoc_resp() {
        let body = [0x01, 0x00, 0x00, 0x00, 0x01, 0x00]; // cap(2) + status=0 + aid=1
        let frame = make_mgmt(1, &body); // subtype 1 = assoc resp
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::AssocResp { .. }), "assoc resp → FrameBody::AssocResp");
    }

    #[test]
    fn route_reassoc_req() {
        let mut body = vec![0u8; 10]; // cap_info(2) + listen_interval(2) + current_ap(6)
        body.extend_from_slice(&[0x00, 0x04]); // SSID IE
        body.extend_from_slice(b"Test");
        let frame = make_mgmt(2, &body); // subtype 2 = reassoc req
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::ReassocReq { .. }), "reassoc req → FrameBody::ReassocReq");
    }

    #[test]
    fn route_reassoc_resp() {
        let body = [0x01, 0x00, 0x00, 0x00, 0x01, 0x00]; // same as assoc resp
        let frame = make_mgmt(3, &body); // subtype 3 = reassoc resp
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::ReassocResp { .. }), "reassoc resp → FrameBody::ReassocResp");
    }

    #[test]
    fn route_action() {
        let body = [0x08, 0x00, 0x01, 0x00]; // category=8 (SA Query), action=0, txid
        let frame = make_mgmt(13, &body); // subtype 13 = action
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Action { .. }), "action → FrameBody::Action");
    }

    // ── Data frame routing ──

    #[test]
    fn route_data_plain() {
        let frame = make_data_frame(false, true, false, false, &[0x00; 10]);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Data { .. }), "data → FrameBody::Data");
    }

    #[test]
    fn route_data_null() {
        // Null data = subtype 4
        let mut frame = vec![0u8; 24];
        frame[0] = (4 << 4) | 0x08; // type=2 (data), subtype=4 (null)
        frame[1] = 0x02; // from_ds
        frame[4..10].copy_from_slice(&[0xAA; 6]);
        frame[10..16].copy_from_slice(&[0xBB; 6]);
        frame[16..22].copy_from_slice(&[0xCC; 6]);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        if let FrameBody::Data { payload, .. } = &pf.body {
            assert!(matches!(payload, DataPayload::Null), "null data → DataPayload::Null");
        } else {
            panic!("expected Data body");
        }
    }

    #[test]
    fn route_data_encrypted() {
        let frame = make_data_frame(false, true, false, true, &[0x00; 20]);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        if let FrameBody::Data { payload, .. } = &pf.body {
            assert!(matches!(payload, DataPayload::Encrypted), "protected=1 → DataPayload::Encrypted");
        } else {
            panic!("expected Data body");
        }
    }

    #[test]
    fn route_data_llc_non_eapol() {
        // LLC/SNAP with ethertype 0x0800 (IPv4)
        let payload = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00];
        let frame = make_data_frame(false, true, false, false, &payload);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        if let FrameBody::Data { payload: dp, .. } = &pf.body {
            assert!(matches!(dp, DataPayload::Llc { ethertype: 0x0800 }),
                "IPv4 LLC → DataPayload::Llc {{ ethertype: 0x0800 }}, got {:?}", dp);
        } else {
            panic!("expected Data body");
        }
    }

    // ── EAPOL routing — THE CRITICAL TESTS ──

    #[test]
    fn route_eapol_m1_non_qos() {
        // M1: pairwise=1, ack=1, mic=0 → ki = 0x008A
        let eapol = make_eapol_key(0x008A);
        let frame = make_data_frame(false, true, false, false, &eapol);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        if let FrameBody::Data { payload: DataPayload::Eapol(parsed), .. } = &pf.body {
            if let crate::protocol::eapol::ParsedEapol::Key { message, .. } = parsed {
                assert_eq!(*message, crate::protocol::eapol::HandshakeMessage::M1,
                    "EAPOL M1 must route to ParsedEapol::Key {{ message: M1 }}");
            } else {
                panic!("EAPOL M1: expected ParsedEapol::Key, got {:?}", parsed);
            }
        } else {
            panic!("EAPOL M1: expected DataPayload::Eapol, got {:?}", pf.body);
        }
    }

    #[test]
    fn route_eapol_m1_qos() {
        // Same as above but QoS data frame (subtype 8)
        let eapol = make_eapol_key(0x008A);
        let frame = make_data_frame(false, true, true, false, &eapol);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        if let FrameBody::Data { payload: DataPayload::Eapol(parsed), .. } = &pf.body {
            if let crate::protocol::eapol::ParsedEapol::Key { message, .. } = parsed {
                assert_eq!(*message, crate::protocol::eapol::HandshakeMessage::M1,
                    "EAPOL M1 (QoS) must route to M1");
            } else {
                panic!("EAPOL M1 (QoS): expected ParsedEapol::Key, got {:?}", parsed);
            }
        } else {
            panic!("EAPOL M1 (QoS): expected DataPayload::Eapol, got {:?}", pf.body);
        }
    }

    #[test]
    fn route_eapol_m2() {
        // M2: pairwise=1, mic=1, no ack/install/secure → ki = 0x010A
        // M2 carries RSN IE in key_data (non-empty distinguishes from M4)
        let rsn_ie = [0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
                      0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
                      0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00];
        let eapol = make_eapol_key_with_data(0x010A, &rsn_ie);
        let frame = make_data_frame(true, false, true, false, &eapol);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        if let FrameBody::Data { payload: DataPayload::Eapol(parsed), .. } = &pf.body {
            if let crate::protocol::eapol::ParsedEapol::Key { message, .. } = parsed {
                assert_eq!(*message, crate::protocol::eapol::HandshakeMessage::M2,
                    "EAPOL M2 must route to ParsedEapol::Key {{ message: M2 }}");
            } else {
                panic!("EAPOL M2: expected ParsedEapol::Key, got {:?}", parsed);
            }
        } else {
            panic!("EAPOL M2: expected DataPayload::Eapol, got {:?}", pf.body);
        }
    }

    #[test]
    fn route_eapol_m3() {
        // M3: pairwise=1, ack=1, mic=1, install=1, secure=1, encrypted=1 → ki = 0x13CA
        let eapol = make_eapol_key(0x13CA);
        let frame = make_data_frame(false, true, true, false, &eapol);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        if let FrameBody::Data { payload: DataPayload::Eapol(parsed), .. } = &pf.body {
            if let crate::protocol::eapol::ParsedEapol::Key { message, .. } = parsed {
                assert_eq!(*message, crate::protocol::eapol::HandshakeMessage::M3,
                    "EAPOL M3 must route to ParsedEapol::Key {{ message: M3 }}");
            } else {
                panic!("EAPOL M3: expected ParsedEapol::Key, got {:?}", parsed);
            }
        } else {
            panic!("EAPOL M3: expected DataPayload::Eapol, got {:?}", pf.body);
        }
    }

    #[test]
    fn route_eapol_m4() {
        // M4: pairwise=1, mic=1, secure=1, no ack/install → ki = 0x030A
        let eapol = make_eapol_key(0x030A);
        let frame = make_data_frame(true, false, true, false, &eapol);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        if let FrameBody::Data { payload: DataPayload::Eapol(parsed), .. } = &pf.body {
            if let crate::protocol::eapol::ParsedEapol::Key { message, .. } = parsed {
                assert_eq!(*message, crate::protocol::eapol::HandshakeMessage::M4,
                    "EAPOL M4 must route to ParsedEapol::Key {{ message: M4 }}");
            } else {
                panic!("EAPOL M4: expected ParsedEapol::Key, got {:?}", parsed);
            }
        } else {
            panic!("EAPOL M4: expected DataPayload::Eapol, got {:?}", pf.body);
        }
    }

    #[test]
    fn route_eapol_m3_not_blocked_by_protected_bit() {
        // M3 with Protected=0 (normal monitor mode capture) — must NOT be Encrypted
        let eapol = make_eapol_key(0x13CA);
        let frame = make_data_frame(false, true, true, false, &eapol);
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        if let FrameBody::Data { payload, .. } = &pf.body {
            assert!(!matches!(payload, DataPayload::Encrypted),
                "M3 with protected=false must NOT be classified as Encrypted");
            assert!(matches!(payload, DataPayload::Eapol(_)),
                "M3 with protected=false must be DataPayload::Eapol");
        } else {
            panic!("expected Data body");
        }
    }

    // ── Control frame routing ──

    #[test]
    fn route_control_rts() {
        let mut frame = vec![0u8; 16];
        frame[0] = 0xB4; // type=1 (ctrl), subtype=11 (RTS)
        frame[1] = 0x00;
        frame[4..10].copy_from_slice(&[0xAA; 6]); // RA
        frame[10..16].copy_from_slice(&[0xBB; 6]); // TA
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Control { detail: ControlDetail::Rts { .. } }),
            "RTS → ControlDetail::Rts");
    }

    #[test]
    fn route_control_cts() {
        let mut frame = vec![0u8; 10];
        frame[0] = 0xC4; // type=1 (ctrl), subtype=12 (CTS)
        frame[1] = 0x00;
        frame[4..10].copy_from_slice(&[0xAA; 6]); // RA
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Control { detail: ControlDetail::Cts { .. } }),
            "CTS → ControlDetail::Cts");
    }

    #[test]
    fn route_control_ack() {
        let mut frame = vec![0u8; 10];
        frame[0] = 0xD4; // type=1 (ctrl), subtype=13 (ACK)
        frame[1] = 0x00;
        frame[4..10].copy_from_slice(&[0xAA; 6]); // RA
        let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);
        assert!(matches!(pf.body, FrameBody::Control { detail: ControlDetail::Ack { .. } }),
            "ACK → ControlDetail::Ack");
    }

    // ── Summary test: verify ALL management subtypes route correctly ──

    #[test]
    fn route_all_mgmt_subtypes() {
        let results: Vec<(&str, u8, &str)> = vec![
            ("assoc_req", 0, "AssocReq"),
            ("assoc_resp", 1, "AssocResp"),
            ("reassoc_req", 2, "ReassocReq"),
            ("reassoc_resp", 3, "ReassocResp"),
            ("probe_req", 4, "ProbeReq"),
            ("probe_resp", 5, "Beacon"),
            ("beacon", 8, "Beacon"),
            ("disassoc", 10, "Disassoc"),
            ("auth", 11, "Auth"),
            ("deauth", 12, "Deauth"),
            ("action", 13, "Action"),
        ];

        for (name, subtype, expected) in &results {
            // Build appropriate body for each type
            let body: Vec<u8> = match *subtype {
                0 => { let mut b = vec![0u8; 4]; b.extend_from_slice(&[0x00, 0x01, b'X']); b } // assoc req
                1 | 3 => vec![0x01, 0x00, 0x00, 0x00, 0x01, 0x00], // assoc/reassoc resp
                2 => { let mut b = vec![0u8; 10]; b.extend_from_slice(&[0x00, 0x01, b'X']); b } // reassoc req
                4 => vec![0x00, 0x01, b'X'], // probe req
                5 | 8 => { let mut b = vec![0u8; 12]; b.extend_from_slice(&[0x00, 0x01, b'X']); b } // beacon/probe resp
                10 => vec![0x08, 0x00], // disassoc
                11 => vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x00], // auth
                12 => vec![0x03, 0x00], // deauth
                13 => vec![0x08, 0x00, 0x01, 0x00], // action (SA Query)
                _ => vec![],
            };

            let frame = make_mgmt(*subtype, &body);
            let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);

            let variant_name = match &pf.body {
                FrameBody::Beacon { .. } => "Beacon",
                FrameBody::ProbeReq { .. } => "ProbeReq",
                FrameBody::Auth { .. } => "Auth",
                FrameBody::Deauth { .. } => "Deauth",
                FrameBody::Disassoc { .. } => "Disassoc",
                FrameBody::AssocReq { .. } => "AssocReq",
                FrameBody::AssocResp { .. } => "AssocResp",
                FrameBody::ReassocReq { .. } => "ReassocReq",
                FrameBody::ReassocResp { .. } => "ReassocResp",
                FrameBody::Action { .. } => "Action",
                FrameBody::Unparseable { reason } => reason,
                _ => "Other",
            };

            assert_eq!(variant_name, *expected,
                "mgmt subtype {} ({}) → expected {}, got {}",
                subtype, name, expected, variant_name);
        }
    }

    // ── EAPOL message routing summary ──

    #[test]
    fn route_all_eapol_messages() {
        use crate::protocol::eapol::HandshakeMessage;

        let rsn_ie = [0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
                      0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
                      0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00];
        let cases: Vec<(&str, u16, HandshakeMessage, bool, bool, &[u8])> = vec![
            // (name, key_info, expected_msg, to_ds, from_ds, key_data)
            // M2 has RSN IE in key_data; M4 has empty key_data
            ("M1", 0x008A, HandshakeMessage::M1, false, true, &[]),
            ("M2", 0x010A, HandshakeMessage::M2, true, false, &rsn_ie),
            ("M3", 0x13CA, HandshakeMessage::M3, false, true, &[0xEE; 32]),
            ("M4", 0x030A, HandshakeMessage::M4, true, false, &[]),
        ];

        for (name, ki, expected_msg, to_ds, from_ds, key_data) in &cases {
            let eapol = make_eapol_key_with_data(*ki, key_data);
            let frame = make_data_frame(*to_ds, *from_ds, true, false, &eapol);
            let pf = parse_frame(&frame, -50, 0, 0, 6, 0, Duration::ZERO);

            match &pf.body {
                FrameBody::Data { payload: DataPayload::Eapol(parsed), .. } => {
                    match parsed {
                        crate::protocol::eapol::ParsedEapol::Key { message, .. } => {
                            assert_eq!(message, expected_msg,
                                "EAPOL {} (ki=0x{:04X}): expected {:?}, got {:?}",
                                name, ki, expected_msg, message);
                        }
                        other => panic!("EAPOL {}: expected Key, got {:?}", name, other),
                    }
                }
                FrameBody::Data { payload, .. } => {
                    panic!("EAPOL {}: expected DataPayload::Eapol, got {:?}", name, payload);
                }
                other => {
                    panic!("EAPOL {}: expected FrameBody::Data, got {:?}", name, other);
                }
            }
        }
    }
}
