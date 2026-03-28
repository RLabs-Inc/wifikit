#![allow(dead_code)]
//! ScanEvent, ScanEventType, EventDetail — discrete scanner events for the Events view.

use std::time::Duration;

use crate::core::MacAddress;
use crate::protocol::eapol::HandshakeQuality;

// ═══════════════════════════════════════════════════════════════════════════════
//  ScanEvent — discrete scanner events for the Events view
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ScanEvent {
    pub seq: u64,
    pub timestamp: Duration,
    pub event_type: ScanEventType,
    pub source: MacAddress,
    pub target: MacAddress,
    pub channel: u8,
    pub rssi: i8,
    pub detail: EventDetail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEventType {
    Auth,
    Deauth,
    AssocReq,
    AssocResp,
    ReassocReq,
    ReassocResp,
    Disassoc,
    BssTransitionReq,
    BssTransitionResp,
    SaQueryReq,
    SaQueryResp,
    TdlsSetup,
    TdlsTeardown,
    RadioMeasurementReq,
    RadioMeasurementResp,
    WnmSleepReq,
    WnmSleepResp,
    FtRequest,
    FtResponse,
    SpectrumAction,
    ControlRts,
    ControlCts,
    ControlBlockAckReq,
    ControlBlockAck,
    ActionOther,
    EapolM1,
    EapolM2,
    EapolM3,
    EapolM4,
    PmkidCaptured,
    HandshakeComplete,
    EapIdentity,
    EapMethod,
}

impl ScanEventType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Auth => "AUTH",
            Self::Deauth => "DEAUTH",
            Self::AssocReq => "ASSOC-REQ",
            Self::AssocResp => "ASSOC-RESP",
            Self::ReassocReq => "REASSOC-REQ",
            Self::ReassocResp => "REASSOC-RESP",
            Self::Disassoc => "DISASSOC",
            Self::BssTransitionReq => "BSS-TRANS-REQ",
            Self::BssTransitionResp => "BSS-TRANS-RESP",
            Self::SaQueryReq => "SA-QUERY-REQ",
            Self::SaQueryResp => "SA-QUERY-RESP",
            Self::TdlsSetup => "TDLS-SETUP",
            Self::TdlsTeardown => "TDLS-TEARDOWN",
            Self::RadioMeasurementReq => "RM-REQ",
            Self::RadioMeasurementResp => "RM-RESP",
            Self::WnmSleepReq => "WNM-SLEEP-REQ",
            Self::WnmSleepResp => "WNM-SLEEP-RESP",
            Self::FtRequest => "FT-REQ",
            Self::FtResponse => "FT-RESP",
            Self::SpectrumAction => "SPECTRUM",
            Self::ControlRts => "RTS",
            Self::ControlCts => "CTS",
            Self::ControlBlockAckReq => "BAR",
            Self::ControlBlockAck => "BA",
            Self::ActionOther => "ACTION",
            Self::EapolM1 => "EAPOL-M1",
            Self::EapolM2 => "EAPOL-M2",
            Self::EapolM3 => "EAPOL-M3",
            Self::EapolM4 => "EAPOL-M4",
            Self::PmkidCaptured => "PMKID",
            Self::HandshakeComplete => "HANDSHAKE",
            Self::EapIdentity => "EAP-ID",
            Self::EapMethod => "EAP-METHOD",
        }
    }
}

#[derive(Debug, Clone)]
pub enum EventDetail {
    None,
    Auth {
        algorithm: u16,
        seq_num: u16,
        status: u16,
    },
    Deauth {
        reason: u16,
        reason_str: &'static str,
    },
    Disassoc {
        reason: u16,
        reason_str: &'static str,
    },
    AssocReq {
        ssid: String,
        listen_interval: u16,
    },
    AssocResp {
        status: u16,
        aid: u16,
    },
    ReassocReq {
        ssid: String,
        current_ap: MacAddress,
    },
    Action {
        category: u8,
        action: u8,
        category_name: &'static str,
    },
    SaQuery {
        transaction_id: u16,
        is_request: bool,
    },
    BssTransition {
        action: u8,
        dialog_token: u8,
        status: Option<u8>,
        target_bssid: Option<MacAddress>,
    },
    FtAction {
        action: u8,
        sta_addr: MacAddress,
        target_ap: MacAddress,
        status: Option<u16>,
    },
    SpectrumMgmt {
        action: u8,
        dialog_token: u8,
    },
    RadioMeasurement {
        action: u8,
        dialog_token: u8,
        num_repetitions: Option<u16>,
    },
    ControlFrame {
        subtype_name: &'static str,
    },
    Eapol {
        message_num: u8,
    },
    Pmkid,
    HandshakeComplete {
        quality: HandshakeQuality,
    },
    EapIdentity {
        identity: String,
    },
    EapMethod {
        method: String,
    },
}
