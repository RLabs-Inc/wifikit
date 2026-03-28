//! IEEE 802.11 constants — frame control, IE tags, cipher suites, AKM types,
//! reason/status codes, capability info bits, and auth algorithms.
//!
//! This module contains NO I/O, NO parsing logic — just constants and enums.
//! Parsers live in `ie.rs`, `frames.rs`, `eapol.rs`.
#![allow(dead_code)]
#![allow(unused_imports)]
//!
//! Reference: IEEE Std 802.11-2020, wifi-map/libwifikit/wifikit.h

// ═══════════════════════════════════════════════════════════════════════════════
//  Frame Control — first 2 bytes of every 802.11 frame (little-endian)
// ═══════════════════════════════════════════════════════════════════════════════

/// Frame type field (bits 2-3 of frame control)
pub mod frame_type {
    pub const MANAGEMENT: u8 = 0;
    pub const CONTROL: u8 = 1;
    pub const DATA: u8 = 2;
}

/// Frame subtype field (bits 4-7 of frame control)
pub mod frame_subtype {
    // Management subtypes
    pub const ASSOC_REQ: u8 = 0;
    pub const ASSOC_RESP: u8 = 1;
    pub const REASSOC_REQ: u8 = 2;
    pub const REASSOC_RESP: u8 = 3;
    pub const PROBE_REQ: u8 = 4;
    pub const PROBE_RESP: u8 = 5;
    pub const TIMING_AD: u8 = 6;
    pub const BEACON: u8 = 8;
    pub const ATIM: u8 = 9;
    pub const DISASSOC: u8 = 10;
    pub const AUTH: u8 = 11;
    pub const DEAUTH: u8 = 12;
    pub const ACTION: u8 = 13;
    pub const ACTION_NO_ACK: u8 = 14;

    // Data subtypes
    pub const DATA: u8 = 0;
    pub const QOS_DATA: u8 = 8;
    pub const QOS_NULL: u8 = 12;
    pub const NULL_DATA: u8 = 4;
}

/// Control frame subtypes (for frame_type::CONTROL)
pub mod control_subtype {
    pub const BLOCK_ACK_REQ: u8 = 8;
    pub const BLOCK_ACK: u8 = 9;
    pub const PS_POLL: u8 = 10;
    pub const RTS: u8 = 11;
    pub const CTS: u8 = 12;
    pub const ACK: u8 = 13;
    pub const CF_END: u8 = 14;
    pub const CF_END_ACK: u8 = 15;
}

/// Pre-composed Frame Control byte 0 values (type + subtype combined).
/// These match the C `WIFIKIT_FC_*` constants exactly.
pub mod fc {
    pub const ASSOC_REQ: u8 = 0x00;
    pub const ASSOC_RESP: u8 = 0x10;
    pub const REASSOC_REQ: u8 = 0x20;
    pub const REASSOC_RESP: u8 = 0x30;
    pub const PROBE_REQ: u8 = 0x40;
    pub const PROBE_RESP: u8 = 0x50;
    pub const BEACON: u8 = 0x80;
    pub const DISASSOC: u8 = 0xA0;
    pub const AUTH: u8 = 0xB0;
    pub const DEAUTH: u8 = 0xC0;
    pub const ACTION: u8 = 0xD0;
    pub const DATA: u8 = 0x08;
    pub const NULL_DATA: u8 = 0x48;
    pub const QOS_DATA: u8 = 0x88;

    // Control frame subtypes (type=1, so bit 2 is set → 0x_4)
    pub const RTS: u8 = 0xB4;
    pub const CTS: u8 = 0xC4;
    pub const ACK: u8 = 0xD4;
}

/// Frame control flag bits (byte 1 of FC, and upper bits of byte 0).
pub mod fc_flags {
    pub const TO_DS: u8 = 0x01;       // FC byte 1, bit 0
    pub const FROM_DS: u8 = 0x02;     // FC byte 1, bit 1
    pub const MORE_FRAG: u8 = 0x04;   // FC byte 1, bit 2
    pub const RETRY: u8 = 0x08;       // FC byte 1, bit 3
    pub const POWER_MGMT: u8 = 0x10;  // FC byte 1, bit 4
    pub const MORE_DATA: u8 = 0x20;   // FC byte 1, bit 5
    pub const PROTECTED: u8 = 0x40;   // FC byte 1, bit 6
    pub const ORDER: u8 = 0x80;       // FC byte 1, bit 7 (HT control)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  802.11 frame geometry — byte offsets within management frames
// ═══════════════════════════════════════════════════════════════════════════════

/// Management frame header size: FC(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtl(2) = 24
pub const MGMT_HEADER_LEN: usize = 24;

/// Beacon/Probe Response fixed fields start at offset 24:
/// Timestamp(8) + Beacon Interval(2) + Capability Info(2) = 12 bytes
pub const BEACON_FIXED_LEN: usize = 12;

/// Tagged parameters start at offset 36 in beacons/probe responses
pub const BEACON_TAGS_OFFSET: usize = MGMT_HEADER_LEN + BEACON_FIXED_LEN;

/// Auth frame body: Auth Algo(2) + Auth Seq(2) + Status(2) = 6 bytes
pub const AUTH_BODY_LEN: usize = 6;

/// Assoc Request fixed fields: Capability(2) + Listen Interval(2) = 4 bytes
pub const ASSOC_REQ_FIXED_LEN: usize = 4;

/// Assoc Response fixed fields: Capability(2) + Status(2) + AID(2) = 6 bytes
pub const ASSOC_RESP_FIXED_LEN: usize = 6;

/// Max 802.11 frame size
pub const MAX_FRAME_LEN: usize = 2346;

// ═══════════════════════════════════════════════════════════════════════════════
//  Information Element tag numbers
// ═══════════════════════════════════════════════════════════════════════════════

pub mod ie_tag {
    pub const SSID: u8 = 0;
    pub const SUPPORTED_RATES: u8 = 1;
    pub const DS_PARAMS: u8 = 3;         // Direct Sequence Parameter Set (channel)
    pub const TIM: u8 = 5;               // Traffic Indication Map
    pub const COUNTRY: u8 = 7;
    pub const QBSS_LOAD: u8 = 11;        // BSS Load (station count, utilization)
    pub const CHALLENGE_TEXT: u8 = 16;
    pub const POWER_CONSTRAINT: u8 = 32;
    pub const TPC_REPORT: u8 = 35;
    pub const CSA: u8 = 37;              // Channel Switch Announcement
    pub const ERP: u8 = 42;              // 802.11g Extended Rate PHY
    pub const HT_CAPABILITIES: u8 = 45;  // 802.11n
    pub const QOS_CAPABILITY: u8 = 46;   // QoS Capability
    pub const RSN: u8 = 48;              // Robust Security Network (WPA2/WPA3)
    pub const EXTENDED_RATES: u8 = 50;
    pub const MOBILITY_DOMAIN: u8 = 54;  // 802.11r Fast Transition
    pub const FAST_BSS_TRANSITION: u8 = 55;
    pub const TIMEOUT_INTERVAL: u8 = 56;
    pub const HT_OPERATION: u8 = 61;     // 802.11n operation
    pub const RM_ENABLED_CAPABILITIES: u8 = 70; // 802.11k Radio Measurement
    pub const MULTI_BSSID: u8 = 71;      // Multiple BSSID
    pub const INTERWORKING: u8 = 107;    // Hotspot 2.0 / Passpoint
    pub const EXTENDED_CAPABILITIES: u8 = 127;
    pub const VHT_CAPABILITIES: u8 = 191; // 802.11ac
    pub const VHT_OPERATION: u8 = 192;
    pub const RNR: u8 = 201;             // Reduced Neighbor Report
    pub const VENDOR_SPECIFIC: u8 = 221;
    pub const EXTENSION: u8 = 255;       // Extension element (HE, etc.)
}

/// Extension element IDs (used with ie_tag::EXTENSION = 255)
pub mod ie_ext_id {
    pub const HE_CAPABILITIES: u8 = 35;
    pub const HE_OPERATION: u8 = 36;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Vendor OUIs — for identifying vendor-specific IEs
// ═══════════════════════════════════════════════════════════════════════════════

/// Microsoft WPA OUI: 00:50:F2
pub const OUI_MICROSOFT: [u8; 3] = [0x00, 0x50, 0xF2];

/// WPA IE vendor type (OUI_MICROSOFT + type 1)
pub const OUI_TYPE_WPA: u8 = 0x01;

/// WPS IE vendor type (OUI_MICROSOFT + type 4)
pub const OUI_TYPE_WPS: u8 = 0x04;

// ═══════════════════════════════════════════════════════════════════════════════
//  Cipher Suite types — OUI 00-0F-AC (IEEE)
// ═══════════════════════════════════════════════════════════════════════════════

/// IEEE cipher suite OUI (used in RSN IE)
pub const OUI_IEEE: [u8; 3] = [0x00, 0x0F, 0xAC];

/// Cipher suite type (4th byte after OUI in RSN IE cipher suite selector)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CipherSuite {
    #[default]
    None = 0,
    Wep40 = 1,
    Tkip = 2,
    // 3 is reserved
    Ccmp = 4,
    Wep104 = 5,
    // 6 = BIP-CMAC-128
    BipCmac128 = 6,
    // 7 = Group addressed traffic not allowed
    // 8 = GCMP-128
    Gcmp = 8,
    Gcmp256 = 9,
    Ccmp256 = 10,
    BipGmac128 = 11,
    BipGmac256 = 12,
    BipCmac256 = 13,
}

impl CipherSuite {
    pub fn from_suite_type(val: u8) -> Self {
        match val {
            0 => Self::None,
            1 => Self::Wep40,
            2 => Self::Tkip,
            4 => Self::Ccmp,
            5 => Self::Wep104,
            6 => Self::BipCmac128,
            8 => Self::Gcmp,
            9 => Self::Gcmp256,
            10 => Self::Ccmp256,
            11 => Self::BipGmac128,
            12 => Self::BipGmac256,
            13 => Self::BipCmac256,
            _ => Self::None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Wep40 => "WEP-40",
            Self::Tkip => "TKIP",
            Self::Ccmp => "CCMP",
            Self::Wep104 => "WEP-104",
            Self::BipCmac128 => "BIP-CMAC-128",
            Self::Gcmp => "GCMP-128",
            Self::Gcmp256 => "GCMP-256",
            Self::Ccmp256 => "CCMP-256",
            Self::BipGmac128 => "BIP-GMAC-128",
            Self::BipGmac256 => "BIP-GMAC-256",
            Self::BipCmac256 => "BIP-CMAC-256",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AKM Suite types — OUI 00-0F-AC (IEEE)
// ═══════════════════════════════════════════════════════════════════════════════

/// AKM suite type (4th byte after OUI in RSN IE AKM suite selector)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum AkmSuite {
    #[default]
    None = 0,
    Ieee8021x = 1,
    Psk = 2,
    Ft8021x = 3,
    FtPsk = 4,
    Ieee8021xSha256 = 5,
    PskSha256 = 6,
    // 7 = TDLS
    Sae = 8,
    FtSae = 9,
    // 10 = AP Peer Key
    // 11 = 802.1X Suite B SHA-256
    SuiteB = 12,           // 802.1X Suite B SHA-384 (WPA3-Enterprise 192-bit)
    // 13-17 = various
    Owe = 18,              // Opportunistic Wireless Encryption
}

impl AkmSuite {
    pub fn from_suite_type(val: u8) -> Self {
        match val {
            0 => Self::None,
            1 => Self::Ieee8021x,
            2 => Self::Psk,
            3 => Self::Ft8021x,
            4 => Self::FtPsk,
            5 => Self::Ieee8021xSha256,
            6 => Self::PskSha256,
            8 => Self::Sae,
            9 => Self::FtSae,
            12 => Self::SuiteB,
            18 => Self::Owe,
            _ => Self::None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Ieee8021x => "802.1X",
            Self::Psk => "PSK",
            Self::Ft8021x => "FT-802.1X",
            Self::FtPsk => "FT-PSK",
            Self::Ieee8021xSha256 => "802.1X-SHA256",
            Self::PskSha256 => "PSK-SHA256",
            Self::Sae => "SAE",
            Self::FtSae => "FT-SAE",
            Self::SuiteB => "SUITE-B-192",
            Self::Owe => "OWE",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Security level — derived from RSN IE parsing
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum Security {
    #[default]
    Open = 0,
    Wep = 1,
    Wpa = 2,
    Wpa2 = 3,
    Wpa2Enterprise = 4,
    Wpa3 = 5,
    Wpa3Enterprise = 6,
    Owe = 7,
}

impl Security {
    /// Derive security level from AKM suite
    pub fn from_akm(akm: AkmSuite) -> Self {
        match akm {
            AkmSuite::Sae | AkmSuite::FtSae => Self::Wpa3,
            AkmSuite::Owe => Self::Owe,
            AkmSuite::SuiteB => Self::Wpa3Enterprise,
            AkmSuite::Ieee8021x | AkmSuite::Ieee8021xSha256 => Self::Wpa2Enterprise,
            AkmSuite::Psk | AkmSuite::PskSha256 | AkmSuite::FtPsk | AkmSuite::Ft8021x => {
                Self::Wpa2
            }
            AkmSuite::None => Self::Open,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Wep => "WEP",
            Self::Wpa => "WPA",
            Self::Wpa2 => "WPA2",
            Self::Wpa2Enterprise => "WPA2-Enterprise",
            Self::Wpa3 => "WPA3",
            Self::Wpa3Enterprise => "WPA3-Enterprise",
            Self::Owe => "OWE",
        }
    }

    /// Short name for compact table columns (max 6 chars).
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Wep => "WEP",
            Self::Wpa => "WPA",
            Self::Wpa2 => "WPA2",
            Self::Wpa2Enterprise => "WPA2-E",
            Self::Wpa3 => "WPA3",
            Self::Wpa3Enterprise => "WPA3-E",
            Self::Owe => "OWE",
        }
    }
}

impl std::fmt::Display for Security {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Capability Info bits — from beacon/probe response fixed fields
// ═══════════════════════════════════════════════════════════════════════════════

pub mod cap_info {
    pub const ESS: u16 = 1 << 0;
    pub const IBSS: u16 = 1 << 1;
    pub const CF_POLLABLE: u16 = 1 << 2;
    pub const CF_POLL_REQUEST: u16 = 1 << 3;
    pub const PRIVACY: u16 = 1 << 4;
    pub const SHORT_PREAMBLE: u16 = 1 << 5;
    pub const SPECTRUM_MGMT: u16 = 1 << 8;
    pub const QOS: u16 = 1 << 9;
    pub const SHORT_SLOT: u16 = 1 << 10;
    pub const APSD: u16 = 1 << 11;
    pub const RADIO_MEASUREMENT: u16 = 1 << 12;
    pub const DSSS_OFDM: u16 = 1 << 13;
    pub const DELAYED_BA: u16 = 1 << 14;
    pub const IMMEDIATE_BA: u16 = 1 << 15;

    /// Standard baseline for AP: ESS + Short Preamble + Short Slot Time
    pub const BASE: u16 = ESS | SHORT_PREAMBLE | SHORT_SLOT;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Authentication algorithms
// ═══════════════════════════════════════════════════════════════════════════════

pub mod auth_algo {
    pub const OPEN_SYSTEM: u16 = 0;
    pub const SHARED_KEY: u16 = 1;
    pub const FAST_BSS_TRANSITION: u16 = 2;
    pub const SAE: u16 = 3;
    pub const FILS_SK: u16 = 4;
    pub const FILS_SK_PFS: u16 = 5;
    pub const FILS_PK: u16 = 6;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Reason codes — used in deauth/disassoc frames (IEEE 802.11-2020 Table 9-49)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ReasonCode {
    Unspecified = 1,
    AuthNoLongerValid = 2,
    DeauthLeaving = 3,
    Inactivity = 4,
    ApFull = 5,
    Class2FromNonAuth = 6,
    Class3FromNonAssoc = 7,
    DisassocLeaving = 8,
    NotAuthenticated = 9,
    UnacceptablePower = 10,
    UnacceptableChannel = 11,
    BssTransition = 12,
    InvalidIe = 13,
    MicFailure = 14,
    FourwayTimeout = 15,
    GroupKeyTimeout = 16,
    IeMismatch = 17,
    InvalidGroupCipher = 18,
    InvalidPairwiseCipher = 19,
    InvalidAkmp = 20,
    UnsupportedRsnVersion = 21,
    InvalidRsnCaps = 22,
    Ieee8021xAuthFailed = 23,
    CipherRejected = 24,
    TdlsTeardownUnreachable = 25,
    TdlsTeardownUnspecified = 26,
    SspRequested = 27,
    NoSspRoaming = 28,
    BadCipherOrAkm = 29,
    NotAuthorized = 30,
    ServiceChange = 31,
    MeshPeeringCancelled = 52,
    MeshMaxPeers = 53,
}

impl ReasonCode {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(Self::Unspecified),
            2 => Some(Self::AuthNoLongerValid),
            3 => Some(Self::DeauthLeaving),
            4 => Some(Self::Inactivity),
            5 => Some(Self::ApFull),
            6 => Some(Self::Class2FromNonAuth),
            7 => Some(Self::Class3FromNonAssoc),
            8 => Some(Self::DisassocLeaving),
            9 => Some(Self::NotAuthenticated),
            10 => Some(Self::UnacceptablePower),
            11 => Some(Self::UnacceptableChannel),
            12 => Some(Self::BssTransition),
            13 => Some(Self::InvalidIe),
            14 => Some(Self::MicFailure),
            15 => Some(Self::FourwayTimeout),
            16 => Some(Self::GroupKeyTimeout),
            17 => Some(Self::IeMismatch),
            18 => Some(Self::InvalidGroupCipher),
            19 => Some(Self::InvalidPairwiseCipher),
            20 => Some(Self::InvalidAkmp),
            21 => Some(Self::UnsupportedRsnVersion),
            22 => Some(Self::InvalidRsnCaps),
            23 => Some(Self::Ieee8021xAuthFailed),
            24 => Some(Self::CipherRejected),
            25 => Some(Self::TdlsTeardownUnreachable),
            26 => Some(Self::TdlsTeardownUnspecified),
            27 => Some(Self::SspRequested),
            28 => Some(Self::NoSspRoaming),
            29 => Some(Self::BadCipherOrAkm),
            30 => Some(Self::NotAuthorized),
            31 => Some(Self::ServiceChange),
            52 => Some(Self::MeshPeeringCancelled),
            53 => Some(Self::MeshMaxPeers),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Unspecified => "Unspecified",
            Self::AuthNoLongerValid => "Auth no longer valid",
            Self::DeauthLeaving => "Deauth: STA leaving",
            Self::Inactivity => "Inactivity",
            Self::ApFull => "AP full",
            Self::Class2FromNonAuth => "Class 2 from non-auth STA",
            Self::Class3FromNonAssoc => "Class 3 from non-assoc STA",
            Self::DisassocLeaving => "Disassoc: STA leaving",
            Self::NotAuthenticated => "Not authenticated",
            Self::UnacceptablePower => "Unacceptable power capability",
            Self::UnacceptableChannel => "Unacceptable supported channels",
            Self::BssTransition => "BSS Transition",
            Self::InvalidIe => "Invalid IE",
            Self::MicFailure => "MIC failure (TKIP)",
            Self::FourwayTimeout => "4-Way Handshake timeout",
            Self::GroupKeyTimeout => "Group key timeout",
            Self::IeMismatch => "IE mismatch",
            Self::InvalidGroupCipher => "Invalid group cipher",
            Self::InvalidPairwiseCipher => "Invalid pairwise cipher",
            Self::InvalidAkmp => "Invalid AKMP",
            Self::UnsupportedRsnVersion => "Unsupported RSN version",
            Self::InvalidRsnCaps => "Invalid RSN capabilities",
            Self::Ieee8021xAuthFailed => "802.1X auth failed",
            Self::CipherRejected => "Cipher rejected",
            Self::TdlsTeardownUnreachable => "TDLS teardown: unreachable",
            Self::TdlsTeardownUnspecified => "TDLS teardown: unspecified",
            Self::SspRequested => "SSP requested",
            Self::NoSspRoaming => "No SSP roaming agreement",
            Self::BadCipherOrAkm => "Bad cipher or AKM",
            Self::NotAuthorized => "Not authorized",
            Self::ServiceChange => "Service change",
            Self::MeshPeeringCancelled => "Mesh peering cancelled",
            Self::MeshMaxPeers => "Mesh max peers reached",
        }
    }
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), *self as u16)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status codes — used in auth/assoc response frames (IEEE 802.11-2020 Table 9-50)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusCode {
    Success = 0,
    Failure = 1,
    CapabilitiesUnsupported = 10,
    ReassocDenied = 11,
    AssocDeniedOther = 12,
    UnsupportedAuthAlgo = 13,
    TransSequenceError = 14,
    ChallengeFailure = 15,
    AuthTimeout = 16,
    ApFull = 17,
    UnsupportedRate = 18,
    UnsupportedShortPreamble = 19,
    UnsupportedShortSlot = 25,
    InvalidRsn = 40,
    InvalidRsnCaps = 45,
    CipherRejected = 46,
    InvalidFtAction = 53,
    InvalidPmkid = 54,
    InvalidMde = 55,
    InvalidFte = 56,
    AntiCloggingTokenRequired = 76,
    FiniteCyclicGroupNotSupported = 77,
    UnknownAuthTransaction = 79,
    SaeHashToElement = 126,
}

impl StatusCode {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Success),
            1 => Some(Self::Failure),
            10 => Some(Self::CapabilitiesUnsupported),
            11 => Some(Self::ReassocDenied),
            12 => Some(Self::AssocDeniedOther),
            13 => Some(Self::UnsupportedAuthAlgo),
            14 => Some(Self::TransSequenceError),
            15 => Some(Self::ChallengeFailure),
            16 => Some(Self::AuthTimeout),
            17 => Some(Self::ApFull),
            18 => Some(Self::UnsupportedRate),
            19 => Some(Self::UnsupportedShortPreamble),
            25 => Some(Self::UnsupportedShortSlot),
            40 => Some(Self::InvalidRsn),
            45 => Some(Self::InvalidRsnCaps),
            46 => Some(Self::CipherRejected),
            53 => Some(Self::InvalidFtAction),
            54 => Some(Self::InvalidPmkid),
            55 => Some(Self::InvalidMde),
            56 => Some(Self::InvalidFte),
            76 => Some(Self::AntiCloggingTokenRequired),
            77 => Some(Self::FiniteCyclicGroupNotSupported),
            79 => Some(Self::UnknownAuthTransaction),
            126 => Some(Self::SaeHashToElement),
            _ => None,
        }
    }

    pub fn is_success(&self) -> bool {
        *self == Self::Success
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::Failure => "Failure",
            Self::CapabilitiesUnsupported => "Capabilities unsupported",
            Self::ReassocDenied => "Reassociation denied",
            Self::AssocDeniedOther => "Association denied",
            Self::UnsupportedAuthAlgo => "Unsupported auth algorithm",
            Self::TransSequenceError => "Transaction sequence error",
            Self::ChallengeFailure => "Challenge failure",
            Self::AuthTimeout => "Auth timeout",
            Self::ApFull => "AP full",
            Self::UnsupportedRate => "Unsupported rate",
            Self::UnsupportedShortPreamble => "Short preamble unsupported",
            Self::UnsupportedShortSlot => "Short slot unsupported",
            Self::InvalidRsn => "Invalid RSN IE",
            Self::InvalidRsnCaps => "Invalid RSN capabilities",
            Self::CipherRejected => "Cipher rejected",
            Self::InvalidFtAction => "Invalid FT action",
            Self::InvalidPmkid => "Invalid PMKID",
            Self::InvalidMde => "Invalid MDE",
            Self::InvalidFte => "Invalid FTE",
            Self::AntiCloggingTokenRequired => "Anti-clogging token required",
            Self::FiniteCyclicGroupNotSupported => "Finite cyclic group not supported",
            Self::UnknownAuthTransaction => "Unknown auth transaction",
            Self::SaeHashToElement => "SAE Hash-to-Element",
        }
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), *self as u16)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WiFi generation — derived from IE presence
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum WifiGeneration {
    #[default]
    Legacy = 0,    // 802.11a/b/g
    Wifi4 = 4,     // 802.11n (HT)
    Wifi5 = 5,     // 802.11ac (VHT)
    Wifi6 = 6,     // 802.11ax (HE)
    Wifi6e = 7,    // 802.11ax in 6 GHz
    Wifi7 = 8,     // 802.11be (EHT)
}

impl WifiGeneration {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Legacy => "Legacy",
            Self::Wifi4 => "Wi-Fi 4 (11n)",
            Self::Wifi5 => "Wi-Fi 5 (11ac)",
            Self::Wifi6 => "Wi-Fi 6 (11ax)",
            Self::Wifi6e => "Wi-Fi 6E",
            Self::Wifi7 => "Wi-Fi 7 (11be)",
        }
    }
}

impl std::fmt::Display for WifiGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Action frame categories — for action frames (fc::ACTION)
// ═══════════════════════════════════════════════════════════════════════════════

pub mod action_category {
    pub const SPECTRUM_MGMT: u8 = 0;
    pub const QOS: u8 = 1;
    pub const DLS: u8 = 2;
    pub const BLOCK_ACK: u8 = 3;
    pub const RADIO_MEASUREMENT: u8 = 5;
    pub const FAST_BSS_TRANSITION: u8 = 6;
    pub const SA_QUERY: u8 = 8;
    pub const WNM: u8 = 10;
    pub const UNPROTECTED_WNM: u8 = 11;
    pub const TDLS: u8 = 12;
    pub const VENDOR_SPECIFIC: u8 = 127;
}

/// WNM action types (within action_category::WNM)
pub mod wnm_action {
    pub const BSS_TRANSITION_MGMT_QUERY: u8 = 6;
    pub const BSS_TRANSITION_MGMT_REQ: u8 = 7;
    pub const BSS_TRANSITION_MGMT_RESP: u8 = 8;
    pub const SLEEP_MODE_REQ: u8 = 16;
    pub const SLEEP_MODE_RESP: u8 = 17;
}

/// SA Query action types (within action_category::SA_QUERY)
pub mod sa_query_action {
    pub const REQUEST: u8 = 0;
    pub const RESPONSE: u8 = 1;
}

/// Fast BSS Transition action types (within action_category::FAST_BSS_TRANSITION)
/// IEEE 802.11-2020 §9.6.10
pub mod ft_action {
    pub const FT_REQUEST: u8 = 1;
    pub const FT_RESPONSE: u8 = 2;
    pub const FT_CONFIRM: u8 = 3;
    pub const FT_ACK: u8 = 4;
}

/// Spectrum Management action types (within action_category::SPECTRUM_MGMT)
/// IEEE 802.11-2020 §9.6.2
pub mod spectrum_action {
    pub const MEASUREMENT_REQ: u8 = 0;
    pub const MEASUREMENT_REPORT: u8 = 1;
    pub const TPC_REQUEST: u8 = 2;
    pub const TPC_REPORT: u8 = 3;
    pub const CHANNEL_SWITCH_ANNOUNCEMENT: u8 = 4;
}

/// Radio Measurement action types (within action_category::RADIO_MEASUREMENT)
/// IEEE 802.11-2020 §9.6.6
pub mod radio_measurement_action {
    pub const RADIO_MEASUREMENT_REQ: u8 = 0;
    pub const RADIO_MEASUREMENT_REPORT: u8 = 1;
    pub const LINK_MEASUREMENT_REQ: u8 = 2;
    pub const LINK_MEASUREMENT_REPORT: u8 = 3;
    pub const NEIGHBOR_REPORT_REQ: u8 = 4;
    pub const NEIGHBOR_REPORT_RESP: u8 = 5;
}

/// DLS action types (within action_category::DLS)
pub mod dls_action {
    pub const DLS_REQUEST: u8 = 0;
    pub const DLS_RESPONSE: u8 = 1;
    pub const DLS_TEARDOWN: u8 = 2;
}

/// TDLS action types (within action_category::TDLS)
/// Note: TDLS actions travel inside data frames with LLC/SNAP, not as management action frames
pub mod tdls_action {
    pub const SETUP_REQUEST: u8 = 0;
    pub const SETUP_RESPONSE: u8 = 1;
    pub const SETUP_CONFIRM: u8 = 2;
    pub const TEARDOWN: u8 = 3;
    pub const PEER_TRAFFIC_INDICATION: u8 = 4;
    pub const CHANNEL_SWITCH_REQ: u8 = 5;
    pub const CHANNEL_SWITCH_RESP: u8 = 6;
    pub const PEER_PSM_REQ: u8 = 7;
    pub const PEER_PSM_RESP: u8 = 8;
    pub const PEER_TRAFFIC_RESP: u8 = 9;
    pub const DISCOVERY_REQ: u8 = 10;
}

/// CSA (Channel Switch Announcement) element in action frames
pub mod csa {
    pub const ELEMENT_ID: u8 = 37;
    pub const ELEMENT_LEN: u8 = 3;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAPOL — used in 4-way handshake, group key handshake
// ═══════════════════════════════════════════════════════════════════════════════

pub mod eapol {
    /// LLC/SNAP header for EAPOL (AA:AA:03:00:00:00:88:8E)
    pub const LLC_SNAP: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];

    /// EtherType for EAPOL
    pub const ETHERTYPE: u16 = 0x888E;

    /// EAPOL packet types
    pub const TYPE_EAP: u8 = 0;
    pub const TYPE_START: u8 = 1;
    pub const TYPE_LOGOFF: u8 = 2;
    pub const TYPE_KEY: u8 = 3;

    /// EAPOL-Key descriptor type
    pub const KEY_DESC_RSN: u8 = 2;

    /// Key Info bit positions (in the 2-byte Key Information field)
    pub const KEY_INFO_TYPE_HMAC_MD5: u16 = 1;     // bit 0-2 = 1 → HMAC-MD5/RC4
    pub const KEY_INFO_TYPE_HMAC_SHA1: u16 = 2;     // bit 0-2 = 2 → HMAC-SHA1/AES
    pub const KEY_INFO_PAIRWISE: u16 = 1 << 3;      // bit 3
    pub const KEY_INFO_INSTALL: u16 = 1 << 6;        // bit 6
    pub const KEY_INFO_ACK: u16 = 1 << 7;            // bit 7
    pub const KEY_INFO_MIC: u16 = 1 << 8;            // bit 8
    pub const KEY_INFO_SECURE: u16 = 1 << 9;         // bit 9
    pub const KEY_INFO_ERROR: u16 = 1 << 10;         // bit 10
    pub const KEY_INFO_REQUEST: u16 = 1 << 11;       // bit 11
    pub const KEY_INFO_ENCRYPTED: u16 = 1 << 12;     // bit 12

    /// EAPOL-Key header size: Version(1) + Type(1) + Length(2) + DescType(1) + KeyInfo(2)
    /// + KeyLen(2) + ReplayCounter(8) + Nonce(32) + IV(16) + RSC(8) + Reserved(8) + MIC(16) + DataLen(2)
    pub const KEY_HEADER_LEN: usize = 99;

    /// Nonce offset within EAPOL-Key frame body (after LLC/SNAP + EAPOL header)
    pub const KEY_NONCE_OFFSET: usize = 17;
    pub const KEY_NONCE_LEN: usize = 32;

    /// MIC offset within EAPOL-Key frame body
    pub const KEY_MIC_OFFSET: usize = 81;
    pub const KEY_MIC_LEN: usize = 16;

    /// Key Data length field offset
    pub const KEY_DATA_LEN_OFFSET: usize = 97;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP — Extensible Authentication Protocol
// ═══════════════════════════════════════════════════════════════════════════════

pub mod eap {
    pub const CODE_REQUEST: u8 = 1;
    pub const CODE_RESPONSE: u8 = 2;
    pub const CODE_SUCCESS: u8 = 3;
    pub const CODE_FAILURE: u8 = 4;

    pub const TYPE_IDENTITY: u8 = 1;
    pub const TYPE_NOTIFICATION: u8 = 2;
    pub const TYPE_NAK: u8 = 3;
    pub const TYPE_MD5: u8 = 4;
    pub const TYPE_OTP: u8 = 5;
    pub const TYPE_GTC: u8 = 6;
    pub const TYPE_TLS: u8 = 13;
    pub const TYPE_LEAP: u8 = 17;
    pub const TYPE_SIM: u8 = 18;
    pub const TYPE_TTLS: u8 = 21;
    pub const TYPE_AKA: u8 = 23;
    pub const TYPE_PEAP: u8 = 25;
    pub const TYPE_MSCHAPV2: u8 = 26;
    pub const TYPE_FAST: u8 = 43;
    pub const TYPE_PSK: u8 = 47;
    pub const TYPE_SAKE: u8 = 48;
    pub const TYPE_IKEV2: u8 = 49;
    pub const TYPE_AKA_PRIME: u8 = 50;
    pub const TYPE_GPSK: u8 = 51;
    pub const TYPE_PWD: u8 = 52;
    pub const TYPE_TEAP: u8 = 55;
    pub const TYPE_WSC: u8 = 254;  // Wi-Fi Simple Configuration (WPS)

    /// EAP header: Code(1) + Identifier(1) + Length(2) = 4 bytes
    pub const HEADER_LEN: usize = 4;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TDLS — Tunneled Direct Link Setup
// ═══════════════════════════════════════════════════════════════════════════════

pub mod tdls {
    /// TDLS uses LLC/SNAP with EtherType 0x890D
    pub const ETHERTYPE: u16 = 0x890D;
    pub const LLC_SNAP: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x89, 0x0D];

    pub const ACTION_SETUP_REQ: u8 = 0;
    pub const ACTION_SETUP_RESP: u8 = 1;
    pub const ACTION_SETUP_CONFIRM: u8 = 2;
    pub const ACTION_TEARDOWN: u8 = 3;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper: compose frame control from type + subtype
// ═══════════════════════════════════════════════════════════════════════════════

/// Build the first byte of frame control from type and subtype
pub const fn fc_byte0(frame_type: u8, subtype: u8) -> u8 {
    (frame_type << 2) | (subtype << 4)
}

/// Extract frame type from frame control word
pub const fn fc_type(fc: u16) -> u8 {
    ((fc >> 2) & 0x03) as u8
}

/// Extract frame subtype from frame control word
pub const fn fc_subtype(fc: u16) -> u8 {
    ((fc >> 4) & 0x0F) as u8
}

/// Check if frame is a beacon
pub const fn is_beacon(fc: u16) -> bool {
    fc_type(fc) == frame_type::MANAGEMENT && fc_subtype(fc) == frame_subtype::BEACON
}

/// Check if frame is a probe response
pub const fn is_probe_resp(fc: u16) -> bool {
    fc_type(fc) == frame_type::MANAGEMENT && fc_subtype(fc) == frame_subtype::PROBE_RESP
}

/// Check if frame is a management frame
pub const fn is_management(fc: u16) -> bool {
    fc_type(fc) == frame_type::MANAGEMENT
}

/// Check if frame is a data frame
pub const fn is_data(fc: u16) -> bool {
    fc_type(fc) == frame_type::DATA
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fc_constants_match_c_defines() {
        // Verify our fc:: constants match the C WIFIKIT_FC_* values
        assert_eq!(fc::ASSOC_REQ, 0x00);
        assert_eq!(fc::ASSOC_RESP, 0x10);
        assert_eq!(fc::PROBE_REQ, 0x40);
        assert_eq!(fc::PROBE_RESP, 0x50);
        assert_eq!(fc::BEACON, 0x80);
        assert_eq!(fc::DISASSOC, 0xA0);
        assert_eq!(fc::AUTH, 0xB0);
        assert_eq!(fc::DEAUTH, 0xC0);
        assert_eq!(fc::ACTION, 0xD0);
        assert_eq!(fc::DATA, 0x08);
        assert_eq!(fc::QOS_DATA, 0x88);
    }

    #[test]
    fn test_fc_byte0_composition() {
        // Beacon: type=0 (mgmt), subtype=8 → 0x80
        assert_eq!(fc_byte0(frame_type::MANAGEMENT, frame_subtype::BEACON), fc::BEACON);
        // Auth: type=0 (mgmt), subtype=11 → 0xB0
        assert_eq!(fc_byte0(frame_type::MANAGEMENT, frame_subtype::AUTH), fc::AUTH);
        // Deauth: type=0 (mgmt), subtype=12 → 0xC0
        assert_eq!(fc_byte0(frame_type::MANAGEMENT, frame_subtype::DEAUTH), fc::DEAUTH);
        // QoS Data: type=2 (data), subtype=8 → 0x88
        assert_eq!(fc_byte0(frame_type::DATA, frame_subtype::QOS_DATA), fc::QOS_DATA);
    }

    #[test]
    fn test_fc_type_subtype_extraction() {
        // Beacon frame: FC = 0x0080 (LE: [0x80, 0x00])
        let fc_val = 0x0080u16;
        assert_eq!(fc_type(fc_val), frame_type::MANAGEMENT);
        assert_eq!(fc_subtype(fc_val), frame_subtype::BEACON);
        assert!(is_beacon(fc_val));
        assert!(is_management(fc_val));
        assert!(!is_data(fc_val));

        // QoS Data: FC = 0x0088 (LE: [0x88, 0x00])
        let fc_val = 0x0088u16;
        assert_eq!(fc_type(fc_val), frame_type::DATA);
        assert_eq!(fc_subtype(fc_val), frame_subtype::QOS_DATA);
        assert!(is_data(fc_val));
        assert!(!is_management(fc_val));
    }

    #[test]
    fn test_cipher_suite_roundtrip() {
        for val in [0u8, 1, 2, 4, 5, 6, 8, 9, 10, 11, 12, 13] {
            let cipher = CipherSuite::from_suite_type(val);
            assert_eq!(cipher as u8, val, "CipherSuite roundtrip failed for {}", val);
        }
        // Unknown maps to None
        assert_eq!(CipherSuite::from_suite_type(99), CipherSuite::None);
    }

    #[test]
    fn test_akm_suite_roundtrip() {
        for val in [0u8, 1, 2, 3, 4, 5, 6, 8, 9, 12, 18] {
            let akm = AkmSuite::from_suite_type(val);
            assert_eq!(akm as u8, val, "AkmSuite roundtrip failed for {}", val);
        }
        assert_eq!(AkmSuite::from_suite_type(99), AkmSuite::None);
    }

    #[test]
    fn test_security_from_akm() {
        assert_eq!(Security::from_akm(AkmSuite::Sae), Security::Wpa3);
        assert_eq!(Security::from_akm(AkmSuite::FtSae), Security::Wpa3);
        assert_eq!(Security::from_akm(AkmSuite::Owe), Security::Owe);
        assert_eq!(Security::from_akm(AkmSuite::SuiteB), Security::Wpa3Enterprise);
        assert_eq!(Security::from_akm(AkmSuite::Ieee8021x), Security::Wpa2Enterprise);
        assert_eq!(Security::from_akm(AkmSuite::Psk), Security::Wpa2);
        assert_eq!(Security::from_akm(AkmSuite::None), Security::Open);
    }

    #[test]
    fn test_cap_info_base() {
        let base = cap_info::BASE;
        assert!(base & cap_info::ESS != 0);
        assert!(base & cap_info::SHORT_PREAMBLE != 0);
        assert!(base & cap_info::SHORT_SLOT != 0);
        assert!(base & cap_info::PRIVACY == 0); // privacy not in BASE
    }

    #[test]
    fn test_reason_code_display() {
        let reason = ReasonCode::DeauthLeaving;
        let s = format!("{}", reason);
        assert!(s.contains("3"));
        assert!(s.contains("leaving"));
    }

    #[test]
    fn test_status_code_success() {
        assert!(StatusCode::Success.is_success());
        assert!(!StatusCode::Failure.is_success());
    }

    #[test]
    fn test_ie_tag_values() {
        // Verify critical IE tag numbers match 802.11 spec
        assert_eq!(ie_tag::SSID, 0);
        assert_eq!(ie_tag::SUPPORTED_RATES, 1);
        assert_eq!(ie_tag::RSN, 48);
        assert_eq!(ie_tag::HT_CAPABILITIES, 45);
        assert_eq!(ie_tag::VHT_CAPABILITIES, 191);
        assert_eq!(ie_tag::VENDOR_SPECIFIC, 221);
        assert_eq!(ie_tag::EXTENSION, 255);
    }

    #[test]
    fn test_eapol_key_info_bits() {
        // M1: ACK + Pairwise (AP → STA)
        let m1_key_info = eapol::KEY_INFO_TYPE_HMAC_SHA1
            | eapol::KEY_INFO_PAIRWISE
            | eapol::KEY_INFO_ACK;
        assert!(m1_key_info & eapol::KEY_INFO_ACK != 0);
        assert!(m1_key_info & eapol::KEY_INFO_PAIRWISE != 0);
        assert!(m1_key_info & eapol::KEY_INFO_MIC == 0);

        // M3: ACK + Pairwise + Install + MIC + Secure + Encrypted
        let m3_key_info = eapol::KEY_INFO_TYPE_HMAC_SHA1
            | eapol::KEY_INFO_PAIRWISE
            | eapol::KEY_INFO_INSTALL
            | eapol::KEY_INFO_ACK
            | eapol::KEY_INFO_MIC
            | eapol::KEY_INFO_SECURE
            | eapol::KEY_INFO_ENCRYPTED;
        assert!(m3_key_info & eapol::KEY_INFO_INSTALL != 0);
        assert!(m3_key_info & eapol::KEY_INFO_SECURE != 0);
    }

    #[test]
    fn test_wifi_generation_ordering() {
        assert!(WifiGeneration::Legacy < WifiGeneration::Wifi4);
        assert!(WifiGeneration::Wifi4 < WifiGeneration::Wifi5);
        assert!(WifiGeneration::Wifi5 < WifiGeneration::Wifi6);
        assert!(WifiGeneration::Wifi6 < WifiGeneration::Wifi6e);
        assert!(WifiGeneration::Wifi6e < WifiGeneration::Wifi7);
    }
}
