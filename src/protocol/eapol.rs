//! EAPOL parser — 802.1X/EAPOL-Key parsing, message identification, PMKID extraction.
//!
//! Pure data module. No I/O, no state machine, no threads. Parses raw bytes into
//! typed structures. The handshake state machine lives in `engine/capture.rs`.
//!
#![allow(dead_code)]
#![allow(unused_imports)]
//! Ported from `wifikit_capture.c` (libwifikit).

// MacAddress used by capture engine when it consumes these parsed types

// ═══════════════════════════════════════════════════════════════════════════════
//  EAPOL Header
// ═══════════════════════════════════════════════════════════════════════════════

/// EAPOL header: Version(1) + Type(1) + BodyLength(2) = 4 bytes
pub const HEADER_LEN: usize = 4;

/// EAPOL packet type (802.1X)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EapolType {
    EapPacket = 0,
    Start     = 1,
    Logoff    = 2,
    Key       = 3,
    AsfAlert  = 4,
    Mka       = 5,
}

impl EapolType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::EapPacket),
            1 => Some(Self::Start),
            2 => Some(Self::Logoff),
            3 => Some(Self::Key),
            4 => Some(Self::AsfAlert),
            5 => Some(Self::Mka),
            _ => None,
        }
    }
}

/// Parsed EAPOL header (first 4 bytes of any EAPOL frame)
#[derive(Clone, Copy, Debug)]
pub struct EapolHeader {
    pub version: u8,
    pub packet_type: EapolType,
    pub body_len: u16,
}

/// Parse a 4-byte EAPOL header.
/// Returns `None` if data is too short or type is unrecognized.
pub fn parse_header(data: &[u8]) -> Option<EapolHeader> {
    if data.len() < HEADER_LEN {
        return None;
    }
    let packet_type = EapolType::from_u8(data[1])?;
    Some(EapolHeader {
        version: data[0],
        packet_type,
        body_len: u16::from_be_bytes([data[2], data[3]]),
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAPOL-Key Parsing
// ═══════════════════════════════════════════════════════════════════════════════

/// EAPOL-Key body field offsets (relative to start of EAPOL body, after 4-byte header)
///
/// Layout (IEEE 802.11i-2004, Figure 43):
///   DescriptorType(1) + KeyInfo(2) + KeyLength(2) + ReplayCounter(8) +
///   Nonce(32) + IV(16) + RSC(8) + Reserved(8) + MIC(16) + KeyDataLen(2) +
///   KeyData(variable)
mod offset {
    pub const DESCRIPTOR_TYPE: usize = 0;   // 1 byte
    pub const KEY_INFO: usize = 1;          // 2 bytes, big-endian
    pub const KEY_LENGTH: usize = 3;        // 2 bytes, big-endian
    pub const REPLAY_COUNTER: usize = 5;    // 8 bytes, big-endian
    pub const NONCE: usize = 13;            // 32 bytes
    pub const IV: usize = 45;              // 16 bytes
    pub const RSC: usize = 61;             // 8 bytes
    pub const _KEY_ID: usize = 69;         // 8 bytes (reserved in RSN)
    pub const MIC: usize = 77;            // 16 bytes
    pub const KEY_DATA_LEN: usize = 93;    // 2 bytes, big-endian
    pub const KEY_DATA: usize = 95;        // variable length
    pub const MIN_BODY_LEN: usize = 95;    // minimum body without key data
}

/// Key descriptor type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyDescriptor {
    Rsn = 2,
    Wpa = 254,
}

impl KeyDescriptor {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            2 => Some(Self::Rsn),
            254 => Some(Self::Wpa),
            _ => None,
        }
    }
}

/// Key Descriptor Version (Key Information bits 0-2)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyVersion {
    HmacMd5Rc4   = 1,   // WPA (TKIP)
    HmacSha1Aes  = 2,   // WPA2 (CCMP)
    Aes128Cmac   = 3,   // WPA2 with MFP (BIP)
}

impl KeyVersion {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v & 0x0007 {
            1 => Some(Self::HmacMd5Rc4),
            2 => Some(Self::HmacSha1Aes),
            3 => Some(Self::Aes128Cmac),
            _ => None,
        }
    }
}

/// Key Information bit masks (IEEE 802.11i-2004, Figure 43)
const KI_VERSION_MASK: u16 = 0x0007;
const KI_PAIRWISE: u16     = 0x0008;  // bit 3
const KI_INSTALL: u16      = 0x0040;  // bit 6
const KI_ACK: u16          = 0x0080;  // bit 7
const KI_MIC: u16          = 0x0100;  // bit 8
const KI_SECURE: u16       = 0x0200;  // bit 9
const KI_ERROR: u16        = 0x0400;  // bit 10
const KI_REQUEST: u16      = 0x0800;  // bit 11
const KI_ENCRYPTED: u16    = 0x1000;  // bit 12
const KI_SMK: u16          = 0x2000;  // bit 13

/// Parsed Key Information field — all bit flags decoded
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyInfo {
    pub raw: u16,
    pub version: u16,
    pub pairwise: bool,
    pub install: bool,
    pub ack: bool,
    pub mic: bool,
    pub secure: bool,
    pub error: bool,
    pub request: bool,
    pub encrypted: bool,
    pub smk: bool,
}

/// Parse the 2-byte Key Information field into individual flags.
pub fn parse_key_info(raw: u16) -> KeyInfo {
    KeyInfo {
        raw,
        version: raw & KI_VERSION_MASK,
        pairwise: raw & KI_PAIRWISE != 0,
        install: raw & KI_INSTALL != 0,
        ack: raw & KI_ACK != 0,
        mic: raw & KI_MIC != 0,
        secure: raw & KI_SECURE != 0,
        error: raw & KI_ERROR != 0,
        request: raw & KI_REQUEST != 0,
        encrypted: raw & KI_ENCRYPTED != 0,
        smk: raw & KI_SMK != 0,
    }
}

/// Parsed EAPOL-Key frame (the body after the 4-byte EAPOL header)
#[derive(Clone, Debug)]
pub struct EapolKey {
    pub descriptor: KeyDescriptor,
    pub key_info: KeyInfo,
    pub key_length: u16,
    pub replay_counter: u64,
    pub nonce: [u8; 32],
    pub iv: [u8; 16],
    pub rsc: [u8; 8],
    pub mic: [u8; 16],
    pub key_data_len: u16,
    pub key_data: Vec<u8>,
}

/// Parse an EAPOL-Key body (bytes after the 4-byte EAPOL header).
/// Returns `None` if body is too short or descriptor type is unrecognized.
pub fn parse_eapol_key(body: &[u8]) -> Option<EapolKey> {
    if body.len() < offset::MIN_BODY_LEN {
        return None;
    }

    let descriptor = KeyDescriptor::from_u8(body[offset::DESCRIPTOR_TYPE])?;
    let raw_key_info = u16::from_be_bytes([
        body[offset::KEY_INFO],
        body[offset::KEY_INFO + 1],
    ]);
    let key_length = u16::from_be_bytes([
        body[offset::KEY_LENGTH],
        body[offset::KEY_LENGTH + 1],
    ]);
    let replay_counter = u64::from_be_bytes([
        body[offset::REPLAY_COUNTER],
        body[offset::REPLAY_COUNTER + 1],
        body[offset::REPLAY_COUNTER + 2],
        body[offset::REPLAY_COUNTER + 3],
        body[offset::REPLAY_COUNTER + 4],
        body[offset::REPLAY_COUNTER + 5],
        body[offset::REPLAY_COUNTER + 6],
        body[offset::REPLAY_COUNTER + 7],
    ]);

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&body[offset::NONCE..offset::NONCE + 32]);

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&body[offset::IV..offset::IV + 16]);

    let mut rsc = [0u8; 8];
    rsc.copy_from_slice(&body[offset::RSC..offset::RSC + 8]);

    let mut mic = [0u8; 16];
    mic.copy_from_slice(&body[offset::MIC..offset::MIC + 16]);

    let key_data_len = u16::from_be_bytes([
        body[offset::KEY_DATA_LEN],
        body[offset::KEY_DATA_LEN + 1],
    ]);

    // Clamp key data to available bytes
    let available = body.len().saturating_sub(offset::KEY_DATA);
    let actual_data_len = (key_data_len as usize).min(available);
    let key_data = if actual_data_len > 0 {
        body[offset::KEY_DATA..offset::KEY_DATA + actual_data_len].to_vec()
    } else {
        Vec::new()
    };

    Some(EapolKey {
        descriptor,
        key_info: parse_key_info(raw_key_info),
        key_length,
        replay_counter,
        nonce,
        iv,
        rsc,
        mic,
        key_data_len,
        key_data,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Handshake Message Identification
// ═══════════════════════════════════════════════════════════════════════════════

/// Handshake message type, identified from Key Information bits.
///
/// IEEE 802.11i 4-way handshake:
///   M1: Pairwise + ACK, no MIC                                  (AP → STA, ANonce)
///   M2: Pairwise + MIC, no ACK                                  (STA → AP, SNonce)
///   M3: Pairwise + ACK + MIC + Install + Secure + Encrypted     (AP → STA, GTK)
///   M4: Pairwise + MIC + Secure, no ACK, no Encrypted           (STA → AP, ACK)
///
/// Group key handshake:
///   G1: ACK + MIC + Secure + Encrypted, no Pairwise             (AP → STA, new GTK)
///   G2: MIC + Secure, no Pairwise, no ACK                       (STA → AP, ACK)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeMessage {
    M1,       // AP → STA: carries ANonce
    M2,       // STA → AP: carries SNonce + RSN IE + MIC
    M3,       // AP → STA: carries encrypted GTK
    M4,       // STA → AP: confirmation
    GroupM1,  // AP → STA: new group key
    GroupM2,  // STA → AP: group key ACK
}

impl HandshakeMessage {
    /// Human-readable short name
    pub fn name(&self) -> &'static str {
        match self {
            Self::M1 => "M1",
            Self::M2 => "M2",
            Self::M3 => "M3",
            Self::M4 => "M4",
            Self::GroupM1 => "Group M1",
            Self::GroupM2 => "Group M2",
        }
    }

    /// Message number (1-6) matching the C implementation
    pub fn number(&self) -> u8 {
        match self {
            Self::M1 => 1,
            Self::M2 => 2,
            Self::M3 => 3,
            Self::M4 => 4,
            Self::GroupM1 => 5,
            Self::GroupM2 => 6,
        }
    }

    /// Is this message sent from AP to STA?
    pub fn is_ap_to_sta(&self) -> bool {
        matches!(self, Self::M1 | Self::M3 | Self::GroupM1)
    }
}

/// Identify the handshake message type from a parsed `KeyInfo`.
///
/// Returns `None` for unrecognized key info patterns.
pub fn identify_message(ki: &KeyInfo, key_data_len: usize) -> Option<HandshakeMessage> {
    if ki.pairwise {
        // 4-way handshake (pairwise key)
        if ki.ack && !ki.mic {
            // M1: AP→STA, ACK set, no MIC (keys not yet derived)
            Some(HandshakeMessage::M1)
        } else if ki.ack && ki.mic && ki.install {
            // M3: AP→STA, ACK + MIC + Install. The Secure and Encrypted flags
            // are typically set but some APs omit Secure on reconnection.
            // Only ACK + MIC + Install are mandatory for M3 identification.
            Some(HandshakeMessage::M3)
        } else if !ki.ack && ki.mic && !ki.install {
            // M2 or M4 — both from STA, both have MIC, neither has ACK/Install.
            // Normal M2: !secure. Normal M4: secure.
            // But post-reassociation M2 can also have Secure set (same bits as M4).
            // Reliable differentiator: M2 carries RSN IE in key_data (non-empty),
            // M4 has empty key_data.
            if key_data_len > 0 {
                Some(HandshakeMessage::M2)
            } else {
                Some(HandshakeMessage::M4)
            }
        } else {
            None
        }
    } else {
        // Group key handshake
        if ki.ack && ki.mic && ki.secure && ki.encrypted {
            Some(HandshakeMessage::GroupM1)
        } else if !ki.ack && ki.mic && ki.secure {
            Some(HandshakeMessage::GroupM2)
        } else {
            None
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PMKID Extraction
// ═══════════════════════════════════════════════════════════════════════════════

/// OUI for RSN (00:0F:AC)
const RSN_OUI: [u8; 3] = [0x00, 0x0F, 0xAC];

/// KDE data type for PMKID
const KDE_TYPE_PMKID: u8 = 4;

/// Extract PMKID from EAPOL-Key M1's Key Data.
///
/// The AP may include a PMKID in the Key Data of M1, enabling clientless
/// WPA2 attack (hashcat -m 22000 type 01).
///
/// Two extraction paths:
///   1. KDE (Key Data Encapsulation): type 0xDD, OUI 00:0F:AC, data type 4
///   2. RSN IE (type 0x30): parse RSN to find PMKID count > 0
///
/// PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AA || SPA)
///
/// Returns the 16-byte PMKID, or `None` if not present.
pub fn extract_pmkid(key_data: &[u8]) -> Option<[u8; 16]> {
    if key_data.len() < 22 {
        return None;
    }

    let mut off = 0usize;
    while off + 2 <= key_data.len() {
        let tag = key_data[off];
        let len = key_data[off + 1] as usize;

        if off + 2 + len > key_data.len() {
            break;
        }

        let element = &key_data[off + 2..off + 2 + len];

        if tag == 0xDD && len >= 20 {
            // KDE: OUI(3) + DataType(1) + Data
            if element[0..3] == RSN_OUI && element[3] == KDE_TYPE_PMKID {
                let mut pmkid = [0u8; 16];
                pmkid.copy_from_slice(&element[4..20]);
                return Some(pmkid);
            }
        } else if tag == 0x30 && len >= 22 {
            // RSN IE — parse for PMKID
            if let Some(pmkid) = extract_pmkid_from_rsn(element) {
                return Some(pmkid);
            }
        }

        off += 2 + len;
    }

    None
}

/// Parse RSN IE body to extract PMKID.
///
/// RSN layout: Version(2) + GroupCipher(4) + PairwiseCount(2) + PairwiseSuites(4*N)
///           + AKMCount(2) + AKMSuites(4*N) + RSNCap(2) + PMKIDCount(2) + PMKIDs(16*N)
fn extract_pmkid_from_rsn(rsn: &[u8]) -> Option<[u8; 16]> {
    let mut pos = 2usize; // skip version

    // Group cipher suite
    pos += 4;
    if pos + 2 > rsn.len() { return None; }

    // Pairwise cipher suites
    let pw_count = u16::from_le_bytes([rsn[pos], rsn[pos + 1]]) as usize;
    pos += 2 + pw_count * 4;
    if pos + 2 > rsn.len() { return None; }

    // AKM suites
    let akm_count = u16::from_le_bytes([rsn[pos], rsn[pos + 1]]) as usize;
    pos += 2 + akm_count * 4;
    if pos + 2 > rsn.len() { return None; }

    // RSN capabilities
    pos += 2;

    // PMKID count
    if pos + 2 > rsn.len() { return None; }
    let pmkid_count = u16::from_le_bytes([rsn[pos], rsn[pos + 1]]) as usize;
    pos += 2;

    if pmkid_count > 0 && pos + 16 <= rsn.len() {
        let mut pmkid = [0u8; 16];
        pmkid.copy_from_slice(&rsn[pos..pos + 16]);
        Some(pmkid)
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Parsing (enterprise — identity and method capture)
// ═══════════════════════════════════════════════════════════════════════════════

/// EAP packet code
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EapCode {
    Request  = 1,
    Response = 2,
    Success  = 3,
    Failure  = 4,
}

impl EapCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Success),
            4 => Some(Self::Failure),
            _ => None,
        }
    }
}

/// EAP method type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EapMethod {
    Identity,
    Notification,
    Nak,
    Md5,
    Gtc,
    Tls,
    Leap,
    Sim,
    Ttls,
    Peap,
    MsChapV2,
    Fast,
    Wsc,
    Unknown(u8),
}

impl EapMethod {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Identity,
            2 => Self::Notification,
            3 => Self::Nak,
            4 => Self::Md5,
            6 => Self::Gtc,
            13 => Self::Tls,
            17 => Self::Leap,
            18 => Self::Sim,
            21 => Self::Ttls,
            25 => Self::Peap,
            26 => Self::MsChapV2,
            43 => Self::Fast,
            254 => Self::Wsc,
            other => Self::Unknown(other),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Identity => "Identity",
            Self::Notification => "Notification",
            Self::Nak => "Nak",
            Self::Md5 => "MD5-Challenge",
            Self::Gtc => "GTC",
            Self::Tls => "EAP-TLS",
            Self::Leap => "LEAP",
            Self::Sim => "EAP-SIM",
            Self::Ttls => "EAP-TTLS",
            Self::Peap => "PEAP",
            Self::MsChapV2 => "MSCHAPv2",
            Self::Fast => "EAP-FAST",
            Self::Wsc => "WSC",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// Parsed EAP header
#[derive(Clone, Debug)]
pub struct EapPacket {
    pub code: EapCode,
    pub identifier: u8,
    pub length: u16,
    pub eap_type: Option<EapMethod>,  // None for Success/Failure (no type field)
    pub body: Vec<u8>,                // type-specific data after the type byte
}

/// EAP header minimum: Code(1) + ID(1) + Length(2) = 4 bytes
const EAP_HEADER_LEN: usize = 4;

/// Parse an EAP packet from the EAPOL body (after 4-byte EAPOL header).
/// The `body` parameter is the EAPOL body for an EAP-Packet type.
pub fn parse_eap(body: &[u8]) -> Option<EapPacket> {
    if body.len() < EAP_HEADER_LEN {
        return None;
    }

    let code = EapCode::from_u8(body[0])?;
    let identifier = body[1];
    let length = u16::from_be_bytes([body[2], body[3]]);

    // Success and Failure have no type field
    if matches!(code, EapCode::Success | EapCode::Failure) {
        return Some(EapPacket {
            code,
            identifier,
            length,
            eap_type: None,
            body: Vec::new(),
        });
    }

    // Request and Response: Code(1) + ID(1) + Length(2) + Type(1) = 5 min
    if body.len() < 5 {
        return None;
    }

    let eap_type = EapMethod::from_u8(body[4]);
    let type_body = if body.len() > 5 {
        body[5..body.len().min(length as usize)].to_vec()
    } else {
        Vec::new()
    };

    Some(EapPacket {
        code,
        identifier,
        length,
        eap_type: Some(eap_type),
        body: type_body,
    })
}

/// Extract the identity string from an EAP-Identity Response.
/// Returns `None` if this isn't an Identity Response or has no identity data.
pub fn extract_eap_identity(eap: &EapPacket) -> Option<String> {
    if eap.code != EapCode::Response {
        return None;
    }
    match eap.eap_type {
        Some(EapMethod::Identity) if !eap.body.is_empty() => {
            Some(String::from_utf8_lossy(&eap.body).into_owned())
        }
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Handshake Quality & State (for capture engine)
// ═══════════════════════════════════════════════════════════════════════════════

/// Handshake capture quality — what messages have been collected
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum HandshakeQuality {
    /// No handshake data
    #[default]
    None,
    /// PMKID only (clientless, from M1)
    Pmkid,
    /// M1 + M2 (minimum for cracking)
    M1M2,
    /// M1 + M2 + M3 (better — confirms AP accepted SNonce)
    M1M2M3,
    /// M1 + M2 + M3 + M4 (complete — confirms mutual authentication)
    Full,
}

impl HandshakeQuality {
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pmkid => "PMKID",
            Self::M1M2 => "M1+M2",
            Self::M1M2M3 => "M1+M2+M3",
            Self::Full => "M1+M2+M3+M4",
        }
    }
}

/// Message pair type for hccapx/hc22000 export
///
/// Determines which M1/M2/M3 combination to use for cracking and how
/// replay counter matching works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessagePair {
    /// M1+M2 with matching replay counter (best — same handshake attempt)
    M1M2SameRc  = 0,
    /// M2+M3 with matching replay counter (AP accepted this M2)
    M2M3SameRc  = 1,
    /// M1+M2 with different replay counters (cross-handshake, less reliable)
    M1M2DiffRc  = 2,
    /// M2+M3 with different replay counters
    M2M3DiffRc  = 3,
    /// M3+M4 rekeying, same replay counter
    M3M4Rekey   = 4,
    /// M3+M4 rekeying, different replay counter
    M3M4DiffRc  = 5,
}

/// Determine message pair type based on replay counters.
///
/// For hashcat/hccapx export — tells the cracker how to verify candidates.
pub fn determine_message_pair(
    replay_counter_m1: u64,
    replay_counter_m2: u64,
    has_m3: bool,
) -> MessagePair {
    if replay_counter_m2 == replay_counter_m1 {
        MessagePair::M1M2SameRc
    } else if has_m3 {
        MessagePair::M2M3DiffRc
    } else {
        MessagePair::M1M2DiffRc
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Full EAPOL Frame Parsing (from raw 802.11 data frame)
// ═══════════════════════════════════════════════════════════════════════════════

/// LLC/SNAP header for EAPOL: AA:AA:03:00:00:00:88:8E
const LLC_SNAP_EAPOL: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];

/// Result of parsing a complete EAPOL frame from a data frame body
#[derive(Clone, Debug)]
pub enum ParsedEapol {
    /// EAPOL-Key frame (4-way or group key handshake)
    Key {
        header: EapolHeader,
        key: EapolKey,
        message: HandshakeMessage,
        raw_eapol: Vec<u8>,  // complete EAPOL frame (header + body) for storage
    },
    /// EAP packet (enterprise identity/method)
    Eap {
        header: EapolHeader,
        eap: EapPacket,
    },
    /// EAPOL-Start
    Start { header: EapolHeader },
    /// EAPOL-Logoff
    Logoff { header: EapolHeader },
}

/// Parse an EAPOL frame from the payload of an 802.11 data frame.
///
/// The input `payload` should start at the LLC/SNAP header (after the 802.11 MAC header
/// and any QoS/HT control fields). This function:
///   1. Verifies the LLC/SNAP header matches EAPOL (AA:AA:03:00:00:00:88:8E)
///   2. Parses the EAPOL header
///   3. Dispatches to Key or EAP parser as appropriate
///
/// Returns `None` if:
///   - Payload is too short
///   - LLC/SNAP doesn't match EAPOL
///   - EAPOL header is malformed
///   - Key frame has unrecognized descriptor or message pattern
pub fn parse_from_data_frame(payload: &[u8]) -> Option<ParsedEapol> {
    // Check LLC/SNAP header
    if payload.len() < LLC_SNAP_EAPOL.len() + HEADER_LEN {
        return None;
    }
    if payload[..8] != LLC_SNAP_EAPOL {
        return None;
    }

    let eapol_data = &payload[8..];
    let header = parse_header(eapol_data)?;

    // Clamp body length to available data
    let body_len = (header.body_len as usize).min(eapol_data.len().saturating_sub(HEADER_LEN));
    let body = &eapol_data[HEADER_LEN..HEADER_LEN + body_len];

    match header.packet_type {
        EapolType::Key => {
            let key = parse_eapol_key(body)?;
            let message = identify_message(&key.key_info, key.key_data.len())?;
            // Store complete EAPOL frame (header + body) for capture engine
            let raw_eapol = eapol_data[..HEADER_LEN + body_len].to_vec();
            Some(ParsedEapol::Key { header, key, message, raw_eapol })
        }
        EapolType::EapPacket => {
            let eap = parse_eap(body)?;
            Some(ParsedEapol::Eap { header, eap })
        }
        EapolType::Start => Some(ParsedEapol::Start { header }),
        EapolType::Logoff => Some(ParsedEapol::Logoff { header }),
        _ => None,
    }
}

/// Parse an EAPOL frame directly from raw EAPOL bytes (no LLC/SNAP prefix).
/// Used when EAPOL data has already been extracted from the frame.
pub fn parse_raw_eapol(eapol_data: &[u8]) -> Option<ParsedEapol> {
    let header = parse_header(eapol_data)?;
    let body_len = (header.body_len as usize).min(eapol_data.len().saturating_sub(HEADER_LEN));
    let body = &eapol_data[HEADER_LEN..HEADER_LEN + body_len];

    match header.packet_type {
        EapolType::Key => {
            let key = parse_eapol_key(body)?;
            let message = identify_message(&key.key_info, key.key_data.len())?;
            let raw_eapol = eapol_data[..HEADER_LEN + body_len].to_vec();
            Some(ParsedEapol::Key { header, key, message, raw_eapol })
        }
        EapolType::EapPacket => {
            let eap = parse_eap(body)?;
            Some(ParsedEapol::Eap { header, eap })
        }
        EapolType::Start => Some(ParsedEapol::Start { header }),
        EapolType::Logoff => Some(ParsedEapol::Logoff { header }),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Utility
// ═══════════════════════════════════════════════════════════════════════════════

/// Check if a 32-byte nonce is all zeros (empty/unset).
pub fn nonce_is_zero(nonce: &[u8; 32]) -> bool {
    nonce.iter().all(|&b| b == 0)
}

/// Format a PMKID as a hex string (32 characters).
pub fn pmkid_to_hex(pmkid: &[u8; 16]) -> String {
    pmkid.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Format a nonce as a hex string (64 characters).
pub fn nonce_to_hex(nonce: &[u8; 32]) -> String {
    nonce.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Format a MIC as a hex string (32 characters).
pub fn mic_to_hex(mic: &[u8; 16]) -> String {
    mic.iter().map(|b| format!("{:02x}", b)).collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Header parsing ──

    #[test]
    fn test_parse_header_key() {
        // EAPOL-Key header: version=2, type=3(Key), body_len=117
        let data = [0x02, 0x03, 0x00, 0x75];
        let h = parse_header(&data).unwrap();
        assert_eq!(h.version, 2);
        assert_eq!(h.packet_type, EapolType::Key);
        assert_eq!(h.body_len, 117);
    }

    #[test]
    fn test_parse_header_eap() {
        let data = [0x01, 0x00, 0x00, 0x20]; // version=1, type=EAP, len=32
        let h = parse_header(&data).unwrap();
        assert_eq!(h.version, 1);
        assert_eq!(h.packet_type, EapolType::EapPacket);
        assert_eq!(h.body_len, 32);
    }

    #[test]
    fn test_parse_header_start() {
        let data = [0x01, 0x01, 0x00, 0x00]; // EAPOL-Start (no body)
        let h = parse_header(&data).unwrap();
        assert_eq!(h.packet_type, EapolType::Start);
        assert_eq!(h.body_len, 0);
    }

    #[test]
    fn test_parse_header_too_short() {
        assert!(parse_header(&[0x02, 0x03]).is_none());
        assert!(parse_header(&[]).is_none());
    }

    #[test]
    fn test_parse_header_unknown_type() {
        let data = [0x02, 0xFF, 0x00, 0x00]; // unknown type
        assert!(parse_header(&data).is_none());
    }

    // ── Key Info parsing ──

    #[test]
    fn test_key_info_m1() {
        // M1: Pairwise + ACK, version=2 (HMAC-SHA1)
        let raw: u16 = 0x008A; // ACK=0x80, Pairwise=0x08, Version=2
        let ki = parse_key_info(raw);
        assert_eq!(ki.version, 2);
        assert!(ki.pairwise);
        assert!(ki.ack);
        assert!(!ki.mic);
        assert!(!ki.secure);
        assert!(!ki.install);
        assert!(!ki.encrypted);
    }

    #[test]
    fn test_key_info_m2() {
        // M2: Pairwise + MIC, version=2
        let raw: u16 = 0x010A; // MIC=0x100, Pairwise=0x08, Version=2
        let ki = parse_key_info(raw);
        assert!(ki.pairwise);
        assert!(ki.mic);
        assert!(!ki.ack);
        assert!(!ki.install);
        assert!(!ki.secure);
    }

    #[test]
    fn test_key_info_m3() {
        // M3: Pairwise + ACK + MIC + Install + Secure + Encrypted
        let raw: u16 = KI_PAIRWISE | KI_ACK | KI_MIC | KI_INSTALL | KI_SECURE | KI_ENCRYPTED | 2;
        let ki = parse_key_info(raw);
        assert!(ki.pairwise);
        assert!(ki.ack);
        assert!(ki.mic);
        assert!(ki.install);
        assert!(ki.secure);
        assert!(ki.encrypted);
    }

    #[test]
    fn test_key_info_m4() {
        // M4: Pairwise + MIC + Secure, no ACK, no Encrypted
        let raw: u16 = KI_PAIRWISE | KI_MIC | KI_SECURE | 2;
        let ki = parse_key_info(raw);
        assert!(ki.pairwise);
        assert!(ki.mic);
        assert!(ki.secure);
        assert!(!ki.ack);
        assert!(!ki.encrypted);
    }

    #[test]
    fn test_key_info_group_m1() {
        // Group M1: ACK + MIC + Secure + Encrypted, NO Pairwise
        let raw: u16 = KI_ACK | KI_MIC | KI_SECURE | KI_ENCRYPTED | 2;
        let ki = parse_key_info(raw);
        assert!(!ki.pairwise);
        assert!(ki.ack);
        assert!(ki.mic);
        assert!(ki.secure);
        assert!(ki.encrypted);
    }

    #[test]
    fn test_key_info_error_request() {
        let raw: u16 = KI_ERROR | KI_REQUEST | KI_MIC | KI_PAIRWISE;
        let ki = parse_key_info(raw);
        assert!(ki.error);
        assert!(ki.request);
        assert!(ki.pairwise);
    }

    // ── Message identification ──

    #[test]
    fn test_identify_m1() {
        let ki = parse_key_info(KI_PAIRWISE | KI_ACK | 2);
        // M1: ACK, no MIC — key_data_len doesn't matter
        assert_eq!(identify_message(&ki, 0), Some(HandshakeMessage::M1));
        assert_eq!(identify_message(&ki, 50), Some(HandshakeMessage::M1));
    }

    #[test]
    fn test_identify_m2() {
        let ki = parse_key_info(KI_PAIRWISE | KI_MIC | 2);
        // M2: MIC, no ACK/Install — has key_data (RSN IE)
        assert_eq!(identify_message(&ki, 22), Some(HandshakeMessage::M2));
    }

    #[test]
    fn test_identify_m3() {
        let ki = parse_key_info(
            KI_PAIRWISE | KI_ACK | KI_MIC | KI_INSTALL | KI_SECURE | KI_ENCRYPTED | 2,
        );
        assert_eq!(identify_message(&ki, 100), Some(HandshakeMessage::M3));
    }

    #[test]
    fn test_identify_m4() {
        let ki = parse_key_info(KI_PAIRWISE | KI_MIC | KI_SECURE | 2);
        // M4: MIC + Secure, no ACK/Install — empty key_data
        assert_eq!(identify_message(&ki, 0), Some(HandshakeMessage::M4));
    }

    #[test]
    fn test_identify_m2_variant_with_secure() {
        // Post-reassociation M2 with Secure bit set — same KeyInfo as M4.
        // Disambiguated by key_data: M2 has RSN IE (non-empty), M4 is empty.
        let ki = parse_key_info(KI_PAIRWISE | KI_MIC | KI_SECURE | 2);
        assert_eq!(identify_message(&ki, 22), Some(HandshakeMessage::M2));
        assert_eq!(identify_message(&ki, 0), Some(HandshakeMessage::M4));
    }

    #[test]
    fn test_identify_group_m1() {
        let ki = parse_key_info(KI_ACK | KI_MIC | KI_SECURE | KI_ENCRYPTED | 2);
        assert_eq!(identify_message(&ki, 0), Some(HandshakeMessage::GroupM1));
    }

    #[test]
    fn test_identify_group_m2() {
        let ki = parse_key_info(KI_MIC | KI_SECURE | 2);
        assert_eq!(identify_message(&ki, 0), Some(HandshakeMessage::GroupM2));
    }

    #[test]
    fn test_identify_unknown() {
        // No meaningful bits set
        let ki = parse_key_info(2);
        assert_eq!(identify_message(&ki, 0), None);
    }

    #[test]
    fn test_message_names() {
        assert_eq!(HandshakeMessage::M1.name(), "M1");
        assert_eq!(HandshakeMessage::M4.name(), "M4");
        assert_eq!(HandshakeMessage::GroupM1.name(), "Group M1");
    }

    #[test]
    fn test_message_numbers() {
        assert_eq!(HandshakeMessage::M1.number(), 1);
        assert_eq!(HandshakeMessage::M4.number(), 4);
        assert_eq!(HandshakeMessage::GroupM1.number(), 5);
        assert_eq!(HandshakeMessage::GroupM2.number(), 6);
    }

    #[test]
    fn test_message_direction() {
        assert!(HandshakeMessage::M1.is_ap_to_sta());
        assert!(!HandshakeMessage::M2.is_ap_to_sta());
        assert!(HandshakeMessage::M3.is_ap_to_sta());
        assert!(!HandshakeMessage::M4.is_ap_to_sta());
        assert!(HandshakeMessage::GroupM1.is_ap_to_sta());
        assert!(!HandshakeMessage::GroupM2.is_ap_to_sta());
    }

    // ── EAPOL-Key parsing ──

    /// Build a minimal EAPOL-Key body for testing
    fn build_eapol_key_body(
        desc: u8,
        key_info: u16,
        key_len: u16,
        replay: u64,
        nonce: &[u8; 32],
        mic: &[u8; 16],
        key_data: &[u8],
    ) -> Vec<u8> {
        let mut body = vec![0u8; offset::KEY_DATA + key_data.len()];
        body[offset::DESCRIPTOR_TYPE] = desc;
        body[offset::KEY_INFO..offset::KEY_INFO + 2]
            .copy_from_slice(&key_info.to_be_bytes());
        body[offset::KEY_LENGTH..offset::KEY_LENGTH + 2]
            .copy_from_slice(&key_len.to_be_bytes());
        body[offset::REPLAY_COUNTER..offset::REPLAY_COUNTER + 8]
            .copy_from_slice(&replay.to_be_bytes());
        body[offset::NONCE..offset::NONCE + 32].copy_from_slice(nonce);
        // IV = zeros (default)
        // RSC = zeros (default)
        // KEY_ID = zeros (default)
        body[offset::MIC..offset::MIC + 16].copy_from_slice(mic);
        body[offset::KEY_DATA_LEN..offset::KEY_DATA_LEN + 2]
            .copy_from_slice(&(key_data.len() as u16).to_be_bytes());
        if !key_data.is_empty() {
            body[offset::KEY_DATA..offset::KEY_DATA + key_data.len()]
                .copy_from_slice(key_data);
        }
        body
    }

    #[test]
    fn test_parse_eapol_key_m1() {
        let anonce: [u8; 32] = [0xAA; 32];
        let mic = [0u8; 16]; // M1 has no MIC
        let key_info = KI_PAIRWISE | KI_ACK | 2; // M1

        let body = build_eapol_key_body(2, key_info, 16, 1, &anonce, &mic, &[]);
        let key = parse_eapol_key(&body).unwrap();

        assert_eq!(key.descriptor, KeyDescriptor::Rsn);
        assert!(key.key_info.pairwise);
        assert!(key.key_info.ack);
        assert!(!key.key_info.mic);
        assert_eq!(key.key_length, 16);
        assert_eq!(key.replay_counter, 1);
        assert_eq!(key.nonce, anonce);
        assert_eq!(key.mic, mic);
        assert_eq!(key.key_data_len, 0);
        assert!(key.key_data.is_empty());
    }

    #[test]
    fn test_parse_eapol_key_m2_with_data() {
        let snonce: [u8; 32] = [0xBB; 32];
        let mic = [0xCC; 16];
        let key_info = KI_PAIRWISE | KI_MIC | 2; // M2
        let rsn_ie = [0x30, 0x14, 0x01, 0x00, // RSN IE, len=20, version=1
            0x00, 0x0F, 0xAC, 0x04,  // group: CCMP
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // 1 pairwise: CCMP
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, // 1 AKM: PSK
            0x00, 0x00]; // RSN caps

        let body = build_eapol_key_body(2, key_info, 16, 1, &snonce, &mic, &rsn_ie);
        let key = parse_eapol_key(&body).unwrap();

        assert_eq!(key.nonce, snonce);
        assert_eq!(key.mic, mic);
        assert_eq!(key.key_data_len, rsn_ie.len() as u16);
        assert_eq!(key.key_data, rsn_ie);
    }

    #[test]
    fn test_parse_eapol_key_too_short() {
        let body = [0u8; 50]; // less than MIN_BODY_LEN (95)
        assert!(parse_eapol_key(&body).is_none());
    }

    #[test]
    fn test_parse_eapol_key_bad_descriptor() {
        let mut body = [0u8; 95];
        body[0] = 0xFF; // invalid descriptor
        assert!(parse_eapol_key(&body).is_none());
    }

    #[test]
    fn test_parse_eapol_key_wpa_descriptor() {
        let nonce = [0u8; 32];
        let mic = [0u8; 16];
        let body = build_eapol_key_body(254, KI_PAIRWISE | KI_ACK | 1, 32, 0, &nonce, &mic, &[]);
        let key = parse_eapol_key(&body).unwrap();
        assert_eq!(key.descriptor, KeyDescriptor::Wpa);
        assert_eq!(key.key_info.version, 1); // HMAC-MD5/RC4 for WPA
    }

    #[test]
    fn test_parse_eapol_key_replay_counter() {
        let nonce = [0u8; 32];
        let mic = [0u8; 16];
        let replay: u64 = 0x0102030405060708;
        let body = build_eapol_key_body(2, KI_PAIRWISE | KI_ACK | 2, 16, replay, &nonce, &mic, &[]);
        let key = parse_eapol_key(&body).unwrap();
        assert_eq!(key.replay_counter, 0x0102030405060708);
    }

    #[test]
    fn test_parse_eapol_key_data_clamped() {
        // Key data length says 100 but only 10 bytes available
        let nonce = [0u8; 32];
        let mic = [0u8; 16];
        let mut body = build_eapol_key_body(2, KI_PAIRWISE | KI_ACK | 2, 16, 0, &nonce, &mic, &[0xAA; 10]);
        // Overwrite key_data_len to claim 100 bytes
        body[offset::KEY_DATA_LEN] = 0;
        body[offset::KEY_DATA_LEN + 1] = 100;
        let key = parse_eapol_key(&body).unwrap();
        // Should clamp to available 10 bytes
        assert_eq!(key.key_data.len(), 10);
        assert_eq!(key.key_data_len, 100); // raw field preserves claimed value
    }

    // ── PMKID extraction ──

    #[test]
    fn test_extract_pmkid_kde() {
        // KDE format: Type=0xDD, Len=20, OUI=00:0F:AC, DataType=4, PMKID(16)
        let pmkid_bytes: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let mut key_data = vec![
            0xDD, 20,              // type=KDE, len=20
            0x00, 0x0F, 0xAC,      // RSN OUI
            0x04,                  // data type = PMKID
        ];
        key_data.extend_from_slice(&pmkid_bytes);

        let result = extract_pmkid(&key_data).unwrap();
        assert_eq!(result, pmkid_bytes);
    }

    #[test]
    fn test_extract_pmkid_rsn_ie() {
        // RSN IE with PMKID embedded
        let pmkid_bytes: [u8; 16] = [0x42; 16];
        let mut rsn_body = vec![
            0x01, 0x00,                   // version=1
            0x00, 0x0F, 0xAC, 0x04,       // group: CCMP
            0x01, 0x00,                   // 1 pairwise
            0x00, 0x0F, 0xAC, 0x04,       // CCMP
            0x01, 0x00,                   // 1 AKM
            0x00, 0x0F, 0xAC, 0x02,       // PSK
            0x00, 0x00,                   // RSN caps
            0x01, 0x00,                   // 1 PMKID
        ];
        rsn_body.extend_from_slice(&pmkid_bytes);

        let mut key_data = vec![0x30, rsn_body.len() as u8]; // tag=RSN IE
        key_data.extend_from_slice(&rsn_body);

        let result = extract_pmkid(&key_data).unwrap();
        assert_eq!(result, pmkid_bytes);
    }

    #[test]
    fn test_extract_pmkid_none() {
        // RSN IE without PMKID
        let rsn_body = vec![
            0x01, 0x00,                   // version
            0x00, 0x0F, 0xAC, 0x04,       // group: CCMP
            0x01, 0x00,                   // 1 pairwise
            0x00, 0x0F, 0xAC, 0x04,       // CCMP
            0x01, 0x00,                   // 1 AKM
            0x00, 0x0F, 0xAC, 0x02,       // PSK
            0x00, 0x00,                   // RSN caps
            0x00, 0x00,                   // 0 PMKIDs
        ];
        let mut key_data = vec![0x30, rsn_body.len() as u8];
        key_data.extend_from_slice(&rsn_body);

        assert!(extract_pmkid(&key_data).is_none());
    }

    #[test]
    fn test_extract_pmkid_too_short() {
        assert!(extract_pmkid(&[0xDD, 0x04, 0x00, 0x0F]).is_none());
        assert!(extract_pmkid(&[]).is_none());
    }

    #[test]
    fn test_extract_pmkid_wrong_oui() {
        // KDE with wrong OUI
        let key_data = vec![
            0xDD, 20,
            0x00, 0x50, 0xF2, // Microsoft OUI (not RSN)
            0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(extract_pmkid(&key_data).is_none());
    }

    #[test]
    fn test_extract_pmkid_multiple_kdes() {
        // First KDE is not PMKID, second is
        let pmkid_bytes: [u8; 16] = [0xAB; 16];
        let mut key_data = vec![
            // KDE 1: GTK (data type 1)
            0xDD, 22,
            0x00, 0x0F, 0xAC,
            0x01,  // GTK, not PMKID
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            // KDE 2: PMKID (data type 4)
            0xDD, 20,
            0x00, 0x0F, 0xAC,
            0x04,
        ];
        key_data.extend_from_slice(&pmkid_bytes);

        let result = extract_pmkid(&key_data).unwrap();
        assert_eq!(result, pmkid_bytes);
    }

    // ── EAP parsing ──

    #[test]
    fn test_parse_eap_identity_response() {
        // EAP-Response/Identity: Code=2, ID=1, Len=15, Type=1, "testuser@corp"
        let identity = b"testuser@corp";
        let total_len = (5 + identity.len()) as u16;
        let mut data = vec![
            0x02, // Response
            0x01, // ID
            (total_len >> 8) as u8, (total_len & 0xFF) as u8,
            0x01, // Identity
        ];
        data.extend_from_slice(identity);

        let eap = parse_eap(&data).unwrap();
        assert_eq!(eap.code, EapCode::Response);
        assert_eq!(eap.identifier, 1);
        assert_eq!(eap.eap_type, Some(EapMethod::Identity));
        assert_eq!(eap.body, identity);

        let id_str = extract_eap_identity(&eap).unwrap();
        assert_eq!(id_str, "testuser@corp");
    }

    #[test]
    fn test_parse_eap_identity_request_not_extracted() {
        // EAP-Request/Identity — we only extract Response identities
        let data = [0x01, 0x01, 0x00, 0x05, 0x01]; // Request, Type=Identity
        let eap = parse_eap(&data).unwrap();
        assert_eq!(eap.code, EapCode::Request);
        assert!(extract_eap_identity(&eap).is_none());
    }

    #[test]
    fn test_parse_eap_success() {
        let data = [0x03, 0x05, 0x00, 0x04]; // Success
        let eap = parse_eap(&data).unwrap();
        assert_eq!(eap.code, EapCode::Success);
        assert_eq!(eap.identifier, 5);
        assert!(eap.eap_type.is_none()); // no type field
    }

    #[test]
    fn test_parse_eap_failure() {
        let data = [0x04, 0x05, 0x00, 0x04]; // Failure
        let eap = parse_eap(&data).unwrap();
        assert_eq!(eap.code, EapCode::Failure);
    }

    #[test]
    fn test_parse_eap_peap_request() {
        let data = [0x01, 0x02, 0x00, 0x06, 25, 0x00]; // Request, PEAP
        let eap = parse_eap(&data).unwrap();
        assert_eq!(eap.eap_type, Some(EapMethod::Peap));
    }

    #[test]
    fn test_parse_eap_too_short() {
        assert!(parse_eap(&[0x01]).is_none());
        assert!(parse_eap(&[]).is_none());
    }

    #[test]
    fn test_parse_eap_unknown_code() {
        let data = [0x00, 0x01, 0x00, 0x04]; // code 0 is invalid
        assert!(parse_eap(&data).is_none());
    }

    #[test]
    fn test_eap_method_names() {
        assert_eq!(EapMethod::MsChapV2.name(), "MSCHAPv2");
        assert_eq!(EapMethod::Peap.name(), "PEAP");
        assert_eq!(EapMethod::Leap.name(), "LEAP");
        assert_eq!(EapMethod::Md5.name(), "MD5-Challenge");
        assert_eq!(EapMethod::Unknown(99).name(), "Unknown");
    }

    // ── Full frame parsing ──

    #[test]
    fn test_parse_from_data_frame_m1() {
        // Build: LLC/SNAP(8) + EAPOL header(4) + EAPOL-Key body(95+)
        let anonce = [0x11; 32];
        let mic = [0u8; 16];
        let key_info = KI_PAIRWISE | KI_ACK | 2;
        let key_body = build_eapol_key_body(2, key_info, 16, 1, &anonce, &mic, &[]);

        let mut payload = Vec::new();
        payload.extend_from_slice(&LLC_SNAP_EAPOL);
        payload.push(0x02); // version
        payload.push(0x03); // type = Key
        let body_len = key_body.len() as u16;
        payload.extend_from_slice(&body_len.to_be_bytes());
        payload.extend_from_slice(&key_body);

        let parsed = parse_from_data_frame(&payload).unwrap();
        match parsed {
            ParsedEapol::Key { header, key, message, raw_eapol } => {
                assert_eq!(header.version, 2);
                assert_eq!(message, HandshakeMessage::M1);
                assert_eq!(key.nonce, anonce);
                assert_eq!(key.replay_counter, 1);
                assert!(!raw_eapol.is_empty());
            }
            _ => panic!("expected Key"),
        }
    }

    #[test]
    fn test_parse_from_data_frame_eap() {
        let identity = b"admin";
        let eap_len = (5 + identity.len()) as u16;
        let mut eap_data = vec![0x02, 0x01]; // Response, ID=1
        eap_data.extend_from_slice(&eap_len.to_be_bytes());
        eap_data.push(0x01); // Identity
        eap_data.extend_from_slice(identity);

        let mut payload = Vec::new();
        payload.extend_from_slice(&LLC_SNAP_EAPOL);
        payload.push(0x01); // version
        payload.push(0x00); // type = EAP
        let body_len = eap_data.len() as u16;
        payload.extend_from_slice(&body_len.to_be_bytes());
        payload.extend_from_slice(&eap_data);

        let parsed = parse_from_data_frame(&payload).unwrap();
        match parsed {
            ParsedEapol::Eap { header: _, eap } => {
                assert_eq!(eap.code, EapCode::Response);
                let id = extract_eap_identity(&eap).unwrap();
                assert_eq!(id, "admin");
            }
            _ => panic!("expected Eap"),
        }
    }

    #[test]
    fn test_parse_from_data_frame_wrong_snap() {
        let mut payload = vec![0x00; 20];
        payload[0] = 0xAA;
        // Rest doesn't match LLC/SNAP
        assert!(parse_from_data_frame(&payload).is_none());
    }

    #[test]
    fn test_parse_from_data_frame_start() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&LLC_SNAP_EAPOL);
        payload.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // Start
        let parsed = parse_from_data_frame(&payload).unwrap();
        assert!(matches!(parsed, ParsedEapol::Start { .. }));
    }

    #[test]
    fn test_parse_from_data_frame_logoff() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&LLC_SNAP_EAPOL);
        payload.extend_from_slice(&[0x01, 0x02, 0x00, 0x00]); // Logoff
        let parsed = parse_from_data_frame(&payload).unwrap();
        assert!(matches!(parsed, ParsedEapol::Logoff { .. }));
    }

    #[test]
    fn test_parse_raw_eapol_m3() {
        let anonce = [0x33; 32];
        let mic = [0xFF; 16];
        let key_info = KI_PAIRWISE | KI_ACK | KI_MIC | KI_INSTALL | KI_SECURE | KI_ENCRYPTED | 2;
        let key_body = build_eapol_key_body(2, key_info, 16, 3, &anonce, &mic, &[0xEE; 32]);

        let mut eapol_data = Vec::new();
        eapol_data.push(0x02); // version
        eapol_data.push(0x03); // type = Key
        let body_len = key_body.len() as u16;
        eapol_data.extend_from_slice(&body_len.to_be_bytes());
        eapol_data.extend_from_slice(&key_body);

        let parsed = parse_raw_eapol(&eapol_data).unwrap();
        match parsed {
            ParsedEapol::Key { key, message, .. } => {
                assert_eq!(message, HandshakeMessage::M3);
                assert_eq!(key.nonce, anonce);
                assert_eq!(key.mic, mic);
                assert_eq!(key.key_data.len(), 32);
            }
            _ => panic!("expected Key M3"),
        }
    }

    // ── Utility ──

    #[test]
    fn test_nonce_is_zero() {
        assert!(nonce_is_zero(&[0u8; 32]));
        let mut nonce = [0u8; 32];
        nonce[31] = 1;
        assert!(!nonce_is_zero(&nonce));
        nonce[0] = 0xFF;
        assert!(!nonce_is_zero(&nonce));
    }

    #[test]
    fn test_pmkid_to_hex() {
        let pmkid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        assert_eq!(pmkid_to_hex(&pmkid), "0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn test_nonce_to_hex_length() {
        let nonce = [0xAB; 32];
        let hex = nonce_to_hex(&nonce);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == 'a' || c == 'b'));
    }

    // ── Handshake quality ──

    #[test]
    fn test_handshake_quality_ordering() {
        assert!(HandshakeQuality::None < HandshakeQuality::Pmkid);
        assert!(HandshakeQuality::Pmkid < HandshakeQuality::M1M2);
        assert!(HandshakeQuality::M1M2 < HandshakeQuality::M1M2M3);
        assert!(HandshakeQuality::M1M2M3 < HandshakeQuality::Full);
    }

    #[test]
    fn test_handshake_quality_names() {
        assert_eq!(HandshakeQuality::None.name(), "none");
        assert_eq!(HandshakeQuality::Pmkid.name(), "PMKID");
        assert_eq!(HandshakeQuality::Full.name(), "M1+M2+M3+M4");
    }

    // ── Message pair ──

    #[test]
    fn test_message_pair_same_rc() {
        let mp = determine_message_pair(1, 1, false);
        assert_eq!(mp, MessagePair::M1M2SameRc);
    }

    #[test]
    fn test_message_pair_diff_rc_no_m3() {
        let mp = determine_message_pair(1, 2, false);
        assert_eq!(mp, MessagePair::M1M2DiffRc);
    }

    #[test]
    fn test_message_pair_diff_rc_with_m3() {
        let mp = determine_message_pair(1, 2, true);
        assert_eq!(mp, MessagePair::M2M3DiffRc);
    }

    // ── Key descriptor and version ──

    #[test]
    fn test_key_descriptor_from_u8() {
        assert_eq!(KeyDescriptor::from_u8(2), Some(KeyDescriptor::Rsn));
        assert_eq!(KeyDescriptor::from_u8(254), Some(KeyDescriptor::Wpa));
        assert_eq!(KeyDescriptor::from_u8(0), None);
        assert_eq!(KeyDescriptor::from_u8(1), None);
    }

    #[test]
    fn test_key_version_from_u16() {
        assert_eq!(KeyVersion::from_u16(1), Some(KeyVersion::HmacMd5Rc4));
        assert_eq!(KeyVersion::from_u16(2), Some(KeyVersion::HmacSha1Aes));
        assert_eq!(KeyVersion::from_u16(3), Some(KeyVersion::Aes128Cmac));
        assert_eq!(KeyVersion::from_u16(0), None);
        // Should mask bits 0-2 only
        assert_eq!(KeyVersion::from_u16(0x0102), Some(KeyVersion::HmacSha1Aes));
    }

    // ── EapolType ──

    #[test]
    fn test_eapol_type_from_u8() {
        assert_eq!(EapolType::from_u8(0), Some(EapolType::EapPacket));
        assert_eq!(EapolType::from_u8(3), Some(EapolType::Key));
        assert_eq!(EapolType::from_u8(5), Some(EapolType::Mka));
        assert_eq!(EapolType::from_u8(6), None);
        assert_eq!(EapolType::from_u8(255), None);
    }

    // ── Edge case: M1 with PMKID in key data ──

    #[test]
    fn test_full_m1_with_pmkid() {
        let anonce = [0x77; 32];
        let mic = [0u8; 16];
        let pmkid_bytes: [u8; 16] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                                      0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];

        // KDE with PMKID
        let mut kde = vec![0xDD, 20, 0x00, 0x0F, 0xAC, 0x04];
        kde.extend_from_slice(&pmkid_bytes);

        let key_info = KI_PAIRWISE | KI_ACK | 2;
        let key_body = build_eapol_key_body(2, key_info, 16, 1, &anonce, &mic, &kde);

        // Build full frame with LLC/SNAP
        let mut payload = Vec::new();
        payload.extend_from_slice(&LLC_SNAP_EAPOL);
        payload.push(0x02); // version
        payload.push(0x03); // type = Key
        let body_len = key_body.len() as u16;
        payload.extend_from_slice(&body_len.to_be_bytes());
        payload.extend_from_slice(&key_body);

        // Parse the full frame
        let parsed = parse_from_data_frame(&payload).unwrap();
        match parsed {
            ParsedEapol::Key { key, message, .. } => {
                assert_eq!(message, HandshakeMessage::M1);
                assert_eq!(key.nonce, anonce);

                // Extract PMKID from key data
                let pmkid = extract_pmkid(&key.key_data).unwrap();
                assert_eq!(pmkid, pmkid_bytes);
                assert_eq!(pmkid_to_hex(&pmkid), "deadbeef0102030405060708090a0b0c");
            }
            _ => panic!("expected Key M1"),
        }
    }
}
