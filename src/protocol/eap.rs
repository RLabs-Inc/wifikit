//! EAP (Extensible Authentication Protocol) — parsing and building.
//!
//! Pure protocol module: parses and builds EAP frames used in WPA2/WPA3-Enterprise.
//! No I/O, no threads, no crypto computations.
//!
#![allow(dead_code)]
#![allow(unused_imports)]
//! Supported inner methods (parse + build):
//!   - EAP-Identity (username/realm extraction)
//!   - MSCHAPv2 (challenge/response capture, hashcat -m 5500)
//!   - LEAP (Cisco, challenge/response, asleap)
//!   - GTC (plaintext token/password)
//!   - MD5-Challenge (hashcat -m 4800)
//!   - EAP-TLS/TTLS/PEAP outer layer (flag parsing, no TLS records)
//!   - EAP-NAK (method negotiation)
//!
//! Reference: RFC 3748 (EAP), RFC 2759 (MSCHAPv2), RFC 5765 (LEAP),
//!            wifi-map/libwifikit/attacks/attack_eap.c

use super::ieee80211::eap as eap_const;

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Code — packet type (RFC 3748 section 4)
// ═══════════════════════════════════════════════════════════════════════════════

/// EAP packet code (first byte of EAP header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EapCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

impl EapCode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Success),
            4 => Some(Self::Failure),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Request => "Request",
            Self::Response => "Response",
            Self::Success => "Success",
            Self::Failure => "Failure",
        }
    }
}

impl std::fmt::Display for EapCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Type — method type (RFC 3748 section 5, IANA registry)
// ═══════════════════════════════════════════════════════════════════════════════

/// EAP method type. Covers all types relevant to WiFi enterprise authentication.
///
/// Values match IANA "EAP Method Types" registry and the C `wifikit_eap_type_t` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EapType {
    /// RFC 3748 — identity exchange
    Identity = 1,
    /// RFC 3748 — notification (display message)
    Notification = 2,
    /// RFC 3748 — legacy NAK (reject method, suggest alternatives)
    Nak = 3,
    /// RFC 3748 — MD5-Challenge (like CHAP)
    Md5Challenge = 4,
    /// RFC 3748 — One-Time Password
    Otp = 5,
    /// RFC 3748 — Generic Token Card
    Gtc = 6,
    /// RFC 5216 — EAP-TLS (certificate-based)
    Tls = 13,
    /// Cisco LEAP (cryptographically broken, still seen in wild)
    Leap = 17,
    /// RFC 4186 — EAP-SIM (GSM SIM auth)
    Sim = 18,
    /// RFC 5281 — EAP-TTLS (tunneled TLS)
    Ttls = 21,
    /// RFC 4187 — EAP-AKA (3G USIM auth)
    Aka = 23,
    /// RFC 4851 (informational) — PEAP (Protected EAP, Microsoft/Cisco)
    Peap = 25,
    /// RFC 2759 / RFC 2433 — MS-CHAPv2 (inner method, most common in enterprise)
    MsChapV2 = 26,
    /// RFC 4851 — TLV extensions (used inside PEAP/FAST tunnels)
    TlvExtensions = 33,
    /// RFC 4851 — EAP-FAST (Cisco Flexible Authentication via Secure Tunneling)
    Fast = 43,
    /// RFC 4764 — EAP-PSK (pre-shared key)
    Psk = 47,
    /// RFC 4763 — EAP-SAKE
    Sake = 48,
    /// RFC 5106 — EAP-IKEv2
    IkeV2 = 49,
    /// RFC 5448 — EAP-AKA' (improved AKA)
    AkaPrime = 50,
    /// RFC 5433 — EAP-GPSK (Generalized Pre-Shared Key)
    Gpsk = 51,
    /// RFC 5931 — EAP-pwd (password-based, SRP-like)
    Pwd = 52,
    /// RFC 7170 — TEAP (Tunnel Extensible Authentication Protocol)
    Teap = 55,
    /// Wi-Fi Simple Configuration (WPS) — EAP-WSC
    Wsc = 254,
}

impl EapType {
    /// Parse from raw u8 value. Returns `None` for unrecognized types.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Identity),
            2 => Some(Self::Notification),
            3 => Some(Self::Nak),
            4 => Some(Self::Md5Challenge),
            5 => Some(Self::Otp),
            6 => Some(Self::Gtc),
            13 => Some(Self::Tls),
            17 => Some(Self::Leap),
            18 => Some(Self::Sim),
            21 => Some(Self::Ttls),
            23 => Some(Self::Aka),
            25 => Some(Self::Peap),
            26 => Some(Self::MsChapV2),
            33 => Some(Self::TlvExtensions),
            43 => Some(Self::Fast),
            47 => Some(Self::Psk),
            48 => Some(Self::Sake),
            49 => Some(Self::IkeV2),
            50 => Some(Self::AkaPrime),
            51 => Some(Self::Gpsk),
            52 => Some(Self::Pwd),
            55 => Some(Self::Teap),
            254 => Some(Self::Wsc),
            _ => None,
        }
    }

    /// Human-readable name for display.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Identity => "Identity",
            Self::Notification => "Notification",
            Self::Nak => "NAK",
            Self::Md5Challenge => "MD5-Challenge",
            Self::Otp => "OTP",
            Self::Gtc => "GTC",
            Self::Tls => "EAP-TLS",
            Self::Leap => "LEAP",
            Self::Sim => "EAP-SIM",
            Self::Ttls => "EAP-TTLS",
            Self::Aka => "EAP-AKA",
            Self::Peap => "PEAP",
            Self::MsChapV2 => "MSCHAPv2",
            Self::TlvExtensions => "TLV-Extensions",
            Self::Fast => "EAP-FAST",
            Self::Psk => "EAP-PSK",
            Self::Sake => "EAP-SAKE",
            Self::IkeV2 => "EAP-IKEv2",
            Self::AkaPrime => "EAP-AKA'",
            Self::Gpsk => "EAP-GPSK",
            Self::Pwd => "EAP-pwd",
            Self::Teap => "TEAP",
            Self::Wsc => "WSC",
        }
    }

    /// Whether this type supports tunneled inner methods (requires TLS).
    pub fn is_tunneled(&self) -> bool {
        matches!(self, Self::Tls | Self::Ttls | Self::Peap | Self::Fast | Self::Teap)
    }

    /// Whether this type can be attacked without TLS (bare inner method).
    pub fn is_bare_capturable(&self) -> bool {
        matches!(
            self,
            Self::Identity | Self::MsChapV2 | Self::Leap | Self::Gtc | Self::Md5Challenge
        )
    }
}

impl std::fmt::Display for EapType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Header — Code(1) + ID(1) + Length(2) [+ Type(1)]
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed EAP header. For Success/Failure packets, `eap_type` is `None`
/// (those packets have no type field — just 4 bytes total).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EapHeader {
    /// Packet code: Request, Response, Success, or Failure.
    pub code: EapCode,
    /// Identifier — matches requests to responses.
    pub id: u8,
    /// Total EAP packet length (including header).
    pub length: u16,
    /// EAP type (method). `None` for Success/Failure packets.
    pub eap_type: Option<EapType>,
    /// Raw EAP type byte. Useful when `eap_type` is `None` because the type
    /// is unrecognized (still available for display/logging).
    pub eap_type_raw: Option<u8>,
}

/// Parse the EAP header from raw bytes.
///
/// Input: EAP packet starting at Code byte (NOT including EAPOL header).
/// Returns `None` if data is too short or has invalid code.
pub fn parse_eap_header(data: &[u8]) -> Option<EapHeader> {
    if data.len() < eap_const::HEADER_LEN {
        return None;
    }

    let code = EapCode::from_u8(data[0])?;
    let id = data[1];
    let length = u16::from_be_bytes([data[2], data[3]]);

    // Sanity: declared length should be >= 4
    if (length as usize) < eap_const::HEADER_LEN {
        return None;
    }

    // Success/Failure have no type field (length == 4)
    let (eap_type, eap_type_raw) = match code {
        EapCode::Success | EapCode::Failure => (None, None),
        EapCode::Request | EapCode::Response => {
            if length >= 5 && data.len() >= 5 {
                let raw = data[4];
                (EapType::from_u8(raw), Some(raw))
            } else {
                (None, None)
            }
        }
    };

    Some(EapHeader {
        code,
        id,
        length,
        eap_type,
        eap_type_raw,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Identity
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed EAP-Identity response (or request with identity hint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EapIdentity {
    /// Full identity string (e.g., "user@domain.com" or "DOMAIN\\user").
    pub identity: String,
    /// Extracted realm/domain from identity. Supports both:
    /// - "user@realm.com" -> realm = "realm.com"
    /// - "DOMAIN\\user" -> realm = "DOMAIN"
    pub realm: Option<String>,
}

/// Parse EAP-Identity payload from the type-specific data.
///
/// Input: bytes AFTER the EAP type byte (offset 5 in EAP packet).
/// The identity is the remaining bytes interpreted as UTF-8 (lossy).
pub fn parse_eap_identity(data: &[u8]) -> Option<EapIdentity> {
    if data.is_empty() {
        return Some(EapIdentity {
            identity: String::new(),
            realm: None,
        });
    }

    let identity = String::from_utf8_lossy(data).into_owned();
    let realm = extract_realm(&identity);

    Some(EapIdentity { identity, realm })
}

/// Extract realm from "user@realm" or "DOMAIN\\user" format.
fn extract_realm(identity: &str) -> Option<String> {
    // Check user@realm format
    if let Some(at_pos) = identity.find('@') {
        let realm = &identity[at_pos + 1..];
        if !realm.is_empty() {
            return Some(realm.to_string());
        }
    }
    // Check DOMAIN\user format
    if let Some(bs_pos) = identity.find('\\') {
        let domain = &identity[..bs_pos];
        if !domain.is_empty() {
            return Some(domain.to_string());
        }
    }
    None
}

/// Build an EAP-Request/Identity packet.
///
/// Returns the complete EAP packet (Code + ID + Length + Type).
/// Does NOT include EAPOL header — caller wraps in EAPOL.
pub fn build_eap_identity_request(id: u8) -> Vec<u8> {
    // EAP-Request/Identity with no prompt: Code(1) + ID(1) + Length(2) + Type(1) = 5
    vec![
        eap_const::CODE_REQUEST,
        id,
        0x00,
        0x05, // length = 5
        eap_const::TYPE_IDENTITY,
    ]
}

/// Build an EAP-Response/Identity packet with the given identity string.
///
/// Returns the complete EAP packet.
pub fn build_eap_identity_response(id: u8, identity: &str) -> Vec<u8> {
    let eap_len = 5 + identity.len();
    let mut buf = Vec::with_capacity(eap_len);
    buf.push(eap_const::CODE_RESPONSE);
    buf.push(id);
    buf.push(((eap_len >> 8) & 0xFF) as u8);
    buf.push((eap_len & 0xFF) as u8);
    buf.push(eap_const::TYPE_IDENTITY);
    buf.extend_from_slice(identity.as_bytes());
    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MSCHAPv2 — RFC 2759
// ═══════════════════════════════════════════════════════════════════════════════

/// MSCHAPv2 OpCodes
pub mod mschapv2_opcode {
    pub const CHALLENGE: u8 = 1;
    pub const RESPONSE: u8 = 2;
    pub const SUCCESS: u8 = 3;
    pub const FAILURE: u8 = 4;
    pub const CHANGE_PASSWORD: u8 = 7;
}

/// Parsed MSCHAPv2 Challenge (OpCode=1, server to client).
///
/// Wire format inside EAP-MSCHAPv2:
///   OpCode(1) + MS-CHAPv2-ID(1) + MS-Length(2) + Value-Size(1) + Challenge(16) + Name(...)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsChapV2Challenge {
    /// OpCode: 1 = Challenge
    pub op_code: u8,
    /// MS-CHAPv2 Identifier (may differ from EAP ID)
    pub ms_chap_id: u8,
    /// MS-Length: total length of MSCHAPv2 payload
    pub ms_length: u16,
    /// Value-Size: always 16 for challenge
    pub value_size: u8,
    /// 16-byte authenticator challenge from server
    pub challenge: [u8; 16],
    /// Server name (authentication server identifier)
    pub name: String,
}

/// Parsed MSCHAPv2 Response (OpCode=2, client to server).
///
/// Wire format inside EAP-MSCHAPv2:
///   OpCode(1) + MS-CHAPv2-ID(1) + MS-Length(2) + Value-Size(1) +
///   Peer-Challenge(16) + Reserved(8) + NT-Response(24) + Flags(1) + Name(...)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsChapV2Response {
    /// OpCode: 2 = Response
    pub op_code: u8,
    /// MS-CHAPv2 Identifier
    pub ms_chap_id: u8,
    /// MS-Length
    pub ms_length: u16,
    /// Value-Size: always 49 (16 + 8 + 24 + 1)
    pub value_size: u8,
    /// 16-byte peer challenge (client-generated random)
    pub peer_challenge: [u8; 16],
    /// 8-byte reserved field (must be zero)
    pub reserved: [u8; 8],
    /// 24-byte NT-Response hash (the crackable value)
    pub nt_response: [u8; 24],
    /// Flags byte
    pub flags: u8,
    /// Client username
    pub name: String,
}

/// Parse MSCHAPv2 Challenge from the EAP type-specific data.
///
/// Input: bytes AFTER the EAP type byte (the MSCHAPv2 payload).
/// Minimum valid length: 1 + 1 + 2 + 1 + 16 = 21 bytes (no name).
pub fn parse_mschapv2_challenge(data: &[u8]) -> Option<MsChapV2Challenge> {
    if data.len() < 21 {
        return None;
    }
    let op_code = data[0];
    if op_code != mschapv2_opcode::CHALLENGE {
        return None;
    }
    let ms_chap_id = data[1];
    let ms_length = u16::from_be_bytes([data[2], data[3]]);
    let value_size = data[4];

    // Value-Size should be 16 for a standard challenge
    if value_size != 16 {
        return None;
    }
    if data.len() < 5 + 16 {
        return None;
    }

    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&data[5..21]);

    let name = if data.len() > 21 {
        String::from_utf8_lossy(&data[21..]).into_owned()
    } else {
        String::new()
    };

    Some(MsChapV2Challenge {
        op_code,
        ms_chap_id,
        ms_length,
        value_size,
        challenge,
        name,
    })
}

/// Parse MSCHAPv2 Response from the EAP type-specific data.
///
/// Input: bytes AFTER the EAP type byte (the MSCHAPv2 payload).
/// Minimum: OpCode(1) + ID(1) + MS-Length(2) + Value-Size(1) + Peer-Challenge(16) +
///          Reserved(8) + NT-Response(24) + Flags(1) = 54 bytes.
pub fn parse_mschapv2_response(data: &[u8]) -> Option<MsChapV2Response> {
    if data.len() < 54 {
        return None;
    }
    let op_code = data[0];
    if op_code != mschapv2_opcode::RESPONSE {
        return None;
    }
    let ms_chap_id = data[1];
    let ms_length = u16::from_be_bytes([data[2], data[3]]);
    let value_size = data[4];

    // Standard value_size is 49 (16 + 8 + 24 + 1)
    // Some implementations deviate, so we parse anyway but check minimum data

    let mut peer_challenge = [0u8; 16];
    peer_challenge.copy_from_slice(&data[5..21]);

    let mut reserved = [0u8; 8];
    reserved.copy_from_slice(&data[21..29]);

    let mut nt_response = [0u8; 24];
    nt_response.copy_from_slice(&data[29..53]);

    let flags = data[53];

    let name = if data.len() > 54 {
        String::from_utf8_lossy(&data[54..]).into_owned()
    } else {
        String::new()
    };

    Some(MsChapV2Response {
        op_code,
        ms_chap_id,
        ms_length,
        value_size,
        peer_challenge,
        reserved,
        nt_response,
        flags,
        name,
    })
}

/// Build an EAP-Request/MSCHAPv2 Challenge packet.
///
/// Returns complete EAP packet (Code + ID + Length + Type + MSCHAPv2 payload).
pub fn build_mschapv2_challenge(id: u8, challenge: &[u8; 16], server_name: &str) -> Vec<u8> {
    let name_bytes = server_name.as_bytes();
    // MSCHAPv2: OpCode(1) + ID(1) + MS-Length(2) + Value-Size(1) + Challenge(16) + Name
    let mschap_len: u16 = 5 + 16 + name_bytes.len() as u16;
    // EAP: Code(1) + ID(1) + Length(2) + Type(1) + MSCHAPv2
    let eap_len: u16 = 5 + mschap_len;

    let mut buf = Vec::with_capacity(eap_len as usize);

    // EAP header
    buf.push(eap_const::CODE_REQUEST);
    buf.push(id);
    buf.push(((eap_len >> 8) & 0xFF) as u8);
    buf.push((eap_len & 0xFF) as u8);
    buf.push(eap_const::TYPE_MSCHAPV2);

    // MSCHAPv2 Challenge
    buf.push(mschapv2_opcode::CHALLENGE); // OpCode
    buf.push(id); // MS-CHAPv2 ID (typically same as EAP ID)
    buf.push(((mschap_len >> 8) & 0xFF) as u8);
    buf.push((mschap_len & 0xFF) as u8);
    buf.push(16); // Value-Size
    buf.extend_from_slice(challenge);
    buf.extend_from_slice(name_bytes);

    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LEAP — Cisco proprietary (lightweight EAP)
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed LEAP Challenge (server to client).
///
/// Wire format inside EAP-LEAP:
///   Version(1) + Unused(1) + Count(1) + Challenge(N) + Name(...)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeapChallenge {
    /// LEAP version (typically 1)
    pub version: u8,
    /// Unused byte (always 0)
    pub unused: u8,
    /// Challenge length (typically 8)
    pub count: u8,
    /// Challenge bytes
    pub challenge: Vec<u8>,
    /// Server name
    pub name: String,
}

/// Parsed LEAP Response (client to server).
///
/// Wire format inside EAP-LEAP:
///   Version(1) + Unused(1) + Count(1) + Response(24) + Name(...)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeapResponse {
    /// LEAP version (typically 1)
    pub version: u8,
    /// Unused byte
    pub unused: u8,
    /// Response length (always 24)
    pub count: u8,
    /// 24-byte NT-Response hash
    pub response: Vec<u8>,
    /// Client username
    pub name: String,
}

/// Parse LEAP Challenge from EAP type-specific data.
///
/// Input: bytes AFTER the EAP type byte.
/// Minimum: Version(1) + Unused(1) + Count(1) + Challenge(count).
pub fn parse_leap_challenge(data: &[u8]) -> Option<LeapChallenge> {
    if data.len() < 3 {
        return None;
    }
    let version = data[0];
    let unused = data[1];
    let count = data[2];

    if data.len() < 3 + count as usize {
        return None;
    }

    let challenge = data[3..3 + count as usize].to_vec();

    let name_start = 3 + count as usize;
    let name = if data.len() > name_start {
        String::from_utf8_lossy(&data[name_start..]).into_owned()
    } else {
        String::new()
    };

    Some(LeapChallenge {
        version,
        unused,
        count,
        challenge,
        name,
    })
}

/// Parse LEAP Response from EAP type-specific data.
///
/// Input: bytes AFTER the EAP type byte.
/// Minimum: Version(1) + Unused(1) + Count(1) + Response(24) = 27 bytes.
pub fn parse_leap_response(data: &[u8]) -> Option<LeapResponse> {
    if data.len() < 3 {
        return None;
    }
    let version = data[0];
    let unused = data[1];
    let count = data[2];

    if count != 24 {
        return None; // LEAP response is always 24 bytes
    }
    if data.len() < 27 {
        return None;
    }

    let response = data[3..27].to_vec();

    let name = if data.len() > 27 {
        String::from_utf8_lossy(&data[27..]).into_owned()
    } else {
        String::new()
    };

    Some(LeapResponse {
        version,
        unused,
        count,
        response,
        name,
    })
}

/// Build an EAP-Request/LEAP Challenge packet.
///
/// `challenge` is typically 8 bytes. Returns complete EAP packet.
pub fn build_leap_challenge(id: u8, challenge: &[u8], server_name: &str) -> Vec<u8> {
    let name_bytes = server_name.as_bytes();
    // LEAP: Version(1) + Unused(1) + Count(1) + Challenge(N) + Name
    let eap_len: u16 = 5 + 3 + challenge.len() as u16 + name_bytes.len() as u16;

    let mut buf = Vec::with_capacity(eap_len as usize);

    // EAP header
    buf.push(eap_const::CODE_REQUEST);
    buf.push(id);
    buf.push(((eap_len >> 8) & 0xFF) as u8);
    buf.push((eap_len & 0xFF) as u8);
    buf.push(eap_const::TYPE_LEAP);

    // LEAP Challenge
    buf.push(0x01); // Version
    buf.push(0x00); // Unused
    buf.push(challenge.len() as u8); // Count
    buf.extend_from_slice(challenge);
    buf.extend_from_slice(name_bytes);

    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
//  GTC — Generic Token Card (RFC 3748 section 5.6)
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed GTC message. In a Request, this is the challenge prompt.
/// In a Response, this is the plaintext token/password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GtcMessage {
    /// Challenge prompt (Request) or plaintext token/password (Response).
    pub message: String,
}

/// Parse GTC payload from EAP type-specific data.
///
/// Input: bytes AFTER the EAP type byte.
pub fn parse_gtc(data: &[u8]) -> Option<GtcMessage> {
    // GTC body is just the message bytes — can be empty
    let message = String::from_utf8_lossy(data).into_owned();
    Some(GtcMessage { message })
}

/// Build an EAP-Request/GTC packet with the given prompt message.
///
/// Returns complete EAP packet.
pub fn build_gtc_request(id: u8, message: &str) -> Vec<u8> {
    let msg_bytes = message.as_bytes();
    let eap_len: u16 = 5 + msg_bytes.len() as u16;

    let mut buf = Vec::with_capacity(eap_len as usize);
    buf.push(eap_const::CODE_REQUEST);
    buf.push(id);
    buf.push(((eap_len >> 8) & 0xFF) as u8);
    buf.push((eap_len & 0xFF) as u8);
    buf.push(eap_const::TYPE_GTC);
    buf.extend_from_slice(msg_bytes);

    buf
}

/// Build an EAP-Response/GTC packet with the plaintext password/token.
///
/// Returns complete EAP packet.
pub fn build_gtc_response(id: u8, token: &str) -> Vec<u8> {
    let token_bytes = token.as_bytes();
    let eap_len: u16 = 5 + token_bytes.len() as u16;

    let mut buf = Vec::with_capacity(eap_len as usize);
    buf.push(eap_const::CODE_RESPONSE);
    buf.push(id);
    buf.push(((eap_len >> 8) & 0xFF) as u8);
    buf.push((eap_len & 0xFF) as u8);
    buf.push(eap_const::TYPE_GTC);
    buf.extend_from_slice(token_bytes);

    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MD5-Challenge (RFC 3748 section 5.4)
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed MD5-Challenge (either request or response).
///
/// Wire format: Value-Size(1) + Value(N) + Name(...)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Md5Challenge {
    /// Length of the challenge/response value
    pub value_size: u8,
    /// Challenge value (Request) or hash response (Response). Typically 16 bytes.
    pub value: Vec<u8>,
    /// Optional name (server name in Request, username in Response)
    pub name: String,
}

/// Parse MD5-Challenge from EAP type-specific data.
///
/// Input: bytes AFTER the EAP type byte.
/// Minimum: Value-Size(1) + Value(value_size).
pub fn parse_md5_challenge(data: &[u8]) -> Option<Md5Challenge> {
    if data.is_empty() {
        return None;
    }
    let value_size = data[0];
    if data.len() < 1 + value_size as usize {
        return None;
    }

    let value = data[1..1 + value_size as usize].to_vec();

    let name_start = 1 + value_size as usize;
    let name = if data.len() > name_start {
        String::from_utf8_lossy(&data[name_start..]).into_owned()
    } else {
        String::new()
    };

    Some(Md5Challenge {
        value_size,
        value,
        name,
    })
}

/// Build an EAP-Request/MD5-Challenge packet.
///
/// `challenge` is typically 16 bytes. Returns complete EAP packet.
pub fn build_md5_challenge(id: u8, challenge: &[u8], server_name: &str) -> Vec<u8> {
    let name_bytes = server_name.as_bytes();
    // MD5: Value-Size(1) + Value(N) + Name
    let eap_len: u16 = 5 + 1 + challenge.len() as u16 + name_bytes.len() as u16;

    let mut buf = Vec::with_capacity(eap_len as usize);
    buf.push(eap_const::CODE_REQUEST);
    buf.push(id);
    buf.push(((eap_len >> 8) & 0xFF) as u8);
    buf.push((eap_len & 0xFF) as u8);
    buf.push(eap_const::TYPE_MD5);
    buf.push(challenge.len() as u8); // Value-Size
    buf.extend_from_slice(challenge);
    buf.extend_from_slice(name_bytes);

    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP-TLS / TTLS / PEAP — outer layer (RFC 5216 section 3.1)
// ═══════════════════════════════════════════════════════════════════════════════

/// EAP-TLS flags byte bit positions.
pub mod tls_flags {
    /// Length Included — TLS Message Length field is present
    pub const LENGTH_INCLUDED: u8 = 0x80;
    /// More Fragments — this is not the last fragment
    pub const MORE_FRAGMENTS: u8 = 0x40;
    /// Start — first message in TLS negotiation (server to client)
    pub const START: u8 = 0x20;
    /// Version mask (bits 0-4, currently always 0 for EAP-TLS)
    pub const VERSION_MASK: u8 = 0x1F;
}

/// Parsed EAP-TLS/TTLS/PEAP outer header.
///
/// Wire format (after EAP type byte):
///   Flags(1) [+ TLS-Message-Length(4)] + TLS-Data(...)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EapTlsHeader {
    /// Flags byte: L(length included), M(more fragments), S(start), version bits
    pub flags: u8,
    /// TLS message total length (present only if L flag is set)
    pub tls_length: Option<u32>,
    /// TLS record data (fragment or complete)
    pub data: Vec<u8>,
}

impl EapTlsHeader {
    /// Returns true if the L (Length Included) flag is set.
    pub fn length_included(&self) -> bool {
        self.flags & tls_flags::LENGTH_INCLUDED != 0
    }

    /// Returns true if the M (More Fragments) flag is set.
    pub fn more_fragments(&self) -> bool {
        self.flags & tls_flags::MORE_FRAGMENTS != 0
    }

    /// Returns true if the S (Start) flag is set.
    pub fn is_start(&self) -> bool {
        self.flags & tls_flags::START != 0
    }

    /// Returns the version field (bits 0-4).
    pub fn version(&self) -> u8 {
        self.flags & tls_flags::VERSION_MASK
    }
}

/// Parse EAP-TLS/TTLS/PEAP outer layer from EAP type-specific data.
///
/// Input: bytes AFTER the EAP type byte.
pub fn parse_eap_tls(data: &[u8]) -> Option<EapTlsHeader> {
    if data.is_empty() {
        return None;
    }

    let flags = data[0];
    let mut offset = 1;

    let tls_length = if flags & tls_flags::LENGTH_INCLUDED != 0 {
        if data.len() < 5 {
            return None;
        }
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        offset = 5;
        Some(len)
    } else {
        None
    };

    let tls_data = if data.len() > offset {
        data[offset..].to_vec()
    } else {
        Vec::new()
    };

    Some(EapTlsHeader {
        flags,
        tls_length,
        data: tls_data,
    })
}

/// Build an EAP-TLS/TTLS/PEAP Start packet (server to client, initiates TLS).
///
/// `eap_type` should be `EapType::Tls`, `EapType::Ttls`, or `EapType::Peap`.
/// Returns complete EAP packet.
pub fn build_eap_tls_start(id: u8, eap_type: EapType) -> Vec<u8> {
    let type_byte = eap_type as u8;
    // EAP header(5) + Flags(1) = 6
    let eap_len: u16 = 6;

    vec![
        eap_const::CODE_REQUEST,
        id,
        ((eap_len >> 8) & 0xFF) as u8,
        (eap_len & 0xFF) as u8,
        type_byte,
        tls_flags::START, // Flags: S=1 (start)
    ]
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP-NAK (RFC 3748 section 5.3.1)
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed EAP-NAK response. Client rejects the offered method and suggests alternatives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EapNak {
    /// Desired EAP types the client would accept (recognized types only).
    pub desired_types: Vec<EapType>,
    /// Raw desired type bytes (includes unrecognized types).
    pub desired_types_raw: Vec<u8>,
}

/// Parse EAP-NAK from EAP type-specific data.
///
/// Input: bytes AFTER the EAP type byte (each byte is a desired type).
pub fn parse_eap_nak(data: &[u8]) -> Option<EapNak> {
    let desired_types_raw = data.to_vec();
    let desired_types: Vec<EapType> = data
        .iter()
        .filter_map(|&b| EapType::from_u8(b))
        .collect();

    Some(EapNak {
        desired_types,
        desired_types_raw,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Unified EAP Body — dispatched by type
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed EAP body, dispatched by method type.
#[derive(Clone, Debug)]
pub enum EapBody {
    /// EAP-Identity (type 1)
    Identity(EapIdentity),
    /// EAP-Notification (type 2) — just a message string
    Notification(String),
    /// EAP-NAK (type 3) — client rejects method
    Nak(EapNak),
    /// MSCHAPv2 Challenge (type 26, opcode 1)
    MsChapV2Challenge(MsChapV2Challenge),
    /// MSCHAPv2 Response (type 26, opcode 2)
    MsChapV2Response(MsChapV2Response),
    /// MSCHAPv2 other opcode (type 26, opcode 3/4/7) — raw data
    MsChapV2Other { op_code: u8, data: Vec<u8> },
    /// LEAP Challenge (type 17, in Request)
    LeapChallenge(LeapChallenge),
    /// LEAP Response (type 17, in Response)
    LeapResponse(LeapResponse),
    /// GTC message (type 6)
    Gtc(GtcMessage),
    /// MD5-Challenge (type 4)
    Md5Challenge(Md5Challenge),
    /// EAP-TLS outer layer (type 13)
    Tls(EapTlsHeader),
    /// EAP-TTLS outer layer (type 21)
    Ttls(EapTlsHeader),
    /// PEAP outer layer (type 25)
    Peap(EapTlsHeader),
    /// EAP-FAST outer layer (type 43)
    Fast(EapTlsHeader),
    /// TEAP outer layer (type 55)
    Teap(EapTlsHeader),
    /// WSC data (type 254) — raw bytes, parsed by wps.rs
    Wsc(Vec<u8>),
    /// Unrecognized EAP type — raw data preserved
    Unknown { eap_type: u8, data: Vec<u8> },
}

/// Parse a complete EAP packet, returning both the header and body.
///
/// Input: complete EAP packet starting at Code byte.
/// For Success/Failure packets, body is `None`.
pub fn parse_eap_packet(data: &[u8]) -> Option<(EapHeader, Option<EapBody>)> {
    let header = parse_eap_header(data)?;

    // Success/Failure have no body
    match header.code {
        EapCode::Success | EapCode::Failure => return Some((header, None)),
        _ => {}
    }

    // Need at least 5 bytes for type-bearing packets
    if data.len() < 5 {
        return Some((header, None));
    }

    let type_byte = data[4];
    // Type-specific data starts at offset 5
    let body_data = if data.len() > 5 {
        &data[5..]
    } else {
        &[] as &[u8]
    };

    let body = parse_eap_body_inner(type_byte, header.code, body_data);
    Some((header, body))
}

/// Parse EAP body by type, given the raw type byte, code, and type-specific data.
///
/// `body_data` is everything AFTER the EAP type byte (offset 5+).
pub fn parse_eap_body(data: &[u8]) -> Option<EapBody> {
    let header = parse_eap_header(data)?;

    match header.code {
        EapCode::Success | EapCode::Failure => return None,
        _ => {}
    }

    if data.len() < 5 {
        return None;
    }

    let type_byte = data[4];
    let body_data = if data.len() > 5 {
        &data[5..]
    } else {
        &[] as &[u8]
    };

    parse_eap_body_inner(type_byte, header.code, body_data)
}

/// Internal body parser dispatched by type byte.
fn parse_eap_body_inner(type_byte: u8, code: EapCode, body_data: &[u8]) -> Option<EapBody> {
    match type_byte {
        // Identity
        1 => parse_eap_identity(body_data).map(EapBody::Identity),

        // Notification
        2 => {
            let msg = String::from_utf8_lossy(body_data).into_owned();
            Some(EapBody::Notification(msg))
        }

        // NAK
        3 => parse_eap_nak(body_data).map(EapBody::Nak),

        // MD5-Challenge
        4 => parse_md5_challenge(body_data).map(EapBody::Md5Challenge),

        // GTC
        6 => parse_gtc(body_data).map(EapBody::Gtc),

        // EAP-TLS
        13 => parse_eap_tls(body_data).map(EapBody::Tls),

        // LEAP — direction depends on code
        17 => match code {
            EapCode::Request => parse_leap_challenge(body_data).map(EapBody::LeapChallenge),
            EapCode::Response => parse_leap_response(body_data)
                .map(EapBody::LeapResponse)
                .or_else(|| parse_leap_challenge(body_data).map(EapBody::LeapChallenge)),
            _ => Some(EapBody::Unknown {
                eap_type: type_byte,
                data: body_data.to_vec(),
            }),
        },

        // EAP-TTLS
        21 => parse_eap_tls(body_data).map(EapBody::Ttls),

        // PEAP
        25 => parse_eap_tls(body_data).map(EapBody::Peap),

        // MSCHAPv2 — dispatch by opcode
        26 => {
            if body_data.is_empty() {
                return Some(EapBody::Unknown {
                    eap_type: type_byte,
                    data: Vec::new(),
                });
            }
            let opcode = body_data[0];
            match opcode {
                mschapv2_opcode::CHALLENGE => {
                    parse_mschapv2_challenge(body_data).map(EapBody::MsChapV2Challenge)
                }
                mschapv2_opcode::RESPONSE => {
                    parse_mschapv2_response(body_data).map(EapBody::MsChapV2Response)
                }
                _ => Some(EapBody::MsChapV2Other {
                    op_code: opcode,
                    data: body_data.to_vec(),
                }),
            }
        }

        // EAP-FAST
        43 => parse_eap_tls(body_data).map(EapBody::Fast),

        // TEAP
        55 => parse_eap_tls(body_data).map(EapBody::Teap),

        // WSC (WPS)
        254 => Some(EapBody::Wsc(body_data.to_vec())),

        // Everything else — preserve raw data
        _ => Some(EapBody::Unknown {
            eap_type: type_byte,
            data: body_data.to_vec(),
        }),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Credential types — for capture engine and export
// ═══════════════════════════════════════════════════════════════════════════════

/// A captured EAP credential from a rogue AP attack.
/// Contains all data needed for offline cracking.
#[derive(Clone, Debug)]
pub struct CapturedCredential {
    /// EAP method used to capture this credential
    pub method: EapType,
    /// EAP identity (username, possibly with realm)
    pub identity: String,
    /// Extracted realm/domain from identity
    pub domain: String,
    /// Raw challenge bytes (method-dependent)
    pub challenge: Vec<u8>,
    /// Raw response bytes (method-dependent)
    pub response: Vec<u8>,
    /// Capture timestamp (microseconds since epoch or attack start)
    pub timestamp_us: u64,
}

/// Structured credential format for export to cracking tools.
///
/// Each variant contains the exact fields needed for its hashcat/john format.
#[derive(Clone, Debug)]
pub enum CredentialFormat {
    /// MSCHAPv2 — hashcat -m 5500 (NetNTLMv1):
    /// `username::::nt_response:peer_challenge+auth_challenge`
    MsChapV2 {
        username: String,
        auth_challenge: [u8; 16],
        peer_challenge: [u8; 16],
        nt_response: [u8; 24],
    },
    /// LEAP — asleap format:
    /// `challenge:response:username`
    Leap {
        username: String,
        challenge: Vec<u8>,
        response: Vec<u8>,
    },
    /// GTC — plaintext (no cracking needed):
    /// Just the password/token
    Gtc {
        username: String,
        token: String,
    },
    /// MD5-Challenge — hashcat -m 4800:
    /// `response:challenge:id`
    Md5 {
        username: String,
        id: u8,
        challenge: Vec<u8>,
        response: Vec<u8>,
    },
    /// Identity only — no credentials captured, just the username.
    IdentityOnly {
        identity: String,
        realm: Option<String>,
    },
}

impl CredentialFormat {
    /// Format credential for hashcat/asleap cracking tool input.
    ///
    /// Returns a single line suitable for writing to a hash file.
    pub fn to_hashcat_format(&self) -> String {
        match self {
            Self::MsChapV2 {
                username,
                auth_challenge,
                peer_challenge,
                nt_response,
            } => {
                // hashcat -m 5500: username::::nt_response:peer_challenge+auth_challenge
                let mut s = format!("{}::::", username);
                for b in nt_response {
                    s.push_str(&format!("{:02x}", b));
                }
                s.push(':');
                for b in peer_challenge {
                    s.push_str(&format!("{:02x}", b));
                }
                for b in auth_challenge {
                    s.push_str(&format!("{:02x}", b));
                }
                s
            }
            Self::Leap {
                username,
                challenge,
                response,
            } => {
                // asleap: challenge:response:username
                let mut s = String::new();
                for b in challenge {
                    s.push_str(&format!("{:02x}", b));
                }
                s.push(':');
                for b in response {
                    s.push_str(&format!("{:02x}", b));
                }
                s.push(':');
                s.push_str(username);
                s
            }
            Self::Gtc { username, token } => {
                // Plaintext — no cracking needed
                format!("# EAP-GTC plaintext credential\n# Identity: {}\n{}", username, token)
            }
            Self::Md5 {
                username: _,
                id,
                challenge,
                response,
            } => {
                // hashcat -m 4800: response:challenge:id
                let mut s = String::new();
                for b in response {
                    s.push_str(&format!("{:02x}", b));
                }
                s.push(':');
                for b in challenge {
                    s.push_str(&format!("{:02x}", b));
                }
                s.push_str(&format!(":{:02x}", id));
                s
            }
            Self::IdentityOnly { identity, .. } => {
                format!("# EAP identity (no credentials captured)\n{}", identity)
            }
        }
    }

    /// Human-readable description of the credential type and cracking method.
    pub fn description(&self) -> &'static str {
        match self {
            Self::MsChapV2 { .. } => "MSCHAPv2 hash (hashcat -m 5500)",
            Self::Leap { .. } => "LEAP hash (asleap / hashcat)",
            Self::Gtc { .. } => "GTC plaintext (no cracking needed)",
            Self::Md5 { .. } => "MD5-Challenge hash (hashcat -m 4800)",
            Self::IdentityOnly { .. } => "Identity only (no credentials)",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Generic EAP frame builders — for rogue AP
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a generic EAP-Request packet with the given type and data.
///
/// Returns complete EAP packet (no EAPOL wrapper).
pub fn build_eap_request(id: u8, eap_type: EapType, data: &[u8]) -> Vec<u8> {
    let eap_len: u16 = 5 + data.len() as u16;
    let mut buf = Vec::with_capacity(eap_len as usize);
    buf.push(eap_const::CODE_REQUEST);
    buf.push(id);
    buf.push(((eap_len >> 8) & 0xFF) as u8);
    buf.push((eap_len & 0xFF) as u8);
    buf.push(eap_type as u8);
    buf.extend_from_slice(data);
    buf
}

/// Build a generic EAP-Response packet with the given type and data.
///
/// Returns complete EAP packet (no EAPOL wrapper).
pub fn build_eap_response(id: u8, eap_type: EapType, data: &[u8]) -> Vec<u8> {
    let eap_len: u16 = 5 + data.len() as u16;
    let mut buf = Vec::with_capacity(eap_len as usize);
    buf.push(eap_const::CODE_RESPONSE);
    buf.push(id);
    buf.push(((eap_len >> 8) & 0xFF) as u8);
    buf.push((eap_len & 0xFF) as u8);
    buf.push(eap_type as u8);
    buf.extend_from_slice(data);
    buf
}

/// Build an EAP-Success packet.
///
/// Success packets have no type field — just Code(1) + ID(1) + Length(2) = 4 bytes.
pub fn build_eap_success(id: u8) -> Vec<u8> {
    vec![eap_const::CODE_SUCCESS, id, 0x00, 0x04]
}

/// Build an EAP-Failure packet.
///
/// Failure packets have no type field — just Code(1) + ID(1) + Length(2) = 4 bytes.
pub fn build_eap_failure(id: u8) -> Vec<u8> {
    vec![eap_const::CODE_FAILURE, id, 0x00, 0x04]
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAPOL wrappers — for embedding EAP in 802.1X
// ═══════════════════════════════════════════════════════════════════════════════

/// Wrap an EAP packet in an EAPOL header.
///
/// Prepends: Version(1) + Type(1) + Length(2) = 4 bytes.
/// Version is 0x02 (802.1X-2004), Type is 0x00 (EAP Packet).
pub fn wrap_eapol(eap_packet: &[u8]) -> Vec<u8> {
    let len = eap_packet.len() as u16;
    let mut buf = Vec::with_capacity(4 + eap_packet.len());
    buf.push(0x02); // Version: 802.1X-2004
    buf.push(0x00); // Type: EAP Packet
    buf.push(((len >> 8) & 0xFF) as u8);
    buf.push((len & 0xFF) as u8);
    buf.extend_from_slice(eap_packet);
    buf
}

/// Build an EAPOL-Start frame (client to AP, requests authentication).
///
/// EAPOL-Start has no body: Version(1) + Type(1) + Length(2) = 4 bytes.
pub fn build_eapol_start() -> Vec<u8> {
    vec![0x02, 0x01, 0x00, 0x00] // Version=2, Type=Start(1), Length=0
}

/// Build an EAPOL-Logoff frame (client to AP, terminates session).
pub fn build_eapol_logoff() -> Vec<u8> {
    vec![0x02, 0x02, 0x00, 0x00] // Version=2, Type=Logoff(2), Length=0
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── EapType ──

    #[test]
    fn test_eap_type_from_u8_known_types() {
        assert_eq!(EapType::from_u8(1), Some(EapType::Identity));
        assert_eq!(EapType::from_u8(3), Some(EapType::Nak));
        assert_eq!(EapType::from_u8(4), Some(EapType::Md5Challenge));
        assert_eq!(EapType::from_u8(6), Some(EapType::Gtc));
        assert_eq!(EapType::from_u8(13), Some(EapType::Tls));
        assert_eq!(EapType::from_u8(17), Some(EapType::Leap));
        assert_eq!(EapType::from_u8(21), Some(EapType::Ttls));
        assert_eq!(EapType::from_u8(25), Some(EapType::Peap));
        assert_eq!(EapType::from_u8(26), Some(EapType::MsChapV2));
        assert_eq!(EapType::from_u8(43), Some(EapType::Fast));
        assert_eq!(EapType::from_u8(52), Some(EapType::Pwd));
        assert_eq!(EapType::from_u8(55), Some(EapType::Teap));
        assert_eq!(EapType::from_u8(254), Some(EapType::Wsc));
    }

    #[test]
    fn test_eap_type_from_u8_unknown() {
        assert_eq!(EapType::from_u8(0), None);
        assert_eq!(EapType::from_u8(7), None);
        assert_eq!(EapType::from_u8(255), None);
    }

    #[test]
    fn test_eap_type_roundtrip() {
        let types = [
            EapType::Identity,
            EapType::Nak,
            EapType::Md5Challenge,
            EapType::Gtc,
            EapType::Tls,
            EapType::Leap,
            EapType::MsChapV2,
            EapType::Peap,
            EapType::Wsc,
        ];
        for t in &types {
            assert_eq!(EapType::from_u8(*t as u8), Some(*t));
        }
    }

    #[test]
    fn test_eap_type_tunneled() {
        assert!(EapType::Tls.is_tunneled());
        assert!(EapType::Ttls.is_tunneled());
        assert!(EapType::Peap.is_tunneled());
        assert!(EapType::Fast.is_tunneled());
        assert!(EapType::Teap.is_tunneled());
        assert!(!EapType::MsChapV2.is_tunneled());
        assert!(!EapType::Gtc.is_tunneled());
    }

    #[test]
    fn test_eap_type_bare_capturable() {
        assert!(EapType::Identity.is_bare_capturable());
        assert!(EapType::MsChapV2.is_bare_capturable());
        assert!(EapType::Leap.is_bare_capturable());
        assert!(EapType::Gtc.is_bare_capturable());
        assert!(EapType::Md5Challenge.is_bare_capturable());
        assert!(!EapType::Peap.is_bare_capturable());
        assert!(!EapType::Tls.is_bare_capturable());
    }

    // ── EapCode ──

    #[test]
    fn test_eap_code_from_u8() {
        assert_eq!(EapCode::from_u8(1), Some(EapCode::Request));
        assert_eq!(EapCode::from_u8(2), Some(EapCode::Response));
        assert_eq!(EapCode::from_u8(3), Some(EapCode::Success));
        assert_eq!(EapCode::from_u8(4), Some(EapCode::Failure));
        assert_eq!(EapCode::from_u8(0), None);
        assert_eq!(EapCode::from_u8(5), None);
    }

    // ── EAP Header ──

    #[test]
    fn test_parse_eap_header_request_identity() {
        // EAP-Request/Identity: Code=1, ID=1, Length=5, Type=1
        let data = [0x01, 0x01, 0x00, 0x05, 0x01];
        let hdr = parse_eap_header(&data).unwrap();
        assert_eq!(hdr.code, EapCode::Request);
        assert_eq!(hdr.id, 1);
        assert_eq!(hdr.length, 5);
        assert_eq!(hdr.eap_type, Some(EapType::Identity));
        assert_eq!(hdr.eap_type_raw, Some(1));
    }

    #[test]
    fn test_parse_eap_header_success() {
        // EAP-Success: Code=3, ID=5, Length=4
        let data = [0x03, 0x05, 0x00, 0x04];
        let hdr = parse_eap_header(&data).unwrap();
        assert_eq!(hdr.code, EapCode::Success);
        assert_eq!(hdr.id, 5);
        assert_eq!(hdr.length, 4);
        assert_eq!(hdr.eap_type, None);
        assert_eq!(hdr.eap_type_raw, None);
    }

    #[test]
    fn test_parse_eap_header_failure() {
        let data = [0x04, 0x0A, 0x00, 0x04];
        let hdr = parse_eap_header(&data).unwrap();
        assert_eq!(hdr.code, EapCode::Failure);
        assert_eq!(hdr.id, 10);
        assert_eq!(hdr.length, 4);
        assert_eq!(hdr.eap_type, None);
    }

    #[test]
    fn test_parse_eap_header_too_short() {
        assert!(parse_eap_header(&[0x01, 0x01, 0x00]).is_none());
        assert!(parse_eap_header(&[]).is_none());
    }

    #[test]
    fn test_parse_eap_header_invalid_code() {
        let data = [0x00, 0x01, 0x00, 0x04];
        assert!(parse_eap_header(&data).is_none());
    }

    #[test]
    fn test_parse_eap_header_length_too_small() {
        // Length = 3, which is less than minimum 4
        let data = [0x01, 0x01, 0x00, 0x03, 0x01];
        assert!(parse_eap_header(&data).is_none());
    }

    // ── EAP Identity ──

    #[test]
    fn test_parse_eap_identity_user_at_realm() {
        let data = b"john@corp.example.com";
        let id = parse_eap_identity(data).unwrap();
        assert_eq!(id.identity, "john@corp.example.com");
        assert_eq!(id.realm, Some("corp.example.com".to_string()));
    }

    #[test]
    fn test_parse_eap_identity_domain_backslash() {
        let data = b"CORP\\john";
        let id = parse_eap_identity(data).unwrap();
        assert_eq!(id.identity, "CORP\\john");
        assert_eq!(id.realm, Some("CORP".to_string()));
    }

    #[test]
    fn test_parse_eap_identity_plain_username() {
        let data = b"admin";
        let id = parse_eap_identity(data).unwrap();
        assert_eq!(id.identity, "admin");
        assert_eq!(id.realm, None);
    }

    #[test]
    fn test_parse_eap_identity_empty() {
        let id = parse_eap_identity(&[]).unwrap();
        assert_eq!(id.identity, "");
        assert_eq!(id.realm, None);
    }

    #[test]
    fn test_build_eap_identity_request() {
        let pkt = build_eap_identity_request(1);
        assert_eq!(pkt, vec![0x01, 0x01, 0x00, 0x05, 0x01]);
        // Verify it round-trips
        let hdr = parse_eap_header(&pkt).unwrap();
        assert_eq!(hdr.code, EapCode::Request);
        assert_eq!(hdr.id, 1);
        assert_eq!(hdr.eap_type, Some(EapType::Identity));
    }

    #[test]
    fn test_build_eap_identity_response() {
        let pkt = build_eap_identity_response(2, "user@test.com");
        assert_eq!(pkt[0], eap_const::CODE_RESPONSE);
        assert_eq!(pkt[1], 2);
        let len = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_eq!(len as usize, pkt.len());
        assert_eq!(pkt[4], eap_const::TYPE_IDENTITY);
        assert_eq!(&pkt[5..], b"user@test.com");
    }

    // ── MSCHAPv2 ──

    #[test]
    fn test_build_and_parse_mschapv2_challenge() {
        let challenge: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let pkt = build_mschapv2_challenge(3, &challenge, "Enterprise");

        // Verify EAP header
        assert_eq!(pkt[0], eap_const::CODE_REQUEST);
        assert_eq!(pkt[1], 3);
        assert_eq!(pkt[4], eap_const::TYPE_MSCHAPV2);

        // Parse back the MSCHAPv2 payload (after EAP type byte)
        let mschap_data = &pkt[5..];
        let parsed = parse_mschapv2_challenge(mschap_data).unwrap();
        assert_eq!(parsed.op_code, mschapv2_opcode::CHALLENGE);
        assert_eq!(parsed.ms_chap_id, 3);
        assert_eq!(parsed.value_size, 16);
        assert_eq!(parsed.challenge, challenge);
        assert_eq!(parsed.name, "Enterprise");
    }

    #[test]
    fn test_parse_mschapv2_response_real_world() {
        // Simulated MSCHAPv2 Response: OpCode=2, ID=3, MS-Length, Value-Size=49,
        // Peer-Challenge(16) + Reserved(8) + NT-Response(24) + Flags(1) + Name
        let mut data = Vec::new();
        data.push(0x02); // OpCode: Response
        data.push(0x03); // MS-CHAPv2 ID
        data.push(0x00);
        data.push(0x3E); // MS-Length = 62 (5 + 49 + 8 name bytes)
        data.push(49); // Value-Size

        // Peer Challenge (16 bytes)
        let peer_ch: [u8; 16] = [0xAA; 16];
        data.extend_from_slice(&peer_ch);
        // Reserved (8 bytes)
        data.extend_from_slice(&[0x00; 8]);
        // NT-Response (24 bytes)
        let nt_resp: [u8; 24] = [0xBB; 24];
        data.extend_from_slice(&nt_resp);
        // Flags
        data.push(0x00);
        // Name
        data.extend_from_slice(b"testuser");

        let parsed = parse_mschapv2_response(&data).unwrap();
        assert_eq!(parsed.op_code, 0x02);
        assert_eq!(parsed.ms_chap_id, 3);
        assert_eq!(parsed.value_size, 49);
        assert_eq!(parsed.peer_challenge, peer_ch);
        assert_eq!(parsed.nt_response, nt_resp);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.name, "testuser");
    }

    #[test]
    fn test_parse_mschapv2_response_too_short() {
        let data = [0x02, 0x03, 0x00, 0x10, 49]; // only 5 bytes
        assert!(parse_mschapv2_response(&data).is_none());
    }

    #[test]
    fn test_parse_mschapv2_challenge_wrong_opcode() {
        let mut data = vec![0x02]; // OpCode=Response, not Challenge
        data.push(0x01);
        data.extend_from_slice(&[0x00, 0x15]); // MS-Length
        data.push(16); // Value-Size
        data.extend_from_slice(&[0x00; 16]); // Challenge
        assert!(parse_mschapv2_challenge(&data).is_none());
    }

    // ── LEAP ──

    #[test]
    fn test_build_and_parse_leap_challenge() {
        let challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let pkt = build_leap_challenge(5, &challenge, "CiscoAP");

        assert_eq!(pkt[0], eap_const::CODE_REQUEST);
        assert_eq!(pkt[1], 5);
        assert_eq!(pkt[4], eap_const::TYPE_LEAP);

        let leap_data = &pkt[5..];
        let parsed = parse_leap_challenge(leap_data).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.unused, 0);
        assert_eq!(parsed.count, 8);
        assert_eq!(parsed.challenge, challenge.to_vec());
        assert_eq!(parsed.name, "CiscoAP");
    }

    #[test]
    fn test_parse_leap_response() {
        let mut data = Vec::new();
        data.push(0x01); // Version
        data.push(0x00); // Unused
        data.push(24); // Count = 24
        let resp = [0xCC; 24];
        data.extend_from_slice(&resp);
        data.extend_from_slice(b"alice");

        let parsed = parse_leap_response(&data).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.count, 24);
        assert_eq!(parsed.response, resp.to_vec());
        assert_eq!(parsed.name, "alice");
    }

    #[test]
    fn test_parse_leap_response_wrong_count() {
        // Count != 24 should fail
        let data = [0x01, 0x00, 8, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_leap_response(&data).is_none());
    }

    // ── GTC ──

    #[test]
    fn test_build_and_parse_gtc_request() {
        let pkt = build_gtc_request(7, "Password: ");

        assert_eq!(pkt[0], eap_const::CODE_REQUEST);
        assert_eq!(pkt[4], eap_const::TYPE_GTC);

        let gtc_data = &pkt[5..];
        let parsed = parse_gtc(gtc_data).unwrap();
        assert_eq!(parsed.message, "Password: ");
    }

    #[test]
    fn test_build_and_parse_gtc_response() {
        let pkt = build_gtc_response(7, "MyS3cretP@ss");

        assert_eq!(pkt[0], eap_const::CODE_RESPONSE);
        assert_eq!(pkt[4], eap_const::TYPE_GTC);

        let gtc_data = &pkt[5..];
        let parsed = parse_gtc(gtc_data).unwrap();
        assert_eq!(parsed.message, "MyS3cretP@ss");
    }

    // ── MD5-Challenge ──

    #[test]
    fn test_build_and_parse_md5_challenge() {
        let challenge = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C,
        ];
        let pkt = build_md5_challenge(8, &challenge, "RADIUS");

        assert_eq!(pkt[0], eap_const::CODE_REQUEST);
        assert_eq!(pkt[4], eap_const::TYPE_MD5);

        let md5_data = &pkt[5..];
        let parsed = parse_md5_challenge(md5_data).unwrap();
        assert_eq!(parsed.value_size, 16);
        assert_eq!(parsed.value, challenge.to_vec());
        assert_eq!(parsed.name, "RADIUS");
    }

    #[test]
    fn test_parse_md5_challenge_empty() {
        assert!(parse_md5_challenge(&[]).is_none());
    }

    #[test]
    fn test_parse_md5_challenge_value_size_mismatch() {
        // Value-Size says 16, but only 4 bytes of data
        let data = [16, 0x01, 0x02, 0x03, 0x04];
        assert!(parse_md5_challenge(&data).is_none());
    }

    // ── EAP-TLS ──

    #[test]
    fn test_parse_eap_tls_start() {
        // Flags: S=1 (start), no length, no data
        let data = [tls_flags::START];
        let parsed = parse_eap_tls(&data).unwrap();
        assert!(parsed.is_start());
        assert!(!parsed.length_included());
        assert!(!parsed.more_fragments());
        assert_eq!(parsed.tls_length, None);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn test_parse_eap_tls_with_length() {
        // Flags: L=1, TLS-Length=256, some data
        let mut data = vec![tls_flags::LENGTH_INCLUDED];
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // TLS-Length = 256
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // fragment data

        let parsed = parse_eap_tls(&data).unwrap();
        assert!(parsed.length_included());
        assert_eq!(parsed.tls_length, Some(256));
        assert_eq!(parsed.data, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_build_eap_tls_start() {
        let pkt = build_eap_tls_start(1, EapType::Peap);
        assert_eq!(pkt[0], eap_const::CODE_REQUEST);
        assert_eq!(pkt[1], 1);
        assert_eq!(pkt[4], EapType::Peap as u8);
        assert_eq!(pkt[5], tls_flags::START);
    }

    #[test]
    fn test_parse_eap_tls_empty() {
        assert!(parse_eap_tls(&[]).is_none());
    }

    // ── EAP-NAK ──

    #[test]
    fn test_parse_eap_nak_single() {
        let data = [eap_const::TYPE_MSCHAPV2];
        let parsed = parse_eap_nak(&data).unwrap();
        assert_eq!(parsed.desired_types, vec![EapType::MsChapV2]);
        assert_eq!(parsed.desired_types_raw, vec![26]);
    }

    #[test]
    fn test_parse_eap_nak_multiple() {
        let data = [eap_const::TYPE_PEAP, eap_const::TYPE_TTLS, eap_const::TYPE_MSCHAPV2];
        let parsed = parse_eap_nak(&data).unwrap();
        assert_eq!(parsed.desired_types.len(), 3);
        assert_eq!(parsed.desired_types[0], EapType::Peap);
        assert_eq!(parsed.desired_types[1], EapType::Ttls);
        assert_eq!(parsed.desired_types[2], EapType::MsChapV2);
    }

    #[test]
    fn test_parse_eap_nak_with_unknown_type() {
        let data = [25, 99]; // PEAP + unknown type 99
        let parsed = parse_eap_nak(&data).unwrap();
        assert_eq!(parsed.desired_types, vec![EapType::Peap]); // only known
        assert_eq!(parsed.desired_types_raw, vec![25, 99]); // all raw
    }

    #[test]
    fn test_parse_eap_nak_empty() {
        let parsed = parse_eap_nak(&[]).unwrap();
        assert!(parsed.desired_types.is_empty());
    }

    // ── Unified parse_eap_packet ──

    #[test]
    fn test_parse_eap_packet_identity_response() {
        let pkt = build_eap_identity_response(1, "bob@example.org");
        let (hdr, body) = parse_eap_packet(&pkt).unwrap();
        assert_eq!(hdr.code, EapCode::Response);
        assert_eq!(hdr.eap_type, Some(EapType::Identity));

        match body.unwrap() {
            EapBody::Identity(id) => {
                assert_eq!(id.identity, "bob@example.org");
                assert_eq!(id.realm, Some("example.org".to_string()));
            }
            other => panic!("expected Identity, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_eap_packet_success() {
        let pkt = build_eap_success(42);
        let (hdr, body) = parse_eap_packet(&pkt).unwrap();
        assert_eq!(hdr.code, EapCode::Success);
        assert_eq!(hdr.id, 42);
        assert!(body.is_none());
    }

    #[test]
    fn test_parse_eap_packet_failure() {
        let pkt = build_eap_failure(99);
        let (hdr, body) = parse_eap_packet(&pkt).unwrap();
        assert_eq!(hdr.code, EapCode::Failure);
        assert_eq!(hdr.id, 99);
        assert!(body.is_none());
    }

    #[test]
    fn test_parse_eap_packet_mschapv2_challenge() {
        let challenge = [0xFF; 16];
        let pkt = build_mschapv2_challenge(10, &challenge, "TestSrv");
        let (hdr, body) = parse_eap_packet(&pkt).unwrap();
        assert_eq!(hdr.code, EapCode::Request);
        assert_eq!(hdr.eap_type, Some(EapType::MsChapV2));

        match body.unwrap() {
            EapBody::MsChapV2Challenge(ch) => {
                assert_eq!(ch.challenge, challenge);
                assert_eq!(ch.name, "TestSrv");
            }
            other => panic!("expected MsChapV2Challenge, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_eap_packet_gtc() {
        let pkt = build_gtc_request(5, "Enter PIN: ");
        let (hdr, body) = parse_eap_packet(&pkt).unwrap();
        assert_eq!(hdr.code, EapCode::Request);

        match body.unwrap() {
            EapBody::Gtc(gtc) => assert_eq!(gtc.message, "Enter PIN: "),
            other => panic!("expected Gtc, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_eap_packet_unknown_type() {
        // Build a packet with unrecognized type 200
        let pkt = [0x01, 0x01, 0x00, 0x07, 200, 0xDE, 0xAD];
        let (hdr, body) = parse_eap_packet(&pkt).unwrap();
        assert_eq!(hdr.code, EapCode::Request);
        assert_eq!(hdr.eap_type, None);
        assert_eq!(hdr.eap_type_raw, Some(200));

        match body.unwrap() {
            EapBody::Unknown { eap_type, data } => {
                assert_eq!(eap_type, 200);
                assert_eq!(data, vec![0xDE, 0xAD]);
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    // ── EAP frame builders ──

    #[test]
    fn test_build_eap_request_generic() {
        let pkt = build_eap_request(1, EapType::MsChapV2, &[0x01, 0x02, 0x03]);
        assert_eq!(pkt[0], eap_const::CODE_REQUEST);
        assert_eq!(pkt[1], 1);
        let len = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_eq!(len, 8); // 5 + 3
        assert_eq!(pkt[4], EapType::MsChapV2 as u8);
        assert_eq!(&pkt[5..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_build_eap_response_generic() {
        let pkt = build_eap_response(2, EapType::Nak, &[25]); // NAK, wants PEAP
        assert_eq!(pkt[0], eap_const::CODE_RESPONSE);
        assert_eq!(pkt[4], EapType::Nak as u8);
        assert_eq!(pkt[5], 25);
    }

    #[test]
    fn test_build_eap_success_structure() {
        let pkt = build_eap_success(10);
        assert_eq!(pkt.len(), 4);
        assert_eq!(pkt[0], eap_const::CODE_SUCCESS);
        assert_eq!(pkt[1], 10);
        assert_eq!(pkt[2], 0x00);
        assert_eq!(pkt[3], 0x04);
    }

    #[test]
    fn test_build_eap_failure_structure() {
        let pkt = build_eap_failure(20);
        assert_eq!(pkt.len(), 4);
        assert_eq!(pkt[0], eap_const::CODE_FAILURE);
        assert_eq!(pkt[1], 20);
        assert_eq!(pkt[2], 0x00);
        assert_eq!(pkt[3], 0x04);
    }

    // ── EAPOL wrappers ──

    #[test]
    fn test_wrap_eapol() {
        let eap = build_eap_identity_request(1);
        let eapol = wrap_eapol(&eap);
        assert_eq!(eapol[0], 0x02); // Version
        assert_eq!(eapol[1], 0x00); // Type: EAP Packet
        let len = u16::from_be_bytes([eapol[2], eapol[3]]);
        assert_eq!(len as usize, eap.len());
        assert_eq!(&eapol[4..], &eap);
    }

    #[test]
    fn test_build_eapol_start() {
        let pkt = build_eapol_start();
        assert_eq!(pkt, vec![0x02, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_build_eapol_logoff() {
        let pkt = build_eapol_logoff();
        assert_eq!(pkt, vec![0x02, 0x02, 0x00, 0x00]);
    }

    // ── Credential formatting ──

    #[test]
    fn test_credential_format_mschapv2_hashcat() {
        let cred = CredentialFormat::MsChapV2 {
            username: "john".to_string(),
            auth_challenge: [0x11; 16],
            peer_challenge: [0x22; 16],
            nt_response: [0x33; 24],
        };
        let s = cred.to_hashcat_format();
        // Format: username::::nt_response:peer_challenge+auth_challenge
        assert!(s.starts_with("john::::"));
        // 24 bytes of 0x33 = 48 hex chars
        assert!(s.contains("333333333333333333333333333333333333333333333333"));
        // Followed by : then 16 bytes of 0x22 + 16 bytes of 0x11 = 64 hex chars
        assert!(s.ends_with("11111111111111111111111111111111"));
    }

    #[test]
    fn test_credential_format_leap_asleap() {
        let cred = CredentialFormat::Leap {
            username: "alice".to_string(),
            challenge: vec![0xAA; 8],
            response: vec![0xBB; 24],
        };
        let s = cred.to_hashcat_format();
        // Format: challenge:response:username
        assert!(s.starts_with("aaaaaaaaaaaaaaaa:"));
        assert!(s.ends_with(":alice"));
    }

    #[test]
    fn test_credential_format_gtc_plaintext() {
        let cred = CredentialFormat::Gtc {
            username: "bob".to_string(),
            token: "P@ssw0rd!".to_string(),
        };
        let s = cred.to_hashcat_format();
        assert!(s.contains("bob"));
        assert!(s.contains("P@ssw0rd!"));
    }

    #[test]
    fn test_credential_format_md5_hashcat() {
        let cred = CredentialFormat::Md5 {
            username: "eve".to_string(),
            id: 0x0A,
            challenge: vec![0xCC; 16],
            response: vec![0xDD; 16],
        };
        let s = cred.to_hashcat_format();
        // Format: response:challenge:id
        assert!(s.starts_with("dddddddddddddddddddddddddddddddd:"));
        assert!(s.ends_with(":0a"));
    }

    // ── C compatibility: verify byte-level match with attack_eap.c builders ──

    #[test]
    fn test_c_compat_identity_request() {
        // C eap_build_request_identity produces EAPOL(4) + EAP(5) = 9 bytes
        // Our build_eap_identity_request produces EAP-only (5 bytes)
        // Wrapped in EAPOL it should match the C output
        let eap = build_eap_identity_request(1);
        let eapol = wrap_eapol(&eap);
        assert_eq!(eapol.len(), 9);
        assert_eq!(eapol[0], 0x02); // EAPOL version
        assert_eq!(eapol[1], 0x00); // EAPOL type: EAP
        assert_eq!(eapol[2], 0x00);
        assert_eq!(eapol[3], 0x05); // EAPOL body length = 5
        assert_eq!(eapol[4], 0x01); // EAP Code: Request
        assert_eq!(eapol[5], 1); // EAP ID
        assert_eq!(eapol[6], 0x00);
        assert_eq!(eapol[7], 0x05); // EAP length = 5
        assert_eq!(eapol[8], 0x01); // EAP Type: Identity
    }

    #[test]
    fn test_c_compat_mschapv2_challenge() {
        // Verify our MSCHAPv2 challenge matches C eap_build_mschapv2_challenge
        let challenge = [0x01; 16];
        let eap = build_mschapv2_challenge(2, &challenge, "Srv");
        let eapol = wrap_eapol(&eap);

        // C output structure:
        // EAPOL: ver(1) + type(1) + len(2)
        // EAP: code(1) + id(1) + len(2) + type(1)
        // MSCHAPv2: opcode(1) + id(1) + ms_len(2) + val_size(1) + challenge(16) + name(3)
        assert_eq!(eapol[0], 0x02); // EAPOL version
        assert_eq!(eapol[1], 0x00); // EAPOL type

        let eap_data = &eapol[4..];
        assert_eq!(eap_data[0], 0x01); // EAP Request
        assert_eq!(eap_data[1], 2); // EAP ID
        assert_eq!(eap_data[4], 26); // Type: MSCHAPv2

        let mschap = &eap_data[5..];
        assert_eq!(mschap[0], 0x01); // OpCode: Challenge
        assert_eq!(mschap[1], 2); // MS-CHAPv2 ID
        assert_eq!(mschap[4], 16); // Value-Size
        assert_eq!(&mschap[5..21], &challenge);
        assert_eq!(&mschap[21..24], b"Srv");
    }

    #[test]
    fn test_c_compat_leap_challenge() {
        // Verify our LEAP challenge matches C eap_build_leap_challenge
        let challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let eap = build_leap_challenge(4, &challenge, "AP");
        let eapol = wrap_eapol(&eap);

        let eap_data = &eapol[4..];
        assert_eq!(eap_data[0], 0x01); // EAP Request
        assert_eq!(eap_data[1], 4); // EAP ID
        assert_eq!(eap_data[4], 17); // Type: LEAP

        let leap = &eap_data[5..];
        assert_eq!(leap[0], 0x01); // Version
        assert_eq!(leap[1], 0x00); // Unused
        assert_eq!(leap[2], 8); // Count
        assert_eq!(&leap[3..11], &challenge);
        assert_eq!(&leap[11..13], b"AP");
    }

    #[test]
    fn test_c_compat_gtc_request() {
        // Verify our GTC request matches C eap_build_gtc_request
        let eap = build_gtc_request(5, "Password: ");
        let eapol = wrap_eapol(&eap);

        let eap_data = &eapol[4..];
        assert_eq!(eap_data[0], 0x01); // EAP Request
        assert_eq!(eap_data[1], 5); // EAP ID
        assert_eq!(eap_data[4], 6); // Type: GTC
        assert_eq!(&eap_data[5..], b"Password: ");
    }

    #[test]
    fn test_c_compat_md5_challenge() {
        // Verify our MD5 challenge matches C eap_build_md5_challenge
        let challenge = [0xDE; 16];
        let eap = build_md5_challenge(6, &challenge, "Srv");
        let eapol = wrap_eapol(&eap);

        let eap_data = &eapol[4..];
        assert_eq!(eap_data[0], 0x01); // EAP Request
        assert_eq!(eap_data[4], 4); // Type: MD5

        let md5 = &eap_data[5..];
        assert_eq!(md5[0], 16); // Value-Size
        assert_eq!(&md5[1..17], &challenge);
        assert_eq!(&md5[17..20], b"Srv");
    }

    #[test]
    fn test_c_compat_success_failure() {
        // C eap_build_result(buf, id, success) produces EAPOL(4) + EAP(4) = 8 bytes
        let success_eap = build_eap_success(5);
        let success_eapol = wrap_eapol(&success_eap);
        assert_eq!(success_eapol.len(), 8);
        assert_eq!(success_eapol[4], 0x03); // Code: Success
        assert_eq!(success_eapol[5], 5); // ID
        assert_eq!(success_eapol[6], 0x00);
        assert_eq!(success_eapol[7], 0x04); // Length: 4

        let failure_eap = build_eap_failure(5);
        let failure_eapol = wrap_eapol(&failure_eap);
        assert_eq!(failure_eapol[4], 0x04); // Code: Failure
    }

    // ── Edge cases ──

    #[test]
    fn test_parse_eap_packet_with_trailing_data() {
        // Valid EAP packet with extra bytes after declared length — should still parse
        let mut pkt = build_eap_identity_request(1);
        pkt.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // trailing garbage
        let (hdr, _body) = parse_eap_packet(&pkt).unwrap();
        assert_eq!(hdr.length, 5); // declared length, not actual buffer length
    }

    #[test]
    fn test_eap_type_matches_ieee80211_constants() {
        // Verify our EapType values match the constants in ieee80211::eap
        assert_eq!(EapType::Identity as u8, eap_const::TYPE_IDENTITY);
        assert_eq!(EapType::Nak as u8, eap_const::TYPE_NAK);
        assert_eq!(EapType::Md5Challenge as u8, eap_const::TYPE_MD5);
        assert_eq!(EapType::Tls as u8, eap_const::TYPE_TLS);
        assert_eq!(EapType::Leap as u8, eap_const::TYPE_LEAP);
        assert_eq!(EapType::Sim as u8, eap_const::TYPE_SIM);
        assert_eq!(EapType::Ttls as u8, eap_const::TYPE_TTLS);
        assert_eq!(EapType::Peap as u8, eap_const::TYPE_PEAP);
        assert_eq!(EapType::MsChapV2 as u8, eap_const::TYPE_MSCHAPV2);
        assert_eq!(EapType::Fast as u8, eap_const::TYPE_FAST);
        assert_eq!(EapType::Wsc as u8, eap_const::TYPE_WSC);
    }

    #[test]
    fn test_eap_code_matches_ieee80211_constants() {
        assert_eq!(EapCode::Request as u8, eap_const::CODE_REQUEST);
        assert_eq!(EapCode::Response as u8, eap_const::CODE_RESPONSE);
        assert_eq!(EapCode::Success as u8, eap_const::CODE_SUCCESS);
        assert_eq!(EapCode::Failure as u8, eap_const::CODE_FAILURE);
    }

    #[test]
    fn test_parse_eap_body_via_full_packet() {
        // Test parse_eap_body which takes a complete EAP packet
        let pkt = build_eap_identity_response(1, "test@example.com");
        let body = parse_eap_body(&pkt).unwrap();
        match body {
            EapBody::Identity(id) => {
                assert_eq!(id.identity, "test@example.com");
                assert_eq!(id.realm, Some("example.com".to_string()));
            }
            other => panic!("expected Identity, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_eap_body_returns_none_for_success() {
        let pkt = build_eap_success(1);
        assert!(parse_eap_body(&pkt).is_none());
    }

    #[test]
    fn test_credential_format_identity_only() {
        let cred = CredentialFormat::IdentityOnly {
            identity: "admin@corp.local".to_string(),
            realm: Some("corp.local".to_string()),
        };
        let s = cred.to_hashcat_format();
        assert!(s.contains("admin@corp.local"));
        assert!(s.contains("no credentials"));
    }

    #[test]
    fn test_credential_format_description() {
        assert_eq!(
            CredentialFormat::MsChapV2 {
                username: String::new(),
                auth_challenge: [0; 16],
                peer_challenge: [0; 16],
                nt_response: [0; 24],
            }
            .description(),
            "MSCHAPv2 hash (hashcat -m 5500)"
        );
        assert_eq!(
            CredentialFormat::Gtc {
                username: String::new(),
                token: String::new(),
            }
            .description(),
            "GTC plaintext (no cracking needed)"
        );
    }
}
