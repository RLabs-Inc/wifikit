//! Information Element (IE) builders and parsers.
//!
//! **Builders**: Construct tagged parameter bytes for injection frames
//! (beacon, probe response, association request, etc.).
//!
#![allow(dead_code)]
#![allow(unused_imports)]
//! **Parsers**: Extract structured data from raw IE byte streams
//! received in beacons and probe responses.
//!
//! Reference: IEEE Std 802.11-2020 §9.4.2, wifi-map/libwifikit/wifikit_ie.c

use super::ieee80211::{
    ie_ext_id, ie_tag, AkmSuite, CipherSuite, OUI_IEEE, OUI_MICROSOFT, Security, WifiGeneration,
};

// ═══════════════════════════════════════════════════════════════════════════════
//  RSN Info — parsed or constructed RSN IE data
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed RSN (Robust Security Network) information from an RSN IE or WPA IE.
#[derive(Debug, Clone, Default)]
pub struct RsnInfo {
    pub security: Security,
    pub group_cipher: CipherSuite,
    pub pairwise_ciphers: Vec<CipherSuite>,
    pub akm_suites: Vec<AkmSuite>,
    pub mfp_capable: bool,
    pub mfp_required: bool,
    pub rsn_caps: u16,
    pub pmkid_count: u16,
    pub pre_auth: bool,
}

impl RsnInfo {
    /// Primary pairwise cipher (first in list), if present.
    pub fn pairwise_cipher(&self) -> Option<CipherSuite> {
        self.pairwise_ciphers.first().copied()
    }

    /// Primary AKM suite (first in list), if present.
    pub fn akm(&self) -> Option<AkmSuite> {
        self.akm_suites.first().copied()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Individual IE builders
// ═══════════════════════════════════════════════════════════════════════════════

/// Build SSID IE (tag 0). Empty `ssid` creates a wildcard/hidden SSID.
pub fn build_ssid(ssid: &[u8]) -> Vec<u8> {
    let mut ie = Vec::with_capacity(2 + ssid.len());
    ie.push(ie_tag::SSID);
    ie.push(ssid.len() as u8);
    ie.extend_from_slice(ssid);
    ie
}

/// Build Supported Rates IE (tag 1) and optionally Extended Supported Rates IE (tag 50).
/// Returns both IEs concatenated.
pub fn build_rates(band_5ghz: bool) -> Vec<u8> {
    // 2.4 GHz: CCK (1,2,5.5,11) + OFDM (6,9,12,18,24,36,48,54) = 12 rates
    // 5 GHz:   OFDM only (6,9,12,18,24,36,48,54) = 8 rates
    // BSS basic rates have bit 7 set (0x80)
    static RATES_24GHZ: &[u8] = &[
        0x82, // 1 Mbps (basic)
        0x84, // 2 Mbps (basic)
        0x8B, // 5.5 Mbps (basic)
        0x96, // 11 Mbps (basic)
        0x0C, // 6 Mbps
        0x12, // 9 Mbps
        0x18, // 12 Mbps
        0x24, // 18 Mbps
        0x30, // 24 Mbps
        0x48, // 36 Mbps
        0x60, // 48 Mbps
        0x6C, // 54 Mbps
    ];

    static RATES_5GHZ: &[u8] = &[
        0x8C, // 6 Mbps (basic)
        0x12, // 9 Mbps
        0x98, // 12 Mbps (basic)
        0x24, // 18 Mbps
        0xB0, // 24 Mbps (basic)
        0x48, // 36 Mbps
        0x60, // 48 Mbps
        0x6C, // 54 Mbps
    ];

    let rates = if band_5ghz { RATES_5GHZ } else { RATES_24GHZ };
    let main_count = rates.len().min(8);
    let ext_count = rates.len().saturating_sub(8);

    let mut ie = Vec::with_capacity(2 + main_count + if ext_count > 0 { 2 + ext_count } else { 0 });

    // Supported Rates IE (tag 1) — max 8 rates
    ie.push(ie_tag::SUPPORTED_RATES);
    ie.push(main_count as u8);
    ie.extend_from_slice(&rates[..main_count]);

    // Extended Supported Rates IE (tag 50) — overflow
    if ext_count > 0 {
        ie.push(ie_tag::EXTENDED_RATES);
        ie.push(ext_count as u8);
        ie.extend_from_slice(&rates[main_count..]);
    }

    ie
}

/// Build DS Parameter Set IE (tag 3) — declares the channel.
pub fn build_ds_param(channel: u8) -> Vec<u8> {
    vec![ie_tag::DS_PARAMS, 1, channel]
}

/// Build RSN IE (tag 48) from an RsnInfo struct, with optional PMKID.
pub fn build_rsn(rsn: &RsnInfo, pmkid: Option<&[u8; 16]>) -> Vec<u8> {
    let pw_suites: Vec<CipherSuite> = if rsn.pairwise_ciphers.is_empty() {
        vec![CipherSuite::Ccmp]
    } else {
        rsn.pairwise_ciphers.clone()
    };

    let akm_list: Vec<AkmSuite> = if rsn.akm_suites.is_empty() {
        vec![AkmSuite::Psk]
    } else {
        rsn.akm_suites.clone()
    };

    // Body: Version(2) + Group(4) + PW Count(2) + PW Suites(4*N)
    //     + AKM Count(2) + AKM Suites(4*M) + RSN Caps(2)
    //     + optional PMKID Count(2) + PMKID(16)
    let body_len = 2 + 4 + 2 + (4 * pw_suites.len()) + 2 + (4 * akm_list.len()) + 2
        + if pmkid.is_some() { 2 + 16 } else { 0 };

    let mut ie = Vec::with_capacity(2 + body_len);

    ie.push(ie_tag::RSN);
    ie.push(body_len as u8);

    // Version: 1
    ie.extend_from_slice(&1u16.to_le_bytes());

    // Group cipher suite
    ie.extend_from_slice(&OUI_IEEE);
    ie.push(rsn.group_cipher as u8);

    // Pairwise cipher suites
    ie.extend_from_slice(&(pw_suites.len() as u16).to_le_bytes());
    for cipher in &pw_suites {
        ie.extend_from_slice(&OUI_IEEE);
        ie.push(*cipher as u8);
    }

    // AKM suites
    ie.extend_from_slice(&(akm_list.len() as u16).to_le_bytes());
    for akm in &akm_list {
        ie.extend_from_slice(&OUI_IEEE);
        ie.push(*akm as u8);
    }

    // RSN Capabilities
    let mut rsn_caps: u16 = rsn.rsn_caps;
    if rsn.mfp_capable {
        rsn_caps |= 1 << 7;
    }
    if rsn.mfp_required {
        rsn_caps |= 1 << 6;
    }
    ie.extend_from_slice(&rsn_caps.to_le_bytes());

    // Optional PMKID
    if let Some(pmkid_bytes) = pmkid {
        ie.extend_from_slice(&1u16.to_le_bytes()); // PMKID count: 1
        ie.extend_from_slice(pmkid_bytes);
    }

    ie
}

/// Build HT Capabilities IE (tag 45) — 802.11n, 28 bytes total.
pub fn build_ht_caps(nss: u8) -> Vec<u8> {
    let mut ie = vec![0u8; 28];
    ie[0] = ie_tag::HT_CAPABILITIES;
    ie[1] = 26; // body length

    // HT Capability Info (2 bytes):
    //   bit 0: LDPC, bit 1: 20/40 MHz, bits 2-3: SM Power Save (3=disabled),
    //   bit 8: Short GI 20, bit 9: Short GI 40, bit 12: DSSS/CCK in 40
    let ht_cap: u16 = (1 << 0) | (1 << 1) | (3 << 2) | (1 << 8) | (1 << 9) | (1 << 12);
    ie[2] = (ht_cap & 0xFF) as u8;
    ie[3] = (ht_cap >> 8) as u8;

    // A-MPDU Parameters: max length exponent=1 (8191), min spacing=5 (4us)
    ie[4] = 0x17;

    // Supported MCS Set (16 bytes at offset 5)
    ie[5] = 0xFF; // MCS 0-7 (stream 1)
    if nss >= 2 {
        ie[6] = 0xFF; // MCS 8-15 (stream 2)
    }
    ie[17] = 0x01; // TX MCS set defined

    ie
}

/// Build HT Operation IE (tag 61) — 24 bytes total.
pub fn build_ht_oper(primary_channel: u8) -> Vec<u8> {
    let mut ie = vec![0u8; 24];
    ie[0] = ie_tag::HT_OPERATION;
    ie[1] = 22; // body length
    ie[2] = primary_channel;
    ie
}

/// Build VHT Capabilities IE (tag 191) — 802.11ac, 14 bytes total.
pub fn build_vht_caps(nss: u8) -> Vec<u8> {
    let mut ie = vec![0u8; 14];
    ie[0] = ie_tag::VHT_CAPABILITIES;
    ie[1] = 12; // body length

    // VHT Capabilities Info (4 bytes):
    //   bit 0: max MPDU 7991, bit 4: RX LDPC, bit 5: Short GI 80, bit 11: SU beamformee
    let vht_cap: u32 = (1 << 0) | (1 << 4) | (1 << 5) | (1 << 11);
    ie[2] = (vht_cap & 0xFF) as u8;
    ie[3] = ((vht_cap >> 8) & 0xFF) as u8;
    ie[4] = ((vht_cap >> 16) & 0xFF) as u8;
    ie[5] = ((vht_cap >> 24) & 0xFF) as u8;

    // VHT-MCS and NSS Set (8 bytes): 2 bits per NSS (0=MCS0-7, 1=MCS0-8, 2=MCS0-9, 3=not supported)
    let mut mcs_map: u16 = 0xFFFF; // all not-supported
    for i in 0..nss.min(8) {
        mcs_map &= !(3 << (i * 2));
        mcs_map |= 2 << (i * 2); // MCS 0-9 per stream
    }
    let mcs_le = mcs_map.to_le_bytes();
    // RX MCS map
    ie[6] = mcs_le[0];
    ie[7] = mcs_le[1];
    // RX highest rate (0 = not specified)
    ie[8] = 0;
    ie[9] = 0;
    // TX MCS map (same as RX)
    ie[10] = mcs_le[0];
    ie[11] = mcs_le[1];
    // TX highest rate
    ie[12] = 0;
    ie[13] = 0;

    ie
}

/// Build HE Capabilities IE (Extension IE 255/35) — 802.11ax, 24 bytes total.
pub fn build_he_caps(nss: u8) -> Vec<u8> {
    let nss = nss.clamp(1, 2);
    let body_len: u8 = 22; // ext_id(1) + MAC Caps(6) + PHY Caps(11) + MCS/NSS(4)

    let mut ie = vec![0u8; 2 + body_len as usize];
    ie[0] = ie_tag::EXTENSION;
    ie[1] = body_len;
    ie[2] = ie_ext_id::HE_CAPABILITIES;

    // HE MAC Capabilities (6 octets at offset 3)
    ie[3] = 0x08;     // B3=1 (fragmentation level 1)
    ie[4] = 0x80;     // B15: A-MSDU in A-MPDU
    ie[6] = 0x02;     // B25: OM Control

    // HE PHY Capabilities (11 octets at offset 9)
    ie[9] = 0x06;     // B1+B2: 40MHz 2.4G + 40/80MHz 5G
    ie[10] = 0x18;    // B11: LDPC, B12: SU PPDU 1xLTF 0.8us GI
    ie[11] = 0x40 | ((nss - 1) << 1); // B22: SU Beamformee, B24-26: BF STS
    ie[14] = 0x01;    // B40: HE-ER SU PPDU 4xLTF 0.8us GI
    ie[15] = 0xA0;    // B53-54: Nominal Packet Padding = 16us

    // HE-MCS and NSS Set (4 octets at offset 20): 2 bits per NSS (2=MCS0-11)
    let mut mcs_map: u16 = 0xFFFF;
    for i in 0..nss.min(8) {
        mcs_map &= !(3 << (i * 2));
        mcs_map |= 2 << (i * 2); // MCS 0-11 per stream
    }
    let mcs_le = mcs_map.to_le_bytes();
    // RX MCS map
    ie[20] = mcs_le[0];
    ie[21] = mcs_le[1];
    // TX MCS map
    ie[22] = mcs_le[0];
    ie[23] = mcs_le[1];

    ie
}

/// Build Extended Capabilities IE (tag 127) — 10 bytes total.
pub fn build_ext_caps() -> Vec<u8> {
    let body_len: u8 = 8;
    let mut ie = vec![0u8; 2 + body_len as usize];
    ie[0] = ie_tag::EXTENDED_CAPABILITIES;
    ie[1] = body_len;
    // Octet 1: bit 2 = Extended Channel Switching
    ie[2] = 0x04;
    // Octet 3: bit 3 = BSS Transition (802.11v)
    ie[4] = 0x08;
    // Octet 7: bit 0 = Operating Mode Notification
    ie[9] = 0x01;
    ie
}

/// Build WMM Information Element (vendor-specific IE 221).
pub fn build_wmm() -> Vec<u8> {
    vec![
        ie_tag::VENDOR_SPECIFIC,
        7,    // length
        0x00, 0x50, 0xF2, // Microsoft OUI
        0x02, // WMM/WME type
        0x00, // WME subtype: Information Element
        0x01, // WME version
        0x00, // QoS info: all AC enabled, no U-APSD
    ]
}

/// Build TIM IE (tag 5) — Traffic Indication Map.
pub fn build_tim(dtim_count: u8, dtim_period: u8) -> Vec<u8> {
    vec![
        ie_tag::TIM,
        4, // length
        dtim_count,
        if dtim_period > 0 { dtim_period } else { 1 },
        0, // Bitmap Control: no multicast buffered
        0, // Partial Virtual Bitmap: no stations in PS
    ]
}

/// Build Country IE (tag 7) with regulatory triplets.
pub fn build_country(country_code: &[u8; 2], band_5ghz: bool) -> Vec<u8> {
    if band_5ghz {
        // 5 GHz: 4 UNII band triplets
        let mut ie = Vec::with_capacity(17);
        ie.push(ie_tag::COUNTRY);
        ie.push(3 + 12); // country string + 4 triplets
        ie.push(country_code[0]);
        ie.push(country_code[1]);
        ie.push(b' '); // environment: any
        // UNII-1: ch 36-48, 23 dBm
        ie.extend_from_slice(&[36, 4, 23]);
        // UNII-2: ch 52-64, 23 dBm
        ie.extend_from_slice(&[52, 4, 23]);
        // UNII-2E: ch 100-144, 30 dBm
        ie.extend_from_slice(&[100, 12, 30]);
        // UNII-3: ch 149-165, 30 dBm
        ie.extend_from_slice(&[149, 5, 30]);
        ie
    } else {
        // 2.4 GHz: 1 triplet
        vec![
            ie_tag::COUNTRY,
            3 + 3, // country string + 1 triplet
            country_code[0],
            country_code[1],
            b' ',
            1, 13, 20, // ch 1-13, 20 dBm
        ]
    }
}

/// Build VHT Operation IE (tag 192) — 7 bytes total.
pub fn build_vht_oper(chan_width: u8, center_seg0: u8) -> Vec<u8> {
    vec![
        ie_tag::VHT_OPERATION,
        5,           // length
        chan_width,   // 0=20/40, 1=80, 2=160
        center_seg0, // center frequency segment 0
        0,           // center frequency segment 1 (160/80+80 only)
        0xFC, 0xFF,  // VHT Basic MCS Set: NSS 1 MCS 0-7, rest not supported
    ]
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Composite IE builders — full tagged parameter sets for frames
// ═══════════════════════════════════════════════════════════════════════════════

/// AP security mode for beacon/probe response IE building.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApSecurity {
    Open,
    Wpa2Psk,
    Wpa3Sae,
    Wpa2Enterprise,
}

/// Configuration for building beacon/probe response IEs.
#[derive(Debug, Clone)]
pub struct BeaconIeConfig {
    pub ssid: Vec<u8>,
    pub channel: u8,
    pub security: ApSecurity,
    pub hidden_ssid: bool,
    pub country_code: [u8; 2],
}

impl Default for BeaconIeConfig {
    fn default() -> Self {
        Self {
            ssid: b"wifikit".to_vec(),
            channel: 6,
            security: ApSecurity::Open,
            hidden_ssid: false,
            country_code: *b"XX",
        }
    }
}

/// Build all tagged parameters for a beacon or probe response frame.
/// When `is_beacon` is true, includes TIM IE and respects `hidden_ssid`.
pub fn build_beacon_ies(config: &BeaconIeConfig, is_beacon: bool) -> Vec<u8> {
    let is_5ghz = config.channel > 14;
    let mut ies = Vec::with_capacity(256);

    // 1. SSID
    if is_beacon && config.hidden_ssid {
        ies.extend(build_ssid(&[]));
    } else {
        ies.extend(build_ssid(&config.ssid));
    }

    // 2. Supported Rates + Extended Rates
    ies.extend(build_rates(is_5ghz));

    // 3. DS Parameter Set
    ies.extend(build_ds_param(config.channel));

    // 4. TIM — only in beacons
    if is_beacon {
        ies.extend(build_tim(0, 1));
    }

    // 5. Country IE
    ies.extend(build_country(&config.country_code, is_5ghz));

    // 6. RSN IE — for WPA2/WPA3
    match config.security {
        ApSecurity::Wpa2Psk => {
            let rsn = RsnInfo {
                security: Security::Wpa2,
                group_cipher: CipherSuite::Ccmp,
                pairwise_ciphers: vec![CipherSuite::Ccmp],
                akm_suites: vec![AkmSuite::Psk],
                ..Default::default()
            };
            ies.extend(build_rsn(&rsn, None));
        }
        ApSecurity::Wpa3Sae => {
            let rsn = RsnInfo {
                security: Security::Wpa3,
                group_cipher: CipherSuite::Ccmp,
                pairwise_ciphers: vec![CipherSuite::Ccmp],
                akm_suites: vec![AkmSuite::Sae],
                mfp_capable: true,
                mfp_required: true,
                ..Default::default()
            };
            ies.extend(build_rsn(&rsn, None));
        }
        ApSecurity::Wpa2Enterprise => {
            let rsn = RsnInfo {
                security: Security::Wpa2Enterprise,
                group_cipher: CipherSuite::Ccmp,
                pairwise_ciphers: vec![CipherSuite::Ccmp],
                akm_suites: vec![AkmSuite::Ieee8021x],
                ..Default::default()
            };
            ies.extend(build_rsn(&rsn, None));
        }
        ApSecurity::Open => {}
    }

    // 7. HT Capabilities
    ies.extend(build_ht_caps(2));

    // 8. HT Operation
    ies.extend(build_ht_oper(config.channel));

    // 9. Extended Capabilities
    ies.extend(build_ext_caps());

    // 10-12. VHT + HE (5 GHz only)
    if is_5ghz {
        ies.extend(build_vht_caps(2));

        // Calculate center channel for 80 MHz
        let center = match config.channel {
            36..=48 => 42,
            52..=64 => 58,
            100..=112 => 106,
            116..=128 => 122,
            132..=144 => 138,
            149..=161 => 155,
            _ => config.channel,
        };
        ies.extend(build_vht_oper(1, center));

        ies.extend(build_he_caps(2));
    }

    // 13. WMM
    ies.extend(build_wmm());

    ies
}

/// Info about a target AP needed for building association request IEs.
#[derive(Debug, Clone, Default)]
pub struct AssocTarget {
    pub ssid: Vec<u8>,
    pub channel: u8,
    pub ds_channel: u8,
    pub rsn: Option<RsnInfo>,
    pub has_ht: bool,
    pub has_vht: bool,
    pub has_he: bool,
    pub has_wmm: bool,
    pub max_nss: u8,
}

/// Build all tagged parameters for an association request frame.
pub fn build_assoc_ies(target: &AssocTarget) -> Vec<u8> {
    let is_5ghz = target.channel > 14;
    let nss = target.max_nss.clamp(1, 2);
    let mut ies = Vec::with_capacity(256);

    // 1. SSID
    ies.extend(build_ssid(&target.ssid));

    // 2. Supported Rates + Extended Rates
    ies.extend(build_rates(is_5ghz));

    // 3. DS Parameter Set — only for 2.4 GHz
    if !is_5ghz {
        let ch = if target.ds_channel > 0 { target.ds_channel } else { target.channel };
        ies.extend(build_ds_param(ch));
    }

    // 4. RSN IE — mirror target's security
    if let Some(rsn) = &target.rsn {
        ies.extend(build_rsn(rsn, None));
    }

    // 5. HT Capabilities
    if target.has_ht {
        ies.extend(build_ht_caps(nss));
    }

    // 6. Extended Capabilities
    ies.extend(build_ext_caps());

    // 7. VHT Capabilities — 5 GHz only
    if is_5ghz && target.has_vht {
        ies.extend(build_vht_caps(nss));
    }

    // 8. HE Capabilities
    if target.has_he {
        ies.extend(build_he_caps(nss));
    }

    // 9. WMM
    if target.has_wmm {
        ies.extend(build_wmm());
    }

    ies
}

// ═══════════════════════════════════════════════════════════════════════════════
//  IE Iterator — walk tagged parameters from any frame
// ═══════════════════════════════════════════════════════════════════════════════

/// A single raw Information Element record.
#[derive(Debug, Clone)]
pub struct IeRecord {
    /// Tag ID (0-255). For extension elements (tag 255), see `ext_tag`.
    pub tag: u8,
    /// Extension tag ID. Non-zero only when `tag == 255`.
    pub ext_tag: u8,
    /// Raw IE body data (after tag + length bytes, including ext_tag byte for ext elements).
    pub data: Vec<u8>,
}

/// A single parsed Information Element (raw, zero-copy).
#[derive(Debug, Clone)]
pub struct RawIe<'a> {
    pub tag: u8,
    pub data: &'a [u8],
}

/// Iterator over Information Elements in a raw byte buffer.
pub struct IeIterator<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> IeIterator<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for IeIterator<'a> {
    type Item = RawIe<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 2 > self.buf.len() {
            return None;
        }
        let tag = self.buf[self.pos];
        let len = self.buf[self.pos + 1] as usize;
        let data_start = self.pos + 2;
        let data_end = data_start + len;
        if data_end > self.buf.len() {
            return None; // truncated IE
        }
        self.pos = data_end;
        Some(RawIe {
            tag,
            data: &self.buf[data_start..data_end],
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Parsed IE Types — one struct per IE type
// ═══════════════════════════════════════════════════════════════════════════════

/// HT Capabilities (tag 45, 26 bytes body) — 802.11n
#[derive(Debug, Clone, Default)]
pub struct HtCapabilities {
    /// Raw HT Capability Info field (2 bytes LE).
    pub ht_cap_info: u16,
    /// A-MPDU Parameters byte.
    pub ampdu_params: u8,
    /// SM Power Save mode (0=static, 1=dynamic, 3=disabled).
    pub sm_power_save: u8,
    /// Supports 40 MHz channel width.
    pub channel_width_40: bool,
    /// Short GI for 20 MHz.
    pub short_gi_20: bool,
    /// Short GI for 40 MHz.
    pub short_gi_40: bool,
    /// TX STBC supported.
    pub tx_stbc: bool,
    /// RX STBC streams (0=not supported, 1-3 = number of streams).
    pub rx_stbc: u8,
    /// LDPC coding capability.
    pub ldpc: bool,
    /// Max A-MSDU length (0=3839, 1=7935).
    pub max_amsdu_len: u16,
    /// Number of spatial streams (derived from MCS set, 1-4).
    pub spatial_streams: u8,
    /// Raw MCS set bytes (16 bytes).
    pub mcs_set: [u8; 16],
}

/// HT Operation (tag 61, 22 bytes body) — 802.11n
#[derive(Debug, Clone, Default)]
pub struct HtOperation {
    /// Primary channel number.
    pub primary_channel: u8,
    /// Secondary channel offset (0=none, 1=above, 3=below).
    pub secondary_channel_offset: u8,
    /// STA channel width (0=20MHz only, 1=any supported width).
    pub channel_width: u8,
    /// RIFS permitted.
    pub rifs_permitted: bool,
    /// HT protection mode (0=none, 1=nonmember, 2=20MHz, 3=non-HT mixed).
    pub ht_protection: u8,
}

/// VHT Capabilities (tag 191, 12 bytes body) — 802.11ac
#[derive(Debug, Clone, Default)]
pub struct VhtCapabilities {
    /// Raw VHT Capabilities Info field (4 bytes LE).
    pub vht_cap_info: u32,
    /// Max MPDU length (0=3895, 1=7991, 2=11454).
    pub max_mpdu_len: u8,
    /// Supported channel width set (0=no 160/80+80, 1=160, 2=160+80+80).
    pub supported_channel_width: u8,
    /// Short GI for 80 MHz.
    pub short_gi_80: bool,
    /// Short GI for 160 / 80+80 MHz.
    pub short_gi_160: bool,
    /// TX STBC supported.
    pub tx_stbc: bool,
    /// RX STBC streams (0-7).
    pub rx_stbc: u8,
    /// SU Beamformer capable.
    pub su_beamformer: bool,
    /// SU Beamformee capable.
    pub su_beamformee: bool,
    /// MU Beamformer capable.
    pub mu_beamformer: bool,
    /// MU Beamformee capable.
    pub mu_beamformee: bool,
    /// Max A-MPDU Length Exponent (0-7).
    pub max_ampdu_exp: u8,
    /// Number of spatial streams (derived from MCS/NSS map, 1-8).
    pub spatial_streams: u8,
    /// RX VHT-MCS Map (2 bits per NSS, 3=not supported).
    pub rx_mcs_map: u16,
    /// TX VHT-MCS Map.
    pub tx_mcs_map: u16,
}

/// VHT Operation (tag 192, 5 bytes body) — 802.11ac
#[derive(Debug, Clone, Default)]
pub struct VhtOperation {
    /// Channel width (0=20/40, 1=80, 2=160, 3=80+80).
    pub channel_width: u8,
    /// Channel center frequency segment 0 (channel number).
    pub center_freq_seg0: u8,
    /// Channel center frequency segment 1 (for 160/80+80).
    pub center_freq_seg1: u8,
}

/// HE Capabilities (tag 255/ext 35) — 802.11ax
#[derive(Debug, Clone, Default)]
pub struct HeCapabilities {
    /// Raw HE MAC Capabilities (6 bytes).
    pub he_mac_cap: [u8; 6],
    /// Raw HE PHY Capabilities (11 bytes).
    pub he_phy_cap: [u8; 11],
    /// Number of spatial streams (derived from MCS/NSS map, 1-8).
    pub spatial_streams: u8,
    /// SU Beamformer capable.
    pub su_beamformer: bool,
    /// SU Beamformee capable.
    pub su_beamformee: bool,
    /// MU Beamformer capable.
    pub mu_beamformer: bool,
    /// BSS Color support (from PHY cap).
    pub bss_color: bool,
    /// TWT Requester support.
    pub twt_requester: bool,
    /// TWT Responder support.
    pub twt_responder: bool,
    /// OFDMA support (inferred from HE capability presence).
    pub ofdma: bool,
    /// Max A-MPDU Length Exponent.
    pub max_ampdu_exp: u8,
}

/// HE Operation (tag 255/ext 36) — 802.11ax
#[derive(Debug, Clone, Default)]
pub struct HeOperation {
    /// Raw HE Operation Parameters (3 bytes).
    pub he_oper_params: [u8; 3],
    /// BSS Color (0-63).
    pub bss_color: u8,
    /// Default PE Duration (0-7).
    pub default_pe_dur: u8,
    /// TWT Required.
    pub twt_required: bool,
    /// Max BSS Color Change Count.
    pub max_bss_color_change: u8,
}

/// Extended Capabilities (tag 127, up to 10 bytes)
#[derive(Debug, Clone, Default)]
pub struct ExtendedCapabilities {
    /// BSS Transition Management (802.11v) — DoS vector.
    pub bss_transition: bool,
    /// WNM-Sleep Mode — KRACK WNM-Sleep target.
    pub wnm_sleep: bool,
    /// Proxy ARP (Hotspot 2.0).
    pub proxy_arp: bool,
    /// Interworking capability.
    pub interworking: bool,
    /// Traffic Filtering Service.
    pub tfs: bool,
    /// Flexible Multicast Service.
    pub fms: bool,
    /// TIM Broadcast.
    pub tim_broadcast: bool,
    /// BSS Coexistence Management.
    pub bss_coexistence_mgmt: bool,
    /// UTC TSF Offset.
    pub utc_tsf_offset: bool,
    /// TDLS Support.
    pub tdls_support: bool,
    /// TDLS Prohibited.
    pub tdls_prohibited: bool,
    /// Operating Mode Notification.
    pub operating_mode_notification: bool,
    /// Raw bytes (for research).
    pub raw: Vec<u8>,
}

/// BSS Load (tag 11, 5 bytes)
#[derive(Debug, Clone, Default)]
pub struct BssLoad {
    /// Number of associated stations (AP self-report).
    pub station_count: u16,
    /// Channel utilization (0-255, 255 = 100%).
    pub channel_utilization: u8,
    /// Available admission capacity (in 32us/s units).
    pub admission_capacity: u16,
}

/// Country IE (tag 7, variable)
#[derive(Debug, Clone, Default)]
pub struct Country {
    /// Two-letter country code (e.g., b"US", b"BR").
    pub country_code: [u8; 2],
    /// Environment byte (b' ' = any).
    pub environment: u8,
    /// Regulatory triplets: (first_channel, num_channels, max_tx_power_dBm).
    pub regulatory_triplets: Vec<(u8, u8, u8)>,
}

/// Power Constraint (tag 32, 1 byte)
#[derive(Debug, Clone, Default)]
pub struct PowerConstraint {
    /// Local power constraint in dB.
    pub power_constraint_db: u8,
}

/// Parsed Power Capability IE (tag 33).
/// Reports minimum and maximum transmit power capability of the STA.
/// IEEE 802.11-2020 §9.4.2.14
#[derive(Debug, Clone, Copy)]
pub struct PowerCapability {
    /// Minimum transmit power capability (dBm), signed.
    pub min_power_dbm: i8,
    /// Maximum transmit power capability (dBm), signed.
    pub max_power_dbm: i8,
}

/// TIM (tag 5, 4+ bytes)
#[derive(Debug, Clone, Default)]
pub struct Tim {
    /// DTIM Count (beacons until next DTIM).
    pub dtim_count: u8,
    /// DTIM Period (beacons between DTIMs).
    pub dtim_period: u8,
    /// Bitmap Control byte.
    pub bitmap_control: u8,
    /// Partial Virtual Bitmap.
    pub partial_virtual_bitmap: Vec<u8>,
}

/// DS Parameter Set (tag 3, 1 byte)
#[derive(Debug, Clone, Default)]
pub struct DsParam {
    /// Channel number from DS Parameter Set (ground truth).
    pub channel: u8,
}

/// ERP IE (tag 42, 1 byte) — 802.11g protection flags
#[derive(Debug, Clone, Default)]
pub struct Erp {
    /// Non-ERP stations present.
    pub non_erp_present: bool,
    /// CTS-to-self protection needed (legacy b clients present).
    pub use_protection: bool,
    /// Barker (long) preamble mode required.
    pub barker_preamble: bool,
}

/// Mobility Domain (tag 54, 3 bytes) — 802.11r Fast Transition
#[derive(Debug, Clone, Default)]
pub struct MobilityDomain {
    /// Mobility Domain Identifier.
    pub mdid: u16,
    /// FT over DS (Distribution System) allowed.
    pub ft_over_ds: bool,
    /// FT Resource Request Protocol supported.
    pub ft_resource_request: bool,
}

/// RM Enabled Capabilities (tag 70, 5 bytes) — 802.11k Radio Measurement
#[derive(Debug, Clone, Default)]
pub struct RmEnabledCapabilities {
    /// Link Measurement capable.
    pub link_measurement: bool,
    /// Neighbor Report capable.
    pub neighbor_report: bool,
    /// Passive beacon measurement.
    pub beacon_passive: bool,
    /// Active beacon measurement.
    pub beacon_active: bool,
    /// Beacon table measurement.
    pub beacon_table: bool,
    /// LCI measurement capable.
    pub lci_measurement: bool,
    /// FTM Range measurement capable.
    pub ftm_range: bool,
}

/// Channel Switch Announcement (tag 37, 3 bytes)
#[derive(Debug, Clone, Default)]
pub struct Csa {
    /// Switch mode (0=allow TX during switch, 1=prohibit).
    pub mode: u8,
    /// New channel number.
    pub new_channel: u8,
    /// Beacons until switch (0 = switch imminent).
    pub count: u8,
}

/// QoS Capability (tag 46, 1 byte)
#[derive(Debug, Clone, Default)]
pub struct QosInfo {
    /// EDCA Parameter Set Update Count (bits 0-3).
    pub edca_param_set_count: u8,
    /// Q-Ack supported (bit 4).
    pub qack: bool,
    /// Queue Request (bit 5).
    pub queue_request: bool,
    /// TXOP Request (bit 6).
    pub txop_request: bool,
    /// Raw QoS info byte.
    pub raw: u8,
}

/// Interworking IE (tag 107, variable) — Hotspot 2.0 / Passpoint
#[derive(Debug, Clone, Default)]
pub struct Interworking {
    /// Access Network Type (0=private, 1=private+guest, 2=chargeable, etc.).
    pub access_network_type: u8,
    /// Internet access available.
    pub internet: bool,
    /// HESSID (optional 6-byte MAC).
    pub hessid: Option<[u8; 6]>,
}

/// Multiple BSSID (tag 71, variable)
#[derive(Debug, Clone, Default)]
pub struct MultiBssid {
    /// Max BSSID Indicator (2^n = max number of BSSIDs).
    pub max_bssid_indicator: u8,
    /// Number of subelements found.
    pub subelement_count: u8,
}

/// Reduced Neighbor Report (tag 201, variable) — WiFi 6E cross-band discovery
#[derive(Debug, Clone, Default)]
pub struct Rnr {
    /// Number of neighbor APs reported.
    pub neighbor_count: u8,
    /// Per-neighbor TBTT info sets.
    pub neighbors: Vec<RnrNeighbor>,
}

/// A single neighbor entry in a Reduced Neighbor Report.
#[derive(Debug, Clone, Default)]
pub struct RnrNeighbor {
    /// TBTT offset.
    pub tbtt_offset: u8,
    /// BSSID (if present).
    pub bssid: Option<[u8; 6]>,
    /// Short SSID (if present).
    pub short_ssid: Option<u32>,
    /// BSS parameters byte.
    pub bss_params: u8,
}

/// WPS state values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WpsState {
    #[default]
    None,
    NotConfigured,
    Configured,
}

/// WPS Information (parsed from vendor IE OUI 00:50:F2:04)
#[derive(Debug, Clone, Default)]
pub struct WpsInfo {
    /// WPS state (Configured / NotConfigured).
    pub state: WpsState,
    /// AP Setup Locked (anti-brute-force).
    pub locked: bool,
    /// WPS version (0x10=1.0, 0x20=2.0).
    pub version: u8,
    /// Device name string.
    pub device_name: String,
    /// Manufacturer string.
    pub manufacturer: String,
    /// Model name string.
    pub model_name: String,
    /// Model number string.
    pub model_number: String,
    /// Serial number string.
    pub serial_number: String,
    /// Primary device type (8 bytes).
    pub primary_device_type: [u8; 8],
    /// Config methods bitmask.
    pub config_methods: u16,
    /// UUID-E (16 bytes).
    pub uuid: [u8; 16],
}

/// WMM/WME Information (parsed from vendor IE OUI 00:50:F2:02)
#[derive(Debug, Clone, Default)]
pub struct WmmInfo {
    /// WME version.
    pub version: u8,
    /// QoS Info byte.
    pub qos_info: u8,
    /// AC parameters (if present — WMM Parameter Element, subtype 1).
    pub ac_params: Option<WmmAcParams>,
}

/// WMM AC parameter set.
#[derive(Debug, Clone, Default)]
pub struct WmmAcParams {
    /// Per-AC parameters: [BE, BK, VI, VO].
    pub ac: [WmmAcParam; 4],
}

/// Single AC parameters.
#[derive(Debug, Clone, Default)]
pub struct WmmAcParam {
    /// ACI/AIFSN byte.
    pub aci_aifsn: u8,
    /// ECWmin/ECWmax byte.
    pub ecw: u8,
    /// TXOP Limit.
    pub txop_limit: u16,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  IE Parsers — extract structured data from raw IE byte streams
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse RSN IE body (after tag + length) into RsnInfo.
/// Works for both RSN (tag 48) and WPA vendor IE (after OUI+type skipped).
pub fn parse_rsn(data: &[u8]) -> Option<RsnInfo> {
    if data.len() < 10 {
        return None;
    }

    let mut pos = 0;

    // Version (must be 1)
    let version = u16::from_le_bytes([data[pos], data[pos + 1]]);
    if version != 1 {
        return None;
    }
    pos += 2;

    // Group cipher suite (4 bytes: OUI + type)
    if pos + 4 > data.len() {
        return None;
    }
    let group_cipher = CipherSuite::from_suite_type(data[pos + 3]);
    pos += 4;

    // Pairwise cipher suite count + suites
    if pos + 2 > data.len() {
        return None;
    }
    let pw_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let mut pairwise_ciphers = Vec::with_capacity(pw_count);
    for _ in 0..pw_count {
        if pos + 4 > data.len() {
            return None;
        }
        pairwise_ciphers.push(CipherSuite::from_suite_type(data[pos + 3]));
        pos += 4;
    }

    // AKM suite count + suites
    if pos + 2 > data.len() {
        return None;
    }
    let akm_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let mut akm_suites = Vec::with_capacity(akm_count);
    for _ in 0..akm_count {
        if pos + 4 > data.len() {
            return None;
        }
        akm_suites.push(AkmSuite::from_suite_type(data[pos + 3]));
        pos += 4;
    }

    // RSN Capabilities (optional 2 bytes)
    let mut rsn_caps: u16 = 0;
    let mut mfp_capable = false;
    let mut mfp_required = false;
    if pos + 2 <= data.len() {
        rsn_caps = u16::from_le_bytes([data[pos], data[pos + 1]]);
        mfp_capable = rsn_caps & (1 << 7) != 0;
        mfp_required = rsn_caps & (1 << 6) != 0;
        pos += 2;
    }

    // Pre-authentication from RSN caps bit 0
    let pre_auth = rsn_caps & 1 != 0;

    // PMKID count (optional)
    let mut pmkid_count: u16 = 0;
    if pos + 2 <= data.len() {
        pmkid_count = u16::from_le_bytes([data[pos], data[pos + 1]]);
    }

    // Derive security level from primary AKM.
    // RSN IE with no AKM suite is malformed per 802.11-2020 9.4.2.25 —
    // default to WPA2 since RSN presence implies WPA2 family.
    let security = akm_suites
        .first()
        .map(|akm| Security::from_akm(*akm))
        .unwrap_or(Security::Wpa2);

    Some(RsnInfo {
        security,
        group_cipher,
        pairwise_ciphers,
        akm_suites,
        mfp_capable,
        mfp_required,
        rsn_caps,
        pmkid_count,
        pre_auth,
    })
}

/// Parse WPA vendor IE body (00:50:F2:01 prefix already matched, full body passed).
/// Skips the 4-byte OUI+type prefix and then parses as RSN with Microsoft OUI.
fn parse_wpa_ie(data: &[u8]) -> Option<RsnInfo> {
    if data.len() < 8 {
        return None;
    }
    // Skip OUI(3) + type(1) = 4 bytes, then parse same as RSN
    // but WPA uses Microsoft OUI in cipher/AKM selectors
    let body = &data[4..];
    if body.len() < 6 {
        return None;
    }

    let mut pos = 0;

    // Version (must be 1)
    let version = u16::from_le_bytes([body[pos], body[pos + 1]]);
    if version != 1 {
        return None;
    }
    pos += 2;

    // Group cipher suite (4 bytes: OUI + type)
    if pos + 4 > body.len() {
        return None;
    }
    let group_cipher = CipherSuite::from_suite_type(body[pos + 3]);
    pos += 4;

    // Pairwise cipher suite count + suites
    if pos + 2 > body.len() {
        return Some(RsnInfo {
            security: Security::Wpa,
            group_cipher,
            ..Default::default()
        });
    }
    let pw_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    let mut pairwise_ciphers = Vec::with_capacity(pw_count);
    for _ in 0..pw_count {
        if pos + 4 > body.len() {
            break;
        }
        pairwise_ciphers.push(CipherSuite::from_suite_type(body[pos + 3]));
        pos += 4;
    }

    // AKM suite count + suites
    let mut akm_suites = Vec::new();
    if pos + 2 <= body.len() {
        let akm_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..akm_count {
            if pos + 4 > body.len() {
                break;
            }
            akm_suites.push(AkmSuite::from_suite_type(body[pos + 3]));
            pos += 4;
        }
    }

    Some(RsnInfo {
        security: Security::Wpa,
        group_cipher,
        pairwise_ciphers,
        akm_suites,
        mfp_capable: false,
        mfp_required: false,
        rsn_caps: 0,
        pmkid_count: 0,
        pre_auth: false,
    })
}

/// Parse HT Capabilities IE body (26 bytes).
fn parse_ht_capabilities(data: &[u8]) -> Option<HtCapabilities> {
    if data.len() < 2 {
        return None;
    }

    let ht_cap_info = u16::from_le_bytes([data[0], data[1]]);
    let ampdu_params = if data.len() >= 3 { data[2] } else { 0 };

    let mut mcs_set = [0u8; 16];
    if data.len() >= 19 {
        mcs_set.copy_from_slice(&data[3..19]);
    }

    // Count spatial streams from MCS set (bytes 3-6 of body = MCS bitmask bytes 0-3)
    let mut spatial_streams: u8 = 1;
    if data.len() >= 7 {
        if data[4] != 0 { spatial_streams = 2; }
        if data.len() >= 6 && data[5] != 0 { spatial_streams = 3; }
        if data.len() >= 7 && data[6] != 0 { spatial_streams = 4; }
    }

    Some(HtCapabilities {
        ht_cap_info,
        ampdu_params,
        sm_power_save: (ht_cap_info >> 2) as u8 & 0x03,
        channel_width_40: ht_cap_info & (1 << 1) != 0,
        short_gi_20: ht_cap_info & (1 << 8) != 0,
        short_gi_40: ht_cap_info & (1 << 9) != 0,
        tx_stbc: ht_cap_info & (1 << 7) != 0,
        rx_stbc: ((ht_cap_info >> 8) & 0x03) as u8,
        ldpc: ht_cap_info & (1 << 0) != 0,
        max_amsdu_len: if ht_cap_info & (1 << 11) != 0 { 7935 } else { 3839 },
        spatial_streams,
        mcs_set,
    })
}

/// Parse HT Operation IE body (22 bytes).
fn parse_ht_operation(data: &[u8]) -> Option<HtOperation> {
    if data.len() < 2 {
        return None;
    }

    let primary_channel = data[0];
    let info_byte = data[1];

    Some(HtOperation {
        primary_channel,
        secondary_channel_offset: info_byte & 0x03,
        channel_width: (info_byte >> 2) & 0x01,
        rifs_permitted: info_byte & (1 << 3) != 0,
        ht_protection: (info_byte >> 4) & 0x03,
    })
}

/// Parse VHT Capabilities IE body (12 bytes).
fn parse_vht_capabilities(data: &[u8]) -> Option<VhtCapabilities> {
    if data.len() < 4 {
        return None;
    }

    let vht_cap_info = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    let mut rx_mcs_map: u16 = 0xFFFF;
    let mut tx_mcs_map: u16 = 0xFFFF;
    if data.len() >= 8 {
        rx_mcs_map = u16::from_le_bytes([data[4], data[5]]);
    }
    if data.len() >= 12 {
        tx_mcs_map = u16::from_le_bytes([data[8], data[9]]);
    }

    // Count spatial streams from RX MCS map
    let mut spatial_streams: u8 = 0;
    for i in 0..8u8 {
        if (rx_mcs_map >> (i * 2)) & 3 != 3 {
            spatial_streams = i + 1;
        }
    }
    if spatial_streams == 0 {
        spatial_streams = 1;
    }

    Some(VhtCapabilities {
        vht_cap_info,
        max_mpdu_len: (vht_cap_info & 0x03) as u8,
        supported_channel_width: ((vht_cap_info >> 2) & 0x03) as u8,
        short_gi_80: vht_cap_info & (1 << 5) != 0,
        short_gi_160: vht_cap_info & (1 << 6) != 0,
        tx_stbc: vht_cap_info & (1 << 7) != 0,
        rx_stbc: ((vht_cap_info >> 8) & 0x07) as u8,
        su_beamformer: vht_cap_info & (1 << 11) != 0,
        su_beamformee: vht_cap_info & (1 << 12) != 0,
        mu_beamformer: vht_cap_info & (1 << 19) != 0,
        mu_beamformee: vht_cap_info & (1 << 20) != 0,
        max_ampdu_exp: ((vht_cap_info >> 23) & 0x07) as u8,
        spatial_streams,
        rx_mcs_map,
        tx_mcs_map,
    })
}

/// Parse VHT Operation IE body (5 bytes).
fn parse_vht_operation(data: &[u8]) -> Option<VhtOperation> {
    if data.len() < 3 {
        return None;
    }
    Some(VhtOperation {
        channel_width: data[0],
        center_freq_seg0: data[1],
        center_freq_seg1: data[2],
    })
}

/// Parse HE Capabilities IE body (after ext_tag byte already consumed).
/// `data` starts AFTER the ext_id byte (i.e., data[0] is first byte of HE MAC Capabilities).
fn parse_he_capabilities(data: &[u8]) -> Option<HeCapabilities> {
    // Minimum: MAC Caps(6) + PHY Caps(11) + MCS/NSS(4) = 21
    if data.len() < 21 {
        return None;
    }

    let mut he_mac_cap = [0u8; 6];
    he_mac_cap.copy_from_slice(&data[0..6]);

    let mut he_phy_cap = [0u8; 11];
    he_phy_cap.copy_from_slice(&data[6..17]);

    // MCS/NSS map at offset 17 (4+ bytes)
    let mcs_map_rx = if data.len() >= 19 {
        u16::from_le_bytes([data[17], data[18]])
    } else {
        0xFFFF
    };

    // Count spatial streams from RX MCS map
    let mut spatial_streams: u8 = 0;
    for i in 0..8u8 {
        if (mcs_map_rx >> (i * 2)) & 3 != 3 {
            spatial_streams = i + 1;
        }
    }
    if spatial_streams == 0 {
        spatial_streams = 1;
    }

    // PHY capabilities bit parsing
    // Byte 6 (he_phy_cap[0]): bits 1-2 = channel width set
    // Byte 7 (he_phy_cap[1]): bits 3-4 = LDPC, SU PPDU
    // Byte 8 (he_phy_cap[2]): bit 6 = SU Beamformee
    let su_beamformer = he_phy_cap[2] & (1 << 5) != 0;
    let su_beamformee = he_phy_cap[2] & (1 << 6) != 0;
    let mu_beamformer = he_phy_cap[3] & (1 << 2) != 0;

    // TWT from MAC caps
    let twt_requester = he_mac_cap[0] & (1 << 1) != 0;
    let twt_responder = he_mac_cap[0] & (1 << 2) != 0;

    // Max A-MPDU exponent from MAC caps byte 2
    let max_ampdu_exp = (he_mac_cap[2] >> 6) & 0x03;

    Some(HeCapabilities {
        he_mac_cap,
        he_phy_cap,
        spatial_streams,
        su_beamformer,
        su_beamformee,
        mu_beamformer,
        bss_color: true, // HE always supports BSS Color
        twt_requester,
        twt_responder,
        ofdma: true, // HE always implies OFDMA
        max_ampdu_exp,
    })
}

/// Parse HE Operation IE body (after ext_tag byte already consumed).
/// `data` starts AFTER the ext_id byte.
fn parse_he_operation(data: &[u8]) -> Option<HeOperation> {
    // Minimum: HE Operation Parameters(3) + BSS Color Info(1) + Basic HE-MCS/NSS(2) = 6
    if data.len() < 6 {
        return None;
    }

    let mut he_oper_params = [0u8; 3];
    he_oper_params.copy_from_slice(&data[0..3]);

    let default_pe_dur = data[0] & 0x07;
    let twt_required = (data[0] >> 3) & 1 != 0;

    // BSS Color Info is byte 3 (offset 3)
    let bss_color = data[3] & 0x3F;
    let max_bss_color_change = (data[3] >> 6) & 0x01;

    Some(HeOperation {
        he_oper_params,
        bss_color,
        default_pe_dur,
        twt_required,
        max_bss_color_change,
    })
}

/// Parse Extended Capabilities IE body (up to 10 bytes).
fn parse_extended_capabilities(data: &[u8]) -> ExtendedCapabilities {
    let raw = data.to_vec();
    let mut ec = ExtendedCapabilities { raw, ..Default::default() };

    // Octet 0 (index 0)
    if !data.is_empty() {
        ec.bss_coexistence_mgmt = data[0] & (1 << 0) != 0;
        ec.interworking = data[0] & (1 << 7) != 0;
    }

    // Octet 1 (index 1)
    if data.len() >= 2 {
        ec.tdls_support = data[1] & (1 << 5) != 0;
        ec.tdls_prohibited = data[1] & (1 << 6) != 0;
    }

    // Octet 2 (index 2): attack-surface-relevant bits
    if data.len() >= 3 {
        ec.tfs = data[2] & (1 << 0) != 0;
        ec.wnm_sleep = data[2] & (1 << 1) != 0;
        ec.utc_tsf_offset = data[2] & (1 << 2) != 0;
        ec.bss_transition = data[2] & (1 << 3) != 0;
        ec.proxy_arp = data[2] & (1 << 4) != 0;
    }

    // Octet 3 (index 3)
    if data.len() >= 4 {
        ec.fms = data[3] & (1 << 1) != 0;
        ec.tim_broadcast = data[3] & (1 << 2) != 0;
    }

    // Octet 7 (index 7)
    if data.len() >= 8 {
        ec.operating_mode_notification = data[7] & (1 << 0) != 0;
    }

    ec
}

/// Parse BSS Load IE body (5 bytes).
fn parse_bss_load(data: &[u8]) -> Option<BssLoad> {
    if data.len() < 5 {
        return None;
    }
    Some(BssLoad {
        station_count: u16::from_le_bytes([data[0], data[1]]),
        channel_utilization: data[2],
        admission_capacity: u16::from_le_bytes([data[3], data[4]]),
    })
}

/// Parse Country IE body (3+ bytes).
fn parse_country(data: &[u8]) -> Option<Country> {
    if data.len() < 3 {
        return None;
    }

    let country_code = [data[0], data[1]];
    let environment = data[2];

    let mut regulatory_triplets = Vec::new();
    let mut pos = 3;
    while pos + 3 <= data.len() {
        // Only parse regulatory triplets (first_channel < 200)
        if data[pos] < 200 {
            regulatory_triplets.push((data[pos], data[pos + 1], data[pos + 2]));
        }
        pos += 3;
    }

    Some(Country {
        country_code,
        environment,
        regulatory_triplets,
    })
}

/// Parse Power Constraint IE body (1 byte).
fn parse_power_constraint(data: &[u8]) -> Option<PowerConstraint> {
    if data.is_empty() {
        return None;
    }
    Some(PowerConstraint {
        power_constraint_db: data[0],
    })
}

/// Parse Power Capability IE value bytes.
/// Format: Min Power(1) + Max Power(1) = 2 bytes.
fn parse_power_capability(data: &[u8]) -> Option<PowerCapability> {
    if data.len() < 2 {
        return None;
    }
    Some(PowerCapability {
        min_power_dbm: data[0] as i8,
        max_power_dbm: data[1] as i8,
    })
}

/// Parse TIM IE body (4+ bytes).
fn parse_tim(data: &[u8]) -> Option<Tim> {
    if data.len() < 4 {
        return None;
    }
    Some(Tim {
        dtim_count: data[0],
        dtim_period: data[1],
        bitmap_control: data[2],
        partial_virtual_bitmap: data[3..].to_vec(),
    })
}

/// Parse DS Parameter Set IE body (1 byte).
fn parse_ds_param(data: &[u8]) -> Option<DsParam> {
    if data.is_empty() {
        return None;
    }
    Some(DsParam { channel: data[0] })
}

/// Parse ERP IE body (1 byte).
fn parse_erp(data: &[u8]) -> Option<Erp> {
    if data.is_empty() {
        return None;
    }
    Some(Erp {
        non_erp_present: data[0] & (1 << 0) != 0,
        use_protection: data[0] & (1 << 1) != 0,
        barker_preamble: data[0] & (1 << 2) != 0,
    })
}

/// Parse Mobility Domain IE body (3 bytes).
fn parse_mobility_domain(data: &[u8]) -> Option<MobilityDomain> {
    if data.len() < 3 {
        return None;
    }
    Some(MobilityDomain {
        mdid: u16::from_le_bytes([data[0], data[1]]),
        ft_over_ds: data[2] & 0x01 != 0,
        ft_resource_request: data[2] & 0x02 != 0,
    })
}

/// Parse RM Enabled Capabilities IE body (5 bytes).
fn parse_rm_enabled_capabilities(data: &[u8]) -> Option<RmEnabledCapabilities> {
    if data.is_empty() {
        return None;
    }
    Some(RmEnabledCapabilities {
        link_measurement: data[0] & (1 << 0) != 0,
        neighbor_report: data[0] & (1 << 1) != 0,
        beacon_passive: data[0] & (1 << 2) != 0,
        beacon_active: data[0] & (1 << 3) != 0,
        beacon_table: data[0] & (1 << 4) != 0,
        lci_measurement: if data.len() >= 2 { data[1] & (1 << 4) != 0 } else { false },
        ftm_range: if data.len() >= 5 { data[4] & (1 << 2) != 0 } else { false },
    })
}

/// Parse CSA IE body (3 bytes).
fn parse_csa(data: &[u8]) -> Option<Csa> {
    if data.len() < 3 {
        return None;
    }
    Some(Csa {
        mode: data[0],
        new_channel: data[1],
        count: data[2],
    })
}

/// Parse QoS Capability IE body (1 byte).
fn parse_qos_info(data: &[u8]) -> Option<QosInfo> {
    if data.is_empty() {
        return None;
    }
    Some(QosInfo {
        edca_param_set_count: data[0] & 0x0F,
        qack: data[0] & (1 << 4) != 0,
        queue_request: data[0] & (1 << 5) != 0,
        txop_request: data[0] & (1 << 6) != 0,
        raw: data[0],
    })
}

/// Parse Interworking IE body (1-9 bytes).
fn parse_interworking(data: &[u8]) -> Option<Interworking> {
    if data.is_empty() {
        return None;
    }
    let access_network_type = data[0] & 0x0F;
    let internet = (data[0] >> 4) & 1 != 0;
    let hessid = if data.len() >= 7 {
        let mut h = [0u8; 6];
        h.copy_from_slice(&data[1..7]);
        Some(h)
    } else if data.len() >= 3 {
        // Could be 3 bytes (interworking + venue info), no HESSID
        None
    } else {
        None
    };

    Some(Interworking {
        access_network_type,
        internet,
        hessid,
    })
}

/// Parse Multiple BSSID IE body (1+ bytes).
fn parse_multi_bssid(data: &[u8]) -> Option<MultiBssid> {
    if data.is_empty() {
        return None;
    }

    // Count subelements
    let mut count: u8 = 0;
    let mut pos = 1; // skip max_bssid_indicator
    while pos + 2 <= data.len() {
        let sub_len = data[pos + 1] as usize;
        if pos + 2 + sub_len > data.len() {
            break;
        }
        count = count.saturating_add(1);
        pos += 2 + sub_len;
    }

    Some(MultiBssid {
        max_bssid_indicator: data[0],
        subelement_count: count,
    })
}

/// Parse Reduced Neighbor Report IE body (4+ bytes).
fn parse_rnr(data: &[u8]) -> Option<Rnr> {
    if data.len() < 4 {
        return None;
    }

    let mut neighbors = Vec::new();
    let mut pos = 0;

    while pos + 4 <= data.len() {
        // TBTT Information Header (2 bytes)
        let _tbtt_info_hdr_type = data[pos] & 0x03;
        let tbtt_info_count = ((data[pos + 1] >> 4) & 0x0F) + 1;
        let tbtt_info_len = data[pos + 1] & 0x0F;
        pos += 2;

        // Operating Class + Channel (2 bytes)
        if pos + 2 > data.len() {
            break;
        }
        pos += 2; // skip operating class + channel

        // Parse TBTT Information Set entries
        for _ in 0..tbtt_info_count {
            if pos + tbtt_info_len as usize > data.len() {
                break;
            }

            let mut neighbor = RnrNeighbor::default();

            if tbtt_info_len >= 1 {
                neighbor.tbtt_offset = data[pos];
            }
            if tbtt_info_len >= 7 {
                let mut bssid = [0u8; 6];
                bssid.copy_from_slice(&data[pos + 1..pos + 7]);
                neighbor.bssid = Some(bssid);
            }
            if tbtt_info_len >= 11 {
                neighbor.short_ssid = Some(u32::from_le_bytes([
                    data[pos + 7], data[pos + 8], data[pos + 9], data[pos + 10],
                ]));
            }
            if tbtt_info_len >= 12 {
                neighbor.bss_params = data[pos + 11];
            }

            neighbors.push(neighbor);
            pos += tbtt_info_len as usize;
        }
    }

    let neighbor_count = neighbors.len() as u8;
    Some(Rnr {
        neighbor_count,
        neighbors,
    })
}

/// WPS TLV attribute type constants.
mod wps_attr {
    pub const VERSION: u16 = 0x104A;
    pub const STATE: u16 = 0x1044;
    pub const AP_SETUP_LOCKED: u16 = 0x1057;
    pub const DEVICE_NAME: u16 = 0x1011;
    pub const MANUFACTURER: u16 = 0x1021;
    pub const MODEL_NAME: u16 = 0x1023;
    pub const MODEL_NUMBER: u16 = 0x1024;
    pub const SERIAL_NUMBER: u16 = 0x1042;
    pub const PRIMARY_DEVICE_TYPE: u16 = 0x1054;
    pub const CONFIG_METHODS: u16 = 0x1008;
    pub const UUID_E: u16 = 0x1047;
}

/// Parse WPS vendor IE body (after matching OUI 00:50:F2:04).
/// `data` is the full vendor IE body including the 4-byte OUI+type prefix.
fn parse_wps_ie(data: &[u8]) -> Option<WpsInfo> {
    if data.len() < 4 {
        return None;
    }

    let mut wps = WpsInfo::default();
    let mut pos = 4; // skip OUI + type

    while pos + 4 <= data.len() {
        let attr_type = (data[pos] as u16) << 8 | data[pos + 1] as u16;
        let attr_len = ((data[pos + 2] as u16) << 8 | data[pos + 3] as u16) as usize;
        pos += 4;

        if pos + attr_len > data.len() {
            break;
        }

        let attr_data = &data[pos..pos + attr_len];

        match attr_type {
            wps_attr::STATE => {
                if attr_len >= 1 {
                    wps.state = match attr_data[0] {
                        1 => WpsState::NotConfigured,
                        2 => WpsState::Configured,
                        _ => WpsState::None,
                    };
                }
            }
            wps_attr::AP_SETUP_LOCKED => {
                if attr_len >= 1 {
                    wps.locked = attr_data[0] != 0;
                }
            }
            wps_attr::VERSION => {
                if attr_len >= 1 {
                    wps.version = attr_data[0];
                }
            }
            wps_attr::DEVICE_NAME => {
                wps.device_name = String::from_utf8_lossy(attr_data).into_owned();
            }
            wps_attr::MANUFACTURER => {
                wps.manufacturer = String::from_utf8_lossy(attr_data).into_owned();
            }
            wps_attr::MODEL_NAME => {
                wps.model_name = String::from_utf8_lossy(attr_data).into_owned();
            }
            wps_attr::MODEL_NUMBER => {
                wps.model_number = String::from_utf8_lossy(attr_data).into_owned();
            }
            wps_attr::SERIAL_NUMBER => {
                wps.serial_number = String::from_utf8_lossy(attr_data).into_owned();
            }
            wps_attr::PRIMARY_DEVICE_TYPE => {
                if attr_len >= 8 {
                    wps.primary_device_type.copy_from_slice(&attr_data[..8]);
                }
            }
            wps_attr::CONFIG_METHODS => {
                if attr_len >= 2 {
                    wps.config_methods = (attr_data[0] as u16) << 8 | attr_data[1] as u16;
                }
            }
            wps_attr::UUID_E => {
                if attr_len >= 16 {
                    wps.uuid.copy_from_slice(&attr_data[..16]);
                }
            }
            _ => {} // skip unknown attributes
        }

        pos += attr_len;
    }

    Some(wps)
}

/// Parse WMM vendor IE body (after matching OUI 00:50:F2:02).
/// `data` is the full vendor IE body including the 4-byte OUI+type prefix.
fn parse_wmm_ie(data: &[u8]) -> Option<WmmInfo> {
    // OUI(3) + type(1) + subtype(1) + version(1) = 6 minimum
    if data.len() < 6 {
        return None;
    }

    let subtype = data[4];
    let version = data[5];

    let mut wmm = WmmInfo {
        version,
        qos_info: 0,
        ac_params: None,
    };

    match subtype {
        0 => {
            // WMM Information Element
            if data.len() >= 7 {
                wmm.qos_info = data[6];
            }
        }
        1 => {
            // WMM Parameter Element
            if data.len() >= 8 {
                wmm.qos_info = data[6];
                // data[7] is reserved
                // AC params start at offset 8, 4 bytes each, 4 ACs
                if data.len() >= 24 {
                    let mut ac_params = WmmAcParams::default();
                    for i in 0..4 {
                        let base = 8 + i * 4;
                        ac_params.ac[i] = WmmAcParam {
                            aci_aifsn: data[base],
                            ecw: data[base + 1],
                            txop_limit: u16::from_le_bytes([data[base + 2], data[base + 3]]),
                        };
                    }
                    wmm.ac_params = Some(ac_params);
                }
            }
        }
        _ => {} // skip unknown WMM subtypes
    }

    Some(wmm)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Master parse function — extract all IEs from beacon/probe response
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed fields from a beacon/probe response IE stream.
/// Contains both structured parsed types and backward-compatible flat fields.
#[derive(Debug, Clone, Default)]
pub struct ParsedIes {
    // === Structured parsed types ===
    pub rsn: Option<RsnInfo>,
    pub wpa: Option<RsnInfo>,
    pub ht_cap: Option<HtCapabilities>,
    pub ht_oper: Option<HtOperation>,
    pub vht_cap: Option<VhtCapabilities>,
    pub vht_oper: Option<VhtOperation>,
    pub he_cap: Option<HeCapabilities>,
    pub he_oper: Option<HeOperation>,
    pub ext_cap: Option<ExtendedCapabilities>,
    pub bss_load: Option<BssLoad>,
    pub country: Option<Country>,
    pub power_constraint: Option<PowerConstraint>,
    pub power_capability: Option<PowerCapability>,
    pub tim: Option<Tim>,
    pub ds: Option<DsParam>,
    pub erp: Option<Erp>,
    pub mobility_domain: Option<MobilityDomain>,
    pub rm_cap: Option<RmEnabledCapabilities>,
    pub csa: Option<Csa>,
    pub qos: Option<QosInfo>,
    pub interworking_ie: Option<Interworking>,
    pub multi_bssid: Option<MultiBssid>,
    pub rnr: Option<Rnr>,
    pub wps: Option<WpsInfo>,
    pub wmm_ie: Option<WmmInfo>,

    // === Flat/scalar fields (backward compatible + convenience) ===
    pub ssid: Option<String>,
    pub ssid_raw: Vec<u8>,
    pub channel: Option<u8>,
    pub supported_rates: Vec<u8>,
    pub extended_rates: Vec<u8>,
    pub vendor_ouis: Vec<[u8; 3]>,
    pub ie_order: Vec<u8>,
    pub raw_ies: Vec<IeRecord>,

    // === Backward-compatible boolean flags ===
    pub has_ht: bool,
    pub has_vht: bool,
    pub has_he: bool,
    pub has_wmm: bool,
    pub has_wps: bool,
    pub ht_cap_raw: u16,
    pub vht_cap_raw: u32,
    pub max_nss: u8,
    pub country_code: Option<[u8; 2]>,
}

/// OUI for Wi-Fi Alliance (50:6F:9A).
const OUI_WFA: [u8; 3] = [0x50, 0x6F, 0x9A];

/// Parse all IEs from a beacon/probe response tagged parameters section.
pub fn parse_ies(data: &[u8]) -> ParsedIes {
    let mut result = ParsedIes::default();
    result.max_nss = 1;

    for ie in IeIterator::new(data) {
        // Track IE order for fingerprinting
        result.ie_order.push(ie.tag);

        // Build owned IeRecord
        let ext_tag = if ie.tag == ie_tag::EXTENSION && !ie.data.is_empty() {
            ie.data[0]
        } else {
            0
        };
        result.raw_ies.push(IeRecord {
            tag: ie.tag,
            ext_tag,
            data: ie.data.to_vec(),
        });

        match ie.tag {
            ie_tag::SSID => {
                result.ssid_raw = ie.data.to_vec();
                if !ie.data.is_empty() {
                    // Check for all-null hidden SSID
                    let all_null = ie.data.iter().all(|&b| b == 0);
                    if !all_null {
                        result.ssid = String::from_utf8(ie.data.to_vec()).ok();
                    }
                }
            }
            ie_tag::SUPPORTED_RATES => {
                result.supported_rates = ie.data.to_vec();
            }
            ie_tag::DS_PARAMS => {
                if let Some(ds) = parse_ds_param(ie.data) {
                    result.channel = Some(ds.channel);
                    result.ds = Some(ds);
                }
            }
            ie_tag::TIM => {
                result.tim = parse_tim(ie.data);
            }
            ie_tag::COUNTRY => {
                if let Some(c) = parse_country(ie.data) {
                    result.country_code = Some(c.country_code);
                    result.country = Some(c);
                }
            }
            ie_tag::QBSS_LOAD => {
                result.bss_load = parse_bss_load(ie.data);
            }
            ie_tag::POWER_CONSTRAINT => {
                result.power_constraint = parse_power_constraint(ie.data);
            }
            33 => {
                result.power_capability = parse_power_capability(ie.data);
            }
            ie_tag::CSA => {
                result.csa = parse_csa(ie.data);
            }
            ie_tag::ERP => {
                result.erp = parse_erp(ie.data);
            }
            ie_tag::HT_CAPABILITIES => {
                result.has_ht = true;
                if ie.data.len() >= 2 {
                    result.ht_cap_raw = u16::from_le_bytes([ie.data[0], ie.data[1]]);
                }
                if let Some(ht) = parse_ht_capabilities(ie.data) {
                    result.max_nss = result.max_nss.max(ht.spatial_streams);
                    result.ht_cap = Some(ht);
                }
            }
            ie_tag::QOS_CAPABILITY => {
                result.qos = parse_qos_info(ie.data);
            }
            ie_tag::RSN => {
                result.rsn = parse_rsn(ie.data);
            }
            ie_tag::EXTENDED_RATES => {
                result.extended_rates = ie.data.to_vec();
            }
            ie_tag::MOBILITY_DOMAIN => {
                result.mobility_domain = parse_mobility_domain(ie.data);
            }
            ie_tag::HT_OPERATION => {
                result.ht_oper = parse_ht_operation(ie.data);
            }
            ie_tag::RM_ENABLED_CAPABILITIES => {
                result.rm_cap = parse_rm_enabled_capabilities(ie.data);
            }
            ie_tag::MULTI_BSSID => {
                result.multi_bssid = parse_multi_bssid(ie.data);
            }
            ie_tag::INTERWORKING => {
                result.interworking_ie = parse_interworking(ie.data);
            }
            ie_tag::EXTENDED_CAPABILITIES => {
                result.ext_cap = Some(parse_extended_capabilities(ie.data));
            }
            ie_tag::VHT_CAPABILITIES => {
                result.has_vht = true;
                if ie.data.len() >= 4 {
                    result.vht_cap_raw = u32::from_le_bytes([
                        ie.data[0], ie.data[1], ie.data[2], ie.data[3],
                    ]);
                }
                if let Some(vht) = parse_vht_capabilities(ie.data) {
                    result.max_nss = result.max_nss.max(vht.spatial_streams);
                    result.vht_cap = Some(vht);
                }
            }
            ie_tag::VHT_OPERATION => {
                result.vht_oper = parse_vht_operation(ie.data);
            }
            ie_tag::RNR => {
                result.rnr = parse_rnr(ie.data);
            }
            ie_tag::VENDOR_SPECIFIC => {
                if ie.data.len() >= 4 {
                    // Track unique vendor OUIs
                    let oui = [ie.data[0], ie.data[1], ie.data[2]];
                    if !result.vendor_ouis.contains(&oui) {
                        result.vendor_ouis.push(oui);
                    }

                    let is_ms = oui == OUI_MICROSOFT;
                    let is_wfa = oui == OUI_WFA;

                    if is_ms {
                        match ie.data[3] {
                            0x01 => {
                                // WPA IE (Microsoft OUI + type 1)
                                result.wpa = parse_wpa_ie(ie.data);
                            }
                            0x02 => {
                                // WMM/WME
                                result.has_wmm = true;
                                result.wmm_ie = parse_wmm_ie(ie.data);
                            }
                            0x04 => {
                                // WPS
                                result.has_wps = true;
                                result.wps = parse_wps_ie(ie.data);
                            }
                            _ => {} // skip unknown Microsoft vendor subtypes
                        }
                    }

                    if is_wfa {
                        // Wi-Fi Alliance vendor IEs (P2P, HS2.0, etc.)
                        // Tracked via vendor_ouis for now
                    }
                } else if ie.data.len() >= 3 {
                    let oui = [ie.data[0], ie.data[1], ie.data[2]];
                    if !result.vendor_ouis.contains(&oui) {
                        result.vendor_ouis.push(oui);
                    }
                }
            }
            ie_tag::EXTENSION => {
                if !ie.data.is_empty() {
                    match ie.data[0] {
                        ie_ext_id::HE_CAPABILITIES => {
                            result.has_he = true;
                            if ie.data.len() > 1 {
                                if let Some(he) = parse_he_capabilities(&ie.data[1..]) {
                                    result.max_nss = result.max_nss.max(he.spatial_streams);
                                    result.he_cap = Some(he);
                                }
                            }
                        }
                        ie_ext_id::HE_OPERATION => {
                            if ie.data.len() > 1 {
                                result.he_oper = parse_he_operation(&ie.data[1..]);
                            }
                        }
                        _ => {} // skip unknown extension IEs
                    }
                }
            }
            _ => {} // skip unknown IEs
        }
    }

    result
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WiFi Generation Derivation
// ═══════════════════════════════════════════════════════════════════════════════

/// Derive the WiFi generation from parsed IEs.
/// HT -> WiFi 4, VHT -> WiFi 5, HE -> WiFi 6, HE + 6GHz channel -> WiFi 6E.
pub fn derive_wifi_generation(ies: &ParsedIes) -> WifiGeneration {
    if ies.has_he {
        // Check for 6 GHz: channels > 177 or specific 6GHz band indicators
        if let Some(ch) = ies.channel {
            if ch > 177 {
                return WifiGeneration::Wifi6e;
            }
        }
        // Also check HE Operation for 6GHz band info
        if ies.rnr.is_some() {
            // RNR presence alongside HE is a strong 6E indicator but not conclusive
            // True 6E detection requires checking the operating band
        }
        return WifiGeneration::Wifi6;
    }
    if ies.has_vht {
        return WifiGeneration::Wifi5;
    }
    if ies.has_ht {
        return WifiGeneration::Wifi4;
    }
    WifiGeneration::Legacy
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // === Builder tests ===

    #[test]
    fn test_build_ssid() {
        let ie = build_ssid(b"TestNet");
        assert_eq!(ie[0], 0); // tag
        assert_eq!(ie[1], 7); // length
        assert_eq!(&ie[2..], b"TestNet");
    }

    #[test]
    fn test_build_ssid_empty() {
        let ie = build_ssid(&[]);
        assert_eq!(ie, vec![0, 0]);
    }

    #[test]
    fn test_build_rates_24ghz() {
        let ie = build_rates(false);
        assert_eq!(ie[0], 1);  // tag: Supported Rates
        assert_eq!(ie[1], 8);  // 8 rates
        assert_eq!(ie[10], 50); // tag: Extended Supported Rates
        assert_eq!(ie[11], 4);  // 4 rates
        assert_eq!(ie.len(), 2 + 8 + 2 + 4);
    }

    #[test]
    fn test_build_rates_5ghz() {
        let ie = build_rates(true);
        assert_eq!(ie[0], 1);  // tag
        assert_eq!(ie[1], 8);  // 8 rates
        assert_eq!(ie.len(), 10); // 2 + 8
    }

    #[test]
    fn test_build_ds_param() {
        let ie = build_ds_param(6);
        assert_eq!(ie, vec![3, 1, 6]);
    }

    #[test]
    fn test_build_rsn_wpa2_psk() {
        let rsn = RsnInfo {
            security: Security::Wpa2,
            group_cipher: CipherSuite::Ccmp,
            pairwise_ciphers: vec![CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::Psk],
            ..Default::default()
        };
        let ie = build_rsn(&rsn, None);
        assert_eq!(ie[0], 48);  // RSN tag
        assert_eq!(ie[2], 1);
        assert_eq!(ie[3], 0);
        assert_eq!(&ie[4..7], &OUI_IEEE);
        assert_eq!(ie[7], 4); // CCMP
        assert_eq!(ie[8], 1);
        assert_eq!(ie[9], 0);
        assert_eq!(ie[13], 4);
        assert_eq!(ie[14], 1);
        assert_eq!(ie[15], 0);
        assert_eq!(ie[19], 2);
    }

    #[test]
    fn test_build_rsn_wpa3_sae() {
        let rsn = RsnInfo {
            security: Security::Wpa3,
            group_cipher: CipherSuite::Ccmp,
            pairwise_ciphers: vec![CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::Sae],
            mfp_capable: true,
            mfp_required: true,
            ..Default::default()
        };
        let ie = build_rsn(&rsn, None);
        let caps_offset = ie.len() - 2;
        let rsn_caps = u16::from_le_bytes([ie[caps_offset], ie[caps_offset + 1]]);
        assert!(rsn_caps & (1 << 7) != 0, "MFP capable not set");
        assert!(rsn_caps & (1 << 6) != 0, "MFP required not set");
    }

    #[test]
    fn test_build_rsn_with_pmkid() {
        let rsn = RsnInfo {
            group_cipher: CipherSuite::Ccmp,
            pairwise_ciphers: vec![CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::Psk],
            ..Default::default()
        };
        let pmkid = [0xAA; 16];
        let ie = build_rsn(&rsn, Some(&pmkid));
        let len = ie.len();
        assert_eq!(ie[len - 18], 1);
        assert_eq!(ie[len - 17], 0);
        assert_eq!(&ie[len - 16..], &[0xAA; 16]);
    }

    #[test]
    fn test_build_rsn_multi_suite() {
        let rsn = RsnInfo {
            group_cipher: CipherSuite::Tkip,
            pairwise_ciphers: vec![CipherSuite::Ccmp, CipherSuite::Tkip],
            akm_suites: vec![AkmSuite::Psk, AkmSuite::PskSha256],
            ..Default::default()
        };
        let ie = build_rsn(&rsn, None);
        assert_eq!(ie[8], 2);
        let akm_count_offset = 8 + 2 + (4 * 2);
        assert_eq!(ie[akm_count_offset], 2);
    }

    #[test]
    fn test_build_ht_caps_size() {
        let ie = build_ht_caps(2);
        assert_eq!(ie.len(), 28);
        assert_eq!(ie[0], 45);
        assert_eq!(ie[1], 26);
    }

    #[test]
    fn test_build_ht_caps_nss() {
        let ie1 = build_ht_caps(1);
        assert_eq!(ie1[5], 0xFF);
        assert_eq!(ie1[6], 0x00);

        let ie2 = build_ht_caps(2);
        assert_eq!(ie2[5], 0xFF);
        assert_eq!(ie2[6], 0xFF);
    }

    #[test]
    fn test_build_vht_caps_size() {
        let ie = build_vht_caps(2);
        assert_eq!(ie.len(), 14);
        assert_eq!(ie[0], 191);
        assert_eq!(ie[1], 12);
    }

    #[test]
    fn test_build_he_caps_size() {
        let ie = build_he_caps(2);
        assert_eq!(ie.len(), 24);
        assert_eq!(ie[0], 255);
        assert_eq!(ie[1], 22);
        assert_eq!(ie[2], 35);
    }

    #[test]
    fn test_build_wmm() {
        let ie = build_wmm();
        assert_eq!(ie[0], 221);
        assert_eq!(ie[1], 7);
        assert_eq!(&ie[2..5], &[0x00, 0x50, 0xF2]);
        assert_eq!(ie[5], 0x02);
    }

    #[test]
    fn test_build_tim() {
        let ie = build_tim(0, 3);
        assert_eq!(ie[0], 5);
        assert_eq!(ie[1], 4);
        assert_eq!(ie[2], 0);
        assert_eq!(ie[3], 3);
    }

    #[test]
    fn test_build_country_24ghz() {
        let ie = build_country(b"US", false);
        assert_eq!(ie[0], 7);
        assert_eq!(ie[2], b'U');
        assert_eq!(ie[3], b'S');
        assert_eq!(ie[5], 1);
        assert_eq!(ie[6], 13);
    }

    #[test]
    fn test_build_country_5ghz() {
        let ie = build_country(b"BR", true);
        assert_eq!(ie[0], 7);
        assert_eq!(ie[2], b'B');
        assert_eq!(ie[3], b'R');
        assert_eq!(ie[5], 36);
        assert_eq!(ie[8], 52);
        assert_eq!(ie[11], 100);
        assert_eq!(ie[14], 149);
    }

    #[test]
    fn test_build_vht_oper() {
        let ie = build_vht_oper(1, 42);
        assert_eq!(ie[0], 192);
        assert_eq!(ie[2], 1);
        assert_eq!(ie[3], 42);
    }

    #[test]
    fn test_build_beacon_ies_open() {
        let config = BeaconIeConfig {
            ssid: b"OpenNet".to_vec(),
            channel: 6,
            security: ApSecurity::Open,
            ..Default::default()
        };
        let ies = build_beacon_ies(&config, true);
        assert_eq!(ies[0], 0);
        assert_eq!(ies[1], 7);
        assert!(ies.len() > 50);
    }

    #[test]
    fn test_build_beacon_ies_hidden() {
        let config = BeaconIeConfig {
            ssid: b"HiddenNet".to_vec(),
            hidden_ssid: true,
            ..Default::default()
        };
        let beacon_ies = build_beacon_ies(&config, true);
        assert_eq!(beacon_ies[0], 0);
        assert_eq!(beacon_ies[1], 0);

        let probe_ies = build_beacon_ies(&config, false);
        assert_eq!(probe_ies[0], 0);
        assert_eq!(probe_ies[1], 9);
    }

    #[test]
    fn test_build_beacon_ies_5ghz_has_vht_he() {
        let config = BeaconIeConfig {
            ssid: b"WiFi5".to_vec(),
            channel: 36,
            ..Default::default()
        };
        let ies = build_beacon_ies(&config, true);
        let parsed = parse_ies(&ies);
        assert!(parsed.has_ht);
        assert!(parsed.has_vht);
        assert!(parsed.has_he);
    }

    #[test]
    fn test_build_assoc_ies() {
        let target = AssocTarget {
            ssid: b"TestAP".to_vec(),
            channel: 36,
            has_ht: true,
            has_vht: true,
            has_he: true,
            has_wmm: true,
            max_nss: 2,
            rsn: Some(RsnInfo {
                group_cipher: CipherSuite::Ccmp,
                pairwise_ciphers: vec![CipherSuite::Ccmp],
                akm_suites: vec![AkmSuite::Psk],
                ..Default::default()
            }),
            ..Default::default()
        };
        let ies = build_assoc_ies(&target);
        let parsed = parse_ies(&ies);
        assert_eq!(parsed.ssid.as_deref(), Some("TestAP"));
        assert!(parsed.rsn.is_some());
        assert!(parsed.has_ht);
        assert!(parsed.has_vht);
        assert!(parsed.has_he);
        assert!(parsed.has_wmm);
    }

    // === Iterator tests ===

    #[test]
    fn test_ie_iterator() {
        let data = [0, 2, b'H', b'i', 3, 1, 6];
        let ies: Vec<_> = IeIterator::new(&data).collect();
        assert_eq!(ies.len(), 2);
        assert_eq!(ies[0].tag, 0);
        assert_eq!(ies[0].data, b"Hi");
        assert_eq!(ies[1].tag, 3);
        assert_eq!(ies[1].data, &[6]);
    }

    #[test]
    fn test_ie_iterator_truncated() {
        let data = [0, 10, 1, 2, 3];
        let ies: Vec<_> = IeIterator::new(&data).collect();
        assert_eq!(ies.len(), 0);
    }

    #[test]
    fn test_ie_iterator_empty() {
        let ies: Vec<_> = IeIterator::new(&[]).collect();
        assert_eq!(ies.len(), 0);
    }

    #[test]
    fn test_ie_iterator_single_byte() {
        let ies: Vec<_> = IeIterator::new(&[0]).collect();
        assert_eq!(ies.len(), 0);
    }

    // === RSN parser tests ===

    #[test]
    fn test_parse_rsn_basic() {
        let rsn = RsnInfo {
            group_cipher: CipherSuite::Ccmp,
            pairwise_ciphers: vec![CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::Psk],
            mfp_capable: true,
            ..Default::default()
        };
        let ie = build_rsn(&rsn, None);
        let parsed = parse_rsn(&ie[2..]).unwrap();
        assert_eq!(parsed.group_cipher, CipherSuite::Ccmp);
        assert_eq!(parsed.pairwise_ciphers, vec![CipherSuite::Ccmp]);
        assert_eq!(parsed.akm_suites, vec![AkmSuite::Psk]);
        assert!(parsed.mfp_capable);
        assert!(!parsed.mfp_required);
    }

    #[test]
    fn test_parse_rsn_roundtrip_multi() {
        let original = RsnInfo {
            group_cipher: CipherSuite::Tkip,
            pairwise_ciphers: vec![CipherSuite::Ccmp, CipherSuite::Tkip],
            akm_suites: vec![AkmSuite::Psk, AkmSuite::Sae],
            mfp_capable: true,
            mfp_required: true,
            ..Default::default()
        };
        let ie = build_rsn(&original, None);
        let parsed = parse_rsn(&ie[2..]).unwrap();
        assert_eq!(parsed.group_cipher, CipherSuite::Tkip);
        assert_eq!(parsed.pairwise_ciphers, vec![CipherSuite::Ccmp, CipherSuite::Tkip]);
        assert_eq!(parsed.akm_suites, vec![AkmSuite::Psk, AkmSuite::Sae]);
        assert!(parsed.mfp_capable);
        assert!(parsed.mfp_required);
    }

    #[test]
    fn test_parse_rsn_too_short() {
        assert!(parse_rsn(&[1, 0]).is_none());
        assert!(parse_rsn(&[]).is_none());
    }

    #[test]
    fn test_parse_rsn_bad_version() {
        // Version 2 (invalid)
        let data = [2, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4];
        assert!(parse_rsn(&data).is_none());
    }

    // === WPA IE parser tests ===

    #[test]
    fn test_parse_wpa_ie() {
        // WPA IE: OUI(00:50:F2) + Type(01) + Version(1) + GroupCipher(TKIP) + PW count(1) + PW(TKIP) + AKM count(1) + AKM(PSK)
        let data = [
            0x00, 0x50, 0xF2, 0x01, // OUI + type
            0x01, 0x00,             // version 1
            0x00, 0x50, 0xF2, 0x02, // group cipher: TKIP
            0x01, 0x00,             // pairwise count: 1
            0x00, 0x50, 0xF2, 0x02, // pairwise: TKIP
            0x01, 0x00,             // AKM count: 1
            0x00, 0x50, 0xF2, 0x02, // AKM: PSK
        ];
        let parsed = parse_wpa_ie(&data).unwrap();
        assert_eq!(parsed.security, Security::Wpa);
        assert_eq!(parsed.group_cipher, CipherSuite::Tkip);
        assert_eq!(parsed.pairwise_ciphers, vec![CipherSuite::Tkip]);
        assert_eq!(parsed.akm_suites, vec![AkmSuite::Psk]);
    }

    // === HT Capabilities parser tests ===

    #[test]
    fn test_parse_ht_capabilities() {
        let ie = build_ht_caps(2);
        // Parse the body (skip tag + length)
        let parsed = parse_ht_capabilities(&ie[2..]).unwrap();
        assert!(parsed.ldpc);
        assert!(parsed.channel_width_40);
        assert!(parsed.short_gi_20);
        assert!(parsed.short_gi_40);
        assert_eq!(parsed.sm_power_save, 3); // disabled
        assert_eq!(parsed.spatial_streams, 2);
        assert_eq!(parsed.ht_cap_info & (1 << 0), 1); // LDPC
        assert_eq!(parsed.ht_cap_info & (1 << 1), 2); // 40MHz
    }

    #[test]
    fn test_parse_ht_capabilities_1ss() {
        let ie = build_ht_caps(1);
        let parsed = parse_ht_capabilities(&ie[2..]).unwrap();
        assert_eq!(parsed.spatial_streams, 1);
    }

    #[test]
    fn test_parse_ht_capabilities_too_short() {
        assert!(parse_ht_capabilities(&[0]).is_none());
        assert!(parse_ht_capabilities(&[]).is_none());
    }

    // === HT Operation parser tests ===

    #[test]
    fn test_parse_ht_operation() {
        let ie = build_ht_oper(11);
        let parsed = parse_ht_operation(&ie[2..]).unwrap();
        assert_eq!(parsed.primary_channel, 11);
        assert_eq!(parsed.secondary_channel_offset, 0);
    }

    #[test]
    fn test_parse_ht_operation_with_secondary() {
        // Manual HT Operation with secondary channel above
        let mut data = [0u8; 22];
        data[0] = 36; // primary channel
        data[1] = 0x01 | (1 << 2); // secondary above + STA channel width any
        let parsed = parse_ht_operation(&data).unwrap();
        assert_eq!(parsed.primary_channel, 36);
        assert_eq!(parsed.secondary_channel_offset, 1);
        assert_eq!(parsed.channel_width, 1);
    }

    // === VHT Capabilities parser tests ===

    #[test]
    fn test_parse_vht_capabilities() {
        let ie = build_vht_caps(2);
        let parsed = parse_vht_capabilities(&ie[2..]).unwrap();
        assert!(parsed.short_gi_80);
        // The builder sets bit 11 which is SU Beamformer per 802.11ac spec
        assert!(parsed.su_beamformer);
        assert_eq!(parsed.spatial_streams, 2);
        assert_eq!(parsed.max_mpdu_len, 1); // bit 0 set = 7991
    }

    #[test]
    fn test_parse_vht_capabilities_1ss() {
        let ie = build_vht_caps(1);
        let parsed = parse_vht_capabilities(&ie[2..]).unwrap();
        assert_eq!(parsed.spatial_streams, 1);
    }

    #[test]
    fn test_parse_vht_capabilities_too_short() {
        assert!(parse_vht_capabilities(&[0, 0, 0]).is_none());
    }

    // === VHT Operation parser tests ===

    #[test]
    fn test_parse_vht_operation() {
        let ie = build_vht_oper(1, 42);
        let parsed = parse_vht_operation(&ie[2..]).unwrap();
        assert_eq!(parsed.channel_width, 1);
        assert_eq!(parsed.center_freq_seg0, 42);
        assert_eq!(parsed.center_freq_seg1, 0);
    }

    // === HE Capabilities parser tests ===

    #[test]
    fn test_parse_he_capabilities() {
        let ie = build_he_caps(2);
        // Body starts after tag(1) + len(1) + ext_id(1)
        let parsed = parse_he_capabilities(&ie[3..]).unwrap();
        assert!(parsed.ofdma);
        assert!(parsed.bss_color);
        assert!(parsed.spatial_streams >= 1);
    }

    #[test]
    fn test_parse_he_capabilities_too_short() {
        assert!(parse_he_capabilities(&[0; 5]).is_none());
    }

    // === HE Operation parser tests ===

    #[test]
    fn test_parse_he_operation() {
        // Construct minimal HE Operation body (after ext_id):
        // HE Oper Params(3) + BSS Color Info(1) + Basic HE-MCS(2) = 6 bytes
        let data = [
            0x05, 0x00, 0x00, // HE Oper Params: PE dur=5, TWT not required
            0x1A,             // BSS Color Info: color=26
            0xFC, 0xFF,       // Basic HE-MCS/NSS Set
        ];
        let parsed = parse_he_operation(&data).unwrap();
        assert_eq!(parsed.default_pe_dur, 5);
        assert!(!parsed.twt_required);
        assert_eq!(parsed.bss_color, 26);
    }

    #[test]
    fn test_parse_he_operation_twt_required() {
        let data = [
            0x0D, 0x00, 0x00, // PE dur=5, TWT required (bit 3 set)
            0x3F,             // BSS Color = 63
            0xFC, 0xFF,
        ];
        let parsed = parse_he_operation(&data).unwrap();
        assert!(parsed.twt_required);
        assert_eq!(parsed.bss_color, 63);
    }

    // === Extended Capabilities parser tests ===

    #[test]
    fn test_parse_extended_capabilities() {
        let ie = build_ext_caps();
        let parsed = parse_extended_capabilities(&ie[2..]);
        assert!(parsed.bss_transition); // bit 3 of octet 2
        assert!(parsed.operating_mode_notification); // bit 0 of octet 7
    }

    #[test]
    fn test_parse_extended_capabilities_attack_surface() {
        // Octet 2: TFS(0), WNM-Sleep(1), UTC(2), BSS Trans(3), Proxy ARP(4)
        // Octet 3: FMS(1), TIM Broadcast(2)
        let data = [0x00, 0x00, 0x1F, 0x06, 0x00, 0x00, 0x00, 0x00];
        let parsed = parse_extended_capabilities(&data);
        assert!(parsed.tfs);
        assert!(parsed.wnm_sleep);
        assert!(parsed.utc_tsf_offset);
        assert!(parsed.bss_transition);
        assert!(parsed.proxy_arp);
        assert!(parsed.fms);
        assert!(parsed.tim_broadcast);
    }

    // === BSS Load parser tests ===

    #[test]
    fn test_parse_bss_load() {
        let data = [0x15, 0x00, 0x80, 0xE8, 0x03]; // 21 stations, 50% util, capacity 1000
        let parsed = parse_bss_load(&data).unwrap();
        assert_eq!(parsed.station_count, 21);
        assert_eq!(parsed.channel_utilization, 128);
        assert_eq!(parsed.admission_capacity, 1000);
    }

    #[test]
    fn test_parse_bss_load_too_short() {
        assert!(parse_bss_load(&[0, 0]).is_none());
    }

    // === Country IE parser tests ===

    #[test]
    fn test_parse_country() {
        let ie = build_country(b"US", false);
        let parsed = parse_country(&ie[2..]).unwrap();
        assert_eq!(parsed.country_code, *b"US");
        assert_eq!(parsed.environment, b' ');
        assert_eq!(parsed.regulatory_triplets.len(), 1);
        assert_eq!(parsed.regulatory_triplets[0], (1, 13, 20));
    }

    #[test]
    fn test_parse_country_5ghz() {
        let ie = build_country(b"BR", true);
        let parsed = parse_country(&ie[2..]).unwrap();
        assert_eq!(parsed.country_code, *b"BR");
        assert_eq!(parsed.regulatory_triplets.len(), 4);
        assert_eq!(parsed.regulatory_triplets[0].0, 36); // UNII-1
        assert_eq!(parsed.regulatory_triplets[3].0, 149); // UNII-3
    }

    // === Power Constraint parser tests ===

    #[test]
    fn test_parse_power_constraint() {
        let parsed = parse_power_constraint(&[3]).unwrap();
        assert_eq!(parsed.power_constraint_db, 3);
    }

    // === Power Capability parser tests ===

    #[test]
    fn test_parse_power_capability() {
        // min=-10 dBm (0xF6), max=20 dBm (0x14)
        let parsed = parse_power_capability(&[0xF6, 0x14]).unwrap();
        assert_eq!(parsed.min_power_dbm, -10);
        assert_eq!(parsed.max_power_dbm, 20);
    }

    #[test]
    fn test_parse_power_capability_too_short() {
        assert!(parse_power_capability(&[0x05]).is_none());
        assert!(parse_power_capability(&[]).is_none());
    }

    // === TIM parser tests ===

    #[test]
    fn test_parse_tim() {
        let ie = build_tim(2, 3);
        let parsed = parse_tim(&ie[2..]).unwrap();
        assert_eq!(parsed.dtim_count, 2);
        assert_eq!(parsed.dtim_period, 3);
        assert_eq!(parsed.bitmap_control, 0);
    }

    // === DS Parameter Set parser tests ===

    #[test]
    fn test_parse_ds_param() {
        let parsed = parse_ds_param(&[11]).unwrap();
        assert_eq!(parsed.channel, 11);
    }

    // === ERP parser tests ===

    #[test]
    fn test_parse_erp() {
        // Non-ERP present + Use protection
        let parsed = parse_erp(&[0x03]).unwrap();
        assert!(parsed.non_erp_present);
        assert!(parsed.use_protection);
        assert!(!parsed.barker_preamble);
    }

    #[test]
    fn test_parse_erp_barker() {
        let parsed = parse_erp(&[0x04]).unwrap();
        assert!(!parsed.non_erp_present);
        assert!(!parsed.use_protection);
        assert!(parsed.barker_preamble);
    }

    // === Mobility Domain parser tests ===

    #[test]
    fn test_parse_mobility_domain() {
        // MDID=0x1234, FT over DS=true, resource request=false
        let data = [0x34, 0x12, 0x01];
        let parsed = parse_mobility_domain(&data).unwrap();
        assert_eq!(parsed.mdid, 0x1234);
        assert!(parsed.ft_over_ds);
        assert!(!parsed.ft_resource_request);
    }

    // === RM Enabled Capabilities parser tests ===

    #[test]
    fn test_parse_rm_enabled_capabilities() {
        // Link meas + neighbor report + beacon passive + active + table
        let data = [0x1F, 0x00, 0x00, 0x00, 0x00];
        let parsed = parse_rm_enabled_capabilities(&data).unwrap();
        assert!(parsed.link_measurement);
        assert!(parsed.neighbor_report);
        assert!(parsed.beacon_passive);
        assert!(parsed.beacon_active);
        assert!(parsed.beacon_table);
    }

    // === CSA parser tests ===

    #[test]
    fn test_parse_csa() {
        let data = [1, 36, 5]; // prohibit TX, switch to ch 36, 5 beacons left
        let parsed = parse_csa(&data).unwrap();
        assert_eq!(parsed.mode, 1);
        assert_eq!(parsed.new_channel, 36);
        assert_eq!(parsed.count, 5);
    }

    // === QoS Capability parser tests ===

    #[test]
    fn test_parse_qos_info() {
        let parsed = parse_qos_info(&[0x35]).unwrap();
        assert_eq!(parsed.edca_param_set_count, 5);
        assert!(parsed.queue_request);
        assert_eq!(parsed.raw, 0x35);
    }

    // === Interworking parser tests ===

    #[test]
    fn test_parse_interworking() {
        // Access network type=2 (chargeable), internet=true
        let data = [0x12];
        let parsed = parse_interworking(&data).unwrap();
        assert_eq!(parsed.access_network_type, 2);
        assert!(parsed.internet);
        assert!(parsed.hessid.is_none());
    }

    #[test]
    fn test_parse_interworking_with_hessid() {
        let data = [0x12, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let parsed = parse_interworking(&data).unwrap();
        assert!(parsed.internet);
        assert_eq!(parsed.hessid, Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }

    // === Multiple BSSID parser tests ===

    #[test]
    fn test_parse_multi_bssid() {
        // Max BSSID indicator=3 (2^3=8 BSSIDs), one subelement
        let data = [0x03, 0x00, 0x02, 0xAA, 0xBB]; // sub: tag=0, len=2, data
        let parsed = parse_multi_bssid(&data).unwrap();
        assert_eq!(parsed.max_bssid_indicator, 3);
        assert_eq!(parsed.subelement_count, 1);
    }

    // === RNR parser tests ===

    #[test]
    fn test_parse_rnr() {
        // TBTT Info Header: type=0, count=0 (means 1), len=1
        // Operating Class=131, Channel=5
        // TBTT Info: offset=0xFF
        let data = [
            0x00, 0x01, // header: count=0(+1=1), len=1
            131, 5,     // op class, channel
            0xFF,       // tbtt offset
        ];
        let parsed = parse_rnr(&data).unwrap();
        assert_eq!(parsed.neighbor_count, 1);
        assert_eq!(parsed.neighbors[0].tbtt_offset, 0xFF);
    }

    // === WPS parser tests ===

    #[test]
    fn test_parse_wps_ie() {
        let mut data = vec![
            0x00, 0x50, 0xF2, 0x04, // OUI + WPS type
        ];
        // WPS State = Configured (0x1044, len=1, val=2)
        data.extend_from_slice(&[0x10, 0x44, 0x00, 0x01, 0x02]);
        // Version = 2.0 (0x104A, len=1, val=0x20)
        data.extend_from_slice(&[0x10, 0x4A, 0x00, 0x01, 0x20]);
        // Device Name = "TestAP" (0x1011, len=6)
        data.extend_from_slice(&[0x10, 0x11, 0x00, 0x06]);
        data.extend_from_slice(b"TestAP");
        // AP Setup Locked = true (0x1057, len=1, val=1)
        data.extend_from_slice(&[0x10, 0x57, 0x00, 0x01, 0x01]);

        let parsed = parse_wps_ie(&data).unwrap();
        assert_eq!(parsed.state, WpsState::Configured);
        assert_eq!(parsed.version, 0x20);
        assert_eq!(parsed.device_name, "TestAP");
        assert!(parsed.locked);
    }

    #[test]
    fn test_parse_wps_ie_not_configured() {
        let mut data = vec![0x00, 0x50, 0xF2, 0x04];
        data.extend_from_slice(&[0x10, 0x44, 0x00, 0x01, 0x01]); // state=1 (not configured)
        let parsed = parse_wps_ie(&data).unwrap();
        assert_eq!(parsed.state, WpsState::NotConfigured);
    }

    // === WMM parser tests ===

    #[test]
    fn test_parse_wmm_ie_info() {
        let ie = build_wmm(); // subtype=0 (info element)
        let parsed = parse_wmm_ie(&ie[2..]).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.qos_info, 0);
        assert!(parsed.ac_params.is_none());
    }

    #[test]
    fn test_parse_wmm_ie_param() {
        // WMM Parameter Element: OUI(3) + type(1) + subtype(1=param) + version(1) + qos_info(1) + reserved(1) + 4 AC params * 4 bytes
        let mut data = vec![
            0x00, 0x50, 0xF2, 0x02, // OUI + WMM type
            0x01, // subtype: Parameter Element
            0x01, // version
            0x80, // QoS info
            0x00, // reserved
        ];
        // 4 AC params, each 4 bytes (aci_aifsn, ecw, txop_limit LE)
        for i in 0..4u8 {
            data.extend_from_slice(&[i | 0x60, 0x43, 0x00, 0x00]);
        }
        let parsed = parse_wmm_ie(&data).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.qos_info, 0x80);
        assert!(parsed.ac_params.is_some());
        let ac = parsed.ac_params.unwrap();
        assert_eq!(ac.ac[0].aci_aifsn, 0x60);
    }

    // === SSID parsing tests ===

    #[test]
    fn test_parse_ssid_hidden_zero_length() {
        let data = [0, 0]; // SSID IE, length 0
        let parsed = parse_ies(&data);
        assert!(parsed.ssid.is_none());
        assert!(parsed.ssid_raw.is_empty());
    }

    #[test]
    fn test_parse_ssid_hidden_null_filled() {
        let data = [0, 5, 0, 0, 0, 0, 0]; // SSID IE, 5 null bytes
        let parsed = parse_ies(&data);
        assert!(parsed.ssid.is_none()); // null-filled treated as hidden
    }

    #[test]
    fn test_parse_ssid_normal() {
        let data = [0, 4, b'T', b'e', b's', b't'];
        let parsed = parse_ies(&data);
        assert_eq!(parsed.ssid.as_deref(), Some("Test"));
    }

    // === Rates parsing tests ===

    #[test]
    fn test_parse_rates() {
        let mut data = Vec::new();
        // Supported Rates IE
        data.extend_from_slice(&[1, 4, 0x82, 0x84, 0x0C, 0x12]);
        // Extended Rates IE
        data.extend_from_slice(&[50, 2, 0x48, 0x6C]);
        let parsed = parse_ies(&data);
        assert_eq!(parsed.supported_rates, vec![0x82, 0x84, 0x0C, 0x12]);
        assert_eq!(parsed.extended_rates, vec![0x48, 0x6C]);
    }

    // === WiFi generation derivation tests ===

    #[test]
    fn test_derive_wifi_generation_legacy() {
        let ies = ParsedIes::default();
        assert_eq!(derive_wifi_generation(&ies), WifiGeneration::Legacy);
    }

    #[test]
    fn test_derive_wifi_generation_wifi4() {
        let ies = ParsedIes { has_ht: true, ..Default::default() };
        assert_eq!(derive_wifi_generation(&ies), WifiGeneration::Wifi4);
    }

    #[test]
    fn test_derive_wifi_generation_wifi5() {
        let ies = ParsedIes { has_ht: true, has_vht: true, ..Default::default() };
        assert_eq!(derive_wifi_generation(&ies), WifiGeneration::Wifi5);
    }

    #[test]
    fn test_derive_wifi_generation_wifi6() {
        let ies = ParsedIes { has_ht: true, has_vht: true, has_he: true, ..Default::default() };
        assert_eq!(derive_wifi_generation(&ies), WifiGeneration::Wifi6);
    }

    // === Full parse_ies integration tests ===

    #[test]
    fn test_parse_ies_full() {
        let config = BeaconIeConfig {
            ssid: b"ParseTest".to_vec(),
            channel: 11,
            security: ApSecurity::Wpa2Psk,
            country_code: *b"BR",
            ..Default::default()
        };
        let ies = build_beacon_ies(&config, true);
        let parsed = parse_ies(&ies);

        assert_eq!(parsed.ssid.as_deref(), Some("ParseTest"));
        assert_eq!(parsed.channel, Some(11));
        assert!(parsed.rsn.is_some());
        let rsn = parsed.rsn.unwrap();
        assert_eq!(rsn.akm_suites, vec![AkmSuite::Psk]);
        assert_eq!(rsn.group_cipher, CipherSuite::Ccmp);
        assert!(parsed.has_ht);
        assert!(!parsed.has_vht);
        assert!(parsed.has_wmm);
        assert_eq!(parsed.country_code, Some(*b"BR"));

        // Check structured types
        assert!(parsed.ht_cap.is_some());
        assert!(parsed.ht_oper.is_some());
        assert!(parsed.tim.is_some());
        assert!(parsed.ds.is_some());
        assert_eq!(parsed.ds.unwrap().channel, 11);
        assert!(parsed.country.is_some());
        assert!(parsed.ext_cap.is_some());
        assert!(parsed.wmm_ie.is_some());
    }

    #[test]
    fn test_parse_ies_5ghz_full() {
        let config = BeaconIeConfig {
            ssid: b"WiFi6Test".to_vec(),
            channel: 36,
            security: ApSecurity::Wpa3Sae,
            country_code: *b"US",
            ..Default::default()
        };
        let ies = build_beacon_ies(&config, false);
        let parsed = parse_ies(&ies);

        assert_eq!(parsed.ssid.as_deref(), Some("WiFi6Test"));
        assert_eq!(parsed.channel, Some(36));
        assert!(parsed.has_ht);
        assert!(parsed.has_vht);
        assert!(parsed.has_he);
        assert!(parsed.has_wmm);
        assert_eq!(parsed.country_code, Some(*b"US"));
        let wifi_gen = derive_wifi_generation(&parsed);
        assert_eq!(wifi_gen, WifiGeneration::Wifi6);

        let rsn = parsed.rsn.unwrap();
        assert_eq!(rsn.akm_suites, vec![AkmSuite::Sae]);
        assert!(rsn.mfp_capable);
        assert!(rsn.mfp_required);

        // Check VHT/HE structured types
        assert!(parsed.vht_cap.is_some());
        assert!(parsed.vht_oper.is_some());
        assert!(parsed.he_cap.is_some());
    }

    #[test]
    fn test_build_then_parse_assoc_roundtrip() {
        let target = AssocTarget {
            ssid: b"RoundTrip".to_vec(),
            channel: 6,
            has_ht: true,
            has_wmm: true,
            max_nss: 2,
            rsn: Some(RsnInfo {
                group_cipher: CipherSuite::Ccmp,
                pairwise_ciphers: vec![CipherSuite::Ccmp],
                akm_suites: vec![AkmSuite::Psk],
                ..Default::default()
            }),
            ..Default::default()
        };
        let ies = build_assoc_ies(&target);
        let parsed = parse_ies(&ies);

        assert_eq!(parsed.ssid.as_deref(), Some("RoundTrip"));
        assert_eq!(parsed.channel, Some(6));
        assert!(parsed.rsn.is_some());
        assert!(parsed.has_ht);
        assert!(parsed.has_wmm);
    }

    #[test]
    fn test_parse_ies_ie_order_tracking() {
        let config = BeaconIeConfig {
            ssid: b"Order".to_vec(),
            channel: 6,
            security: ApSecurity::Open,
            ..Default::default()
        };
        let ies = build_beacon_ies(&config, true);
        let parsed = parse_ies(&ies);

        // IE order should start with SSID(0), Rates(1), DS(3), TIM(5)
        assert!(parsed.ie_order.len() >= 4);
        assert_eq!(parsed.ie_order[0], 0);  // SSID
        assert_eq!(parsed.ie_order[1], 1);  // Supported Rates
    }

    #[test]
    fn test_parse_ies_vendor_oui_tracking() {
        let config = BeaconIeConfig {
            ssid: b"Vendor".to_vec(),
            channel: 6,
            security: ApSecurity::Open,
            ..Default::default()
        };
        let ies = build_beacon_ies(&config, true);
        let parsed = parse_ies(&ies);

        // Should have Microsoft OUI from WMM IE
        assert!(parsed.vendor_ouis.contains(&OUI_MICROSOFT));
    }

    #[test]
    fn test_parse_ies_raw_ies_populated() {
        let data = [0, 2, b'A', b'B', 3, 1, 6];
        let parsed = parse_ies(&data);
        assert_eq!(parsed.raw_ies.len(), 2);
        assert_eq!(parsed.raw_ies[0].tag, 0);
        assert_eq!(parsed.raw_ies[0].ext_tag, 0);
        assert_eq!(parsed.raw_ies[1].tag, 3);
    }

    #[test]
    fn test_parse_ies_wps_in_vendor() {
        let mut data = Vec::new();
        // Vendor specific IE with WPS
        let wps_body: Vec<u8> = vec![
            0x00, 0x50, 0xF2, 0x04, // WPS OUI+type
            0x10, 0x44, 0x00, 0x01, 0x02, // WPS State = Configured
            0x10, 0x4A, 0x00, 0x01, 0x10, // Version = 1.0
        ];
        data.push(ie_tag::VENDOR_SPECIFIC);
        data.push(wps_body.len() as u8);
        data.extend_from_slice(&wps_body);

        let parsed = parse_ies(&data);
        assert!(parsed.has_wps);
        assert!(parsed.wps.is_some());
        let wps = parsed.wps.unwrap();
        assert_eq!(wps.state, WpsState::Configured);
        assert_eq!(wps.version, 0x10);
    }

    #[test]
    fn test_parse_ies_csa() {
        let data = [ie_tag::CSA, 3, 1, 36, 5];
        let parsed = parse_ies(&data);
        assert!(parsed.csa.is_some());
        let csa = parsed.csa.unwrap();
        assert_eq!(csa.mode, 1);
        assert_eq!(csa.new_channel, 36);
        assert_eq!(csa.count, 5);
    }

    #[test]
    fn test_parse_ies_erp() {
        let data = [ie_tag::ERP, 1, 0x03]; // non-ERP present + use protection
        let parsed = parse_ies(&data);
        assert!(parsed.erp.is_some());
        let erp = parsed.erp.unwrap();
        assert!(erp.non_erp_present);
        assert!(erp.use_protection);
    }

    #[test]
    fn test_parse_ies_mobility_domain() {
        let data = [ie_tag::MOBILITY_DOMAIN, 3, 0x34, 0x12, 0x01];
        let parsed = parse_ies(&data);
        assert!(parsed.mobility_domain.is_some());
        let md = parsed.mobility_domain.unwrap();
        assert_eq!(md.mdid, 0x1234);
        assert!(md.ft_over_ds);
    }

    #[test]
    fn test_parse_ies_rm_capabilities() {
        let data = [ie_tag::RM_ENABLED_CAPABILITIES, 5, 0x1F, 0x00, 0x00, 0x00, 0x00];
        let parsed = parse_ies(&data);
        assert!(parsed.rm_cap.is_some());
        let rm = parsed.rm_cap.unwrap();
        assert!(rm.link_measurement);
        assert!(rm.neighbor_report);
        assert!(rm.beacon_passive);
    }

    #[test]
    fn test_parse_ies_bss_load() {
        let data = [ie_tag::QBSS_LOAD, 5, 0x0A, 0x00, 0x80, 0xE8, 0x03];
        let parsed = parse_ies(&data);
        assert!(parsed.bss_load.is_some());
        let bl = parsed.bss_load.unwrap();
        assert_eq!(bl.station_count, 10);
        assert_eq!(bl.channel_utilization, 128);
    }

    #[test]
    fn test_parse_ies_power_constraint() {
        let data = [ie_tag::POWER_CONSTRAINT, 1, 3];
        let parsed = parse_ies(&data);
        assert!(parsed.power_constraint.is_some());
        assert_eq!(parsed.power_constraint.unwrap().power_constraint_db, 3);
    }

    #[test]
    fn test_parse_ies_multi_bssid() {
        let data = [ie_tag::MULTI_BSSID, 1, 0x03]; // max_bssid_indicator=3
        let parsed = parse_ies(&data);
        assert!(parsed.multi_bssid.is_some());
        assert_eq!(parsed.multi_bssid.unwrap().max_bssid_indicator, 3);
    }

    #[test]
    fn test_parse_ies_interworking() {
        let data = [ie_tag::INTERWORKING, 1, 0x12]; // type=2, internet=true
        let parsed = parse_ies(&data);
        assert!(parsed.interworking_ie.is_some());
        let iw = parsed.interworking_ie.unwrap();
        assert_eq!(iw.access_network_type, 2);
        assert!(iw.internet);
    }

    #[test]
    fn test_parse_ies_qos_capability() {
        let data = [ie_tag::QOS_CAPABILITY, 1, 0x35];
        let parsed = parse_ies(&data);
        assert!(parsed.qos.is_some());
        assert_eq!(parsed.qos.unwrap().raw, 0x35);
    }

    #[test]
    fn test_parse_ies_wpa_vendor() {
        // WPA vendor IE: 00:50:F2:01 + version(1) + group(TKIP) + PW count(1) + PW(TKIP) + AKM count(1) + AKM(PSK)
        let wpa_body = [
            0x00, 0x50, 0xF2, 0x01,
            0x01, 0x00,
            0x00, 0x50, 0xF2, 0x02,
            0x01, 0x00,
            0x00, 0x50, 0xF2, 0x02,
            0x01, 0x00,
            0x00, 0x50, 0xF2, 0x02,
        ];
        let mut data = Vec::new();
        data.push(ie_tag::VENDOR_SPECIFIC);
        data.push(wpa_body.len() as u8);
        data.extend_from_slice(&wpa_body);

        let parsed = parse_ies(&data);
        assert!(parsed.wpa.is_some());
        let wpa = parsed.wpa.unwrap();
        assert_eq!(wpa.security, Security::Wpa);
        assert_eq!(wpa.group_cipher, CipherSuite::Tkip);
    }

    #[test]
    fn test_parse_ies_empty_data() {
        let parsed = parse_ies(&[]);
        assert!(parsed.ssid.is_none());
        assert!(parsed.rsn.is_none());
        assert!(!parsed.has_ht);
        assert_eq!(parsed.max_nss, 1);
    }

    #[test]
    fn test_parse_ies_malformed_resilience() {
        // Mix of valid and truncated IEs
        let mut data = Vec::new();
        // Valid SSID
        data.extend_from_slice(&[0, 3, b'A', b'B', b'C']);
        // Truncated HT Caps (claims 26 bytes but only 2 available)
        data.extend_from_slice(&[45, 26, 0x0F, 0x13]);
        // The iterator will stop at the truncated IE
        let parsed = parse_ies(&data);
        assert_eq!(parsed.ssid.as_deref(), Some("ABC"));
        // HT should NOT be parsed since the IE is truncated
        assert!(!parsed.has_ht);
    }
}
