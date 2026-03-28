//! Capture export engine — PCAP, hccapx, hc22000, aircrack-ng, EAP credential export.
//!
//! All output format writers for interop with cracking tools (hashcat, aircrack-ng,
//! john, asleap, pixiewps). Formats are byte-exact per their respective specifications.
//!
#![allow(dead_code)]
#![allow(unused_imports)]
//! Ported from `wifikit_export.c` (libwifikit).

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use crate::core::error::{Error, ExportFormat, ExportOp, Result};
use crate::core::mac::MacAddress;
use crate::protocol::eapol::{EapMethod, HandshakeQuality};

// Re-export capture::Handshake as the canonical handshake type for export.
// capture.rs owns the state machine; export.rs only reads the result.
pub use super::capture::Handshake;

/// Captured enterprise credential from rogue AP / EAP attack.
///
/// Contains all data needed to export in the appropriate cracking format.
/// Fields are Optional because different EAP methods capture different data.
#[derive(Clone, Debug)]
pub struct CapturedCredential {
    /// Client MAC that authenticated
    pub client_mac: MacAddress,
    /// EAP method used for capture
    pub eap_method: EapMethod,
    /// EAP username (e.g. "john@corp.com", "CORP\\jsmith")
    pub identity: String,
    /// Extracted domain (from user@domain or DOMAIN\\user)
    pub domain: String,

    /// MSCHAPv2 authenticator challenge (16 bytes)
    pub mschapv2_auth_challenge: Option<[u8; 16]>,
    /// MSCHAPv2 peer challenge (16 bytes)
    pub mschapv2_peer_challenge: Option<[u8; 16]>,
    /// MSCHAPv2 NT response (24 bytes)
    pub mschapv2_nt_response: Option<[u8; 24]>,

    /// LEAP challenge (8 bytes)
    pub leap_challenge: Option<[u8; 8]>,
    /// LEAP response (24 bytes)
    pub leap_response: Option<[u8; 24]>,

    /// GTC/PAP plaintext password (no cracking needed)
    pub plaintext_password: Option<String>,

    /// MD5-Challenge challenge value (16 bytes)
    pub md5_challenge: Option<[u8; 16]>,
    /// MD5-Challenge response (16 bytes)
    pub md5_response: Option<[u8; 16]>,
    /// MD5-Challenge ID byte
    pub md5_id: Option<u8>,

    /// RSSI at time of capture (dBm)
    pub rssi: i8,
    /// Timestamp in microseconds since epoch
    pub timestamp_us: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PCAP WRITER — standard libpcap format
//
//  Global header: 24 bytes (magic, version, snaplen, link type)
//  Per-packet header: 16 bytes (timestamp sec, timestamp usec, incl_len, orig_len)
//  Link type 105 = IEEE 802.11 (raw)
//  Link type 127 = IEEE 802.11 + RadioTap header
//
//  Compatible with: Wireshark, tcpdump, tshark, aircrack-ng, hashcat
// ═══════════════════════════════════════════════════════════════════════════════

/// PCAP magic number (little-endian native byte order)
pub const PCAP_MAGIC: u32 = 0xA1B2_C3D4;
/// PCAP major version
pub const PCAP_VERSION_MAJOR: u16 = 2;
/// PCAP minor version
pub const PCAP_VERSION_MINOR: u16 = 4;
/// IEEE 802.11 link type (raw frames, no radiotap)
pub const PCAP_LINKTYPE_IEEE802_11: u32 = 105;
/// IEEE 802.11 + RadioTap header link type
pub const PCAP_LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;
/// Maximum capture length per packet
pub const PCAP_SNAPLEN: u32 = 65535;

/// PCAP file writer. Creates standard libpcap format files readable by
/// Wireshark, tcpdump, aircrack-ng, hashcat, and all PCAP-compatible tools.
pub struct PcapWriter {
    file: File,
    packet_count: u64,
    bytes_written: u64,
    path: String,
}

impl PcapWriter {
    /// Create a new PCAP file and write the 24-byte global header.
    ///
    /// `linktype` should be one of `PCAP_LINKTYPE_IEEE802_11` (105) or
    /// `PCAP_LINKTYPE_IEEE802_11_RADIOTAP` (127).
    pub fn create(path: &str, linktype: u32) -> Result<Self> {
        let mut file = File::create(path).map_err(|e| Error::ExportFailed {
            format: ExportFormat::Pcap,
            op: ExportOp::Create,
            path: PathBuf::from(path),
            source: e,
        })?;

        // PCAP global header: 24 bytes, all little-endian
        // magic(4) + version_major(2) + version_minor(2) + thiszone(4) +
        // sigfigs(4) + snaplen(4) + linktype(4)
        let mut header = [0u8; 24];
        header[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
        header[4..6].copy_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
        header[6..8].copy_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
        // thiszone: i32 = 0 (UTC)
        header[8..12].copy_from_slice(&0i32.to_le_bytes());
        // sigfigs: u32 = 0
        header[12..16].copy_from_slice(&0u32.to_le_bytes());
        header[16..20].copy_from_slice(&PCAP_SNAPLEN.to_le_bytes());
        header[20..24].copy_from_slice(&linktype.to_le_bytes());

        file.write_all(&header).map_err(|e| Error::ExportFailed {
            format: ExportFormat::Pcap,
            op: ExportOp::WriteHeader,
            path: PathBuf::from(path),
            source: e,
        })?;

        Ok(Self {
            file,
            packet_count: 0,
            bytes_written: 24,
            path: path.to_string(),
        })
    }

    /// Write a single packet record to the PCAP file.
    ///
    /// Each record is: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) + data.
    /// `timestamp_us` is microseconds since epoch (or since capture start).
    pub fn write_packet(&mut self, data: &[u8], timestamp_us: u64) -> Result<()> {
        let ts_sec = (timestamp_us / 1_000_000) as u32;
        let ts_usec = (timestamp_us % 1_000_000) as u32;
        let incl_len = data.len() as u32;
        let orig_len = data.len() as u32;

        // Packet record header: 16 bytes, all little-endian
        let mut pkt_header = [0u8; 16];
        pkt_header[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        pkt_header[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        pkt_header[8..12].copy_from_slice(&incl_len.to_le_bytes());
        pkt_header[12..16].copy_from_slice(&orig_len.to_le_bytes());

        self.file.write_all(&pkt_header).map_err(|e| Error::ExportFailed {
            format: ExportFormat::Pcap,
            op: ExportOp::WriteData,
            path: PathBuf::from(&self.path),
            source: e,
        })?;
        self.file.write_all(data).map_err(|e| Error::ExportFailed {
            format: ExportFormat::Pcap,
            op: ExportOp::WriteData,
            path: PathBuf::from(&self.path),
            source: e,
        })?;

        self.packet_count += 1;
        self.bytes_written += 16 + data.len() as u64;
        Ok(())
    }

    /// Flush the file and return statistics. Consumes the writer.
    /// Returns Err if the final flush fails (e.g., full disk).
    pub fn finish(mut self) -> crate::core::error::Result<PcapStats> {
        self.file.flush().map_err(|e| crate::core::error::Error::ExportFailed {
            format: ExportFormat::Pcap,
            op: ExportOp::Flush,
            path: PathBuf::from(&self.path),
            source: e,
        })?;
        Ok(PcapStats {
            packets: self.packet_count,
            bytes: self.bytes_written,
            path: self.path.clone(),
        })
    }

    /// Number of packets written so far.
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }

    /// Total bytes written so far (including global header and all packet headers).
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

/// Statistics returned after completing a PCAP write session.
#[derive(Clone, Debug)]
pub struct PcapStats {
    /// Total packets written
    pub packets: u64,
    /// Total bytes written (headers + data)
    pub bytes: u64,
    /// File path
    pub path: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HCCAPX FORMAT — hashcat legacy (-m 2500)
//
//  Binary format, 393 bytes per handshake entry.
//  Contains: ESSID, AP MAC, STA MAC, ANonce, SNonce, EAPOL frame, MIC.
//
//  hashcat hccapx spec: https://hashcat.net/wiki/doku.php?id=hccapx
// ═══════════════════════════════════════════════════════════════════════════════

/// hccapx signature: "HCPX" as u32 little-endian = 0x58504348
pub const HCCAPX_SIGNATURE: u32 = 0x5850_4348;
/// hccapx format version
pub const HCCAPX_VERSION: u32 = 4;
/// hccapx record size in bytes (must be exactly 393)
pub const HCCAPX_SIZE: usize = 393;
/// Maximum EAPOL frame size in hccapx record
pub const HCCAPX_MAX_EAPOL: usize = 256;

/// MIC offset within an EAPOL-Key frame.
///
/// EAPOL header(4) + Key descriptor type(1) + Key info(2) + Key length(2) +
/// Replay counter(8) + Nonce(32) + IV(16) + RSC(8) + Reserved(8) = 81 bytes.
/// MIC is 16 bytes starting at offset 81.
const EAPOL_MIC_OFFSET: usize = 81;

/// MIC length in bytes
const EAPOL_MIC_LEN: usize = 16;

/// Single hccapx record — 393 bytes, packed binary format.
///
/// This struct is serialized field-by-field (not with repr(C)) to guarantee
/// the exact byte layout that hashcat expects, regardless of platform alignment.
#[derive(Clone, Debug)]
pub struct HccapxRecord {
    /// HCCAPX_SIGNATURE (0x58504348)
    pub signature: u32,
    /// HCCAPX_VERSION (4)
    pub version: u32,
    /// Message pair type: 0=M1M2, 1=M1M4, 2=M2M3, 3=M3M4, +128=LE
    pub message_pair: u8,
    /// SSID length (0-32)
    pub essid_len: u8,
    /// SSID bytes (null-padded to 32)
    pub essid: [u8; 32],
    /// Key version: 1=WPA (HMAC-MD5), 2=WPA2 (HMAC-SHA1), 3=WPA2 (AES-CMAC)
    pub keyver: u8,
    /// MIC from the EAPOL-Key frame (M2 or M4)
    pub keymic: [u8; 16],
    /// AP MAC address (BSSID)
    pub mac_ap: [u8; 6],
    /// AP nonce (ANonce from M1 or M3)
    pub nonce_ap: [u8; 32],
    /// Station MAC address
    pub mac_sta: [u8; 6],
    /// Station nonce (SNonce from M2 or M4)
    pub nonce_sta: [u8; 32],
    /// Length of EAPOL frame in `eapol` field
    pub eapol_len: u16,
    /// Complete EAPOL frame (M2) with MIC field zeroed for hash verification.
    /// hashcat recomputes the MIC using the candidate PMK to verify correctness.
    pub eapol: [u8; 256],
}

impl HccapxRecord {
    /// Serialize to exactly 393 bytes in the format hashcat expects.
    ///
    /// Layout (all multi-byte fields little-endian):
    ///   signature(4) + version(4) + message_pair(1) + essid_len(1) + essid(32) +
    ///   keyver(1) + keymic(16) + mac_ap(6) + nonce_ap(32) + mac_sta(6) +
    ///   nonce_sta(32) + eapol_len(2) + eapol(256) = 393
    pub fn to_bytes(&self) -> [u8; HCCAPX_SIZE] {
        let mut buf = [0u8; HCCAPX_SIZE];
        let mut pos = 0;

        buf[pos..pos + 4].copy_from_slice(&self.signature.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&self.version.to_le_bytes());
        pos += 4;
        buf[pos] = self.message_pair;
        pos += 1;
        buf[pos] = self.essid_len;
        pos += 1;
        buf[pos..pos + 32].copy_from_slice(&self.essid);
        pos += 32;
        buf[pos] = self.keyver;
        pos += 1;
        buf[pos..pos + 16].copy_from_slice(&self.keymic);
        pos += 16;
        buf[pos..pos + 6].copy_from_slice(&self.mac_ap);
        pos += 6;
        buf[pos..pos + 32].copy_from_slice(&self.nonce_ap);
        pos += 32;
        buf[pos..pos + 6].copy_from_slice(&self.mac_sta);
        pos += 6;
        buf[pos..pos + 32].copy_from_slice(&self.nonce_sta);
        pos += 32;
        buf[pos..pos + 2].copy_from_slice(&self.eapol_len.to_le_bytes());
        pos += 2;
        buf[pos..pos + 256].copy_from_slice(&self.eapol);
        pos += 256;

        debug_assert_eq!(pos, HCCAPX_SIZE);
        buf
    }
}

/// Build an hccapx record from a captured handshake.
///
/// Requires at minimum M1 + M2 (for ANonce, SNonce, MIC, and the EAPOL frame).
/// The M2 EAPOL frame is copied with the MIC field zeroed at offset 81 —
/// hashcat recomputes the MIC from candidate passwords to verify correctness.
///
/// Returns `None` if the handshake doesn't have enough data (quality < M1M2,
/// missing M2 frame, or M2 frame exceeds 256 bytes).
pub fn build_hccapx(handshake: &Handshake) -> Option<HccapxRecord> {
    if handshake.quality < HandshakeQuality::M1M2 {
        return None;
    }

    let m2_frame = handshake.m2_frame.as_ref()?;
    if m2_frame.is_empty() || m2_frame.len() > HCCAPX_MAX_EAPOL {
        return None;
    }

    // All crypto fields must be present for a valid hccapx record.
    // Zero-filling produces uncrackable files — skip instead.
    let key_mic = handshake.key_mic?;
    let anonce = handshake.anonce?;
    let snonce = handshake.snonce?;

    let mut record = HccapxRecord {
        signature: HCCAPX_SIGNATURE,
        version: HCCAPX_VERSION,
        // message_pair 0 = "M1+M2 from same authentication session" — valid default
        // per hashcat hccapx format spec when session info is unavailable
        message_pair: handshake.message_pair.map(|mp| mp as u8).unwrap_or(0),
        essid_len: 0,
        essid: [0u8; 32],
        keyver: handshake.key_version as u8,
        keymic: key_mic,
        mac_ap: *handshake.ap_mac.as_bytes(),
        nonce_ap: anonce,
        mac_sta: *handshake.sta_mac.as_bytes(),
        nonce_sta: snonce,
        eapol_len: 0,
        eapol: [0u8; 256],
    };

    // ESSID (truncate to 32 bytes max, as per spec)
    let ssid_bytes = handshake.ssid.as_bytes();
    let ssid_len = ssid_bytes.len().min(32);
    record.essid_len = ssid_len as u8;
    record.essid[..ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);

    // EAPOL frame from M2 — copy and zero the MIC field
    let eapol_len = m2_frame.len();
    record.eapol_len = eapol_len as u16;
    record.eapol[..eapol_len].copy_from_slice(m2_frame);

    // Zero the MIC field within the copied EAPOL frame.
    // MIC is at offset 81 from start of EAPOL frame.
    if eapol_len > EAPOL_MIC_OFFSET + EAPOL_MIC_LEN {
        record.eapol[EAPOL_MIC_OFFSET..EAPOL_MIC_OFFSET + EAPOL_MIC_LEN]
            .fill(0);
    }

    Some(record)
}

/// Write one or more hccapx records to a file.
///
/// Creates or overwrites the file. Multiple records are concatenated
/// (hashcat processes them sequentially). Returns the number of records written.
pub fn write_hccapx(path: &str, records: &[HccapxRecord]) -> Result<u64> {
    let mut file = File::create(path).map_err(|e| Error::ExportFailed {
        format: ExportFormat::Hccapx,
        op: ExportOp::Create,
        path: PathBuf::from(path),
        source: e,
    })?;

    let mut written = 0u64;
    for record in records {
        let bytes = record.to_bytes();
        file.write_all(&bytes).map_err(|e| Error::ExportFailed {
            format: ExportFormat::Hccapx,
            op: ExportOp::WriteData,
            path: PathBuf::from(path),
            source: e,
        })?;
        written += 1;
    }

    file.flush().map_err(|e| Error::ExportFailed {
        format: ExportFormat::Hccapx,
        op: ExportOp::Flush,
        path: PathBuf::from(path),
        source: e,
    })?;

    Ok(written)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HC22000 FORMAT — hashcat modern (-m 22000)
//
//  Text-based format, one line per entry. Supports BOTH PMKID and EAPOL.
//  Supersedes hccapx as the preferred hashcat input format.
//
//  PMKID:  WPA*01*PMKID*MAC_AP*MAC_STA*ESSID_HEX***
//  EAPOL:  WPA*02*MIC*MAC_AP*MAC_STA*ESSID_HEX*ANONCE*EAPOL_HEX*MP
//
//  hashcat 22000 spec: https://hashcat.net/wiki/doku.php?id=hc22000
// ═══════════════════════════════════════════════════════════════════════════════

/// Encode bytes as lowercase hex string.
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Generate an hc22000 line for a PMKID capture (type 01).
///
/// Format: `WPA*01*PMKID*MAC_AP*MAC_STA*ESSID_HEX***`
///
/// PMKID-based attacks are clientless — only requires a single association
/// exchange to extract the PMKID from the AP's M1 RSN IE Key Data.
pub fn format_hc22000_pmkid(
    pmkid: &[u8; 16],
    ap_mac: &[u8; 6],
    sta_mac: &[u8; 6],
    ssid: &str,
) -> String {
    format!(
        "WPA*01*{}*{}*{}*{}***",
        hex_encode(pmkid),
        hex_encode(ap_mac),
        hex_encode(sta_mac),
        hex_encode(ssid.as_bytes()),
    )
}

/// Generate an hc22000 line for an EAPOL handshake capture (type 02).
///
/// Format: `WPA*02*MIC*MAC_AP*MAC_STA*ESSID_HEX*ANONCE*EAPOL_HEX*MP`
///
/// The EAPOL frame (M2) is included with the MIC field zeroed — hashcat
/// recomputes the MIC from candidate passwords. The original MIC is provided
/// separately for verification.
///
/// Returns `None` if the handshake doesn't have M1+M2 data.
pub fn format_hc22000_eapol(handshake: &Handshake) -> Option<String> {
    if handshake.quality < HandshakeQuality::M1M2 {
        return None;
    }

    let m2_frame = handshake.m2_frame.as_ref()?;
    if m2_frame.is_empty() {
        return None;
    }

    // Copy M2 EAPOL frame and zero the MIC field
    let mut eapol_copy = m2_frame.clone();
    if eapol_copy.len() > EAPOL_MIC_OFFSET + EAPOL_MIC_LEN {
        eapol_copy[EAPOL_MIC_OFFSET..EAPOL_MIC_OFFSET + EAPOL_MIC_LEN]
            .fill(0);
    }

    let key_mic = handshake.key_mic?;
    let anonce = handshake.anonce?;
    let message_pair = handshake.message_pair.map(|mp| mp as u8).unwrap_or(0);

    Some(format!(
        "WPA*02*{}*{}*{}*{}*{}*{}*{:02x}",
        hex_encode(&key_mic),
        hex_encode(handshake.ap_mac.as_bytes()),
        hex_encode(handshake.sta_mac.as_bytes()),
        hex_encode(handshake.ssid.as_bytes()),
        hex_encode(&anonce),
        hex_encode(&eapol_copy),
        message_pair,
    ))
}

/// Write hc22000 lines to a file. One line per capture.
///
/// Creates or overwrites the file. Returns the number of lines written.
pub fn write_hc22000(path: &str, lines: &[String]) -> Result<u64> {
    let mut file = File::create(path).map_err(|e| Error::ExportFailed {
        format: ExportFormat::Hc22000,
        op: ExportOp::Create,
        path: PathBuf::from(path),
        source: e,
    })?;

    let mut written = 0u64;
    for line in lines {
        file.write_all(line.as_bytes()).map_err(|e| Error::ExportFailed {
            format: ExportFormat::Hc22000,
            op: ExportOp::WriteData,
            path: PathBuf::from(path),
            source: e,
        })?;
        file.write_all(b"\n").map_err(|e| Error::ExportFailed {
            format: ExportFormat::Hc22000,
            op: ExportOp::WriteData,
            path: PathBuf::from(path),
            source: e,
        })?;
        written += 1;
    }

    file.flush().map_err(|e| Error::ExportFailed {
        format: ExportFormat::Hc22000,
        op: ExportOp::Flush,
        path: PathBuf::from(path),
        source: e,
    })?;

    Ok(written)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AIRCRACK-NG COMPATIBLE EXPORT
//
//  Writes handshake as PCAP with:
//  1. Synthetic beacon frame (for SSID association — aircrack needs this)
//  2. EAPOL M1-M4 as 802.11 data frames with LLC/SNAP headers
//
//  Link type 105 (raw 802.11, no radiotap)
// ═══════════════════════════════════════════════════════════════════════════════

/// 802.11 Frame Control: Beacon (type=0 mgmt, subtype=8)
const FC_BEACON: u8 = 0x80;

/// 802.11 Frame Control: Data (type=2 data, subtype=0)
const FC_DATA: u8 = 0x08;

/// Capability Info: ESS bit
const CAPINFO_ESS: u16 = 0x0001;

/// Capability Info: Privacy bit (WEP/WPA/WPA2)
const CAPINFO_PRIVACY: u16 = 0x0010;

/// Capability Info: Short slot time
const CAPINFO_SHORT_SLOT: u16 = 0x0400;

/// LLC/SNAP header for EAPOL: AA AA 03 00 00 00 88 8E
/// (DSAP=AA, SSAP=AA, Ctrl=03, OUI=000000, EtherType=888E)
const LLC_SNAP_EAPOL: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];

/// Build a synthetic beacon frame for SSID association.
///
/// aircrack-ng needs a beacon in the PCAP to associate the SSID with
/// the BSSID. This builds a minimal but valid beacon frame.
///
/// Layout: FC(2) + Dur(2) + DA(6) + SA(6) + BSSID(6) + SeqCtl(2) +
///         Timestamp(8) + BeaconInterval(2) + CapInfo(2) + SSID_IE(2+N)
fn build_synthetic_beacon(ap_mac: &[u8; 6], ssid: &str) -> Vec<u8> {
    let ssid_bytes = ssid.as_bytes();
    let ssid_len = ssid_bytes.len().min(32);

    let mut beacon = Vec::with_capacity(38 + ssid_len);

    // Frame Control: beacon (type 0, subtype 8)
    beacon.push(FC_BEACON);
    beacon.push(0x00);

    // Duration
    beacon.extend_from_slice(&[0x00, 0x00]);

    // DA = broadcast
    beacon.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // SA = BSSID
    beacon.extend_from_slice(ap_mac);
    // BSSID
    beacon.extend_from_slice(ap_mac);

    // Sequence control
    beacon.extend_from_slice(&[0x00, 0x00]);

    // Fixed parameters: Timestamp (8 bytes, zeros)
    beacon.extend_from_slice(&[0x00; 8]);
    // Beacon interval: 100 TU (0x0064 LE)
    beacon.extend_from_slice(&[0x64, 0x00]);
    // Capability info: ESS + Privacy + Short Slot
    let cap = CAPINFO_ESS | CAPINFO_PRIVACY | CAPINFO_SHORT_SLOT;
    beacon.extend_from_slice(&cap.to_le_bytes());

    // SSID IE: tag=0, length, ssid bytes
    beacon.push(0x00); // SSID tag number
    beacon.push(ssid_len as u8);
    beacon.extend_from_slice(&ssid_bytes[..ssid_len]);

    beacon
}

/// Build an 802.11 data frame wrapping an EAPOL message for PCAP export.
///
/// `ap_to_sta`: true for M1/M3 (AP->STA, FromDS=1), false for M2/M4 (STA->AP, ToDS=1).
///
/// Layout: FC(2) + Dur(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtl(2) +
///         LLC/SNAP(8) + EAPOL_data
fn build_eapol_data_frame(
    ap_mac: &[u8; 6],
    sta_mac: &[u8; 6],
    eapol_data: &[u8],
    ap_to_sta: bool,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(32 + 8 + eapol_data.len());

    // Frame Control: Data
    pkt.push(FC_DATA);

    if ap_to_sta {
        // AP -> STA: ToDS=0, FromDS=1 (flags byte = 0x02)
        pkt.push(0x02);
        // Duration
        pkt.extend_from_slice(&[0x00, 0x00]);
        // Addr1 = DA (STA)
        pkt.extend_from_slice(sta_mac);
        // Addr2 = BSSID (AP)
        pkt.extend_from_slice(ap_mac);
        // Addr3 = SA (AP)
        pkt.extend_from_slice(ap_mac);
    } else {
        // STA -> AP: ToDS=1, FromDS=0 (flags byte = 0x01)
        pkt.push(0x01);
        // Duration
        pkt.extend_from_slice(&[0x00, 0x00]);
        // Addr1 = BSSID (AP)
        pkt.extend_from_slice(ap_mac);
        // Addr2 = SA (STA)
        pkt.extend_from_slice(sta_mac);
        // Addr3 = DA (AP)
        pkt.extend_from_slice(ap_mac);
    }

    // Sequence control
    pkt.extend_from_slice(&[0x00, 0x00]);

    // LLC/SNAP header for EAPOL (EtherType 0x888E)
    pkt.extend_from_slice(&LLC_SNAP_EAPOL);

    // EAPOL payload
    pkt.extend_from_slice(eapol_data);

    pkt
}

/// Export a captured handshake as a PCAP file compatible with aircrack-ng.
///
/// Writes a synthetic beacon (for SSID association) followed by all available
/// EAPOL messages (M1-M4) as 802.11 data frames with LLC/SNAP headers.
///
/// If `beacon_frame` is provided, it is used instead of the synthetic beacon.
///
/// Usage: `aircrack-ng -w wordlist.txt output.pcap`
pub fn export_for_aircrack(
    path: &str,
    handshake: &Handshake,
    beacon_frame: Option<&[u8]>,
) -> Result<PcapStats> {
    let mut writer = PcapWriter::create(path, PCAP_LINKTYPE_IEEE802_11)?;

    // Base timestamp (current time as microseconds since epoch)
    let base_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;

    // Write beacon (real or synthetic)
    let beacon = match beacon_frame {
        Some(frame) => frame.to_vec(),
        None => build_synthetic_beacon(handshake.ap_mac.as_bytes(), &handshake.ssid),
    };
    writer.write_packet(&beacon, base_ts)?;

    let ap_mac = handshake.ap_mac.as_bytes();
    let sta_mac = handshake.sta_mac.as_bytes();

    // Write each EAPOL message as an 802.11 data frame.
    // M1, M3: AP -> STA (FromDS=1)
    // M2, M4: STA -> AP (ToDS=1)
    let messages: [(Option<&Vec<u8>>, bool); 4] = [
        (handshake.m1_frame.as_ref(), true),   // M1: AP -> STA
        (handshake.m2_frame.as_ref(), false),  // M2: STA -> AP
        (handshake.m3_frame.as_ref(), true),   // M3: AP -> STA
        (handshake.m4_frame.as_ref(), false),  // M4: STA -> AP
    ];

    for (i, (frame_opt, ap_to_sta)) in messages.iter().enumerate() {
        if let Some(eapol_data) = frame_opt {
            if eapol_data.is_empty() {
                continue;
            }
            let pkt = build_eapol_data_frame(ap_mac, sta_mac, eapol_data, *ap_to_sta);
            // Offset each message by 1ms for correct ordering
            writer.write_packet(&pkt, base_ts + (i as u64 + 1) * 1000)?;
        }
    }

    writer.finish()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SCAN EXPORT — full frame dump as PCAP
// ═══════════════════════════════════════════════════════════════════════════════

/// Export all captured frames from a scan session as a PCAP file.
///
/// Each entry in `frames` is `(raw_frame_data, timestamp_us)`.
/// Uses link type 105 (raw 802.11, no radiotap).
pub fn export_scan_pcap(
    path: &str,
    frames: &[(Vec<u8>, u64)],
) -> Result<PcapStats> {
    let mut writer = PcapWriter::create(path, PCAP_LINKTYPE_IEEE802_11)?;

    for (data, timestamp_us) in frames {
        writer.write_packet(data, *timestamp_us)?;
    }

    writer.finish()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BATCH EXPORT — all handshakes in all formats
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of a batch export operation.
#[derive(Clone, Debug, Default)]
pub struct ExportResult {
    /// PCAP stats (aircrack-ng format), if any handshakes were exported
    pub pcap_stats: Option<PcapStats>,
    /// Number of hccapx records written
    pub hccapx_count: u64,
    /// Number of hc22000 lines written
    pub hc22000_count: u64,
    /// Number of PMKID-only entries in hc22000
    pub pmkid_count: u64,
    /// Total files created
    pub total_files: u64,
}

impl Default for PcapStats {
    fn default() -> Self {
        Self {
            packets: 0,
            bytes: 0,
            path: String::new(),
        }
    }
}

/// Export all handshakes in all supported formats for maximum tool compatibility.
///
/// Creates up to 3 files in `output_dir`:
/// - `{prefix}.pcap`    — aircrack-ng compatible (beacon + EAPOL frames per handshake)
/// - `{prefix}.hccapx`  — hashcat legacy format (-m 2500)
/// - `{prefix}.hc22000` — hashcat modern format (-m 22000, PMKID + EAPOL)
///
/// `beacon_frames` maps BSSID bytes to raw beacon frame data. If a beacon is
/// available for a handshake's AP, it is included in the PCAP for SSID association.
/// Otherwise a synthetic beacon is generated.
pub fn export_all(
    output_dir: &str,
    prefix: &str,
    handshakes: &[Handshake],
    beacon_frames: &HashMap<[u8; 6], Vec<u8>>,
) -> Result<ExportResult> {
    if handshakes.is_empty() {
        return Ok(ExportResult::default());
    }

    let mut result = ExportResult::default();

    // ── hc22000 (modern hashcat, supports both PMKID and EAPOL) ──
    let mut hc22000_lines = Vec::new();
    for hs in handshakes {
        // Type 01: PMKID (clientless)
        if let Some(pmkid) = &hs.pmkid {
            let line = format_hc22000_pmkid(
                pmkid,
                hs.ap_mac.as_bytes(),
                hs.sta_mac.as_bytes(),
                &hs.ssid,
            );
            hc22000_lines.push(line);
            result.pmkid_count += 1;
        }

        // Type 02: EAPOL (requires M1+M2)
        if let Some(line) = format_hc22000_eapol(hs) {
            hc22000_lines.push(line);
        }
    }

    if !hc22000_lines.is_empty() {
        let hc22000_path = format!("{}/{}.hc22000", output_dir, prefix);
        result.hc22000_count = write_hc22000(&hc22000_path, &hc22000_lines)?;
        result.total_files += 1;
    }

    // ── hccapx (legacy hashcat, EAPOL only — requires M1+M2) ──
    let hccapx_records: Vec<HccapxRecord> = handshakes
        .iter()
        .filter_map(build_hccapx)
        .collect();

    if !hccapx_records.is_empty() {
        let hccapx_path = format!("{}/{}.hccapx", output_dir, prefix);
        result.hccapx_count = write_hccapx(&hccapx_path, &hccapx_records)?;
        result.total_files += 1;
    }

    // ── PCAP (aircrack-ng compatible — beacon + EAPOL frames) ──
    let exportable: Vec<&Handshake> = handshakes
        .iter()
        .filter(|hs| hs.quality >= HandshakeQuality::Pmkid)
        .collect();

    if !exportable.is_empty() {
        let pcap_path = format!("{}/{}.pcap", output_dir, prefix);
        let mut writer = PcapWriter::create(&pcap_path, PCAP_LINKTYPE_IEEE802_11)?;

        let base_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let mut ts_offset: u64 = 0;

        for hs in &exportable {
            let ap_bytes = *hs.ap_mac.as_bytes();

            // Write beacon (real if available, synthetic otherwise)
            let beacon = match beacon_frames.get(&ap_bytes) {
                Some(frame) => frame.clone(),
                None => build_synthetic_beacon(&ap_bytes, &hs.ssid),
            };
            writer.write_packet(&beacon, base_ts + ts_offset)?;
            ts_offset += 1000;

            // Write EAPOL messages M1-M4 as 802.11 data frames
            let messages: [(Option<&Vec<u8>>, bool); 4] = [
                (hs.m1_frame.as_ref(), true),   // M1: AP -> STA
                (hs.m2_frame.as_ref(), false),  // M2: STA -> AP
                (hs.m3_frame.as_ref(), true),   // M3: AP -> STA
                (hs.m4_frame.as_ref(), false),  // M4: STA -> AP
            ];

            for (frame_opt, ap_to_sta) in &messages {
                if let Some(eapol_data) = frame_opt {
                    if eapol_data.is_empty() {
                        continue;
                    }
                    let pkt = build_eapol_data_frame(
                        &ap_bytes,
                        hs.sta_mac.as_bytes(),
                        eapol_data,
                        *ap_to_sta,
                    );
                    writer.write_packet(&pkt, base_ts + ts_offset)?;
                    ts_offset += 1000;
                }
            }
        }

        result.pcap_stats = Some(writer.finish()?);
        result.total_files += 1;
    }

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ENTERPRISE CREDENTIAL EXPORT
//
//  Export captured EAP credentials for offline cracking:
//    MSCHAPv2 → hashcat -m 5500 (user::::nt_response:peer_challenge+auth_challenge)
//    LEAP     → asleap format (challenge:response:username)
//    MD5      → hashcat -m 4800 (response:challenge:id)
//    GTC/PAP  → plaintext (no cracking needed, written as-is)
//    Identity → identity only (no credentials captured)
// ═══════════════════════════════════════════════════════════════════════════════

/// Format a single EAP credential for its appropriate cracking tool.
///
/// Returns a string in the format expected by the relevant cracking tool:
/// - MSCHAPv2: `user::::nt_response:peer_challenge+auth_challenge` (hashcat -m 5500)
/// - LEAP: `challenge:response:username` (asleap format)
/// - MD5: `response:challenge:id` (hashcat -m 4800)
/// - GTC/PAP: plaintext with comment header
/// - Identity only: identity with comment header
fn format_eap_credential(cred: &CapturedCredential) -> String {
    // MSCHAPv2 — hashcat -m 5500
    if let (Some(nt_response), Some(peer_challenge), Some(auth_challenge)) = (
        &cred.mschapv2_nt_response,
        &cred.mschapv2_peer_challenge,
        &cred.mschapv2_auth_challenge,
    ) {
        return format!(
            "{}::::{}:{}{}",
            cred.identity,
            hex_encode(nt_response),
            hex_encode(peer_challenge),
            hex_encode(auth_challenge),
        );
    }

    // LEAP — asleap format: challenge:response:username
    if let (Some(challenge), Some(response)) = (&cred.leap_challenge, &cred.leap_response) {
        return format!(
            "{}:{}:{}",
            hex_encode(challenge),
            hex_encode(response),
            cred.identity,
        );
    }

    // MD5-Challenge — hashcat -m 4800: response:challenge:id
    if let (Some(response), Some(challenge), Some(id)) = (
        &cred.md5_response,
        &cred.md5_challenge,
        &cred.md5_id,
    ) {
        return format!(
            "{}:{}:{:02x}",
            hex_encode(response),
            hex_encode(challenge),
            id,
        );
    }

    // GTC/PAP — plaintext password (no cracking needed)
    if let Some(password) = &cred.plaintext_password {
        return format!(
            "# EAP-GTC plaintext credential\n# Identity: {}\n{}",
            cred.identity, password,
        );
    }

    // Identity only — no crackable credentials captured
    format!("# EAP identity (no credentials captured)\n{}", cred.identity)
}

/// Export captured EAP credentials to a file for offline cracking.
///
/// Each credential is written on its own line(s). The format depends on the
/// EAP method used during capture (see `format_eap_credential`).
///
/// Returns the number of credentials written.
pub fn export_eap_credentials(
    path: &str,
    credentials: &[CapturedCredential],
) -> Result<u64> {
    let mut file = File::create(path).map_err(|e| Error::ExportFailed {
        format: ExportFormat::EapCredentials,
        op: ExportOp::Create,
        path: PathBuf::from(path),
        source: e,
    })?;

    let mut written = 0u64;
    for cred in credentials {
        let line = format_eap_credential(cred);
        file.write_all(line.as_bytes()).map_err(|e| Error::ExportFailed {
            format: ExportFormat::EapCredentials,
            op: ExportOp::WriteData,
            path: PathBuf::from(path),
            source: e,
        })?;
        file.write_all(b"\n").map_err(|e| Error::ExportFailed {
            format: ExportFormat::EapCredentials,
            op: ExportOp::WriteData,
            path: PathBuf::from(path),
            source: e,
        })?;
        written += 1;
    }

    file.flush().map_err(|e| Error::ExportFailed {
        format: ExportFormat::EapCredentials,
        op: ExportOp::Flush,
        path: PathBuf::from(path),
        source: e,
    })?;

    Ok(written)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::eapol::MessagePair;

    /// Helper: create a test handshake with M1+M2+M3 data and a PMKID.
    fn make_test_handshake() -> Handshake {
        // Fake M2 EAPOL frame — 121 bytes (enough to contain MIC at offset 81..97)
        let mut m2_frame = vec![0xAA; 121];
        // Put a recognizable MIC at offset 81 (will be zeroed in exports)
        m2_frame[81..97].copy_from_slice(&[
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ]);

        let mut hs = Handshake::new(
            MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]),
            MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]),
            "TestNetwork".to_string(),
        );
        hs.anonce = Some([0x11; 32]);
        hs.snonce = Some([0x22; 32]);
        hs.pmkid = Some([0x33; 16]);
        hs.key_version = 2;
        hs.key_mic = Some([0x44; 16]);
        hs.message_pair = Some(MessagePair::M1M2SameRc);
        hs.m1_frame = Some(vec![0xBB; 99]);
        hs.m2_frame = Some(m2_frame);
        hs.m3_frame = Some(vec![0xCC; 115]);
        hs.has_m1 = true;
        hs.has_m2 = true;
        hs.has_m3 = true;
        hs.has_pmkid = true;
        hs.quality = HandshakeQuality::M1M2M3;
        hs
    }

    // ── PCAP tests ──

    #[test]
    fn test_pcap_global_header_bytes() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_pcap_header.pcap");
        let path_str = path.to_str().unwrap();

        let writer = PcapWriter::create(path_str, PCAP_LINKTYPE_IEEE802_11).unwrap();
        let stats = writer.finish().unwrap();

        // Global header is exactly 24 bytes
        assert_eq!(stats.bytes, 24);
        assert_eq!(stats.packets, 0);

        let data = std::fs::read(path_str).unwrap();
        assert_eq!(data.len(), 24);

        // Verify each field byte-by-byte
        assert_eq!(u32::from_le_bytes([data[0], data[1], data[2], data[3]]), PCAP_MAGIC);
        assert_eq!(u16::from_le_bytes([data[4], data[5]]), PCAP_VERSION_MAJOR);
        assert_eq!(u16::from_le_bytes([data[6], data[7]]), PCAP_VERSION_MINOR);
        assert_eq!(i32::from_le_bytes([data[8], data[9], data[10], data[11]]), 0);
        assert_eq!(u32::from_le_bytes([data[12], data[13], data[14], data[15]]), 0);
        assert_eq!(u32::from_le_bytes([data[16], data[17], data[18], data[19]]), PCAP_SNAPLEN);
        assert_eq!(u32::from_le_bytes([data[20], data[21], data[22], data[23]]), PCAP_LINKTYPE_IEEE802_11);

        let _ignored = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_pcap_write_packet_structure() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_pcap_packet.pcap");
        let path_str = path.to_str().unwrap();

        let mut writer = PcapWriter::create(path_str, PCAP_LINKTYPE_IEEE802_11).unwrap();

        let frame = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        // 1700000 seconds + 123456 microseconds
        let timestamp_us: u64 = 1_700_000_123_456;

        writer.write_packet(&frame, timestamp_us).unwrap();
        assert_eq!(writer.packet_count(), 1);

        let stats = writer.finish().unwrap();
        assert_eq!(stats.packets, 1);
        // 24 (global header) + 16 (packet header) + 6 (data) = 46
        assert_eq!(stats.bytes, 46);

        let data = std::fs::read(path_str).unwrap();
        assert_eq!(data.len(), 46);

        // Packet header at offset 24
        let ts_sec = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let ts_usec = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
        let incl_len = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let orig_len = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

        assert_eq!(ts_sec, 1_700_000);
        assert_eq!(ts_usec, 123_456);
        assert_eq!(incl_len, 6);
        assert_eq!(orig_len, 6);

        // Packet data at offset 40
        assert_eq!(&data[40..46], &frame);

        let _ignored = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_pcap_multiple_packets() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_pcap_multi.pcap");
        let path_str = path.to_str().unwrap();

        let mut writer = PcapWriter::create(path_str, PCAP_LINKTYPE_IEEE802_11_RADIOTAP).unwrap();
        writer.write_packet(&[0x01, 0x02], 1_000_000).unwrap();
        writer.write_packet(&[0x03, 0x04, 0x05], 2_000_000).unwrap();
        writer.write_packet(&[0x06], 3_000_000).unwrap();

        assert_eq!(writer.packet_count(), 3);
        let stats = writer.finish().unwrap();
        assert_eq!(stats.packets, 3);
        // 24 + (16+2) + (16+3) + (16+1) = 78
        assert_eq!(stats.bytes, 78);

        // Verify radiotap linktype
        let data = std::fs::read(path_str).unwrap();
        let linktype = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        assert_eq!(linktype, PCAP_LINKTYPE_IEEE802_11_RADIOTAP);

        let _ignored = std::fs::remove_file(path_str);
    }

    // ── hccapx tests ──

    #[test]
    fn test_hccapx_record_size_exactly_393() {
        // hashcat REQUIRES exactly 393 bytes per hccapx record
        let hs = make_test_handshake();
        let record = build_hccapx(&hs).unwrap();
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), HCCAPX_SIZE);
        assert_eq!(bytes.len(), 393);
    }

    #[test]
    fn test_hccapx_signature_and_version() {
        let hs = make_test_handshake();
        let record = build_hccapx(&hs).unwrap();
        let bytes = record.to_bytes();

        let sig = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(sig, HCCAPX_SIGNATURE);
        assert_eq!(sig, 0x5850_4348); // "HCPX"

        let ver = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(ver, HCCAPX_VERSION);
        assert_eq!(ver, 4);
    }

    #[test]
    fn test_hccapx_fields_correct() {
        let hs = make_test_handshake();
        let record = build_hccapx(&hs).unwrap();

        assert_eq!(record.message_pair, 0);
        assert_eq!(record.essid_len, 11); // "TestNetwork"
        assert_eq!(&record.essid[..11], b"TestNetwork");
        assert_eq!(record.essid[11..], [0u8; 21]); // null-padded
        assert_eq!(record.keyver, 2);
        assert_eq!(record.keymic, [0x44; 16]);
        assert_eq!(record.mac_ap, [0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        assert_eq!(record.nonce_ap, [0x11; 32]);
        assert_eq!(record.mac_sta, [0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);
        assert_eq!(record.nonce_sta, [0x22; 32]);
        assert_eq!(record.eapol_len, 121);
    }

    #[test]
    fn test_hccapx_mic_zeroed_in_eapol_copy() {
        // Critical: the EAPOL frame copy MUST have the MIC zeroed at offset 81.
        // hashcat uses the separate keymic field for verification.
        let hs = make_test_handshake();
        let record = build_hccapx(&hs).unwrap();

        // MIC at offset 81 in the eapol field should be all zeros
        assert_eq!(&record.eapol[81..97], &[0u8; 16]);

        // The keymic field retains the original MIC
        assert_eq!(record.keymic, [0x44; 16]);
    }

    #[test]
    fn test_hccapx_returns_none_insufficient_quality() {
        let mut hs = make_test_handshake();
        hs.quality = HandshakeQuality::Pmkid;
        assert!(build_hccapx(&hs).is_none());

        hs.quality = HandshakeQuality::None;
        assert!(build_hccapx(&hs).is_none());
    }

    #[test]
    fn test_hccapx_returns_none_missing_m2() {
        let mut hs = make_test_handshake();
        hs.m2_frame = None;
        assert!(build_hccapx(&hs).is_none());
    }

    #[test]
    fn test_hccapx_returns_none_oversized_m2() {
        let mut hs = make_test_handshake();
        hs.m2_frame = Some(vec![0xAA; 257]); // exceeds 256-byte max
        assert!(build_hccapx(&hs).is_none());
    }

    #[test]
    fn test_hccapx_returns_none_empty_m2() {
        let mut hs = make_test_handshake();
        hs.m2_frame = Some(vec![]); // empty
        assert!(build_hccapx(&hs).is_none());
    }

    #[test]
    fn test_write_hccapx_single_record() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_write_single.hccapx");
        let path_str = path.to_str().unwrap();

        let hs = make_test_handshake();
        let records = vec![build_hccapx(&hs).unwrap()];
        let count = write_hccapx(path_str, &records).unwrap();
        assert_eq!(count, 1);

        let data = std::fs::read(path_str).unwrap();
        assert_eq!(data.len(), HCCAPX_SIZE);

        let _ignored = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_write_hccapx_multiple_records() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_write_multi.hccapx");
        let path_str = path.to_str().unwrap();

        let hs = make_test_handshake();
        let record = build_hccapx(&hs).unwrap();
        let records = vec![record.clone(), record.clone(), record];
        let count = write_hccapx(path_str, &records).unwrap();
        assert_eq!(count, 3);

        let data = std::fs::read(path_str).unwrap();
        assert_eq!(data.len(), HCCAPX_SIZE * 3);

        let _ignored = std::fs::remove_file(path_str);
    }

    // ── hc22000 tests ──

    #[test]
    fn test_hc22000_pmkid_format() {
        let pmkid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let ap_mac = [0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0];
        let sta_mac = [0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03];
        let ssid = "TestNet";

        let line = format_hc22000_pmkid(&pmkid, &ap_mac, &sta_mac, ssid);

        assert!(line.starts_with("WPA*01*"));
        assert!(line.contains("0102030405060708090a0b0c0d0e0f10")); // PMKID hex
        assert!(line.contains("7c10c90310e0")); // AP MAC hex
        assert!(line.contains("8c882b010203")); // STA MAC hex
        assert!(line.contains("546573744e6574")); // "TestNet" hex
        assert!(line.ends_with("***"));
    }

    #[test]
    fn test_hc22000_pmkid_field_count() {
        let pmkid = [0xFF; 16];
        let ap_mac = [0x00; 6];
        let sta_mac = [0x11; 6];

        let line = format_hc22000_pmkid(&pmkid, &ap_mac, &sta_mac, "X");
        let parts: Vec<&str> = line.split('*').collect();
        // WPA*01*PMKID*MAC_AP*MAC_STA*ESSID*** = 9 fields
        assert_eq!(parts.len(), 9);
        assert_eq!(parts[0], "WPA");
        assert_eq!(parts[1], "01");
    }

    #[test]
    fn test_hc22000_eapol_format() {
        let hs = make_test_handshake();
        let line = format_hc22000_eapol(&hs).unwrap();

        assert!(line.starts_with("WPA*02*"));
        // MIC field (key_mic = all 0x44)
        assert!(line.contains("44444444444444444444444444444444"));
        // AP MAC
        assert!(line.contains("7c10c90310e0"));
        // STA MAC
        assert!(line.contains("8c882b010203"));
        // SSID "TestNetwork" in hex
        assert!(line.contains("546573744e6574776f726b"));
        // ANonce (all 0x11)
        assert!(line.contains("1111111111111111111111111111111111111111111111111111111111111111"));
        // Message pair byte at end
        assert!(line.ends_with("*00"));
    }

    #[test]
    fn test_hc22000_eapol_field_count() {
        let hs = make_test_handshake();
        let line = format_hc22000_eapol(&hs).unwrap();
        let parts: Vec<&str> = line.split('*').collect();
        // WPA*02*MIC*MAC_AP*MAC_STA*ESSID*ANONCE*EAPOL*MP = 9 fields
        assert_eq!(parts.len(), 9);
        assert_eq!(parts[0], "WPA");
        assert_eq!(parts[1], "02");
    }

    #[test]
    fn test_hc22000_eapol_mic_zeroed_in_frame() {
        let hs = make_test_handshake();
        let line = format_hc22000_eapol(&hs).unwrap();

        // MIC at offset 81 in the EAPOL frame = hex chars at position 162..194
        let parts: Vec<&str> = line.split('*').collect();
        let eapol_hex = parts[7];
        let mic_hex = &eapol_hex[162..194];
        assert_eq!(mic_hex, "00000000000000000000000000000000");
    }

    #[test]
    fn test_hc22000_eapol_returns_none_insufficient_quality() {
        let mut hs = make_test_handshake();
        hs.quality = HandshakeQuality::Pmkid;
        assert!(format_hc22000_eapol(&hs).is_none());
    }

    #[test]
    fn test_hc22000_eapol_returns_none_missing_m2() {
        let mut hs = make_test_handshake();
        hs.m2_frame = None;
        assert!(format_hc22000_eapol(&hs).is_none());
    }

    #[test]
    fn test_write_hc22000_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_write.hc22000");
        let path_str = path.to_str().unwrap();

        let lines = vec![
            "WPA*01*aabbccdd*001122334455*667788990011*54657374***".to_string(),
            "WPA*02*deadbeef*001122334455*667788990011*54657374*nonce*eapol*00".to_string(),
        ];
        let count = write_hc22000(path_str, &lines).unwrap();
        assert_eq!(count, 2);

        let content = std::fs::read_to_string(path_str).unwrap();
        let file_lines: Vec<&str> = content.trim().split('\n').collect();
        assert_eq!(file_lines.len(), 2);
        assert!(file_lines[0].starts_with("WPA*01*"));
        assert!(file_lines[1].starts_with("WPA*02*"));

        let _ignored = std::fs::remove_file(path_str);
    }

    // ── Aircrack export tests ──

    #[test]
    fn test_export_for_aircrack_creates_valid_pcap() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_aircrack.pcap");
        let path_str = path.to_str().unwrap();

        let hs = make_test_handshake();
        let stats = export_for_aircrack(path_str, &hs, None).unwrap();

        // 1 beacon + M1 + M2 + M3 = 4 packets (M4 is None)
        assert_eq!(stats.packets, 4);

        let data = std::fs::read(path_str).unwrap();
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(magic, PCAP_MAGIC);
        let linktype = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        assert_eq!(linktype, PCAP_LINKTYPE_IEEE802_11);

        let _ignored = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_export_for_aircrack_with_custom_beacon() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_aircrack_beacon.pcap");
        let path_str = path.to_str().unwrap();

        let hs = make_test_handshake();
        let custom_beacon = vec![0x80, 0x00, 0xFF, 0xFF];
        let stats = export_for_aircrack(path_str, &hs, Some(&custom_beacon)).unwrap();

        // beacon + M1 + M2 + M3 = 4
        assert_eq!(stats.packets, 4);

        let _ignored = std::fs::remove_file(path_str);
    }

    // ── Synthetic beacon test ──

    #[test]
    fn test_synthetic_beacon_structure() {
        let ap_mac = [0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0];
        let beacon = build_synthetic_beacon(&ap_mac, "MyWiFi");

        // Frame Control: beacon
        assert_eq!(beacon[0], FC_BEACON);
        assert_eq!(beacon[1], 0x00);

        // DA = broadcast
        assert_eq!(&beacon[4..10], &[0xFF; 6]);

        // SA = BSSID = ap_mac
        assert_eq!(&beacon[10..16], &ap_mac);
        assert_eq!(&beacon[16..22], &ap_mac);

        // SSID IE at offset 36 (after all fixed fields)
        let ssid_offset = 36;
        assert_eq!(beacon[ssid_offset], 0x00);     // SSID tag
        assert_eq!(beacon[ssid_offset + 1], 6);    // "MyWiFi" length
        assert_eq!(&beacon[ssid_offset + 2..ssid_offset + 8], b"MyWiFi");
    }

    #[test]
    fn test_synthetic_beacon_capability_bits() {
        let ap_mac = [0x00; 6];
        let beacon = build_synthetic_beacon(&ap_mac, "X");

        // Capability info at offset 34-35 (after timestamp + interval)
        let cap = u16::from_le_bytes([beacon[34], beacon[35]]);
        assert_ne!(cap & CAPINFO_ESS, 0);
        assert_ne!(cap & CAPINFO_PRIVACY, 0);
        assert_ne!(cap & CAPINFO_SHORT_SLOT, 0);
    }

    // ── EAPOL data frame tests ──

    #[test]
    fn test_eapol_data_frame_ap_to_sta() {
        let ap_mac = [0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0];
        let sta_mac = [0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03];
        let eapol = [0x01, 0x02, 0x03];

        let frame = build_eapol_data_frame(&ap_mac, &sta_mac, &eapol, true);

        assert_eq!(frame[0], FC_DATA);
        assert_eq!(frame[1], 0x02); // FromDS
        assert_eq!(&frame[2..4], &[0x00, 0x00]); // duration
        assert_eq!(&frame[4..10], &sta_mac);  // Addr1 = DA
        assert_eq!(&frame[10..16], &ap_mac);  // Addr2 = BSSID
        assert_eq!(&frame[16..22], &ap_mac);  // Addr3 = SA
        assert_eq!(&frame[22..24], &[0x00, 0x00]); // seq ctrl
        assert_eq!(&frame[24..32], &LLC_SNAP_EAPOL);
        assert_eq!(&frame[32..35], &eapol);
    }

    #[test]
    fn test_eapol_data_frame_sta_to_ap() {
        let ap_mac = [0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0];
        let sta_mac = [0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03];
        let eapol = [0x04, 0x05];

        let frame = build_eapol_data_frame(&ap_mac, &sta_mac, &eapol, false);

        assert_eq!(frame[0], FC_DATA);
        assert_eq!(frame[1], 0x01); // ToDS
        assert_eq!(&frame[4..10], &ap_mac);   // Addr1 = BSSID
        assert_eq!(&frame[10..16], &sta_mac); // Addr2 = SA
        assert_eq!(&frame[16..22], &ap_mac);  // Addr3 = DA
        assert_eq!(&frame[24..32], &LLC_SNAP_EAPOL);
        assert_eq!(&frame[32..34], &eapol);
    }

    // ── Scan PCAP export test ──

    #[test]
    fn test_export_scan_pcap() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_scan.pcap");
        let path_str = path.to_str().unwrap();

        let frames = vec![
            (vec![0x01, 0x02, 0x03], 1_000_000u64),
            (vec![0x04, 0x05], 2_000_000),
            (vec![0x06, 0x07, 0x08, 0x09], 3_000_000),
        ];

        let stats = export_scan_pcap(path_str, &frames).unwrap();
        assert_eq!(stats.packets, 3);
        // 24 + (16+3) + (16+2) + (16+4) = 81
        assert_eq!(stats.bytes, 81);

        let data = std::fs::read(path_str).unwrap();
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(magic, PCAP_MAGIC);

        let _ignored = std::fs::remove_file(path_str);
    }

    // ── EAP credential export tests ──

    #[test]
    fn test_format_eap_mschapv2() {
        let cred = CapturedCredential {
            client_mac: MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]),
            eap_method: EapMethod::MsChapV2,
            identity: "john@corp.com".to_string(),
            domain: "corp.com".to_string(),
            mschapv2_auth_challenge: Some([0xAA; 16]),
            mschapv2_peer_challenge: Some([0xBB; 16]),
            mschapv2_nt_response: Some([0xCC; 24]),
            leap_challenge: None,
            leap_response: None,
            plaintext_password: None,
            md5_challenge: None,
            md5_response: None,
            md5_id: None,
            rssi: -42,
            timestamp_us: 1_000_000,
        };

        let line = format_eap_credential(&cred);
        // hashcat -m 5500: user::::nt_response:peer_challenge+auth_challenge
        assert!(line.starts_with("john@corp.com::::"));
        assert!(line.contains(&hex_encode(&[0xCC; 24]))); // NT response
        assert!(line.contains(&hex_encode(&[0xBB; 16]))); // peer challenge
        assert!(line.contains(&hex_encode(&[0xAA; 16]))); // auth challenge
    }

    #[test]
    fn test_format_eap_leap() {
        let cred = CapturedCredential {
            client_mac: MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]),
            eap_method: EapMethod::Leap,
            identity: "admin".to_string(),
            domain: String::new(),
            mschapv2_auth_challenge: None,
            mschapv2_peer_challenge: None,
            mschapv2_nt_response: None,
            leap_challenge: Some([0xDD; 8]),
            leap_response: Some([0xEE; 24]),
            plaintext_password: None,
            md5_challenge: None,
            md5_response: None,
            md5_id: None,
            rssi: -55,
            timestamp_us: 2_000_000,
        };

        let line = format_eap_credential(&cred);
        // asleap: challenge:response:username
        assert!(line.starts_with(&hex_encode(&[0xDD; 8])));
        assert!(line.contains(&hex_encode(&[0xEE; 24])));
        assert!(line.ends_with(":admin"));
    }

    #[test]
    fn test_format_eap_md5() {
        let cred = CapturedCredential {
            client_mac: MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]),
            eap_method: EapMethod::Md5,
            identity: "user".to_string(),
            domain: String::new(),
            mschapv2_auth_challenge: None,
            mschapv2_peer_challenge: None,
            mschapv2_nt_response: None,
            leap_challenge: None,
            leap_response: None,
            plaintext_password: None,
            md5_challenge: Some([0x11; 16]),
            md5_response: Some([0x22; 16]),
            md5_id: Some(0x42),
            rssi: -60,
            timestamp_us: 3_000_000,
        };

        let line = format_eap_credential(&cred);
        // hashcat -m 4800: response:challenge:id
        assert!(line.starts_with(&hex_encode(&[0x22; 16])));
        assert!(line.contains(&hex_encode(&[0x11; 16])));
        assert!(line.ends_with(":42"));
    }

    #[test]
    fn test_format_eap_plaintext() {
        let cred = CapturedCredential {
            client_mac: MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]),
            eap_method: EapMethod::Gtc,
            identity: "guest".to_string(),
            domain: String::new(),
            mschapv2_auth_challenge: None,
            mschapv2_peer_challenge: None,
            mschapv2_nt_response: None,
            leap_challenge: None,
            leap_response: None,
            plaintext_password: Some("P@ssw0rd!".to_string()),
            md5_challenge: None,
            md5_response: None,
            md5_id: None,
            rssi: -30,
            timestamp_us: 4_000_000,
        };

        let line = format_eap_credential(&cred);
        assert!(line.contains("EAP-GTC plaintext"));
        assert!(line.contains("guest"));
        assert!(line.contains("P@ssw0rd!"));
    }

    #[test]
    fn test_format_eap_identity_only() {
        let cred = CapturedCredential {
            client_mac: MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]),
            eap_method: EapMethod::Identity,
            identity: "user@example.com".to_string(),
            domain: "example.com".to_string(),
            mschapv2_auth_challenge: None,
            mschapv2_peer_challenge: None,
            mschapv2_nt_response: None,
            leap_challenge: None,
            leap_response: None,
            plaintext_password: None,
            md5_challenge: None,
            md5_response: None,
            md5_id: None,
            rssi: -70,
            timestamp_us: 5_000_000,
        };

        let line = format_eap_credential(&cred);
        assert!(line.contains("no credentials captured"));
        assert!(line.contains("user@example.com"));
    }

    #[test]
    fn test_export_eap_credentials_to_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_eap_creds.txt");
        let path_str = path.to_str().unwrap();

        let cred = CapturedCredential {
            client_mac: MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]),
            eap_method: EapMethod::MsChapV2,
            identity: "test@example.com".to_string(),
            domain: "example.com".to_string(),
            mschapv2_auth_challenge: Some([0xAA; 16]),
            mschapv2_peer_challenge: Some([0xBB; 16]),
            mschapv2_nt_response: Some([0xCC; 24]),
            leap_challenge: None,
            leap_response: None,
            plaintext_password: None,
            md5_challenge: None,
            md5_response: None,
            md5_id: None,
            rssi: -45,
            timestamp_us: 5_000_000,
        };

        let count = export_eap_credentials(path_str, &[cred]).unwrap();
        assert_eq!(count, 1);

        let content = std::fs::read_to_string(path_str).unwrap();
        assert!(content.contains("test@example.com::::"));

        let _ignored = std::fs::remove_file(path_str);
    }

    // ── Batch export test ──

    #[test]
    fn test_export_all_creates_all_formats() {
        let dir = std::env::temp_dir().join("wifikit_test_export_all");
        let _ignored = std::fs::create_dir_all(&dir);
        let dir_str = dir.to_str().unwrap();

        let hs = make_test_handshake();
        let beacon_frames = HashMap::new();

        let result = export_all(dir_str, "test_capture", &[hs], &beacon_frames).unwrap();

        // hc22000: 1 PMKID line + 1 EAPOL line = 2
        assert_eq!(result.hc22000_count, 2);
        assert_eq!(result.pmkid_count, 1);
        // hccapx: 1 record (M1+M2)
        assert_eq!(result.hccapx_count, 1);
        // PCAP: should exist
        assert!(result.pcap_stats.is_some());
        // 3 files: .hc22000 + .hccapx + .pcap
        assert_eq!(result.total_files, 3);

        // Verify files exist
        assert!(std::path::Path::new(&format!("{}/test_capture.hc22000", dir_str)).exists());
        assert!(std::path::Path::new(&format!("{}/test_capture.hccapx", dir_str)).exists());
        assert!(std::path::Path::new(&format!("{}/test_capture.pcap", dir_str)).exists());

        let _ignored = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_export_all_empty_handshakes() {
        let result = export_all("/tmp", "empty", &[], &HashMap::new()).unwrap();
        assert_eq!(result.total_files, 0);
        assert_eq!(result.hc22000_count, 0);
        assert_eq!(result.hccapx_count, 0);
        assert!(result.pcap_stats.is_none());
    }

    // ── Utility tests ──

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_hex_encode_single_byte() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xFF]), "ff");
        assert_eq!(hex_encode(&[0x0A]), "0a");
    }

    #[test]
    fn test_hex_encode_multiple_bytes() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(
            hex_encode(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
            "0123456789abcdef"
        );
    }

    #[test]
    fn test_handshake_quality_ordering() {
        assert!(HandshakeQuality::None < HandshakeQuality::Pmkid);
        assert!(HandshakeQuality::Pmkid < HandshakeQuality::M1M2);
        assert!(HandshakeQuality::M1M2 < HandshakeQuality::M1M2M3);
        assert!(HandshakeQuality::M1M2M3 < HandshakeQuality::Full);
    }

    #[test]
    fn test_handshake_has_eapol() {
        let mut hs = make_test_handshake();
        assert!(hs.has_eapol());

        hs.quality = HandshakeQuality::Pmkid;
        assert!(!hs.has_eapol());

        hs.quality = HandshakeQuality::M1M2;
        assert!(hs.has_eapol());

        hs.m2_frame = None;
        assert!(!hs.has_eapol());
    }

    #[test]
    fn test_handshake_has_pmkid() {
        let mut hs = make_test_handshake();
        assert!(hs.has_pmkid_captured());

        hs.pmkid = None;
        assert!(!hs.has_pmkid_captured());
    }
}
