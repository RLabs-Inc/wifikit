//! Handshake capture engine — stateful EAPOL frame processing + capture database.
//!
//! This module tracks 4-way handshake state across frames for each AP+STA pair.
//! No threads, no I/O — called by the scanner engine to process EAPOL frames.
//! All parsing types come from `protocol::eapol`.
#![allow(dead_code)]
#![allow(unused_imports)]
//!
//! Ported from `wifikit_capture.c` (libwifikit).

use std::time::Instant;

use crate::core::mac::MacAddress;
use crate::protocol::eapol::{
    self, EapCode, EapMethod, EapolKey, HandshakeMessage, HandshakeQuality,
    MessagePair, ParsedEapol,
};

// ═══════════════════════════════════════════════════════════════════════════════
//  Capture Events
// ═══════════════════════════════════════════════════════════════════════════════

/// Discrete event emitted during EAPOL processing.
/// Fired immediately when something interesting happens.
#[derive(Clone, Debug)]
pub enum CaptureEvent {
    /// A handshake message (M1-M4, Group M1/M2) was captured.
    HandshakeMessage {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        message: HandshakeMessage,
        quality: HandshakeQuality,
    },

    /// PMKID extracted from M1 Key Data (clientless attack vector).
    PmkidCaptured {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        pmkid: [u8; 16],
    },

    /// Handshake reached a complete state (all 4 messages captured).
    HandshakeComplete {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        quality: HandshakeQuality,
    },

    /// Handshake quality improved (e.g., M1M2 -> M1M2M3).
    HandshakeQualityImproved {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        old_quality: HandshakeQuality,
        new_quality: HandshakeQuality,
    },

    /// EAP identity captured from enterprise authentication.
    EapIdentityCaptured {
        sta_mac: MacAddress,
        identity: String,
    },

    /// EAP method negotiated (e.g., PEAP, EAP-TLS).
    EapMethodNegotiated {
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        method: EapMethod,
    },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Handshake Entry
// ═══════════════════════════════════════════════════════════════════════════════

/// Complete state for a single AP+STA handshake capture.
///
/// Tracks all 4 messages of the 4-way handshake plus group key handshake,
/// raw frames (for export to pcap/hccapx/hc22000), nonces, MIC, PMKID,
/// and quality state.
#[derive(Clone, Debug)]
pub struct Handshake {
    // === Identifiers ===
    /// AP (authenticator) MAC address / BSSID
    pub ap_mac: MacAddress,
    /// Station (supplicant) MAC address
    pub sta_mac: MacAddress,
    /// Network SSID (from beacon/probe or caller)
    pub ssid: String,

    // === Key data ===
    /// ANonce from M1/M3 (AP's random nonce)
    pub anonce: Option<[u8; 32]>,
    /// SNonce from M2 (STA's random nonce)
    pub snonce: Option<[u8; 32]>,
    /// PMKID extracted from M1 Key Data (clientless attack)
    pub pmkid: Option<[u8; 16]>,
    /// MIC from M2 (what hashcat cracks against)
    pub key_mic: Option<[u8; 16]>,
    /// Key Descriptor Version: 1=HMAC-MD5/RC4, 2=HMAC-SHA1/AES, 3=AES-128-CMAC
    pub key_version: u16,
    /// Key Descriptor Type: 2=RSN, 254=WPA
    pub key_descriptor: u8,
    /// EAPOL version byte from the frame header
    pub eapol_version: u8,

    // === Raw frames (for pcap/hccapx/hc22000 export) ===
    /// Raw EAPOL frame for M1 (complete: header + body)
    pub m1_frame: Option<Vec<u8>>,
    /// Raw EAPOL frame for M2
    pub m2_frame: Option<Vec<u8>>,
    /// Raw EAPOL frame for M3
    pub m3_frame: Option<Vec<u8>>,
    /// Raw EAPOL frame for M4
    pub m4_frame: Option<Vec<u8>>,
    /// Raw EAPOL frame for Group M1
    pub gtk_m1_frame: Option<Vec<u8>>,
    /// Raw EAPOL frame for Group M2
    pub gtk_m2_frame: Option<Vec<u8>>,

    // === State ===
    /// Overall handshake capture quality
    pub quality: HandshakeQuality,
    /// Whether M1 has been captured
    pub has_m1: bool,
    /// Whether M2 has been captured
    pub has_m2: bool,
    /// Whether M3 has been captured
    pub has_m3: bool,
    /// Whether M4 has been captured
    pub has_m4: bool,
    /// Whether a Group Key handshake was captured
    pub has_gtk: bool,
    /// Whether a PMKID was extracted from M1
    pub has_pmkid: bool,

    // === Timing ===
    /// When this handshake entry was first created
    pub first_seen: Instant,
    /// When this handshake entry was last updated
    pub last_updated: Instant,
    /// Timestamp (microseconds from scan start) of M1 capture
    pub m1_timestamp: Option<u64>,
    /// Timestamp (microseconds from scan start) of M2 capture
    pub m2_timestamp: Option<u64>,
    /// Timestamp (microseconds from scan start) of M3 capture
    pub m3_timestamp: Option<u64>,
    /// Timestamp (microseconds from scan start) of M4 capture
    pub m4_timestamp: Option<u64>,

    // === Replay counter tracking ===
    /// Replay counter from M1
    pub replay_counter_m1: u64,
    /// Replay counter from M2
    pub replay_counter_m2: u64,

    // === Message pair (for hccapx export) ===
    /// How M1/M2/M3 relate by replay counter
    pub message_pair: Option<MessagePair>,

    // === EAP identity (enterprise networks) ===
    /// EAP identity string captured during enterprise auth
    pub eap_identity: Option<String>,
    /// Negotiated EAP method type
    pub eap_type: Option<EapMethod>,
}

impl Handshake {
    /// Create a new empty handshake entry for the given AP+STA pair.
    pub fn new(ap_mac: MacAddress, sta_mac: MacAddress, ssid: String) -> Self {
        let now = Instant::now();
        Self {
            ap_mac,
            sta_mac,
            ssid,
            anonce: None,
            snonce: None,
            pmkid: None,
            key_mic: None,
            key_version: 0,
            key_descriptor: 0,
            eapol_version: 0,
            m1_frame: None,
            m2_frame: None,
            m3_frame: None,
            m4_frame: None,
            gtk_m1_frame: None,
            gtk_m2_frame: None,
            quality: HandshakeQuality::None,
            has_m1: false,
            has_m2: false,
            has_m3: false,
            has_m4: false,
            has_gtk: false,
            has_pmkid: false,
            first_seen: now,
            last_updated: now,
            m1_timestamp: None,
            m2_timestamp: None,
            m3_timestamp: None,
            m4_timestamp: None,
            replay_counter_m1: 0,
            replay_counter_m2: 0,
            message_pair: None,
            eap_identity: None,
            eap_type: None,
        }
    }

    /// Returns true if this handshake has enough data for EAPOL-based cracking.
    /// Requires at minimum M1 (for ANonce) + M2 (for SNonce, MIC, EAPOL frame).
    pub fn has_eapol(&self) -> bool {
        self.quality >= HandshakeQuality::M1M2 && self.m2_frame.is_some()
    }

    /// Returns true if a PMKID was captured (clientless attack).
    pub fn has_pmkid_captured(&self) -> bool {
        self.pmkid.is_some()
    }

    /// Reset handshake state for a new attempt (new M1 with different ANonce).
    /// Preserves identity info, SSID, and MAC addresses.
    fn reset_handshake(&mut self) {
        self.m1_frame = None;
        self.m2_frame = None;
        self.m3_frame = None;
        self.m4_frame = None;
        self.has_m1 = false;
        self.has_m2 = false;
        self.has_m3 = false;
        self.has_m4 = false;
        self.has_pmkid = false;
        self.anonce = None;
        self.snonce = None;
        self.pmkid = None;
        self.key_mic = None;
        self.replay_counter_m1 = 0;
        self.replay_counter_m2 = 0;
        self.message_pair = None;
        self.m1_timestamp = None;
        self.m2_timestamp = None;
        self.m3_timestamp = None;
        self.m4_timestamp = None;
        self.quality = HandshakeQuality::None;
    }

    /// Recalculate handshake quality from message flags.
    /// Returns (old_quality, new_quality) so callers can detect quality improvements
    /// and emit HandshakeQualityImproved events.
    /// Mirrors `hs_update_quality` from C reference.
    fn update_quality(&mut self) -> (HandshakeQuality, HandshakeQuality) {
        let old = self.quality;

        if self.has_m1 && self.has_m2 && self.has_m3 && self.has_m4 {
            self.quality = HandshakeQuality::Full;
        } else if self.has_m1 && self.has_m2 && self.has_m3 {
            self.quality = HandshakeQuality::M1M2M3;
        } else if self.has_m1 && self.has_m2 {
            self.quality = HandshakeQuality::M1M2;
        } else if self.has_pmkid {
            self.quality = HandshakeQuality::Pmkid;
        } else {
            self.quality = HandshakeQuality::None;
        }

        // Determine message pair for hccapx when we have M1+M2
        if self.has_m1 && self.has_m2 {
            self.message_pair = Some(eapol::determine_message_pair(
                self.replay_counter_m1,
                self.replay_counter_m2,
                self.has_m3,
            ));
        }

        (old, self.quality)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EAP Identity Entry
// ═══════════════════════════════════════════════════════════════════════════════

/// Captured EAP identity from enterprise authentication.
#[derive(Clone, Debug)]
pub struct EapIdentity {
    /// Station MAC address that sent the identity
    pub sta_mac: MacAddress,
    /// AP BSSID the station was authenticating to
    pub ap_mac: MacAddress,
    /// The identity string (e.g., "user@corp.com")
    pub identity: String,
    /// Realm portion after '@' if present (e.g., "corp.com")
    pub realm: Option<String>,
    /// Negotiated EAP method (if seen in subsequent Request)
    pub eap_type: Option<EapMethod>,
    /// When this identity was captured
    pub timestamp: Instant,
}

impl EapIdentity {
    fn new(sta_mac: MacAddress, ap_mac: MacAddress, identity: String) -> Self {
        let realm = identity
            .find('@')
            .map(|pos| identity[pos + 1..].to_string());
        Self {
            sta_mac,
            ap_mac,
            identity,
            realm,
            eap_type: None,
            timestamp: Instant::now(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Capture Statistics
// ═══════════════════════════════════════════════════════════════════════════════

/// Summary statistics for the capture database.
#[derive(Clone, Debug)]
pub struct CaptureStats {
    /// Total number of tracked handshake entries (AP+STA pairs)
    pub total_handshakes: usize,
    /// Handshakes with quality >= M1M2 (crackable)
    pub crackable_handshakes: usize,
    /// Handshakes with quality == Full
    pub complete_handshakes: usize,
    /// Number of PMKIDs captured
    pub pmkid_captures: usize,
    /// Number of EAP identities captured
    pub eap_identities: usize,
    /// Best handshake quality across all entries
    pub best_quality: HandshakeQuality,
    /// Number of unique APs with any handshake data
    pub unique_aps: usize,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Capture Database
// ═══════════════════════════════════════════════════════════════════════════════

/// Stateful database tracking all captured handshakes and EAP identities.
///
/// Called by the scanner engine each time an EAPOL frame is received.
/// No threads, no I/O — pure state management.
#[derive(Clone, Debug)]
pub struct CaptureDatabase {
    /// All tracked handshake entries, indexed by insertion order
    handshakes: Vec<Handshake>,
    /// Maximum number of handshake entries to track (default: 64)
    max_handshakes: usize,

    /// Captured EAP identities (enterprise networks)
    eap_identities: Vec<EapIdentity>,
    /// Maximum number of EAP identities to track (default: 128)
    max_eap_identities: usize,

    /// Total EAPOL frames processed (for stats)
    pub frames_processed: u64,
}

impl CaptureDatabase {
    /// Create a new capture database with default capacities.
    ///
    /// Default: 512 handshakes, 128 EAP identities.
    /// Higher capacity because we keep ALL handshake attempts (not just latest).
    pub fn new() -> Self {
        Self::with_capacity(512, 128)
    }

    /// Create a new capture database with explicit capacity limits.
    ///
    /// # Arguments
    /// * `max_hs` - Maximum number of AP+STA handshake entries
    /// * `max_eap` - Maximum number of EAP identity entries
    pub fn with_capacity(max_hs: usize, max_eap: usize) -> Self {
        Self {
            handshakes: Vec::with_capacity(max_hs.min(256)),
            max_handshakes: max_hs,
            eap_identities: Vec::with_capacity(max_eap.min(512)),
            max_eap_identities: max_eap,
            frames_processed: 0,
        }
    }

    /// Find an existing handshake entry for the given AP+STA pair.
    /// Find the most recent handshake entry for the given AP+STA pair.
    pub fn find(&self, ap_mac: &MacAddress, sta_mac: &MacAddress) -> Option<&Handshake> {
        let idx = self.handshakes.iter().rposition(|hs| hs.ap_mac == *ap_mac && hs.sta_mac == *sta_mac)?;
        Some(&self.handshakes[idx])
    }

    /// Find an existing handshake entry for the given AP+STA pair (mutable, last/latest).
    fn find_mut(&mut self, ap_mac: &MacAddress, sta_mac: &MacAddress) -> Option<&mut Handshake> {
        let idx = self.handshakes.iter().rposition(|hs| hs.ap_mac == *ap_mac && hs.sta_mac == *sta_mac)?;
        Some(&mut self.handshakes[idx])
    }

    /// Find the LAST (most recent) entry for this pair — used by process_m1 after pushing.
    fn find_last_mut(&mut self, ap_mac: &MacAddress, sta_mac: &MacAddress) -> Option<&mut Handshake> {
        let idx = self.handshakes.iter().rposition(|hs| hs.ap_mac == *ap_mac && hs.sta_mac == *sta_mac)?;
        Some(&mut self.handshakes[idx])
    }

    /// Find or create a handshake entry for the given AP+STA pair.
    ///
    /// If the database is full, returns `None` (matches C behavior).
    fn find_or_create(
        &mut self,
        ap_mac: MacAddress,
        sta_mac: MacAddress,
        ssid: &str,
    ) -> Option<&mut Handshake> {
        // Find the LAST (most recent) entry — M2/M3/M4 go to the latest attempt
        if let Some(idx) = self
            .handshakes
            .iter()
            .rposition(|hs| hs.ap_mac == ap_mac && hs.sta_mac == sta_mac)
        {
            // Update SSID if we now have one and didn't before
            if !ssid.is_empty() && self.handshakes[idx].ssid.is_empty() {
                self.handshakes[idx].ssid = ssid.to_string();
            }
            return Some(&mut self.handshakes[idx]);
        }

        // Create new entry if there's room
        if self.handshakes.len() >= self.max_handshakes {
            return None;
        }

        self.handshakes
            .push(Handshake::new(ap_mac, sta_mac, ssid.to_string()));
        self.handshakes.last_mut()
    }

    /// All tracked handshakes.
    pub fn handshakes(&self) -> &[Handshake] {
        &self.handshakes
    }

    /// Handshakes for a specific AP (by BSSID).
    pub fn handshakes_for_ap(&self, ap_mac: &MacAddress) -> Vec<&Handshake> {
        self.handshakes
            .iter()
            .filter(|hs| hs.ap_mac == *ap_mac)
            .collect()
    }

    /// Best handshake for an AP (highest quality, most recent if tied).
    pub fn best_handshake(&self, ap_mac: &MacAddress) -> Option<&Handshake> {
        self.handshakes
            .iter()
            .filter(|hs| hs.ap_mac == *ap_mac)
            .max_by(|a, b| {
                a.quality
                    .cmp(&b.quality)
                    .then(a.last_updated.cmp(&b.last_updated))
            })
    }

    /// All captured EAP identities.
    pub fn eap_identities(&self) -> &[EapIdentity] {
        &self.eap_identities
    }

    /// Compute summary statistics.
    pub fn stats(&self) -> CaptureStats {
        let mut stats = CaptureStats {
            total_handshakes: self.handshakes.len(),
            crackable_handshakes: 0,
            complete_handshakes: 0,
            pmkid_captures: 0,
            eap_identities: 0,
            best_quality: HandshakeQuality::None,
            unique_aps: 0,
        };

        let mut ap_set = std::collections::HashSet::new();

        for hs in &self.handshakes {
            if hs.quality >= HandshakeQuality::M1M2 {
                stats.crackable_handshakes += 1;
            }
            if hs.quality == HandshakeQuality::Full {
                stats.complete_handshakes += 1;
            }
            if hs.has_pmkid {
                stats.pmkid_captures += 1;
            }
            if hs.quality > stats.best_quality {
                stats.best_quality = hs.quality;
            }
            ap_set.insert(hs.ap_mac);
        }

        stats.eap_identities = self.eap_identities.len();
        stats.unique_aps = ap_set.len();
        stats
    }

    /// Number of handshake entries currently tracked.
    pub fn handshake_count(&self) -> usize {
        self.handshakes.len()
    }

    /// Number of EAP identities currently tracked.
    pub fn eap_identity_count(&self) -> usize {
        self.eap_identities.len()
    }
}

impl Default for CaptureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Frame Processing — Main Entry Points
// ═══════════════════════════════════════════════════════════════════════════════

/// Process an EAPOL frame from the scanner.
///
/// This is the main entry point called by the scan engine when it detects an
/// EAPOL frame (LLC/SNAP EtherType 0x888E) in a data frame.
///
/// The `eapol_data` should be raw EAPOL bytes starting from the EAPOL header
/// (version, type, length). NOT including LLC/SNAP.
///
/// Returns a list of events for anything interesting that happened.
///
/// # Arguments
/// * `db` - The capture database to update
/// * `ap_mac` - BSSID of the AP
/// * `sta_mac` - MAC of the station
/// * `ssid` - SSID of the network (may be empty if unknown)
/// * `eapol_data` - Raw EAPOL frame starting from EAPOL header
/// * `timestamp` - Timestamp in microseconds from scan start
pub fn process_eapol_frame(
    db: &mut CaptureDatabase,
    ap_mac: MacAddress,
    sta_mac: MacAddress,
    ssid: &str,
    eapol_data: &[u8],
    timestamp: u64,
) -> Vec<CaptureEvent> {
    db.frames_processed += 1;

    // Parse the raw EAPOL frame
    let parsed = match eapol::parse_raw_eapol(eapol_data) {
        Some(p) => p,
        None => return Vec::new(),
    };

    match parsed {
        ParsedEapol::Key {
            header,
            key,
            message,
            raw_eapol,
        } => process_eapol_key(db, ap_mac, sta_mac, ssid, header.version, &key, message, raw_eapol, timestamp),

        ParsedEapol::Eap { header: _, eap } => {
            process_eap_packet(db, ap_mac, sta_mac, &eap, timestamp)
        }

        ParsedEapol::Start { .. } | ParsedEapol::Logoff { .. } => {
            // EAPOL-Start and Logoff don't carry handshake data
            Vec::new()
        }
    }
}

/// Process a data frame payload that may contain EAPOL (with LLC/SNAP header).
///
/// Convenience function that handles the LLC/SNAP detection before delegating
/// to `process_eapol_frame`.
///
/// # Arguments
/// * `db` - The capture database to update
/// * `ap_mac` - BSSID of the AP
/// * `sta_mac` - MAC of the station
/// * `ssid` - SSID of the network (may be empty if unknown)
/// * `payload` - Data frame payload starting from LLC/SNAP header
/// * `timestamp` - Timestamp in microseconds from scan start
pub fn process_data_payload(
    db: &mut CaptureDatabase,
    ap_mac: MacAddress,
    sta_mac: MacAddress,
    ssid: &str,
    payload: &[u8],
    timestamp: u64,
) -> Vec<CaptureEvent> {
    db.frames_processed += 1;

    let parsed = match eapol::parse_from_data_frame(payload) {
        Some(p) => p,
        None => return Vec::new(),
    };

    match parsed {
        ParsedEapol::Key {
            header,
            key,
            message,
            raw_eapol,
        } => process_eapol_key(db, ap_mac, sta_mac, ssid, header.version, &key, message, raw_eapol, timestamp),

        ParsedEapol::Eap { header: _, eap } => {
            process_eap_packet(db, ap_mac, sta_mac, &eap, timestamp)
        }

        ParsedEapol::Start { .. } | ParsedEapol::Logoff { .. } => Vec::new(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Internal: EAPOL-Key Processing (4-way + group key handshake)
// ═══════════════════════════════════════════════════════════════════════════════

/// Process an EAPOL-Key frame. This is the core handshake state machine.
///
/// Mirrors `scan_process_eapol` from C reference for EAPOL-Key type.
fn process_eapol_key(
    db: &mut CaptureDatabase,
    ap_mac: MacAddress,
    sta_mac: MacAddress,
    ssid: &str,
    eapol_version: u8,
    key: &EapolKey,
    message: HandshakeMessage,
    raw_eapol: Vec<u8>,
    timestamp: u64,
) -> Vec<CaptureEvent> {
    let mut events = Vec::new();

    // ── M1 is handled separately — never destroys existing captures ──
    if message == HandshakeMessage::M1 {
        return process_m1(db, ap_mac, sta_mac, ssid, eapol_version, key, raw_eapol, timestamp);
    }

    // ── M2/M3/M4/Group: find the latest entry for this pair ──
    let hs = match db.find_or_create(ap_mac, sta_mac, ssid) {
        Some(hs) => hs,
        None => return events, // database full
    };

    // Store EAPOL version and key descriptor info
    hs.eapol_version = eapol_version;
    hs.key_version = key.key_info.version;
    hs.key_descriptor = key.descriptor as u8;

    let old_quality = hs.quality;

    // DEBUG: Log every EAPOL message entering the capture state machine
    {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true).append(true)
            .open("/tmp/wifikit_capture_sm.log")
        {
            let _ = writeln!(f, "[{}] {:?} ap={} sta={} has_m1={} has_m2={} has_m3={} has_m4={} anonce_match={} replay_m2={}",
                timestamp, message, ap_mac, sta_mac,
                hs.has_m1, hs.has_m2, hs.has_m3, hs.has_m4,
                hs.anonce.as_ref().map_or("none".to_string(), |a| {
                    if *a == key.nonce { "YES".to_string() } else { "NO".to_string() }
                }),
                if hs.has_m2 { format!("{}", hs.replay_counter_m2 == key.replay_counter) } else { "n/a".to_string() },
            );
        }
    }

    match message {
        HandshakeMessage::M1 => unreachable!(), // handled above

        // ── M2: STA -> AP (SNonce + MIC) ──
        HandshakeMessage::M2 => {
            // Must have M1 first
            if !hs.has_m1 {
                return events;
            }

            // Check for retransmission (same replay counter)
            if hs.has_m2 && hs.replay_counter_m2 == key.replay_counter {
                return events; // retransmission
            }

            // Store SNonce and MIC
            hs.snonce = Some(key.nonce);
            hs.replay_counter_m2 = key.replay_counter;
            hs.m2_timestamp = Some(timestamp);
            hs.key_mic = Some(key.mic);
            hs.m2_frame = Some(raw_eapol);
            hs.has_m2 = true;
        }

        // ── M3: AP -> STA (GTK encrypted in Key Data) ──
        HandshakeMessage::M3 => {
            // Must have M1+M2
            if !hs.has_m2 {
                return events;
            }

            // Verify ANonce matches M1 (same handshake attempt)
            if let Some(ref anonce) = hs.anonce {
                if *anonce != key.nonce {
                    return events; // different handshake
                }
            }

            hs.m3_timestamp = Some(timestamp);
            hs.m3_frame = Some(raw_eapol);
            hs.has_m3 = true;
        }

        // ── M4: STA -> AP (ACK — handshake complete) ──
        HandshakeMessage::M4 => {
            // Must have M1+M2+M3
            if !hs.has_m3 {
                return events;
            }

            hs.m4_timestamp = Some(timestamp);
            hs.m4_frame = Some(raw_eapol);
            hs.has_m4 = true;
        }

        // ── Group M1: AP -> STA (new GTK) ──
        HandshakeMessage::GroupM1 => {
            hs.has_gtk = true;
            hs.gtk_m1_frame = Some(raw_eapol);
        }

        // ── Group M2: STA -> AP (ACK) ──
        HandshakeMessage::GroupM2 => {
            hs.gtk_m2_frame = Some(raw_eapol);
        }
    }

    // Update quality and timing
    hs.update_quality();
    hs.last_updated = Instant::now();

    let new_quality = hs.quality;

    // Emit message event
    events.push(CaptureEvent::HandshakeMessage {
        ap_mac,
        sta_mac,
        message,
        quality: new_quality,
    });

    // Emit quality improvement event
    if new_quality > old_quality {
        events.push(CaptureEvent::HandshakeQualityImproved {
            ap_mac,
            sta_mac,
            old_quality,
            new_quality,
        });
    }

    // Emit completion event
    if new_quality == HandshakeQuality::Full && old_quality != HandshakeQuality::Full {
        events.push(CaptureEvent::HandshakeComplete {
            ap_mac,
            sta_mac,
            quality: new_quality,
        });
    }

    events
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Internal: EAP Processing (enterprise identity/method capture)
// ═══════════════════════════════════════════════════════════════════════════════

/// Process an EAP packet (inside EAPOL type=0).
///
/// Captures EAP-Identity Response strings and tracks negotiated EAP methods.
/// Mirrors the EAP handling in `scan_process_eapol` from C reference.
fn process_eap_packet(
    db: &mut CaptureDatabase,
    ap_mac: MacAddress,
    sta_mac: MacAddress,
    eap: &eapol::EapPacket,
    _timestamp: u64,
) -> Vec<CaptureEvent> {
    let mut events = Vec::new();

    // EAP-Identity Response: capture the identity string
    if let Some(ref identity) = eapol::extract_eap_identity(eap) {
        if !identity.is_empty() && db.eap_identities.len() < db.max_eap_identities {
            db.eap_identities
                .push(EapIdentity::new(sta_mac, ap_mac, identity.clone()));

            // Also store in any matching handshake entry
            if let Some(hs) = db.find_mut(&ap_mac, &sta_mac) {
                hs.eap_identity = Some(identity.clone());
            }

            events.push(CaptureEvent::EapIdentityCaptured {
                sta_mac,
                identity: identity.clone(),
            });
        }
    }

    // Track negotiated EAP method from Request (code=1)
    if eap.code == EapCode::Request {
        if let Some(method) = eap.eap_type {
            if method != EapMethod::Identity {
                // Store method in handshake entry
                if let Some(hs) = db.find_mut(&ap_mac, &sta_mac) {
                    hs.eap_type = Some(method);
                }

                // Store method in EAP identity entry
                for eid in &mut db.eap_identities {
                    if eid.sta_mac == sta_mac && eid.ap_mac == ap_mac {
                        eid.eap_type = Some(method);
                    }
                }

                events.push(CaptureEvent::EapMethodNegotiated {
                    ap_mac,
                    sta_mac,
                    method,
                });
            }
        }
    }

    events
}

// ═══════════════════════════════════════════════════════════════════════════════
//  M1 processing — preserves existing captures, creates new entries
// ═══════════════════════════════════════════════════════════════════════════════

/// Process an EAPOL M1 frame. Never destroys existing handshake data.
///
/// When a new M1 arrives with a different ANonce:
/// - If the current entry already has M1 data → create a NEW entry (preserve old)
/// - If the current entry is empty → use it directly
///
/// This ensures deauth attacks don't destroy captured handshakes when
/// clients reconnect repeatedly.
fn process_m1(
    db: &mut CaptureDatabase,
    ap_mac: MacAddress,
    sta_mac: MacAddress,
    ssid: &str,
    eapol_version: u8,
    key: &EapolKey,
    raw_eapol: Vec<u8>,
    timestamp: u64,
) -> Vec<CaptureEvent> {
    let mut events = Vec::new();

    // Check for retransmission (same nonce as latest entry)
    if let Some(existing) = db.find(& ap_mac, &sta_mac) {
        if existing.has_m1 {
            if let Some(ref anonce) = existing.anonce {
                if *anonce == key.nonce {
                    return events; // retransmission — ignore
                }
            }
        }
    }

    // Decide: reuse existing empty entry or create new one
    let needs_new_entry = db.find(&ap_mac, &sta_mac)
        .map_or(false, |hs| hs.has_m1);

    if needs_new_entry {
        // Existing entry has data — create a fresh entry to preserve it
        if db.handshakes.len() < db.max_handshakes {
            db.handshakes.push(Handshake::new(ap_mac, sta_mac, ssid.to_string()));
        } else {
            // Database full — find the worst quality entry for this pair and reuse it
            if let Some(idx) = db.handshakes.iter().position(|hs|
                hs.ap_mac == ap_mac && hs.sta_mac == sta_mac
                && hs.quality == HandshakeQuality::None
            ) {
                db.handshakes[idx] = Handshake::new(ap_mac, sta_mac, ssid.to_string());
            } else {
                return events; // all entries have useful data, don't destroy
            }
        }
    } else if db.find(&ap_mac, &sta_mac).is_none() {
        // No entry at all — create one
        if db.handshakes.len() >= db.max_handshakes {
            return events; // database full
        }
        db.handshakes.push(Handshake::new(ap_mac, sta_mac, ssid.to_string()));
    }

    // Now get the latest entry (the one we just created or the empty existing one)
    let hs = match db.find_last_mut(&ap_mac, &sta_mac) {
        Some(hs) => hs,
        None => return events,
    };

    // Store M1 data
    hs.eapol_version = eapol_version;
    hs.key_version = key.key_info.version;
    hs.key_descriptor = key.descriptor as u8;
    hs.anonce = Some(key.nonce);
    hs.replay_counter_m1 = key.replay_counter;
    hs.m1_timestamp = Some(timestamp);
    hs.m1_frame = Some(raw_eapol);
    hs.has_m1 = true;
    hs.last_updated = Instant::now();

    // Extract PMKID from Key Data
    if !key.key_data.is_empty() {
        if let Some(pmkid) = eapol::extract_pmkid(&key.key_data) {
            hs.pmkid = Some(pmkid);
            hs.has_pmkid = true;
            events.push(CaptureEvent::PmkidCaptured { ap_mac, sta_mac, pmkid });
        }
    }

    // Update quality (PMKID alone = Pmkid quality)
    hs.update_quality();

    events.push(CaptureEvent::HandshakeMessage {
        ap_mac, sta_mac,
        message: HandshakeMessage::M1,
        quality: hs.quality,
    });

    events
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    const AP: MacAddress = MacAddress([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
    const STA: MacAddress = MacAddress([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);
    const SSID: &str = "TestNetwork";

    // Key info bit constants (matching eapol.rs internals)
    const KI_PAIRWISE: u16 = 0x0008;
    const KI_INSTALL: u16 = 0x0040;
    const KI_ACK: u16 = 0x0080;
    const KI_MIC: u16 = 0x0100;
    const KI_SECURE: u16 = 0x0200;
    const KI_ENCRYPTED: u16 = 0x1000;

    /// Build a complete raw EAPOL frame (header + key body) for testing.
    fn build_eapol_frame(
        key_info: u16,
        replay: u64,
        nonce: &[u8; 32],
        mic: &[u8; 16],
        key_data: &[u8],
    ) -> Vec<u8> {
        // EAPOL-Key body
        let body_len = 95 + key_data.len();
        let mut body = vec![0u8; body_len];
        body[0] = 2; // descriptor type = RSN
        body[1..3].copy_from_slice(&key_info.to_be_bytes());
        body[3..5].copy_from_slice(&16u16.to_be_bytes()); // key length
        body[5..13].copy_from_slice(&replay.to_be_bytes());
        body[13..45].copy_from_slice(nonce);
        // IV, RSC, KEY_ID = zeros
        body[77..93].copy_from_slice(mic);
        body[93..95].copy_from_slice(&(key_data.len() as u16).to_be_bytes());
        if !key_data.is_empty() {
            body[95..].copy_from_slice(key_data);
        }

        // EAPOL header
        let mut frame = Vec::with_capacity(4 + body_len);
        frame.push(0x02); // version
        frame.push(0x03); // type = Key
        frame.extend_from_slice(&(body_len as u16).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    fn build_m1(replay: u64, anonce: &[u8; 32], key_data: &[u8]) -> Vec<u8> {
        let ki = KI_PAIRWISE | KI_ACK | 2;
        build_eapol_frame(ki, replay, anonce, &[0u8; 16], key_data)
    }

    fn build_m2(replay: u64, snonce: &[u8; 32]) -> Vec<u8> {
        let ki = KI_PAIRWISE | KI_MIC | 2;
        build_eapol_frame(ki, replay, snonce, &[0xCC; 16], &[])
    }

    fn build_m3(replay: u64, anonce: &[u8; 32]) -> Vec<u8> {
        let ki = KI_PAIRWISE | KI_ACK | KI_MIC | KI_INSTALL | KI_SECURE | KI_ENCRYPTED | 2;
        build_eapol_frame(ki, replay, anonce, &[0xDD; 16], &[0xEE; 32])
    }

    fn build_m4(replay: u64) -> Vec<u8> {
        let ki = KI_PAIRWISE | KI_MIC | KI_SECURE | 2;
        build_eapol_frame(ki, replay, &[0u8; 32], &[0xFF; 16], &[])
    }

    fn build_eap_identity_response(identity: &[u8]) -> Vec<u8> {
        let eap_len = (5 + identity.len()) as u16;
        let mut eap_body = vec![
            0x02, // Response
            0x01, // ID
            (eap_len >> 8) as u8,
            (eap_len & 0xFF) as u8,
            0x01, // Identity type
        ];
        eap_body.extend_from_slice(identity);

        // Wrap in EAPOL header
        let mut frame = Vec::new();
        frame.push(0x01); // version
        frame.push(0x00); // type = EAP
        frame.extend_from_slice(&(eap_body.len() as u16).to_be_bytes());
        frame.extend_from_slice(&eap_body);
        frame
    }

    // ── Database creation ──

    #[test]
    fn test_database_new_empty() {
        let db = CaptureDatabase::new();
        assert_eq!(db.handshake_count(), 0);
        assert_eq!(db.eap_identity_count(), 0);
        assert_eq!(db.frames_processed, 0);
        let stats = db.stats();
        assert_eq!(stats.total_handshakes, 0);
        assert_eq!(stats.best_quality, HandshakeQuality::None);
    }

    #[test]
    fn test_database_with_capacity() {
        let db = CaptureDatabase::with_capacity(8, 16);
        assert_eq!(db.max_handshakes, 8);
        assert_eq!(db.max_eap_identities, 16);
    }

    // ── Single message processing ──

    #[test]
    fn test_process_m1_creates_entry() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let frame = build_m1(1, &anonce, &[]);

        let events = process_eapol_frame(&mut db, AP, STA, SSID, &frame, 1000);

        assert_eq!(db.handshake_count(), 1);
        let hs = db.find(&AP, &STA).unwrap();
        assert!(hs.has_m1);
        assert!(!hs.has_m2);
        assert_eq!(hs.anonce, Some(anonce));
        assert_eq!(hs.ssid, SSID);
        assert_eq!(hs.quality, HandshakeQuality::None); // M1 alone = no quality
        assert_eq!(hs.m1_timestamp, Some(1000));
        assert!(hs.m1_frame.is_some());

        // Should emit a HandshakeMessage event
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeMessage { message: HandshakeMessage::M1, .. }
        )));
    }

    #[test]
    fn test_process_m1_with_pmkid() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let pmkid_bytes: [u8; 16] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                                      0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        let mut kde = vec![0xDD, 20, 0x00, 0x0F, 0xAC, 0x04];
        kde.extend_from_slice(&pmkid_bytes);

        let frame = build_m1(1, &anonce, &kde);
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &frame, 1000);

        let hs = db.find(&AP, &STA).unwrap();
        assert!(hs.has_pmkid);
        assert_eq!(hs.pmkid, Some(pmkid_bytes));
        assert_eq!(hs.quality, HandshakeQuality::Pmkid);

        // Should emit PmkidCaptured event
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::PmkidCaptured { pmkid, .. } if *pmkid == pmkid_bytes
        )));
    }

    #[test]
    fn test_m2_without_m1_ignored() {
        let mut db = CaptureDatabase::new();
        let snonce = [0xBB; 32];
        let frame = build_m2(1, &snonce);

        let events = process_eapol_frame(&mut db, AP, STA, SSID, &frame, 2000);

        // M2 without prior M1 creates the entry but doesn't set has_m2
        // because the state machine requires M1 first
        // Actually it won't find_or_create with has_m1=false check
        // Let's verify: the entry IS created (find_or_create runs) but M2 is rejected
        // Actually looking at the code: find_or_create creates the entry,
        // then process_eapol_key checks has_m1 and returns early.
        // The entry still exists but with no useful data.
        let hs = db.find(&AP, &STA);
        // The entry was created but M2 was not stored
        if let Some(hs) = hs {
            assert!(!hs.has_m2);
        }
        // Only the message event for M2 should NOT be emitted (returned early)
        assert!(events.is_empty() || !events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeMessage { message: HandshakeMessage::M2, .. }
        )));
    }

    // ── Full 4-way handshake ──

    #[test]
    fn test_full_4way_handshake() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let snonce = [0xBB; 32];

        // M1
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeMessage { message: HandshakeMessage::M1, .. }
        )));

        // M2
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &snonce), 2000);
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeQualityImproved { new_quality: HandshakeQuality::M1M2, .. }
        )));

        let hs = db.find(&AP, &STA).unwrap();
        assert_eq!(hs.quality, HandshakeQuality::M1M2);
        assert_eq!(hs.snonce, Some(snonce));
        assert!(hs.key_mic.is_some());

        // M3
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &build_m3(2, &anonce), 3000);
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeQualityImproved { new_quality: HandshakeQuality::M1M2M3, .. }
        )));

        let hs = db.find(&AP, &STA).unwrap();
        assert_eq!(hs.quality, HandshakeQuality::M1M2M3);

        // M4
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &build_m4(2), 4000);
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeComplete { quality: HandshakeQuality::Full, .. }
        )));
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeQualityImproved {
                old_quality: HandshakeQuality::M1M2M3,
                new_quality: HandshakeQuality::Full,
                ..
            }
        )));

        let hs = db.find(&AP, &STA).unwrap();
        assert_eq!(hs.quality, HandshakeQuality::Full);
        assert!(hs.has_m1);
        assert!(hs.has_m2);
        assert!(hs.has_m3);
        assert!(hs.has_m4);
        assert!(hs.m1_frame.is_some());
        assert!(hs.m2_frame.is_some());
        assert!(hs.m3_frame.is_some());
        assert!(hs.m4_frame.is_some());
        assert_eq!(hs.m1_timestamp, Some(1000));
        assert_eq!(hs.m4_timestamp, Some(4000));
    }

    // ── Retransmission handling ──

    #[test]
    fn test_m1_retransmission_ignored() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];

        // First M1
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        assert!(db.find(&AP, &STA).unwrap().has_m1);

        // Same M1 again (retransmission — same nonce)
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1100);
        // Should be empty — retransmission detected
        assert!(events.is_empty());
    }

    #[test]
    fn test_new_m1_preserves_old_creates_new() {
        let mut db = CaptureDatabase::new();
        let anonce1 = [0xAA; 32];
        let anonce2 = [0xBB; 32]; // different nonce = new handshake attempt
        let snonce = [0xCC; 32];

        // M1 + M2 with first nonce → M1M2 quality
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce1, &[]), 1000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &snonce), 2000);
        assert_eq!(db.handshake_count(), 1);
        assert_eq!(db.handshakes()[0].quality, HandshakeQuality::M1M2);

        // New M1 with different nonce — creates NEW entry, old preserved
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(3, &anonce2, &[]), 3000);
        assert_eq!(db.handshake_count(), 2);

        // Old entry still has M1M2
        assert_eq!(db.handshakes()[0].quality, HandshakeQuality::M1M2);
        assert_eq!(db.handshakes()[0].anonce, Some(anonce1));

        // New entry has only M1
        assert!(db.handshakes()[1].has_m1);
        assert!(!db.handshakes()[1].has_m2);
        assert_eq!(db.handshakes()[1].anonce, Some(anonce2));
        assert_eq!(db.handshakes()[1].quality, HandshakeQuality::None);
    }

    #[test]
    fn test_m2_retransmission_ignored() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let snonce = [0xBB; 32];

        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &snonce), 2000);

        // Same M2 again (same replay counter)
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &snonce), 2100);
        assert!(events.is_empty());
    }

    // ── M3 nonce verification ──

    #[test]
    fn test_m3_wrong_anonce_rejected() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let wrong_anonce = [0xFF; 32];
        let snonce = [0xBB; 32];

        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &snonce), 2000);

        // M3 with wrong ANonce
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &build_m3(2, &wrong_anonce), 3000);
        // Should be rejected — no M3 stored
        assert!(events.is_empty());
        assert!(!db.find(&AP, &STA).unwrap().has_m3);
    }

    // ── M4 without M3 ──

    #[test]
    fn test_m4_without_m3_rejected() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let snonce = [0xBB; 32];

        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &snonce), 2000);

        // Skip M3, send M4
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &build_m4(2), 4000);
        assert!(events.is_empty());
        assert!(!db.find(&AP, &STA).unwrap().has_m4);
    }

    // ── Group key handshake ──

    #[test]
    fn test_group_key_handshake() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let snonce = [0xBB; 32];

        // Complete 4-way first
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &snonce), 2000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m3(2, &anonce), 3000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m4(2), 4000);

        // Group M1
        let ki_g1 = KI_ACK | KI_MIC | KI_SECURE | KI_ENCRYPTED | 2;
        let g1 = build_eapol_frame(ki_g1, 5, &[0u8; 32], &[0xAA; 16], &[0xBB; 32]);
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &g1, 5000);
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeMessage { message: HandshakeMessage::GroupM1, .. }
        )));

        let hs = db.find(&AP, &STA).unwrap();
        assert!(hs.has_gtk);
        assert!(hs.gtk_m1_frame.is_some());

        // Group M2
        let ki_g2 = KI_MIC | KI_SECURE | 2;
        let g2 = build_eapol_frame(ki_g2, 5, &[0u8; 32], &[0xBB; 16], &[]);
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &g2, 6000);
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeMessage { message: HandshakeMessage::GroupM2, .. }
        )));

        let hs = db.find(&AP, &STA).unwrap();
        assert!(hs.gtk_m2_frame.is_some());
    }

    // ── Message pair determination ──

    #[test]
    fn test_message_pair_same_replay_counter() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let snonce = [0xBB; 32];

        // M1 and M2 with same replay counter
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &snonce), 2000);

        let hs = db.find(&AP, &STA).unwrap();
        assert_eq!(hs.message_pair, Some(MessagePair::M1M2SameRc));
    }

    #[test]
    fn test_message_pair_diff_replay_counter_with_m3() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let snonce = [0xBB; 32];

        // M1 rc=1, M2 rc=2, then M3
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(2, &snonce), 2000);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m3(3, &anonce), 3000);

        let hs = db.find(&AP, &STA).unwrap();
        assert_eq!(hs.message_pair, Some(MessagePair::M2M3DiffRc));
    }

    // ── EAP identity capture ──

    #[test]
    fn test_eap_identity_capture() {
        let mut db = CaptureDatabase::new();
        let frame = build_eap_identity_response(b"testuser@corp.com");

        let events = process_eapol_frame(&mut db, AP, STA, SSID, &frame, 1000);

        assert_eq!(db.eap_identity_count(), 1);
        let eid = &db.eap_identities()[0];
        assert_eq!(eid.identity, "testuser@corp.com");
        assert_eq!(eid.realm, Some("corp.com".to_string()));
        assert_eq!(eid.sta_mac, STA);
        assert_eq!(eid.ap_mac, AP);

        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::EapIdentityCaptured { identity, .. } if identity == "testuser@corp.com"
        )));
    }

    #[test]
    fn test_eap_identity_no_realm() {
        let mut db = CaptureDatabase::new();
        let frame = build_eap_identity_response(b"localuser");

        process_eapol_frame(&mut db, AP, STA, SSID, &frame, 1000);

        let eid = &db.eap_identities()[0];
        assert_eq!(eid.identity, "localuser");
        assert_eq!(eid.realm, None);
    }

    #[test]
    fn test_eap_method_negotiated() {
        let mut db = CaptureDatabase::new();

        // First capture identity
        let id_frame = build_eap_identity_response(b"user@corp");
        process_eapol_frame(&mut db, AP, STA, SSID, &id_frame, 1000);

        // Then EAP-Request/PEAP
        let mut eap_req = Vec::new();
        eap_req.push(0x01); // version
        eap_req.push(0x00); // type = EAP
        let eap_body: Vec<u8> = vec![
            0x01, // Request
            0x02, // ID
            0x00, 0x06, // length
            25,   // PEAP
            0x00, // flags
        ];
        eap_req.extend_from_slice(&(eap_body.len() as u16).to_be_bytes());
        eap_req.extend_from_slice(&eap_body);

        let events = process_eapol_frame(&mut db, AP, STA, SSID, &eap_req, 2000);

        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::EapMethodNegotiated { method: EapMethod::Peap, .. }
        )));

        // Check it's stored in EAP identity entry
        let eid = &db.eap_identities()[0];
        assert_eq!(eid.eap_type, Some(EapMethod::Peap));
    }

    // ── Database queries ──

    #[test]
    fn test_handshakes_for_ap() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let sta2 = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        // Two stations connecting to same AP
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        process_eapol_frame(&mut db, AP, sta2, SSID, &build_m1(1, &anonce, &[]), 2000);

        let hs_list = db.handshakes_for_ap(&AP);
        assert_eq!(hs_list.len(), 2);
    }

    #[test]
    fn test_best_handshake() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let snonce = [0xBB; 32];
        let sta2 = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        // STA1: only M1
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);

        // STA2: M1+M2
        process_eapol_frame(&mut db, AP, sta2, SSID, &build_m1(1, &anonce, &[]), 2000);
        process_eapol_frame(&mut db, AP, sta2, SSID, &build_m2(1, &snonce), 3000);

        let best = db.best_handshake(&AP).unwrap();
        assert_eq!(best.sta_mac, sta2);
        assert_eq!(best.quality, HandshakeQuality::M1M2);
    }

    #[test]
    fn test_stats() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let snonce = [0xBB; 32];

        // Build a PMKID M1
        let pmkid_bytes: [u8; 16] = [0xDE; 16];
        let mut kde = vec![0xDD, 20, 0x00, 0x0F, 0xAC, 0x04];
        kde.extend_from_slice(&pmkid_bytes);
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &kde), 1000);

        // M2
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &snonce), 2000);

        // EAP identity on different network
        let ap2 = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let id_frame = build_eap_identity_response(b"admin@corp");
        process_eapol_frame(&mut db, ap2, STA, "Enterprise", &id_frame, 3000);

        let stats = db.stats();
        assert_eq!(stats.total_handshakes, 1); // only the 4-way (EAP alone doesn't create entry)
        assert_eq!(stats.crackable_handshakes, 1); // M1+M2
        assert_eq!(stats.pmkid_captures, 1);
        assert_eq!(stats.eap_identities, 1);
        assert_eq!(stats.best_quality, HandshakeQuality::M1M2);
        assert_eq!(stats.unique_aps, 1);
    }

    // ── Database capacity ──

    #[test]
    fn test_database_full_rejects_new() {
        let mut db = CaptureDatabase::with_capacity(2, 2);
        let anonce = [0xAA; 32];

        let sta1 = MacAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x01]);
        let sta2 = MacAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x02]);
        let sta3 = MacAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x03]);

        process_eapol_frame(&mut db, AP, sta1, SSID, &build_m1(1, &anonce, &[]), 1000);
        process_eapol_frame(&mut db, AP, sta2, SSID, &build_m1(1, &anonce, &[]), 2000);
        assert_eq!(db.handshake_count(), 2);

        // Third should be rejected
        let events = process_eapol_frame(&mut db, AP, sta3, SSID, &build_m1(1, &anonce, &[]), 3000);
        assert_eq!(db.handshake_count(), 2);
        assert!(events.is_empty());
    }

    // ── Malformed frame handling ──

    #[test]
    fn test_malformed_eapol_ignored() {
        let mut db = CaptureDatabase::new();

        // Too short
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &[0x02, 0x03], 1000);
        assert!(events.is_empty());

        // Empty
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &[], 1000);
        assert!(events.is_empty());

        // Invalid type
        let events = process_eapol_frame(&mut db, AP, STA, SSID, &[0x02, 0xFF, 0x00, 0x00], 1000);
        assert!(events.is_empty());
    }

    // ── Data payload processing ──

    #[test]
    fn test_process_data_payload_with_llc_snap() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];

        // Build M1 with LLC/SNAP prefix
        let m1_eapol = build_m1(1, &anonce, &[]);
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        payload.extend_from_slice(&m1_eapol);

        let events = process_data_payload(&mut db, AP, STA, SSID, &payload, 1000);

        assert_eq!(db.handshake_count(), 1);
        assert!(db.find(&AP, &STA).unwrap().has_m1);
        assert!(events.iter().any(|e| matches!(e,
            CaptureEvent::HandshakeMessage { message: HandshakeMessage::M1, .. }
        )));
    }

    // ── SSID update ──

    #[test]
    fn test_ssid_updated_on_later_frame() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];
        let snonce = [0xBB; 32];

        // M1 with empty SSID
        process_eapol_frame(&mut db, AP, STA, "", &build_m1(1, &anonce, &[]), 1000);
        assert_eq!(db.find(&AP, &STA).unwrap().ssid, "");

        // M2 with SSID now known
        process_eapol_frame(&mut db, AP, STA, "MyNetwork", &build_m2(1, &snonce), 2000);
        assert_eq!(db.find(&AP, &STA).unwrap().ssid, "MyNetwork");
    }

    // ── EAP identity stored in handshake ──

    #[test]
    fn test_eap_identity_stored_in_handshake() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];

        // Create handshake entry first
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);

        // Then capture identity
        let id_frame = build_eap_identity_response(b"jdoe@company.org");
        process_eapol_frame(&mut db, AP, STA, SSID, &id_frame, 2000);

        let hs = db.find(&AP, &STA).unwrap();
        assert_eq!(hs.eap_identity, Some("jdoe@company.org".to_string()));
    }

    // ── Frames processed counter ──

    #[test]
    fn test_frames_processed_counter() {
        let mut db = CaptureDatabase::new();
        let anonce = [0xAA; 32];

        process_eapol_frame(&mut db, AP, STA, SSID, &build_m1(1, &anonce, &[]), 1000);
        process_eapol_frame(&mut db, AP, STA, SSID, &[], 2000); // malformed
        process_eapol_frame(&mut db, AP, STA, SSID, &build_m2(1, &[0xBB; 32]), 3000);

        assert_eq!(db.frames_processed, 3);
    }
}
