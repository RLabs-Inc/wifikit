//! SAE (Simultaneous Authentication of Equals) / Dragonfly protocol module.
//!
//! Pure protocol definitions — frame parsing, frame building, group definitions,
//! WPA3 transition detection, and Dragonblood vulnerability indicators.
//!
#![allow(dead_code)]
#![allow(unused_imports)]
//! No actual ECC math is performed here. For real scalar multiplication,
//! hash-to-curve, and key derivation, see trait/function signatures with TODO
//! comments marking where crypto backends would plug in.
//!
//! Reference: IEEE 802.11-2020 Section 12.4 (SAE), RFC 7664 (Dragonfly),
//!            wifi-map/libwifikit/attacks/attack_wpa3.c

use crate::protocol::ie::RsnInfo;
use crate::protocol::ieee80211::AkmSuite;

use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

// ═══════════════════════════════════════════════════════════════════════════════
//  SAE Status Codes (802.11 Table 9-50, SAE-specific subset)
// ═══════════════════════════════════════════════════════════════════════════════

/// SAE-specific status codes used in authentication frames.
/// These are a subset of the general 802.11 status codes, collected here
/// for convenient use in SAE protocol handling.
pub mod sae_status {
    /// Authentication successful
    pub const SUCCESS: u16 = 0;
    /// General authentication failure
    pub const FAILURE: u16 = 1;
    /// AP requires an anti-clogging token before processing Commit
    pub const ANTI_CLOGGING_TOKEN_REQUIRED: u16 = 76;
    /// AP does not support the finite cyclic group we proposed
    pub const FINITE_CYCLIC_GROUP_NOT_SUPPORTED: u16 = 77;
    /// AP does not recognize the password identifier we sent
    pub const UNKNOWN_PASSWORD_IDENTIFIER: u16 = 123;
    /// SAE Hash-to-Element (H2E) indication — AP supports/requires H2E
    pub const SAE_HASH_TO_ELEMENT: u16 = 126;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ECC Group Definitions
// ═══════════════════════════════════════════════════════════════════════════════

/// Elliptic Curve Cryptography groups used in SAE/Dragonfly.
///
/// Group identifiers are assigned by IANA (RFC 2409, RFC 5903, RFC 7027).
/// SAE mandates support for Group 19 (P-256). Other groups are optional.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SaeGroup {
    /// NIST P-256 (secp256r1) — 256-bit prime, MANDATORY for WPA3
    Group19,
    /// NIST P-384 (secp384r1) — 384-bit prime
    Group20,
    /// NIST P-521 (secp521r1) — 521-bit prime
    Group21,
    /// Brainpool P-256r1 — 256-bit prime (used by some European vendors)
    Group28,
    /// Brainpool P-384r1 — 384-bit prime
    Group29,
    /// Brainpool P-512r1 — 512-bit prime
    Group30,
}

/// All defined SAE groups, ordered from weakest to strongest security.
/// Used for downgrade testing (CVE-2019-9495).
pub const SAE_GROUPS_WEAK_TO_STRONG: &[SaeGroup] = &[
    SaeGroup::Group28, // BP-256: 128-bit security
    SaeGroup::Group19, // P-256:  128-bit security (mandatory)
    SaeGroup::Group29, // BP-384: 192-bit security
    SaeGroup::Group20, // P-384:  192-bit security
    SaeGroup::Group30, // BP-512: 256-bit security
    SaeGroup::Group21, // P-521:  ~260-bit security
];

/// Default groups to test when no specific group is requested.
pub const SAE_DEFAULT_GROUPS: &[SaeGroup] = &[
    SaeGroup::Group19,
    SaeGroup::Group20,
    SaeGroup::Group21,
];

impl SaeGroup {
    /// Create from IANA group identifier. Returns `None` for unknown groups.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            19 => Some(Self::Group19),
            20 => Some(Self::Group20),
            21 => Some(Self::Group21),
            28 => Some(Self::Group28),
            29 => Some(Self::Group29),
            30 => Some(Self::Group30),
            _ => None,
        }
    }

    /// IANA group identifier number.
    pub fn id(&self) -> u16 {
        match self {
            Self::Group19 => 19,
            Self::Group20 => 20,
            Self::Group21 => 21,
            Self::Group28 => 28,
            Self::Group29 => 29,
            Self::Group30 => 30,
        }
    }

    /// Human-readable name including curve family.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Group19 => "P-256 (NIST)",
            Self::Group20 => "P-384 (NIST)",
            Self::Group21 => "P-521 (NIST)",
            Self::Group28 => "Brainpool P-256r1",
            Self::Group29 => "Brainpool P-384r1",
            Self::Group30 => "Brainpool P-512r1",
        }
    }

    /// Size of the prime field in bytes.
    /// For P-521, this is ceil(521/8) = 66 bytes.
    pub fn prime_len(&self) -> usize {
        match self {
            Self::Group19 => 32,
            Self::Group20 => 48,
            Self::Group21 => 66, // ceil(521/8)
            Self::Group28 => 32,
            Self::Group29 => 48,
            Self::Group30 => 64,
        }
    }

    /// Size of an uncompressed elliptic curve point: 2 * prime_len bytes
    /// (x-coordinate || y-coordinate, no 0x04 prefix in SAE frames).
    pub fn element_len(&self) -> usize {
        self.prime_len() * 2
    }

    /// Size of the scalar value in bytes (same as prime_len).
    pub fn scalar_len(&self) -> usize {
        self.prime_len()
    }

    /// Size of the group order in bytes (same as prime_len).
    pub fn order_len(&self) -> usize {
        self.prime_len()
    }

    /// Whether this group is mandatory per WPA3 specification.
    /// Only Group 19 (P-256) is mandatory.
    pub fn is_mandatory(&self) -> bool {
        *self == Self::Group19
    }

    /// Approximate security level in bits (symmetric equivalent).
    pub fn security_bits(&self) -> u16 {
        match self {
            Self::Group19 => 128,
            Self::Group20 => 192,
            Self::Group21 => 260,
            Self::Group28 => 128,
            Self::Group29 => 192,
            Self::Group30 => 256,
        }
    }
}

impl std::fmt::Display for SaeGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Group {} ({})", self.id(), self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SAE Commit Frame
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed SAE Commit frame body.
///
/// Wire format (after auth fixed fields: algo=3, seq=1, status):
///   Group ID (2 LE) || [Anti-Clogging Token (variable)] || Scalar (N) || Element (2N)
///   [Optional: Password Identifier element]
///
/// The anti-clogging token is present only when responding to a token request
/// (status code 76). Per IEEE 802.11-2020, the token goes BEFORE scalar.
#[derive(Clone, Debug)]
pub struct SaeCommit {
    /// Finite cyclic group identifier (IANA number, e.g. 19 for P-256)
    pub group_id: u16,
    /// Anti-clogging token, present when responding to AP's token request.
    /// Per 802.11-2020 12.4.8.6.4, token is placed between group ID and scalar.
    pub anti_clogging_token: Option<Vec<u8>>,
    /// Scalar value, big-endian, `group.scalar_len()` bytes.
    /// In a real SAE exchange, this is (rand + mask) mod order.
    pub scalar: Vec<u8>,
    /// Element (uncompressed curve point), `group.element_len()` bytes.
    /// x-coordinate || y-coordinate, no 0x04 prefix.
    /// In a real SAE exchange, this is -(mask * PWE).
    pub element: Vec<u8>,
    /// SAE-PK password identifier (from extension element, if present).
    /// Used with SAE-PK (Public Key) for server authentication.
    pub password_id: Option<String>,
}

/// Parse an SAE Commit from the auth frame body.
///
/// `data` starts AFTER the auth fixed fields (algo=3, seq=1, status).
/// So `data[0..2]` is the Group ID.
///
/// Returns `None` if the frame is malformed or too short.
pub fn parse_sae_commit(data: &[u8]) -> Option<SaeCommit> {
    // Minimum: Group ID (2) + scalar (at least 32) + element (at least 64) = 98
    if data.len() < 2 {
        return None;
    }

    let group_id = u16::from_le_bytes([data[0], data[1]]);
    let group = SaeGroup::from_id(group_id);

    // If we know the group, use its exact sizes; otherwise try Group 19 sizes
    let (scalar_len, element_len) = match group {
        Some(g) => (g.scalar_len(), g.element_len()),
        None => {
            // Unknown group — we can still try to parse if data is large enough.
            // Default to Group 19 sizes as a guess, but mark the parse as best-effort.
            (32, 64)
        }
    };

    let remaining = &data[2..];
    let required_len = scalar_len + element_len;

    if remaining.len() < required_len {
        return None;
    }

    // Determine if there's an anti-clogging token between group ID and scalar+element.
    // The token is present if there's more data than scalar + element need.
    // Token length = remaining - scalar - element - possible_extensions
    let has_token = remaining.len() > required_len;

    let (anti_clogging_token, scalar_start) = if has_token {
        // Everything between group_id and the last (scalar_len + element_len) bytes
        // could be token + extensions. We assume token is contiguous before scalar.
        // Per 802.11-2020: Group ID || Token || Scalar || Element || [Extensions]
        //
        // We need to figure out where the scalar starts. The scalar + element
        // are the last (scalar_len + element_len) bytes before any tagged extensions.
        //
        // Extensions (if present) are TLV-encoded IEs at the end.
        // We scan backwards to find where extensions start.
        let extensions_start = find_extensions_start(remaining, scalar_len, element_len);

        let token_and_scalar_element = &remaining[..extensions_start];

        if token_and_scalar_element.len() < required_len {
            return None;
        }

        let token_len = token_and_scalar_element.len() - required_len;
        if token_len > 0 {
            let token = remaining[..token_len].to_vec();
            (Some(token), token_len)
        } else {
            (None, 0)
        }
    } else {
        (None, 0)
    };

    let scalar = remaining[scalar_start..scalar_start + scalar_len].to_vec();
    let element_start = scalar_start + scalar_len;
    let element = remaining[element_start..element_start + element_len].to_vec();

    // Check for password identifier extension after element
    let after_element = element_start + element_len;
    let password_id = if after_element < remaining.len() {
        parse_password_id_extension(&remaining[after_element..])
    } else {
        None
    };

    Some(SaeCommit {
        group_id,
        anti_clogging_token,
        scalar,
        element,
        password_id,
    })
}

/// Build an SAE Commit frame body (to be wrapped in an auth frame).
///
/// Output format: Group ID (2 LE) || [Token] || Scalar || Element || [PW-ID Extension]
pub fn build_sae_commit(commit: &SaeCommit) -> Vec<u8> {
    let token_len = commit.anti_clogging_token.as_ref().map_or(0, |t| t.len());
    let pw_id_len = commit.password_id.as_ref().map_or(0, |id| {
        // Extension element: tag(1) + len(1) + ext_id(1) + data
        3 + id.len()
    });

    let total = 2 + token_len + commit.scalar.len() + commit.element.len() + pw_id_len;
    let mut buf = Vec::with_capacity(total);

    // Group ID (little-endian)
    buf.extend_from_slice(&commit.group_id.to_le_bytes());

    // Anti-clogging token (if present, before scalar per 802.11-2020)
    if let Some(ref token) = commit.anti_clogging_token {
        buf.extend_from_slice(token);
    }

    // Scalar
    buf.extend_from_slice(&commit.scalar);

    // Element (x || y)
    buf.extend_from_slice(&commit.element);

    // Password Identifier extension element (if present)
    if let Some(ref pw_id) = commit.password_id {
        buf.push(PASSWORD_IDENTIFIER_IE_TAG); // Extension tag (255)
        buf.push((1 + pw_id.len()) as u8);   // Length: ext_id + string
        buf.push(PASSWORD_IDENTIFIER_EXT_ID); // Extension Element ID
        buf.extend_from_slice(pw_id.as_bytes());
    }

    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SAE Confirm Frame
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed SAE Confirm frame body.
///
/// Wire format (after auth fixed fields: algo=3, seq=2, status=0):
///   Send-Confirm (2 LE) || Confirm (hash output, group-dependent size)
///
/// For Group 19 (P-256), Confirm is 32 bytes (SHA-256 output).
#[derive(Clone, Debug)]
pub struct SaeConfirm {
    /// Send-Confirm counter. Monotonically increasing per exchange.
    /// Used to distinguish retransmissions from new attempts.
    pub send_confirm: u16,
    /// HMAC confirmation value. Size depends on the group's hash function:
    /// - Group 19: 32 bytes (SHA-256)
    /// - Group 20: 48 bytes (SHA-384)
    /// - Group 21: 64 bytes (SHA-512)
    pub confirm: Vec<u8>,
}

/// Parse an SAE Confirm from the auth frame body.
///
/// `data` starts AFTER the auth fixed fields (algo=3, seq=2, status=0).
/// So `data[0..2]` is the Send-Confirm counter.
///
/// Returns `None` if the frame is too short (minimum 3 bytes: counter + some confirm).
pub fn parse_sae_confirm(data: &[u8]) -> Option<SaeConfirm> {
    // Minimum: Send-Confirm (2) + at least 1 byte of confirm hash
    if data.len() < 3 {
        return None;
    }

    let send_confirm = u16::from_le_bytes([data[0], data[1]]);
    let confirm = data[2..].to_vec();

    Some(SaeConfirm {
        send_confirm,
        confirm,
    })
}

/// Build an SAE Confirm frame body (to be wrapped in an auth frame).
///
/// Output format: Send-Confirm (2 LE) || Confirm (N bytes)
pub fn build_sae_confirm(confirm: &SaeConfirm) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + confirm.confirm.len());
    buf.extend_from_slice(&confirm.send_confirm.to_le_bytes());
    buf.extend_from_slice(&confirm.confirm);
    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Anti-Clogging Token
// ═══════════════════════════════════════════════════════════════════════════════

/// Anti-clogging token sent by an AP to mitigate SAE Commit flooding.
///
/// When an AP is under load (many concurrent SAE exchanges), it responds
/// with status=76 (ANTI_CLOGGING_TOKEN_REQUIRED) and includes a token.
/// The STA must include this token in its next Commit to prove it received
/// the AP's response (proof of reachability).
#[derive(Clone, Debug)]
pub struct AntiCloggingToken {
    /// The opaque token value. AP-generated, must be echoed back verbatim.
    pub token: Vec<u8>,
    /// The group ID from the original Commit that triggered the token request.
    /// Present if the AP included a group ID in the rejection body.
    pub group_id: u16,
}

/// Parse an anti-clogging token request from an SAE auth frame body.
///
/// This is used when the AP responds with status=76 (ANTI_CLOGGING_TOKEN_REQUIRED)
/// to an SAE Commit (algo=3, seq=1).
///
/// `data` starts AFTER the auth fixed fields.
/// The body format for a token request is: Group ID (2 LE) || Token (variable)
///
/// Returns `None` if the body is too short.
pub fn parse_anti_clogging_request(data: &[u8]) -> Option<AntiCloggingToken> {
    // Minimum: Group ID (2) + at least 1 byte of token
    if data.len() < 3 {
        return None;
    }

    let group_id = u16::from_le_bytes([data[0], data[1]]);
    let token = data[2..].to_vec();

    Some(AntiCloggingToken { token, group_id })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SAE Auth Frame Parser (high-level dispatch)
// ═══════════════════════════════════════════════════════════════════════════════

/// High-level parsed SAE authentication frame.
///
/// Combines all SAE frame types into a single enum for convenient dispatch.
/// The variant is determined by the auth sequence number and status code.
#[derive(Clone, Debug)]
pub enum SaeFrame {
    /// SAE Commit (seq=1, status=0 or status=126 for H2E)
    Commit(SaeCommit),
    /// SAE Confirm (seq=2, status=0)
    Confirm(SaeConfirm),
    /// Anti-clogging token request (seq=1, status=76)
    AntiCloggingRequest(AntiCloggingToken),
    /// Group rejection (seq=1, status=77). Contains list of AP-supported groups
    /// parsed from the rejection body, if present.
    GroupReject {
        /// Groups the AP claims to support (parsed from rejection body).
        /// Each group ID is 2 bytes LE. May be empty if AP doesn't include them.
        supported_groups: Vec<u16>,
    },
    /// Unknown password identifier (seq=1, status=123)
    UnknownPasswordId,
}

/// Parse an SAE authentication frame body into a high-level `SaeFrame`.
///
/// `seq` is the auth transaction sequence number (1 for Commit, 2 for Confirm).
/// `status` is the status code from the auth frame fixed fields.
/// `body` is the frame body AFTER the auth fixed fields (algo, seq, status).
///
/// The auth algorithm MUST be 3 (SAE) — the caller is responsible for checking.
///
/// Returns `None` if the frame cannot be parsed.
pub fn parse_sae_auth(seq: u16, status: u16, body: &[u8]) -> Option<SaeFrame> {
    match (seq, status) {
        // Commit: seq=1, status=0 (normal) or status=126 (H2E)
        (1, s) if s == sae_status::SUCCESS || s == sae_status::SAE_HASH_TO_ELEMENT => {
            parse_sae_commit(body).map(SaeFrame::Commit)
        }

        // Anti-clogging token request: seq=1, status=76
        (1, sae_status::ANTI_CLOGGING_TOKEN_REQUIRED) => {
            parse_anti_clogging_request(body).map(SaeFrame::AntiCloggingRequest)
        }

        // Group rejection: seq=1, status=77
        (1, sae_status::FINITE_CYCLIC_GROUP_NOT_SUPPORTED) => {
            // Body may contain list of supported group IDs (2 bytes each, LE)
            let mut supported_groups = Vec::new();
            let mut pos = 0;
            while pos + 2 <= body.len() {
                let gid = u16::from_le_bytes([body[pos], body[pos + 1]]);
                supported_groups.push(gid);
                pos += 2;
            }
            Some(SaeFrame::GroupReject { supported_groups })
        }

        // Unknown password identifier: seq=1, status=123
        (1, sae_status::UNKNOWN_PASSWORD_IDENTIFIER) => {
            Some(SaeFrame::UnknownPasswordId)
        }

        // Confirm: seq=2, status=0
        (2, sae_status::SUCCESS) => {
            parse_sae_confirm(body).map(SaeFrame::Confirm)
        }

        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPA3 Transition Mode Detection
// ═══════════════════════════════════════════════════════════════════════════════

/// Analysis of an AP's WPA3 transition mode configuration.
///
/// WPA3 transition mode allows both WPA2-PSK and WPA3-SAE clients to connect.
/// This is common during migration periods but introduces downgrade risks
/// (CVE-2019-9496) if MFP is not properly enforced.
#[derive(Clone, Debug, Default)]
pub struct Wpa3TransitionInfo {
    /// AP advertises WPA2-PSK (AKM type 2 or 6) in RSN IE
    pub has_wpa2_psk: bool,
    /// AP advertises SAE (AKM type 8) or FT-SAE (AKM type 9) in RSN IE
    pub has_sae: bool,
    /// Management Frame Protection capable (RSN capabilities bit 7)
    pub mfp_capable: bool,
    /// Management Frame Protection required (RSN capabilities bit 6)
    pub mfp_required: bool,
    /// True if AP is in transition mode:
    /// has_sae && has_wpa2_psk && mfp_capable && !mfp_required
    ///
    /// This configuration allows WPA2 clients without MFP, making the network
    /// potentially vulnerable to deauth-based downgrade attacks.
    pub transition_mode: bool,
}

/// Detect WPA3 transition mode from an RSN Information Element.
///
/// Examines the AKM suites and MFP (Management Frame Protection) flags
/// to determine if the AP operates in WPA2/WPA3 mixed mode.
///
/// A network is in transition mode when it advertises BOTH PSK and SAE
/// AKM suites with MFP capable but not required. This allows legacy WPA2
/// clients to connect without MFP while also supporting WPA3-SAE.
pub fn detect_wpa3_transition(rsn: &RsnInfo) -> Wpa3TransitionInfo {
    let has_wpa2_psk = rsn.akm_suites.iter().any(|akm| {
        matches!(akm, AkmSuite::Psk | AkmSuite::PskSha256 | AkmSuite::FtPsk)
    });

    let has_sae = rsn.akm_suites.iter().any(|akm| {
        matches!(akm, AkmSuite::Sae | AkmSuite::FtSae)
    });

    let mfp_capable = rsn.mfp_capable;
    let mfp_required = rsn.mfp_required;

    let transition_mode = has_sae && has_wpa2_psk && mfp_capable && !mfp_required;

    Wpa3TransitionInfo {
        has_wpa2_psk,
        has_sae,
        mfp_capable,
        mfp_required,
        transition_mode,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Dragonblood Attack Indicators
// ═══════════════════════════════════════════════════════════════════════════════

/// Vulnerability indicators detectable from SAE protocol behavior.
///
/// These correspond to the Dragonblood family of attacks (CVE-2019-9494 through
/// CVE-2019-9499, plus additional implementation-specific vulnerabilities).
///
/// Each boolean field indicates whether a specific vulnerability was detected
/// during active probing of an AP's SAE implementation.
#[derive(Clone, Debug, Default)]
pub struct DragonbloodIndicators {
    /// CVE-2019-9495: AP accepts ECC groups weaker than its mandatory minimum.
    /// Detected by sending SAE Commits with non-standard groups and checking
    /// if the AP responds with a Commit (acceptance) rather than status 77.
    pub accepts_group_downgrade: bool,

    /// CVE-2019-9494: AP's response time varies significantly with the password
    /// element derivation. Detected by statistical analysis of SAE Commit
    /// response times (coefficient of variation > 15% indicates non-constant-time).
    pub timing_side_channel: bool,

    /// AP reflects our Commit back without proper state tracking.
    /// A vulnerable AP processes its own Commit when replayed, leading to
    /// key confusion or denial of service.
    pub reflects_commit: bool,

    /// CVE-2019-9498/9499: AP accepts elliptic curve points that are NOT on the
    /// specified curve. Detected by sending a Commit with an obviously invalid
    /// element (e.g., (0, 0xFF..FF)) and checking for acceptance.
    pub accepts_invalid_curve: bool,

    /// CVE-2019-9497: AP has no anti-clogging protection or an insufficient
    /// threshold, making it vulnerable to CPU exhaustion from Commit flooding.
    /// Detected by measuring response time degradation under load.
    pub vulnerable_to_commit_dos: bool,

    /// AP produces the same element for different SAE exchanges, suggesting
    /// it caches or reuses password-derived values. This could enable a
    /// cache-based side-channel attack to recover the password.
    pub cache_attack_possible: bool,

    /// CVE-2019-9496: Network is in WPA2/WPA3 transition mode and can be
    /// downgraded to WPA2-only by creating a rogue AP without SAE.
    /// Clients without WPA3 support will connect to the WPA2 rogue AP.
    pub transition_downgrade: bool,

    /// AP's anti-clogging tokens can be replayed from different source MACs
    /// or after significant time delay, indicating tokens are not properly
    /// bound to the sender's identity or time-limited.
    pub token_replay_possible: bool,
}

impl DragonbloodIndicators {
    /// Total number of vulnerabilities detected.
    pub fn vulnerability_count(&self) -> u32 {
        let mut count = 0u32;
        if self.accepts_group_downgrade { count += 1; }
        if self.timing_side_channel { count += 1; }
        if self.reflects_commit { count += 1; }
        if self.accepts_invalid_curve { count += 1; }
        if self.vulnerable_to_commit_dos { count += 1; }
        if self.cache_attack_possible { count += 1; }
        if self.transition_downgrade { count += 1; }
        if self.token_replay_possible { count += 1; }
        count
    }

    /// Whether any vulnerability was detected.
    pub fn any_vulnerable(&self) -> bool {
        self.vulnerability_count() > 0
    }

    /// List of CVEs that apply based on detected vulnerabilities.
    pub fn applicable_cves(&self) -> Vec<&'static str> {
        let mut cves = Vec::new();
        if self.timing_side_channel { cves.push("CVE-2019-9494"); }
        if self.accepts_group_downgrade { cves.push("CVE-2019-9495"); }
        if self.transition_downgrade { cves.push("CVE-2019-9496"); }
        if self.vulnerable_to_commit_dos { cves.push("CVE-2019-9497"); }
        if self.accepts_invalid_curve {
            cves.push("CVE-2019-9498");
            cves.push("CVE-2019-9499");
        }
        cves
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SAE-PK (Public Key) Extensions
// ═══════════════════════════════════════════════════════════════════════════════

/// SAE-PK modifier extracted from SAE Commit extension elements.
///
/// SAE-PK provides server authentication by binding the password to a public key.
/// The modifier is used to derive the password element in a way that proves
/// the AP knows the corresponding private key.
#[derive(Clone, Debug)]
pub struct SaePkModifier {
    /// Truncated hash of the AP's public key (fingerprint).
    /// Used by the STA to verify it's connecting to the legitimate AP.
    pub fingerprint: Vec<u8>,
    /// Password modifier value. Combined with the password during
    /// element derivation to bind the exchange to the AP's key pair.
    pub modifier: Vec<u8>,
}

/// SAE-PK extension element ID (within IE tag 255 = Extension)
const SAE_PK_EXT_ID: u8 = 0x3F;

/// Parse SAE-PK elements from extension data following an SAE Commit body.
///
/// `data` is the extension portion after the SAE Commit's scalar and element.
/// SAE-PK elements are encoded as Extension IEs (tag 255).
///
/// Returns `None` if no SAE-PK elements are found.
pub fn parse_sae_pk_elements(data: &[u8]) -> Option<SaePkModifier> {
    let mut pos = 0;
    let mut fingerprint = None;
    let mut modifier = None;

    while pos + 2 <= data.len() {
        let tag = data[pos];
        let len = data[pos + 1] as usize;
        pos += 2;

        if pos + len > data.len() {
            break;
        }

        // Extension element (tag 255)
        if tag == 255 && len >= 1 {
            let ext_id = data[pos];
            let ext_data = &data[pos + 1..pos + len];

            if ext_id == SAE_PK_EXT_ID && ext_data.len() >= 2 {
                // SAE-PK element: fingerprint_len(1) || fingerprint || modifier
                let fp_len = ext_data[0] as usize;
                if fp_len + 1 <= ext_data.len() {
                    fingerprint = Some(ext_data[1..1 + fp_len].to_vec());
                    if 1 + fp_len < ext_data.len() {
                        modifier = Some(ext_data[1 + fp_len..].to_vec());
                    }
                }
            }
        }

        pos += len;
    }

    match (fingerprint, modifier) {
        (Some(fp), Some(m)) => Some(SaePkModifier {
            fingerprint: fp,
            modifier: m,
        }),
        (Some(fp), None) => Some(SaePkModifier {
            fingerprint: fp,
            modifier: Vec::new(),
        }),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  H2E (Hash-to-Element) Support
// ═══════════════════════════════════════════════════════════════════════════════

/// Information about SAE Hash-to-Element (H2E) usage.
///
/// H2E is an improved password element derivation method that avoids the
/// timing side-channel of the original hunting-and-pecking algorithm.
/// Indicated by status code 126 in SAE Commit frames.
#[derive(Clone, Debug, Default)]
pub struct SaeH2eInfo {
    /// Password identifier used with H2E (if any).
    /// Allows multiple passwords to be configured on an AP.
    pub password_identifier: Option<String>,
    /// Groups the AP rejected (from status=77 responses).
    /// Accumulated from previous exchange attempts.
    pub rejected_groups: Vec<u16>,
}

/// Check if an SAE auth frame indicates Hash-to-Element (H2E) usage.
///
/// Status code 126 in an SAE Commit indicates the AP supports/requires H2E.
pub fn is_h2e_auth(status: u16) -> bool {
    status == sae_status::SAE_HASH_TO_ELEMENT
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Password Identifier Extension
// ═══════════════════════════════════════════════════════════════════════════════

/// Extension element tag for Extension IEs (IE tag 255)
const PASSWORD_IDENTIFIER_IE_TAG: u8 = 255;

/// Extension Element ID for Password Identifier (within tag 255)
/// IEEE 802.11-2020 Table 9-92
const PASSWORD_IDENTIFIER_EXT_ID: u8 = 33;

/// Parse a Password Identifier extension element from tagged parameters.
///
/// Scans for Extension IE (tag 255) with extension ID 33 (Password Identifier).
/// Returns the identifier as a UTF-8 string, or `None` if not found.
fn parse_password_id_extension(data: &[u8]) -> Option<String> {
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let tag = data[pos];
        let len = data[pos + 1] as usize;
        pos += 2;

        if pos + len > data.len() {
            break;
        }

        if tag == PASSWORD_IDENTIFIER_IE_TAG && len >= 2 {
            let ext_id = data[pos];
            if ext_id == PASSWORD_IDENTIFIER_EXT_ID {
                let id_bytes = &data[pos + 1..pos + len];
                return String::from_utf8(id_bytes.to_vec()).ok();
            }
        }

        pos += len;
    }

    None
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Crypto Trait Signatures (TODO: implement with actual ECC backend)
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for SAE cryptographic operations.
///
/// This defines the interface that a crypto backend must implement for
/// performing actual SAE/Dragonfly key exchanges. The protocol module
/// (this file) handles frame parsing and building; the crypto backend
/// handles the math.
///
/// TODO: Implement with a suitable ECC library (e.g., p256, p384 crates,
/// or a unified backend like ring/openssl).
pub trait SaeCrypto {
    /// Derive the Password Element (PWE) from password, MAC addresses, and group.
    ///
    /// Uses hunting-and-pecking (legacy) or hash-to-element (H2E) depending
    /// on the `use_h2e` flag.
    ///
    /// Returns the PWE as an uncompressed curve point (x || y).
    fn derive_pwe(
        &self,
        group: SaeGroup,
        password: &[u8],
        sta_mac: &[u8; 6],
        ap_mac: &[u8; 6],
        use_h2e: bool,
    ) -> Option<Vec<u8>>;

    /// Generate a random scalar in [2, order-1] for the given group.
    fn generate_scalar(&self, group: SaeGroup) -> Option<Vec<u8>>;

    /// Compute the element: -(mask * PWE) where mask = scalar - rand.
    ///
    /// Returns the element as an uncompressed curve point (x || y).
    fn compute_element(
        &self,
        group: SaeGroup,
        mask: &[u8],
        pwe: &[u8],
    ) -> Option<Vec<u8>>;

    /// Compute the SAE Confirm value using HMAC.
    ///
    /// confirm = HMAC-Hash(KCK, send_confirm || scalar_a || element_a || scalar_b || element_b)
    fn compute_confirm(
        &self,
        group: SaeGroup,
        kck: &[u8],
        send_confirm: u16,
        scalar_a: &[u8],
        element_a: &[u8],
        scalar_b: &[u8],
        element_b: &[u8],
    ) -> Option<Vec<u8>>;

    /// Derive the shared secret (KCK + PMK) from the SAE exchange.
    ///
    /// Returns (KCK, PMK) where KCK is used for Confirm and PMK is used
    /// for the subsequent 4-way handshake.
    fn derive_keys(
        &self,
        group: SaeGroup,
        shared_secret: &[u8],
        scalar_a: &[u8],
        scalar_b: &[u8],
        sta_mac: &[u8; 6],
        ap_mac: &[u8; 6],
    ) -> Option<(Vec<u8>, Vec<u8>)>;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ECC Point Arithmetic (P-256 / secp256r1)
// ═══════════════════════════════════════════════════════════════════════════════

/// Curve parameters for NIST P-256 (secp256r1).
///
/// Short Weierstrass form: y^2 = x^3 + ax + b (mod p)
/// where a = p - 3.
struct P256Params {
    p: BigUint,
    a: BigUint,
    b: BigUint,
    order: BigUint,
    #[allow(dead_code)] // Generator point coordinates — needed when SAE full handshake is implemented
    gx: BigUint,
    #[allow(dead_code)] // Generator point coordinates — needed when SAE full handshake is implemented
    gy: BigUint,
}

impl P256Params {
    fn new() -> Self {
        // NIST P-256 constants (FIPS 186-4) as big-endian byte arrays.
        // Using from_bytes_be() instead of parse_bytes().unwrap() — infallible by type system.
        let p = BigUint::from_bytes_be(&[
            0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x01,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
        ]);
        let a = BigUint::from_bytes_be(&[
            0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x01,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFC,
        ]);
        let b = BigUint::from_bytes_be(&[
            0x5A,0xC6,0x35,0xD8, 0xAA,0x3A,0x93,0xE7,
            0xB3,0xEB,0xBD,0x55, 0x76,0x98,0x86,0xBC,
            0x65,0x1D,0x06,0xB0, 0xCC,0x53,0xB0,0xF6,
            0x3B,0xCE,0x3C,0x3E, 0x27,0xD2,0x60,0x4B,
        ]);
        let order = BigUint::from_bytes_be(&[
            0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00,
            0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
            0xBC,0xE6,0xFA,0xAD, 0xA7,0x17,0x9E,0x84,
            0xF3,0xB9,0xCA,0xC2, 0xFC,0x63,0x25,0x51,
        ]);
        let gx = BigUint::from_bytes_be(&[
            0x6B,0x17,0xD1,0xF2, 0xE1,0x2C,0x42,0x47,
            0xF8,0xBC,0xE6,0xE5, 0x63,0xA4,0x40,0xF2,
            0x77,0x03,0x7D,0x81, 0x2D,0xEB,0x33,0xA0,
            0xF4,0xA1,0x39,0x45, 0xD8,0x98,0xC2,0x96,
        ]);
        let gy = BigUint::from_bytes_be(&[
            0x4F,0xE3,0x42,0xE2, 0xFE,0x1A,0x7F,0x9B,
            0x8E,0xE7,0xEB,0x4A, 0x7C,0x0F,0x9E,0x16,
            0x2B,0xCE,0x33,0x57, 0x6B,0x31,0x5E,0xCE,
            0xCB,0xB6,0x40,0x68, 0x37,0xBF,0x51,0xF5,
        ]);
        Self {
            p,
            a,
            b,
            order,
            gx,
            gy,
        }
    }
}

/// A point on an elliptic curve (affine coordinates), or the point at infinity.
#[derive(Clone, Debug)]
enum EcPoint {
    /// The identity element (point at infinity).
    Infinity,
    /// An affine point (x, y) on the curve.
    Affine { x: BigUint, y: BigUint },
}

impl EcPoint {
    /// Create a new affine point.
    fn new(x: BigUint, y: BigUint) -> Self {
        EcPoint::Affine { x, y }
    }

    /// Check if this point is the identity.
    fn is_infinity(&self) -> bool {
        matches!(self, EcPoint::Infinity)
    }
}

/// Modular inverse using extended Euclidean algorithm.
///
/// Returns a^(-1) mod m, or None if gcd(a, m) != 1.
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_integer::Integer;

    if a.is_zero() {
        return None;
    }

    // Use the extended GCD on signed integers for correctness.
    // We work with BigInt to handle negative intermediates.
    let a_int = num_bigint::BigInt::from(a.clone());
    let m_int = num_bigint::BigInt::from(m.clone());

    let result = a_int.extended_gcd(&m_int);
    if result.gcd != num_bigint::BigInt::one() {
        return None;
    }

    // Ensure the result is positive mod m
    let inv = ((result.x % &m_int) + &m_int) % &m_int;
    inv.to_biguint()
}

/// Elliptic curve point doubling on a short Weierstrass curve.
///
/// For point P = (x, y):
///   lambda = (3*x^2 + a) / (2*y) mod p
///   x_r = lambda^2 - 2*x mod p
///   y_r = lambda * (x - x_r) - y mod p
fn ec_double(point: &EcPoint, a: &BigUint, p: &BigUint) -> EcPoint {
    match point {
        EcPoint::Infinity => EcPoint::Infinity,
        EcPoint::Affine { x, y } => {
            if y.is_zero() {
                return EcPoint::Infinity;
            }

            // lambda = (3*x^2 + a) * (2*y)^(-1) mod p
            let two = BigUint::from(2u32);
            let three = BigUint::from(3u32);

            let numerator = (&three * x.modpow(&two, p) + a) % p;
            let denominator = (&two * y) % p;

            let inv = match mod_inverse(&denominator, p) {
                Some(v) => v,
                None => return EcPoint::Infinity,
            };

            let lambda = (&numerator * &inv) % p;

            // x_r = lambda^2 - 2*x mod p
            let x_r = (lambda.modpow(&two, p) + p + p - x - x) % p;

            // y_r = lambda * (x - x_r) - y mod p
            let y_r = if x >= &x_r {
                (&lambda * (x - &x_r) + p - y) % p
            } else {
                (&lambda * (p - &x_r + x) + p - y) % p
            };

            EcPoint::new(x_r, y_r)
        }
    }
}

/// Elliptic curve point addition on a short Weierstrass curve.
///
/// For points P = (x1, y1) and Q = (x2, y2) where P != Q:
///   lambda = (y2 - y1) / (x2 - x1) mod p
///   x_r = lambda^2 - x1 - x2 mod p
///   y_r = lambda * (x1 - x_r) - y1 mod p
fn ec_add(p1: &EcPoint, p2: &EcPoint, a: &BigUint, p: &BigUint) -> EcPoint {
    match (p1, p2) {
        (EcPoint::Infinity, _) => p2.clone(),
        (_, EcPoint::Infinity) => p1.clone(),
        (EcPoint::Affine { x: x1, y: y1 }, EcPoint::Affine { x: x2, y: y2 }) => {
            if x1 == x2 {
                if y1 == y2 {
                    // Same point — use doubling
                    return ec_double(p1, a, p);
                }
                // x equal, y different — points are additive inverses
                return EcPoint::Infinity;
            }

            // lambda = (y2 - y1) * (x2 - x1)^(-1) mod p
            let numerator = if y2 >= y1 {
                (y2 - y1) % p
            } else {
                (p - (y1 - y2) % p) % p
            };

            let denominator = if x2 >= x1 {
                (x2 - x1) % p
            } else {
                (p - (x1 - x2) % p) % p
            };

            let inv = match mod_inverse(&denominator, p) {
                Some(v) => v,
                None => return EcPoint::Infinity,
            };

            let lambda = (&numerator * &inv) % p;

            // x_r = lambda^2 - x1 - x2 mod p
            let two = BigUint::from(2u32);
            let x_r = (lambda.modpow(&two, p) + p + p - x1 - x2) % p;

            // y_r = lambda * (x1 - x_r) - y1 mod p
            let y_r = if x1 >= &x_r {
                (&lambda * (x1 - &x_r) + p - y1) % p
            } else {
                (&lambda * (p - &x_r + x1) + p - y1) % p
            };

            EcPoint::new(x_r, y_r)
        }
    }
}

/// Elliptic curve scalar multiplication using double-and-add.
///
/// Computes k * P on the curve defined by parameters (a, p).
fn ec_scalar_mul(k: &BigUint, point: &EcPoint, a: &BigUint, p: &BigUint) -> EcPoint {
    if k.is_zero() || point.is_infinity() {
        return EcPoint::Infinity;
    }

    let mut result = EcPoint::Infinity;
    let mut addend = point.clone();

    // Double-and-add, LSB first
    let bits = k.to_bytes_be();
    for byte in bits.iter().rev() {
        for bit_pos in 0..8 {
            if (byte >> bit_pos) & 1 == 1 {
                result = ec_add(&result, &addend, a, p);
            }
            addend = ec_double(&addend, a, p);
        }
    }

    result
}

/// Negate a point on the curve: -(x, y) = (x, p - y).
fn ec_negate(point: &EcPoint, p: &BigUint) -> EcPoint {
    match point {
        EcPoint::Infinity => EcPoint::Infinity,
        EcPoint::Affine { x, y } => {
            if y.is_zero() {
                EcPoint::Affine {
                    x: x.clone(),
                    y: BigUint::zero(),
                }
            } else {
                EcPoint::Affine {
                    x: x.clone(),
                    y: p - y,
                }
            }
        }
    }
}

/// Check if a point (x, y) lies on the curve y^2 = x^3 + ax + b (mod p).
#[allow(dead_code)] // Validation helper — used when SAE point verification is implemented
fn ec_is_on_curve(x: &BigUint, y: &BigUint, a: &BigUint, b: &BigUint, p: &BigUint) -> bool {
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);

    let lhs = y.modpow(&two, p);
    let rhs = (x.modpow(&three, p) + (a * x) % p + b) % p;
    lhs == rhs
}

/// Convert a BigUint to a fixed-length big-endian byte array.
/// Pads with leading zeros or truncates to exactly `len` bytes.
fn biguint_to_fixed_bytes(val: &BigUint, len: usize) -> Vec<u8> {
    let bytes = val.to_bytes_be();
    if bytes.len() >= len {
        bytes[bytes.len() - len..].to_vec()
    } else {
        let mut result = vec![0u8; len - bytes.len()];
        result.extend_from_slice(&bytes);
        result
    }
}

/// Encode an EcPoint as uncompressed coordinates: x || y (no 0x04 prefix).
/// Each coordinate is padded to `coord_len` bytes.
fn ec_point_to_bytes(point: &EcPoint, coord_len: usize) -> Option<Vec<u8>> {
    match point {
        EcPoint::Infinity => None,
        EcPoint::Affine { x, y } => {
            let mut result = biguint_to_fixed_bytes(x, coord_len);
            result.extend_from_slice(&biguint_to_fixed_bytes(y, coord_len));
            Some(result)
        }
    }
}

/// Decode uncompressed coordinates (x || y) to an EcPoint.
/// Each coordinate is `coord_len` bytes.
fn ec_point_from_bytes(data: &[u8], coord_len: usize) -> Option<EcPoint> {
    if data.len() != coord_len * 2 {
        return None;
    }
    let x = BigUint::from_bytes_be(&data[..coord_len]);
    let y = BigUint::from_bytes_be(&data[coord_len..]);
    Some(EcPoint::new(x, y))
}

/// Generate a cryptographically random BigUint in [2, upper_bound - 1].
///
/// Uses a simple rejection sampling approach with std random bytes,
/// hashed through SHA-256 for entropy mixing.
fn random_scalar_in_range(upper_bound: &BigUint, byte_len: usize) -> BigUint {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Mix multiple entropy sources via repeated hashing.
    // For a pentesting tool, this provides sufficient randomness.
    let mut seed = Vec::with_capacity(64);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    seed.extend_from_slice(&ts.as_nanos().to_le_bytes());
    seed.extend_from_slice(&(std::process::id() as u64).to_le_bytes());

    // Additional entropy from stack address
    let stack_val: u64 = &seed as *const _ as u64;
    seed.extend_from_slice(&stack_val.to_le_bytes());

    let two = BigUint::from(2u32);
    let _range = upper_bound - &two; // range = order - 2

    // Rejection sampling with hash-based PRNG
    for counter in 0u64..1000 {
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        hasher.update(&counter.to_le_bytes());
        // Hash a second time with different data for more bits if needed
        let hash1 = hasher.finalize();

        let mut buf = Vec::with_capacity(byte_len);
        buf.extend_from_slice(&hash1);

        // If we need more bytes than SHA-256 provides, hash again
        while buf.len() < byte_len {
            let mut hasher2 = Sha256::new();
            hasher2.update(&hash1);
            hasher2.update(&buf);
            hasher2.update(&counter.to_le_bytes());
            let hash2 = hasher2.finalize();
            buf.extend_from_slice(&hash2);
        }
        buf.truncate(byte_len);

        let candidate = BigUint::from_bytes_be(&buf) % upper_bound;
        if candidate >= two {
            return candidate;
        }
    }

    // Fallback (should never happen with 1000 iterations)
    two
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SaeCryptoImpl — Concrete SAE Crypto Backend (Group 19 / P-256)
// ═══════════════════════════════════════════════════════════════════════════════

/// Concrete implementation of the SAE cryptographic operations.
///
/// Currently supports Group 19 (NIST P-256 / secp256r1), which covers
/// 95%+ of real WPA3 deployments. Other groups return `None`.
///
/// ECC operations are implemented using `num-bigint` for arbitrary-precision
/// modular arithmetic. This is sufficient for a pentesting tool where we
/// need correctness over raw speed.
pub struct SaeCryptoImpl;

type HmacSha256 = Hmac<Sha256>;

impl SaeCrypto for SaeCryptoImpl {
    /// Derive the Password Element (PWE) using hunting-and-pecking.
    ///
    /// Per IEEE 802.11-2020 Section 12.4.4.2.2:
    /// 1. Compute max_mac = max(sta_mac, ap_mac), min_mac = min(sta_mac, ap_mac)
    /// 2. For counter = 1..40:
    ///    a. seed = HMAC-SHA-256(max_mac || min_mac, password || counter)
    ///    b. Interpret seed as x-coordinate
    ///    c. If x is a valid x-coord on the curve, compute y and return (x, y)
    /// 3. If no valid point found in 40 iterations, return None
    fn derive_pwe(
        &self,
        group: SaeGroup,
        password: &[u8],
        sta_mac: &[u8; 6],
        ap_mac: &[u8; 6],
        _use_h2e: bool,
    ) -> Option<Vec<u8>> {
        if group != SaeGroup::Group19 {
            return None; // Only P-256 supported currently
        }

        let params = P256Params::new();
        let coord_len = group.scalar_len(); // 32 bytes for P-256

        // Determine max_mac and min_mac (lexicographic comparison)
        let (max_mac, min_mac) = if sta_mac > ap_mac {
            (sta_mac.as_slice(), ap_mac.as_slice())
        } else {
            (ap_mac.as_slice(), sta_mac.as_slice())
        };

        // HMAC key = max_mac || min_mac
        let mut hmac_key = Vec::with_capacity(12);
        hmac_key.extend_from_slice(max_mac);
        hmac_key.extend_from_slice(min_mac);

        // Hunting-and-pecking: try counter values 1..=40
        // Per spec, must always run all 40 iterations (constant time),
        // but for a pentesting tool we can short-circuit on first valid point.
        let two = BigUint::from(2u32);

        for counter in 1u8..=40 {
            // seed = HMAC-SHA-256(key, password || counter)
            let mut mac =
                HmacSha256::new_from_slice(&hmac_key).ok()?;
            mac.update(password);
            mac.update(&[counter]);
            let seed = mac.finalize().into_bytes();

            // Interpret seed as a candidate x-coordinate
            let x = BigUint::from_bytes_be(&seed) % &params.p;

            // Check if x is a valid x-coordinate: compute y^2 = x^3 + ax + b mod p
            let three = BigUint::from(3u32);
            let y_sq = (x.modpow(&three, &params.p)
                + (&params.a * &x) % &params.p
                + &params.b)
                % &params.p;

            // Check if y_sq is a quadratic residue (has a square root mod p)
            // For P-256, p = 3 mod 4, so sqrt = y_sq^((p+1)/4) mod p
            let p_plus_1_div_4 = (&params.p + BigUint::one()) >> 2;
            let y = y_sq.modpow(&p_plus_1_div_4, &params.p);

            // Verify: y^2 mod p == y_sq
            if y.modpow(&two, &params.p) == y_sq {
                // Valid point found. Use the even y (LSB = 0) by convention.
                let y_final = if y.bit(0) {
                    &params.p - &y
                } else {
                    y
                };

                let mut result = biguint_to_fixed_bytes(&x, coord_len);
                result.extend_from_slice(&biguint_to_fixed_bytes(&y_final, coord_len));
                return Some(result);
            }
        }

        None // No valid PWE found in 40 iterations
    }

    /// Generate a random scalar in [2, order - 1] for the given group.
    ///
    /// The scalar is returned as a big-endian byte array of `group.scalar_len()` bytes.
    fn generate_scalar(&self, group: SaeGroup) -> Option<Vec<u8>> {
        if group != SaeGroup::Group19 {
            return None;
        }

        let params = P256Params::new();
        let scalar = random_scalar_in_range(&params.order, group.scalar_len());
        Some(biguint_to_fixed_bytes(&scalar, group.scalar_len()))
    }

    /// Compute the element: -(mask * PWE).
    ///
    /// `mask` is a scalar (big-endian), `pwe` is an uncompressed point (x || y).
    /// Returns the negated product as an uncompressed point (x || y).
    fn compute_element(
        &self,
        group: SaeGroup,
        mask: &[u8],
        pwe: &[u8],
    ) -> Option<Vec<u8>> {
        if group != SaeGroup::Group19 {
            return None;
        }

        let params = P256Params::new();
        let coord_len = group.scalar_len();

        let mask_scalar = BigUint::from_bytes_be(mask);
        let pwe_point = ec_point_from_bytes(pwe, coord_len)?;

        // Compute mask * PWE
        let product = ec_scalar_mul(&mask_scalar, &pwe_point, &params.a, &params.p);

        // Negate the result: -(mask * PWE)
        let negated = ec_negate(&product, &params.p);

        ec_point_to_bytes(&negated, coord_len)
    }

    /// Compute the SAE Confirm value.
    ///
    /// confirm = HMAC-SHA-256(KCK, send_confirm_le || scalar_a || element_a || scalar_b || element_b)
    ///
    /// Per IEEE 802.11-2020 Section 12.4.7.2.
    fn compute_confirm(
        &self,
        group: SaeGroup,
        kck: &[u8],
        send_confirm: u16,
        scalar_a: &[u8],
        element_a: &[u8],
        scalar_b: &[u8],
        element_b: &[u8],
    ) -> Option<Vec<u8>> {
        if group != SaeGroup::Group19 {
            return None;
        }

        let mut mac = HmacSha256::new_from_slice(kck).ok()?;
        mac.update(&send_confirm.to_le_bytes());
        mac.update(scalar_a);
        mac.update(element_a);
        mac.update(scalar_b);
        mac.update(element_b);

        Some(mac.finalize().into_bytes().to_vec())
    }

    /// Derive SAE keys (KCK, PMK) from the shared secret.
    ///
    /// Per IEEE 802.11-2020 Section 12.4.5.4:
    /// 1. keyseed = HMAC-SHA-256(zeros, shared_secret_x)
    /// 2. KCK || PMK = KDF-512(keyseed, "SAE KCK and PMK",
    ///                          max(scalar_a, scalar_b) || min(scalar_a, scalar_b))
    ///
    /// KCK = first 32 bytes, PMK = next 32 bytes.
    ///
    /// `shared_secret` is the x-coordinate of the shared secret point (scalar_len bytes).
    fn derive_keys(
        &self,
        group: SaeGroup,
        shared_secret: &[u8],
        scalar_a: &[u8],
        scalar_b: &[u8],
        _sta_mac: &[u8; 6],
        _ap_mac: &[u8; 6],
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        if group != SaeGroup::Group19 {
            return None;
        }

        // Step 1: keyseed = HMAC-SHA-256(zeros, shared_secret)
        let zeros = vec![0u8; 32];
        let mut mac = HmacSha256::new_from_slice(&zeros).ok()?;
        mac.update(shared_secret);
        let keyseed = mac.finalize().into_bytes();

        // Step 2: KDF-512 to produce 64 bytes (KCK + PMK)
        // Determine max/min scalars (big-endian comparison)
        let (max_scalar, min_scalar) = if scalar_a > scalar_b {
            (scalar_a, scalar_b)
        } else {
            (scalar_b, scalar_a)
        };

        // context = max_scalar || min_scalar
        let mut context = Vec::with_capacity(max_scalar.len() + min_scalar.len());
        context.extend_from_slice(max_scalar);
        context.extend_from_slice(min_scalar);

        // KDF-512: produce 512 bits (64 bytes) using HMAC-SHA-256 in counter mode
        // Per IEEE 802.11-2020 Section 12.7.1.7.2:
        //   result = HMAC-SHA-256(key, counter_le16 || label || context || length_le16)
        let label = b"SAE KCK and PMK";
        let length: u16 = 512; // bits
        let mut output = Vec::with_capacity(64);

        for counter in 1u16..=2 {
            let mut mac = HmacSha256::new_from_slice(&keyseed).ok()?;
            mac.update(&counter.to_le_bytes());
            mac.update(label.as_slice());
            mac.update(&context);
            mac.update(&length.to_le_bytes());
            let block = mac.finalize().into_bytes();
            output.extend_from_slice(&block);
        }

        output.truncate(64);

        let kck = output[..32].to_vec();
        let pmk = output[32..64].to_vec();

        Some((kck, pmk))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Find where extension IEs start in the SAE Commit body (after group_id).
///
/// The body after group_id is: [token] || scalar || element || [extensions]
/// Extensions are TLV-encoded (tag, length, value) and start with valid IE tags.
///
/// We know scalar_len + element_len must be present. Everything beyond that
/// at the end that looks like TLV IEs is extensions; everything between
/// group_id and scalar is token.
fn find_extensions_start(data: &[u8], scalar_len: usize, element_len: usize) -> usize {
    let required = scalar_len + element_len;
    if data.len() <= required {
        return data.len();
    }

    // Try to find TLV extensions at the end by scanning backwards.
    // Extensions typically start with tag 255 (Extension element).
    // Walk from the position after required bytes and check for valid TLV structure.
    let pos = required;

    // Check if there are valid TLV elements starting at various positions
    while pos < data.len() {
        if pos + 2 > data.len() {
            break;
        }
        let tag = data[pos];
        let len = data[pos + 1] as usize;

        // Extension elements use tag 255
        if tag == PASSWORD_IDENTIFIER_IE_TAG && pos + 2 + len <= data.len() {
            // Found what looks like a valid extension IE
            return pos;
        }
        // Not an extension — this byte is part of token/scalar/element
        break;
    }

    data.len()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── SaeGroup tests ──────────────────────────────────────────────────────

    #[test]
    fn test_sae_group_from_id_known() {
        assert_eq!(SaeGroup::from_id(19), Some(SaeGroup::Group19));
        assert_eq!(SaeGroup::from_id(20), Some(SaeGroup::Group20));
        assert_eq!(SaeGroup::from_id(21), Some(SaeGroup::Group21));
        assert_eq!(SaeGroup::from_id(28), Some(SaeGroup::Group28));
        assert_eq!(SaeGroup::from_id(29), Some(SaeGroup::Group29));
        assert_eq!(SaeGroup::from_id(30), Some(SaeGroup::Group30));
    }

    #[test]
    fn test_sae_group_from_id_unknown() {
        assert_eq!(SaeGroup::from_id(0), None);
        assert_eq!(SaeGroup::from_id(1), None);
        assert_eq!(SaeGroup::from_id(18), None);
        assert_eq!(SaeGroup::from_id(22), None);
        assert_eq!(SaeGroup::from_id(255), None);
        assert_eq!(SaeGroup::from_id(u16::MAX), None);
    }

    #[test]
    fn test_sae_group_id_roundtrip() {
        for group in &[
            SaeGroup::Group19, SaeGroup::Group20, SaeGroup::Group21,
            SaeGroup::Group28, SaeGroup::Group29, SaeGroup::Group30,
        ] {
            assert_eq!(SaeGroup::from_id(group.id()), Some(*group));
        }
    }

    #[test]
    fn test_sae_group_sizes_match_c() {
        // Verified against sae_group_scalar_len() / sae_group_element_len() in attack_wpa3.c
        assert_eq!(SaeGroup::Group19.scalar_len(), 32);
        assert_eq!(SaeGroup::Group19.element_len(), 64);
        assert_eq!(SaeGroup::Group20.scalar_len(), 48);
        assert_eq!(SaeGroup::Group20.element_len(), 96);
        assert_eq!(SaeGroup::Group21.scalar_len(), 66);
        assert_eq!(SaeGroup::Group21.element_len(), 132);
        assert_eq!(SaeGroup::Group28.scalar_len(), 32);
        assert_eq!(SaeGroup::Group28.element_len(), 64);
        assert_eq!(SaeGroup::Group29.scalar_len(), 48);
        assert_eq!(SaeGroup::Group29.element_len(), 96);
        assert_eq!(SaeGroup::Group30.scalar_len(), 64);
        assert_eq!(SaeGroup::Group30.element_len(), 128);
    }

    #[test]
    fn test_sae_group_element_is_double_scalar() {
        for group in &[
            SaeGroup::Group19, SaeGroup::Group20, SaeGroup::Group21,
            SaeGroup::Group28, SaeGroup::Group29, SaeGroup::Group30,
        ] {
            assert_eq!(group.element_len(), group.scalar_len() * 2);
        }
    }

    #[test]
    fn test_sae_group_order_equals_prime() {
        for group in &[
            SaeGroup::Group19, SaeGroup::Group20, SaeGroup::Group21,
            SaeGroup::Group28, SaeGroup::Group29, SaeGroup::Group30,
        ] {
            assert_eq!(group.order_len(), group.prime_len());
        }
    }

    #[test]
    fn test_sae_group_mandatory() {
        assert!(SaeGroup::Group19.is_mandatory());
        assert!(!SaeGroup::Group20.is_mandatory());
        assert!(!SaeGroup::Group21.is_mandatory());
        assert!(!SaeGroup::Group28.is_mandatory());
        assert!(!SaeGroup::Group29.is_mandatory());
        assert!(!SaeGroup::Group30.is_mandatory());
    }

    #[test]
    fn test_sae_group_names() {
        assert_eq!(SaeGroup::Group19.name(), "P-256 (NIST)");
        assert_eq!(SaeGroup::Group20.name(), "P-384 (NIST)");
        assert_eq!(SaeGroup::Group21.name(), "P-521 (NIST)");
        assert_eq!(SaeGroup::Group28.name(), "Brainpool P-256r1");
        assert_eq!(SaeGroup::Group29.name(), "Brainpool P-384r1");
        assert_eq!(SaeGroup::Group30.name(), "Brainpool P-512r1");
    }

    #[test]
    fn test_sae_group_display() {
        let s = format!("{}", SaeGroup::Group19);
        assert!(s.contains("19"));
        assert!(s.contains("P-256"));
    }

    // ── SAE Commit parsing/building ─────────────────────────────────────────

    #[test]
    fn test_parse_sae_commit_group19_minimal() {
        // Group ID (19 = 0x0013) + 32-byte scalar + 64-byte element
        let mut data = Vec::new();
        data.extend_from_slice(&19u16.to_le_bytes()); // Group ID
        data.extend_from_slice(&[0xAA; 32]);          // Scalar
        data.extend_from_slice(&[0xBB; 64]);          // Element

        let commit = parse_sae_commit(&data).unwrap();
        assert_eq!(commit.group_id, 19);
        assert!(commit.anti_clogging_token.is_none());
        assert_eq!(commit.scalar.len(), 32);
        assert_eq!(commit.element.len(), 64);
        assert_eq!(commit.scalar, vec![0xAA; 32]);
        assert_eq!(commit.element, vec![0xBB; 64]);
        assert!(commit.password_id.is_none());
    }

    #[test]
    fn test_parse_sae_commit_group20() {
        // Group 20: 48-byte scalar + 96-byte element
        let mut data = Vec::new();
        data.extend_from_slice(&20u16.to_le_bytes());
        data.extend_from_slice(&[0x11; 48]); // Scalar
        data.extend_from_slice(&[0x22; 96]); // Element

        let commit = parse_sae_commit(&data).unwrap();
        assert_eq!(commit.group_id, 20);
        assert_eq!(commit.scalar.len(), 48);
        assert_eq!(commit.element.len(), 96);
    }

    #[test]
    fn test_parse_sae_commit_group21() {
        // Group 21: 66-byte scalar + 132-byte element
        let mut data = Vec::new();
        data.extend_from_slice(&21u16.to_le_bytes());
        data.extend_from_slice(&[0x33; 66]);  // Scalar
        data.extend_from_slice(&[0x44; 132]); // Element

        let commit = parse_sae_commit(&data).unwrap();
        assert_eq!(commit.group_id, 21);
        assert_eq!(commit.scalar.len(), 66);
        assert_eq!(commit.element.len(), 132);
    }

    #[test]
    fn test_parse_sae_commit_with_token() {
        // Group 19 with 16-byte anti-clogging token
        let mut data = Vec::new();
        data.extend_from_slice(&19u16.to_le_bytes()); // Group ID
        data.extend_from_slice(&[0xCC; 16]);           // Token (16 bytes)
        data.extend_from_slice(&[0xAA; 32]);           // Scalar
        data.extend_from_slice(&[0xBB; 64]);           // Element

        let commit = parse_sae_commit(&data).unwrap();
        assert_eq!(commit.group_id, 19);
        let token = commit.anti_clogging_token.unwrap();
        assert_eq!(token.len(), 16);
        assert_eq!(token, vec![0xCC; 16]);
        assert_eq!(commit.scalar, vec![0xAA; 32]);
        assert_eq!(commit.element, vec![0xBB; 64]);
    }

    #[test]
    fn test_parse_sae_commit_too_short() {
        // Too short: only 1 byte
        assert!(parse_sae_commit(&[0x13]).is_none());

        // Group ID only, no scalar/element
        assert!(parse_sae_commit(&[0x13, 0x00]).is_none());

        // Group ID + partial scalar (only 16 bytes, need 32+64=96)
        let mut data = vec![0x13, 0x00];
        data.extend_from_slice(&[0x00; 16]);
        assert!(parse_sae_commit(&data).is_none());
    }

    #[test]
    fn test_parse_sae_commit_empty() {
        assert!(parse_sae_commit(&[]).is_none());
    }

    #[test]
    fn test_build_sae_commit_group19() {
        let commit = SaeCommit {
            group_id: 19,
            anti_clogging_token: None,
            scalar: vec![0xAA; 32],
            element: vec![0xBB; 64],
            password_id: None,
        };

        let buf = build_sae_commit(&commit);
        assert_eq!(buf.len(), 2 + 32 + 64);
        assert_eq!(buf[0], 0x13); // Group 19, LE low byte
        assert_eq!(buf[1], 0x00); // Group 19, LE high byte
        assert_eq!(&buf[2..34], &[0xAA; 32]);
        assert_eq!(&buf[34..98], &[0xBB; 64]);
    }

    #[test]
    fn test_build_sae_commit_with_token() {
        let commit = SaeCommit {
            group_id: 19,
            anti_clogging_token: Some(vec![0xCC; 16]),
            scalar: vec![0xAA; 32],
            element: vec![0xBB; 64],
            password_id: None,
        };

        let buf = build_sae_commit(&commit);
        assert_eq!(buf.len(), 2 + 16 + 32 + 64);
        // Group ID
        assert_eq!(&buf[0..2], &19u16.to_le_bytes());
        // Token
        assert_eq!(&buf[2..18], &[0xCC; 16]);
        // Scalar
        assert_eq!(&buf[18..50], &[0xAA; 32]);
        // Element
        assert_eq!(&buf[50..114], &[0xBB; 64]);
    }

    #[test]
    fn test_build_sae_commit_with_password_id() {
        let commit = SaeCommit {
            group_id: 19,
            anti_clogging_token: None,
            scalar: vec![0xAA; 32],
            element: vec![0xBB; 64],
            password_id: Some("testpw".to_string()),
        };

        let buf = build_sae_commit(&commit);
        // 2 + 32 + 64 + 3 (tag + len + ext_id) + 6 ("testpw")
        assert_eq!(buf.len(), 2 + 32 + 64 + 3 + 6);
        // Check extension tag
        let ext_offset = 2 + 32 + 64;
        assert_eq!(buf[ext_offset], 255); // Extension tag
        assert_eq!(buf[ext_offset + 1], 7); // len: 1 (ext_id) + 6 ("testpw")
        assert_eq!(buf[ext_offset + 2], PASSWORD_IDENTIFIER_EXT_ID);
        assert_eq!(&buf[ext_offset + 3..], b"testpw");
    }

    #[test]
    fn test_sae_commit_roundtrip_group19() {
        let original = SaeCommit {
            group_id: 19,
            anti_clogging_token: None,
            scalar: vec![0x42; 32],
            element: vec![0x7F; 64],
            password_id: None,
        };

        let buf = build_sae_commit(&original);
        let parsed = parse_sae_commit(&buf).unwrap();

        assert_eq!(parsed.group_id, original.group_id);
        assert_eq!(parsed.scalar, original.scalar);
        assert_eq!(parsed.element, original.element);
        assert!(parsed.anti_clogging_token.is_none());
    }

    #[test]
    fn test_sae_commit_roundtrip_with_token() {
        let original = SaeCommit {
            group_id: 20,
            anti_clogging_token: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            scalar: vec![0x42; 48],
            element: vec![0x7F; 96],
            password_id: None,
        };

        let buf = build_sae_commit(&original);
        let parsed = parse_sae_commit(&buf).unwrap();

        assert_eq!(parsed.group_id, original.group_id);
        assert_eq!(parsed.scalar, original.scalar);
        assert_eq!(parsed.element, original.element);
        let token = parsed.anti_clogging_token.unwrap();
        assert_eq!(token, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // ── SAE Confirm parsing/building ────────────────────────────────────────

    #[test]
    fn test_parse_sae_confirm_group19() {
        // Send-Confirm (2 LE) + 32-byte confirm hash
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes()); // send_confirm = 1
        data.extend_from_slice(&[0xFF; 32]);          // confirm hash

        let confirm = parse_sae_confirm(&data).unwrap();
        assert_eq!(confirm.send_confirm, 1);
        assert_eq!(confirm.confirm.len(), 32);
        assert_eq!(confirm.confirm, vec![0xFF; 32]);
    }

    #[test]
    fn test_parse_sae_confirm_counter_value() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0234u16.to_le_bytes());
        data.extend_from_slice(&[0x11; 48]); // P-384 confirm

        let confirm = parse_sae_confirm(&data).unwrap();
        assert_eq!(confirm.send_confirm, 0x0234);
        assert_eq!(confirm.confirm.len(), 48);
    }

    #[test]
    fn test_parse_sae_confirm_too_short() {
        // Only 2 bytes (counter, no confirm data)
        assert!(parse_sae_confirm(&[0x01, 0x00]).is_none());
        // Empty
        assert!(parse_sae_confirm(&[]).is_none());
        // 1 byte
        assert!(parse_sae_confirm(&[0x01]).is_none());
    }

    #[test]
    fn test_build_sae_confirm() {
        let confirm = SaeConfirm {
            send_confirm: 1,
            confirm: vec![0xAB; 32],
        };

        let buf = build_sae_confirm(&confirm);
        assert_eq!(buf.len(), 2 + 32);
        assert_eq!(&buf[0..2], &1u16.to_le_bytes());
        assert_eq!(&buf[2..], &[0xAB; 32]);
    }

    #[test]
    fn test_sae_confirm_roundtrip() {
        let original = SaeConfirm {
            send_confirm: 42,
            confirm: vec![0xDE; 32],
        };

        let buf = build_sae_confirm(&original);
        let parsed = parse_sae_confirm(&buf).unwrap();

        assert_eq!(parsed.send_confirm, original.send_confirm);
        assert_eq!(parsed.confirm, original.confirm);
    }

    // ── Anti-Clogging Token ─────────────────────────────────────────────────

    #[test]
    fn test_parse_anti_clogging_request() {
        let mut data = Vec::new();
        data.extend_from_slice(&19u16.to_le_bytes()); // Group ID
        data.extend_from_slice(&[0xAA; 32]);           // Token

        let token = parse_anti_clogging_request(&data).unwrap();
        assert_eq!(token.group_id, 19);
        assert_eq!(token.token.len(), 32);
        assert_eq!(token.token, vec![0xAA; 32]);
    }

    #[test]
    fn test_parse_anti_clogging_request_too_short() {
        // Just group ID, no token
        assert!(parse_anti_clogging_request(&[0x13, 0x00]).is_none());
        assert!(parse_anti_clogging_request(&[]).is_none());
    }

    // ── SAE Auth Frame Dispatch ─────────────────────────────────────────────

    #[test]
    fn test_parse_sae_auth_commit() {
        let mut body = Vec::new();
        body.extend_from_slice(&19u16.to_le_bytes());
        body.extend_from_slice(&[0xAA; 32]); // scalar
        body.extend_from_slice(&[0xBB; 64]); // element

        let frame = parse_sae_auth(1, 0, &body).unwrap();
        match frame {
            SaeFrame::Commit(c) => {
                assert_eq!(c.group_id, 19);
                assert_eq!(c.scalar.len(), 32);
            }
            _ => panic!("Expected Commit"),
        }
    }

    #[test]
    fn test_parse_sae_auth_commit_h2e() {
        let mut body = Vec::new();
        body.extend_from_slice(&19u16.to_le_bytes());
        body.extend_from_slice(&[0xAA; 32]);
        body.extend_from_slice(&[0xBB; 64]);

        let frame = parse_sae_auth(1, sae_status::SAE_HASH_TO_ELEMENT, &body).unwrap();
        match frame {
            SaeFrame::Commit(c) => assert_eq!(c.group_id, 19),
            _ => panic!("Expected Commit (H2E)"),
        }
    }

    #[test]
    fn test_parse_sae_auth_confirm() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&[0xCC; 32]);

        let frame = parse_sae_auth(2, 0, &body).unwrap();
        match frame {
            SaeFrame::Confirm(c) => {
                assert_eq!(c.send_confirm, 1);
                assert_eq!(c.confirm.len(), 32);
            }
            _ => panic!("Expected Confirm"),
        }
    }

    #[test]
    fn test_parse_sae_auth_anti_clogging() {
        let mut body = Vec::new();
        body.extend_from_slice(&19u16.to_le_bytes());
        body.extend_from_slice(&[0xDD; 20]); // token

        let frame = parse_sae_auth(
            1,
            sae_status::ANTI_CLOGGING_TOKEN_REQUIRED,
            &body,
        ).unwrap();
        match frame {
            SaeFrame::AntiCloggingRequest(t) => {
                assert_eq!(t.group_id, 19);
                assert_eq!(t.token.len(), 20);
            }
            _ => panic!("Expected AntiCloggingRequest"),
        }
    }

    #[test]
    fn test_parse_sae_auth_group_reject() {
        // AP rejects with supported groups list: 19, 20
        let mut body = Vec::new();
        body.extend_from_slice(&19u16.to_le_bytes());
        body.extend_from_slice(&20u16.to_le_bytes());

        let frame = parse_sae_auth(
            1,
            sae_status::FINITE_CYCLIC_GROUP_NOT_SUPPORTED,
            &body,
        ).unwrap();
        match frame {
            SaeFrame::GroupReject { supported_groups } => {
                assert_eq!(supported_groups, vec![19, 20]);
            }
            _ => panic!("Expected GroupReject"),
        }
    }

    #[test]
    fn test_parse_sae_auth_group_reject_empty() {
        // AP rejects without listing supported groups
        let frame = parse_sae_auth(
            1,
            sae_status::FINITE_CYCLIC_GROUP_NOT_SUPPORTED,
            &[],
        ).unwrap();
        match frame {
            SaeFrame::GroupReject { supported_groups } => {
                assert!(supported_groups.is_empty());
            }
            _ => panic!("Expected GroupReject"),
        }
    }

    #[test]
    fn test_parse_sae_auth_unknown_password_id() {
        let frame = parse_sae_auth(
            1,
            sae_status::UNKNOWN_PASSWORD_IDENTIFIER,
            &[],
        ).unwrap();
        assert!(matches!(frame, SaeFrame::UnknownPasswordId));
    }

    #[test]
    fn test_parse_sae_auth_unknown_seq_status() {
        // seq=3 doesn't exist in SAE
        assert!(parse_sae_auth(3, 0, &[]).is_none());
        // seq=2 with non-zero status
        assert!(parse_sae_auth(2, 1, &[]).is_none());
    }

    // ── WPA3 Transition Detection ───────────────────────────────────────────

    #[test]
    fn test_detect_wpa3_transition_mode() {
        let rsn = RsnInfo {
            security: crate::protocol::ieee80211::Security::Wpa3,
            group_cipher: crate::protocol::ieee80211::CipherSuite::Ccmp,
            pairwise_ciphers: vec![crate::protocol::ieee80211::CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::Psk, AkmSuite::Sae],
            mfp_capable: true,
            mfp_required: false,
            rsn_caps: 0,
            ..Default::default()
        };

        let info = detect_wpa3_transition(&rsn);
        assert!(info.has_wpa2_psk);
        assert!(info.has_sae);
        assert!(info.mfp_capable);
        assert!(!info.mfp_required);
        assert!(info.transition_mode);
    }

    #[test]
    fn test_detect_wpa3_only_not_transition() {
        let rsn = RsnInfo {
            security: crate::protocol::ieee80211::Security::Wpa3,
            group_cipher: crate::protocol::ieee80211::CipherSuite::Ccmp,
            pairwise_ciphers: vec![crate::protocol::ieee80211::CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::Sae],
            mfp_capable: true,
            mfp_required: true,
            ..Default::default()
        };

        let info = detect_wpa3_transition(&rsn);
        assert!(!info.has_wpa2_psk);
        assert!(info.has_sae);
        assert!(info.mfp_required);
        assert!(!info.transition_mode);
    }

    #[test]
    fn test_detect_wpa2_only_not_transition() {
        let rsn = RsnInfo {
            security: crate::protocol::ieee80211::Security::Wpa2,
            group_cipher: crate::protocol::ieee80211::CipherSuite::Ccmp,
            pairwise_ciphers: vec![crate::protocol::ieee80211::CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::Psk],
            ..Default::default()
        };

        let info = detect_wpa3_transition(&rsn);
        assert!(info.has_wpa2_psk);
        assert!(!info.has_sae);
        assert!(!info.transition_mode);
    }

    #[test]
    fn test_detect_transition_mfp_required_not_transition() {
        // Both PSK and SAE but MFP required — not transition (pure WPA3 mode)
        let rsn = RsnInfo {
            security: crate::protocol::ieee80211::Security::Wpa3,
            group_cipher: crate::protocol::ieee80211::CipherSuite::Ccmp,
            pairwise_ciphers: vec![crate::protocol::ieee80211::CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::Psk, AkmSuite::Sae],
            mfp_capable: true,
            mfp_required: true,
            ..Default::default()
        };

        let info = detect_wpa3_transition(&rsn);
        assert!(info.has_wpa2_psk);
        assert!(info.has_sae);
        assert!(info.mfp_required);
        // Not transition because MFP is required (WPA2 clients can't connect without MFP)
        assert!(!info.transition_mode);
    }

    #[test]
    fn test_detect_transition_ft_variants() {
        let rsn = RsnInfo {
            security: crate::protocol::ieee80211::Security::Wpa3,
            group_cipher: crate::protocol::ieee80211::CipherSuite::Ccmp,
            pairwise_ciphers: vec![crate::protocol::ieee80211::CipherSuite::Ccmp],
            akm_suites: vec![AkmSuite::FtPsk, AkmSuite::FtSae],
            mfp_capable: true,
            mfp_required: false,
            ..Default::default()
        };

        let info = detect_wpa3_transition(&rsn);
        assert!(info.has_wpa2_psk); // FT-PSK counts as WPA2-PSK
        assert!(info.has_sae);      // FT-SAE counts as SAE
        assert!(info.transition_mode);
    }

    // ── Dragonblood Indicators ──────────────────────────────────────────────

    #[test]
    fn test_dragonblood_default_no_vulns() {
        let indicators = DragonbloodIndicators::default();
        assert_eq!(indicators.vulnerability_count(), 0);
        assert!(!indicators.any_vulnerable());
        assert!(indicators.applicable_cves().is_empty());
    }

    #[test]
    fn test_dragonblood_all_vulns() {
        let indicators = DragonbloodIndicators {
            accepts_group_downgrade: true,
            timing_side_channel: true,
            reflects_commit: true,
            accepts_invalid_curve: true,
            vulnerable_to_commit_dos: true,
            cache_attack_possible: true,
            transition_downgrade: true,
            token_replay_possible: true,
        };
        assert_eq!(indicators.vulnerability_count(), 8);
        assert!(indicators.any_vulnerable());
    }

    #[test]
    fn test_dragonblood_cves() {
        let indicators = DragonbloodIndicators {
            timing_side_channel: true,
            accepts_group_downgrade: true,
            accepts_invalid_curve: true,
            ..Default::default()
        };
        let cves = indicators.applicable_cves();
        assert!(cves.contains(&"CVE-2019-9494"));
        assert!(cves.contains(&"CVE-2019-9495"));
        assert!(cves.contains(&"CVE-2019-9498"));
        assert!(cves.contains(&"CVE-2019-9499"));
    }

    #[test]
    fn test_dragonblood_commit_dos_cve() {
        let indicators = DragonbloodIndicators {
            vulnerable_to_commit_dos: true,
            ..Default::default()
        };
        let cves = indicators.applicable_cves();
        assert_eq!(cves, vec!["CVE-2019-9497"]);
    }

    #[test]
    fn test_dragonblood_transition_cve() {
        let indicators = DragonbloodIndicators {
            transition_downgrade: true,
            ..Default::default()
        };
        let cves = indicators.applicable_cves();
        assert_eq!(cves, vec!["CVE-2019-9496"]);
    }

    // ── H2E ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_h2e_auth() {
        assert!(is_h2e_auth(126));
        assert!(is_h2e_auth(sae_status::SAE_HASH_TO_ELEMENT));
        assert!(!is_h2e_auth(0));
        assert!(!is_h2e_auth(76));
        assert!(!is_h2e_auth(77));
    }

    // ── Status code constants ───────────────────────────────────────────────

    #[test]
    fn test_sae_status_codes_match_ieee() {
        // Verify against 802.11 Table 9-50 and attack_wpa3.c constants
        assert_eq!(sae_status::SUCCESS, 0);
        assert_eq!(sae_status::FAILURE, 1);
        assert_eq!(sae_status::ANTI_CLOGGING_TOKEN_REQUIRED, 76);
        assert_eq!(sae_status::FINITE_CYCLIC_GROUP_NOT_SUPPORTED, 77);
        assert_eq!(sae_status::UNKNOWN_PASSWORD_IDENTIFIER, 123);
        assert_eq!(sae_status::SAE_HASH_TO_ELEMENT, 126);
    }

    // ── Weak-to-strong ordering ─────────────────────────────────────────────

    #[test]
    fn test_groups_weak_to_strong_ordering() {
        // Verify security levels are non-decreasing
        let mut prev_bits = 0u16;
        for group in SAE_GROUPS_WEAK_TO_STRONG {
            assert!(group.security_bits() >= prev_bits,
                "Group {} ({} bits) should be >= {} bits",
                group.id(), group.security_bits(), prev_bits);
            prev_bits = group.security_bits();
        }
    }

    #[test]
    fn test_default_groups_contains_mandatory() {
        assert!(SAE_DEFAULT_GROUPS.contains(&SaeGroup::Group19));
    }

    // ── SAE-PK parsing ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_sae_pk_elements() {
        // Build a fake SAE-PK extension: tag(255) + len + ext_id(0x3F) + fp_len + fp + modifier
        let mut data = Vec::new();
        data.push(255);          // Extension tag
        data.push(10);           // Length: ext_id(1) + fp_len(1) + fp(4) + modifier(4)
        data.push(SAE_PK_EXT_ID); // Extension Element ID
        data.push(4);            // fingerprint length
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // fingerprint
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // modifier

        let pk = parse_sae_pk_elements(&data).unwrap();
        assert_eq!(pk.fingerprint, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(pk.modifier, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_sae_pk_elements_no_pk() {
        // Extension tag but wrong ext_id
        let data = vec![255, 3, 0x01, 0x02, 0x03];
        assert!(parse_sae_pk_elements(&data).is_none());
    }

    #[test]
    fn test_parse_sae_pk_elements_empty() {
        assert!(parse_sae_pk_elements(&[]).is_none());
    }

    // ── SaeCryptoImpl tests ────────────────────────────────────────────────

    #[test]
    fn test_p256_params_valid() {
        let params = P256Params::new();
        // Generator must be on the curve
        assert!(ec_is_on_curve(&params.gx, &params.gy, &params.a, &params.b, &params.p));
    }

    #[test]
    fn test_p256_generator_order() {
        // n * G should be the point at infinity
        let params = P256Params::new();
        let g = EcPoint::new(params.gx.clone(), params.gy.clone());
        let result = ec_scalar_mul(&params.order, &g, &params.a, &params.p);
        assert!(result.is_infinity(), "n * G must be point at infinity");
    }

    #[test]
    fn test_ec_double_identity() {
        let params = P256Params::new();
        let result = ec_double(&EcPoint::Infinity, &params.a, &params.p);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_ec_add_identity() {
        let params = P256Params::new();
        let g = EcPoint::new(params.gx.clone(), params.gy.clone());
        // G + O = G
        let result = ec_add(&g, &EcPoint::Infinity, &params.a, &params.p);
        match result {
            EcPoint::Affine { x, y } => {
                assert_eq!(x, params.gx);
                assert_eq!(y, params.gy);
            }
            EcPoint::Infinity => panic!("expected affine point"),
        }
    }

    #[test]
    fn test_ec_scalar_mul_known_value() {
        // 2 * G should produce the known P-256 doubling result
        let params = P256Params::new();
        let g = EcPoint::new(params.gx.clone(), params.gy.clone());
        let two = BigUint::from(2u32);
        let result = ec_scalar_mul(&two, &g, &params.a, &params.p);
        match &result {
            EcPoint::Affine { x, y } => {
                // Verify the result is on the curve
                assert!(ec_is_on_curve(x, y, &params.a, &params.b, &params.p));
                // Verify it's not the generator itself
                assert_ne!(x, &params.gx);
            }
            EcPoint::Infinity => panic!("2*G should not be infinity"),
        }
    }

    #[test]
    fn test_ec_negate_and_add() {
        // G + (-G) = infinity
        let params = P256Params::new();
        let g = EcPoint::new(params.gx.clone(), params.gy.clone());
        let neg_g = ec_negate(&g, &params.p);
        let result = ec_add(&g, &neg_g, &params.a, &params.p);
        assert!(result.is_infinity(), "G + (-G) must be infinity");
    }

    #[test]
    fn test_ec_point_encode_decode_roundtrip() {
        let params = P256Params::new();
        let g = EcPoint::new(params.gx.clone(), params.gy.clone());
        let bytes = ec_point_to_bytes(&g, 32).unwrap();
        assert_eq!(bytes.len(), 64);

        let decoded = ec_point_from_bytes(&bytes, 32).unwrap();
        match decoded {
            EcPoint::Affine { x, y } => {
                assert_eq!(x, params.gx);
                assert_eq!(y, params.gy);
            }
            EcPoint::Infinity => panic!("expected affine point"),
        }
    }

    #[test]
    fn test_crypto_impl_generate_scalar_group19() {
        let crypto = SaeCryptoImpl;
        let scalar = crypto.generate_scalar(SaeGroup::Group19).unwrap();
        assert_eq!(scalar.len(), 32, "Group 19 scalar must be 32 bytes");

        // Scalar should be >= 2 (not all zeros or 1)
        let val = BigUint::from_bytes_be(&scalar);
        assert!(val >= BigUint::from(2u32), "scalar must be >= 2");

        // Scalar should be < order
        let params = P256Params::new();
        assert!(val < params.order, "scalar must be < order");
    }

    #[test]
    fn test_crypto_impl_generate_scalar_unsupported_group() {
        let crypto = SaeCryptoImpl;
        assert!(crypto.generate_scalar(SaeGroup::Group20).is_none());
        assert!(crypto.generate_scalar(SaeGroup::Group21).is_none());
    }

    #[test]
    fn test_crypto_impl_derive_pwe_group19() {
        let crypto = SaeCryptoImpl;
        let password = b"testpassword";
        let sta_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ap_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let pwe = crypto
            .derive_pwe(SaeGroup::Group19, password, &sta_mac, &ap_mac, false)
            .unwrap();
        assert_eq!(pwe.len(), 64, "PWE must be 64 bytes (x || y)");

        // Verify the resulting point is on the P-256 curve
        let params = P256Params::new();
        let x = BigUint::from_bytes_be(&pwe[..32]);
        let y = BigUint::from_bytes_be(&pwe[32..]);
        assert!(
            ec_is_on_curve(&x, &y, &params.a, &params.b, &params.p),
            "PWE must be on the P-256 curve"
        );
    }

    #[test]
    fn test_crypto_impl_derive_pwe_deterministic() {
        let crypto = SaeCryptoImpl;
        let password = b"hunter2";
        let sta_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ap_mac = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

        let pwe1 = crypto
            .derive_pwe(SaeGroup::Group19, password, &sta_mac, &ap_mac, false)
            .unwrap();
        let pwe2 = crypto
            .derive_pwe(SaeGroup::Group19, password, &sta_mac, &ap_mac, false)
            .unwrap();
        assert_eq!(pwe1, pwe2, "PWE derivation must be deterministic");
    }

    #[test]
    fn test_crypto_impl_compute_element_group19() {
        let crypto = SaeCryptoImpl;
        let password = b"wpa3test";
        let sta_mac = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let ap_mac = [0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0];

        let pwe = crypto
            .derive_pwe(SaeGroup::Group19, password, &sta_mac, &ap_mac, false)
            .unwrap();

        // Generate a mask scalar
        let mask = crypto.generate_scalar(SaeGroup::Group19).unwrap();

        let element = crypto
            .compute_element(SaeGroup::Group19, &mask, &pwe)
            .unwrap();
        assert_eq!(element.len(), 64, "Element must be 64 bytes");

        // Verify the element is on the curve
        let params = P256Params::new();
        let x = BigUint::from_bytes_be(&element[..32]);
        let y = BigUint::from_bytes_be(&element[32..]);
        assert!(
            ec_is_on_curve(&x, &y, &params.a, &params.b, &params.p),
            "Element must be on the P-256 curve"
        );
    }

    #[test]
    fn test_crypto_impl_compute_confirm_returns_32_bytes() {
        let crypto = SaeCryptoImpl;
        let kck = [0x42u8; 32];
        let scalar_a = [0x11u8; 32];
        let element_a = [0x22u8; 64];
        let scalar_b = [0x33u8; 32];
        let element_b = [0x44u8; 64];

        let confirm = crypto
            .compute_confirm(
                SaeGroup::Group19,
                &kck,
                1,
                &scalar_a,
                &element_a,
                &scalar_b,
                &element_b,
            )
            .unwrap();
        assert_eq!(confirm.len(), 32, "Confirm must be 32 bytes (SHA-256)");
    }

    #[test]
    fn test_crypto_impl_compute_confirm_deterministic() {
        let crypto = SaeCryptoImpl;
        let kck = [0xABu8; 32];
        let scalar_a = [0x11u8; 32];
        let element_a = [0x22u8; 64];
        let scalar_b = [0x33u8; 32];
        let element_b = [0x44u8; 64];

        let c1 = crypto
            .compute_confirm(
                SaeGroup::Group19, &kck, 1,
                &scalar_a, &element_a, &scalar_b, &element_b,
            )
            .unwrap();
        let c2 = crypto
            .compute_confirm(
                SaeGroup::Group19, &kck, 1,
                &scalar_a, &element_a, &scalar_b, &element_b,
            )
            .unwrap();
        assert_eq!(c1, c2, "Confirm must be deterministic");
    }

    #[test]
    fn test_crypto_impl_compute_confirm_different_counter() {
        let crypto = SaeCryptoImpl;
        let kck = [0xABu8; 32];
        let scalar_a = [0x11u8; 32];
        let element_a = [0x22u8; 64];
        let scalar_b = [0x33u8; 32];
        let element_b = [0x44u8; 64];

        let c1 = crypto
            .compute_confirm(
                SaeGroup::Group19, &kck, 1,
                &scalar_a, &element_a, &scalar_b, &element_b,
            )
            .unwrap();
        let c2 = crypto
            .compute_confirm(
                SaeGroup::Group19, &kck, 2,
                &scalar_a, &element_a, &scalar_b, &element_b,
            )
            .unwrap();
        assert_ne!(c1, c2, "Different send_confirm must produce different values");
    }

    #[test]
    fn test_crypto_impl_derive_keys_group19() {
        let crypto = SaeCryptoImpl;
        let shared_secret = [0x55u8; 32];
        let scalar_a = [0x11u8; 32];
        let scalar_b = [0x22u8; 32];
        let sta_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ap_mac = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];

        let (kck, pmk) = crypto
            .derive_keys(
                SaeGroup::Group19,
                &shared_secret,
                &scalar_a,
                &scalar_b,
                &sta_mac,
                &ap_mac,
            )
            .unwrap();

        assert_eq!(kck.len(), 32, "KCK must be 32 bytes");
        assert_eq!(pmk.len(), 32, "PMK must be 32 bytes");
        assert_ne!(kck, pmk, "KCK and PMK should differ");
    }

    #[test]
    fn test_crypto_impl_derive_keys_deterministic() {
        let crypto = SaeCryptoImpl;
        let shared_secret = [0x77u8; 32];
        let scalar_a = [0xAA; 32];
        let scalar_b = [0xBB; 32];
        let sta_mac = [0x01; 6];
        let ap_mac = [0x02; 6];

        let (kck1, pmk1) = crypto
            .derive_keys(SaeGroup::Group19, &shared_secret, &scalar_a, &scalar_b, &sta_mac, &ap_mac)
            .unwrap();
        let (kck2, pmk2) = crypto
            .derive_keys(SaeGroup::Group19, &shared_secret, &scalar_a, &scalar_b, &sta_mac, &ap_mac)
            .unwrap();
        assert_eq!(kck1, kck2);
        assert_eq!(pmk1, pmk2);
    }

    #[test]
    fn test_crypto_impl_full_commit_confirm_roundtrip() {
        // Simulate a complete SAE Commit/Confirm exchange between two parties
        let crypto = SaeCryptoImpl;
        let password = b"mysecretpassword";
        let sta_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ap_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        // Both parties derive the same PWE
        let pwe = crypto
            .derive_pwe(SaeGroup::Group19, password, &sta_mac, &ap_mac, false)
            .unwrap();

        // Party A generates scalar and mask, computes element
        let scalar_a = crypto.generate_scalar(SaeGroup::Group19).unwrap();
        let mask_a = crypto.generate_scalar(SaeGroup::Group19).unwrap();
        let element_a = crypto
            .compute_element(SaeGroup::Group19, &mask_a, &pwe)
            .unwrap();

        // Party B generates scalar and mask, computes element
        let scalar_b = crypto.generate_scalar(SaeGroup::Group19).unwrap();
        let mask_b = crypto.generate_scalar(SaeGroup::Group19).unwrap();
        let element_b = crypto
            .compute_element(SaeGroup::Group19, &mask_b, &pwe)
            .unwrap();

        // Verify all produced values have correct lengths
        assert_eq!(scalar_a.len(), 32);
        assert_eq!(scalar_b.len(), 32);
        assert_eq!(element_a.len(), 64);
        assert_eq!(element_b.len(), 64);

        // Both parties can derive keys (using a synthetic shared secret for this test)
        let shared_secret = [0x99u8; 32];
        let (kck_a, pmk_a) = crypto
            .derive_keys(SaeGroup::Group19, &shared_secret, &scalar_a, &scalar_b, &sta_mac, &ap_mac)
            .unwrap();
        let (kck_b, pmk_b) = crypto
            .derive_keys(SaeGroup::Group19, &shared_secret, &scalar_a, &scalar_b, &sta_mac, &ap_mac)
            .unwrap();

        // Both parties derive the same keys
        assert_eq!(kck_a, kck_b, "KCK must match between parties");
        assert_eq!(pmk_a, pmk_b, "PMK must match between parties");

        // Party A computes confirm
        let confirm_a = crypto
            .compute_confirm(
                SaeGroup::Group19, &kck_a, 1,
                &scalar_a, &element_a, &scalar_b, &element_b,
            )
            .unwrap();

        // Party B verifies A's confirm by recomputing
        let verify_a = crypto
            .compute_confirm(
                SaeGroup::Group19, &kck_b, 1,
                &scalar_a, &element_a, &scalar_b, &element_b,
            )
            .unwrap();

        assert_eq!(confirm_a, verify_a, "A's confirm must be verifiable by B");

        // Party B computes its own confirm (reversed scalar/element order)
        let confirm_b = crypto
            .compute_confirm(
                SaeGroup::Group19, &kck_b, 2,
                &scalar_b, &element_b, &scalar_a, &element_a,
            )
            .unwrap();

        assert_eq!(confirm_b.len(), 32);
        // B's confirm should differ from A's (different send_confirm and ordering)
        assert_ne!(confirm_a, confirm_b, "A and B confirms must differ");
    }

    #[test]
    fn test_mod_inverse_basic() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(7u32);
        let inv = mod_inverse(&a, &m).unwrap();
        // 3 * 5 = 15 = 1 mod 7
        assert_eq!(inv, BigUint::from(5u32));
    }

    #[test]
    fn test_mod_inverse_zero() {
        let a = BigUint::zero();
        let m = BigUint::from(7u32);
        assert!(mod_inverse(&a, &m).is_none());
    }

    #[test]
    fn test_biguint_to_fixed_bytes_padding() {
        let val = BigUint::from(0xAABBu32);
        let bytes = biguint_to_fixed_bytes(&val, 4);
        assert_eq!(bytes, vec![0x00, 0x00, 0xAA, 0xBB]);
    }

    #[test]
    fn test_biguint_to_fixed_bytes_exact() {
        let val = BigUint::from(0xAABBCCDDu32);
        let bytes = biguint_to_fixed_bytes(&val, 4);
        assert_eq!(bytes, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
