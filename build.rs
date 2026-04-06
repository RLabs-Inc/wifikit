//! Build script — generates OUI lookup table from docs/oui.csv
//!
//! Reads the IEEE OUI CSV (semicolon-separated: Assignment;Organization Name)
//! and generates a sorted const array for binary search at runtime.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    let csv_path = Path::new("docs/oui.csv");
    if !csv_path.exists() {
        // No CSV — generate empty table so include!() doesn't fail
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let out_path = Path::new(&out_dir).join("oui_db.rs");
        let mut out = fs::File::create(&out_path).expect("failed to create oui_db.rs");
        writeln!(out, "// No OUI CSV found — empty fallback table").unwrap();
        writeln!(out, "static OUI_DB: &[([u8; 3], &str)] = &[];").unwrap();
        return;
    }

    println!("cargo:rerun-if-changed=docs/oui.csv");
    println!("cargo:rerun-if-changed=docs/mam.csv");
    println!("cargo:rerun-if-changed=docs/oui36.csv");

    let mut entries: BTreeMap<[u8; 3], String> = BTreeMap::new();

    // Load all three IEEE databases:
    // MA-L (OUI, 24-bit): docs/oui.csv — 6-char hex assignments
    // MA-M (28-bit): docs/mam.csv — 7-char hex, we use first 6 (3 bytes)
    // MA-S (36-bit): docs/oui36.csv — 9-char hex, we use first 6 (3 bytes)
    let csv_files = ["docs/oui.csv", "docs/mam.csv", "docs/oui36.csv"];

    for csv_file in &csv_files {
        let path = Path::new(csv_file);
        if !path.exists() {
            continue;
        }
        let csv = fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("failed to read {}", csv_file));

        for line in csv.lines().skip(1) {
            let parts: Vec<&str> = line.splitn(2, ';').collect();
            if parts.len() != 2 {
                continue;
            }

            let hex = parts[0].trim();
            let name = parts[1].trim();

            // Need at least 6 hex chars for 3 OUI bytes
            // Filter to only valid hex characters first (skip corrupt entries)
            let hex_clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if hex_clean.len() < 6 {
                continue;
            }

            // Parse first 3 bytes (6 hex chars) regardless of assignment size
            let oui = match (
                u8::from_str_radix(&hex_clean[0..2], 16),
                u8::from_str_radix(&hex_clean[2..4], 16),
                u8::from_str_radix(&hex_clean[4..6], 16),
            ) {
                (Ok(a), Ok(b), Ok(c)) => [a, b, c],
                _ => continue,
            };

            // Clean up vendor name — shorten for display
            let clean = clean_vendor_name(name);
            if !clean.is_empty() {
                // MA-L entries take priority over MA-M/MA-S for same OUI prefix
                entries.entry(oui).or_insert(clean);
            }
        }
    }

    // Generate Rust source
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("oui_db.rs");
    let mut out = fs::File::create(&out_path).expect("failed to create oui_db.rs");

    writeln!(out, "// Auto-generated from docs/oui.csv — {} entries", entries.len()).unwrap();
    writeln!(out, "// Do not edit manually.").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "static OUI_DB: &[([u8; 3], &str)] = &[").unwrap();

    for (oui, name) in &entries {
        // Escape any quotes in vendor names
        let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
        writeln!(
            out,
            "    ([0x{:02X}, 0x{:02X}, 0x{:02X}], \"{}\"),",
            oui[0], oui[1], oui[2], escaped
        )
        .unwrap();
    }

    writeln!(out, "];").unwrap();
}

/// Extract short vendor name for CLI display.
/// Takes only the first meaningful word/brand name.
/// "TP-Link Technologies Co.,LTD" → "TP-Link"
/// "Cisco Systems, Inc" → "Cisco"
/// "Hewlett Packard Enterprise" → "HPE"
/// "ASUSTek Computer" → "ASUS"
fn clean_vendor_name(name: &str) -> String {
    // Known brand mappings — some companies need special handling
    let brand_map: &[(&str, &str)] = &[
        ("Hewlett Packard", "HP"),
        ("Hewlett-Packard", "HP"),
        ("ASUSTek", "ASUS"),
        ("AsusTek", "ASUS"),
        ("SAMSUNG ELECTRO", "Samsung"),
        ("Samsung Electro", "Samsung"),
        ("GUANGDONG OPPO", "OPPO"),
        ("Guangdong Oppo", "OPPO"),
        ("GUANGDONG GENIUS", "Genius"),
        ("Microsoft Corporation", "Microsoft"),
        ("Texas Instruments", "TI"),
        ("Espressif", "Espressif"),
        ("Raspberry Pi", "RPi"),
        ("Routerboard", "MikroTik"),
        ("Mikrotikls", "MikroTik"),
        ("Amazon Technologies", "Amazon"),
        ("Amazon.com", "Amazon"),
        ("Google, LLC", "Google"),
        ("Google,", "Google"),
        ("Alphabet", "Google"),
        ("HUAWEI TECHNOLOGIES", "Huawei"),
        ("Huawei Technologies", "Huawei"),
        ("Huawei Device", "Huawei"),
        ("ZTE Corporation", "ZTE"),
        ("Xiaomi Communications", "Xiaomi"),
        ("Beijing Xiaomi", "Xiaomi"),
        ("LG Electronics", "LG"),
        ("LG Innotek", "LG"),
        ("Motorola Mobility", "Motorola"),
        ("Motorola Solutions", "Motorola"),
        ("Dell Technologies", "Dell"),
        ("Dell Inc", "Dell"),
        ("Dell EMC", "Dell"),
        ("Lenovo", "Lenovo"),
        ("Sony Interactive", "Sony"),
        ("Sony Mobile", "Sony"),
        ("Nokia Shanghai Bell", "Nokia"),
        ("Nokia Solutions", "Nokia"),
        ("Nokia Danmark", "Nokia"),
        ("Sagemcom Broadband", "Sagemcom"),
        ("Technicolor CH", "Technicolor"),
        ("Technicolor Connected", "Technicolor"),
        ("Arris Group", "Arris"),
        ("CommScope", "CommScope"),
        ("Shenzhen Mercury", "Mercury"),
        ("Shenzhen Tenda", "Tenda"),
        ("SHENZHEN BILIAN", "Bilian"),
        ("Shenzhen Bilian", "Bilian"),
        ("Shenzhen Skyworth", "Skyworth"),
        ("Hon Hai Precision", "Foxconn"),
        ("Foxconn", "Foxconn"),
        ("Pegatron", "Pegatron"),
        ("Quanta Computer", "Quanta"),
        ("Compal Electronics", "Compal"),
        ("Wistron", "Wistron"),
        ("Murata Manufacturing", "Murata"),
        ("Intelbras", "Intelbras"),
        ("INTELBRAS", "Intelbras"),
        ("Fiberhome Telecom", "Fiberhome"),
        ("FiberHome Telecom", "Fiberhome"),
        ("Ruijie Networks", "Ruijie"),
        ("Ruckus Networks", "Ruckus"),
        ("Ruckus Wireless", "Ruckus"),
        ("Ubiquiti Networks", "Ubiquiti"),
        ("Ubiquiti Inc", "Ubiquiti"),
        ("Cambium Networks", "Cambium"),
        ("Juniper Networks", "Juniper"),
        ("Palo Alto Networks", "PaloAlto"),
        ("Fortinet", "Fortinet"),
        ("Extreme Networks", "Extreme"),
        ("AVM Audiovisuelles", "AVM"),
        ("AVM GmbH", "AVM"),
        ("Tuya Smart", "Tuya"),
        ("Espressif Inc", "Espressif"),
        ("Belkin International", "Belkin"),
        ("NETGEAR", "Netgear"),
        ("Netgear", "Netgear"),
        ("D-Link International", "D-Link"),
        ("D-Link Corporation", "D-Link"),
        ("TP-LINK", "TP-Link"),
        ("TP-Link", "TP-Link"),
        ("Cisco Systems", "Cisco"),
        ("Cisco Meraki", "Meraki"),
        ("Aruba, a Hewlett", "Aruba"),
        ("IEEE Registration", "IEEE"),
        ("Private", "Private"),
    ];

    // Check known brands first
    for (pattern, brand) in brand_map {
        if name.starts_with(pattern) {
            return brand.to_string();
        }
    }

    // Fall back to first word, handling hyphenated brands
    let s = name.trim();

    // Take first word (split on space or comma)
    let first_word = s.split(|c: char| c == ' ' || c == ',')
        .next()
        .unwrap_or(s)
        .trim_end_matches(|c: char| c == ',' || c == '.');

    // If first word is too short (< 3 chars) or generic, try first two words
    if first_word.len() < 3 {
        let two_words: String = s.split(|c: char| c == ',')
            .next()
            .unwrap_or(s)
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let result = two_words.trim_end_matches(|c: char| c == ',' || c == '.').to_string();
        if result.len() > 20 {
            return result.chars().take(20).collect();
        }
        return result;
    }

    let result = first_word.to_string();
    if result.len() > 20 {
        return result.chars().take(20).collect();
    }
    result
}
