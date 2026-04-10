//! RTL8852AU standalone monitor — listens on a fixed channel and prints frames
//!
//! Usage: sudo monitor_8852au [channel]   (default: 6)
//!
//! Searches for:
//!   - Internal WiFi MAC (50:1f:c6:f2:0e:ee)
//!   - Test SSIDs (WIFIKIT_TEST_PROBE, WIFIKIT_IBSS_TEST, WIFIKIT_AP_TEST)
//!   - NDRV injection MAC (de:ad:be:ef:ca:fe)
//!   - All 802.11 management frames (probes, beacons, deauth, etc.)

use std::time::{Duration, Instant};
use wifikit::core::chip::ChipDriver;

/// Known MACs to watch for
const INTERNAL_WIFI_MAC: [u8; 6] = [0x50, 0x1f, 0xc6, 0xf2, 0x0e, 0xee];
const INJECT_TEST_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];

/// Test SSIDs to search for in raw data
const TEST_SSIDS: &[&[u8]] = &[
    b"WIFIKIT_TEST_PROBE",
    b"WIFIKIT_IBSS_TEST",
    b"WIFIKIT_AP_TEST",
    b"WIFIKIT_INJECT_TEST",
];

fn mac_to_string(mac: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn frame_type_str(fc0: u8) -> &'static str {
    let ftype = (fc0 >> 2) & 0x3;
    let subtype = (fc0 >> 4) & 0xf;
    match (ftype, subtype) {
        (0, 0) => "AssocReq",
        (0, 1) => "AssocResp",
        (0, 4) => "ProbeReq",
        (0, 5) => "ProbeResp",
        (0, 8) => "Beacon",
        (0, 10) => "Disassoc",
        (0, 11) => "Auth",
        (0, 12) => "Deauth",
        (0, 13) => "Action",
        (0, _) => "Mgmt(?)",
        (1, _) => "Ctrl",
        (2, _) => "Data",
        _ => "???",
    }
}

fn scan_for_80211_frames(data: &[u8], read_num: u64) -> u64 {
    let mut hits = 0u64;

    // The 8852AU RX descriptor is typically 24-32 bytes before the 802.11 frame.
    // Scan through the data looking for valid 802.11 frame control patterns.
    // Management frames: FC byte0 has type=0 (bits 3:2 = 00)
    // We scan by looking for MAC patterns first (more reliable).

    // Search for internal WiFi MAC
    let mut pos = 0;
    while pos + 6 <= data.len() {
        if let Some(idx) = find_bytes(&data[pos..], &INTERNAL_WIFI_MAC) {
            let abs_pos = pos + idx;

            // Check if this could be addr2 (SA) in an 802.11 frame header
            // addr2 starts at FC(2) + Duration(2) + addr1(6) = offset 10 from frame start
            // So FC would be at abs_pos - 10
            if abs_pos >= 10 {
                let fc_pos = abs_pos - 10;
                let fc0 = data[fc_pos];
                let ftype = (fc0 >> 2) & 0x3;

                if ftype <= 2 {
                    // Valid frame type
                    let ftype_str = frame_type_str(fc0);
                    let addr1 = &data[fc_pos + 4..fc_pos + 10];
                    let addr2 = &data[fc_pos + 10..fc_pos + 16];

                    eprintln!(
                        "!!! INTERNAL WIFI [{:>10}] read#{} offset={} | {} | DA={} SA={}",
                        ftype_str,
                        read_num,
                        fc_pos,
                        format!("FC={:02x}{:02x}", fc0, data[fc_pos + 1]),
                        mac_to_string(addr1),
                        mac_to_string(addr2),
                    );

                    // If it's a beacon or probe, try to extract SSID
                    if ftype == 0 {
                        // Management frame — SSID IE is after fixed fields
                        // Beacon: 24-byte header + 12 bytes fixed = offset 36
                        // Probe req: 24-byte header + 0 fixed = offset 24
                        let ie_start = if (fc0 >> 4) & 0xf == 8 {
                            fc_pos + 36 // beacon
                        } else {
                            fc_pos + 24 // probe req/resp
                        };

                        if ie_start + 2 < data.len() {
                            // Look for SSID IE (tag 0)
                            let mut ie_pos = ie_start;
                            while ie_pos + 2 < data.len() {
                                let tag = data[ie_pos];
                                let len = data[ie_pos + 1] as usize;
                                if tag == 0 && len > 0 && ie_pos + 2 + len <= data.len() {
                                    let ssid = &data[ie_pos + 2..ie_pos + 2 + len];
                                    if let Ok(s) = std::str::from_utf8(ssid) {
                                        eprintln!("    SSID: \"{}\"", s);
                                    } else {
                                        eprintln!("    SSID (hex): {:02x?}", ssid);
                                    }
                                    break;
                                }
                                if tag == 0 && len == 0 {
                                    eprintln!("    SSID: (broadcast/hidden)");
                                    break;
                                }
                                ie_pos += 2 + len;
                                if len == 0 { break; }
                            }
                        }
                    }

                    // Show raw context
                    let ctx_start = fc_pos;
                    let ctx_end = std::cmp::min(fc_pos + 40, data.len());
                    eprintln!("    Raw: {:02x?}", &data[ctx_start..ctx_end]);
                    hits += 1;
                }
            }

            pos = abs_pos + 6;
        } else {
            break;
        }
    }

    // Search for NDRV injection MAC
    if let Some(idx) = find_bytes(data, &INJECT_TEST_MAC) {
        eprintln!(
            "!!! NDRV INJECT MAC found at offset {} in read #{}",
            idx, read_num
        );
        let ctx_start = idx.saturating_sub(10);
        let ctx_end = std::cmp::min(idx + 20, data.len());
        eprintln!("    Raw: {:02x?}", &data[ctx_start..ctx_end]);
        hits += 1;
    }

    // Search for test SSIDs (MAC-independent — catches randomized MACs too)
    for ssid in TEST_SSIDS {
        if let Some(idx) = find_bytes(data, ssid) {
            eprintln!(
                "!!! TEST SSID '{}' found at offset {} in read #{}",
                std::str::from_utf8(ssid).unwrap_or("?"),
                idx,
                read_num
            );
            let ctx_start = idx.saturating_sub(30);
            let ctx_end = std::cmp::min(idx + ssid.len() + 10, data.len());
            eprintln!("    Raw: {:02x?}", &data[ctx_start..ctx_end]);
            hits += 1;
        }
    }

    // Also scan for ANY probe request frame (FC=0x40 0x00) — catches randomized MAC probes
    // Probe Request: type=0 subtype=4 → FC byte0 = 0x40
    let mut scan_pos = 0;
    while scan_pos + 30 < data.len() {
        // Look for FC=0x40 followed by valid-looking addresses
        if data[scan_pos] == 0x40 && (data[scan_pos + 1] & 0x0F) == 0x00 {
            // Potential probe request — check if DA is broadcast (ff:ff:ff:ff:ff:ff)
            if scan_pos + 10 <= data.len()
                && data[scan_pos + 4] == 0xff
                && data[scan_pos + 5] == 0xff
                && data[scan_pos + 6] == 0xff
                && data[scan_pos + 7] == 0xff
                && data[scan_pos + 8] == 0xff
                && data[scan_pos + 9] == 0xff
            {
                let sa = &data[scan_pos + 10..scan_pos + 16];
                eprintln!(
                    ">>> PROBE REQUEST detected in read #{} offset={} SA={}",
                    read_num, scan_pos, mac_to_string(sa)
                );
                // Try to extract SSID IE
                let ie_start = scan_pos + 24;
                if ie_start + 2 < data.len() && data[ie_start] == 0 {
                    let ssid_len = data[ie_start + 1] as usize;
                    if ssid_len > 0 && ie_start + 2 + ssid_len <= data.len() {
                        if let Ok(s) = std::str::from_utf8(&data[ie_start + 2..ie_start + 2 + ssid_len]) {
                            eprintln!("    SSID: \"{}\"", s);
                        }
                    } else if ssid_len == 0 {
                        eprintln!("    SSID: (broadcast)");
                    }
                }
                hits += 1;
            }
        }
        scan_pos += 1;
    }

    hits
}

fn main() {
    let ch_num: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

    eprintln!("=== RTL8852AU Monitor — Channel {} ===", ch_num);
    eprintln!("Watching for:");
    eprintln!("  Internal WiFi MAC: {}", mac_to_string(&INTERNAL_WIFI_MAC));
    eprintln!("  NDRV Inject MAC:   {}", mac_to_string(&INJECT_TEST_MAC));
    eprintln!("  Test SSIDs:        WIFIKIT_TEST_PROBE, WIFIKIT_IBSS_TEST, WIFIKIT_AP_TEST");
    eprintln!();

    let (mut driver, _endpoints) =
        match wifikit::chips::rtl8852au::Rtl8852au::open_usb(0x2357, 0x013F) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to open: {}", e);
                std::process::exit(1);
            }
        };

    match driver.init() {
        Ok(()) => eprintln!("INIT OK"),
        Err(e) => {
            eprintln!("INIT FAILED: {}", e);
            std::process::exit(1);
        }
    }

    eprintln!("8852AU MAC: {}", driver.mac());

    let channel = wifikit::core::Channel::new(ch_num);
    driver.set_channel(channel).unwrap();
    eprintln!("Listening on channel {}...\n", ch_num);

    let handle = driver.usb_handle();
    let ep_in = driver.bulk_in_ep();
    let mut buf = vec![0u8; 32768];

    let start = Instant::now();
    let mut total_reads = 0u64;
    let mut total_bytes = 0u64;
    let mut hit_count = 0u64;

    loop {
        match handle.read_bulk(ep_in, &mut buf, Duration::from_millis(200)) {
            Ok(n) if n > 0 => {
                total_reads += 1;
                total_bytes += n as u64;

                let data = &buf[..n];
                hit_count += scan_for_80211_frames(data, total_reads);

                // Periodic status every 200 reads
                if total_reads % 200 == 0 {
                    let elapsed = start.elapsed().as_secs_f64();
                    eprintln!(
                        "[{:.1}s] {} reads, {:.1}KB, {} hits",
                        elapsed,
                        total_reads,
                        total_bytes as f64 / 1024.0,
                        hit_count
                    );
                }
            }
            Ok(_) => {}
            Err(e) => {
                if !format!("{}", e).contains("timed out") {
                    eprintln!("Read error: {}", e);
                }
            }
        }

        if start.elapsed() > Duration::from_secs(300) {
            eprintln!("\n5 minute timeout reached.");
            break;
        }
    }

    eprintln!("\n=== Summary ===");
    eprintln!("Total reads: {}", total_reads);
    eprintln!("Total bytes: {}", total_bytes);
    eprintln!("Hits from internal WiFi / test SSIDs: {}", hit_count);
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
