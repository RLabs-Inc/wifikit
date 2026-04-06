//! RTL8852AU TX diagnostic — tests injection through SharedAdapter
//!
//! Sends probe requests on a fixed channel, checks for probe responses.
//! Also tests auth frame injection (like PMKID attack).
//!
//! Usage:
//!   cargo run --bin test_8852au_tx [channel]
//!   Default: channel 6

use std::time::{Duration, Instant};

use wifikit::core::adapter::AdapterInfo;
use wifikit::core::chip::ChipId;
use wifikit::core::TxOptions;
use wifikit::core::MacAddress;
use wifikit::pipeline::FrameGate;
use wifikit::protocol::frames;
use wifikit::protocol::ieee80211::StatusCode;
use wifikit::store::FrameStore;

fn main() {
    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

    eprintln!("=== RTL8852AU TX Test — Channel {} ===\n", channel);

    let info = AdapterInfo {
        vid: 0x2357, pid: 0x013F,
        chip: ChipId::Rtl8852au,
        name: "TP-Link Archer TX20U Plus (RTL8852AU)",
        bus: 0, address: 0,
    };

    let store = FrameStore::new();
    let gate = FrameGate::new(store.clone(), None);

    eprintln!("Opening via SharedAdapter::spawn...");
    let shared = wifikit::adapter::SharedAdapter::spawn(&info, gate.clone(), |msg| {
        eprintln!("  {}", msg);
    }).expect("spawn failed");

    let our_mac = shared.mac();
    let driver_mac = shared.driver_mac();
    eprintln!("\nMAC (randomized): {}", our_mac);
    eprintln!("MAC (driver/HW):  {}", driver_mac);

    // Set channel
    eprintln!("\nSetting channel {}...", channel);
    shared.set_channel(channel).expect("set_channel failed");
    eprintln!("Channel set. Waiting 500ms for settle...");
    std::thread::sleep(Duration::from_millis(500));

    let sub = shared.subscribe("tx-test");

    // ── Test 1: Probe request (our MAC as SA) ──
    eprintln!("\n══════════════════════════════════════");
    eprintln!("  TEST 1: Probe Request (SA = our MAC)");
    eprintln!("══════════════════════════════════════");

    let probe = frames::build_probe_request(&our_mac, "", &[]).expect("build probe");
    eprintln!("Frame: {} bytes, SA={}", probe.len(), our_mac);
    eprintln!("FC: {:02X}{:02X}  DA: FF:FF:FF:FF:FF:FF", probe[0], probe[1]);

    let tx_opts = TxOptions::default();
    for i in 1..=5 {
        match shared.tx_frame(&probe, &tx_opts) {
            Ok(()) => eprintln!("  TX #{}: OK (bulk write succeeded)", i),
            Err(e) => eprintln!("  TX #{}: FAILED: {}", i, e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Wait for probe responses
    eprintln!("\nListening 3s for probe responses...");
    let listen_start = Instant::now();
    let mut probe_resps = 0u32;
    while listen_start.elapsed() < Duration::from_secs(3) {
        if let Some(frame) = sub.try_recv() {
            let raw = &frame.raw;
            if raw.len() >= 2 {
                let fc = u16::from_le_bytes([raw[0], raw[1]]);
                let subtype = (fc >> 4) & 0xF;
                let ftype = (fc >> 2) & 0x3;
                // Probe response = type 0 subtype 5
                if ftype == 0 && subtype == 5 {
                    probe_resps += 1;
                    if raw.len() >= 16 && probe_resps <= 10 {
                        let sa = &raw[10..16];
                        eprintln!("  ProbeResp #{} from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            probe_resps, sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
                    }
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    eprintln!("Result: {} probe responses received", probe_resps);
    if probe_resps > 0 {
        eprintln!("  ✓ TX WORKS — probe requests are being transmitted and APs respond");
    } else {
        eprintln!("  ✗ No probe responses — TX may not be working");
    }

    // ── Test 2: Probe request with DRIVER MAC as SA ──
    eprintln!("\n══════════════════════════════════════");
    eprintln!("  TEST 2: Probe Request (SA = driver MAC)");
    eprintln!("══════════════════════════════════════");

    let probe2 = frames::build_probe_request(&driver_mac, "", &[]).expect("build probe");
    for i in 1..=5 {
        match shared.tx_frame(&probe2, &tx_opts) {
            Ok(()) => eprintln!("  TX #{}: OK", i),
            Err(e) => eprintln!("  TX #{}: FAILED: {}", i, e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    eprintln!("\nListening 3s for probe responses...");
    let listen_start = Instant::now();
    let mut probe_resps2 = 0u32;
    while listen_start.elapsed() < Duration::from_secs(3) {
        if let Some(frame) = sub.try_recv() {
            let raw = &frame.raw;
            if raw.len() >= 2 {
                let fc = u16::from_le_bytes([raw[0], raw[1]]);
                if (fc >> 2) & 0x3 == 0 && (fc >> 4) & 0xF == 5 {
                    probe_resps2 += 1;
                    if raw.len() >= 16 && probe_resps2 <= 5 {
                        let sa = &raw[10..16];
                        eprintln!("  ProbeResp #{} from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            probe_resps2, sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
                    }
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    eprintln!("Result: {} probe responses (driver MAC)", probe_resps2);

    // ── Test 3: Auth frame to an AP (PMKID-style) ──
    eprintln!("\n══════════════════════════════════════");
    eprintln!("  TEST 3: Auth to AP (PMKID-style)");
    eprintln!("══════════════════════════════════════");

    // Find an AP from beacons
    eprintln!("Looking for APs on channel {}...", channel);
    let listen_start = Instant::now();
    let mut target_bssid: Option<MacAddress> = None;
    while listen_start.elapsed() < Duration::from_secs(2) {
        if let Some(frame) = sub.try_recv() {
            let raw = &frame.raw;
            if raw.len() >= 24 {
                let fc = u16::from_le_bytes([raw[0], raw[1]]);
                let ftype = (fc >> 2) & 0x3;
                let subtype = (fc >> 4) & 0xF;
                // Beacon = type 0 subtype 8
                if ftype == 0 && subtype == 8 {
                    if let Some(bssid) = MacAddress::from_slice(&raw[16..22]) {
                        eprintln!("  Found AP: {}", bssid);
                        target_bssid = Some(bssid);
                        break;
                    }
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    if let Some(bssid) = target_bssid {
        eprintln!("Sending Auth to {} (SA={})...", bssid, our_mac);
        let auth = frames::build_auth(
            &our_mac, &bssid,
            0, // open system
            1, // seq 1
            StatusCode::Success,
        );
        for i in 1..=3 {
            match shared.tx_frame(&auth, &tx_opts) {
                Ok(()) => eprintln!("  Auth TX #{}: OK", i),
                Err(e) => eprintln!("  Auth TX #{}: FAILED: {}", i, e),
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        eprintln!("\nListening 5s for Auth response...");
        let listen_start = Instant::now();
        let mut auth_resps = 0u32;
        while listen_start.elapsed() < Duration::from_secs(5) {
            if let Some(frame) = sub.try_recv() {
                let raw = &frame.raw;
                if raw.len() >= 30 {
                    let fc = u16::from_le_bytes([raw[0], raw[1]]);
                    let ftype = (fc >> 2) & 0x3;
                    let subtype = (fc >> 4) & 0xF;
                    // Auth = type 0 subtype 11
                    if ftype == 0 && subtype == 11 {
                        let sa = MacAddress::from_slice(&raw[10..16]).unwrap();
                        let da = MacAddress::from_slice(&raw[4..10]).unwrap();
                        let status = u16::from_le_bytes([raw[28], raw[29]]);
                        let seq = u16::from_le_bytes([raw[26], raw[27]]);
                        auth_resps += 1;
                        eprintln!("  Auth Response! SA={} DA={} seq={} status={}",
                            sa, da, seq, status);
                        if da == our_mac {
                            eprintln!("  ✓ AP responded TO US — TX confirmed working!");
                        }
                    }
                }
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if auth_resps == 0 {
            eprintln!("  ✗ No auth responses in 5s");
        }
    } else {
        eprintln!("  No APs found on channel {} — skipping auth test", channel);
    }

    // ── Summary ──
    eprintln!("\n══════════════════════════════════════");
    eprintln!("  SUMMARY");
    eprintln!("══════════════════════════════════════");
    eprintln!("  Probe (our MAC):    {} responses", probe_resps);
    eprintln!("  Probe (driver MAC): {} responses", probe_resps2);
    eprintln!("  Auth (PMKID-style): see above");
    eprintln!("\nDone.");
}
