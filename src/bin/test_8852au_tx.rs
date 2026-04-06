//! RTL8852AU TX diagnostic — tests injection through SharedAdapter
//!
//! Sends probe requests on a fixed channel, checks for probe responses.
//! Also tests auth frame injection (like PMKID attack).
//! V2: checks DA field to distinguish "response to US" vs ambient traffic.
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

const MGMT_SUBTYPES: [&str; 16] = [
    "AssocReq", "AssocResp", "ReassocReq", "ReassocResp",
    "ProbeReq", "ProbeResp", "TimingAdv", "Reserved",
    "Beacon", "ATIM", "Disassoc", "Auth",
    "Deauth", "Action", "ActionNoAck", "Reserved",
];

fn mac_from(raw: &[u8], off: usize) -> String {
    if raw.len() >= off + 6 {
        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            raw[off], raw[off+1], raw[off+2], raw[off+3], raw[off+4], raw[off+5])
    } else {
        "??:??:??:??:??:??".to_string()
    }
}

fn main() {
    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

    eprintln!("=== RTL8852AU TX Test V2 — Channel {} ===\n", channel);

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

    // Get pipeline stats for TX feedback monitoring
    let sp = wifikit::chips::rtl8852au::get_pipeline_stats();

    // Drain any queued frames
    while sub.try_recv().is_some() {}

    let tx_opts = TxOptions::default();

    // Pipeline stats helper
    let print_stats = |label: &str| {
        if let Some(ref sp) = sp {
            use std::sync::atomic::Ordering::Relaxed;
            eprintln!("  [pipeline {}] usb_reads={} frames={} tx_rpt={} c2h={} other={}",
                label,
                sp.usb_reads.load(Relaxed),
                sp.frames_submitted.load(Relaxed),
                sp.rpkt_tx_rpt.load(Relaxed),
                sp.rpkt_c2h.load(Relaxed),
                sp.rpkt_other.load(Relaxed));
        }
    };
    print_stats("initial");

    // ── Test 0: Verbatim pcap probe (capture machine's MAC + WD) ──
    eprintln!("\n══════════════════════════════════════");
    eprintln!("  TEST 0: Verbatim pcap probe (SA=0A:C4:90:27:7C:AB)");
    eprintln!("══════════════════════════════════════");
    eprintln!("  This is the EXACT bytes from the working Linux capture.");
    eprintln!("  If this works, our WD format or MAC is wrong.");
    eprintln!("  If this fails too, firmware TX path is broken.");

    // Exact pcap TX frame BULK_212: 48-byte WD + 42-byte probe request
    let pcap_tx: [u8; 90] = [
        0x00, 0xC4, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x24, 0x00, 0x00, 0x20, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x40, 0x00, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0xC4, 0x90, 0x27, 0x7C, 0xAB,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x82, 0x84, 0x8B, 0x96,
        0x8C, 0x12, 0x98, 0x24, 0x32, 0x04, 0xB0, 0x48, 0x60, 0x6C,
    ];
    let pcap_mac_str = "0A:C4:90:27:7C:AB";

    for i in 1..=5 {
        match shared.tx_frame(&pcap_tx[48..], &tx_opts) {
            Ok(()) => eprintln!("  via inject_frame #{}: OK", i),
            Err(e) => eprintln!("  via inject_frame #{}: FAILED: {}", i, e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Also send the raw pcap frame via inject_frame with pcap MAC as SA
    let pcap_probe_frame = &pcap_tx[48..]; // just the 802.11 frame, no WD
    eprintln!("  Now trying inject_frame with pcap MAC as SA...");
    let pcap_mac_addr = MacAddress::from_slice(&[0x0A, 0xC4, 0x90, 0x27, 0x7C, 0xAB]).unwrap();
    if let Some(probe_pcap) = frames::build_probe_request(&pcap_mac_addr, "", &[]) {
        for i in 1..=5 {
            match shared.tx_frame(&probe_pcap, &tx_opts) {
                Ok(()) => eprintln!("    pcap-MAC probe #{}: OK", i),
                Err(e) => eprintln!("    pcap-MAC probe #{}: FAILED: {}", i, e),
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    eprintln!("\nListening 3s for probe responses to pcap MAC {}...", pcap_mac_str);
    let listen_start = Instant::now();
    let pcap_mac = MacAddress::from_slice(&[0x0A, 0xC4, 0x90, 0x27, 0x7C, 0xAB]).unwrap();
    let mut for_pcap = 0u32;
    let mut for_us_t0 = 0u32;
    let mut for_others_t0 = 0u32;
    while listen_start.elapsed() < Duration::from_secs(3) {
        if let Some(frame) = sub.try_recv() {
            let raw = &frame.raw;
            if raw.len() >= 24 {
                let fc = u16::from_le_bytes([raw[0], raw[1]]);
                let ftype = (fc >> 2) & 0x3;
                let subtype = (fc >> 4) & 0xF;
                if ftype == 0 && subtype == 5 {
                    let da = MacAddress::from_slice(&raw[4..10]).unwrap();
                    if da == pcap_mac {
                        for_pcap += 1;
                        if for_pcap <= 5 {
                            eprintln!("  ✓ ProbeResp for PCAP MAC from {}", mac_from(raw, 10));
                        }
                    } else if da == our_mac {
                        for_us_t0 += 1;
                    } else {
                        for_others_t0 += 1;
                    }
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    eprintln!("Result: {} for pcap MAC, {} for our MAC, {} for others", for_pcap, for_us_t0, for_others_t0);

    // ── Test 1: Probe request (our MAC as SA) ──
    eprintln!("\n══════════════════════════════════════");
    eprintln!("  TEST 1: Probe Request (SA = our MAC)");
    eprintln!("══════════════════════════════════════");

    let probe = frames::build_probe_request(&our_mac, "", &[]).expect("build probe");
    eprintln!("TX frame ({} bytes):", probe.len());
    eprintln!("  FC: {:02X}{:02X}  Type: ProbeReq", probe[0], probe[1]);
    eprintln!("  DA: {}  (broadcast)", mac_from(&probe, 4));
    eprintln!("  SA: {}", mac_from(&probe, 10));
    eprintln!("  BSSID: {}", mac_from(&probe, 16));

    for i in 1..=5 {
        match shared.tx_frame(&probe, &tx_opts) {
            Ok(()) => eprintln!("  TX #{}: OK", i),
            Err(e) => eprintln!("  TX #{}: FAILED: {}", i, e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Wait for probe responses — check DA to see if they're for US
    eprintln!("\nListening 3s for probe responses...");
    let listen_start = Instant::now();
    let mut for_us = 0u32;
    let mut for_others = 0u32;
    while listen_start.elapsed() < Duration::from_secs(3) {
        if let Some(frame) = sub.try_recv() {
            let raw = &frame.raw;
            if raw.len() >= 24 {
                let fc = u16::from_le_bytes([raw[0], raw[1]]);
                let ftype = (fc >> 2) & 0x3;
                let subtype = (fc >> 4) & 0xF;
                if ftype == 0 && subtype == 5 {
                    let da = MacAddress::from_slice(&raw[4..10]).unwrap();
                    let sa_str = mac_from(raw, 10);
                    if da == our_mac {
                        for_us += 1;
                        if for_us <= 5 {
                            eprintln!("  ✓ ProbeResp FOR US #{} from {} (DA={})",
                                for_us, sa_str, our_mac);
                        }
                    } else {
                        for_others += 1;
                        if for_others <= 3 {
                            eprintln!("  · ProbeResp for other: DA={} from {}",
                                da, sa_str);
                        }
                    }
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    print_stats("after-test1-TX");
    eprintln!("Result: {} for us, {} for others", for_us, for_others);
    if for_us > 0 {
        eprintln!("  ✓ TX CONFIRMED — APs respond directly to our MAC");
    } else if for_others > 0 {
        eprintln!("  ✗ Probe responses seen but NONE addressed to us — TX likely NOT working");
        eprintln!("    (we see ambient probe responses in monitor mode)");
    } else {
        eprintln!("  ✗ No probe responses at all");
    }

    // ── Test 2: Auth frame to an AP (PMKID-style) ──
    eprintln!("\n══════════════════════════════════════");
    eprintln!("  TEST 2: Auth to AP (PMKID-style)");
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
        let auth = frames::build_auth(
            &our_mac, &bssid,
            0, // open system
            1, // seq 1
            StatusCode::Success,
        );

        eprintln!("\nAuth frame ({} bytes):", auth.len());
        eprintln!("  FC: {:02X}{:02X}", auth[0], auth[1]);
        eprintln!("  DA: {}  (AP)", mac_from(&auth, 4));
        eprintln!("  SA: {}  (us)", mac_from(&auth, 10));
        eprintln!("  BSSID: {}", mac_from(&auth, 16));
        if auth.len() >= 30 {
            let algo = u16::from_le_bytes([auth[24], auth[25]]);
            let seq = u16::from_le_bytes([auth[26], auth[27]]);
            let status = u16::from_le_bytes([auth[28], auth[29]]);
            eprintln!("  Auth: algo={} seq={} status={}", algo, seq, status);
        }
        eprintln!("  Hex: {}", auth.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));

        eprintln!("\nSending 3 auth frames...");
        for i in 1..=3 {
            match shared.tx_frame(&auth, &tx_opts) {
                Ok(()) => eprintln!("  Auth TX #{}: OK", i),
                Err(e) => eprintln!("  Auth TX #{}: FAILED: {}", i, e),
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        eprintln!("\nListening 5s — logging ALL management frames from AP and to us...");
        let listen_start = Instant::now();
        let mut auth_resps = 0u32;
        let mut mgmt_from_ap = 0u32;
        let mut mgmt_to_us = 0u32;
        while listen_start.elapsed() < Duration::from_secs(5) {
            if let Some(frame) = sub.try_recv() {
                let raw = &frame.raw;
                if raw.len() >= 24 {
                    let fc = u16::from_le_bytes([raw[0], raw[1]]);
                    let ftype = (fc >> 2) & 0x3;
                    let subtype = ((fc >> 4) & 0xF) as usize;
                    if ftype == 0 {
                        let da = MacAddress::from_slice(&raw[4..10]).unwrap();
                        let sa = MacAddress::from_slice(&raw[10..16]).unwrap();
                        let frame_bssid = MacAddress::from_slice(&raw[16..22]).unwrap();

                        // Auth response from AP to us
                        if subtype == 11 && sa == bssid {
                            auth_resps += 1;
                            let status = if raw.len() >= 30 {
                                u16::from_le_bytes([raw[28], raw[29]])
                            } else { 0xFFFF };
                            let seq = if raw.len() >= 28 {
                                u16::from_le_bytes([raw[26], raw[27]])
                            } else { 0 };
                            eprintln!("  ★ AUTH from AP! DA={} seq={} status={}", da, seq, status);
                            if da == our_mac {
                                eprintln!("    ✓ Addressed to US!");
                            }
                        }

                        // Any management from AP
                        if sa == bssid && subtype != 8 { // skip beacons
                            mgmt_from_ap += 1;
                            if mgmt_from_ap <= 10 {
                                eprintln!("  AP→ {} DA={} ({})",
                                    MGMT_SUBTYPES[subtype], da, frame_bssid);
                            }
                        }

                        // Any management addressed to us
                        if da == our_mac {
                            mgmt_to_us += 1;
                            if mgmt_to_us <= 10 {
                                eprintln!("  →US {} from {} ({})",
                                    MGMT_SUBTYPES[subtype], sa, frame_bssid);
                            }
                        }
                    }
                }
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        eprintln!("\nAuth from AP: {}", auth_resps);
        eprintln!("Mgmt from AP (non-beacon): {}", mgmt_from_ap);
        eprintln!("Mgmt addressed to us: {}", mgmt_to_us);
    } else {
        eprintln!("  No APs found on channel {} — skipping auth test", channel);
    }

    eprintln!("\nDone.");
}
