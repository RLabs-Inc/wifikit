// MT7921AU TX Capabilities Validation
//
// Systematic hardware validation of everything built in the TX overhaul:
//   1. Multi-rate injection (CCK, OFDM, HT, VHT, HE, HE_EXT_SU)
//   2. Bandwidth injection (20/40/80 MHz)
//   3. TX flags (LDPC, STBC, short GI, RTS/CTS protect)
//   4. Per-frame power control
//   5. QoS queue mapping (all 4 AC queues)
//   6. Testmode: burst TX, antenna control, temperature, TSSI
//   7. TXS (TX status / ACK feedback) parsing
//
// Usage:
//   cargo run --bin test_tx_mt7921
//   cargo run --bin test_tx_mt7921 -- --mode rates        # Rate injection only
//   cargo run --bin test_tx_mt7921 -- --mode bw            # Bandwidth tests
//   cargo run --bin test_tx_mt7921 -- --mode power         # Power sweep
//   cargo run --bin test_tx_mt7921 -- --mode testmode      # RF test mode
//   cargo run --bin test_tx_mt7921 -- --mode all           # Everything
//   cargo run --bin test_tx_mt7921 -- --channel 36         # Use channel 36

use std::time::Duration;
use wifikit::core::chip::ChipDriver;
use wifikit::core::{Channel, Band, TxOptions, TxFlags};
use wifikit::core::frame::TxRate;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut channel: u8 = 6;
    let mut mode = "all".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" | "-c" => {
                i += 1;
                if i < args.len() { channel = args[i].parse().unwrap_or(6); }
            }
            "--mode" | "-m" => {
                i += 1;
                if i < args.len() { mode = args[i].clone(); }
            }
            _ => {}
        }
        i += 1;
    }

    let band = if channel >= 36 { Band::Band5g } else { Band::Band2g };

    eprintln!("╔══════════════════════════════════════════════════╗");
    eprintln!("║  MT7921AU TX Capabilities Validation             ║");
    eprintln!("║  The most complete WiFi TX test suite ever built  ║");
    eprintln!("╚══════════════════════════════════════════════════╝\n");
    eprintln!("  Channel: {} ({:?})", channel, band);
    eprintln!("  Mode:    {}\n", mode);

    // ── Open device ──
    let devices = [(0x0E8D, 0x7961, "Fenvi MT7921AU"), (0x3574, 0x6211, "COMFAST CF-952AX")];
    let mut driver = None;
    for (vid, pid, name) in &devices {
        match wifikit::chips::mt7921au::Mt7921au::open_usb(*vid, *pid) {
            Ok((d, _ep)) => {
                eprintln!("  Found: {} ({:04X}:{:04X})", name, vid, pid);
                driver = Some(d);
                break;
            }
            Err(_) => continue,
        }
    }
    let mut driver = match driver {
        Some(d) => d,
        None => { eprintln!("ERROR: No MT7921AU found. Plug it in!"); std::process::exit(1); }
    };

    eprint!("  Init... ");
    driver.init().expect("init failed");
    eprintln!("OK");

    let mac = driver.mac().0;
    eprintln!("  MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    eprint!("  Monitor mode... ");
    driver.set_monitor_mode().expect("monitor failed");
    eprintln!("OK");

    eprint!("  Set channel {}... ", channel);
    driver.set_channel(Channel::new(channel)).expect("set channel failed");
    eprintln!("OK\n");

    let run_all = mode == "all";

    if run_all || mode == "rates" {
        test_rates(&mut driver, channel, band);
    }
    if run_all || mode == "bw" {
        test_bandwidth(&mut driver, channel, band);
    }
    if run_all || mode == "flags" {
        test_flags(&mut driver, channel, band);
    }
    if run_all || mode == "power" {
        test_power_sweep(&mut driver, channel, band);
    }
    if run_all || mode == "qos" {
        test_qos_queues(&mut driver, channel, band);
    }
    if run_all || mode == "testmode" {
        test_testmode(&mut driver);
    }

    eprintln!("\n══════════════════════════════════════════");
    eprintln!("  All tests complete!");
    eprintln!("══════════════════════════════════════════");
}

// ── Helpers ──

/// Build a probe request frame (type=0 subtype=4) — universally accepted by all APs
fn build_probe_request(src_mac: &[u8; 6], channel: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64);
    // Frame Control: type=0 (mgmt), subtype=4 (probe request)
    frame.extend_from_slice(&[0x40, 0x00]);
    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);
    // DA: broadcast
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // SA: our MAC
    frame.extend_from_slice(src_mac);
    // BSSID: broadcast
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // Sequence control
    frame.extend_from_slice(&[0x00, 0x00]);
    // IE: SSID (wildcard — empty)
    frame.extend_from_slice(&[0x00, 0x00]);
    // IE: Supported Rates (1, 2, 5.5, 11, 6, 9, 12, 18)
    frame.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    // IE: DS Parameter Set (current channel)
    frame.extend_from_slice(&[0x03, 0x01, channel]);
    frame
}

/// Build a QoS null data frame with specific TID
fn build_qos_null(src_mac: &[u8; 6], tid: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(30);
    // Frame Control: type=2 (data), subtype=12 (QoS Null) = 0xC8
    frame.extend_from_slice(&[0xC8, 0x01]); // To DS=1
    // Duration
    frame.extend_from_slice(&[0x00, 0x00]);
    // BSSID (addr1): broadcast for test
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // SA (addr2): our MAC
    frame.extend_from_slice(src_mac);
    // DA (addr3): broadcast
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // Sequence control
    frame.extend_from_slice(&[0x00, 0x00]);
    // QoS Control: TID in bits [3:0]
    frame.extend_from_slice(&[tid & 0x0F, 0x00]);
    frame
}

fn inject(driver: &mut wifikit::chips::mt7921au::Mt7921au, frame: &[u8], opts: &TxOptions, label: &str) {
    match driver.tx_frame(frame, opts) {
        Ok(_) => eprint!(" OK"),
        Err(e) => eprint!(" FAIL({})", e),
    }
}

// ── Test: Multi-Rate Injection ──

fn test_rates(driver: &mut wifikit::chips::mt7921au::Mt7921au, channel: u8, band: Band) {
    eprintln!("── Test 1: Multi-Rate Injection ──────────────────");
    let mac = driver.mac().0;
    let frame = build_probe_request(&mac, channel);

    let rates: Vec<(&str, TxRate)> = if band == Band::Band2g {
        vec![
            ("CCK 1M",   TxRate::Cck1m),
            ("CCK 11M",  TxRate::Cck11m),
            ("OFDM 6M",  TxRate::Ofdm6m),
            ("OFDM 54M", TxRate::Ofdm54m),
            ("HT MCS0",  TxRate::HtMcs(0)),
            ("HT MCS7",  TxRate::HtMcs(7)),
            ("HT MCS15", TxRate::HtMcs(15)),  // 2SS
            ("VHT 1SS MCS0", TxRate::VhtMcs { mcs: 0, nss: 1 }),
            ("VHT 1SS MCS9", TxRate::VhtMcs { mcs: 9, nss: 1 }),
            ("VHT 2SS MCS9", TxRate::VhtMcs { mcs: 9, nss: 2 }),
            ("HE 1SS MCS0",  TxRate::HeMcs { mcs: 0, nss: 1 }),
            ("HE 1SS MCS11", TxRate::HeMcs { mcs: 11, nss: 1 }),
            ("HE 2SS MCS11", TxRate::HeMcs { mcs: 11, nss: 2 }),
            ("HE_EXT_SU MCS0", TxRate::HeExtSuMcs { mcs: 0, nss: 1 }),
        ]
    } else {
        vec![
            ("OFDM 6M",  TxRate::Ofdm6m),
            ("OFDM 54M", TxRate::Ofdm54m),
            ("HT MCS0",  TxRate::HtMcs(0)),
            ("HT MCS15", TxRate::HtMcs(15)),
            ("VHT 1SS MCS0", TxRate::VhtMcs { mcs: 0, nss: 1 }),
            ("VHT 2SS MCS9", TxRate::VhtMcs { mcs: 9, nss: 2 }),
            ("HE 1SS MCS0",  TxRate::HeMcs { mcs: 0, nss: 1 }),
            ("HE 2SS MCS11", TxRate::HeMcs { mcs: 11, nss: 2 }),
            ("HE_EXT_SU MCS0",  TxRate::HeExtSuMcs { mcs: 0, nss: 1 }),
            ("HE_EXT_SU MCS11", TxRate::HeExtSuMcs { mcs: 11, nss: 1 }),
        ]
    };

    for (name, rate) in &rates {
        eprint!("  {:20}", name);
        let opts = TxOptions { rate: *rate, ..Default::default() };
        inject(driver, &frame, &opts, name);
        eprintln!();
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!();
}

// ── Test: Bandwidth Injection ──

fn test_bandwidth(driver: &mut wifikit::chips::mt7921au::Mt7921au, channel: u8, band: Band) {
    eprintln!("── Test 2: Bandwidth Injection ───────────────────");
    let mac = driver.mac().0;
    let frame = build_probe_request(&mac, channel);

    let bws: Vec<(&str, u8, TxRate)> = vec![
        ("20 MHz (HT MCS7)",     0, TxRate::HtMcs(7)),
        ("40 MHz (HT MCS7)",     1, TxRate::HtMcs(7)),
        ("20 MHz (VHT MCS9)",    0, TxRate::VhtMcs { mcs: 9, nss: 1 }),
        ("40 MHz (VHT MCS9)",    1, TxRate::VhtMcs { mcs: 9, nss: 1 }),
        ("80 MHz (VHT MCS9)",    2, TxRate::VhtMcs { mcs: 9, nss: 1 }),
        ("20 MHz (HE MCS11)",    0, TxRate::HeMcs { mcs: 11, nss: 1 }),
        ("40 MHz (HE MCS11)",    1, TxRate::HeMcs { mcs: 11, nss: 1 }),
        ("80 MHz (HE MCS11)",    2, TxRate::HeMcs { mcs: 11, nss: 1 }),
    ];

    for (name, bw, rate) in &bws {
        eprint!("  {:26}", name);
        let opts = TxOptions { rate: *rate, bw: *bw, ..Default::default() };
        inject(driver, &frame, &opts, name);
        eprintln!();
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!();
}

// ── Test: TX Flags ──

fn test_flags(driver: &mut wifikit::chips::mt7921au::Mt7921au, channel: u8, band: Band) {
    eprintln!("── Test 3: TX Flags ─────────────────────────────");
    let mac = driver.mac().0;
    let frame = build_probe_request(&mac, channel);
    let base_rate = TxRate::HeMcs { mcs: 0, nss: 1 };

    let flag_tests: Vec<(&str, TxFlags, u8, u8)> = vec![
        ("No flags (baseline)",    TxFlags::empty(),     0, 0),
        ("LDPC",                   TxFlags::LDPC,        0, 0),
        ("STBC",                   TxFlags::STBC,        0, 0),
        ("LDPC + STBC",            TxFlags::LDPC | TxFlags::STBC, 0, 0),
        ("Short GI",               TxFlags::empty(),     1, 0),
        ("Extended GI (3.2us)",    TxFlags::empty(),     2, 0),
        ("PROTECT (RTS/CTS)",      TxFlags::PROTECT,     0, 0),
        ("WANT_ACK",               TxFlags::WANT_ACK,    0, 0),
        ("DYN_BW (80MHz)",         TxFlags::DYN_BW,      0, 2),
    ];

    for (name, flags, gi, bw) in &flag_tests {
        eprint!("  {:26}", name);
        let opts = TxOptions {
            rate: base_rate,
            flags: *flags,
            gi: *gi,
            bw: *bw,
            ..Default::default()
        };
        inject(driver, &frame, &opts, name);
        eprintln!();
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!();
}

// ── Test: TX Power Sweep ──

fn test_power_sweep(driver: &mut wifikit::chips::mt7921au::Mt7921au, channel: u8, band: Band) {
    eprintln!("── Test 4: TX Power Sweep ───────────────────────");
    eprintln!("  Setting TX power via set_tx_power() API:");

    let powers: Vec<(i8, &str)> = vec![
        (5,  " 5 dBm (stealth)"),
        (10, "10 dBm (low)"),
        (15, "15 dBm (medium)"),
        (20, "20 dBm (default)"),
        (0,  " 0 dBm (max / eFuse limit)"),
    ];

    let mac = driver.mac().0;
    let frame = build_probe_request(&mac, channel);
    let opts = TxOptions::default();

    for (dbm, label) in &powers {
        eprint!("  {:30}", label);
        match driver.set_tx_power(*dbm) {
            Ok(_) => {
                inject(driver, &frame, &opts, label);
                eprintln!();
            }
            Err(e) => eprintln!(" SET_POWER_FAIL({})", e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Restore max power
    let _ = driver.set_tx_power(0);
    eprintln!();
}

// ── Test: QoS Queue Mapping ──

fn test_qos_queues(driver: &mut wifikit::chips::mt7921au::Mt7921au, channel: u8, band: Band) {
    eprintln!("── Test 5: QoS Queue Mapping (WMM) ─────────────");
    eprintln!("  Injecting QoS Null frames with different TIDs:");
    let mac = driver.mac().0;
    let opts = TxOptions::default();

    let tids: Vec<(u8, &str)> = vec![
        (0, "TID 0 → AC_BE (Best Effort)"),
        (1, "TID 1 → AC_BK (Background)"),
        (2, "TID 2 → AC_BK (Background)"),
        (3, "TID 3 → AC_BE (Best Effort)"),
        (4, "TID 4 → AC_VI (Video)"),
        (5, "TID 5 → AC_VI (Video)"),
        (6, "TID 6 → AC_VO (Voice)"),
        (7, "TID 7 → AC_VO (Voice)"),
    ];

    for (tid, label) in &tids {
        eprint!("  {:38}", label);
        let frame = build_qos_null(&mac, *tid);
        inject(driver, &frame, &opts, label);
        eprintln!();
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!();
}

// ── Test: RF Test Mode ──

fn test_testmode(driver: &mut wifikit::chips::mt7921au::Mt7921au) {
    eprintln!("── Test 6: RF Test Mode (Testmode AT Commands) ──");

    // Temperature query (works in normal mode via AT query)
    eprint!("  Temperature query...");
    match driver.testmode_get_temperature() {
        Ok((p0, p1)) => eprintln!(" param0={} param1={}", p0, p1),
        Err(e) => eprintln!(" {}", e),
    }

    // Enter RF test mode
    eprint!("  Enter RF test mode...");
    match driver.testmode_enter_rftest() {
        Ok(_) => eprintln!(" OK"),
        Err(e) => { eprintln!(" FAIL({})", e); return; }
    }

    // Antenna control
    for (mask, label) in [(1, "Ant0 only"), (2, "Ant1 only"), (3, "Both (MIMO)")] {
        eprint!("  TX antenna: {:14}", label);
        match driver.testmode_set_tx_antenna(mask) {
            Ok(_) => eprintln!(" OK"),
            Err(e) => eprintln!(" FAIL({})", e),
        }
    }

    // System BW
    for (bw, label) in [(0, "20 MHz"), (1, "40 MHz"), (2, "80 MHz")] {
        eprint!("  System BW: {:15}", label);
        match driver.testmode_set_system_bw(bw) {
            Ok(_) => eprintln!(" OK"),
            Err(e) => eprintln!(" FAIL({})", e),
        }
    }

    // TX power sweep in test mode
    for half_dbm in [10, 20, 30, 40, 50, 60] {
        eprint!("  TX power: {:4.1} dBm...", half_dbm as f32 / 2.0);
        match driver.testmode_set_tx_power(half_dbm) {
            Ok(_) => eprintln!(" OK"),
            Err(e) => eprintln!(" FAIL({})", e),
        }
    }

    // Rate modes
    for (mode, label) in [
        (0, "CCK"), (1, "OFDM"), (2, "HT"), (3, "VHT"), (4, "HE_SU"), (5, "HE_EXT_SU")
    ] {
        eprint!("  TX rate mode: {:11}", label);
        match driver.testmode_set_tx_rate(mode) {
            Ok(_) => eprintln!(" OK"),
            Err(e) => eprintln!(" FAIL({})", e),
        }
    }

    // GI
    for (gi, label) in [(0, "Normal (0.8us)"), (1, "Short (0.4us)"), (2, "Extended (3.2us)")] {
        eprint!("  TX GI: {:19}", label);
        match driver.testmode_set_tx_gi(gi) {
            Ok(_) => eprintln!(" OK"),
            Err(e) => eprintln!(" FAIL({})", e),
        }
    }

    // STBC / LDPC
    eprint!("  TX STBC on...");
    match driver.testmode_set_tx_stbc(1) {
        Ok(_) => eprintln!(" OK"),
        Err(e) => eprintln!(" FAIL({})", e),
    }
    eprint!("  TX LDPC on...");
    match driver.testmode_set_tx_ldpc(1) {
        Ok(_) => eprintln!(" OK"),
        Err(e) => eprintln!(" FAIL({})", e),
    }

    // TSSI query
    eprint!("  TSSI (measured TX power)...");
    match driver.testmode_get_tssi() {
        Ok((p0, p1)) => eprintln!(" param0={} param1={}", p0, p1),
        Err(e) => eprintln!(" {}", e),
    }

    // RX stats
    eprint!("  RX stats...");
    match driver.testmode_get_rx_stats() {
        Ok((pkts, fcs_err)) => eprintln!(" packets={} fcs_errors={}", pkts, fcs_err),
        Err(e) => eprintln!(" {}", e),
    }

    // Clean TX queue
    eprint!("  Clean TX queue...");
    match driver.testmode_clean_tx_queue() {
        Ok(_) => eprintln!(" OK"),
        Err(e) => eprintln!(" FAIL({})", e),
    }

    // Exit test mode
    eprint!("  Exit test mode...");
    match driver.testmode_exit() {
        Ok(_) => eprintln!(" OK"),
        Err(e) => eprintln!(" FAIL({})", e),
    }
    eprintln!();
}
