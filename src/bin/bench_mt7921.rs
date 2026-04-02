// MT7921AU Fenvi USB3 Performance Benchmark
//
// Standalone binary for measuring RX throughput, channel switching speed,
// and TX power across all bands. Use this to iterate on driver tuning
// without the scanner overhead.
//
// Usage:
//   cargo run --bin bench_mt7921
//   cargo run --bin bench_mt7921 -- --dwell 1000 --bands 2g,5g,6g
//   cargo run --bin bench_mt7921 -- --channel 36 --duration 10
//   cargo run --bin bench_mt7921 -- --hop --dwell 500

use std::time::{Duration, Instant};
use std::collections::HashMap;
use wifikit::core::chip::ChipDriver;
use wifikit::core::{Channel, Band};
use wifikit::core::channel::Bandwidth;

// ── Config ──

struct BenchConfig {
    /// Single channel to park on (0 = hop mode)
    channel: u8,
    /// Band for single channel (when channel is 6GHz-ambiguous)
    band: Option<Band>,
    /// Bandwidth (20/40/80/160 MHz)
    bandwidth: Bandwidth,
    /// Dwell time per channel in ms (hop mode)
    dwell_ms: u64,
    /// Total benchmark duration in seconds
    duration_secs: u64,
    /// Hop through channels
    hop: bool,
    /// Which bands to scan
    bands_2g: bool,
    bands_5g: bool,
    bands_6g: bool,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            channel: 0,
            band: None,
            bandwidth: Bandwidth::Bw20,
            dwell_ms: 500,
            duration_secs: 30,
            hop: false,
            bands_2g: true,
            bands_5g: true,
            bands_6g: true,
        }
    }
}

fn parse_args() -> BenchConfig {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = BenchConfig::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" | "-c" => {
                i += 1;
                if i < args.len() { cfg.channel = args[i].parse().unwrap_or(0); }
            }
            "--band" => {
                i += 1;
                if i < args.len() {
                    cfg.band = match args[i].as_str() {
                        "2g" => Some(Band::Band2g),
                        "5g" => Some(Band::Band5g),
                        "6g" => Some(Band::Band6g),
                        _ => None,
                    };
                }
            }
            "--dwell" | "-d" => {
                i += 1;
                if i < args.len() { cfg.dwell_ms = args[i].parse().unwrap_or(500); }
            }
            "--duration" | "-t" => {
                i += 1;
                if i < args.len() { cfg.duration_secs = args[i].parse().unwrap_or(30); }
            }
            "--bw" => {
                i += 1;
                if i < args.len() {
                    cfg.bandwidth = match args[i].as_str() {
                        "20" => Bandwidth::Bw20,
                        "40" => Bandwidth::Bw40,
                        "80" => Bandwidth::Bw80,
                        "160" => Bandwidth::Bw160,
                        _ => Bandwidth::Bw20,
                    };
                }
            }
            "--hop" => { cfg.hop = true; }
            "--bands" => {
                i += 1;
                if i < args.len() {
                    cfg.bands_2g = false;
                    cfg.bands_5g = false;
                    cfg.bands_6g = false;
                    for b in args[i].split(',') {
                        match b.trim() {
                            "2g" => cfg.bands_2g = true,
                            "5g" => cfg.bands_5g = true,
                            "6g" => cfg.bands_6g = true,
                            _ => {}
                        }
                    }
                }
            }
            "--help" | "-h" => {
                eprintln!("MT7921AU Fenvi USB3 Benchmark");
                eprintln!();
                eprintln!("Usage:");
                eprintln!("  bench_mt7921                         Park on ch6, measure 30s");
                eprintln!("  bench_mt7921 --channel 36            Park on ch36 (5GHz)");
                eprintln!("  bench_mt7921 --channel 36 --bw 80    Park on ch36 80MHz");
                eprintln!("  bench_mt7921 --channel 36 --bw 40    Park on ch36 40MHz");
                eprintln!("  bench_mt7921 --channel 1 --band 6g   Park on 6GHz ch1");
                eprintln!("  bench_mt7921 --hop --dwell 500       Hop all bands, 500ms/ch");
                eprintln!("  bench_mt7921 --hop --bands 6g        Hop 6GHz only");
                eprintln!("  bench_mt7921 --duration 60           Run for 60 seconds");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    cfg
}

// ── Frame classification ──

#[derive(Default)]
struct FrameStats {
    total: u64,
    beacons: u64,
    probe_resp: u64,
    probe_req: u64,
    data: u64,
    eapol: u64,
    action: u64,
    other_mgmt: u64,
    control: u64,
    bytes: u64,
    unique_bssids: HashMap<[u8; 6], u8>, // bssid -> count (capped)
    unique_stations: HashMap<[u8; 6], u8>,
}

impl FrameStats {
    fn classify(&mut self, frame: &[u8]) {
        self.total += 1;
        self.bytes += frame.len() as u64;

        if frame.len() < 24 {
            self.control += 1;
            return;
        }

        let fc0 = frame[0];
        let fc1 = frame[1];
        let frame_type = (fc0 >> 2) & 0x3;
        let subtype = (fc0 >> 4) & 0xF;

        match frame_type {
            0 => {
                // Management
                match subtype {
                    0x08 => {
                        self.beacons += 1;
                        if frame.len() >= 22 {
                            let mut bssid = [0u8; 6];
                            bssid.copy_from_slice(&frame[16..22]);
                            let e = self.unique_bssids.entry(bssid).or_insert(0);
                            *e = e.saturating_add(1);
                        }
                    }
                    0x05 => self.probe_resp += 1,
                    0x04 => self.probe_req += 1,
                    0x0D => self.action += 1,
                    _ => self.other_mgmt += 1,
                }
            }
            1 => self.control += 1,
            2 => {
                // Data
                self.data += 1;
                // Check for EAPOL (LLC/SNAP ethertype 0x888E)
                let hdr_len = if (fc1 & 0x80) != 0 { 30 } else { 24 }; // QoS adds 2, but simplified
                if frame.len() > hdr_len + 8 {
                    let snap_start = hdr_len;
                    if frame.len() > snap_start + 8
                        && frame[snap_start..snap_start+6] == [0xAA, 0x55, 0x03, 0x00, 0x00, 0x00]
                    {
                        // Check ethertype at snap_start+6..snap_start+8
                    }
                    // Quick EAPOL check: look for 0x888E anywhere in likely positions
                    for off in [hdr_len + 6, hdr_len + 8, 30, 32] {
                        if frame.len() > off + 1 && frame[off] == 0x88 && frame[off + 1] == 0x8E {
                            self.eapol += 1;
                            break;
                        }
                    }
                }
                // Track stations (SA from addr2)
                if frame.len() >= 16 {
                    let mut sa = [0u8; 6];
                    sa.copy_from_slice(&frame[10..16]);
                    if sa != [0xFF; 6] && sa != [0; 6] {
                        let e = self.unique_stations.entry(sa).or_insert(0);
                        *e = e.saturating_add(1);
                    }
                }
            }
            _ => {}
        }
    }

    fn fps(&self, elapsed: Duration) -> f64 {
        if elapsed.as_secs_f64() > 0.0 {
            self.total as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        }
    }

    fn useful_fps(&self, elapsed: Duration) -> f64 {
        let useful = self.total.saturating_sub(self.control);
        if elapsed.as_secs_f64() > 0.0 {
            useful as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        }
    }

    fn print_summary(&self, label: &str, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        eprintln!("\n╔══ {} ({:.1}s) ══", label, secs);
        eprintln!("║ Total frames:   {:>8}  ({:.0} fps)", self.total, self.fps(elapsed));
        eprintln!("║ Useful frames:  {:>8}  ({:.0} fps)", self.total - self.control, self.useful_fps(elapsed));
        eprintln!("║ Bytes:          {:>8}  ({:.1} KB/s)", self.bytes, self.bytes as f64 / secs / 1024.0);
        eprintln!("║");
        eprintln!("║ Beacons:        {:>8}", self.beacons);
        eprintln!("║ Probe Response: {:>8}", self.probe_resp);
        eprintln!("║ Probe Request:  {:>8}", self.probe_req);
        eprintln!("║ Data:           {:>8}", self.data);
        eprintln!("║ EAPOL:          {:>8}", self.eapol);
        eprintln!("║ Action:         {:>8}", self.action);
        eprintln!("║ Other Mgmt:     {:>8}", self.other_mgmt);
        eprintln!("║ Control:        {:>8}  ({:.0}% noise)", self.control,
            if self.total > 0 { self.control as f64 / self.total as f64 * 100.0 } else { 0.0 });
        eprintln!("║");
        eprintln!("║ Unique APs:     {:>8}", self.unique_bssids.len());
        eprintln!("║ Unique STAs:    {:>8}", self.unique_stations.len());
        eprintln!("╚══════════════════════════");
    }
}

// ── Channel switch timing ──

struct SwitchStats {
    times: Vec<Duration>,
}

impl SwitchStats {
    fn new() -> Self { Self { times: Vec::new() } }

    fn record(&mut self, d: Duration) { self.times.push(d); }

    fn print_summary(&self) {
        if self.times.is_empty() { return; }
        let min = self.times.iter().min().unwrap();
        let max = self.times.iter().max().unwrap();
        let avg: f64 = self.times.iter().map(|d| d.as_secs_f64() * 1000.0).sum::<f64>() / self.times.len() as f64;
        let p50 = percentile(&self.times, 50);
        let p95 = percentile(&self.times, 95);

        eprintln!("\n╔══ Channel Switch Timing ({} switches) ══", self.times.len());
        eprintln!("║ Min:    {:>6.1} ms", min.as_secs_f64() * 1000.0);
        eprintln!("║ Avg:    {:>6.1} ms", avg);
        eprintln!("║ P50:    {:>6.1} ms", p50.as_secs_f64() * 1000.0);
        eprintln!("║ P95:    {:>6.1} ms", p95.as_secs_f64() * 1000.0);
        eprintln!("║ Max:    {:>6.1} ms", max.as_secs_f64() * 1000.0);
        eprintln!("╚══════════════════════════════════════");
    }
}

fn percentile(times: &[Duration], pct: usize) -> Duration {
    let mut sorted: Vec<Duration> = times.to_vec();
    sorted.sort();
    let idx = (pct * sorted.len() / 100).min(sorted.len() - 1);
    sorted[idx]
}

// ── Main ──

fn main() {
    let cfg = parse_args();

    eprintln!("╔══════════════════════════════════════════╗");
    eprintln!("║  MT7921AU Fenvi USB3 Performance Bench   ║");
    eprintln!("╚══════════════════════════════════════════╝\n");

    // Try both known Fenvi VID:PIDs
    let devices = [(0x0E8D, 0x7961, "Fenvi MT7921AU"), (0x3574, 0x6211, "COMFAST CF-952AX")];
    let mut driver = None;

    for (vid, pid, name) in &devices {
        match wifikit::chips::mt7921au::Mt7921au::open_usb(*vid, *pid) {
            Ok((d, ep)) => {
                eprintln!("  Found: {} ({:04X}:{:04X})", name, vid, pid);
                eprintln!("  Endpoints: IN=0x{:02X} OUT=0x{:02X}", ep.bulk_in, ep.bulk_out);
                driver = Some(d);
                break;
            }
            Err(_) => continue,
        }
    }

    let mut driver = match driver {
        Some(d) => d,
        None => {
            eprintln!("ERROR: No MT7921AU device found. Replug and retry.");
            std::process::exit(1);
        }
    };

    // Full init (power on + FW + DMA + radio)
    eprint!("  Initializing... ");
    let init_start = Instant::now();
    match driver.init() {
        Ok(()) => eprintln!("OK ({:.0}ms)", init_start.elapsed().as_secs_f64() * 1000.0),
        Err(e) => {
            eprintln!("FAILED: {}", e);
            eprintln!("  Try: unplug and replug the device");
            std::process::exit(1);
        }
    }

    let info = driver.chip_info();
    eprintln!("  Chip: {} rev=0x{:08X}", info.name, info.vid);
    eprintln!("  FW: {}", info.firmware_version);
    eprintln!("  MAC: {}", driver.mac());
    eprintln!("  Caps: {:?}", info.caps);
    eprintln!("  Bands: {:?}", info.bands);
    eprintln!("  Channels: {}", driver.supported_channels().len());

    // Set monitor mode
    eprint!("  Monitor mode... ");
    let mon_start = Instant::now();
    match driver.set_monitor_mode() {
        Ok(()) => eprintln!("OK ({:.0}ms)", mon_start.elapsed().as_secs_f64() * 1000.0),
        Err(e) => {
            eprintln!("FAILED: {}", e);
            std::process::exit(1);
        }
    }

    // Build channel list
    let channels = build_channels(&cfg, driver.supported_channels());
    eprintln!("  Channel list: {} channels", channels.len());
    if channels.len() <= 20 {
        let ch_str: Vec<String> = channels.iter().map(|c| {
            let band = match c.band { Band::Band2g => "", Band::Band5g => "", Band::Band6g => "6g:" };
            format!("{}{}", band, c.number)
        }).collect();
        eprintln!("  Channels: [{}]", ch_str.join(", "));
    }

    let bw_str = match cfg.bandwidth {
        Bandwidth::Bw20 => "20MHz",
        Bandwidth::Bw40 => "40MHz",
        Bandwidth::Bw80 => "80MHz",
        Bandwidth::Bw160 => "160MHz",
    };
    eprintln!("\n  Duration: {}s | Dwell: {}ms | BW: {} | Mode: {}",
        cfg.duration_secs, cfg.dwell_ms, bw_str,
        if cfg.hop || cfg.channel == 0 { "hop" } else { "park" });

    // ── Run benchmark ──

    if cfg.hop || (cfg.channel == 0 && channels.len() > 1) {
        run_hop_bench(&mut driver, &channels, &cfg);
    } else {
        let ch = if cfg.channel > 0 {
            let base = match cfg.band {
                Some(Band::Band6g) => Channel::new_6ghz(cfg.channel),
                _ => Channel::new(cfg.channel),
            };
            base.with_bandwidth(cfg.bandwidth)
        } else {
            channels[0].with_bandwidth(cfg.bandwidth)
        };
        run_park_bench(&mut driver, ch, &cfg);
    }
}

fn build_channels(cfg: &BenchConfig, supported: &[Channel]) -> Vec<Channel> {
    if cfg.channel > 0 && !cfg.hop {
        let ch = match cfg.band {
            Some(Band::Band6g) => Channel::new_6ghz(cfg.channel),
            _ => Channel::new(cfg.channel),
        };
        return vec![ch.with_bandwidth(cfg.bandwidth)];
    }

    supported.iter().filter(|ch| match ch.band {
        Band::Band2g => cfg.bands_2g,
        Band::Band5g => cfg.bands_5g,
        Band::Band6g => cfg.bands_6g,
    }).map(|ch| ch.with_bandwidth(cfg.bandwidth)).collect()
}

/// Park on a single channel and measure raw RX throughput.
fn run_park_bench(driver: &mut wifikit::chips::mt7921au::Mt7921au, ch: Channel, cfg: &BenchConfig) {
    let band_name = match ch.band { Band::Band2g => "2.4GHz", Band::Band5g => "5GHz", Band::Band6g => "6GHz" };
    let bw_str = match ch.bandwidth { Bandwidth::Bw20 => "20MHz", Bandwidth::Bw40 => "40MHz", Bandwidth::Bw80 => "80MHz", Bandwidth::Bw160 => "160MHz" };
    eprintln!("\n── Park on ch{} ({} {}) ──", ch.number, band_name, bw_str);

    // Switch channel
    let sw_start = Instant::now();
    if let Err(e) = driver.set_channel(ch) {
        eprintln!("  Channel switch failed: {}", e);
        return;
    }
    eprintln!("  Channel switch: {:.1}ms", sw_start.elapsed().as_secs_f64() * 1000.0);

    // Receive loop
    let mut stats = FrameStats::default();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(cfg.duration_secs);
    let mut last_report = start;
    let mut last_count = 0u64;

    while Instant::now() < deadline {
        match driver.rx_frame(Duration::from_millis(10)) {
            Ok(Some(frame)) => stats.classify(&frame.data),
            Ok(None) => {} // no frame available
            Err(_) => {}   // USB timeout, retry
        }

        // Live stats every 2 seconds
        let now = Instant::now();
        if now.duration_since(last_report) >= Duration::from_secs(2) {
            let interval_frames = stats.total - last_count;
            let interval_secs = now.duration_since(last_report).as_secs_f64();
            eprint!("\r  [{:.0}s] {:>6} frames | {:>5.0} fps | {:>4} APs | {:>4} STAs",
                now.duration_since(start).as_secs_f64(),
                stats.total,
                interval_frames as f64 / interval_secs,
                stats.unique_bssids.len(),
                stats.unique_stations.len(),
            );
            last_report = now;
            last_count = stats.total;
        }
    }
    eprintln!();

    stats.print_summary(&format!("ch{} ({})", ch.number, band_name), start.elapsed());
}

/// Hop through channels and measure throughput + switch timing.
fn run_hop_bench(driver: &mut wifikit::chips::mt7921au::Mt7921au, channels: &[Channel], cfg: &BenchConfig) {
    eprintln!("\n── Hop mode ({} channels, {}ms dwell) ──", channels.len(), cfg.dwell_ms);

    let mut global_stats = FrameStats::default();
    let mut per_band: HashMap<&str, FrameStats> = HashMap::new();
    let mut switch_stats = SwitchStats::new();

    let start = Instant::now();
    let deadline = start + Duration::from_secs(cfg.duration_secs);
    let dwell = Duration::from_millis(cfg.dwell_ms);
    let mut ch_idx = 0;
    let mut rounds = 0u32;
    let mut last_report = start;
    let mut last_count = 0u64;

    while Instant::now() < deadline {
        let ch = channels[ch_idx];
        let band_name = match ch.band {
            Band::Band2g => "2.4GHz",
            Band::Band5g => "5GHz",
            Band::Band6g => "6GHz",
        };

        // Switch channel
        let sw_start = Instant::now();
        if let Err(_) = driver.set_channel(ch) {
            ch_idx = (ch_idx + 1) % channels.len();
            continue;
        }
        switch_stats.record(sw_start.elapsed());

        // Dwell and receive
        let dwell_end = Instant::now() + dwell;
        while Instant::now() < dwell_end && Instant::now() < deadline {
            match driver.rx_frame(Duration::from_millis(10)) {
                Ok(Some(frame)) => {
                    global_stats.classify(&frame.data);
                    per_band.entry(band_name).or_default().classify(&frame.data);
                }
                Ok(None) | Err(_) => {}
            }
        }

        ch_idx += 1;
        if ch_idx >= channels.len() {
            ch_idx = 0;
            rounds += 1;
        }

        // Live stats every 3 seconds
        let now = Instant::now();
        if now.duration_since(last_report) >= Duration::from_secs(3) {
            let interval_frames = global_stats.total - last_count;
            let interval_secs = now.duration_since(last_report).as_secs_f64();
            eprint!("\r  [{:.0}s] R{} {:>6} frames | {:>5.0} fps | {:>4} APs | {:>4} STAs",
                now.duration_since(start).as_secs_f64(),
                rounds,
                global_stats.total,
                interval_frames as f64 / interval_secs,
                global_stats.unique_bssids.len(),
                global_stats.unique_stations.len(),
            );
            last_report = now;
            last_count = global_stats.total;
        }
    }
    eprintln!();

    // Results
    let elapsed = start.elapsed();
    eprintln!("\n  Completed {} full rounds in {:.1}s", rounds, elapsed.as_secs_f64());

    global_stats.print_summary("Global (all bands)", elapsed);

    for band_name in &["2.4GHz", "5GHz", "6GHz"] {
        if let Some(stats) = per_band.get(band_name) {
            if stats.total > 0 {
                stats.print_summary(band_name, elapsed);
            }
        }
    }

    switch_stats.print_summary();
}
