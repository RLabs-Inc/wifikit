//! WiFi adapter pipeline test — real infrastructure
//!
//! Uses SharedAdapter → FrameGate → PipelineSubscriber through the full
//! production path. Tests stream-based RX (8852AU) or standard RX (others).
//!
//! Usage:
//!   test_8852au_pipeline          # defaults to 8852AU
//!   test_8852au_pipeline 8812bu   # test RTL8812BU instead

use std::time::{Duration, Instant};
use std::collections::HashMap;

use wifikit::core::adapter::AdapterInfo;
use wifikit::core::chip::ChipId;
use wifikit::pipeline::FrameGate;
use wifikit::store::FrameStore;

const DWELL_PER_CHANNEL: Duration = Duration::from_secs(2);

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let (info, label) = match arg.to_lowercase().as_str() {
        "8812bu" | "bu" => (
            AdapterInfo {
                vid: 0x2357, pid: 0x0115,
                chip: ChipId::Rtl8812bu,
                name: "TP-Link Archer T4U V3 (RTL8812BU)",
                bus: 0, address: 0,
            },
            "RTL8812BU (standard RX)",
        ),
        "7921" | "mt7921" | "fenvi" | "comfast" => (
            AdapterInfo {
                vid: 0x3574, pid: 0x6211,
                chip: ChipId::Mt7921au,
                name: "COMFAST CF-952AX (MT7921AU)",
                bus: 0, address: 0,
            },
            "MT7921AU (WiFi 6)",
        ),
        _ => (
            AdapterInfo {
                vid: 0x2357, pid: 0x013F,
                chip: ChipId::Rtl8852au,
                name: "TP-Link Archer TX20U Plus (RTL8852AU)",
                bus: 0, address: 0,
            },
            "RTL8852AU (stream pipeline)",
        ),
    };

    eprintln!("=== {} Pipeline Test ===\n", label);

    let store = FrameStore::new();
    let gate = FrameGate::new(store.clone(), None);

    eprintln!("Opening {} via SharedAdapter::spawn...", info.name);
    let shared = wifikit::adapter::SharedAdapter::spawn(&info, gate.clone(), |msg| {
        eprintln!("  {}", msg);
    }).expect("spawn failed");

    eprintln!("\nAdapter ready. MAC: {} (driver: {})", shared.mac(), shared.driver_mac());

    let sub = shared.subscribe("pipeline-test");
    let channels = shared.supported_channels();
    eprintln!("Channels: {}\n", channels.len());

    let mut grand = ChannelStats::default();
    let scan_start = Instant::now();

    // Get pipeline stats handle for per-channel snapshots (8852AU only)
    let sp = if info.chip == ChipId::Rtl8852au {
        wifikit::chips::rtl8852au::get_pipeline_stats()
    } else {
        None
    };

    for ch_info in &channels {
        let ch = ch_info.number;
        let band = if ch <= 14 { "2.4G" } else { "5G" };

        // Snapshot pipeline counters before this channel
        let (sliced_before, wifi_before, ppdu_before, submitted_before, evicted_before, skipped_before) =
            if let Some(ref sp) = sp {
                use std::sync::atomic::Ordering::Relaxed;
                (sp.packets_sliced.load(Relaxed), sp.rpkt_wifi.load(Relaxed),
                 sp.rpkt_ppdu.load(Relaxed), sp.frames_submitted.load(Relaxed),
                 sp.frames_evicted.load(Relaxed), sp.skipped.load(Relaxed))
            } else {
                (0, 0, 0, 0, 0, 0)
            };

        shared.set_channel_full(ch_info.clone()).expect("set_channel failed");
        std::thread::sleep(Duration::from_millis(50));

        let ch_start = Instant::now();
        let mut st = ChannelStats::default();

        while ch_start.elapsed() < DWELL_PER_CHANNEL {
            match sub.recv_timeout(Duration::from_millis(100)) {
                Some(frame) => {
                    st.frames += 1;
                    let rssi = frame.rssi;
                    if rssi != 0 {
                        st.with_rssi += 1;
                        st.rssi_sum += rssi as i64;
                        if rssi < st.rssi_min { st.rssi_min = rssi; }
                        if rssi > st.rssi_max { st.rssi_max = rssi; }
                    }
                    match frame.frame_type {
                        0 => st.mgmt += 1,
                        1 => st.ctrl += 1,
                        2 => st.data += 1,
                        _ => st.other += 1,
                    }
                    if let Some(bssid) = frame.addr3 {
                        *st.bssids.entry(bssid.to_string()).or_insert(0u64) += 1;
                    }
                }
                None => {}
            }
        }

        let elapsed = ch_start.elapsed();
        let fps = st.frames as f64 / elapsed.as_secs_f64().max(0.001);
        let rssi_avg = if st.with_rssi > 0 { st.rssi_sum / st.with_rssi as i64 } else { 0 };

        // Snapshot pipeline counters after this channel
        if let Some(ref sp) = sp {
            use std::sync::atomic::Ordering::Relaxed;
            let sliced = sp.packets_sliced.load(Relaxed) - sliced_before;
            let wifi = sp.rpkt_wifi.load(Relaxed) - wifi_before;
            let ppdu = sp.rpkt_ppdu.load(Relaxed) - ppdu_before;
            let submitted = sp.frames_submitted.load(Relaxed) - submitted_before;
            let evicted = sp.frames_evicted.load(Relaxed) - evicted_before;
            let skipped = sp.skipped.load(Relaxed) - skipped_before;
            let matched = submitted;
            let match_pct = if ppdu > 0 { matched as f64 / ppdu as f64 * 100.0 } else { 0.0 };

            eprintln!(
                "  Ch {:<3} ({}): {:>5} sliced, {:>4} wifi, {:>4} ppdu, {:>4} match ({:>3.0}%), {:>4} evict, {:>4} skip | {:>5} out ({:>5.0} fps) {:>4} mgmt {:>3} data {:>3} ctrl | RSSI {}/{}/{} | {} APs",
                ch, band, sliced, wifi, ppdu, matched, match_pct, evicted, skipped,
                st.frames, fps, st.mgmt, st.data, st.ctrl,
                if st.with_rssi > 0 { st.rssi_min as i64 } else { 0 },
                rssi_avg,
                if st.with_rssi > 0 { st.rssi_max as i64 } else { 0 },
                st.bssids.len(),
            );
        } else {
            eprintln!(
                "  Ch {:<3} ({}): {:>5} frames ({:>5.0} fps) | {:>4} mgmt {:>3} data {:>3} ctrl | RSSI: {}/{}/{} | {} APs",
                ch, band, st.frames, fps,
                st.mgmt, st.data, st.ctrl,
                if st.with_rssi > 0 { st.rssi_min as i64 } else { 0 },
                rssi_avg,
                if st.with_rssi > 0 { st.rssi_max as i64 } else { 0 },
                st.bssids.len(),
            );
        }

        grand.add(&st);
    }

    let total_elapsed = scan_start.elapsed();

    // Pipeline stats
    let ps = gate.stats();
    eprintln!("\n{}", "=".repeat(70));
    eprintln!("  PIPELINE STATS ({})", label);
    eprintln!("{}", "=".repeat(70));
    eprintln!("  USB frames submitted:   {}", ps.usb_frames);
    eprintln!("  Frames parsed:          {}", ps.frames_parsed);
    eprintln!("  Frames unparseable:     {}", ps.frames_unparseable);
    eprintln!("  Beacons:                {}", ps.beacon_count);
    eprintln!("  Management:             {}", ps.mgmt_count);
    eprintln!("  Data:                   {}", ps.data_count);
    eprintln!("  Control:                {}", ps.control_count);
    eprintln!("  EAPOL:                  {}", ps.eapol_count);
    eprintln!("  Peak queue depth:       {}", ps.peak_pending);

    // Grand totals
    let grand_fps = if total_elapsed.as_secs_f64() > 0.0 {
        grand.frames as f64 / total_elapsed.as_secs_f64()
    } else { 0.0 };
    let grand_rssi_avg = if grand.with_rssi > 0 {
        grand.rssi_sum / grand.with_rssi as i64
    } else { 0 };

    eprintln!("\n{}", "=".repeat(70));
    eprintln!("  GRAND TOTALS — {} ({:.1}s, {} channels)", label, total_elapsed.as_secs_f64(), channels.len());
    eprintln!("{}", "=".repeat(70));
    eprintln!("  Total frames:     {}", grand.frames);
    eprintln!("  Average FPS:      {:.1}", grand_fps);
    eprintln!("  With RSSI:        {} ({:.1}%)",
        grand.with_rssi,
        if grand.frames > 0 { grand.with_rssi as f64 / grand.frames as f64 * 100.0 } else { 0.0 });
    eprintln!("  RSSI range:       {} / {} / {} (min/avg/max)",
        if grand.with_rssi > 0 { grand.rssi_min as i64 } else { 0 },
        grand_rssi_avg,
        if grand.with_rssi > 0 { grand.rssi_max as i64 } else { 0 });
    eprintln!("  Frame types:      {} mgmt, {} data, {} ctrl",
        grand.mgmt, grand.data, grand.ctrl);
    eprintln!("  Unique BSSIDs:    {}", grand.bssids.len());

    // RX thread stats (all adapters)
    {
        use std::sync::atomic::Ordering::Relaxed;
        let rs = shared.rx_stats();
        let reads = rs.usb_reads.load(Relaxed);
        let bytes = rs.usb_bytes.load(Relaxed);
        let parsed = rs.packets_parsed.load(Relaxed);
        let frames = rs.frames_submitted.load(Relaxed);
        let driver_msg = rs.driver_messages.load(Relaxed);
        let tx_st = rs.tx_status.load(Relaxed);
        let c2h = rs.c2h_events.load(Relaxed);
        let ch_info = rs.channel_info.load(Relaxed);
        let dfs = rs.dfs_reports.load(Relaxed);
        let bb = rs.bb_scope.load(Relaxed);
        let ss = rs.spatial_sounding.load(Relaxed);
        let other = rs.other_packets.load(Relaxed);
        let skipped = rs.skipped.load(Relaxed);
        let consumed_zero = rs.consumed_zero.load(Relaxed);
        let max_read = rs.max_read_size.load(Relaxed);
        let multi = rs.multi_frame_reads.load(Relaxed);

        eprintln!("\n{}", "=".repeat(70));
        eprintln!("  RX THREAD STATS ({})", label);
        eprintln!("{}", "=".repeat(70));
        eprintln!("\n  USB:");
        eprintln!("    Reads:              {}", reads);
        eprintln!("    Bytes:              {} ({:.1} MB)", bytes, bytes as f64 / 1_048_576.0);
        eprintln!("    Avg read size:      {} bytes", if reads > 0 { bytes / reads as u64 } else { 0 });
        eprintln!("    Max read size:      {} bytes", max_read);
        eprintln!("    Multi-frame reads:  {} ({:.1}% of reads)",
            multi, if reads > 0 { multi as f64 / reads as f64 * 100.0 } else { 0.0 });

        eprintln!("\n  Parsing:");
        eprintln!("    Packets parsed:     {}", parsed);
        eprintln!("    Consumed==0 (partial/corrupt): {}", consumed_zero);
        eprintln!("    Frames → FrameGate: {}", frames);
        eprintln!("    DriverMessages:     {}", driver_msg);
        eprintln!("    TxStatus reports:   {}", tx_st);
        eprintln!("    C2H/MCU events:     {}", c2h);
        eprintln!("    ChannelInfo (CSI):  {}", ch_info);
        eprintln!("    DFS radar:          {}", dfs);
        eprintln!("    BB scope (I/Q):     {}", bb);
        eprintln!("    Spatial sounding:   {}", ss);
        eprintln!("    Other:              {}", other);
        eprintln!("    Skipped:            {}", skipped);
        let total_pkt = frames + driver_msg + tx_st + c2h + ch_info + dfs + bb + ss + other + skipped;
        if total_pkt > 0 {
            eprintln!("    Frame yield:        {:.1}% ({} frames / {} packets)",
                frames as f64 / total_pkt as f64 * 100.0, frames, total_pkt);
        }
    }

    // 8852AU stream pipeline internal stats
    if info.chip == ChipId::Rtl8852au {
        use std::sync::atomic::Ordering::Relaxed;
        if let Some(sp) = wifikit::chips::rtl8852au::get_pipeline_stats() {
            let usb_reads = sp.usb_reads.load(Relaxed);
            let usb_bytes = sp.usb_bytes.load(Relaxed);
            let sliced = sp.packets_sliced.load(Relaxed);
            let incomplete = sp.incomplete_waits.load(Relaxed);
            let empty_desc = sp.empty_descriptors.load(Relaxed);
            let peak_buf = sp.peak_stream_bytes.load(Relaxed);
            let dw0_total = sp.dw0_inspected.load(Relaxed);
            let wifi = sp.rpkt_wifi.load(Relaxed);
            let ppdu = sp.rpkt_ppdu.load(Relaxed);
            let c2h = sp.rpkt_c2h.load(Relaxed);
            let tx_rpt = sp.rpkt_tx_rpt.load(Relaxed);
            let other = sp.rpkt_other.load(Relaxed);
            let submitted = sp.frames_submitted.load(Relaxed);
            let evicted = sp.frames_evicted.load(Relaxed);
            let skipped = sp.skipped.load(Relaxed);

            eprintln!("\n{}", "=".repeat(70));
            eprintln!("  STREAM PIPELINE INTERNALS");
            eprintln!("{}", "=".repeat(70));

            eprintln!("\n  USB Reader:");
            eprintln!("    Reads:              {}", usb_reads);
            eprintln!("    Bytes:              {} ({:.1} MB)", usb_bytes, usb_bytes as f64 / 1_048_576.0);
            eprintln!("    Avg read size:      {} bytes",
                if usb_reads > 0 { usb_bytes / usb_reads } else { 0 });

            let not_sliced = dw0_total.saturating_sub(sliced).saturating_sub(empty_desc);

            eprintln!("\n  Stream Slicer:");
            eprintln!("    DW0 inspected:      {}", dw0_total);
            eprintln!("    Packets sliced:     {}", sliced);
            eprintln!("    Empty descriptors:  {}", empty_desc);
            eprintln!("    Incomplete (waited): {}", incomplete);
            eprintln!("    NOT sliced:         {} (dw0 - sliced - empty)", not_sliced);
            eprintln!("    Peak buffer:        {} bytes", peak_buf);

            eprintln!("\n  Parser (by rpkt_type):");
            eprintln!("    WiFi (type 0):      {}", wifi);
            eprintln!("    PPDU (type 1):      {}", ppdu);
            eprintln!("    C2H  (type 10):     {}", c2h);
            eprintln!("    TX_RPT (type 6):    {}", tx_rpt);
            eprintln!("    Other:              {}", other);
            let ratio = if ppdu > 0 { wifi as f64 / ppdu as f64 } else { 0.0 };
            eprintln!("    WiFi:PPDU ratio:    {:.2}:1", ratio);

            eprintln!("\n  Output to FrameGate:");
            eprintln!("    Frames (w/ RSSI):   {} (PPDU matched)", submitted);
            eprintln!("    Frames (no RSSI):   {} (evicted, PPDU lost)", evicted);
            eprintln!("    Skipped:            {} (CRC err, empty, etc)", skipped);
            let total_out = submitted + evicted;
            if total_out > 0 {
                eprintln!("    RSSI correlation:   {:.1}%", submitted as f64 / total_out as f64 * 100.0);
            }
            if wifi > 0 {
                eprintln!("    WiFi→Frame yield:   {:.1}% ({} of {} WiFi packets became frames)",
                    total_out as f64 / wifi as f64 * 100.0, total_out, wifi);
            }
        }
    }

    shared.shutdown();
    eprintln!("\nDone.");
}

#[derive(Default)]
struct ChannelStats {
    frames: u64,
    with_rssi: u64,
    rssi_sum: i64,
    rssi_min: i8,
    rssi_max: i8,
    mgmt: u64,
    data: u64,
    ctrl: u64,
    other: u64,
    bssids: HashMap<String, u64>,
}

impl ChannelStats {
    fn add(&mut self, other: &ChannelStats) {
        self.frames += other.frames;
        self.with_rssi += other.with_rssi;
        self.rssi_sum += other.rssi_sum;
        if other.with_rssi > 0 {
            if other.rssi_min < self.rssi_min { self.rssi_min = other.rssi_min; }
            if other.rssi_max > self.rssi_max { self.rssi_max = other.rssi_max; }
        }
        self.mgmt += other.mgmt;
        self.data += other.data;
        self.ctrl += other.ctrl;
        self.other += other.other;
        for (k, v) in &other.bssids {
            *self.bssids.entry(k.clone()).or_insert(0) += v;
        }
    }
}
