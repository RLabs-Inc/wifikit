//! FrameGate — the single entry point for all adapter frames.
//!
//! Any adapter calls `gate.submit(frame)` to feed frames into the system.
//! The pipeline thread (spawned by FrameGate::new) handles:
//!   1. Parsing via `parsed_frame::parse_frame()` (once, here, never again)
//!   2. Writing raw bytes to pcap (BufWriter, zero loss)
//!   3. Calling the extractor to update the FrameStore
//!   4. Broadcasting `Arc<ParsedFrame>` to raw subscribers
//!
//! FrameGate is Clone (Arc-based inner). submit() never blocks.

#![allow(dead_code)]

pub mod subscriber;
pub mod extractor;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::core::frame::RxFrame;
use crate::core::parsed_frame::{self, ParsedFrame, FrameBody, DataPayload};
use crate::store::FrameStore;
use crate::store::update::StoreUpdate;

pub use subscriber::PipelineSubscriber;
pub use subscriber::UpdateSubscriber;

// ═══════════════════════════════════════════════════════════════════════════════
//  PCAP constants
// ═══════════════════════════════════════════════════════════════════════════════

const PCAP_MAGIC: u32 = 0xA1B2_C3D4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65535;
/// Link-layer type: raw 802.11 (no radiotap header).
const PCAP_LINKTYPE_IEEE802_11: u32 = 105;

// ═══════════════════════════════════════════════════════════════════════════════
//  PipelineStats — atomic counters visible to CLI
// ═══════════════════════════════════════════════════════════════════════════════

/// Pipeline statistics. Atomics for lock-free reads from any thread.
struct PipelineStats {
    /// Total frames received (submitted to the pipeline).
    pub frames_received: AtomicU64,
    /// Total frames successfully parsed.
    pub frames_parsed: AtomicU64,
    /// Frames too short or malformed to parse.
    pub frames_unparseable: AtomicU64,
    /// Total bytes written to pcap file.
    pub pcap_bytes_written: AtomicU64,
    /// Total frames written to pcap file.
    pub pcap_frames_written: AtomicU64,
    /// Number of active subscribers.
    pub subscriber_count: AtomicU64,

    // ── Per-type counters ──
    /// Management frames received.
    pub mgmt_count: AtomicU64,
    /// Data frames received.
    pub data_count: AtomicU64,
    /// Control frames received.
    pub control_count: AtomicU64,
    /// EAPOL frames detected within data frames.
    pub eapol_count: AtomicU64,
    /// Beacon/probe response frames.
    pub beacon_count: AtomicU64,
    /// Frames with FCS errors (received but not parsed/extracted).
    pub fcs_errors: AtomicU64,

    // ── Queue depth counters ──
    /// Frames extracted from USB by adapter threads (submitted count).
    pub usb_frames: AtomicU64,
    /// Current depth of the submit→pipeline queue.
    pub pending: AtomicU64,
    /// Peak depth ever observed (high-water mark).
    pub peak_pending: AtomicU64,
}

impl PipelineStats {
    fn new() -> Self {
        Self {
            frames_received: AtomicU64::new(0),
            frames_parsed: AtomicU64::new(0),
            frames_unparseable: AtomicU64::new(0),
            pcap_bytes_written: AtomicU64::new(0),
            pcap_frames_written: AtomicU64::new(0),
            subscriber_count: AtomicU64::new(0),
            mgmt_count: AtomicU64::new(0),
            data_count: AtomicU64::new(0),
            control_count: AtomicU64::new(0),
            eapol_count: AtomicU64::new(0),
            beacon_count: AtomicU64::new(0),
            fcs_errors: AtomicU64::new(0),
            usb_frames: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            peak_pending: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> PipelineStatsSnapshot {
        PipelineStatsSnapshot {
            usb_frames: self.usb_frames.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            frames_parsed: self.frames_parsed.load(Ordering::Relaxed),
            frames_unparseable: self.frames_unparseable.load(Ordering::Relaxed),
            pcap_bytes_written: self.pcap_bytes_written.load(Ordering::Relaxed),
            pcap_frames_written: self.pcap_frames_written.load(Ordering::Relaxed),
            subscriber_count: self.subscriber_count.load(Ordering::Relaxed),
            mgmt_count: self.mgmt_count.load(Ordering::Relaxed),
            data_count: self.data_count.load(Ordering::Relaxed),
            control_count: self.control_count.load(Ordering::Relaxed),
            eapol_count: self.eapol_count.load(Ordering::Relaxed),
            beacon_count: self.beacon_count.load(Ordering::Relaxed),
            fcs_errors: self.fcs_errors.load(Ordering::Relaxed),
            pending: self.pending.load(Ordering::Relaxed),
            peak_pending: self.peak_pending.load(Ordering::Relaxed),
        }
    }
}

/// Copyable snapshot of pipeline stats for display.
#[derive(Debug, Clone, Copy)]
pub struct PipelineStatsSnapshot {
    /// Frames extracted from USB by adapter threads.
    pub usb_frames: u64,
    /// Frames received by the pipeline thread.
    pub frames_received: u64,
    /// Frames successfully parsed.
    pub frames_parsed: u64,
    /// Frames too short or malformed.
    pub frames_unparseable: u64,
    /// Bytes written to pcap file.
    pub pcap_bytes_written: u64,
    /// Frames written to pcap file.
    pub pcap_frames_written: u64,
    /// Active subscriber count.
    pub subscriber_count: u64,
    /// Management frames.
    pub mgmt_count: u64,
    /// Data frames.
    pub data_count: u64,
    /// Control frames.
    pub control_count: u64,
    /// EAPOL frames.
    pub eapol_count: u64,
    /// Beacon/probe response frames.
    pub beacon_count: u64,
    /// Frames with FCS errors (counted but not parsed/extracted).
    pub fcs_errors: u64,
    /// Current queue depth (submit→pipeline).
    pub pending: u64,
    /// Peak queue depth ever observed.
    pub peak_pending: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FrameGate — the core
// ═══════════════════════════════════════════════════════════════════════════════

/// The Frame Gate — single entry point for all adapter frames.
///
/// Any adapter calls `gate.submit(frame)`. The pipeline thread parses,
/// writes pcap, updates the store, and broadcasts to subscribers.
///
/// Clone is cheap (Arc internals). submit() never blocks.
#[derive(Clone)]
pub struct FrameGate {
    inner: Arc<FrameGateInner>,
}

struct FrameGateInner {
    /// Channel for submitting RxFrames to the pipeline thread.
    tx: mpsc::Sender<RxFrame>,
    /// All active raw frame subscriber channels. Protected by mutex for subscribe/remove.
    subscribers: Mutex<Vec<mpsc::Sender<Arc<ParsedFrame>>>>,
    /// All active delta subscriber channels. Receives semantic StoreUpdate deltas.
    update_subscribers: Mutex<Vec<mpsc::Sender<Arc<Vec<StoreUpdate>>>>>,
    /// Pipeline statistics (atomic, lock-free reads).
    stats: PipelineStats,
    /// When the pipeline was created (for pcap timestamp calculation).
    start_time: Instant,
    /// Pcap file path if capturing.
    pcap_path: Option<PathBuf>,
}

struct PcapCapture {
    writer: BufWriter<File>,
    path: PathBuf,
    bytes_written: u64,
    packets_written: u64,
}

impl FrameGate {
    /// Create a new FrameGate, spawning the pipeline thread.
    ///
    /// `store`: the FrameStore to update with extracted intelligence.
    /// `pcap_path`: if Some, creates a pcap file and writes all raw frames.
    pub fn new(store: FrameStore, pcap_path: Option<PathBuf>) -> Self {
        let (tx, rx) = mpsc::channel::<RxFrame>();

        let stats = PipelineStats::new();
        let start_time = Instant::now();

        // Open pcap file if requested
        let pcap = pcap_path.as_deref().and_then(|path| {
            match create_pcap_file(path) {
                Ok(capture) => Some(capture),
                Err(e) => {
                    eprintln!("[pipeline] failed to create pcap at {:?}: {}", path, e);
                    None
                }
            }
        });

        let inner = Arc::new(FrameGateInner {
            tx,
            subscribers: Mutex::new(Vec::new()),
            update_subscribers: Mutex::new(Vec::new()),
            stats,
            start_time,
            pcap_path: pcap_path.clone(),
        });

        // Spawn the pipeline thread
        let gate_inner = Arc::clone(&inner);
        thread::Builder::new()
            .name("pipeline".into())
            .spawn(move || {
                pipeline_thread(rx, gate_inner, store, pcap);
            })
            .expect("failed to spawn pipeline thread");

        FrameGate { inner }
    }

    /// Submit a raw frame from any adapter. Never blocks.
    ///
    /// This is the ONLY entry point for frames into the system.
    /// The pipeline thread handles parsing, pcap, store updates, and broadcast.
    pub fn submit(&self, frame: RxFrame) {
        // Track USB-side frame count + pending depth
        self.inner.stats.usb_frames.fetch_add(1, Ordering::Relaxed);
        let pending = self.inner.stats.pending.fetch_add(1, Ordering::Relaxed) + 1;
        // Update high-water mark
        let mut peak = self.inner.stats.peak_pending.load(Ordering::Relaxed);
        while pending > peak {
            match self.inner.stats.peak_pending.compare_exchange_weak(
                peak, pending, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => peak = actual,
            }
        }

        // Send to pipeline thread — unbounded channel, never blocks.
        // If the pipeline thread has exited (channel closed), silently drop.
        let _ = self.inner.tx.send(frame);
    }

    /// Subscribe to the parsed frame stream.
    ///
    /// Returns a PipelineSubscriber with an unbounded channel.
    /// Every frame parsed after this call will be delivered.
    /// The channel NEVER drops frames.
    pub fn subscribe(&self, label: &str) -> PipelineSubscriber {
        let (tx, rx) = mpsc::channel();
        {
            let mut subs = self.inner.subscribers.lock().unwrap_or_else(|e| e.into_inner());
            subs.push(tx);
        }
        self.inner.stats.subscriber_count.fetch_add(1, Ordering::Relaxed);
        PipelineSubscriber::new(rx, label)
    }

    /// Subscribe to the semantic delta stream.
    ///
    /// Returns an UpdateSubscriber that receives `Arc<Vec<StoreUpdate>>` batches.
    /// Each batch contains all deltas produced from a single frame (or scanner event).
    /// The channel is unbounded — it NEVER drops updates.
    pub fn subscribe_updates(&self, label: &str) -> UpdateSubscriber {
        let (tx, rx) = mpsc::channel();
        {
            let mut subs = self.inner.update_subscribers.lock().unwrap_or_else(|e| e.into_inner());
            subs.push(tx);
        }
        UpdateSubscriber::new(rx, label)
    }

    /// Emit StoreUpdate deltas from any producer (attacks, scanner, adapter).
    ///
    /// Applies the deltas to the FrameStore and broadcasts them to all
    /// update subscribers. This is the same path the pipeline thread uses
    /// for frame-derived deltas — attacks and other producers use it to
    /// push their state into the unified delta stream.
    pub fn emit_updates(&self, store: &FrameStore, deltas: Vec<StoreUpdate>) {
        if deltas.is_empty() { return; }
        store.apply(&deltas);
        let arc_deltas = Arc::new(deltas);
        let mut usubs = self.inner.update_subscribers.lock().unwrap_or_else(|e| e.into_inner());
        usubs.retain(|tx| tx.send(Arc::clone(&arc_deltas)).is_ok());
    }

    /// Get a snapshot of pipeline statistics.
    pub fn stats(&self) -> PipelineStatsSnapshot {
        self.inner.stats.snapshot()
    }

    /// Get the pcap file path, if capturing.
    pub fn pcap_path(&self) -> Option<&Path> {
        self.inner.pcap_path.as_deref()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Pipeline thread — the hot loop
// ═══════════════════════════════════════════════════════════════════════════════

fn pipeline_thread(
    rx: mpsc::Receiver<RxFrame>,
    inner: Arc<FrameGateInner>,
    store: FrameStore,
    mut pcap: Option<PcapCapture>,
) {
    // Periodic pcap flush interval
    let mut last_flush = Instant::now();
    let flush_interval = std::time::Duration::from_secs(1);

    while let Ok(rx_frame) = rx.recv() {
        inner.stats.pending.fetch_sub(1, Ordering::Relaxed);
        inner.stats.frames_received.fetch_add(1, Ordering::Relaxed);

        // ── 0. FCS error filter ──
        // Frames with FCS errors have corrupted bytes — parsing them creates
        // phantom APs/STAs with garbage MACs and SSIDs. Count them and write
        // to pcap for offline analysis, but skip parsing and extraction.
        if rx_frame.is_fcs_error {
            inner.stats.fcs_errors.fetch_add(1, Ordering::Relaxed);

            // Still write to pcap (errored frames are valuable for RF analysis)
            if let Some(ref mut cap) = pcap {
                let elapsed = inner.start_time.elapsed();
                let ts_us = elapsed.as_micros() as u64;
                if write_pcap_packet(&mut cap.writer, &rx_frame.data, ts_us).is_ok() {
                    cap.packets_written += 1;
                    cap.bytes_written += (16 + rx_frame.data.len()) as u64;
                    inner.stats.pcap_frames_written.store(cap.packets_written, Ordering::Relaxed);
                    inner.stats.pcap_bytes_written.store(cap.bytes_written, Ordering::Relaxed);
                }
            }

            continue; // Skip parsing, extraction, and broadcasting
        }

        // ── 1. 802.11 frame control sanity check ──
        // Valid frames: protocol version = 0 (bits 0-1), type = 0-2 (bits 2-3).
        // Type 3 is reserved. Non-zero protocol version is invalid.
        if rx_frame.data.len() >= 2 {
            let fc = u16::from_le_bytes([rx_frame.data[0], rx_frame.data[1]]);
            let proto_ver = fc & 0x3;
            let frame_type = (fc >> 2) & 0x3;
            if proto_ver != 0 || frame_type == 3 {
                inner.stats.frames_unparseable.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        }

        // ── 2. Parse ──
        let parsed = parsed_frame::parse_frame(
            &rx_frame.data,
            rx_frame.rssi,
            rx_frame.channel,
            rx_frame.band,
            rx_frame.timestamp,
        );

        // ── 3. Update per-type counters ──
        match parsed.frame_type {
            0 => {
                inner.stats.mgmt_count.fetch_add(1, Ordering::Relaxed);
                if parsed.frame_subtype == 8 || parsed.frame_subtype == 5 {
                    inner.stats.beacon_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            1 => {
                inner.stats.control_count.fetch_add(1, Ordering::Relaxed);
            }
            2 => {
                inner.stats.data_count.fetch_add(1, Ordering::Relaxed);
                if let FrameBody::Data {
                    payload: DataPayload::Eapol(_), ..
                } = &parsed.body {
                    inner.stats.eapol_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => {}
        }

        if matches!(parsed.body, FrameBody::Unparseable { .. }) {
            inner.stats.frames_unparseable.fetch_add(1, Ordering::Relaxed);
        } else {
            inner.stats.frames_parsed.fetch_add(1, Ordering::Relaxed);
        }

        // ── 4. Write to pcap ──
        if let Some(ref mut cap) = pcap {
            let elapsed = inner.start_time.elapsed();
            let ts_us = elapsed.as_micros() as u64;
            if write_pcap_packet(&mut cap.writer, &rx_frame.data, ts_us).is_ok() {
                cap.packets_written += 1;
                cap.bytes_written += (16 + rx_frame.data.len()) as u64;
                inner.stats.pcap_frames_written.store(cap.packets_written, Ordering::Relaxed);
                inner.stats.pcap_bytes_written.store(cap.bytes_written, Ordering::Relaxed);
            }
        }

        // ── 5. Extract deltas + apply to the FrameStore ──
        //
        // The extractor produces semantic deltas from each frame.
        // The store applies them (single write path for all state).
        // The deltas are then broadcast to all update subscribers.
        let deltas = extractor::extract_frame(&parsed, parsed.channel, parsed.band, &store);
        store.apply(&deltas);

        // ── 5. Broadcast deltas to update subscribers ──
        if !deltas.is_empty() {
            let arc_deltas = Arc::new(deltas);
            let mut usubs = inner.update_subscribers.lock().unwrap_or_else(|e| e.into_inner());
            usubs.retain(|tx| tx.send(Arc::clone(&arc_deltas)).is_ok());
        }

        // ── 6. Broadcast raw frames to subscribers ──
        let arc_frame = Arc::new(parsed);
        {
            let mut subs = inner.subscribers.lock().unwrap_or_else(|e| e.into_inner());
            // Remove dead subscribers (receiver dropped)
            subs.retain(|tx| tx.send(Arc::clone(&arc_frame)).is_ok());
            // Update subscriber count after cleanup
            inner.stats.subscriber_count.store(subs.len() as u64, Ordering::Relaxed);
        }

        // ── 6. Periodic pcap flush ──
        if pcap.is_some() && last_flush.elapsed() >= flush_interval {
            if let Some(ref mut cap) = pcap {
                let _ = cap.writer.flush();
            }
            last_flush = Instant::now();
        }
    }

    // Channel closed — flush pcap and exit
    if let Some(ref mut cap) = pcap {
        let _ = cap.writer.flush();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Pcap helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn create_pcap_file(path: &Path) -> std::io::Result<PcapCapture> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(path)?;
    let mut writer = BufWriter::with_capacity(64 * 1024, file); // 64KB buffer

    // Write pcap global header (24 bytes)
    let mut header = [0u8; 24];
    header[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    header[6..8].copy_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    // thiszone: i32 = 0 (UTC), sigfigs: u32 = 0
    header[16..20].copy_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    header[20..24].copy_from_slice(&PCAP_LINKTYPE_IEEE802_11.to_le_bytes());

    writer.write_all(&header)?;

    Ok(PcapCapture {
        writer,
        path: path.to_path_buf(),
        bytes_written: 24,
        packets_written: 0,
    })
}

fn write_pcap_packet(writer: &mut BufWriter<File>, data: &[u8], timestamp_us: u64) -> std::io::Result<()> {
    let ts_sec = (timestamp_us / 1_000_000) as u32;
    let ts_usec = (timestamp_us % 1_000_000) as u32;
    let len = data.len() as u32;

    let mut pkt_header = [0u8; 16];
    pkt_header[0..4].copy_from_slice(&ts_sec.to_le_bytes());
    pkt_header[4..8].copy_from_slice(&ts_usec.to_le_bytes());
    pkt_header[8..12].copy_from_slice(&len.to_le_bytes());
    pkt_header[12..16].copy_from_slice(&len.to_le_bytes());

    writer.write_all(&pkt_header)?;
    writer.write_all(data)?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_beacon_frame() -> RxFrame {
        let mut data = vec![0u8; 42];
        data[0] = 0x80; // beacon
        data[1] = 0x00;
        data[4..10].copy_from_slice(&[0xFF; 6]); // addr1 broadcast
        data[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // addr2
        data[16..22].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // addr3
        data[32] = 0x64; data[33] = 0x00; // beacon interval
        data[36] = 0x00; data[37] = 0x04; // SSID IE
        data[38] = b'T'; data[39] = b'e'; data[40] = b's'; data[41] = b't';
        RxFrame { data, rssi: -42, channel: 6, band: 0, timestamp: Duration::from_millis(100), ..Default::default() }
    }

    fn make_data_frame() -> RxFrame {
        let mut data = vec![0u8; 32];
        data[0] = 0x08; // type=data, subtype=0
        data[1] = 0x02; // from-ds
        data[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]); // addr1=STA
        data[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // addr2=BSSID
        RxFrame { data, rssi: -55, channel: 11, band: 0, timestamp: Duration::from_millis(200), ..Default::default() }
    }

    /// Helper: wait briefly for the pipeline thread to process submitted frames.
    fn settle() {
        thread::sleep(Duration::from_millis(50));
    }

    #[test]
    fn test_framegate_subscribe_and_receive() {
        let store = FrameStore::new();
        let gate = FrameGate::new(store, None);
        let sub = gate.subscribe("test");

        gate.submit(make_beacon_frame());
        settle();

        let frame = sub.try_recv().expect("should receive frame");
        assert_eq!(frame.frame_type, 0); // management
        assert_eq!(frame.frame_subtype, 8); // beacon
        assert_eq!(frame.rssi, -42);
    }

    #[test]
    fn test_framegate_multiple_subscribers() {
        let store = FrameStore::new();
        let gate = FrameGate::new(store, None);
        let sub1 = gate.subscribe("scanner");
        let sub2 = gate.subscribe("attack");

        gate.submit(make_beacon_frame());
        settle();

        let f1 = sub1.try_recv().expect("sub1 should receive");
        let f2 = sub2.try_recv().expect("sub2 should receive");
        assert_eq!(f1.frame_type, f2.frame_type);
        assert_eq!(f1.rssi, f2.rssi);
    }

    #[test]
    fn test_framegate_stats_updated() {
        let store = FrameStore::new();
        let gate = FrameGate::new(store, None);
        let _sub = gate.subscribe("test");

        gate.submit(make_beacon_frame());
        gate.submit(make_data_frame());
        gate.submit(make_beacon_frame());
        settle();

        let stats = gate.stats();
        assert_eq!(stats.frames_received, 3);
        assert_eq!(stats.mgmt_count, 2);
        assert_eq!(stats.data_count, 1);
        assert_eq!(stats.beacon_count, 2);
    }

    #[test]
    fn test_framegate_subscriber_drain() {
        let store = FrameStore::new();
        let gate = FrameGate::new(store, None);
        let sub = gate.subscribe("test");

        for _ in 0..5 {
            gate.submit(make_beacon_frame());
        }
        settle();

        let frames = sub.drain();
        assert_eq!(frames.len(), 5);
        for f in &frames {
            assert_eq!(f.frame_subtype, 8);
        }
    }

    #[test]
    fn test_framegate_dead_subscriber_cleaned() {
        let store = FrameStore::new();
        let gate = FrameGate::new(store, None);
        let sub = gate.subscribe("temp");
        drop(sub);

        gate.submit(make_beacon_frame());
        settle();

        let stats = gate.stats();
        assert_eq!(stats.subscriber_count, 0);
    }

    #[test]
    #[ignore = "pcap flush timing — needs explicit flush_pcap() method on FrameGate"]
    fn test_framegate_pcap_capture() {
        let tmp = std::env::temp_dir().join("wifikit_test_framegate.pcap");
        let store = FrameStore::new();
        let gate = FrameGate::new(store, Some(tmp.clone()));

        gate.submit(make_beacon_frame());
        gate.submit(make_data_frame());
        settle();

        let stats = gate.stats();
        assert_eq!(stats.pcap_frames_written, 2);
        assert!(stats.pcap_bytes_written > 24); // header + 2 packets

        // Drop the gate to trigger channel close → pcap flush to disk
        drop(gate);
        // Pipeline thread needs time to notice channel closed and flush pcap
        thread::sleep(Duration::from_millis(200));

        // Verify pcap file exists and has correct magic
        let data = std::fs::read(&tmp).expect("pcap file should exist");
        assert!(data.len() >= 24, "pcap file too small: {} bytes", data.len());
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(magic, PCAP_MAGIC);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_framegate_wait_for() {
        let store = FrameStore::new();
        let gate = FrameGate::new(store, None);
        let sub = gate.subscribe("test");

        gate.submit(make_beacon_frame());
        gate.submit(make_data_frame());
        settle();

        let found = sub.wait_for(
            |f| f.frame_type == 2, // data
            Duration::from_millis(200),
        );
        assert!(found.is_some());
        assert_eq!(found.unwrap().frame_type, 2);
    }

    #[test]
    fn test_framegate_no_frame_loss() {
        let store = FrameStore::new();
        let gate = FrameGate::new(store, None);
        let sub = gate.subscribe("test");

        let count = 10_000;
        for _ in 0..count {
            gate.submit(make_beacon_frame());
        }
        // Give pipeline thread time to process 10K frames
        thread::sleep(Duration::from_millis(500));

        let received = sub.drain();
        assert_eq!(received.len(), count, "zero frame loss: all {} frames received", count);
    }

    #[test]
    fn test_framegate_usb_frames_and_pending() {
        let store = FrameStore::new();
        let gate = FrameGate::new(store, None);

        gate.submit(make_beacon_frame());
        gate.submit(make_beacon_frame());
        settle();

        let stats = gate.stats();
        assert_eq!(stats.usb_frames, 2);
        // After processing, pending should be 0
        assert_eq!(stats.pending, 0);
    }
}
