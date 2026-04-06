//! SharedAdapter — shared access to a USB adapter with independent TX/RX paths.
//!
//! Architecture (FrameGate):
//!   - One dedicated RX thread reads USB bulk IN continuously
//!   - RX frames are submitted to FrameGate via gate.submit()
//!   - FrameGate handles parsing, pcap, and distribution
//!   - TX goes through Mutex<Adapter> (attacks, channel control)
//!   - RX and TX never contend — separate USB endpoints, separate code paths
//!
//! The RX thread starts immediately after SharedAdapter::spawn(). From that
//! moment, every frame the adapter receives is read, chip-parsed into RxFrames,
//! and submitted to the FrameGate. The gate handles all downstream processing
//! (802.11 parsing, pcap writes, subscriber broadcast).
//!
//! Channel locking protocol:
//!   1. No lock: scanner hops freely, RX thread captures on whatever channel
//!   2. Attack calls lock_channel(ch) → radio moves to ch, scanner pauses hopping
//!   3. Attack calls unlock_channel() → scanner resumes hopping
//!   4. RX thread doesn't care — it reads whatever arrives, always

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::core::adapter::{Adapter, AdapterInfo};
use crate::core::channel::Channel;
use crate::core::chip::RxHandle;
use crate::core::mac::MacAddress;
use crate::core::Result;
use crate::pipeline::FrameGate;

/// Channel value meaning "no channel locked" (channel 0 is not a valid WiFi channel).
const NO_CHANNEL_LOCK: u8 = 0;

/// RX thread diagnostic counters — shared via Arc, readable from outside.
#[derive(Default)]
pub struct RxThreadStats {
    /// USB bulk reads performed.
    pub usb_reads: AtomicU32,
    /// Total bytes received from USB.
    pub usb_bytes: AtomicU64,
    /// Packets successfully parsed (consumed > 0).
    pub packets_parsed: AtomicU32,
    /// Frames submitted to FrameGate.
    pub frames_submitted: AtomicU32,
    /// DriverMessage packets forwarded.
    pub driver_messages: AtomicU32,
    /// TxStatus reports received.
    pub tx_status: AtomicU32,
    /// C2H/MCU events received.
    pub c2h_events: AtomicU32,
    /// ChannelInfo (CSI) packets received.
    pub channel_info: AtomicU32,
    /// DFS radar reports received.
    pub dfs_reports: AtomicU32,
    /// BbScope (I/Q) packets received.
    pub bb_scope: AtomicU32,
    /// SpatialSounding reports received.
    pub spatial_sounding: AtomicU32,
    /// F2P/TxPdRelease/other non-frame packets.
    pub other_packets: AtomicU32,
    /// Packets skipped (ParsedPacket::Skip).
    pub skipped: AtomicU32,
    /// Times consumed==0 was returned (partial/corrupt packet).
    pub consumed_zero: AtomicU32,
    /// Largest single USB read size (bytes).
    pub max_read_size: AtomicU32,
    /// Number of USB reads with multiple frames (aggregation working).
    pub multi_frame_reads: AtomicU32,
}

/// RX thread poll timeout — how long to wait for USB data before checking alive flag.
// Short timeout for USB bulk reads. With MT7921AU returning 1 frame per read
// (no aggregation), we need to spin fast. 1ms timeout = max ~1000 timeout cycles/sec
// on empty channels, but frames arrive sub-millisecond on busy channels.
const RX_POLL_TIMEOUT: Duration = Duration::from_millis(1);

// ═══════════════════════════════════════════════════════════════════════════════
//  SharedAdapter — the shared access wrapper with independent TX/RX
// ═══════════════════════════════════════════════════════════════════════════════

/// Shared access to a USB adapter for concurrent scanner + attack use.
///
/// RX path: dedicated thread → chip parse_fn → FrameGate.submit()
/// TX path: Mutex<Adapter> → attacks call tx_frame()
/// Channel: AtomicU8 lock → scanner/attacks coordinate
///
/// Clone is cheap (Arc). Pass to scanner, attacks, and CLI freely.
#[derive(Clone)]
pub struct SharedAdapter {
    inner: Arc<SharedAdapterInner>,
}

struct SharedAdapterInner {
    /// The USB adapter, behind a mutex for TX and control operations.
    /// RX is handled by the dedicated RX thread (not through this mutex).
    adapter: Mutex<Adapter>,
    /// The FrameGate that receives all RX frames for downstream processing.
    gate: FrameGate,
    /// Current channel the radio is tuned to (updated by set_channel).
    /// The RX thread reads this to tag frames with the correct channel.
    current_channel: AtomicU8,
    /// Current band: 0=2.4GHz, 1=5GHz, 2=6GHz. Updated alongside current_channel.
    current_band: AtomicU8,
    /// Locked channel number (0 = no lock, scanner hops freely).
    locked_channel: AtomicU8,
    /// Whether the RX thread should keep running.
    /// Set to false by stop_rx() → thread exits. Set to true by start_rx() → new thread.
    /// Also set to false by shutdown() (permanent death).
    /// Arc so drivers with their own RX pipeline can share this flag.
    alive: Arc<AtomicBool>,
    /// Whether the adapter has been permanently shut down (USB closed).
    /// Unlike `alive` (which toggles for stop_rx/start_rx), this is one-way.
    shut_down: AtomicBool,
    /// RX thread join handle. None when RX is stopped (idle adapter).
    rx_thread: Mutex<Option<thread::JoinHandle<()>>>,
    /// Who holds the channel lock (for status bar display).
    lock_holder: Mutex<Option<String>>,
    /// Static adapter info (chip, VID/PID, name) — no lock needed.
    pub info: AdapterInfo,
    /// MAC address at init time (randomized by Adapter::init).
    pub mac: MacAddress,
    /// Hardware MAC from the driver (EFUSE/chip-level, not randomized).
    pub driver_mac: MacAddress,
    /// RX thread diagnostic counters.
    pub rx_stats: Arc<RxThreadStats>,
}

impl SharedAdapter {
    /// Open, initialize, enter monitor mode, and start the RX thread.
    ///
    /// After this returns:
    /// - The adapter is in monitor mode
    /// - The RX thread is running (frames flowing to FrameGate)
    /// - Call gate.subscribe() to get parsed frames
    /// - Call .tx_frame() to transmit (independent of RX)
    ///
    /// `gate`: the FrameGate that receives all RX frames for parsing and distribution.
    /// `on_status` is called with progress messages during init.
    pub fn spawn(
        info: &AdapterInfo,
        gate: FrameGate,
        mut on_status: impl FnMut(&str),
    ) -> Result<Self> {
        // 1. Open adapter (USB claim)
        on_status(&format!("Opening {}...", info.name));
        let mut adapter = Adapter::open(info)?;
        on_status(&format!(
            "USB claimed (IN={:#04x} OUT={:#04x})",
            adapter.endpoints.bulk_in,
            adapter.endpoints.bulk_out,
        ));

        // 2. Initialize chip (power on, firmware, PHY calibration)
        on_status("Initializing chip (power on, firmware, PHY)...");
        adapter.init()?;
        let mac = adapter.mac();
        let driver_mac = adapter.driver.mac();
        on_status(&format!("Chip initialized. MAC={} (driver={})", mac, driver_mac));

        // 3. Enter monitor mode
        on_status("Setting monitor mode...");
        adapter.set_monitor_mode()?;
        on_status("Monitor mode active.");

        // 4. Build the SharedAdapter (need alive flag before starting RX)
        let alive = Arc::new(AtomicBool::new(true));
        let shared = Self {
            inner: Arc::new(SharedAdapterInner {
                adapter: Mutex::new(adapter),
                gate: gate.clone(),
                current_channel: AtomicU8::new(0),
                current_band: AtomicU8::new(0),
                locked_channel: AtomicU8::new(NO_CHANNEL_LOCK),
                alive: alive.clone(),
                shut_down: AtomicBool::new(false),
                rx_thread: Mutex::new(None),
                lock_holder: Mutex::new(None),
                info: info.clone(),
                mac,
                driver_mac,
                rx_stats: Arc::new(RxThreadStats::default()),
            }),
        };

        // 5. Start RX — driver-managed pipeline first, fall back to shared RX thread
        let driver_manages_rx = {
            let mut adapter = shared.inner.adapter.lock()
                .unwrap_or_else(|e| e.into_inner());
            adapter.driver.start_rx_pipeline(gate.clone(), alive)
        };

        if driver_manages_rx {
            on_status("RX pipeline active (driver-managed).");
        } else {
            // Fall back to shared RX thread via take_rx_handle
            let rx_handle = {
                let mut adapter = shared.inner.adapter.lock()
                    .unwrap_or_else(|e| e.into_inner());
                adapter.driver.take_rx_handle()
            };
            if let Some(rx_handle) = rx_handle {
                on_status("Starting RX thread (FrameGate)...");
                let inner_clone = Arc::clone(&shared.inner);
                let handle = start_rx_thread(rx_handle, gate, inner_clone);
                *shared.inner.rx_thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
                on_status("RX thread active.");
            } else {
                on_status("RX thread not available (driver doesn't support split RX).");
            }
        }

        Ok(shared)
    }

    // ── FrameGate access ──

    /// Get a reference to the FrameGate for subscribing to frames.
    pub fn gate(&self) -> &FrameGate {
        &self.inner.gate
    }

    /// Subscribe to raw ParsedFrames from the pipeline.
    ///
    /// Convenience method — delegates to `gate().subscribe()`.
    /// Used by attacks that need real-time frame filtering (e.g., waiting for
    /// EAPOL M1 after sending Auth). The FrameStore holds aggregate intelligence;
    /// this gives access to individual frames as they arrive.
    pub fn subscribe(&self, label: &str) -> crate::pipeline::PipelineSubscriber {
        self.inner.gate.subscribe(label)
    }

    /// Get pipeline statistics snapshot.
    pub fn pipeline_stats(&self) -> crate::pipeline::PipelineStatsSnapshot {
        self.inner.gate.stats()
    }

    // ── Channel locking ──

    /// Lock the radio to a specific channel. Called by attacks before starting.
    ///
    /// The scanner will see this and stop hopping, staying on the locked channel.
    /// The status bar will show "ch:N (locked: holder)".
    ///
    /// Returns `Err` if another attack already holds the lock.
    pub fn lock_channel(&self, channel: u8, holder: &str) -> Result<()> {
        let prev = self.inner.locked_channel.compare_exchange(
            NO_CHANNEL_LOCK,
            channel,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        match prev {
            Ok(_) => {
                let mut lh = self.inner.lock_holder.lock()
                    .unwrap_or_else(|e| e.into_inner());
                *lh = Some(holder.to_string());
                drop(lh);

                // Set the channel on the adapter (TX path mutex)
                let ch = Channel::new(channel);
                let band_idx = match ch.band {
                    crate::core::channel::Band::Band2g => 0u8,
                    crate::core::channel::Band::Band5g => 1,
                    crate::core::channel::Band::Band6g => 2,
                };
                let mut adapter = self.inner.adapter.lock()
                    .unwrap_or_else(|e| e.into_inner());
                match adapter.driver.set_channel(ch) {
                    Ok(()) => {
                        // Update current channel + band for RX thread frame tagging
                        self.inner.current_channel.store(channel, Ordering::SeqCst);
                        self.inner.current_band.store(band_idx, Ordering::SeqCst);
                        Ok(())
                    }
                    Err(e) => {
                        // Channel set failed — release the lock we just acquired
                        // so subsequent lock attempts don't see a stale lock
                        drop(adapter);
                        self.inner.locked_channel.store(NO_CHANNEL_LOCK, Ordering::SeqCst);
                        let mut lh = self.inner.lock_holder.lock()
                            .unwrap_or_else(|e| e.into_inner());
                        *lh = None;
                        Err(e)
                    }
                }
            }
            Err(existing) => {
                let holder_name = self.inner.lock_holder.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                    .unwrap_or_else(|| "unknown".into());
                Err(crate::core::Error::ChannelLocked {
                    channel: existing,
                    holder: holder_name,
                })
            }
        }
    }

    /// Unlock the channel. Called by attacks when they finish.
    /// Scanner will resume hopping on its next iteration.
    pub fn unlock_channel(&self) {
        self.inner.locked_channel.store(NO_CHANNEL_LOCK, Ordering::SeqCst);
        let mut lh = self.inner.lock_holder.lock()
            .unwrap_or_else(|e| e.into_inner());
        *lh = None;
    }

    /// Get the currently locked channel, or 0 if no lock.
    pub fn locked_channel(&self) -> u8 {
        self.inner.locked_channel.load(Ordering::SeqCst)
    }

    /// Get the name of whoever holds the channel lock, if any.
    pub fn lock_holder(&self) -> Option<String> {
        self.inner.lock_holder.lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Check if the channel is currently locked.
    pub fn is_channel_locked(&self) -> bool {
        self.locked_channel() != NO_CHANNEL_LOCK
    }

    // ── TX + Control access (through adapter mutex) ──

    /// Execute a closure with exclusive adapter access.
    ///
    /// Used for TX, channel control, and any operation that needs the adapter.
    /// The RX thread does NOT go through this mutex — it uses the USB handle
    /// directly for bulk IN reads.
    pub fn with_adapter<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Adapter) -> Result<T>,
    {
        if self.inner.shut_down.load(Ordering::SeqCst) {
            return Err(crate::core::Error::AdapterNotInitialized);
        }
        let mut adapter = self.inner.adapter.lock()
            .unwrap_or_else(|e| e.into_inner());
        f(&mut adapter)
    }

    /// Set the radio channel (2.4/5GHz by number). Respects channel lock.
    pub fn set_channel(&self, channel: u8) -> Result<()> {
        self.set_channel_full(Channel::new(channel))
    }

    /// Set the radio channel with full band information. Respects channel lock.
    /// Use this for 6GHz channels where the number alone is ambiguous.
    pub fn set_channel_full(&self, channel: Channel) -> Result<()> {
        let locked = self.locked_channel();
        if locked != NO_CHANNEL_LOCK && locked != channel.number {
            return Ok(());
        }
        self.inner.current_channel.store(channel.number, Ordering::SeqCst);
        self.inner.current_band.store(
            match channel.band {
                crate::core::channel::Band::Band2g => 0,
                crate::core::channel::Band::Band5g => 1,
                crate::core::channel::Band::Band6g => 2,
            },
            Ordering::SeqCst,
        );
        self.with_adapter(|adapter| {
            adapter.driver.set_channel(channel)
        })
    }

    /// Transmit a frame. Independent of the RX thread — no contention.
    pub fn tx_frame(&self, frame: &[u8], opts: &crate::core::TxOptions) -> Result<()> {
        self.with_adapter(|adapter| {
            adapter.driver.tx_frame(frame, opts)
        })
    }

    /// Get the adapter's MAC address (randomized).
    pub fn mac(&self) -> MacAddress {
        self.inner.mac
    }

    /// Get the driver's hardware MAC (EFUSE/chip-level).
    pub fn driver_mac(&self) -> MacAddress {
        self.inner.driver_mac
    }

    /// Get static adapter info.
    pub fn info(&self) -> &AdapterInfo {
        &self.inner.info
    }

    /// Get RX thread diagnostic stats.
    pub fn rx_stats(&self) -> Arc<RxThreadStats> {
        Arc::clone(&self.inner.rx_stats)
    }

    /// Check if the adapter is still alive.
    pub fn is_alive(&self) -> bool {
        self.inner.alive.load(Ordering::SeqCst)
    }

    /// Get the current channel the radio is tuned to.
    pub fn current_channel(&self) -> u8 {
        self.inner.current_channel.load(Ordering::SeqCst)
    }

    /// Get the current band: 0=2.4GHz, 1=5GHz, 2=6GHz.
    pub fn current_band(&self) -> u8 {
        self.inner.current_band.load(Ordering::SeqCst)
    }

    // ── Chipset capability queries ──

    /// Get the channel settle time for this adapter's chipset.
    /// Each chip reports its own PLL retune time (e.g., 5ms for RTL, 200ms for MT7921).
    pub fn channel_settle_time(&self) -> Duration {
        if self.inner.shut_down.load(Ordering::SeqCst) {
            return Duration::from_millis(10);
        }
        let adapter = self.inner.adapter.lock().unwrap_or_else(|e| e.into_inner());
        adapter.driver.channel_settle_time()
    }

    /// Recommended dwell time per channel for scanning.
    /// Chipset drivers override this based on their channel switch speed.
    pub fn scan_dwell_time(&self) -> Duration {
        if self.inner.shut_down.load(Ordering::SeqCst) {
            return Duration::from_millis(500);
        }
        let adapter = self.inner.adapter.lock().unwrap_or_else(|e| e.into_inner());
        adapter.driver.scan_dwell_time()
    }

    /// Get supported channels from the chipset driver.
    pub fn supported_channels(&self) -> Vec<Channel> {
        if self.inner.shut_down.load(Ordering::SeqCst) {
            return Vec::new();
        }
        let adapter = self.inner.adapter.lock().unwrap_or_else(|e| e.into_inner());
        adapter.driver.supported_channels().to_vec()
    }

    /// Get supported bands from the chipset driver.
    pub fn supported_bands(&self) -> Vec<crate::core::channel::Band> {
        if self.inner.shut_down.load(Ordering::SeqCst) {
            return Vec::new();
        }
        let adapter = self.inner.adapter.lock().unwrap_or_else(|e| e.into_inner());
        adapter.driver.supported_bands()
    }

    /// Read per-channel survey data (busy/tx/rx/obss time in microseconds).
    /// Works in normal mode — no testmode needed.
    pub fn survey_read(&self, band_idx: u8) -> Result<crate::core::chip::ChannelSurvey> {
        if self.inner.shut_down.load(Ordering::SeqCst) {
            return Ok(crate::core::chip::ChannelSurvey::default());
        }
        let adapter = self.inner.adapter.lock().unwrap_or_else(|e| e.into_inner());
        adapter.driver.survey_read(band_idx)
    }

    /// Reset survey counters to start fresh measurement.
    pub fn survey_reset(&self, band_idx: u8) -> Result<()> {
        if self.inner.shut_down.load(Ordering::SeqCst) {
            return Ok(());
        }
        let adapter = self.inner.adapter.lock().unwrap_or_else(|e| e.into_inner());
        adapter.driver.survey_reset(band_idx)
    }

    // ── RX thread lifecycle ──
    //
    // The RX thread can be stopped and restarted without affecting the adapter.
    // USB stays claimed, monitor mode stays active, firmware stays loaded.
    // Only the RX reading loop starts/stops.
    //
    // Used by the shell to idle a dedicated attack adapter when the attack
    // finishes, then wake it up when a new attack starts. No re-init needed.

    /// Stop the RX thread. The adapter stays initialized and ready.
    ///
    /// Blocks until the thread exits (max ~RX_POLL_TIMEOUT for the USB read
    /// to timeout and check the alive flag). Safe to call if already stopped.
    pub fn stop_rx(&self) {
        self.inner.alive.store(false, Ordering::SeqCst);
        let handle = self.inner.rx_thread.lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(h) = handle {
            let _ = h.join();
        }
    }

    /// Start (or restart) the RX thread. Gets a fresh RxHandle from the driver
    /// and spawns a new thread. Safe to call if already running (no-op).
    ///
    /// This is the inverse of stop_rx(): the adapter was idle, now frames flow again.
    pub fn start_rx(&self) {
        // Already running — nothing to do
        if self.inner.alive.load(Ordering::SeqCst) {
            return;
        }
        // Permanently shut down — can't restart
        if self.inner.shut_down.load(Ordering::SeqCst) {
            return;
        }

        // Get a fresh RxHandle from the driver (creates new MCU channel for MediaTek)
        let rx_handle = {
            let mut adapter = self.inner.adapter.lock()
                .unwrap_or_else(|e| e.into_inner());
            adapter.driver.take_rx_handle()
        };

        if let Some(rx_handle) = rx_handle {
            self.inner.alive.store(true, Ordering::SeqCst);
            let gate = self.inner.gate.clone();
            let inner_clone = Arc::clone(&self.inner);
            let handle = start_rx_thread(rx_handle, gate, inner_clone);
            *self.inner.rx_thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        }
    }

    /// Check if the RX thread is currently running.
    pub fn is_rx_active(&self) -> bool {
        self.inner.alive.load(Ordering::SeqCst)
    }

    // ── Adapter lifecycle ──

    /// Shut down the adapter permanently. Stops RX thread, closes USB.
    /// After this, all operations return `AdapterNotInitialized`.
    /// Cannot be restarted — use stop_rx()/start_rx() for temporary idle.
    pub fn shutdown(&self) {
        // Stop RX thread first (blocks until thread exits)
        self.stop_rx();
        // Mark as permanently dead
        self.inner.shut_down.store(true, Ordering::SeqCst);
        // Close the adapter (releases USB)
        let mut adapter = self.inner.adapter.lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = adapter.close();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RX Thread — USB reader + chip parse_fn + FrameGate submit
// ═══════════════════════════════════════════════════════════════════════════════
//
// Single thread:
//
//   [rx-usb]  USB bulk IN → parse_fn → RxFrame → gate.submit()
//
// Simplified from the old two-thread design: FrameGate handles all downstream
// processing (802.11 parsing, pcap, subscriber broadcast). The RX thread just
// reads USB and does chip-specific header stripping via parse_fn.
//
// DriverMessages (MCU responses for MediaTek adapters) are routed directly
// to the driver via driver_msg_tx — they never enter the FrameGate.

/// Start the dedicated RX thread: USB reader → chip parse_fn → FrameGate.
///
/// The thread reads bulk IN continuously, calls the chip-specific parse_fn
/// to extract RxFrames, and submits them to the FrameGate. The gate handles
/// all downstream processing (parsing, pcap, distribution).
fn start_rx_thread(
    rx_handle: RxHandle,
    gate: FrameGate,
    inner: Arc<SharedAdapterInner>,
) -> thread::JoinHandle<()> {
    let stats = Arc::clone(&inner.rx_stats);
    thread::Builder::new()
        .name("rx-usb".into())
        .spawn(move || {
            let mut buf = vec![0u8; rx_handle.rx_buf_size];
            let mut read_num = 0u64;
            const READS_PER_CHANNEL: u64 = 5; // log 5 reads per channel change
            let mut reads_this_channel = 0u64;
            let mut last_log_channel = 0u8;
            let mut log = {
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new()
                    .create(true).write(true).truncate(true)
                    .open("/tmp/wifikit_shared_usb_reads.log").ok();
                if let Some(ref mut f) = f {
                    let _ = writeln!(f, "=== Shared RX Thread USB Reads ({} per channel) ===\n", READS_PER_CHANNEL);
                }
                f
            };

            loop {
                if !inner.alive.load(Ordering::SeqCst) {
                    break;
                }

                // Read USB bulk IN — this is the ONLY blocking point
                let actual = match rx_handle.device.read_bulk(
                    rx_handle.ep_in,
                    &mut buf,
                    RX_POLL_TIMEOUT,
                ) {
                    Ok(n) => n,
                    Err(rusb::Error::Timeout
                        | rusb::Error::Interrupted
                        | rusb::Error::Overflow) => continue,
                    Err(_) => break,
                };

                if actual == 0 {
                    continue;
                }

                read_num += 1;
                stats.usb_reads.fetch_add(1, Ordering::Relaxed);
                stats.usb_bytes.fetch_add(actual as u64, Ordering::Relaxed);
                // Track max read size
                let prev_max = stats.max_read_size.load(Ordering::Relaxed);
                if actual as u32 > prev_max {
                    stats.max_read_size.store(actual as u32, Ordering::Relaxed);
                }

                let channel = inner.current_channel.load(Ordering::Relaxed);

                // Dump a few USB reads per channel for diagnostics
                if channel != last_log_channel {
                    last_log_channel = channel;
                    reads_this_channel = 0;
                    if let Some(ref mut f) = log {
                        use std::io::Write;
                        let _ = writeln!(f, "\n{}", "=".repeat(60));
                        let _ = writeln!(f, "  CHANNEL {} (band={})", channel,
                            if channel <= 14 { "2.4GHz" } else { "5GHz" });
                        let _ = writeln!(f, "{}", "=".repeat(60));
                    }
                }
                reads_this_channel += 1;
                if reads_this_channel <= READS_PER_CHANNEL {
                    if let Some(ref mut f) = log {
                        use std::io::Write;
                        let _ = writeln!(f, "\n══ USB READ #{} (ch{} read #{}) — {} bytes ══",
                            read_num, channel, reads_this_channel, actual);
                        let mut p = 0;
                        while p < actual {
                            let end = (p + 16).min(actual);
                            let hex: String = buf[p..end].iter()
                                .map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                            let ascii: String = buf[p..end].iter()
                                .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' })
                                .collect();
                            let _ = writeln!(f, "  {:04X}: {:<48} |{}|", p, hex, ascii);
                            p += 16;
                        }
                    }
                }

                // Parse all frames from the USB bulk transfer
                // (USB aggregation means one transfer can contain multiple frames)
                let mut pos = 0;
                let mut frames_this_read = 0u32;
                while pos < actual {
                    let remaining = &buf[pos..actual];
                    let (consumed, packet) = (rx_handle.parse_fn)(remaining, channel);

                    if consumed == 0 {
                        stats.consumed_zero.fetch_add(1, Ordering::Relaxed);
                        break; // Don't skip — leftover bytes are partial packet
                    }

                    pos += consumed;
                    stats.packets_parsed.fetch_add(1, Ordering::Relaxed);

                    match packet {
                        crate::core::chip::ParsedPacket::Frame(frame) => {
                            frames_this_read += 1;
                            stats.frames_submitted.fetch_add(1, Ordering::Relaxed);
                            gate.submit(frame);
                        }
                        crate::core::chip::ParsedPacket::DriverMessage(msg) => {
                            stats.driver_messages.fetch_add(1, Ordering::Relaxed);
                            if let Some(ref tx) = rx_handle.driver_msg_tx {
                                let _ = tx.send(msg);
                            }
                        }
                        crate::core::chip::ParsedPacket::TxStatus(rpt) => {
                            stats.tx_status.fetch_add(1, Ordering::Relaxed);
                            if let Some(ref tx) = rx_handle.driver_msg_tx {
                                let _ = tx.send(rpt.raw);
                            }
                        }
                        crate::core::chip::ParsedPacket::C2hEvent(evt) => {
                            stats.c2h_events.fetch_add(1, Ordering::Relaxed);
                            if let Some(ref tx) = rx_handle.driver_msg_tx {
                                let _ = tx.send(evt.raw);
                            }
                        }
                        // TODO: Route CSI, DFS, BB scope, spatial sounding to
                        // FrameStore/subscribers once consumers exist (spectrum
                        // analyzer, positioning, radar detection views).
                        crate::core::chip::ParsedPacket::ChannelInfo(_) => {
                            stats.channel_info.fetch_add(1, Ordering::Relaxed);
                        }
                        crate::core::chip::ParsedPacket::DfsReport(_) => {
                            stats.dfs_reports.fetch_add(1, Ordering::Relaxed);
                        }
                        crate::core::chip::ParsedPacket::BbScope(_) => {
                            stats.bb_scope.fetch_add(1, Ordering::Relaxed);
                        }
                        crate::core::chip::ParsedPacket::SpatialSounding(_) => {
                            stats.spatial_sounding.fetch_add(1, Ordering::Relaxed);
                        }
                        crate::core::chip::ParsedPacket::F2pTxCmdReport(_) |
                        crate::core::chip::ParsedPacket::TxPdRelease(_) => {
                            stats.other_packets.fetch_add(1, Ordering::Relaxed);
                        }
                        crate::core::chip::ParsedPacket::Skip => {
                            stats.skipped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                if frames_this_read > 1 {
                    stats.multi_frame_reads.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
        .expect("failed to spawn rx-usb thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_adapter_is_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<SharedAdapter>();
    }

    #[test]
    fn test_rx_lifecycle_methods_exist() {
        // Compile-time verification that the API surface exists.
        // Can't test with real USB, but we verify the method signatures.
        fn _assert_api(sa: &SharedAdapter) {
            let _: bool = sa.is_rx_active();
            sa.stop_rx();
            sa.start_rx();
        }
    }
}
