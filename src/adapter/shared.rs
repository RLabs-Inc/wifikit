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

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
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
    alive: AtomicBool,
    /// Whether the adapter has been permanently shut down (USB closed).
    /// Unlike `alive` (which toggles for stop_rx/start_rx), this is one-way.
    shut_down: AtomicBool,
    /// RX thread join handle. None when RX is stopped (idle adapter).
    rx_thread: Mutex<Option<thread::JoinHandle<()>>>,
    /// Who holds the channel lock (for status bar display).
    lock_holder: Mutex<Option<String>>,
    /// Static adapter info (chip, VID/PID, name) — no lock needed.
    pub info: AdapterInfo,
    /// MAC address at init time.
    pub mac: MacAddress,
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
        on_status(&format!("Chip initialized. MAC={}", mac));

        // 3. Enter monitor mode
        on_status("Setting monitor mode...");
        adapter.set_monitor_mode()?;
        on_status("Monitor mode active.");

        // 4. Extract RX handle for the dedicated RX thread
        let rx_handle = adapter.driver.take_rx_handle();

        // 5. Build the SharedAdapter
        let shared = Self {
            inner: Arc::new(SharedAdapterInner {
                adapter: Mutex::new(adapter),
                gate: gate.clone(),
                current_channel: AtomicU8::new(0),
                current_band: AtomicU8::new(0),
                locked_channel: AtomicU8::new(NO_CHANNEL_LOCK),
                alive: AtomicBool::new(true),
                shut_down: AtomicBool::new(false),
                rx_thread: Mutex::new(None),
                lock_holder: Mutex::new(None),
                info: info.clone(),
                mac,
            }),
        };

        // 6. Start the RX thread if the driver supports split RX
        if let Some(rx_handle) = rx_handle {
            on_status("Starting RX thread (FrameGate)...");
            let inner_clone = Arc::clone(&shared.inner);
            let handle = start_rx_thread(rx_handle, gate, inner_clone);
            *shared.inner.rx_thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
            on_status("RX thread active.");
        } else {
            on_status("RX thread not available (driver doesn't support split RX).");
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

    /// Get the adapter's MAC address.
    pub fn mac(&self) -> MacAddress {
        self.inner.mac
    }

    /// Get static adapter info.
    pub fn info(&self) -> &AdapterInfo {
        &self.inner.info
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
    thread::Builder::new()
        .name("rx-usb".into())
        .spawn(move || {
            let mut buf = vec![0u8; rx_handle.rx_buf_size];

            // Debug logging to /tmp/wifikit_rx.log
            use std::io::Write;
            let mut log_file = std::fs::File::create("/tmp/wifikit_rx.log")
                .ok()
                .map(|f| std::io::BufWriter::new(f));
            let mut usb_reads = 0u64;
            let mut usb_bytes = 0u64;
            let mut usb_timeouts = 0u64;
            let mut frames_extracted = 0u64;
            let mut frames_submitted = 0u64;
            let log_start = std::time::Instant::now();

            // Timing instrumentation — where does time go?
            let mut time_in_usb_read = std::time::Duration::ZERO;
            let mut time_in_parse = std::time::Duration::ZERO;
            let mut time_in_submit = std::time::Duration::ZERO;
            let mut last_timing_report = std::time::Instant::now();

            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "rx-usb thread started. ep_in={:#04x} buf_size={}",
                    rx_handle.ep_in, rx_handle.rx_buf_size);
                let _ = log.flush();
            }

            loop {
                if !inner.alive.load(Ordering::SeqCst) {
                    break;
                }

                // Read USB bulk IN — this is the ONLY blocking point
                let t_usb = std::time::Instant::now();
                let actual = match rx_handle.device.read_bulk(
                    rx_handle.ep_in,
                    &mut buf,
                    RX_POLL_TIMEOUT,
                ) {
                    Ok(n) => {
                        time_in_usb_read += t_usb.elapsed();
                        n
                    }
                    Err(rusb::Error::Timeout) => {
                        time_in_usb_read += t_usb.elapsed();
                        usb_timeouts += 1;
                        continue;
                    }
                    Err(rusb::Error::Interrupted) => {
                        time_in_usb_read += t_usb.elapsed();
                        continue;
                    }
                    Err(rusb::Error::Overflow) => {
                        time_in_usb_read += t_usb.elapsed();
                        continue;
                    }
                    Err(e) => {
                        if let Some(ref mut log) = log_file {
                            let _ = writeln!(log, "[{:.3}s] FATAL USB error: {:?}",
                                log_start.elapsed().as_secs_f64(), e);
                            let _ = log.flush();
                        }
                        break;
                    }
                };

                if actual == 0 {
                    continue;
                }

                usb_reads += 1;
                usb_bytes += actual as u64;

                // Log first few reads and then every 1000th
                if let Some(ref mut log) = log_file {
                    if usb_reads <= 5 || usb_reads % 1000 == 0 {
                        let _ = writeln!(log, "[{:.3}s] USB read #{}: {} bytes, ch={}",
                            log_start.elapsed().as_secs_f64(),
                            usb_reads, actual,
                            inner.current_channel.load(Ordering::Relaxed));
                        let _ = log.flush();
                    }
                }

                // Get current channel for frame tagging
                let channel = inner.current_channel.load(Ordering::Relaxed);

                // Parse all frames from the USB bulk transfer
                // (USB aggregation means one transfer can contain multiple frames)
                let mut pos = 0;
                while pos < actual {
                    let remaining = &buf[pos..actual];

                    let t_parse = std::time::Instant::now();
                    let (consumed, packet) = (rx_handle.parse_fn)(remaining, channel);
                    time_in_parse += t_parse.elapsed();

                    if consumed == 0 {
                        pos += 4;
                        continue;
                    }

                    pos += consumed;
                    frames_extracted += 1;

                    match packet {
                        crate::core::chip::ParsedPacket::Frame(frame) => {
                            // Log first few frames
                            if frames_submitted < 10 {
                                if let Some(ref mut log) = log_file {
                                    let fc = if frame.data.len() >= 2 {
                                        format!("fc={:#06x}", u16::from_le_bytes([frame.data[0], frame.data[1]]))
                                    } else {
                                        "fc=??".to_string()
                                    };
                                    let _ = writeln!(log, "  frame #{}: {} bytes, rssi={}, ch={}, {}",
                                        frames_submitted, frame.data.len(), frame.rssi, frame.channel, fc);
                                }
                            }

                            // Submit to FrameGate — gate handles parsing, pcap, distribution
                            let t_submit = std::time::Instant::now();
                            gate.submit(frame);
                            time_in_submit += t_submit.elapsed();

                            frames_submitted += 1;
                        }
                        crate::core::chip::ParsedPacket::DriverMessage(msg) => {
                            // MCU responses go directly to driver — no parsing needed
                            if let Some(ref tx) = rx_handle.driver_msg_tx {
                                let _ = tx.send(msg);
                            }
                        }
                        crate::core::chip::ParsedPacket::TxStatus(txs) => {
                            // TX status report — ACK feedback for injected frames.
                            // Route through driver message channel for now; the driver
                            // can distinguish TXS from MCU responses by pkt_type in DW0.
                            if let Some(ref tx) = rx_handle.driver_msg_tx {
                                let _ = tx.send(txs);
                            }
                        }
                        crate::core::chip::ParsedPacket::Skip => {}
                    }
                }

                // Timing report every 5 seconds
                if last_timing_report.elapsed() >= std::time::Duration::from_secs(5) {
                    if let Some(ref mut log) = log_file {
                        let wall = last_timing_report.elapsed().as_secs_f64();
                        let usb_pct = time_in_usb_read.as_secs_f64() / wall * 100.0;
                        let parse_pct = time_in_parse.as_secs_f64() / wall * 100.0;
                        let submit_pct = time_in_submit.as_secs_f64() / wall * 100.0;
                        let other_pct = 100.0 - usb_pct - parse_pct - submit_pct;
                        let reads_per_sec = usb_reads as f64 / log_start.elapsed().as_secs_f64();
                        let frames_per_sec = frames_submitted as f64 / log_start.elapsed().as_secs_f64();
                        let timeout_pct = if usb_reads + usb_timeouts > 0 {
                            usb_timeouts as f64 / (usb_reads + usb_timeouts) as f64 * 100.0
                        } else { 0.0 };
                        let _ = writeln!(log, "\n═══ TIMING REPORT ({:.1}s wall) ═══", wall);
                        let _ = writeln!(log, "  USB read:  {:>6.1}% ({:.3}s)  — {} reads, {} timeouts ({:.1}% timeout)",
                            usb_pct, time_in_usb_read.as_secs_f64(), usb_reads, usb_timeouts, timeout_pct);
                        let _ = writeln!(log, "  parse_fn:  {:>6.1}% ({:.3}s)  — {} frames extracted",
                            parse_pct, time_in_parse.as_secs_f64(), frames_extracted);
                        let _ = writeln!(log, "  gate sub:  {:>6.1}% ({:.3}s)  — {} frames submitted",
                            submit_pct, time_in_submit.as_secs_f64(), frames_submitted);
                        let _ = writeln!(log, "  other:     {:>6.1}%           — atomics, logging, alive check",
                            other_pct);
                        let _ = writeln!(log, "  RATES: {:.0} reads/s, {:.0} frames/s, {:.3}ms avg/read",
                            reads_per_sec, frames_per_sec,
                            if usb_reads > 0 { time_in_usb_read.as_secs_f64() / usb_reads as f64 * 1000.0 } else { 0.0 });
                        let _ = writeln!(log, "═══════════════════════════════\n");
                        let _ = log.flush();
                    }
                    // Reset timing counters for next window
                    time_in_usb_read = std::time::Duration::ZERO;
                    time_in_parse = std::time::Duration::ZERO;
                    time_in_submit = std::time::Duration::ZERO;
                    last_timing_report = std::time::Instant::now();
                }
            }

            if let Some(ref mut log) = log_file {
                let _ = writeln!(log, "rx-usb exiting. usb_reads={}, usb_bytes={}, extracted={}, submitted={}",
                    usb_reads, usb_bytes, frames_extracted, frames_submitted);
                let _ = log.flush();
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
