//! Scanner — slim channel hopper for adapter management.
//!
//! The scanner does ONE thing well: cycle through WiFi channels on an adapter.
//! It does NOT process frames, own data stores, or track APs/stations.
//!
//! Frame processing: FrameGate / extractors (via pipeline subscribers)
//! Data storage: FrameStore
//! AP/station tracking: FrameStore
//!
//! The scanner's `run()` method blocks until stopped. The CLI spawns it on a
//! dedicated thread and calls `stop()` to terminate.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::adapter::SharedAdapter;
use crate::core::TxOptions;
use crate::protocol::frames;
use crate::store::FrameStore;

// ═══════════════════════════════════════════════════════════════════════════════
//  Channel lists for hopping
// ═══════════════════════════════════════════════════════════════════════════════

pub const CHANNELS_24GHZ: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

pub const CHANNELS_5GHZ: &[u8] = &[
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165,
];

/// WiFi 6E UNII-5 through UNII-8 (requires 6 GHz capable adapter).
pub const CHANNELS_6GHZ: &[u8] = &[
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69,
    73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 129,
    133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185,
    189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233,
];

// ═══════════════════════════════════════════════════════════════════════════════
//  Scan configuration
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Dwell time per channel. Default: 300ms.
    pub dwell_time: Duration,

    /// Number of scan rounds (0 = infinite). Default: 0.
    pub num_rounds: u32,

    /// Scan 2.4 GHz channels (1-13). Default: true.
    pub scan_2ghz: bool,

    /// Scan 5 GHz channels (36-165). Default: true.
    pub scan_5ghz: bool,

    /// Scan 6 GHz channels (WiFi 6E, requires capable adapter). Default: false.
    pub scan_6ghz: bool,

    /// Active scan — send probe requests on each channel. Default: false (passive).
    pub active: bool,

    /// Override default channel list. None = use defaults for enabled bands.
    pub custom_channels: Option<Vec<u8>>,

    /// Channel settle time after switching — wait for PHY to stabilize.
    /// Default: 5ms.
    pub channel_settle: Duration,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            dwell_time: Duration::from_millis(300),
            num_rounds: 0,
            scan_2ghz: true,
            scan_5ghz: true,
            scan_6ghz: false,
            active: false,
            custom_channels: None,
            channel_settle: Duration::from_millis(5),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Scanner
// ═══════════════════════════════════════════════════════════════════════════════

/// Slim channel hopper. Manages channel cycling for one adapter.
///
/// Does NOT process frames or own any data. Just hops channels, optionally
/// sends probe requests, and tracks scan rounds.
///
/// Usage:
/// ```ignore
/// let scanner = Scanner::new(ScanConfig::default());
/// let scanner_clone = scanner.clone();
/// let shared_clone = shared.clone();
/// std::thread::spawn(move || scanner_clone.run(&shared_clone));
/// // ... later ...
/// scanner.stop();
/// ```
pub struct Scanner {
    config: ScanConfig,
    running: Arc<AtomicBool>,
    current_channel: Arc<AtomicU8>,
    round: Arc<AtomicU32>,
}

impl Clone for Scanner {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            running: Arc::clone(&self.running),
            current_channel: Arc::clone(&self.current_channel),
            round: Arc::clone(&self.round),
        }
    }
}

impl Scanner {
    /// Create a new scanner with the given configuration.
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            current_channel: Arc::new(AtomicU8::new(0)),
            round: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Build the channel list from config (band flags + custom override).
    fn build_channel_list(&self) -> Vec<u8> {
        if let Some(ref custom) = self.config.custom_channels {
            return custom.clone();
        }

        let mut channels = Vec::with_capacity(
            CHANNELS_24GHZ.len() + CHANNELS_5GHZ.len() + CHANNELS_6GHZ.len(),
        );

        if self.config.scan_2ghz {
            channels.extend_from_slice(CHANNELS_24GHZ);
        }
        if self.config.scan_5ghz {
            channels.extend_from_slice(CHANNELS_5GHZ);
        }
        if self.config.scan_6ghz {
            channels.extend_from_slice(CHANNELS_6GHZ);
        }

        channels
    }

    /// Main scan loop. Blocks until `stop()` is called or `num_rounds` is reached.
    ///
    /// For each channel in the list:
    /// 1. Check if channel is locked by an attack — if so, skip (stay on locked channel)
    /// 2. Switch adapter to the channel
    /// 3. Wait for PHY to settle
    /// 4. If active scan: send a broadcast probe request
    /// 5. Dwell for `dwell_time`
    /// 6. Check running flag
    ///
    /// After completing all channels, increment the round counter.
    pub fn run(&self, shared: &SharedAdapter, store: &FrameStore) {
        let channels = self.build_channel_list();
        if channels.is_empty() {
            return;
        }

        self.running.store(true, Ordering::SeqCst);
        self.round.store(0, Ordering::SeqCst);

        let mac = shared.mac();

        'outer: loop {
            for &ch in &channels {
                if !self.running.load(Ordering::SeqCst) {
                    break 'outer;
                }

                // If an attack has locked a channel, skip hopping — stay on locked channel.
                let locked = shared.locked_channel();
                if locked != 0 {
                    // Dwell on the locked channel without switching.
                    self.current_channel.store(locked, Ordering::SeqCst);
                    store.set_current_channel(locked);
                    self.dwell();
                    continue;
                }

                // Switch channel.
                if let Err(_e) = shared.set_channel(ch) {
                    // Channel not supported by this adapter — skip silently.
                    continue;
                }
                self.current_channel.store(ch, Ordering::SeqCst);
                store.set_current_channel(ch);

                // Wait for PHY to stabilize after channel switch.
                if !self.config.channel_settle.is_zero() {
                    std::thread::sleep(self.config.channel_settle);
                }

                // Active scan: send broadcast probe request.
                if self.config.active {
                    if let Some(probe) = frames::build_probe_request(&mac, "", &[]) {
                        let opts = TxOptions::default();
                        let _ = shared.tx_frame(&probe, &opts);
                    }
                }

                // Dwell on this channel.
                self.dwell();
            }

            // Completed one full round through all channels.
            let completed = self.round.fetch_add(1, Ordering::SeqCst) + 1;
            store.set_round(completed);

            // Check round limit (0 = infinite).
            if self.config.num_rounds > 0 && completed >= self.config.num_rounds {
                break;
            }
        }

        self.running.store(false, Ordering::SeqCst);
    }

    /// Dwell on the current channel for `dwell_time`, checking the running flag
    /// periodically so we can respond to stop signals promptly.
    fn dwell(&self) {
        // Sleep in small slices so stop() is responsive (max 50ms per slice).
        let total = self.config.dwell_time;
        let slice = Duration::from_millis(50);
        let mut remaining = total;

        while remaining > Duration::ZERO {
            if !self.running.load(Ordering::SeqCst) {
                return;
            }
            let sleep_for = remaining.min(slice);
            std::thread::sleep(sleep_for);
            remaining = remaining.saturating_sub(sleep_for);
        }
    }

    /// Signal the scanner to stop. Non-blocking — sets an AtomicBool.
    /// The scan loop will exit within one dwell slice (~50ms).
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the scanner is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get the channel the scanner is currently dwelling on.
    /// Returns 0 if the scanner hasn't started yet.
    pub fn current_channel(&self) -> u8 {
        self.current_channel.load(Ordering::SeqCst)
    }

    /// Get the number of completed scan rounds.
    pub fn round(&self) -> u32 {
        self.round.load(Ordering::SeqCst)
    }

    /// Get a reference to the scan configuration.
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        let cfg = ScanConfig::default();
        assert_eq!(cfg.dwell_time, Duration::from_millis(300));
        assert_eq!(cfg.num_rounds, 0);
        assert!(cfg.scan_2ghz);
        assert!(cfg.scan_5ghz);
        assert!(!cfg.scan_6ghz);
        assert!(!cfg.active);
        assert!(cfg.custom_channels.is_none());
        assert_eq!(cfg.channel_settle, Duration::from_millis(5));
    }

    #[test]
    fn test_build_channel_list_default() {
        let scanner = Scanner::new(ScanConfig::default());
        let channels = scanner.build_channel_list();
        // 13 (2.4GHz) + 25 (5GHz) = 38
        assert_eq!(channels.len(), 38);
        assert_eq!(channels[0], 1);
        assert_eq!(channels[12], 13);
        assert_eq!(channels[13], 36);
        assert_eq!(channels[37], 165);
    }

    #[test]
    fn test_build_channel_list_2ghz_only() {
        let scanner = Scanner::new(ScanConfig {
            scan_5ghz: false,
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list();
        assert_eq!(channels.len(), 13);
        assert_eq!(channels[0], 1);
        assert_eq!(channels[12], 13);
    }

    #[test]
    fn test_build_channel_list_5ghz_only() {
        let scanner = Scanner::new(ScanConfig {
            scan_2ghz: false,
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list();
        assert_eq!(channels.len(), 25);
        assert_eq!(channels[0], 36);
        assert_eq!(channels[24], 165);
    }

    #[test]
    fn test_build_channel_list_with_6ghz() {
        let scanner = Scanner::new(ScanConfig {
            scan_6ghz: true,
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list();
        // 13 + 25 + 59 = 97
        assert_eq!(channels.len(), 97);
    }

    #[test]
    fn test_build_channel_list_custom() {
        let scanner = Scanner::new(ScanConfig {
            custom_channels: Some(vec![1, 6, 11, 36, 149]),
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list();
        assert_eq!(channels, vec![1, 6, 11, 36, 149]);
    }

    #[test]
    fn test_build_channel_list_none_enabled() {
        let scanner = Scanner::new(ScanConfig {
            scan_2ghz: false,
            scan_5ghz: false,
            scan_6ghz: false,
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list();
        assert!(channels.is_empty());
    }

    #[test]
    fn test_scanner_initial_state() {
        let scanner = Scanner::new(ScanConfig::default());
        assert!(!scanner.is_running());
        assert_eq!(scanner.current_channel(), 0);
        assert_eq!(scanner.round(), 0);
    }

    #[test]
    fn test_scanner_stop_before_start() {
        let scanner = Scanner::new(ScanConfig::default());
        scanner.stop(); // should not panic
        assert!(!scanner.is_running());
    }

    #[test]
    fn test_scanner_clone_shares_state() {
        let scanner = Scanner::new(ScanConfig::default());
        let clone = scanner.clone();

        // Shared atomics — writing through one is visible from the other.
        scanner.running.store(true, Ordering::SeqCst);
        assert!(clone.is_running());

        clone.stop();
        assert!(!scanner.is_running());
    }

    #[test]
    fn test_channel_lists_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &ch in CHANNELS_24GHZ {
            assert!(seen.insert(ch), "duplicate 2.4GHz channel: {}", ch);
        }

        seen.clear();
        for &ch in CHANNELS_5GHZ {
            assert!(seen.insert(ch), "duplicate 5GHz channel: {}", ch);
        }

        seen.clear();
        for &ch in CHANNELS_6GHZ {
            assert!(seen.insert(ch), "duplicate 6GHz channel: {}", ch);
        }
    }

    #[test]
    fn test_channel_lists_sorted() {
        for pair in CHANNELS_24GHZ.windows(2) {
            assert!(pair[0] < pair[1], "2.4GHz not sorted: {} >= {}", pair[0], pair[1]);
        }
        for pair in CHANNELS_5GHZ.windows(2) {
            assert!(pair[0] < pair[1], "5GHz not sorted: {} >= {}", pair[0], pair[1]);
        }
        for pair in CHANNELS_6GHZ.windows(2) {
            assert!(pair[0] < pair[1], "6GHz not sorted: {} >= {}", pair[0], pair[1]);
        }
    }
}
