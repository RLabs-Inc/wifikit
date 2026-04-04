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
use crate::core::channel::{Band, Channel};
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

    /// Active scan — send probe requests on each channel. Default: true.
    /// Use --passive for stealth mode (no TX, receive only).
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
            dwell_time: Duration::from_millis(500),
            num_rounds: 0,
            scan_2ghz: true,
            scan_5ghz: true,
            scan_6ghz: false,
            active: true,
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

    /// Build the channel list from adapter capabilities + config filters.
    ///
    /// Returns full Channel structs (with band info) so the scanner knows
    /// the exact band for each channel — critical for 6GHz where channel
    /// numbers collide with 2.4GHz.
    ///
    /// If adapter_channels is provided, use the adapter's own channel list
    /// filtered by the config's band flags. Otherwise, fall back to hardcoded lists.
    /// Custom channels override everything.
    fn build_channel_list(&self, adapter_channels: Option<&[Channel]>) -> Vec<Channel> {
        if let Some(ref custom) = self.config.custom_channels {
            return custom.iter().map(|&ch| Channel::new(ch)).collect();
        }

        // If the adapter reports its channels, use those (filtered by band config).
        if let Some(adapter_chs) = adapter_channels {
            let mut channels = Vec::new();
            for ch in adapter_chs {
                match ch.band {
                    Band::Band2g if self.config.scan_2ghz => channels.push(*ch),
                    Band::Band5g if self.config.scan_5ghz => channels.push(*ch),
                    Band::Band6g if self.config.scan_6ghz => channels.push(*ch),
                    _ => {}
                }
            }
            return channels;
        }

        // Fallback: hardcoded lists (no adapter available).
        let mut channels = Vec::with_capacity(
            CHANNELS_24GHZ.len() + CHANNELS_5GHZ.len() + CHANNELS_6GHZ.len(),
        );

        if self.config.scan_2ghz {
            for &ch in CHANNELS_24GHZ {
                channels.push(Channel::new(ch));
            }
        }
        if self.config.scan_5ghz {
            for &ch in CHANNELS_5GHZ {
                channels.push(Channel::new(ch));
            }
        }
        if self.config.scan_6ghz {
            for &ch in CHANNELS_6GHZ {
                channels.push(Channel::new_6ghz(ch));
            }
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
        // Query adapter for its capabilities — channels and settle time.
        let adapter_channels = shared.supported_channels();
        let settle_time = shared.channel_settle_time();
        let channels = self.build_channel_list(
            if adapter_channels.is_empty() { None } else { Some(&adapter_channels) }
        );
        if channels.is_empty() {
            return;
        }

        self.running.store(true, Ordering::SeqCst);
        self.round.store(0, Ordering::SeqCst);
        store.set_round(0);

        // Clear stale channel stats from any previous scan (different adapter
        // may have scanned different channels — e.g., MT7921 6GHz entries
        // would persist when switching to RTL8812BU).
        store.clear_channel_stats();

        let mac = shared.mac();

        // Track the previous channel's band for proper end_dwell keying.
        let mut prev_band_idx: u8 = 0;

        'outer: loop {
            for ch in &channels {
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

                // Band index from the Channel struct (correct for 6GHz).
                let band_idx = match ch.band {
                    Band::Band2g => 0u8,
                    Band::Band5g => 1,
                    Band::Band6g => 2,
                };

                // End dwell on previous channel (if any) before switching.
                // This calculates per-channel FPS for the channel we're leaving.
                {
                    let prev_ch = self.current_channel.load(Ordering::SeqCst);
                    if prev_ch != 0 {
                        let prev_key = crate::store::stats::channel_key(prev_ch, prev_band_idx);
                        store.with_channel_stats_mut(|stats| {
                            if let Some(cs) = stats.get_mut(&prev_key) {
                                cs.end_dwell();
                            }
                        });
                    }
                }

                // Switch channel — use full Channel struct for proper 6GHz handling.
                if let Err(_e) = shared.set_channel_full(*ch) {
                    // Channel not supported by this adapter — skip silently.
                    continue;
                }
                self.current_channel.store(ch.number, Ordering::SeqCst);
                store.set_current_channel(ch.number);
                prev_band_idx = band_idx;

                // Start dwell tracking on the new channel.
                // Create the entry if it doesn't exist yet — this ensures
                // frame_count_at_dwell_start is set BEFORE frames arrive,
                // so FPS is accurate from the very first round.
                let key = crate::store::stats::channel_key(ch.number, band_idx);
                store.with_channel_stats_mut(|stats| {
                    stats.entry(key)
                        .or_insert_with(|| crate::store::stats::ChannelStats::new(ch.number, band_idx))
                        .start_dwell();
                });

                // Wait for PHY to stabilize after channel switch.
                // Settle time comes from the chipset — each adapter knows its PLL retune time.
                if !settle_time.is_zero() {
                    std::thread::sleep(settle_time);
                }

                // Active scan: send broadcast probe request at START of dwell.
                // IEEE 802.11 §11.1.4: probe request → wait → collect responses.
                // APs respond in 1-5ms, so the entire dwell window captures responses
                // plus beacons plus STA data. This is how every real scanner works —
                // probes at the start, collect everything during dwell.
                if self.config.active {
                    if let Some(probe) = frames::build_probe_request(&mac, "", &[]) {
                        let opts = TxOptions {
                            retries: 1,
                            ..Default::default()
                        };
                        let _ = shared.tx_frame(&probe, &opts);
                    }
                }

                // Dwell on this channel — collect probe responses + beacons + data.
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
        assert_eq!(cfg.dwell_time, Duration::from_millis(500));
        assert_eq!(cfg.num_rounds, 0);
        assert!(cfg.scan_2ghz);
        assert!(cfg.scan_5ghz);
        assert!(!cfg.scan_6ghz);
        assert!(cfg.active);
        assert!(cfg.custom_channels.is_none());
        assert_eq!(cfg.channel_settle, Duration::from_millis(5)); // still in config for backward compat
    }

    #[test]
    fn test_build_channel_list_default() {
        let scanner = Scanner::new(ScanConfig::default());
        let channels = scanner.build_channel_list(None);
        let nums: Vec<u8> = channels.iter().map(|c| c.number).collect();
        // 13 (2.4GHz) + 25 (5GHz) = 38
        assert_eq!(nums.len(), 38);
        assert_eq!(nums[0], 1);
        assert_eq!(nums[12], 13);
        assert_eq!(nums[13], 36);
        assert_eq!(nums[37], 165);
    }

    #[test]
    fn test_build_channel_list_2ghz_only() {
        let scanner = Scanner::new(ScanConfig {
            scan_5ghz: false,
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list(None);
        let nums: Vec<u8> = channels.iter().map(|c| c.number).collect();
        assert_eq!(nums.len(), 13);
        assert_eq!(nums[0], 1);
        assert_eq!(nums[12], 13);
    }

    #[test]
    fn test_build_channel_list_5ghz_only() {
        let scanner = Scanner::new(ScanConfig {
            scan_2ghz: false,
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list(None);
        let nums: Vec<u8> = channels.iter().map(|c| c.number).collect();
        assert_eq!(nums.len(), 25);
        assert_eq!(nums[0], 36);
        assert_eq!(nums[24], 165);
    }

    #[test]
    fn test_build_channel_list_with_6ghz() {
        let scanner = Scanner::new(ScanConfig {
            scan_6ghz: true,
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list(None);
        // 13 + 25 + 59 = 97
        assert_eq!(channels.len(), 97);
        // Verify 6GHz channels have correct band
        let last = channels.last().unwrap();
        assert_eq!(last.number, 233);
        assert_eq!(last.band, Band::Band6g);
    }

    #[test]
    fn test_build_channel_list_custom() {
        let scanner = Scanner::new(ScanConfig {
            custom_channels: Some(vec![1, 6, 11, 36, 149]),
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list(None);
        let nums: Vec<u8> = channels.iter().map(|c| c.number).collect();
        assert_eq!(nums, vec![1, 6, 11, 36, 149]);
    }

    #[test]
    fn test_build_channel_list_none_enabled() {
        let scanner = Scanner::new(ScanConfig {
            scan_2ghz: false,
            scan_5ghz: false,
            scan_6ghz: false,
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list(None);
        assert!(channels.is_empty());
    }

    #[test]
    fn test_build_channel_list_adapter_6ghz_labeled_correctly() {
        // Simulate an adapter that supports 6GHz
        let adapter_channels = vec![
            Channel::new(1),          // 2.4GHz ch1
            Channel::new(36),         // 5GHz ch36
            Channel::new_6ghz(1),     // 6GHz ch1
            Channel::new_6ghz(5),     // 6GHz ch5
        ];
        let scanner = Scanner::new(ScanConfig {
            scan_6ghz: true,
            ..ScanConfig::default()
        });
        let channels = scanner.build_channel_list(Some(&adapter_channels));
        assert_eq!(channels.len(), 4);
        assert_eq!(channels[0].band, Band::Band2g);
        assert_eq!(channels[1].band, Band::Band5g);
        assert_eq!(channels[2].band, Band::Band6g);
        assert_eq!(channels[2].number, 1); // 6GHz ch1, distinct from 2.4GHz ch1
        assert_eq!(channels[3].band, Band::Band6g);
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
