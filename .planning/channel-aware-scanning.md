# Plan: Channel-Aware Scanning — Per-Chipset Capabilities

## Problem Statement

The scanner uses hardcoded channel lists, a fixed 5ms channel settle time, and bare `u8` channel numbers throughout the pipeline. This causes:

1. **MT7921AU gets 0 frames on many channels** — firmware PLL retune takes 140-500ms, but settle time is only 5ms. The radio isn't tuned yet when we start dwelling.
2. **RTL8812BU also misses some channels** — 5ms settle is approximately right but marginal.
3. **6GHz never scanned by default** — MT7921AU supports WiFi 6E but `scan_6ghz: false` is hardcoded.
4. **Scanner ignores adapter capabilities** — uses hardcoded lists, never queries `supported_channels()`.
5. **6GHz channel numbers collide with 2.4GHz** — channels 1-13 exist in both bands. The pipeline uses bare `u8`, losing band information.
6. **Channels view has no "6G" band label** — only "2.4G" and "5G".

## Architecture Principle

**The chipset knows its own capabilities. The scanner asks, never assumes.**

When we add a new adapter (RT3572, RTL8812AU, etc.), it implements ChipDriver and reports its capabilities. The scanner, extractor, store, and views adapt automatically. Zero hardcoded adapter-specific logic outside the chip driver files.

---

## Phase 1: ChipDriver Reports Capabilities

### 1A. Add `channel_settle_time()` to ChipDriver trait

**File**: `src/core/chip.rs`

Add to the `ChipDriver` trait (after `supported_channels()`):

```rust
/// Minimum time to wait after set_channel() before the radio is receiving.
/// Accounts for PLL retune, AGC settling, and firmware processing.
/// The scanner sleeps this duration after each channel switch.
///
/// Default: 10ms (conservative for register-based chips).
/// Override for MCU-based chips with longer firmware retune (e.g., MT7921: 200ms).
fn channel_settle_time(&self) -> Duration {
    Duration::from_millis(10)
}
```

### 1B. Override in MT7921AU

**File**: `src/chips/mt7921au.rs` (in the `impl ChipDriver for Mt7921au` block, around line 2795)

```rust
fn channel_settle_time(&self) -> Duration {
    // MT7921AU firmware PLL retune: 140-500ms (measured Session 68).
    // 200ms covers ~95% of retunes. Longer than minimum but ensures
    // we actually receive frames on the channel we switched to.
    Duration::from_millis(200)
}
```

### 1C. Override in RTL8812BU

**File**: `src/chips/rtl8812bu.rs` (in the `impl ChipDriver for Rtl8812bu` block, around line 2130)

```rust
fn channel_settle_time(&self) -> Duration {
    // RTL8812BU: register-based PLL. Hardware re-lock is ~1-2ms.
    // 5ms is conservative and confirmed working.
    Duration::from_millis(5)
}
```

### 1D. Add to other chip drivers (RTL8812AU, MT7612U, RT3572)

Each chip file has an `impl ChipDriver` block. They can use the default (10ms) or override if known. Check each file:
- `src/chips/rtl8812au.rs` — register-based like BU, 5ms is fine
- `src/chips/mt7612u.rs` — MediaTek MCU-based, likely needs 100-200ms (check if similar to MT7921)
- `src/chips/rt3572.rs` — Ralink register-based, 10ms default is fine

### 1E. Add `supported_bands()` convenience method

**File**: `src/core/chip.rs`

Add to ChipDriver trait:

```rust
/// Which bands this adapter supports. Derived from supported_channels().
/// Used by the scanner to auto-enable band scanning.
fn supported_bands(&self) -> Vec<Band> {
    let mut bands = Vec::new();
    for ch in self.supported_channels() {
        if !bands.contains(&ch.band) {
            bands.push(ch.band);
        }
    }
    bands
}
```

This has a default implementation so existing drivers get it for free.

---

## Phase 2: SharedAdapter Exposes Chipset Capabilities

### 2A. Add capability query methods to SharedAdapter

**File**: `src/adapter/shared.rs`

Add methods that query through the adapter mutex:

```rust
/// Get the channel settle time for this adapter's chipset.
pub fn channel_settle_time(&self) -> Duration {
    if self.inner.shut_down.load(Ordering::SeqCst) {
        return Duration::from_millis(10); // fallback
    }
    let adapter = self.inner.adapter.lock().unwrap_or_else(|e| e.into_inner());
    adapter.driver.channel_settle_time()
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
pub fn supported_bands(&self) -> Vec<Band> {
    if self.inner.shut_down.load(Ordering::SeqCst) {
        return Vec::new();
    }
    let adapter = self.inner.adapter.lock().unwrap_or_else(|e| e.into_inner());
    adapter.driver.supported_bands()
}
```

Note: these lock the adapter mutex briefly. They're called once at scan start, not per-frame. Fine.

---

## Phase 3: Scanner Uses Adapter Capabilities

### 3A. Scanner gets settle time from adapter, not config

**File**: `src/scanner/mod.rs`

Change `ScanConfig`:
- Remove `channel_settle: Duration` field (it was hardcoded 5ms)
- The scanner will query `shared.channel_settle_time()` directly

In `Scanner::run()`, replace:
```rust
if !self.config.channel_settle.is_zero() {
    std::thread::sleep(self.config.channel_settle);
}
```
With:
```rust
// Settle time comes from the chipset — each adapter knows its PLL retune time.
let settle = settle_time; // captured before the loop from shared.channel_settle_time()
if !settle.is_zero() {
    std::thread::sleep(settle);
}
```

Capture `settle_time` once before the loop:
```rust
let settle_time = shared.channel_settle_time();
```

### 3B. Scanner builds channel list from adapter capabilities

**File**: `src/scanner/mod.rs`

Change `Scanner::run()` to accept the adapter's supported channels and intersect with the config:

Currently `build_channel_list()` uses hardcoded `CHANNELS_24GHZ`, `CHANNELS_5GHZ`, `CHANNELS_6GHZ`.

New approach — `build_channel_list()` takes the adapter's supported channels:

```rust
fn build_channel_list(&self, adapter_channels: &[Channel]) -> Vec<u8> {
    if let Some(ref custom) = self.config.custom_channels {
        return custom.clone();
    }

    let mut channels = Vec::new();
    for ch in adapter_channels {
        match ch.band {
            Band::Band2g if self.config.scan_2ghz => channels.push(ch.number),
            Band::Band5g if self.config.scan_5ghz => channels.push(ch.number),
            Band::Band6g if self.config.scan_6ghz => channels.push(ch.number),
            _ => {}
        }
    }
    channels
}
```

And in `run()`:
```rust
let adapter_channels = shared.supported_channels();
let channels = self.build_channel_list(&adapter_channels);
```

### 3C. Auto-enable 6GHz when adapter supports it

**File**: `src/cli/commands/scan.rs`

In the `start()` function, after getting the SharedAdapter, check if it supports 6GHz and auto-enable:

```rust
let mut config = parsed_config;
// Auto-enable 6GHz if adapter supports it (unless user explicitly disabled)
let bands = shared.supported_bands();
if bands.contains(&Band::Band6g) && !user_disabled_6ghz {
    config.scan_6ghz = true;
    ctx.layout.print(&format!("  {} 6GHz enabled (adapter supports WiFi 6E)",
        prism::s().cyan().paint("◆")));
}
```

To track "user explicitly disabled", `parse_scan_flags` should return whether `--no-6ghz` was passed (add a `--no-6ghz` flag). If user passes `--no-6ghz`, don't auto-enable. Otherwise, auto-detect.

### 3D. Update ScanConfig default and parse_scan_flags

**File**: `src/scanner/mod.rs`

Remove `channel_settle` from `ScanConfig` (it's now per-adapter from ChipDriver).

**File**: `src/cli/commands/scan.rs`

Add `--no-6ghz` flag to `parse_scan_flags()`. Return a struct or tuple that includes `user_disabled_6ghz: bool`.

### 3E. Update all tests referencing channel_settle in ScanConfig

**Files**: `src/scanner/mod.rs` tests, `src/cli/commands/scan.rs` tests

Remove assertions about `channel_settle` from ScanConfig tests. The settle time is no longer a config field.

---

## Phase 4: Fix Channel Number Collision (u8 → Band-Aware)

### 4A. Change FrameStore current_channel to include band

**File**: `src/store/mod.rs`

Currently:
```rust
current_channel: AtomicU8,
```

Change to store both channel and band. Options:
- Pack into AtomicU16: `(band as u8) << 8 | channel` — simple, atomic
- Or keep AtomicU8 for channel + separate AtomicU8 for band

Recommended: Add `current_band: AtomicU8` alongside `current_channel: AtomicU8`:
```rust
current_channel: AtomicU8,
current_band: AtomicU8,  // 0=2.4G, 1=5G, 2=6G
```

Add `set_current_channel_band(ch: u8, band: Band)` and `current_band() -> u8`.

### 4B. Scanner sets band when hopping

**File**: `src/scanner/mod.rs`

When the scanner switches channels, it now needs to set both channel and band on the store. Since we have the full `Channel` struct from `adapter_channels`, we can look up the band:

```rust
store.set_current_channel(ch);
store.set_current_band(band_for_channel(ch, &adapter_channels));
```

Or better: change the scanner to work with `Channel` structs instead of `u8`:
```rust
fn build_channel_list(&self, adapter_channels: &[Channel]) -> Vec<Channel> { ... }
```

Then in the loop:
```rust
for ch in &channels {
    shared.set_channel(ch.number)?;  // or pass the full Channel
    store.set_current_channel(ch.number);
    store.set_current_band(ch.band);
}
```

### 4C. Extractor receives band information

**File**: `src/pipeline/extractor.rs`

Currently: `process_frame(pf, channel: u8, store)` — no band info.

The extractor is called from the pipeline thread, which gets frames from the FrameGate. The frame's channel comes from `RxFrame.channel` (set by the RX thread from `current_channel`). We need the band too.

Options:
1. Add `band: u8` to `RxFrame` struct
2. Read `current_band` from FrameStore atomically (same as channel)
3. Derive band from channel number using a lookup (won't work for 6GHz collision)

Recommended: Option 2 — the pipeline thread reads `store.current_band()` alongside `store.current_channel()` when processing each frame. Actually, the pipeline thread already has the `store` reference. The channel is on the `RxFrame` (set by RX thread). We need to add band to `RxFrame` too.

**File**: `src/core/frame.rs`

Add `band: u8` field to `RxFrame`:
```rust
pub struct RxFrame {
    pub data: Vec<u8>,
    pub rssi: i8,
    pub channel: u8,
    pub band: u8,      // 0=2.4G, 1=5G, 2=6G
    pub timestamp: Duration,
}
```

**File**: `src/adapter/shared.rs` — RX thread

The RX thread sets `frame.channel = inner.current_channel.load()`. Add: `frame.band = inner.current_band.load()`. (Requires adding `current_band: AtomicU8` to SharedAdapterInner.)

Wait — actually, the RX thread currently doesn't set the channel on the frame. Let me check... The chip's `parse_fn` returns the frame with channel from the RX descriptor. Let me verify this is correct.

Actually, looking at the RX thread code more carefully: the channel is read from `inner.current_channel` and passed to `parse_fn`. The parse_fn puts it on the frame. So the pipeline gets it from there.

For band: add `current_band: AtomicU8` to `SharedAdapterInner`, set it alongside `current_channel` in `set_channel()`, and read it in the RX thread to pass to parse_fn or set on the frame.

### 4D. ChannelStats becomes band-aware

**File**: `src/store/stats.rs`

`ChannelStats::new()` currently:
```rust
band: if channel <= 14 { 0 } else { 1 },
```

Change to accept band:
```rust
pub(crate) fn new(channel: u8, band: u8) -> Self {
    Self { channel, band, ... }
}
```

**File**: `src/pipeline/extractor.rs`

Where we create ChannelStats entries:
```rust
let cs = stats.entry(channel)
    .or_insert_with(|| ChannelStats::new(channel, band));
```

The `band` comes from the frame or store.

### 4E. ChannelStats key becomes (channel, band) or channel stays u8

Since 6GHz channels 1-13 collide with 2.4GHz, the HashMap key `u8` won't work for 6GHz.

Option A: Change key to `(u8, u8)` (channel, band) — most correct, but changes many signatures.

Option B: Change key to `u16` — pack `(band << 8) | channel`. Simple, backwards compatible key type.

Option C: Use a unique channel ID — e.g., 6GHz channel 1 becomes 201, channel 5 becomes 205, etc. Offset by 200.

**Recommended: Option B** — `u16` key where high byte is band, low byte is channel number.

```rust
fn channel_key(channel: u8, band: u8) -> u16 {
    (band as u16) << 8 | channel as u16
}
```

Change `HashMap<u8, ChannelStats>` to `HashMap<u16, ChannelStats>` in FrameStore.

Update all callers:
- `src/store/mod.rs`: `channel_stats: RwLock<HashMap<u16, ChannelStats>>`
- `src/pipeline/extractor.rs`: use `channel_key(channel, band)` for lookups
- `src/scanner/mod.rs`: use `channel_key()` for start_dwell/end_dwell
- `src/cli/scanner/mod.rs`: snapshot collection
- `src/cli/scanner/views.rs`: channel overlay loop

### 4F. ChannelEntry band label includes 6GHz

**File**: `src/cli/scanner/views.rs`

```rust
impl ChannelEntry {
    fn new(channel: u8, band: u8) -> Self {
        Self {
            channel,
            band: match band {
                0 => "2.4G",
                1 => "5G",
                2 => "6G",
                _ => "?",
            },
            ...
        }
    }
}
```

---

## Phase 5: SharedAdapter Tracks Band

### 5A. Add current_band to SharedAdapterInner

**File**: `src/adapter/shared.rs`

```rust
struct SharedAdapterInner {
    ...
    current_channel: AtomicU8,
    current_band: AtomicU8,  // 0=2.4G, 1=5G, 2=6G
    ...
}
```

Initialize to 0 in `spawn()`.

### 5B. Update set_channel to store band

**File**: `src/adapter/shared.rs`

`set_channel()` currently takes `channel: u8`. It needs the band too. Change signature to:

```rust
pub fn set_channel_full(&self, channel: Channel) -> Result<()> {
    let locked = self.locked_channel();
    if locked != NO_CHANNEL_LOCK && locked != channel.number {
        return Ok(());
    }
    self.inner.current_channel.store(channel.number, Ordering::SeqCst);
    self.inner.current_band.store(channel.band as u8, Ordering::SeqCst);
    self.with_adapter(|adapter| {
        adapter.driver.set_channel(channel)
    })
}
```

Keep the old `set_channel(u8)` as a convenience that creates `Channel::new(ch)` (works for 2.4/5GHz). Add `set_channel_6ghz(u8)` or prefer `set_channel_full(Channel)` everywhere.

Better: just change `set_channel` to take `Channel`:
```rust
pub fn set_channel(&self, channel: Channel) -> Result<()> { ... }
```

Update all callers (scanner, attacks) to pass `Channel` instead of `u8`.

---

## Phase 6: Verify and Test

### 6A. Update existing tests

- `src/scanner/mod.rs` tests: update `build_channel_list` tests to pass adapter_channels
- `src/store/stats.rs` tests: update ChannelStats::new calls with band
- `src/pipeline/extractor.rs`: if there are tests using channel stats, update keys
- `src/cli/commands/scan.rs` tests: remove channel_settle assertions, add 6ghz auto-detect

### 6B. Add new tests

- Test that MT7921 `channel_settle_time()` returns 200ms
- Test that RTL8812BU `channel_settle_time()` returns 5ms
- Test that `supported_bands()` includes Band6g for MT7921
- Test that `channel_key()` correctly distinguishes 2.4GHz ch1 from 6GHz ch1
- Test that ChannelEntry shows "6G" for band=2

---

## File Change Summary

| File | Changes |
|------|---------|
| `src/core/chip.rs` | Add `channel_settle_time()`, `supported_bands()` to ChipDriver |
| `src/core/frame.rs` | Add `band: u8` to RxFrame |
| `src/core/channel.rs` | No changes needed (already has Band enum + new_6ghz) |
| `src/chips/mt7921au.rs` | Override `channel_settle_time()` → 200ms |
| `src/chips/rtl8812bu.rs` | Override `channel_settle_time()` → 5ms |
| `src/chips/rtl8812au.rs` | Override `channel_settle_time()` → 5ms (register-based) |
| `src/chips/mt7612u.rs` | Override `channel_settle_time()` → 150ms (MCU-based, verify) |
| `src/chips/rt3572.rs` | Use default 10ms or override if known |
| `src/adapter/shared.rs` | Add `current_band`, `set_channel(Channel)`, capability queries |
| `src/scanner/mod.rs` | Remove channel_settle from config, use adapter settle time, build_channel_list from adapter channels |
| `src/store/mod.rs` | Change channel_stats key to u16, add current_band atomic |
| `src/store/stats.rs` | ChannelStats::new takes band, add channel_key() helper |
| `src/pipeline/mod.rs` | Pass band to extractor (from RxFrame or store) |
| `src/pipeline/extractor.rs` | Use channel_key for stats, pass band to ChannelStats::new |
| `src/cli/commands/scan.rs` | Auto-enable 6GHz, remove channel_settle from config, add --no-6ghz |
| `src/cli/scanner/mod.rs` | Snapshot includes band-aware channel stats |
| `src/cli/scanner/views.rs` | ChannelEntry::new takes band, "6G" label |

## Implementation Order

1. **Phase 1** (ChipDriver) — pure additions, nothing breaks
2. **Phase 5** (SharedAdapter band tracking) — add the atoms, update set_channel
3. **Phase 2** (SharedAdapter capability queries) — expose to consumers
4. **Phase 4D-4F** (ChannelStats + ChannelEntry band-aware) — store layer
5. **Phase 4C** (Extractor band-aware) — pipeline layer
6. **Phase 3** (Scanner uses capabilities) — scanner layer
7. **Phase 6** (Tests) — verify everything

Each phase compiles and tests pass before moving to the next.

---

## What This Enables

After this plan:
- `/scan` on MT7921 auto-enables 6GHz, uses 200ms settle → real frames on every channel
- `/scan` on RTL8812BU uses 5ms settle → fast hopping, still catches everything
- Channels view shows "2.4G", "5G", "6G" correctly
- 6GHz channel 1 and 2.4GHz channel 1 are separate rows in the table
- Adding a new adapter = implement ChipDriver, everything else works
- No hardcoded channel lists or settle times outside chip drivers

## Changes Already Made This Session (DO NOT REDO)

These are already in the codebase and should NOT be reimplemented:

1. **stop_rx() / start_rx() on SharedAdapter** (`src/adapter/shared.rs`) — RX thread lifecycle with JoinHandle, alive/shut_down flags
2. **Centralized in AdapterManager** (`src/adapter/mod.rs`) — assign_role calls start_rx, clear_role calls stop_rx when no roles remain
3. **Extractor creates ChannelStats entries** (`src/pipeline/extractor.rs`) — changed get_mut to entry().or_insert_with()
4. **Scanner calls start_dwell/end_dwell** (`src/scanner/mod.rs`) — tracks per-channel FPS at hop boundaries
