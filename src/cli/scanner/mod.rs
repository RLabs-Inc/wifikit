//! Scanner module — the interactive scanner experience in the wifikit shell.
//!
//! Integrates with the shell's Layout active zone to provide:
//! - 6 scan-level views (APs, Clients, Probes, Channels, Events, Handshakes)
//! - 9 AP detail tabs (Overview, Security, Radio, Clients, Probes, Features, Timing, Attack Surface, IEs)
#![allow(dead_code)]
#![allow(unused_imports)]
//! - 6 Client detail tabs (Overview, Fingerprint, Probes, Sequences, Activity, Raw)
//! - Column toggles, sorting, filtering, j/k scrolling, Enter/Esc drill-in/out

pub mod style;
pub mod views;
pub mod detail;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use crate::core::MacAddress;
use crate::pipeline::subscriber::UpdateSubscriber;
use crate::scanner::Scanner;
use crate::store::{
    Ap, ChannelStats, FrameStore, ProbeReq, ScanEvent, ScanStats, Station, WpsState,
};
use crate::store::update::StoreUpdate;
use crate::protocol::ieee80211::{Security, WifiGeneration};

// ═══════════════════════════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanView {
    Aps,
    Clients,
    Probes,
    Channels,
    Events,
    Handshakes,
}

impl ScanView {
    pub const ALL: &[ScanView] = &[
        ScanView::Aps,
        ScanView::Clients,
        ScanView::Probes,
        ScanView::Channels,
        ScanView::Events,
        ScanView::Handshakes,
    ];

    pub fn next(self) -> Self {
        match self {
            Self::Aps => Self::Clients,
            Self::Clients => Self::Probes,
            Self::Probes => Self::Channels,
            Self::Channels => Self::Events,
            Self::Events => Self::Handshakes,
            Self::Handshakes => Self::Aps,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Aps => Self::Handshakes,
            Self::Clients => Self::Aps,
            Self::Probes => Self::Clients,
            Self::Channels => Self::Probes,
            Self::Events => Self::Channels,
            Self::Handshakes => Self::Events,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aps => "APs",
            Self::Clients => "Clients",
            Self::Probes => "Probes",
            Self::Channels => "Channels",
            Self::Events => "Events",
            Self::Handshakes => "Handshakes",
        }
    }
}

#[derive(Debug, Clone)]
pub enum DetailState {
    None,
    Ap { bssid: MacAddress, tab: u8 },
    Client { mac: MacAddress, tab: u8 },
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Sort — field selection for AP table ordering
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Rssi,       // default — strongest first
    Channel,
    Security,
    Ssid,
    Clients,
    WifiGen,
    FirstSeen,
}

impl SortField {
    pub const ALL: &[SortField] = &[
        SortField::Rssi,
        SortField::Channel,
        SortField::Security,
        SortField::Ssid,
        SortField::Clients,
        SortField::WifiGen,
        SortField::FirstSeen,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Rssi => "RSSI (signal strength)",
            Self::Channel => "Channel",
            Self::Security => "Security",
            Self::Ssid => "SSID",
            Self::Clients => "Clients",
            Self::WifiGen => "WiFi Gen",
            Self::FirstSeen => "First Seen",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|f| *f == self).unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Filter — AP table filtering criteria
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterBand {
    Band2g,
    Band5g,
}

impl FilterBand {
    pub fn label(self) -> &'static str {
        match self {
            Self::Band2g => "2.4 GHz",
            Self::Band5g => "5 GHz",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanFilter {
    pub band: Option<FilterBand>,
    pub security: Option<Security>,
    pub wps_only: bool,
    pub hidden_only: bool,
    pub wifi_gen: Option<WifiGeneration>,
    pub min_clients: u16,
}

impl ScanFilter {
    /// Returns true if the AP passes all active filters.
    pub fn matches(&self, ap: &Ap) -> bool {
        if let Some(band) = self.band {
            match band {
                FilterBand::Band2g => { if ap.channel > 14 { return false; } }
                FilterBand::Band5g => { if ap.channel <= 14 { return false; } }
            }
        }
        if let Some(sec) = self.security {
            if ap.security != sec { return false; }
        }
        if self.wps_only && ap.wps_state == WpsState::None {
            return false;
        }
        if self.hidden_only && !ap.is_hidden {
            return false;
        }
        if let Some(wifi_gen) = self.wifi_gen {
            if ap.wifi_gen != wifi_gen { return false; }
        }
        if self.min_clients > 0 && ap.client_count < self.min_clients {
            return false;
        }
        true
    }

    /// Count of active filter criteria (for badge display).
    pub fn active_count(&self) -> usize {
        let mut n = 0;
        if self.band.is_some() { n += 1; }
        if self.security.is_some() { n += 1; }
        if self.wps_only { n += 1; }
        if self.hidden_only { n += 1; }
        if self.wifi_gen.is_some() { n += 1; }
        if self.min_clients > 0 { n += 1; }
        n
    }
}

/// Which row is highlighted in the filter menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMenuItem {
    Band,
    Security,
    WpsOnly,
    HiddenOnly,
    WifiGen,
    MinClients,
}

impl FilterMenuItem {
    pub const ALL: &[FilterMenuItem] = &[
        FilterMenuItem::Band,
        FilterMenuItem::Security,
        FilterMenuItem::WpsOnly,
        FilterMenuItem::HiddenOnly,
        FilterMenuItem::WifiGen,
        FilterMenuItem::MinClients,
    ];

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|f| *f == self).unwrap_or(0)
    }
}

/// Sort APs in place by the given field and direction.
pub fn sort_aps(aps: &mut [Ap], field: SortField, ascending: bool) {
    aps.sort_by(|a, b| {
        let ord = match field {
            SortField::Rssi => a.rssi.cmp(&b.rssi),
            SortField::Channel => a.channel.cmp(&b.channel),
            SortField::Security => a.security.cmp(&b.security),
            SortField::Ssid => a.ssid.to_lowercase().cmp(&b.ssid.to_lowercase()),
            SortField::Clients => a.client_count.cmp(&b.client_count),
            SortField::WifiGen => a.wifi_gen.cmp(&b.wifi_gen),
            SortField::FirstSeen => a.first_seen.cmp(&b.first_seen),
        };
        if ascending { ord } else { ord.reverse() }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ScanSnapshot — lock once, clone what we need, render from snapshot
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
pub struct ScanSnapshot {
    pub aps: Vec<Ap>,
    pub stations: Vec<Station>,
    pub probes: Vec<ProbeReq>,
    pub handshakes: Vec<crate::engine::capture::Handshake>,
    pub scan_events: Vec<ScanEvent>,
    pub channel_stats: Vec<ChannelStats>,
    pub stats: ScanStats,
    pub channel: u8,
}

impl Default for ScanSnapshot {
    fn default() -> Self {
        Self {
            aps: Vec::new(),
            stations: Vec::new(),
            probes: Vec::new(),
            handshakes: Vec::new(),
            scan_events: Vec::new(),
            channel_stats: Vec::new(),
            stats: ScanStats::default(),
            channel: 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DirtyFlags — what categories of data changed since last render
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Default)]
struct DirtyFlags {
    any: bool,
    aps: bool,
    stations: bool,
    probes: bool,
    channels: bool,
    events: bool,
    handshakes: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ScannerModule — the interactive scanner state
// ═══════════════════════════════════════════════════════════════════════════════

pub struct ScannerModule {
    pub scanner: Arc<Scanner>,
    /// FrameStore — the single source of truth for all intelligence.
    pub store: FrameStore,
    /// SharedAdapter reference — used to read pipeline stats for status bar.
    pub shared: Option<crate::adapter::SharedAdapter>,
    /// Delta subscriber — receives StoreUpdate batches from the pipeline.
    /// Wired in start() when SharedAdapter becomes available.
    update_sub: Option<UpdateSubscriber>,
    pub view: ScanView,
    pub detail: DetailState,
    pub selected: usize,
    pub scroll_offset: usize,
    pub detail_scroll: usize,
    pub scan_start: Instant,
    accumulated_events: VecDeque<ScanEvent>,

    /// Cached snapshot — refreshed when deltas arrive, reused when nothing changed.
    /// Clone-based semantics: cache survives across calls, zero store reads on quiet frames.
    cached_snapshot: Option<ScanSnapshot>,

    // Sort state
    pub sort_field: SortField,
    pub sort_ascending: bool,
    pub sort_menu_open: bool,
    pub sort_menu_cursor: usize,

    // Filter state
    pub filter: ScanFilter,
    pub filter_menu_open: bool,
    pub filter_menu_cursor: usize,

    // Channel filter — set when Enter is pressed on Channels view
    pub channel_filter: Option<u8>,

    /// Actual visible data rows from last render — used by key handler for
    /// scroll bounds. Computed dynamically during render() so it always
    /// matches the real viewport, regardless of terminal size or status bar height.
    visible_data_rows: usize,

}

impl ScannerModule {
    pub fn new(scanner: Arc<Scanner>, store: FrameStore) -> Self {
        Self {
            scanner,
            store,
            shared: None,
            update_sub: None,
            view: ScanView::Aps,
            detail: DetailState::None,
            selected: 0,
            scroll_offset: 0,
            detail_scroll: 0,
            scan_start: Instant::now(),
            accumulated_events: VecDeque::new(),
            cached_snapshot: None,
            sort_field: SortField::Rssi,
            sort_ascending: false,
            sort_menu_open: false,
            sort_menu_cursor: 0,
            filter: ScanFilter::default(),
            filter_menu_open: false,
            filter_menu_cursor: 0,
            channel_filter: None,
            visible_data_rows: 0,
        }
    }

    /// Drain pending deltas from the subscriber and categorize what changed.
    /// Returns DirtyFlags indicating which data categories have new updates.
    /// When no subscriber is wired (pre-start), returns all-dirty to force full reads.
    fn process_deltas(&mut self) -> DirtyFlags {
        let sub = match &self.update_sub {
            Some(s) => s,
            None => {
                // No subscriber yet — treat everything as dirty (legacy behavior)
                return DirtyFlags {
                    any: true, aps: true, stations: true, probes: true,
                    channels: true, events: true, handshakes: true,
                };
            }
        };

        let batches = sub.drain();
        if batches.is_empty() {
            return DirtyFlags::default();
        }

        let mut flags = DirtyFlags { any: true, ..Default::default() };

        for batch in &batches {
            for delta in batch.iter() {
                match delta {
                    StoreUpdate::ApDiscovered { .. }
                    | StoreUpdate::ApBeaconUpdate { .. }
                    | StoreUpdate::ApSsidRevealed { .. }
                    | StoreUpdate::ApClientCountChanged { .. }
                    | StoreUpdate::ApCaptureStateChanged { .. } => flags.aps = true,

                    StoreUpdate::StationDiscovered { .. }
                    | StoreUpdate::StationAssociated { .. }
                    | StoreUpdate::StationDataUpdate { .. }
                    | StoreUpdate::StationProbeUpdate { .. }
                    | StoreUpdate::StationFingerprinted { .. }
                    | StoreUpdate::StationPowerSaveChanged { .. }
                    | StoreUpdate::StationHandshakeProgress { .. } => flags.stations = true,

                    StoreUpdate::ProbeDiscovered { .. }
                    | StoreUpdate::ProbeUpdated { .. } => flags.probes = true,

                    StoreUpdate::ScanEvent { .. } => flags.events = true,

                    StoreUpdate::ChannelFrameCounted { .. }
                    | StoreUpdate::ChannelDwellComplete { .. }
                    | StoreUpdate::ChannelStatsCleared
                    | StoreUpdate::ChannelDwellStarted { .. }
                    | StoreUpdate::ChannelDwellEnded { .. }
                    | StoreUpdate::ScannerChannelChanged { .. }
                    | StoreUpdate::ScannerRoundComplete { .. } => flags.channels = true,

                    StoreUpdate::HandshakeComplete { .. }
                    | StoreUpdate::HandshakeQualityImproved { .. }
                    | StoreUpdate::PmkidCaptured { .. }
                    | StoreUpdate::EapolMessage { .. }
                    | StoreUpdate::HandshakeExportReady { .. }
                    | StoreUpdate::EapIdentityCaptured { .. }
                    | StoreUpdate::EapMethodNegotiated { .. } => flags.handshakes = true,

                    StoreUpdate::FrameCounted { .. }
                    | StoreUpdate::BeaconTimingUpdate { .. } => {
                        // Frame counting updates stats (FPS, frame counts).
                        // Beacon timing is used in AP detail views.
                        // Mark aps dirty so stats refresh.
                        flags.aps = true;
                    }

                    // Adapter lifecycle, TX feedback, diagnostics, sensor data,
                    // attack lifecycle — not relevant for scanner views
                    _ => {}
                }
            }
        }

        flags
    }

    /// Refresh the cached snapshot from the store.
    /// Per-category lazy refresh: only re-reads dirty categories from the store,
    /// reusing cached data for clean categories. During active scanning with 30+
    /// APs and hundreds of stations, this avoids cloning the entire AP HashMap
    /// when only a station's RSSI changed.
    ///
    /// Events still drain from the store's EventRing (Phase 0 — will move to
    /// delta-based events when we rewrite the Events view).
    pub fn refresh_snapshot(&mut self) {
        let dirty = self.process_deltas();

        // Fast path: subscriber active, nothing changed, cache intact → skip
        if self.update_sub.is_some() && !dirty.any && self.cached_snapshot.is_some() {
            return;
        }

        // Drain scan events from store (still EventRing-based for Phase 0)
        if dirty.events || self.update_sub.is_none() {
            let new_events = self.store.drain_events();
            self.accumulated_events.extend(new_events);
            const MAX_ACCUMULATED_EVENTS: usize = 10_000;
            while self.accumulated_events.len() > MAX_ACCUMULATED_EVENTS {
                self.accumulated_events.pop_front();
            }
        }

        // Per-category lazy refresh: only re-read what actually changed.
        // Reuse cached data for clean categories to avoid unnecessary clones.
        let prev = self.cached_snapshot.take();

        let aps = if dirty.aps || prev.is_none() {
            self.store.get_aps().into_values().collect()
        } else {
            prev.as_ref().unwrap().aps.clone()
        };

        let stations = if dirty.stations || prev.is_none() {
            self.store.get_stations().into_values().collect()
        } else {
            prev.as_ref().unwrap().stations.clone()
        };

        let probes = if dirty.probes || prev.is_none() {
            self.store.get_probes()
        } else {
            prev.as_ref().unwrap().probes.clone()
        };

        let handshakes = if dirty.handshakes || prev.is_none() {
            self.store.with_capture_db_read(|db| db.handshakes().to_vec())
        } else {
            prev.as_ref().unwrap().handshakes.clone()
        };

        let channel_stats = if dirty.channels || prev.is_none() {
            self.store.get_channel_stats().into_values().collect()
        } else {
            prev.as_ref().unwrap().channel_stats.clone()
        };

        // Stats and channel are always cheap to read (atomics, no locks)
        self.cached_snapshot = Some(ScanSnapshot {
            aps,
            stations,
            probes,
            handshakes,
            scan_events: self.accumulated_events.iter().cloned().collect(),
            channel_stats,
            stats: self.store.stats(),
            channel: self.store.current_channel(),
        });
    }

    /// Get a clone of the cached snapshot, refreshing if needed.
    /// Clone instead of take — the cache survives across calls within a frame
    /// and across frames when no deltas arrive (zero store reads on quiet periods).
    fn snapshot(&mut self) -> ScanSnapshot {
        self.refresh_snapshot();
        self.cached_snapshot.clone().unwrap_or_default()
    }

    /// Total row count for current view (for scroll bounds).
    fn row_count(&self, snap: &ScanSnapshot) -> usize {
        match &self.detail {
            DetailState::None => match self.view {
                ScanView::Aps => snap.aps.len(),
                ScanView::Clients => snap.stations.len(),
                ScanView::Probes => snap.probes.len(),
                ScanView::Channels => {
                    let mut channels: Vec<u8> = snap.aps.iter().map(|a| a.channel).collect();
                    for cs in &snap.channel_stats {
                        channels.push(cs.channel);
                    }
                    channels.sort();
                    channels.dedup();
                    channels.len()
                }
                ScanView::Events => 0, // events use stream-style scrolling, not row selection
                ScanView::Handshakes => snap.handshakes.iter()
                    .filter(|hs| hs.quality != crate::protocol::eapol::HandshakeQuality::None)
                    .count(),
            },
            _ => 0, // detail views don't use row selection
        }
    }

    /// Clamp selected index to valid range.
    fn clamp_selected(&mut self, snap: &ScanSnapshot) {
        let count = self.row_count(snap);
        if count == 0 {
            self.selected = 0;
        } else if self.selected >= count {
            self.selected = count - 1;
        }
    }

    /// Render the scanner view as a fixed-height block.
    /// ALWAYS returns exactly `height` lines — no more, no less.
    pub fn render(&mut self, width: u16, height: u16) -> Vec<String> {
        let h = height as usize;
        let mut snap = self.snapshot();

        // Apply filter and sort to APs before rendering
        if self.view == ScanView::Aps && matches!(self.detail, DetailState::None) {
            // Apply channel filter (from Enter on Channels view)
            if let Some(ch) = self.channel_filter {
                snap.aps.retain(|ap| ap.channel == ch);
            }
            snap.aps.retain(|ap| self.filter.matches(ap));
            sort_aps(&mut snap.aps, self.sort_field, self.sort_ascending);
        }

        // Clamp selection after filter may have reduced count
        let ap_count = snap.aps.len();
        if ap_count == 0 {
            self.selected = 0;
            self.scroll_offset = 0;
        } else if self.selected >= ap_count {
            self.selected = ap_count - 1;
        }

        let mut lines = Vec::new();

        // View tabs header (2 lines: tabs + separator)
        let tab_line = self.render_view_tabs(width);
        let tab_width = prism::measure_width(&tab_line);
        lines.push(tab_line);
        lines.push(format!("  {}", prism::s().dim().paint(
            &prism::divider("─", tab_width.saturating_sub(2))
        )));
        lines.push(String::new());

        // Content gets everything after tabs(3: tab + hr + empty)
        let content_rows = h.saturating_sub(3);

        // Default visible data rows — updated dynamically by render_aps via scroll_table capacity
        self.visible_data_rows = content_rows.saturating_sub(7).max(1);

        match &self.detail {
            DetailState::None => {
                match self.view {
                    ScanView::Aps => {
                        if self.sort_menu_open {
                            views::render_sort_menu(
                                self.sort_field, self.sort_ascending,
                                self.sort_menu_cursor, width, content_rows,
                                &mut lines,
                            );
                        } else if self.filter_menu_open {
                            views::render_filter_menu(
                                &self.filter, self.filter_menu_cursor,
                                width, content_rows, &mut lines,
                            );
                        } else {
                            let capacity = views::render_aps(&snap, width, self.selected, self.scroll_offset, content_rows, self.sort_field, &self.filter, &mut lines);
                            self.visible_data_rows = capacity.max(1);
                        }
                    }
                    ScanView::Clients => {
                        let capacity = views::render_clients(&snap, width, self.selected, self.scroll_offset, content_rows, &mut lines);
                        self.visible_data_rows = capacity.max(1);
                    }
                    ScanView::Probes => {
                        let capacity = views::render_probes(&snap, width, self.selected, self.scroll_offset, content_rows, &mut lines);
                        self.visible_data_rows = capacity.max(1);
                    }
                    ScanView::Channels => {
                        let capacity = views::render_channels(&snap, width, self.selected, self.scroll_offset, content_rows, &mut lines);
                        self.visible_data_rows = capacity.max(1);
                    }
                    ScanView::Events => views::render_events(&snap, width, self.scroll_offset, content_rows, &mut lines),
                    ScanView::Handshakes => {
                        let capacity = views::render_handshakes(&snap, width, self.selected, self.scroll_offset, content_rows, &mut lines);
                        self.visible_data_rows = capacity.max(1);
                    }
                }
            }
            DetailState::Ap { bssid, tab } => {
                if let Some(ap) = snap.aps.iter().find(|a| &a.bssid == bssid) {
                    let clients = self.store.get_ap_clients(bssid);
                    let probes = self.store.get_probes();
                    let bt_map = self.store.get_beacon_timing();
                    let bt = bt_map.get(bssid).cloned();
                    let mut detail_lines = Vec::new();
                    let pin_count = detail::render_ap_detail(ap, &clients, &probes, bt.as_ref(), *tab, width, &mut detail_lines);

                    // Apply detail scrolling — pin_count includes shared headers + tab table headers
                    let total = detail_lines.len();
                    let hc = pin_count.min(total);
                    let scrollable_len = total.saturating_sub(hc);
                    let scroll = self.detail_scroll.min(scrollable_len);
                    self.detail_scroll = scroll; // clamp

                    // Add headers (always visible)
                    lines.extend(detail_lines[..hc].iter().cloned());
                    // Scroll indicator if scrolled down
                    if scroll > 0 {
                        lines.push(format!("  {} {}",
                            prism::s().dim().paint(&format!("\u{2191}{} above", scroll)),
                            prism::s().dim().paint("(k/g to scroll up)")));
                    }
                    // Add scrolled content
                    lines.extend(detail_lines[hc..].iter().skip(scroll).cloned());
                } else {
                    lines.push(format!("  {} AP no longer visible", prism::s().dim().paint("?")));
                }
            }
            DetailState::Client { mac, tab } => {
                if let Some(sta) = snap.stations.iter().find(|s| &s.mac == mac) {
                    let probes: Vec<crate::store::ProbeReq> = self.store.get_probes().into_iter()
                        .filter(|p| &p.sta_mac == mac)
                        .collect();
                    let mut detail_lines = Vec::new();
                    let pin_count = detail::render_client_detail(sta, &probes, *tab, width, &mut detail_lines);

                    // Apply detail scrolling — pin_count includes shared headers + tab table headers
                    let total = detail_lines.len();
                    let hc = pin_count.min(total);
                    let scrollable_len = total.saturating_sub(hc);
                    let scroll = self.detail_scroll.min(scrollable_len);
                    self.detail_scroll = scroll; // clamp

                    // Add headers (always visible)
                    lines.extend(detail_lines[..hc].iter().cloned());
                    // Scroll indicator if scrolled down
                    if scroll > 0 {
                        lines.push(format!("  {} {}",
                            prism::s().dim().paint(&format!("\u{2191}{} above", scroll)),
                            prism::s().dim().paint("(k/g to scroll up)")));
                    }
                    // Add scrolled content
                    lines.extend(detail_lines[hc..].iter().skip(scroll).cloned());
                } else {
                    lines.push(format!("  {} Station no longer visible", prism::s().dim().paint("?")));
                }
            }
        }

        // Enforce EXACT height: pad if short, truncate if over
        while lines.len() < h {
            lines.push(String::new());
        }
        lines.truncate(h);
        lines
    }

    /// Render the view tab bar.
    ///
    /// In scan mode: full tab bar with active tab highlighted.
    /// In detail mode: compact breadcrumb — `APs ▸ RL-WiFi ▸ Overview`
    fn render_view_tabs(&self, _width: u16) -> String {
        match &self.detail {
            DetailState::Ap { bssid, tab } => {
                let ssid_str = self.store.get_ap(bssid)
                    .map(|a| if a.ssid.is_empty() { format!("{}", a.bssid) } else { a.ssid.clone() })
                    .unwrap_or_else(|| format!("{}", bssid));
                format!("   {} {} {} {} {}",
                    prism::s().dim().paint(self.view.name()),
                    prism::s().dim().paint("▸"),
                    prism::s().cyan().bold().paint(&ssid_str),
                    prism::s().dim().paint("▸"),
                    prism::s().bold().paint(detail::ap_tab_name(*tab)),
                )
            }
            DetailState::Client { mac, tab } => {
                let vendor = self.cached_snapshot.as_ref()
                    .and_then(|snap| snap.stations.iter().find(|s| s.mac == *mac))
                    .map(|s| s.vendor.clone())
                    .unwrap_or_default();
                let label = if vendor.is_empty() {
                    format!("{}", mac)
                } else {
                    format!("{} ({})", mac, vendor)
                };
                format!("   {} {} {} {} {}",
                    prism::s().dim().paint("Clients"),
                    prism::s().dim().paint("▸"),
                    prism::s().cyan().bold().paint(&label),
                    prism::s().dim().paint("▸"),
                    prism::s().bold().paint(detail::client_tab_name(*tab)),
                )
            }
            DetailState::None => {
                let sep = prism::s().dim().paint(" │ ");
                let mut tabs = Vec::new();
                for v in ScanView::ALL {
                    let is_active = *v == self.view;
                    if is_active {
                        tabs.push(prism::s().cyan().bold().inverse().paint(&format!(" {} ", v.name())));
                    } else {
                        tabs.push(prism::s().dim().paint(v.name()));
                    }
                }
                let mut line = format!("   {}  ", tabs.join(&sep.to_string()));
                if let Some(ch) = self.channel_filter {
                    line.push_str(&format!("  {} {}",
                        prism::s().yellow().paint(&format!("ch:{ch}")),
                        prism::s().dim().paint("(f to clear)"),
                    ));
                }
                line
            }
        }
    }

    /// Status bar segments for the scanner (shown even when not focused).
    /// Always reads fresh stats from the store — stats() is cheap (atomics +
    /// one small mutex). The cached_snapshot is only refreshed during render(),
    /// which only runs for the focused module, so relying on it here would
    /// freeze the status bar whenever an attack has focus.
    pub fn status_segments(&self) -> Vec<StatusSegment> {
        let stats = self.store.stats();
        let channel = self.store.current_channel();
        let elapsed = style::format_elapsed_precise(stats.elapsed);

        // Discovery counts with handshakes/PMKIDs when captured
        // Show crackable count (M1+M2 minimum), not total tracking entries
        let mut counts = format!("{} APs \u{00b7} {} STAs", stats.ap_count, stats.sta_count);
        if stats.crackable_count > 0 || stats.complete_handshake_count > 0 {
            if stats.complete_handshake_count > 0 {
                counts.push_str(&format!(" \u{00b7} {} HS ({} full)",
                    stats.crackable_count, stats.complete_handshake_count));
            } else {
                counts.push_str(&format!(" \u{00b7} {} HS", stats.crackable_count));
            }
        }
        if stats.pmkid_count > 0 {
            counts.push_str(&format!(" \u{00b7} {} PMKID", stats.pmkid_count));
        }

        // Channel with lock indicator — locked state gets distinct yellow styling
        // Fixed-width ch field (ch:XXX = 6 chars) so status bar doesn't jitter
        let (ch_text, ch_style) = if let Some(ref shared) = self.shared {
            let locked = shared.locked_channel();
            if locked != 0 {
                let text = if let Some(holder) = shared.lock_holder() {
                    format!("ch:{:<3} \u{1f512}{}", locked, holder)
                } else {
                    format!("ch:{:<3} \u{1f512}", locked)
                };
                (text, SegmentStyle::YellowBold)
            } else {
                (format!("ch:{:<3}", channel), SegmentStyle::Bold)
            }
        } else {
            (format!("ch:{:<3}", channel), SegmentStyle::Bold)
        };

        let round_text = format!("r:{:<3}", stats.round);

        vec![
            StatusSegment::new("scan", SegmentStyle::CyanBold),
            StatusSegment::new(counts, SegmentStyle::Bold),
            StatusSegment::new(ch_text, ch_style),
            StatusSegment::new(round_text, SegmentStyle::Dim),
            StatusSegment::new(elapsed, SegmentStyle::Dim),
            StatusSegment::new(format!("{:>6} fps", stats.frames_per_sec), SegmentStyle::Bold),
        ]
    }

    /// Handle a keypress in Normal Mode. Returns true if key was consumed.
    pub fn handle_key(&mut self, key: &prism::KeyEvent) -> bool {
        // Ctrl keys handled by shell
        if key.ctrl || key.meta {
            return false;
        }

        match &self.detail {
            DetailState::None => self.handle_view_key(key),
            DetailState::Ap { tab, .. } => self.handle_ap_detail_key(key, *tab),
            DetailState::Client { tab, .. } => self.handle_client_detail_key(key, *tab),
        }
    }

    /// Ensure selected row is visible within scroll window.
    fn ensure_visible(&mut self, visible_rows: usize) {
        if visible_rows == 0 { return; }
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        } else if self.selected >= self.scroll_offset + visible_rows {
            self.scroll_offset = self.selected - visible_rows + 1;
        }
    }

    fn handle_view_key(&mut self, key: &prism::KeyEvent) -> bool {
        // ── Sort menu key handling ──────────────────────────────────────────
        if self.sort_menu_open {
            return self.handle_sort_menu_key(key);
        }

        // ── Filter menu key handling ────────────────────────────────────────
        if self.filter_menu_open {
            return self.handle_filter_menu_key(key);
        }

        let mut snap = self.snapshot();
        // Apply same sort/filter as render() so selected index matches displayed order
        if self.view == ScanView::Aps {
            if let Some(ch) = self.channel_filter {
                snap.aps.retain(|ap| ap.channel == ch);
            }
            snap.aps.retain(|ap| self.filter.matches(ap));
            sort_aps(&mut snap.aps, self.sort_field, self.sort_ascending);
        }
        // Use the actual visible rows computed during the last render cycle.
        // This adapts to any terminal size and status bar height automatically.
        let visible_rows = self.visible_data_rows;

        // Events view has stream-style scrolling (k=older, j=newer, g=oldest, G=newest)
        if self.view == ScanView::Events {
            return match key.key.as_str() {
                "k" | "up" => {
                    let max_offset = snap.scan_events.len();
                    if self.scroll_offset < max_offset {
                        self.scroll_offset += 1;
                    }
                    true
                }
                "j" | "down" => {
                    if self.scroll_offset > 0 {
                        self.scroll_offset -= 1;
                    }
                    true
                }
                "g" => { self.scroll_offset = snap.scan_events.len(); true }
                "G" => { self.scroll_offset = 0; true }
                "tab" => {
                    self.view = self.view.next();
                    self.selected = 0;
                    self.scroll_offset = 0;
                    true
                }
                _ => false,
            };
        }

        match key.key.as_str() {
            // Navigation
            "j" | "down" => {
                let count = self.row_count(&snap);
                if count > 0 && self.selected < count - 1 {
                    self.selected += 1;
                    self.ensure_visible(visible_rows);
                }
                true
            }
            "k" | "up" => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.ensure_visible(visible_rows);
                }
                true
            }
            "g" => { self.selected = 0; self.scroll_offset = 0; true }
            "G" => {
                let count = self.row_count(&snap);
                if count > 0 {
                    self.selected = count - 1;
                    self.ensure_visible(visible_rows);
                }
                true
            }

            // View switching
            "tab" => {
                self.view = self.view.next();
                self.selected = 0;
                self.scroll_offset = 0;
                true
            }

            // Drill into detail
            "enter" => {
                match self.view {
                    ScanView::Aps => {
                        if let Some(ap) = snap.aps.get(self.selected) {
                            self.detail = DetailState::Ap { bssid: ap.bssid, tab: 1 };
                            self.detail_scroll = 0;
                        }
                    }
                    ScanView::Clients => {
                        if let Some(sta) = snap.stations.get(self.selected) {
                            self.detail = DetailState::Client { mac: sta.mac, tab: 1 };
                            self.detail_scroll = 0;
                        }
                    }
                    ScanView::Channels => {
                        // Drill into APs view filtered to the selected channel
                        let mut channels: Vec<u8> = snap.aps.iter().map(|a| a.channel).collect();
                        channels.sort();
                        channels.dedup();
                        if let Some(&ch) = channels.get(self.selected) {
                            self.channel_filter = Some(ch);
                            self.view = ScanView::Aps;
                            self.selected = 0;
                            self.scroll_offset = 0;
                        }
                    }
                    ScanView::Handshakes => {
                        // Drill into AP detail for the handshake's AP
                        // Must use the FILTERED list (same as render) so selected index matches
                        let filtered_hs: Vec<_> = snap.handshakes.iter()
                            .filter(|hs| hs.quality != crate::protocol::eapol::HandshakeQuality::None)
                            .collect();
                        if let Some(hs) = filtered_hs.get(self.selected) {
                            self.detail = DetailState::Ap { bssid: hs.ap_mac, tab: 1 };
                            self.detail_scroll = 0;
                        }
                    }
                    ScanView::Probes => {
                        // Drill into Client detail for the probing station
                        let mut probes = snap.probes.clone();
                        probes.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                        if let Some(probe) = probes.get(self.selected) {
                            self.detail = DetailState::Client { mac: probe.sta_mac, tab: 1 };
                            self.detail_scroll = 0;
                        }
                    }
                    ScanView::Events => {}
                }
                true
            }

            // Contextual filter toggle
            "f" => {
                if self.channel_filter.is_some() {
                    // Clear channel filter
                    self.channel_filter = None;
                    self.selected = 0;
                    self.scroll_offset = 0;
                } else if self.view == ScanView::Aps {
                    // Set channel filter based on selected AP's channel
                    if let Some(ap) = snap.aps.get(self.selected) {
                        self.channel_filter = Some(ap.channel);
                        self.selected = 0;
                        self.scroll_offset = 0;
                    }
                }
                true
            }

            // Sort menu (APs view only)
            "S" if self.view == ScanView::Aps => {
                self.sort_menu_open = true;
                self.sort_menu_cursor = self.sort_field.index();
                true
            }

            // Filter menu (APs view only)
            "F" if self.view == ScanView::Aps => {
                self.filter_menu_open = true;
                self.filter_menu_cursor = 0;
                true
            }

            _ => false,
        }
    }

    /// Handle keys while the sort menu is open.
    fn handle_sort_menu_key(&mut self, key: &prism::KeyEvent) -> bool {
        let count = SortField::ALL.len();
        match key.key.as_str() {
            "j" | "down" => {
                if self.sort_menu_cursor < count - 1 {
                    self.sort_menu_cursor += 1;
                }
                true
            }
            "k" | "up" => {
                if self.sort_menu_cursor > 0 {
                    self.sort_menu_cursor -= 1;
                }
                true
            }
            "enter" => {
                let new_field = SortField::ALL[self.sort_menu_cursor];
                if new_field == self.sort_field {
                    // Toggle direction if same field selected again
                    self.sort_ascending = !self.sort_ascending;
                } else {
                    self.sort_field = new_field;
                    // Sensible default direction per field
                    self.sort_ascending = match new_field {
                        SortField::Rssi => false,       // strongest first
                        SortField::Channel => true,     // low to high
                        SortField::Security => false,   // strongest sec first
                        SortField::Ssid => true,        // A-Z
                        SortField::Clients => false,    // most clients first
                        SortField::WifiGen => false,    // newest gen first
                        SortField::FirstSeen => false,  // newest first
                    };
                }
                self.sort_menu_open = false;
                self.selected = 0;
                self.scroll_offset = 0;
                true
            }
            "escape" | "S" => {
                self.sort_menu_open = false;
                true
            }
            _ => true, // consume all keys while menu is open
        }
    }

    /// Handle keys while the filter menu is open.
    fn handle_filter_menu_key(&mut self, key: &prism::KeyEvent) -> bool {
        let count = FilterMenuItem::ALL.len();
        match key.key.as_str() {
            "j" | "down" => {
                if self.filter_menu_cursor < count - 1 {
                    self.filter_menu_cursor += 1;
                }
                true
            }
            "k" | "up" => {
                if self.filter_menu_cursor > 0 {
                    self.filter_menu_cursor -= 1;
                }
                true
            }
            "enter" | " " => {
                // Toggle/cycle the selected filter
                match FilterMenuItem::ALL[self.filter_menu_cursor] {
                    FilterMenuItem::Band => {
                        self.filter.band = match self.filter.band {
                            None => Some(FilterBand::Band2g),
                            Some(FilterBand::Band2g) => Some(FilterBand::Band5g),
                            Some(FilterBand::Band5g) => None,
                        };
                    }
                    FilterMenuItem::Security => {
                        self.filter.security = match self.filter.security {
                            None => Some(Security::Open),
                            Some(Security::Open) => Some(Security::Wep),
                            Some(Security::Wep) => Some(Security::Wpa),
                            Some(Security::Wpa) => Some(Security::Wpa2),
                            Some(Security::Wpa2) => Some(Security::Wpa2Enterprise),
                            Some(Security::Wpa2Enterprise) => Some(Security::Wpa3),
                            Some(Security::Wpa3) => Some(Security::Wpa3Enterprise),
                            Some(Security::Wpa3Enterprise) => Some(Security::Owe),
                            Some(Security::Owe) => None,
                        };
                    }
                    FilterMenuItem::WpsOnly => {
                        self.filter.wps_only = !self.filter.wps_only;
                    }
                    FilterMenuItem::HiddenOnly => {
                        self.filter.hidden_only = !self.filter.hidden_only;
                    }
                    FilterMenuItem::WifiGen => {
                        self.filter.wifi_gen = match self.filter.wifi_gen {
                            None => Some(WifiGeneration::Legacy),
                            Some(WifiGeneration::Legacy) => Some(WifiGeneration::Wifi4),
                            Some(WifiGeneration::Wifi4) => Some(WifiGeneration::Wifi5),
                            Some(WifiGeneration::Wifi5) => Some(WifiGeneration::Wifi6),
                            Some(WifiGeneration::Wifi6) => Some(WifiGeneration::Wifi6e),
                            Some(WifiGeneration::Wifi6e) => Some(WifiGeneration::Wifi7),
                            Some(WifiGeneration::Wifi7) => None,
                        };
                    }
                    FilterMenuItem::MinClients => {
                        // Cycle: 0 -> 1 -> 2 -> 5 -> 10 -> 0
                        self.filter.min_clients = match self.filter.min_clients {
                            0 => 1,
                            1 => 2,
                            2 => 5,
                            5 => 10,
                            _ => 0,
                        };
                    }
                }
                self.selected = 0;
                self.scroll_offset = 0;
                true
            }
            "x" => {
                // Clear all filters
                self.filter = ScanFilter::default();
                self.selected = 0;
                self.scroll_offset = 0;
                true
            }
            "escape" | "F" => {
                self.filter_menu_open = false;
                true
            }
            _ => true, // consume all keys while menu is open
        }
    }

    fn handle_ap_detail_key(&mut self, key: &prism::KeyEvent, current_tab: u8) -> bool {
        match key.key.as_str() {
            // Detail scrolling
            "j" | "down" => { self.detail_scroll += 1; true }
            "k" | "up" => { if self.detail_scroll > 0 { self.detail_scroll -= 1; } true }
            "g" => { self.detail_scroll = 0; true }
            "G" => { self.detail_scroll = usize::MAX; true } // will be clamped in render
            "escape" => { self.detail = DetailState::None; self.detail_scroll = 0; true }
            "1" => { self.set_ap_tab(1); true }
            "2" => { self.set_ap_tab(2); true }
            "3" => { self.set_ap_tab(3); true }
            "4" => { self.set_ap_tab(4); true }
            "5" => { self.set_ap_tab(5); true }
            "6" => { self.set_ap_tab(6); true }
            "7" => { self.set_ap_tab(7); true }
            "8" => { self.set_ap_tab(8); true }
            "9" => { self.set_ap_tab(9); true }
            "tab" => {
                let next = if current_tab >= 9 { 1 } else { current_tab + 1 };
                self.set_ap_tab(next);
                true
            }
            // Enter on Clients tab (4) could drill into client detail
            "enter" if current_tab == 4 => {
                // TODO: drill into client detail from AP's client list
                false
            }
            _ => false,
        }
    }

    fn handle_client_detail_key(&mut self, key: &prism::KeyEvent, current_tab: u8) -> bool {
        match key.key.as_str() {
            // Detail scrolling
            "j" | "down" => { self.detail_scroll += 1; true }
            "k" | "up" => { if self.detail_scroll > 0 { self.detail_scroll -= 1; } true }
            "g" => { self.detail_scroll = 0; true }
            "G" => { self.detail_scroll = usize::MAX; true } // will be clamped in render
            "escape" => { self.detail = DetailState::None; self.detail_scroll = 0; true }
            "1" => { self.set_client_tab(1); true }
            "2" => { self.set_client_tab(2); true }
            "3" => { self.set_client_tab(3); true }
            "4" => { self.set_client_tab(4); true }
            "5" => { self.set_client_tab(5); true }
            "6" => { self.set_client_tab(6); true }
            "tab" => {
                let next = if current_tab >= 6 { 1 } else { current_tab + 1 };
                self.set_client_tab(next);
                true
            }
            _ => false,
        }
    }

    fn set_ap_tab(&mut self, new_tab: u8) {
        if let DetailState::Ap { ref mut tab, .. } = self.detail {
            *tab = new_tab;
        }
        self.detail_scroll = 0;
    }

    fn set_client_tab(&mut self, new_tab: u8) {
        if let DetailState::Client { ref mut tab, .. } = self.detail {
            *tab = new_tab;
        }
        self.detail_scroll = 0;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Module trait implementation
// ═══════════════════════════════════════════════════════════════════════════════

use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};

impl Module for ScannerModule {
    fn name(&self) -> &str { "scanner" }
    fn description(&self) -> &str { "WiFi scanner — discover APs, stations, and handshakes" }
    fn module_type(&self) -> ModuleType { ModuleType::Scanner }

    fn start(&mut self, shared: crate::adapter::SharedAdapter) {
        // Subscribe to delta stream BEFORE starting scanner thread
        // so we don't miss any early deltas
        self.update_sub = Some(shared.gate().subscribe_updates("scanner-ui"));

        // Keep a clone for pipeline stats access from status bar
        self.shared = Some(shared.clone());

        let scanner = Arc::clone(&self.scanner);
        let store = self.store.clone();
        // In v2, scanner just hops channels. Frame processing is handled
        // by the FrameGate → extractor → FrameStore pipeline automatically.
        // Scanner writes round + channel to the store (single source of truth).
        std::thread::Builder::new()
            .name("scanner".into())
            .spawn(move || {
                scanner.run(&shared, &store);
            })
            .expect("failed to spawn scanner thread");
    }

    fn signal_stop(&self) {
        self.scanner.stop();
    }

    fn is_running(&self) -> bool {
        self.scanner.is_running()
    }

    fn is_done(&self) -> bool {
        // Scanner is "done" only after stop + run() returns.
        // While running, it's never done (continuous module).
        !self.scanner.is_running()
    }

    fn views(&self) -> &[ViewDef] {
        // Static view definitions — cached to avoid allocation
        const VIEWS: &[ViewDef] = &[
            ViewDef { label: String::new(), key_hint: None }, // placeholder, see below
        ];
        // Can't use const with String, so we use a thread-local or just return dynamically
        // This is called once per render cycle, allocation is fine
        &[]  // Views are managed internally via ScanView enum — this is for the shell's tab bar
    }

    fn render(&mut self, _view: usize, width: u16, height: u16) -> Vec<String> {
        // The ScannerModule manages its own views internally via ScanView enum.
        self.refresh_snapshot();
        ScannerModule::render(self, width, height)
    }

    fn handle_key(&mut self, key: &prism::KeyEvent, _view: usize) -> bool {
        // ScannerModule manages its own view switching internally
        ScannerModule::handle_key(self, key)
    }

    fn status_segments(&self) -> Vec<StatusSegment> {
        // Scanner now returns StatusSegment directly — no lossy bridge needed
        ScannerModule::status_segments(self)
    }

    fn freeze_summary(&self, _width: u16) -> Vec<String> {
        // Scanner doesn't freeze — it's continuous.
        // When explicitly stopped, just show a brief summary.
        let stats = self.store.stats();
        vec![
            format!("  {} Scan stopped: {} APs, {} STAs, {} handshakes in {}",
                prism::s().dim().paint("\u{2500}\u{2500}\u{2500}"),
                stats.ap_count, stats.sta_count, stats.handshake_count,
                style::format_elapsed(stats.elapsed)),
        ]
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}
