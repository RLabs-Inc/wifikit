//! CLI renderer + Module implementation for the Rogue AP attack.
//!
//! Renders the attack progress as styled terminal lines:
//! - Attack mode (Evil Twin / KARMA / MANA Loud / Known Beacons / Normal)
//! - Rogue AP status (beacon count, probe activity, connected clients)
//! - Client table (MAC, state, RSSI, probe SSID, data stats)
//! - KARMA SSID collection (for KARMA/MANA modes)
//! - Event log scrollback

use std::collections::VecDeque;

use crate::attacks::ap::{
    ApAttack, ApEvent, ApEventKind, ApFinalResult, ApInfo,
    ApMode, ApParams, ApPhase, ApResult, ClientApState,
};
use crate::pipeline::UpdateSubscriber;
use crate::store::update::{AttackEventKind, AttackId, AttackType, StoreUpdate};

use prism::{s, truncate};
use super::{fps_sparkline, tx_stats_line};

// ═══════════════════════════════════════════════════════════════════════════════
//  Phase display
// ═══════════════════════════════════════════════════════════════════════════════

fn phase_label(phase: ApPhase) -> &'static str {
    match phase {
        ApPhase::Idle => "idle",
        ApPhase::Starting => "starting",
        ApPhase::Broadcasting => "broadcasting",
        ApPhase::Active => "active",
        ApPhase::Done => "done",
    }
}

/// Styled mode name for display.
fn mode_display(mode: ApMode) -> String {
    match mode {
        ApMode::EvilTwin => s().red().bold().paint("Evil Twin"),
        ApMode::Karma => s().red().bold().paint("KARMA"),
        ApMode::ManaLoud => s().red().bold().paint("MANA Loud"),
        ApMode::KnownBeacons => s().yellow().bold().paint("Known Beacons"),
        ApMode::Normal => s().cyan().paint("Normal"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Event formatting — for scrollback output
// ═══════════════════════════════════════════════════════════════════════════════

/// Format an AP event as a styled terminal line for the output zone.
pub fn format_event(event: &ApEvent) -> String {
    let ts = format!("{:>7.3}s", event.timestamp.as_secs_f64());
    let ts_styled = s().dim().paint(&ts);

    match &event.kind {
        ApEventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts_styled, s().dim().paint("LOCK"), channel)
        }
        ApEventKind::ApStarted { bssid, ssid, mode } => {
            format!("  [{}] {} Rogue AP started: {} ({})  {}",
                ts_styled, s().red().bold().paint("AP"),
                s().bold().paint(ssid),
                s().cyan().paint(mode.name()),
                s().dim().paint(&bssid.to_string()))
        }
        ApEventKind::ProbeRequest { mac, ssid, rssi } => {
            let ssid_str = if ssid.is_empty() {
                s().dim().paint("(broadcast)")
            } else {
                s().bold().paint(ssid)
            };
            format!("  [{}] {} {} \u{2190} {} ({} dBm)",
                ts_styled, s().dim().paint("PROBE"),
                ssid_str,
                s().dim().paint(&mac.to_string()), rssi)
        }
        ApEventKind::ProbeResponse { mac, ssid } => {
            format!("  [{}] {} {} \u{2192} {}",
                ts_styled, s().cyan().paint("RESP"),
                s().dim().paint(ssid),
                s().dim().paint(&mac.to_string()))
        }
        ApEventKind::KarmaSsidCollected { ssid, mac, total } => {
            format!("  [{}] {} New SSID: {} (#{}) \u{2190} {}",
                ts_styled, s().green().paint("KARMA"),
                s().bold().paint(ssid),
                total,
                s().dim().paint(&mac.to_string()))
        }
        ApEventKind::ClientAuthenticated { mac, rssi } => {
            format!("  [{}] {} {} ({} dBm)",
                ts_styled, s().cyan().paint("AUTH"),
                s().bold().paint(&mac.to_string()), rssi)
        }
        ApEventKind::ClientAssociated { mac, aid, rssi } => {
            format!("  [{}] {} {} (AID={}, {} dBm)",
                ts_styled, s().green().bold().paint("ASSOC"),
                s().bold().paint(&mac.to_string()), aid, rssi)
        }
        ApEventKind::ClientReassociated { mac, aid } => {
            format!("  [{}] {} {} (AID={})",
                ts_styled, s().cyan().paint("REASSOC"),
                s().bold().paint(&mac.to_string()), aid)
        }
        ApEventKind::ClientDisconnected { mac, reason } => {
            format!("  [{}] {} {} (reason={})",
                ts_styled, s().yellow().paint("DISCON"),
                s().dim().paint(&mac.to_string()), reason)
        }
        ApEventKind::DeauthBurst { target_bssid, count } => {
            format!("  [{}] {} {} deauth frames \u{2192} {}",
                ts_styled, s().red().paint("DEAUTH"),
                count,
                s().dim().paint(&target_bssid.to_string()))
        }
        ApEventKind::DataFrameReceived { mac, bytes } => {
            format!("  [{}] {} {} bytes \u{2190} {}",
                ts_styled, s().dim().paint("DATA"),
                bytes,
                s().dim().paint(&mac.to_string()))
        }
        ApEventKind::TimeoutReached { elapsed } => {
            format!("  [{}] {} Attack timeout ({:.0}s) reached",
                ts_styled, s().yellow().paint("TIMEOUT"), elapsed.as_secs_f64())
        }
        ApEventKind::AttackComplete { clients_total, karma_ssids, elapsed } => {
            let summary = if *karma_ssids > 0 {
                format!("{} clients, {} SSIDs collected", clients_total, karma_ssids)
            } else {
                format!("{} clients", clients_total)
            };
            format!("  [{}] {} AP attack complete: {}  ({:.1}s)",
                ts_styled, s().bold().paint("DONE"),
                s().green().paint(&summary),
                elapsed.as_secs_f64())
        }
        ApEventKind::Error { message } => {
            format!("  [{}] {} {}", ts_styled, s().red().bold().paint("ERROR"), message)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Active zone view
// ═══════════════════════════════════════════════════════════════════════════════

/// Render the AP attack progress view for the Layout active zone.
pub fn render_ap_view(info: &ApInfo, width: u16, fps_history: &VecDeque<f64>) -> Vec<String> {
    let w = width as usize;
    let inner_w = w.saturating_sub(6);

    // ── Border helpers ──
    let bc = |t: &str| s().dim().paint(t);
    let vline = |content: &str, iw: usize| {
        let display_w = prism::measure_width(content);
        let pad = iw.saturating_sub(display_w);
        format!("  {} {}{}{}", bc("\u{2502}"), content, " ".repeat(pad), bc("\u{2502}"))
    };
    let empty_line = || vline("", inner_w);

    let mut lines = Vec::new();

    // Breathing room above the frame
    lines.push(String::new());

    // ═══ Header border with mode title ═══
    let title = format!(" {} ", info.mode.name());
    let title_styled = s().red().bold().paint(&title);
    let title_plain_w = prism::measure_width(&title);
    let remaining = inner_w.saturating_sub(title_plain_w + 1);
    lines.push(format!("  {}{}{}{}", bc("\u{256d}\u{2500}"), title_styled,
        bc(&"\u{2500}".repeat(remaining)), bc("\u{256e}")));

    // ═══ Target + BSSID ═══
    if !info.ssid.is_empty() || info.channel > 0 {
        let ssid_display = if info.ssid.is_empty() {
            s().dim().italic().paint("(hidden)")
        } else {
            s().bold().paint(&truncate(&info.ssid, 24, "\u{2026}"))
        };
        let mut target_line = format!("{}  ch{}", ssid_display, info.channel);
        if info.our_bssid != crate::core::MacAddress::ZERO {
            target_line.push_str(&format!("  rogue: {}", s().dim().paint(&info.our_bssid.to_string())));
        }
        if let Some(tb) = info.target_bssid {
            if tb != info.our_bssid {
                target_line.push_str(&format!("  target: {}", s().dim().paint(&tb.to_string())));
            } else {
                target_line.push_str(&format!("  {}", s().dim().paint("(cloned)")));
            }
        }
        lines.push(vline(&target_line, inner_w));
    }

    // ═══ Step progress ═══
    if info.running || info.phase == ApPhase::Done {
        let spinner = prism::get_spinner("dots");
        let spin_frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let start_step = match info.phase {
            ApPhase::Idle => format!("{} START", s().dim().paint("\u{25cb}")),
            ApPhase::Starting => format!("{} START", s().yellow().paint(spin_frame)),
            _ => format!("{} START", s().green().paint("\u{2714}")),
        };

        let beacon_step = match info.phase {
            ApPhase::Idle | ApPhase::Starting =>
                format!("{} BEACON", s().dim().paint("\u{25cb}")),
            ApPhase::Broadcasting => format!("{} BEACON", s().cyan().paint(spin_frame)),
            _ => format!("{} BEACON", s().green().paint("\u{2714}")),
        };

        let active_step = match info.phase {
            ApPhase::Active => format!("{} ACTIVE", s().green().bold().paint(spin_frame)),
            ApPhase::Done => format!("{} ACTIVE", s().green().paint("\u{2714}")),
            _ => format!("{} ACTIVE", s().dim().paint("\u{25cb}")),
        };

        let arrow = s().dim().paint(" \u{2192} ");
        let steps = format!("{}{}{}{}{}", start_step, arrow, beacon_step, arrow, active_step);

        // Append FPS sparkline for beacon/frame rate
        if fps_history.len() > 1 {
            let spark = fps_sparkline(fps_history, 12);
            lines.push(vline(&format!("{}  {}", steps, spark), inner_w));
        } else {
            lines.push(vline(&steps, inner_w));
        }

        // TX stats line (rogue AP sends beacons/probes — TX feedback shows reach)
        if let Some(tx_line) = tx_stats_line(&info.tx_feedback, info.frames_sent, info.frames_per_sec) {
            lines.push(vline(&tx_line, inner_w));
        }
    }

    lines.push(empty_line());

    // ═══ Stats ═══
    if info.phase != ApPhase::Idle {
        let elapsed_secs = info.start_time.elapsed().as_secs_f64();

        // Client + KARMA stats
        let connected_str = format!("{}/{}", info.clients_connected, info.clients_total);
        let mut stats1 = format!("{} clients",
            s().green().bold().paint(&connected_str));
        if info.karma_ssids_collected > 0 {
            stats1.push_str(&format!("  {} SSIDs",
                s().green().paint(&info.karma_ssids_collected.to_string())));
        }
        stats1.push_str(&format!("  {:.1}s", elapsed_secs));
        lines.push(vline(&stats1, inner_w));

        // Interaction metrics (the hidden fields!)
        let fps_str = format!("{} fps", prism::format_compact(info.frames_per_sec as u64));
        let stats2 = format!("{} probes ({} resp)  {}/{} auth  {}/{} assoc  {} deauth  {}",
            prism::format_compact(info.probes_received),
            prism::format_compact(info.probes_answered),
            prism::format_compact(info.auths_accepted),
            prism::format_compact(info.auths_received),
            prism::format_compact(info.assocs_accepted),
            prism::format_compact(info.assocs_received),
            prism::format_compact(info.deauths_sent),
            s().yellow().paint(&fps_str));
        lines.push(vline(&s().dim().paint(&stats2), inner_w));

        // Traffic stats
        if info.data_frames_rx > 0 || info.frames_sent > 0 {
            let mut stats3 = format!("{} TX  {} RX  {} data frames  {}",
                prism::format_compact(info.frames_sent),
                prism::format_compact(info.frames_received),
                prism::format_compact(info.data_frames_rx),
                prism::format_bytes(info.bytes_rx));
            if info.tx_feedback.total_reports > 0 {
                stats3.push_str(&format!("  {} ack  {} nack",
                    s().green().paint(&prism::format_number(info.tx_feedback.acked)),
                    s().red().paint(&prism::format_number(info.tx_feedback.nacked))));
                if let Some(pct) = info.tx_feedback.delivery_pct() {
                    stats3.push_str(&format!("  {}%", pct as u64));
                }
            }
            lines.push(vline(&s().dim().paint(&stats3), inner_w));
        }

        // Deauths received (AP under attack?)
        if info.deauths_received > 0 {
            lines.push(vline(
                &format!("{} {} deauths received (someone attacking our AP?)",
                    s().yellow().paint("\u{26a0}"),
                    prism::format_number(info.deauths_received)),
                inner_w));
        }

        lines.push(empty_line());
    }

    // ═══ Client table ═══
    if !info.clients.is_empty() {
        lines.push(vline(
            &format!("{}  {}  {}  {}  {}  {}",
                s().bold().dim().paint(&prism::pad("CLIENT", 17, "left")),
                s().bold().dim().paint(&prism::pad("STATE", 8, "left")),
                s().bold().dim().paint(&prism::pad("RSSI", 4, "left")),
                s().bold().dim().paint(&prism::pad("PROBED SSID", 20, "left")),
                s().bold().dim().paint(&prism::pad("DATA", 8, "right")),
                s().bold().dim().paint(&prism::pad("SEEN", 6, "right"))),
            inner_w));

        for client in &info.clients {
            let state_str = match client.state {
                ClientApState::Probed => s().dim().paint("probed"),
                ClientApState::Authenticated => s().yellow().paint("authed"),
                ClientApState::Associated => s().green().bold().paint("assoc"),
                ClientApState::Disconnected => s().red().paint("discon"),
            };

            let probe_ssid = if client.probe_ssid.is_empty() {
                s().dim().paint("\u{2014}")
            } else {
                truncate(&client.probe_ssid, 20, "\u{2026}").to_string()
            };

            let data_str = format_bytes_display(client.bytes_rx);
            let seen_str = format!("{:.0}s", client.last_seen.as_secs_f64());

            lines.push(vline(
                &format!("{}  {}  {:>4}  {}  {}  {}",
                    s().dim().paint(&client.mac.to_string()),
                    prism::pad(&state_str, 8, "left"),
                    client.rssi,
                    prism::pad(&probe_ssid, 20, "left"),
                    prism::pad(&data_str, 8, "right"),
                    prism::pad(&seen_str, 6, "right")),
                inner_w));
        }
    } else if info.phase == ApPhase::Broadcasting || info.phase == ApPhase::Active {
        let spinner = prism::get_spinner("dots");
        let frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(vline(
            &format!("{} {}", s().cyan().paint(frame), s().dim().paint("Waiting for clients to connect...")),
            inner_w));
    }

    // ═══ KARMA SSIDs ═══
    if !info.karma_ssids.is_empty() {
        lines.push(empty_line());
        lines.push(vline(
            &format!("{} ({} collected)",
                s().green().bold().paint("KARMA SSIDs"),
                info.karma_ssids_collected),
            inner_w));

        let max_show = 12;
        let shown: Vec<&String> = info.karma_ssids.iter().rev().take(max_show).collect();
        for ssid in &shown {
            lines.push(vline(&format!("  {} {}", s().dim().paint("\u{25cf}"), ssid), inner_w));
        }
        if info.karma_ssids_collected as usize > max_show {
            lines.push(vline(
                &format!("  {} ... and {} more",
                    s().dim().paint("\u{25cf}"),
                    info.karma_ssids_collected as usize - max_show),
                inner_w));
        }
    }

    // ═══ Bottom border ═══
    lines.push(format!("  {}{}{}", bc("\u{2570}"),
        bc(&"\u{2500}".repeat(inner_w + 1)), bc("\u{256f}")));

    lines
}

/// Format byte count as human-readable string, with em-dash for zero.
fn format_bytes_display(bytes: u64) -> String {
    if bytes == 0 {
        "\u{2014}".to_string()
    } else {
        prism::format_bytes(bytes)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status bar segments
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate status bar segments for the AP attack.
pub fn status_segments(info: &ApInfo) -> Vec<StatusSegment> {
    let mut segs = Vec::new();

    if !info.running && info.phase == ApPhase::Idle {
        return segs;
    }

    let attack_text = if info.ssid.is_empty() {
        format!("ap {}: {}", info.mode.short_name(), phase_label(info.phase))
    } else {
        format!("ap {}: {} ({})", info.mode.short_name(), info.ssid, phase_label(info.phase))
    };

    segs.push(StatusSegment::new(attack_text, SegmentStyle::RedBold));

    if info.clients_connected > 0 {
        segs.push(StatusSegment::new(
            format!("{} clients", info.clients_connected),
            SegmentStyle::GreenBold,
        ));
    }

    if info.karma_ssids_collected > 0 {
        segs.push(StatusSegment::new(
            format!("{} SSIDs", info.karma_ssids_collected),
            SegmentStyle::Cyan,
        ));
    }

    if let Some(pct) = info.tx_feedback.delivery_pct() {
        segs.push(StatusSegment::new(format!("{}%tx", pct as u64), SegmentStyle::Dim));
    }

    let elapsed_secs = info.start_time.elapsed().as_secs_f64();
    segs.push(StatusSegment::new(format!("{:.1}s", elapsed_secs), SegmentStyle::Dim));

    segs
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ApModule — Module trait implementation
// ═══════════════════════════════════════════════════════════════════════════════

use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};
use crate::store::Ap;

/// ApModule wraps ApAttack with the Module trait for the shell's focus stack.
///
/// Delta-driven: subscribes to the streaming pipeline via UpdateSubscriber.
/// Events arrive as AttackEvent deltas, counters as AttackCountersUpdate, etc.
/// The module processes deltas in tick(), caches info, and queues scrollback lines.
pub struct ApModule {
    attack: ApAttack,
    /// Target AP for Evil Twin mode.
    target: Option<Ap>,
    /// Cached info for rendering — refreshed when deltas arrive.
    cached_info: Option<ApInfo>,
    /// Delta subscriber — receives StoreUpdate batches from the pipeline.
    update_sub: Option<UpdateSubscriber>,
    /// Attack ID learned from the first AttackStarted delta.
    attack_id: Option<AttackId>,
    /// Dirty flag — set when deltas arrive, cleared after info refresh.
    dirty: bool,
    /// Formatted scrollback lines accumulated from AttackEvent deltas.
    scrollback_lines: Vec<String>,
    /// FPS history for sparkline — accumulated from AttackCountersUpdate deltas.
    fps_history: VecDeque<f64>,
}

impl ApModule {
    pub fn new(params: ApParams) -> Self {
        let attack = ApAttack::new(params);
        Self {
            attack,
            target: None,
            cached_info: None,
            update_sub: None,
            attack_id: None,
            dirty: false,
            scrollback_lines: Vec::new(),
            fps_history: VecDeque::new(),
        }
    }

    /// Get the underlying attack.
    pub fn attack(&self) -> &ApAttack {
        &self.attack
    }

    /// Set target AP before starting (Evil Twin mode).
    pub fn set_target(&mut self, target: Ap) {
        self.target = Some(target);
    }

    /// Subscribe to the delta stream. Call BEFORE starting the attack
    /// so we don't miss early deltas (AttackStarted, first events).
    pub fn subscribe(&mut self, shared: &crate::adapter::SharedAdapter) {
        self.update_sub = Some(shared.gate().subscribe_updates("ap-ui"));
    }

    /// Process pending deltas from the subscriber.
    /// Filters for this attack's deltas, marks dirty, and accumulates scrollback lines.
    fn process_deltas(&mut self) {
        let sub = match &self.update_sub {
            Some(s) => s,
            None => return,
        };

        for update in sub.drain_flat() {
            match &update {
                StoreUpdate::AttackStarted { id, attack_type: AttackType::Ap, .. } => {
                    self.attack_id = Some(*id);
                    self.dirty = true;
                }
                StoreUpdate::AttackPhaseChanged { id, .. } if self.is_our_attack(*id) => {
                    self.dirty = true;
                }
                StoreUpdate::AttackCountersUpdate { id, frames_per_sec, .. } if self.is_our_attack(*id) => {
                    self.fps_history.push_back(*frames_per_sec);
                    const MAX_FPS_SAMPLES: usize = 60;
                    while self.fps_history.len() > MAX_FPS_SAMPLES {
                        self.fps_history.pop_front();
                    }
                    self.dirty = true;
                }
                StoreUpdate::AttackEvent { id, event: AttackEventKind::Ap(kind), timestamp, .. }
                    if self.is_our_attack(*id) =>
                {
                    let event = ApEvent { seq: 0, timestamp: *timestamp, kind: kind.clone() };
                    self.scrollback_lines.push(format_event(&event));
                    self.dirty = true;
                }
                StoreUpdate::AttackComplete { id, attack_type: AttackType::Ap, .. }
                    if self.is_our_attack(*id) =>
                {
                    self.dirty = true;
                }
                _ => {}
            }
        }
    }

    /// Check if an AttackId belongs to this module's attack.
    fn is_our_attack(&self, id: AttackId) -> bool {
        self.attack_id.is_some_and(|our_id| our_id == id)
    }

    /// Per-frame tick: process deltas, refresh cached info if dirty, return scrollback lines.
    pub fn tick(&mut self) -> Vec<String> {
        self.process_deltas();

        // Always refresh — attack info() is a cheap mutex clone, and values
        // like elapsed, beacons_sent, clients update continuously.
        self.cached_info = Some(self.attack.info());
        self.dirty = false;

        std::mem::take(&mut self.scrollback_lines)
    }

    /// Get current attack info. Used by the shell for external state access.
    #[allow(dead_code)]
    pub fn info(&self) -> ApInfo {
        self.attack.info()
    }
}

impl Module for ApModule {
    fn name(&self) -> &str { "ap" }
    fn description(&self) -> &str { "Rogue AP / Evil Twin / KARMA" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }

    fn start(&mut self, shared: crate::adapter::SharedAdapter) {
        // Subscribe to delta stream BEFORE starting attack thread
        self.update_sub = Some(shared.gate().subscribe_updates("ap-ui"));
        let target = self.target.take();
        self.attack.start(shared, target);
    }

    fn signal_stop(&self) {
        self.attack.signal_stop();
    }

    fn is_running(&self) -> bool {
        self.attack.is_running()
    }

    fn is_done(&self) -> bool {
        self.attack.is_done()
    }

    fn views(&self) -> &[ViewDef] {
        &[] // AP uses a single view
    }

    fn render(&mut self, _view: usize, width: u16, _height: u16) -> Vec<String> {
        let info = self.cached_info.clone().unwrap_or_else(|| self.attack.info());
        render_ap_view(&info, width, &self.fps_history)
    }

    fn handle_key(&mut self, _key: &prism::KeyEvent, _view: usize) -> bool {
        false
    }

    fn status_segments(&self) -> Vec<StatusSegment> {
        if let Some(ref info) = self.cached_info {
            status_segments(info)
        } else {
            vec![]
        }
    }

    fn freeze_summary(&self, width: u16) -> Vec<String> {
        let info = self.cached_info.clone()
            .unwrap_or_else(|| self.attack.info());
        let elapsed = info.start_time.elapsed();
        let ap_result = ApResult {
            mode: info.mode,
            ssid: info.ssid.clone(),
            channel: info.channel,
            clients_connected: info.clients_connected,
            credentials_captured: 0,
            elapsed,
        };
        let final_result = ApFinalResult {
            results: vec![ap_result],
            total_clients: info.clients_total,
            total_credentials: 0,
            elapsed,
        };
        let mut content_lines = Vec::new();
        content_lines.push(format!("Mode: {}", mode_display(info.mode)));
        content_lines.push(format!("SSID: {} (ch{})", info.ssid, info.channel));
        content_lines.push(format!("BSSID: {}", info.our_bssid));
        let client_str = if final_result.total_clients > 0 {
            let connected = if info.clients_connected > 0 {
                format!(" ({} still connected)", info.clients_connected)
            } else {
                String::new()
            };
            format!("{}{}", final_result.total_clients, connected)
        } else {
            "none".to_string()
        };
        content_lines.push(format!("Clients: {}", client_str));
        if info.karma_ssids_collected > 0 {
            content_lines.push(format!("KARMA SSIDs: {}", info.karma_ssids_collected));
        }
        content_lines.push(format!("Beacons: {}, Probes: {}, Deauths: {}",
            prism::format_number(info.beacons_sent),
            prism::format_number(info.probes_answered),
            prism::format_number(info.deauths_sent)));
        if info.bytes_rx > 0 {
            content_lines.push(format!("Data received: {}",
                prism::format_bytes(info.bytes_rx)));
        }
        content_lines.push(format!("Duration: {:.1}s", final_result.elapsed.as_secs_f64()));
        let content = content_lines.join("\n");
        let framed = prism::frame(&content, &prism::FrameOptions {
            border: prism::BorderStyle::Rounded,
            title: Some(format!("AP Attack ({}) Complete", info.mode.name())),
            width: Some((width as usize).saturating_sub(4)),
            ..Default::default()
        });
        framed.lines().map(|l| l.to_string()).collect()
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use crate::core::MacAddress;

    #[test]
    fn test_phase_labels() {
        assert_eq!(phase_label(ApPhase::Idle), "idle");
        assert_eq!(phase_label(ApPhase::Broadcasting), "broadcasting");
        assert_eq!(phase_label(ApPhase::Active), "active");
        assert_eq!(phase_label(ApPhase::Done), "done");
    }

    #[test]
    fn test_render_empty_info() {
        let info = ApInfo::default();
        let lines = render_ap_view(&info, 80, &VecDeque::new());
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_format_ap_started() {
        let event = ApEvent {
            seq: 1,
            timestamp: Duration::from_millis(100),
            kind: ApEventKind::ApStarted {
                bssid: MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]),
                ssid: "FreeWiFi".to_string(),
                mode: ApMode::Karma,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("AP"));
        assert!(formatted.contains("FreeWiFi"));
        assert!(formatted.contains("KARMA"));
    }

    #[test]
    fn test_format_karma_ssid() {
        let event = ApEvent {
            seq: 5,
            timestamp: Duration::from_secs(10),
            kind: ApEventKind::KarmaSsidCollected {
                ssid: "CorpNet".to_string(),
                mac: MacAddress::new([0xA4, 0x83, 0xE7, 0x12, 0x34, 0x56]),
                total: 15,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("KARMA"));
        assert!(formatted.contains("CorpNet"));
        assert!(formatted.contains("#15"));
    }

    #[test]
    fn test_format_client_associated() {
        let event = ApEvent {
            seq: 3,
            timestamp: Duration::from_secs(5),
            kind: ApEventKind::ClientAssociated {
                mac: MacAddress::new([0xA4, 0x83, 0xE7, 0x12, 0x34, 0x56]),
                aid: 1,
                rssi: -42,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("ASSOC"));
        assert!(formatted.contains("AID=1"));
    }

    #[test]
    fn test_status_segments_idle() {
        let info = ApInfo::default();
        let segs = status_segments(&info);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_status_segments_running() {
        let mut info = ApInfo::default();
        info.running = true;
        info.phase = ApPhase::Active;
        info.mode = ApMode::Karma;
        info.ssid = "FreeWiFi".to_string();
        info.clients_connected = 3;
        info.karma_ssids_collected = 12;
        let segs = status_segments(&info);
        assert!(segs.len() >= 3);
    }

    #[test]
    fn test_format_bytes_display() {
        assert_eq!(format_bytes_display(0), "\u{2014}");
        // Non-zero values use prism::format_bytes
        assert!(!format_bytes_display(512).is_empty());
        assert!(!format_bytes_display(2048).is_empty());
        assert!(!format_bytes_display(1048576).is_empty());
    }

    #[test]
    fn test_format_deauth_burst() {
        let event = ApEvent {
            seq: 2,
            timestamp: Duration::from_millis(500),
            kind: ApEventKind::DeauthBurst {
                target_bssid: MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]),
                count: 5,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("DEAUTH"));
        assert!(formatted.contains("5"));
    }
}
