//! CLI renderer + Module implementation for the DoS attack.
//!
//! Renders the attack progress as styled terminal lines:
//! - Attack type + target AP info
//! - Frame counter + rate (fps) + elapsed time
//! - Connected clients table (from scanner) — shows who drops off during attack
//! - Event log scrollback
//!
//! The client monitoring feature works because the scanner keeps running on
//! the locked channel during the attack. Stations that stop sending frames
//! have likely been disconnected by the DoS.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::attacks::dos::{
    DosAttack, DosEvent, DosEventKind, DosInfo, DosParams,
    DosPhase, StopReason,
};
use crate::core::MacAddress;
use crate::pipeline::UpdateSubscriber;
use crate::store::update::{AttackEventKind, AttackId, AttackType, StoreUpdate};

use prism::{s, truncate, FrameOptions, BorderStyle};
use crate::cli::scanner::style::{rssi_sparkline, snr_sparkline, style_snr, snr_badge};
use super::{signal_bar, fps_sparkline, tx_stats_line};

// ═══════════════════════════════════════════════════════════════════════════════
//  Phase display
// ═══════════════════════════════════════════════════════════════════════════════

fn phase_label(phase: DosPhase) -> &'static str {
    match phase {
        DosPhase::Idle => "idle",
        DosPhase::ChannelLock => "locking channel",
        DosPhase::Flooding => "flooding",
        DosPhase::Cooldown => "cooldown",
        DosPhase::Done => "done",
    }
}

fn stop_reason_label(reason: StopReason) -> &'static str {
    match reason {
        StopReason::UserStopped => "stopped by user",
        StopReason::DurationReached => "duration limit reached",
        StopReason::FrameCountReached => "frame count reached",
        StopReason::ChannelError => "channel lock failed",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Event formatting — for scrollback output
// ═══════════════════════════════════════════════════════════════════════════════

/// Format a DoS event as a styled terminal line for the output zone.
pub fn format_event(event: &DosEvent) -> String {
    let ts = format!("{:>7.3}s", event.timestamp.as_secs_f64());
    let ts_styled = s().dim().paint(&ts);

    match &event.kind {
        DosEventKind::AttackStarted { attack_type, bssid, ssid, channel, station } => {
            let target_str = if let Some(sta) = station {
                format!("  \u{2192} client {}",  s().bold().paint(&sta.to_string()))
            } else {
                String::new()
            };
            format!("  [{}] {} {}  {}  {}  ch{}{}",
                ts_styled,
                s().red().bold().paint("DOS"),
                s().cyan().bold().paint(attack_type.label()),
                s().bold().paint(ssid),
                s().dim().paint(&bssid.to_string()),
                channel,
                target_str)
        }
        DosEventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts_styled, s().dim().paint("LOCK"), channel)
        }
        DosEventKind::FloodingStarted => {
            format!("  [{}] {} Frame injection started", ts_styled, s().red().paint("FLOOD"))
        }
        DosEventKind::RateSnapshot { frames_sent, frames_per_sec, elapsed, bytes_sent } => {
            let rate = format_rate(*frames_per_sec);
            let bytes = prism::format_bytes(*bytes_sent);
            format!("  [{}] {} {} frames  {}  {}  {:.1}s",
                ts_styled,
                s().dim().paint("RATE"),
                s().bold().paint(&prism::format_number(*frames_sent)),
                rate,
                s().dim().paint(&bytes),
                prism::format_time((elapsed.as_secs_f64() * 1000.0) as u64))
        }
        DosEventKind::BurstPause { burst_num, frames_in_burst, pause_secs } => {
            format!("  [{}] {} Burst #{} ({} frames) — pausing {:.0}s",
                ts_styled,
                s().cyan().paint("PAUSE"),
                burst_num,
                frames_in_burst,
                pause_secs)
        }
        DosEventKind::AttackComplete { frames_sent, elapsed, reason } => {
            let reason_str = stop_reason_label(*reason);
            format!("  [{}] {} {} — {} frames in {:.1}s ({})",
                ts_styled,
                s().bold().paint("DONE"),
                s().green().bold().paint("DoS attack complete"),
                prism::format_number(*frames_sent),
                prism::format_time((elapsed.as_secs_f64() * 1000.0) as u64),
                s().dim().paint(reason_str))
        }
        DosEventKind::CooldownStarted { duration_secs } => {
            format!("  [{}] {} Capturing late reconnections for {:.0}s — TX stopped, channel locked",
                ts_styled, s().cyan().bold().paint("COOLDOWN"), duration_secs)
        }
        DosEventKind::ChannelUnlocked => {
            format!("  [{}] {} Channel unlocked — scanner resumes hopping",
                ts_styled, s().dim().paint("UNLOCK"))
        }
        DosEventKind::Error { message } => {
            format!("  [{}] {} {}", ts_styled, s().red().bold().paint("ERROR"), message)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Active zone view — rendered in the Layout active zone during attack
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-client EAPOL state tracked during the attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEapolState {
    None,
    M1,
    M2,
    Captured,
}

/// Client snapshot for the DoS view — pulled from the scanner each render cycle.
#[derive(Debug, Clone)]
pub struct ClientSnapshot {
    pub mac: MacAddress,
    pub rssi: i8,
    pub snr: u8,
    pub last_seen: Instant,
    pub frame_count: u32,
    pub vendor: String,
    /// When the client was last seen quiet (>5s) before coming back.
    /// Set by update_target_clients when it detects a reconnection.
    pub reconnect_at: Option<Instant>,
    /// RSSI history for sparkline rendering — pulled from Station.rssi_samples.
    pub rssi_samples: VecDeque<(Duration, i8)>,
    /// SNR history for sparkline rendering — pulled from Station.snr_samples.
    pub snr_samples: VecDeque<(Duration, u8)>,
    /// Per-client EAPOL state — set by the module from delta stream.
    pub eapol_state: ClientEapolState,
}

/// Render the DoS attack progress view for the Layout active zone.
pub fn render_dos_view(info: &DosInfo, clients: &[ClientSnapshot], width: u16, fps_history: &VecDeque<f64>) -> Vec<String> {
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

    // ═══ Header border with attack type title ═══
    let title = format!(" {} ", info.attack_type.label());
    let title_styled = s().red().bold().paint(&title);
    let title_plain_w = prism::measure_width(&title);
    let remaining = inner_w.saturating_sub(title_plain_w + 1);
    lines.push(format!("  {}{}{}{}", bc("\u{256d}\u{2500}"), title_styled,
        bc(&"\u{2500}".repeat(remaining)), bc("\u{256e}")));

    lines.push(empty_line());

    // ═══ Target info ═══
    let ssid_display = if info.target_ssid.is_empty() {
        s().dim().italic().paint("(hidden)")
    } else {
        s().bold().paint(&prism::truncate(&info.target_ssid, 24, "\u{2026}"))
    };

    // Signal bar (shared helper)
    let signal = signal_bar(info.target_rssi);

    let target_line = format!("{}  {}  ch{}  {}  {}dBm",
        ssid_display,
        s().dim().paint(&info.target_bssid.to_string()),
        info.target_channel,
        signal,
        s().dim().paint(&format!("{}", info.target_rssi)),
    );
    lines.push(vline(&target_line, inner_w));

    // Station target (if targeted attack)
    if let Some(sta) = &info.target_station {
        lines.push(vline(&format!("\u{2192} client {}", s().bold().paint(&sta.to_string())), inner_w));
    }

    // ═══ Step progress ═══
    if info.running || info.phase == DosPhase::Done {
        let spinner = prism::get_spinner("dots");
        let spin_frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let lock_step = match info.phase {
            DosPhase::Idle => format!("{} LOCK", s().dim().paint("\u{25cb}")),
            DosPhase::ChannelLock => format!("{} LOCK", s().yellow().paint(spin_frame)),
            _ => format!("{} LOCK", s().green().paint("\u{2714}")),
        };

        let flood_step = match info.phase {
            DosPhase::Idle | DosPhase::ChannelLock =>
                format!("{} FLOOD", s().dim().paint("\u{25cb}")),
            DosPhase::Flooding => format!("{} FLOOD", s().red().bold().paint(spin_frame)),
            _ => format!("{} FLOOD", s().green().paint("\u{2714}")),
        };

        let cooldown_step = match info.phase {
            DosPhase::Cooldown => format!("{} CAPTURE", s().cyan().paint(spin_frame)),
            DosPhase::Done => format!("{} CAPTURE", s().green().paint("\u{2714}")),
            _ => format!("{} CAPTURE", s().dim().paint("\u{25cb}")),
        };

        let arrow = s().dim().paint(" \u{2192} ");
        let steps = format!("{}{}{}{}{}", lock_step, arrow, flood_step, arrow, cooldown_step);

        // Append FPS sparkline to the step line when we have throughput data
        if fps_history.len() > 1 {
            let spark = fps_sparkline(fps_history, 12);
            lines.push(vline(&format!("{}  {}", steps, spark), inner_w));
        } else {
            lines.push(vline(&steps, inner_w));
        }
    }

    lines.push(empty_line());

    // ═══ Stats line ═══
    if info.phase == DosPhase::Flooding || info.phase == DosPhase::Done || info.phase == DosPhase::Cooldown {
        let elapsed_fmt = prism::format_time((info.start_time.elapsed().as_secs_f64() * 1000.0) as u64);
        let rate = format_rate(info.frames_per_sec);
        let mut stats = format!("{} sent  {} recv  {}  {}  {}",
            s().red().bold().paint(&prism::format_number(info.frames_sent)),
            s().dim().paint(&prism::format_number(info.frames_received)),
            rate,
            s().dim().paint(&prism::format_bytes(info.bytes_sent)),
            elapsed_fmt);
        if info.tx_feedback.total_reports > 0 {
            let pct = info.tx_feedback.delivery_pct().unwrap_or(0.0);
            stats.push_str(&format!("  {} ack  {} nack ({}%)",
                s().green().paint(&prism::format_number(info.tx_feedback.acked)),
                s().red().paint(&prism::format_number(info.tx_feedback.nacked)),
                s().bold().paint(&format!("{:.0}", pct))));
        }
        lines.push(vline(&stats, inner_w));

        // TX delivery bar + compact stats (shared helper)
        if let Some(tx_line) = tx_stats_line(&info.tx_feedback, info.frames_sent, info.frames_per_sec) {
            lines.push(vline(&tx_line, inner_w));
        }
    }

    // Cooldown progress bar
    if info.phase == DosPhase::Cooldown {
        if let Some(cooldown_start) = info.cooldown_start {
            let elapsed = cooldown_start.elapsed();
            let total_secs = info.cooldown_duration.as_secs_f64();
            let remaining = (total_secs - elapsed.as_secs_f64()).max(0.0);
            let progress = (elapsed.as_secs_f64() / total_secs).min(1.0);

            let bar_width = inner_w.saturating_sub(30).min(40);
            fn cyan_bar(t: &str) -> String { s().cyan().paint(t) }
            let bar = prism::render_progress_bar(
                (progress * 100.0) as u64,
                &prism::RenderOptions {
                    total: 100, width: bar_width,
                    style: prism::BarStyle::Smooth,
                    color: Some(cyan_bar), ..Default::default()
                },
            );
            lines.push(vline(
                &format!("{} {} {:.0}s remaining",
                    s().cyan().bold().paint("\u{25f7}"), bar, remaining),
                inner_w));
        }
    }

    lines.push(empty_line());

    // ═══ Client table — attack-semantic status ═══
    //
    // During deauth, clients disconnect and reconnect within 1-3 seconds.
    // Thresholds tuned for attack tempo, not passive scanning:
    //   ⟳ yellow  = reconnect cycle — deauth landing, client coming back (EAPOL window!)
    //   ● red     = still active (<2s) — deauth not working on this client
    //   ○ dim     = going quiet (2-8s) — might be dropping
    //   ✓ green   = dropped (>8s silence) — deauth SUCCESS
    if !clients.is_empty() {
        lines.push(vline(
            &format!("{}  {}  {}  {}  {}  {}  {}  {}",
                s().bold().dim().paint(&prism::pad("CLIENT", 17, "left")),
                s().bold().dim().paint(&prism::pad("SIGNAL", 13, "left")),
                s().bold().dim().paint(&prism::pad("SNR", 13, "left")),
                s().bold().dim().paint(&prism::pad("CAPT", 5, "left")),
                s().bold().dim().paint(&prism::pad("FRAMES", 8, "left")),
                s().bold().dim().paint(&prism::pad("LAST SEEN", 8, "left")),
                s().bold().dim().paint(&prism::pad("STATUS", 10, "left")),
                s().bold().dim().paint(&prism::pad("VENDOR", 15, "left"))),
            inner_w));

        let now = Instant::now();
        for client in clients {
            let age = now.duration_since(client.last_seen);
            let age_str = format_age(age);

            let is_reconnecting = client.reconnect_at
                .map(|t| now.duration_since(t) < Duration::from_secs(4))
                .unwrap_or(false);

            // Attack-semantic status — priority order:
            //   1. captured  — M1+M2 from this client (goal achieved)
            //   2. capturing — EAPOL M1 or M2 in progress (handshake happening)
            //   3. reconnect — was quiet, now active again (disconnect confirmed)
            //   4. active    — sending frames right now (deauth not working yet)
            //   5. quiet     — was active, now silent (might be dropping)
            //   6. dropped   — silent >8s (deauth success)
            let (status_icon, status_label, mac_styled) = if client.eapol_state == ClientEapolState::Captured {
                (s().green().bold().paint("\u{2605}"),
                 s().green().bold().paint("captured"),
                 s().green().bold().paint(&client.mac.to_string()))
            } else if client.eapol_state == ClientEapolState::M2 {
                (s().cyan().bold().paint("\u{25b6}"),
                 s().cyan().bold().paint("capturing"),
                 s().cyan().bold().paint(&client.mac.to_string()))
            } else if client.eapol_state == ClientEapolState::M1 {
                (s().cyan().paint("\u{25b7}"),
                 s().cyan().paint("M1 seen"),
                 s().cyan().paint(&client.mac.to_string()))
            } else if is_reconnecting {
                (s().yellow().bold().paint("\u{27f3}"),
                 s().yellow().bold().paint("reconnect"),
                 s().yellow().bold().paint(&client.mac.to_string()))
            } else if age < Duration::from_secs(2) {
                (s().red().paint("\u{25cf}"),
                 s().red().paint("active"),
                 s().red().paint(&client.mac.to_string()))
            } else if age < Duration::from_secs(8) {
                (s().dim().paint("\u{25cb}"),
                 s().dim().paint("quiet"),
                 s().dim().paint(&client.mac.to_string()))
            } else {
                (s().green().paint("\u{2713}"),
                 s().green().paint("dropped"),
                 s().green().paint(&client.mac.to_string()))
            };

            // RSSI sparkline + current value
            let spark = rssi_sparkline(&client.rssi_samples, 8);
            let rssi_num = format!("{}", client.rssi);
            let signal_col = format!("{} {}", spark, prism::pad(&rssi_num, 4, "left"));

            // SNR sparkline + current value + capture quality badge
            let snr_spark = snr_sparkline(&client.snr_samples, 8);
            let snr_num = style_snr(client.snr);
            let snr_col = format!("{} {}", snr_spark, prism::pad(&snr_num, 4, "left"));
            let capt_badge = snr_badge(client.snr);

            let vendor_display = truncate(&client.vendor, 15, "\u{2026}");
            let frames_str = prism::format_number(client.frame_count as u64);

            lines.push(vline(
                &format!("{} {}  {}  {}  {}  {}  {}  {}  {}",
                    status_icon,
                    prism::pad(&mac_styled, 17, "left"),
                    prism::pad(&signal_col, 13, "left"),
                    prism::pad(&snr_col, 13, "left"),
                    prism::pad(&capt_badge, 5, "left"),
                    prism::pad(&frames_str, 8, "right"),
                    prism::pad(&s().dim().paint(&age_str), 8, "left"),
                    prism::pad(&status_label, 10, "left"),
                    s().dim().paint(&vendor_display)),
                inner_w));
        }
    } else if info.phase == DosPhase::Flooding {
        lines.push(vline(
            &format!("{} {}", s().dim().paint("\u{25cb}"),
                s().dim().paint("No clients associated with target AP")),
            inner_w));
    } else if info.phase == DosPhase::ChannelLock {
        let spinner = prism::get_spinner("dots");
        let frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(vline(
            &format!("{} {}", s().cyan().paint(frame), s().dim().paint("Locking channel...")),
            inner_w));
    }

    // ═══ Bottom border ═══
    lines.push(format!("  {}{}{}", bc("\u{2570}"),
        bc(&"\u{2500}".repeat(inner_w + 1)), bc("\u{256f}")));

    lines
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status bar segments
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate status bar segments for the DoS attack.
pub fn status_segments(info: &DosInfo) -> Vec<StatusSegment> {
    let mut segs = Vec::new();

    if !info.running && info.phase == DosPhase::Idle {
        return segs;
    }

    // Attack type + target: "deauth-flood: Larissazoe5G (flooding)"
    let attack_text = if info.target_ssid.is_empty() {
        format!("{}: {}", info.attack_type.label(), phase_label(info.phase))
    } else {
        format!("{}: {} ({})", info.attack_type.label(), info.target_ssid, phase_label(info.phase))
    };

    segs.push(StatusSegment::new(attack_text, SegmentStyle::RedBold));

    // Target channel
    if info.target_channel > 0 {
        segs.push(StatusSegment::new(format!("ch:{}", info.target_channel), SegmentStyle::Bold));
    }

    // Frames sent
    if info.frames_sent > 0 {
        segs.push(StatusSegment::new(
            format!("{} sent", prism::format_number(info.frames_sent)),
            SegmentStyle::Yellow,
        ));
    }

    // TX rate
    if info.frames_per_sec > 0.0 {
        segs.push(StatusSegment::new(format!("{:.0} fps", info.frames_per_sec), SegmentStyle::Yellow));
    }

    // Elapsed time
    segs.push(StatusSegment::new(prism::format_time((info.start_time.elapsed().as_secs_f64() * 1000.0) as u64), SegmentStyle::Dim));

    // Bytes sent
    if info.bytes_sent > 0 {
        segs.push(StatusSegment::new(prism::format_bytes(info.bytes_sent), SegmentStyle::Dim));
    }

    // TX delivery rate
    if let Some(pct) = info.tx_feedback.delivery_pct() {
        let style = if pct > 80.0 { SegmentStyle::Green }
            else if pct > 50.0 { SegmentStyle::Yellow }
            else { SegmentStyle::Red };
        segs.push(StatusSegment::new(format!("{:.0}% delivered", pct), style));
    }

    segs
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Format frames/sec as a styled rate string.
fn format_rate(fps: f64) -> String {
    let fps_str = if fps >= 1000.0 {
        format!("{} fps", prism::format_compact(fps as u64))
    } else if fps >= 1.0 {
        format!("{:.0} fps", fps)
    } else if fps > 0.0 {
        format!("{:.1} fps", fps)
    } else {
        "0 fps".to_string()
    };
    if fps > 1000.0 {
        s().yellow().bold().paint(&fps_str)
    } else {
        s().yellow().paint(&fps_str)
    }
}

/// Format a duration as a fixed-width (7 char) age string.
/// Fixed width prevents column misalignment when age changes.
fn format_age(age: Duration) -> String {
    let secs = age.as_secs();
    if secs < 2 {
        "   now ".to_string()
    } else if secs < 10 {
        format!("  {}s ago", secs)
    } else if secs < 60 {
        format!(" {}s ago", secs)
    } else if secs < 600 {
        format!("{}m{:02}s  ", secs / 60, secs % 60)
    } else {
        format!("{:>4}m  ", secs / 60)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DosModule — Module trait implementation for DoS attack
// ═══════════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};
use crate::protocol::eapol::HandshakeMessage;
use crate::store::Station;

/// DosModule wraps DosAttack with the Module trait for the shell's focus stack.
pub struct DosModule {
    attack: DosAttack,
    target: Option<Ap>,
    target_station: Option<Station>,
    cached_info: Option<DosInfo>,
    target_clients: Vec<ClientSnapshot>,
    update_sub: Option<UpdateSubscriber>,
    attack_id: Option<AttackId>,
    dirty: bool,
    scrollback_lines: Vec<String>,
    fps_history: VecDeque<f64>,
    /// Per-client EAPOL state — populated from EapolMessage deltas.
    client_eapol: HashMap<MacAddress, ClientEapolState>,
    /// Target BSSID — for filtering EAPOL deltas.
    target_bssid: Option<MacAddress>,
}

use crate::store::Ap;

impl DosModule {
    pub fn new(params: DosParams) -> Self {
        let attack = DosAttack::new(params);
        Self {
            attack,
            target: None,
            target_station: None,
            cached_info: None,
            target_clients: Vec::new(),
            update_sub: None,
            attack_id: None,
            dirty: false,
            scrollback_lines: Vec::new(),
            fps_history: VecDeque::new(),
            client_eapol: HashMap::new(),
            target_bssid: None,
        }
    }

    /// Get the underlying attack for starting with targets.
    pub fn attack(&self) -> &DosAttack {
        &self.attack
    }

    /// Set target AP and optional station before starting.
    pub fn set_targets(&mut self, target: Ap, station: Option<Station>) {
        self.target_bssid = Some(target.bssid);
        self.target = Some(target);
        self.target_station = station;
    }

    /// Get current attack info.
    pub fn info(&self) -> DosInfo {
        self.attack.info()
    }

    /// Subscribe to the delta stream. Call BEFORE starting the attack
    /// so we don't miss early deltas (AttackStarted, first events).
    pub fn subscribe(&mut self, shared: &crate::adapter::SharedAdapter) {
        self.update_sub = Some(shared.gate().subscribe_updates("dos-ui"));
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
                // ── Per-client EAPOL tracking ──
                StoreUpdate::EapolMessage { ap_mac, sta_mac, message, quality, .. }
                    if self.target_bssid.is_some_and(|b| b == *ap_mac) =>
                {
                    let entry = self.client_eapol.entry(*sta_mac).or_insert(ClientEapolState::None);
                    match message {
                        HandshakeMessage::M1 => {
                            if *entry == ClientEapolState::None {
                                *entry = ClientEapolState::M1;
                            }
                        }
                        HandshakeMessage::M2 => {
                            *entry = ClientEapolState::M2;
                        }
                        _ => {}
                    }
                    if *quality >= crate::protocol::eapol::HandshakeQuality::M1M2 {
                        *entry = ClientEapolState::Captured;
                    }
                    self.dirty = true;
                }
                StoreUpdate::HandshakeComplete { ap_mac, sta_mac, .. }
                    if self.target_bssid.is_some_and(|b| b == *ap_mac) =>
                {
                    self.client_eapol.insert(*sta_mac, ClientEapolState::Captured);
                    self.dirty = true;
                }

                // ── Attack lifecycle deltas ──
                StoreUpdate::AttackStarted { id, attack_type: AttackType::Dos, .. } => {
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
                StoreUpdate::AttackEvent { id, event: AttackEventKind::Dos(kind), timestamp, .. }
                    if self.is_our_attack(*id) =>
                {
                    let event = DosEvent { seq: 0, timestamp: *timestamp, kind: kind.clone() };
                    self.scrollback_lines.push(format_event(&event));
                    self.dirty = true;
                }
                StoreUpdate::AttackComplete { id, attack_type: AttackType::Dos, .. }
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
    ///
    /// Called by poll_modules() every frame. This is the single entry point for
    /// delta processing -- render() and status_segments() just read cached_info.
    pub fn tick(&mut self) -> Vec<String> {
        self.process_deltas();

        // Always refresh — attack info() is a cheap mutex clone, and values
        // like elapsed, frames_received, fps update continuously between
        // delta emissions (e.g. during burst pauses in deauth).
        self.cached_info = Some(self.attack.info());
        self.dirty = false;

        std::mem::take(&mut self.scrollback_lines)
    }

    /// Update connected clients of the target AP (called by shell from scanner data).
    /// This enables the client monitoring UX: showing who drops off during the attack.
    /// Detects reconnections: if a client was quiet then active again, marks it
    /// with `reconnect_at` for a visual flash effect.
    ///
    /// Thresholds tuned for deauth tempo: clients disconnect/reconnect in 1-3s,
    /// so we detect reconnection at 2s quiet (not 5s which misses every cycle).
    pub fn update_target_clients(&mut self, mut clients: Vec<ClientSnapshot>) {
        let now = Instant::now();

        for client in &mut clients {
            // Apply per-client EAPOL state from our tracking
            if let Some(&state) = self.client_eapol.get(&client.mac) {
                client.eapol_state = state;
            }

            // Check if this client existed in previous snapshot
            if let Some(prev) = self.target_clients.iter().find(|c| c.mac == client.mac) {
                let prev_age = now.duration_since(prev.last_seen);
                let cur_age = now.duration_since(client.last_seen);

                // Client was quiet (>2s) but is now active again (<2s) → reconnection!
                // Tuned for deauth: clients typically reconnect within 1-3 seconds.
                if prev_age > Duration::from_secs(2) && cur_age < Duration::from_secs(2) {
                    client.reconnect_at = Some(now);
                } else if let Some(prev_reconnect) = prev.reconnect_at {
                    // Carry forward reconnect_at if still within flash window (4s)
                    if now.duration_since(prev_reconnect) < Duration::from_secs(4) {
                        client.reconnect_at = Some(prev_reconnect);
                    }
                }
            }
        }

        self.target_clients = clients;
    }
}

impl Module for DosModule {
    fn name(&self) -> &str { "dos" }
    fn description(&self) -> &str { "DoS attack" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }

    fn start(&mut self, shared: crate::adapter::SharedAdapter) {
        // Subscribe to delta stream BEFORE starting attack thread
        // so we don't miss any early deltas (like AttackStarted).
        self.update_sub = Some(shared.gate().subscribe_updates("dos-ui"));

        if let Some(target) = self.target.take() {
            let station = self.target_station.take();
            self.attack.start(shared, target, station);
        }
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
        &[] // DoS uses a single view — no tabs
    }

    fn render(&mut self, _view: usize, width: u16, _height: u16) -> Vec<String> {
        // tick() is called by poll_modules() before render, so cached_info is fresh.
        // Fallback: if no cached info yet (first frame), read directly.
        let info = self.cached_info.clone().unwrap_or_else(|| self.attack.info());
        render_dos_view(&info, &self.target_clients, width, &self.fps_history)
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

        let reason_str = info.stop_reason
            .map(|r| stop_reason_label(r))
            .unwrap_or("completed");

        let tx_line = if info.tx_feedback.total_reports > 0 {
            let pct = info.tx_feedback.delivery_pct().unwrap_or(0.0);
            format!("\nTX: {} ack  {} nack  ({:.0}% delivered)",
                prism::format_number(info.tx_feedback.acked),
                prism::format_number(info.tx_feedback.nacked),
                pct)
        } else {
            String::new()
        };

        let content = format!(
            "Target: {} ({})\nType: {}\nFrames: {} ({} fps)\nDuration: {}  |  {} sent{}\nReason: {}",
            info.target_ssid,
            info.target_bssid,
            info.attack_type.label(),
            prism::format_number(info.frames_sent),
            if info.frames_per_sec >= 1.0 { prism::format_compact(info.frames_per_sec as u64) } else { format!("{:.1}", info.frames_per_sec) },
            prism::format_time((info.elapsed.as_secs_f64() * 1000.0) as u64),
            prism::format_bytes(info.bytes_sent),
            tx_line,
            reason_str,
        );

        let frame_width = (width as usize).saturating_sub(4);
        let framed = prism::frame(&content, &FrameOptions {
            border: BorderStyle::Rounded,
            title: Some("DoS Attack Complete".into()),
            width: Some(frame_width),
            ..Default::default()
        });

        let mut lines = Vec::new();
        lines.push(String::new());
        for line in framed.lines() {
            lines.push(format!("  {}", line));
        }
        lines.push(String::new());
        lines
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attacks::dos::DosType;
    use std::time::Duration;

    #[test]
    fn test_phase_labels() {
        assert_eq!(phase_label(DosPhase::Idle), "idle");
        assert_eq!(phase_label(DosPhase::ChannelLock), "locking channel");
        assert_eq!(phase_label(DosPhase::Flooding), "flooding");
        assert_eq!(phase_label(DosPhase::Done), "done");
    }

    #[test]
    fn test_prism_format_number() {
        assert_eq!(prism::format_number(0), "0");
        assert_eq!(prism::format_number(999), "999");
        assert_eq!(prism::format_number(1000), "1,000");
        assert_eq!(prism::format_number(1234567), "1,234,567");
        assert_eq!(prism::format_number(42000), "42,000");
    }

    #[test]
    fn test_prism_format_bytes() {
        assert_eq!(prism::format_bytes(0), "0 B");
        assert_eq!(prism::format_bytes(512), "512 B");
        assert_eq!(prism::format_bytes(1024), "1.0 KB");
        assert_eq!(prism::format_bytes(1536), "1.5 KB");
        assert_eq!(prism::format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn test_format_age() {
        assert_eq!(format_age(Duration::from_secs(0)), "   now ");
        assert_eq!(format_age(Duration::from_secs(1)), "   now ");
        assert_eq!(format_age(Duration::from_secs(5)), "  5s ago");
        assert_eq!(format_age(Duration::from_secs(15)), " 15s ago");
        assert_eq!(format_age(Duration::from_secs(65)), "1m05s  ");
    }

    #[test]
    fn test_render_empty_info() {
        let info = DosInfo::default();
        let lines = render_dos_view(&info, &[], 80, &VecDeque::new());
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_render_with_clients() {
        let mut info = DosInfo::default();
        info.phase = DosPhase::Flooding;
        info.running = true;
        info.attack_type = DosType::DeauthFlood;
        info.target_ssid = "TestAP".to_string();
        info.target_bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        info.target_channel = 6;
        info.target_rssi = -42;
        info.frames_sent = 5000;
        info.frames_per_sec = 850.0;

        let clients = vec![
            ClientSnapshot {
                mac: MacAddress::new([0xA4, 0x83, 0xE7, 0x12, 0x34, 0x56]),
                rssi: -38,
                snr: 28,
                last_seen: Instant::now(),
                frame_count: 247,
                vendor: "Apple".to_string(),
                reconnect_at: None,
                rssi_samples: VecDeque::new(),
                snr_samples: VecDeque::new(),
                eapol_state: ClientEapolState::None,
            },
            ClientSnapshot {
                mac: MacAddress::new([0x8C, 0x85, 0x90, 0xAB, 0xCD, 0xEF]),
                rssi: -52,
                snr: 9,
                last_seen: Instant::now() - Duration::from_secs(20),
                frame_count: 12,
                vendor: "Samsung".to_string(),
                reconnect_at: None,
                rssi_samples: VecDeque::new(),
                snr_samples: VecDeque::new(),
                eapol_state: ClientEapolState::None,
            },
        ];

        let lines = render_dos_view(&info, &clients, 100, &VecDeque::new());
        // Should have header + counters + separator + column header + 2 client rows
        assert!(lines.len() >= 6);
    }

    #[test]
    fn test_format_event_attack_started() {
        let event = DosEvent {
            seq: 1,
            timestamp: Duration::from_millis(100),
            kind: DosEventKind::AttackStarted {
                attack_type: DosType::DeauthFlood,
                bssid: MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]),
                ssid: "TestAP".to_string(),
                channel: 6,
                station: None,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("DOS"));
        assert!(formatted.contains("deauth-flood"));
        assert!(formatted.contains("TestAP"));
    }

    #[test]
    fn test_format_event_rate_snapshot() {
        let event = DosEvent {
            seq: 5,
            timestamp: Duration::from_secs(3),
            kind: DosEventKind::RateSnapshot {
                frames_sent: 42000,
                frames_per_sec: 14000.0,
                elapsed: Duration::from_secs(3),
                bytes_sent: 1092000,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("RATE"));
        assert!(formatted.contains("42,000"));
    }

    #[test]
    fn test_format_event_attack_complete() {
        let event = DosEvent {
            seq: 10,
            timestamp: Duration::from_secs(30),
            kind: DosEventKind::AttackComplete {
                frames_sent: 420000,
                elapsed: Duration::from_secs(30),
                reason: StopReason::UserStopped,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("DONE"));
        assert!(formatted.contains("420,000"));
        assert!(formatted.contains("stopped by user"));
    }

    #[test]
    fn test_status_segments_idle() {
        let info = DosInfo::default();
        let segs = status_segments(&info);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_status_segments_running() {
        let mut info = DosInfo::default();
        info.running = true;
        info.phase = DosPhase::Flooding;
        info.attack_type = DosType::DeauthFlood;
        info.target_ssid = "TestAP".to_string();
        info.frames_sent = 5000;
        info.frames_per_sec = 850.0;
        let segs = status_segments(&info);
        assert!(segs.len() >= 3);
    }

    #[test]
    fn test_stop_reason_labels() {
        assert_eq!(stop_reason_label(StopReason::UserStopped), "stopped by user");
        assert_eq!(stop_reason_label(StopReason::DurationReached), "duration limit reached");
        assert_eq!(stop_reason_label(StopReason::FrameCountReached), "frame count reached");
        assert_eq!(stop_reason_label(StopReason::ChannelError), "channel lock failed");
    }
}
