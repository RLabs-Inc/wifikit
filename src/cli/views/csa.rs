//! CLI renderer + Module implementation for the CSA injection attack.
//!
//! Renders the attack progress as styled terminal lines:
//! - Target AP info with PMF status prominently displayed
//! - Phase progress: STIMULATE → CSA → LISTEN → CAPTURE
//! - Handshake capture status (quality, PMKID, M1/M2 indicators)
//! - Connected clients table with per-client status
//! - Attack strategy breakdown (CSA beacons, deauths, stimulation frames)
//! - Event log scrollback

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::attacks::csa::{
    CsaAttack, CsaEvent, CsaEventKind, CsaInfo, CsaParams,
    CsaPhase, CsaStopReason, PmfStatus,
};
use crate::core::MacAddress;
use crate::pipeline::UpdateSubscriber;
use crate::protocol::eapol::HandshakeQuality;
use crate::store::update::{AttackEventKind, AttackId, AttackType, StoreUpdate};

use prism::{s, truncate};
use crate::cli::scanner::style::{rssi_sparkline, snr_sparkline, style_snr, snr_badge};
use super::{signal_bar, fps_sparkline, tx_stats_line};

// ═══════════════════════════════════════════════════════════════════════════════
//  Phase + event formatting
// ═══════════════════════════════════════════════════════════════════════════════

fn phase_label(phase: CsaPhase) -> &'static str {
    match phase {
        CsaPhase::Idle => "idle",
        CsaPhase::ChannelLock => "locking channel",
        CsaPhase::Stimulating => "stimulating",
        CsaPhase::CsaBurst => "CSA injection",
        CsaPhase::Listening => "listening",
        CsaPhase::Cooldown => "cooldown",
        CsaPhase::Done => "done",
    }
}

fn stop_reason_label(reason: CsaStopReason) -> &'static str {
    match reason {
        CsaStopReason::UserStopped => "stopped by user",
        CsaStopReason::HandshakeCaptured => "handshake captured!",
        CsaStopReason::MaxRoundsReached => "max rounds reached",
        CsaStopReason::ChannelError => "channel lock failed",
    }
}

fn pmf_styled(pmf: PmfStatus) -> String {
    match pmf {
        PmfStatus::None => s().dim().paint("PMF:off"),
        PmfStatus::Capable => s().yellow().paint("PMF:capable"),
        PmfStatus::Required => s().red().bold().paint("PMF:required"),
    }
}

fn quality_styled(quality: HandshakeQuality) -> String {
    match quality {
        HandshakeQuality::None => s().dim().paint("none"),
        HandshakeQuality::Pmkid => s().yellow().paint("PMKID"),
        HandshakeQuality::M1M2 => s().green().bold().paint("M1+M2"),
        HandshakeQuality::M1M2M3 => s().green().bold().paint("M1+M2+M3"),
        HandshakeQuality::Full => s().green().bold().paint("FULL"),
    }
}

/// Format a CSA event as a styled terminal line for the output zone.
pub fn format_event(event: &CsaEvent) -> String {
    let ts = format!("{:>7.3}s", event.timestamp.as_secs_f64());
    let ts_styled = s().dim().paint(&ts);

    match &event.kind {
        CsaEventKind::AttackStarted { bssid, ssid, channel, pmf } => {
            format!("  [{}] {} {}  {}  ch{}  {}",
                ts_styled,
                s().cyan().bold().paint("CSA"),
                s().bold().paint(ssid),
                s().dim().paint(&bssid.to_string()),
                channel,
                pmf_styled(*pmf))
        }
        CsaEventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts_styled, s().dim().paint("LOCK"), channel)
        }
        CsaEventKind::StimulationSent { frames } => {
            format!("  [{}] {} QoS Null stimulation ({} frames)",
                ts_styled, s().blue().paint("STIM"), frames)
        }
        CsaEventKind::CsaBurstSent { burst_num, beacons, csa_channel } => {
            format!("  [{}] {} Burst #{} \u{2192} ch{} ({} frames)",
                ts_styled, s().red().bold().paint("CSA"), burst_num, csa_channel, beacons)
        }
        CsaEventKind::InterBurstGap { gap_secs } => {
            format!("  [{}] {} Inter-burst gap ({:.1}s)",
                ts_styled, s().dim().paint("GAP"), gap_secs)
        }
        CsaEventKind::ListeningStarted { round } => {
            format!("  [{}] {} Listening for EAPOL (round #{})",
                ts_styled, s().cyan().paint("LISTEN"), round)
        }
        CsaEventKind::M1Detected { sta_mac } => {
            let sta = if *sta_mac == MacAddress::ZERO {
                String::new()
            } else {
                format!(" from {}", s().bold().paint(&sta_mac.to_string()))
            };
            format!("  [{}] {} EAPOL M1 detected{} \u{2014} extending listen for M2",
                ts_styled, s().yellow().bold().paint("M1"), sta)
        }
        CsaEventKind::HalfHandshakePivot { sta_mac } => {
            let sta = if *sta_mac == MacAddress::ZERO {
                String::new()
            } else {
                format!(" from {}", s().bold().paint(&sta_mac.to_string()))
            };
            format!("  [{}] {} M2 without M1{} \u{2014} pivoting to CSA/deauth",
                ts_styled, s().yellow().bold().paint("PIVOT"), sta)
        }
        CsaEventKind::HandshakeCaptured { sta_mac, quality } => {
            let sta = if *sta_mac == MacAddress::ZERO {
                String::new()
            } else {
                format!(" from {}", s().bold().paint(&sta_mac.to_string()))
            };
            format!("  [{}] {} Handshake captured{}  quality: {}",
                ts_styled,
                s().green().bold().paint("\u{2714} CAPTURE"),
                sta,
                quality_styled(*quality))
        }
        CsaEventKind::PmkidCaptured { sta_mac } => {
            format!("  [{}] {} PMKID extracted from {}",
                ts_styled, s().green().bold().paint("PMKID"),
                s().bold().paint(&sta_mac.to_string()))
        }
        CsaEventKind::DeauthFallbackSent { frames } => {
            format!("  [{}] {} Deauth fallback ({} frames)",
                ts_styled, s().red().paint("DEAUTH"), frames)
        }
        CsaEventKind::RoundStarted { round } => {
            format!("  [{}] {} Round #{}", ts_styled, s().dim().paint("ROUND"), round)
        }
        CsaEventKind::RateSnapshot { frames_sent, frames_per_sec, elapsed } => {
            format!("  [{}] {} {} frames  {:.0} fps  {:.1}s",
                ts_styled,
                s().dim().paint("RATE"),
                prism::format_number(*frames_sent),
                frames_per_sec,
                elapsed.as_secs_f64())
        }
        CsaEventKind::CooldownStarted { duration_secs } => {
            format!("  [{}] {} Capturing late reconnections for {:.0}s",
                ts_styled, s().cyan().bold().paint("COOLDOWN"), duration_secs)
        }
        CsaEventKind::ChannelUnlocked => {
            format!("  [{}] {} Channel unlocked \u{2014} scanner resumes hopping",
                ts_styled, s().dim().paint("UNLOCK"))
        }
        CsaEventKind::AttackComplete { frames_sent, elapsed, reason, quality } => {
            let reason_str = stop_reason_label(*reason);
            format!("  [{}] {} {} \u{2014} {} frames in {:.1}s  quality: {}  ({})",
                ts_styled,
                s().bold().paint("DONE"),
                s().green().bold().paint("CSA attack complete"),
                prism::format_number(*frames_sent),
                elapsed.as_secs_f64(),
                quality_styled(*quality),
                s().dim().paint(reason_str))
        }
        CsaEventKind::Error { message } => {
            format!("  [{}] {} {}", ts_styled, s().red().bold().paint("ERROR"), message)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Active zone view
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-client EAPOL state tracked during the attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEapolState {
    /// No EAPOL activity seen for this client.
    None,
    /// M1 received (AP sent ANonce to this client).
    M1,
    /// M2 received (client responded — handshake in progress).
    M2,
    /// M1+M2 captured (crackable handshake from this client).
    Captured,
}

/// Client snapshot for the CSA view.
#[derive(Debug, Clone)]
pub struct ClientSnapshot {
    pub mac: MacAddress,
    pub rssi: i8,
    pub snr: u8,
    pub last_seen: Instant,
    pub frame_count: u32,
    pub vendor: String,
    pub reconnect_at: Option<Instant>,
    pub rssi_samples: VecDeque<(Duration, i8)>,
    pub snr_samples: VecDeque<(Duration, u8)>,
    /// Per-client EAPOL state — set by the module from delta stream.
    pub eapol_state: ClientEapolState,
}

/// Render the CSA attack view for the Layout active zone.
pub fn render_csa_view(info: &CsaInfo, clients: &[ClientSnapshot], width: u16, fps_history: &VecDeque<f64>) -> Vec<String> {
    let w = width as usize;
    let inner_w = w.saturating_sub(6);

    let bc = |t: &str| s().dim().paint(t);
    let vline = |content: &str, iw: usize| {
        let display_w = prism::measure_width(content);
        let pad = iw.saturating_sub(display_w);
        format!("  {} {}{}{}", bc("\u{2502}"), content, " ".repeat(pad), bc("\u{2502}"))
    };
    let empty_line = || vline("", inner_w);

    let mut lines = Vec::new();
    lines.push(String::new());

    // ═══ Header border ═══
    let title = " CSA injection ";
    let title_styled = s().cyan().bold().paint(title);
    let title_plain_w = prism::measure_width(title);
    let remaining = inner_w.saturating_sub(title_plain_w + 1);
    lines.push(format!("  {}{}{}{}", bc("\u{256d}\u{2500}"), title_styled,
        bc(&"\u{2500}".repeat(remaining)), bc("\u{256e}")));
    lines.push(empty_line());

    // ═══ Target info ═══
    let ssid_display = if info.target_ssid.is_empty() {
        s().dim().italic().paint("(hidden)")
    } else {
        s().bold().paint(&truncate(&info.target_ssid, 24, "\u{2026}"))
    };

    let signal = signal_bar(info.target_rssi);
    let pmf = pmf_styled(info.target_pmf);

    let target_line = format!("{}  {}  ch{}  {}  {}dBm  {}",
        ssid_display,
        s().dim().paint(&info.target_bssid.to_string()),
        info.target_channel,
        signal,
        s().dim().paint(&format!("{}", info.target_rssi)),
        pmf,
    );
    lines.push(vline(&target_line, inner_w));

    // ═══ Capture status ═══
    let quality_display = quality_styled(info.handshake_quality);
    let pmkid_display = if info.has_pmkid {
        s().green().bold().paint("\u{2714} PMKID")
    } else {
        s().dim().paint("\u{25cb} PMKID")
    };
    let m1_display = if info.m1_seen {
        s().green().paint("\u{2714} M1")
    } else {
        s().dim().paint("\u{25cb} M1")
    };
    let m2_display = if info.m2_seen {
        s().green().paint("\u{2714} M2")
    } else {
        s().dim().paint("\u{25cb} M2")
    };

    let capture_line = format!("Capture: {}  {}  {}  {}",
        quality_display, pmkid_display, m1_display, m2_display);
    lines.push(vline(&capture_line, inner_w));

    // ═══ Step progress ═══
    if info.running || info.phase == CsaPhase::Done {
        let spinner = prism::get_spinner("dots");
        let spin_frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let stim_step = match info.phase {
            CsaPhase::Idle | CsaPhase::ChannelLock =>
                format!("{} STIM", s().dim().paint("\u{25cb}")),
            CsaPhase::Stimulating =>
                format!("{} STIM", s().blue().paint(spin_frame)),
            _ => format!("{} STIM", s().green().paint("\u{2714}")),
        };

        let csa_step = match info.phase {
            CsaPhase::Idle | CsaPhase::ChannelLock | CsaPhase::Stimulating =>
                format!("{} CSA", s().dim().paint("\u{25cb}")),
            CsaPhase::CsaBurst =>
                format!("{} CSA", s().red().bold().paint(spin_frame)),
            _ => format!("{} CSA", s().green().paint("\u{2714}")),
        };

        let listen_step = match info.phase {
            CsaPhase::Listening =>
                format!("{} LISTEN", s().cyan().paint(spin_frame)),
            CsaPhase::Cooldown | CsaPhase::Done =>
                format!("{} LISTEN", s().green().paint("\u{2714}")),
            _ => format!("{} LISTEN", s().dim().paint("\u{25cb}")),
        };

        let capture_step = match info.phase {
            CsaPhase::Cooldown =>
                format!("{} CAPTURE", s().cyan().paint(spin_frame)),
            CsaPhase::Done if info.handshake_quality >= HandshakeQuality::M1M2 =>
                format!("{} CAPTURE", s().green().bold().paint("\u{2714}")),
            CsaPhase::Done =>
                format!("{} CAPTURE", s().yellow().paint("\u{25cb}")),
            _ => format!("{} CAPTURE", s().dim().paint("\u{25cb}")),
        };

        let arrow = s().dim().paint(" \u{2192} ");
        let steps = format!("{}{}{}{}{}{}{}", stim_step, arrow, csa_step, arrow, listen_step, arrow, capture_step);

        if fps_history.len() > 1 {
            let spark = fps_sparkline(fps_history, 12);
            lines.push(vline(&format!("{}  {}", steps, spark), inner_w));
        } else {
            lines.push(vline(&steps, inner_w));
        }
    }

    lines.push(empty_line());

    // ═══ Stats line ═══
    if matches!(info.phase, CsaPhase::CsaBurst | CsaPhase::Listening | CsaPhase::Cooldown | CsaPhase::Done) {
        let elapsed_fmt = prism::format_time((info.start_time.elapsed().as_secs_f64() * 1000.0) as u64);
        let csa_count = s().red().bold().paint(&format!("{} CSA", prism::format_number(info.csa_beacons_sent)));
        let deauth_count = if info.deauth_frames_sent > 0 {
            format!("  {} deauth", s().yellow().paint(&prism::format_number(info.deauth_frames_sent)))
        } else { String::new() };
        let stim_count = if info.stimulation_frames_sent > 0 {
            format!("  {} stim", s().blue().paint(&prism::format_number(info.stimulation_frames_sent)))
        } else { String::new() };
        let round_str = s().dim().paint(&format!("round #{}", info.round));
        let pivot_str = if info.half_handshake_pivots > 0 {
            format!("  {} pivots", s().yellow().paint(&prism::format_number(info.half_handshake_pivots as u64)))
        } else { String::new() };

        let stats = format!("{}{}{}  {}  {}{}",
            csa_count, deauth_count, stim_count, round_str, elapsed_fmt, pivot_str);
        lines.push(vline(&stats, inner_w));

        // TX delivery bar
        if let Some(tx_line) = tx_stats_line(&info.tx_feedback, info.frames_sent, info.frames_per_sec) {
            lines.push(vline(&tx_line, inner_w));
        }
    }

    // ═══ Cooldown progress bar ═══
    if info.phase == CsaPhase::Cooldown {
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

    // ═══ Client table ═══
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
            //   1. captured  — M1+M2 from this client (green, goal achieved)
            //   2. capturing — EAPOL M1 or M2 in progress (cyan, handshake happening)
            //   3. reconnect — was quiet, now active again (yellow, disconnect confirmed)
            //   4. active    — sending frames right now (red, not disconnected yet)
            //   5. quiet     — was active, now silent (dim, something happened)
            //   6. idle      — wasn't active before attack (dim dash, not our doing)
            let was_seen_during_attack = client.last_seen > info.start_time;

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
            } else if age < Duration::from_secs(3) {
                (s().red().paint("\u{25cf}"),
                 s().red().paint("active"),
                 s().red().paint(&client.mac.to_string()))
            } else if was_seen_during_attack && age < Duration::from_secs(15) {
                (s().dim().paint("\u{25cb}"),
                 s().dim().paint("quiet"),
                 s().dim().paint(&client.mac.to_string()))
            } else {
                (s().dim().paint("\u{2014}"),
                 s().dim().paint("idle"),
                 s().dim().paint(&client.mac.to_string()))
            };

            let spark = rssi_sparkline(&client.rssi_samples, 8);
            let rssi_num = format!("{}", client.rssi);
            let signal_col = format!("{} {}", spark, prism::pad(&rssi_num, 4, "left"));

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
    } else if info.phase == CsaPhase::Listening || info.phase == CsaPhase::CsaBurst {
        lines.push(vline(
            &format!("{} {}", s().dim().paint("\u{25cb}"),
                s().dim().paint("No clients associated with target AP")),
            inner_w));
    } else if info.phase == CsaPhase::ChannelLock {
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

pub fn status_segments(info: &CsaInfo) -> Vec<StatusSegment> {
    let mut segs = Vec::new();

    if !info.running && info.phase == CsaPhase::Idle {
        return segs;
    }

    let attack_text = if info.target_ssid.is_empty() {
        format!("CSA: {}", phase_label(info.phase))
    } else {
        format!("CSA: {} ({})", info.target_ssid, phase_label(info.phase))
    };
    segs.push(StatusSegment::new(attack_text, SegmentStyle::CyanBold));

    if info.target_channel > 0 {
        segs.push(StatusSegment::new(format!("ch:{}", info.target_channel), SegmentStyle::Bold));
    }

    // Handshake quality
    if info.handshake_quality > HandshakeQuality::None {
        segs.push(StatusSegment::new(
            format!("{}", info.handshake_quality.name()),
            SegmentStyle::Green,
        ));
    }

    // Round
    if info.round > 0 {
        segs.push(StatusSegment::new(format!("r:{}", info.round), SegmentStyle::Dim));
    }

    // CSA beacons
    if info.csa_beacons_sent > 0 {
        segs.push(StatusSegment::new(
            format!("{} csa", prism::format_number(info.csa_beacons_sent)),
            SegmentStyle::Yellow,
        ));
    }

    // Elapsed
    segs.push(StatusSegment::new(
        prism::format_time((info.start_time.elapsed().as_secs_f64() * 1000.0) as u64),
        SegmentStyle::Dim,
    ));

    segs
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn format_age(age: Duration) -> String {
    let secs = age.as_secs();
    if secs < 2 { "   now ".to_string() }
    else if secs < 10 { format!("  {}s ago", secs) }
    else if secs < 60 { format!(" {}s ago", secs) }
    else if secs < 600 { format!("{}m{:02}s  ", secs / 60, secs % 60) }
    else { format!("{:>4}m  ", secs / 60) }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CsaModule — Module trait implementation
// ═══════════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};
use crate::protocol::eapol::HandshakeMessage;
use crate::store::{Ap, Station};

pub struct CsaModule {
    attack: CsaAttack,
    target: Option<Ap>,
    target_station: Option<Station>,
    cached_info: Option<CsaInfo>,
    target_clients: Vec<ClientSnapshot>,
    update_sub: Option<UpdateSubscriber>,
    attack_id: Option<AttackId>,
    dirty: bool,
    scrollback_lines: Vec<String>,
    fps_history: VecDeque<f64>,
    /// Per-client EAPOL state — populated from EapolMessage deltas.
    client_eapol: HashMap<MacAddress, ClientEapolState>,
    /// Target BSSID — for filtering EAPOL deltas to our target AP.
    target_bssid: Option<MacAddress>,
}

impl CsaModule {
    pub fn new(params: CsaParams) -> Self {
        let attack = CsaAttack::new(params);
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

    pub fn attack(&self) -> &CsaAttack {
        &self.attack
    }

    pub fn set_targets(&mut self, target: Ap, station: Option<Station>) {
        self.target_bssid = Some(target.bssid);
        self.target = Some(target);
        self.target_station = station;
    }

    pub fn info(&self) -> CsaInfo {
        self.attack.info()
    }

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
                    if *quality >= HandshakeQuality::M1M2 {
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
                StoreUpdate::AttackStarted { id, attack_type: AttackType::Csa, .. } => {
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
                StoreUpdate::AttackEvent { id, event: AttackEventKind::Csa(kind), timestamp, .. }
                    if self.is_our_attack(*id) =>
                {
                    let event = CsaEvent { seq: 0, timestamp: *timestamp, kind: kind.clone() };
                    self.scrollback_lines.push(format_event(&event));
                    self.dirty = true;
                }
                StoreUpdate::AttackComplete { id, attack_type: AttackType::Csa, .. }
                    if self.is_our_attack(*id) =>
                {
                    self.dirty = true;
                }
                _ => {}
            }
        }
    }

    fn is_our_attack(&self, id: AttackId) -> bool {
        self.attack_id.is_some_and(|our_id| our_id == id)
    }

    pub fn tick(&mut self) -> Vec<String> {
        self.process_deltas();
        self.cached_info = Some(self.attack.info());
        self.dirty = false;
        std::mem::take(&mut self.scrollback_lines)
    }

    pub fn update_target_clients(&mut self, mut clients: Vec<ClientSnapshot>) {
        let now = Instant::now();
        for client in &mut clients {
            // Apply per-client EAPOL state from our tracking
            if let Some(&state) = self.client_eapol.get(&client.mac) {
                client.eapol_state = state;
            }

            // Reconnection detection
            if let Some(prev) = self.target_clients.iter().find(|c| c.mac == client.mac) {
                let prev_age = now.duration_since(prev.last_seen);
                let cur_age = now.duration_since(client.last_seen);
                // CSA cycles are longer than deauth — 3s quiet threshold
                if prev_age > Duration::from_secs(3) && cur_age < Duration::from_secs(3) {
                    client.reconnect_at = Some(now);
                } else if let Some(prev_reconnect) = prev.reconnect_at {
                    if now.duration_since(prev_reconnect) < Duration::from_secs(4) {
                        client.reconnect_at = Some(prev_reconnect);
                    }
                }
            }
        }
        self.target_clients = clients;
    }
}

impl Module for CsaModule {
    fn name(&self) -> &str { "csa" }
    fn description(&self) -> &str { "CSA injection attack" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }

    fn start(&mut self, shared: crate::adapter::SharedAdapter) {
        self.update_sub = Some(shared.gate().subscribe_updates("csa-ui"));
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
        &[]
    }

    fn render(&mut self, _view: usize, width: u16, _height: u16) -> Vec<String> {
        let info = self.cached_info.clone().unwrap_or_else(|| self.attack.info());
        render_csa_view(&info, &self.target_clients, width, &self.fps_history)
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

        let pmf_str = match info.target_pmf {
            PmfStatus::Required => " (PMF required \u{2014} CSA only)",
            PmfStatus::Capable => " (PMF capable)",
            PmfStatus::None => "",
        };

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
            "Target: {} ({}){}\nHandshake: {}\nCSA beacons: {}  Deauth: {}  Stimulation: {}\nRounds: {}  Pivots: {}\nDuration: {}  |  {} sent{}\nReason: {}",
            info.target_ssid,
            info.target_bssid,
            pmf_str,
            info.handshake_quality.name(),
            prism::format_number(info.csa_beacons_sent),
            prism::format_number(info.deauth_frames_sent),
            prism::format_number(info.stimulation_frames_sent),
            info.round,
            info.half_handshake_pivots,
            prism::format_time((info.elapsed.as_secs_f64() * 1000.0) as u64),
            prism::format_bytes(info.bytes_sent),
            tx_line,
            reason_str,
        );

        let frame_width = (width as usize).saturating_sub(4);
        let framed = prism::frame(&content, &prism::FrameOptions {
            border: prism::BorderStyle::Rounded,
            title: Some("CSA Attack Complete".into()),
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
