//! CLI renderer + Module implementation for the PMKID attack.
//!
//! Renders the attack progress as styled terminal lines:
//! - Phase indicator (authenticating, waiting M1, etc.)
//! - Current target with SSID, BSSID, channel, RSSI
//! - Progress bar for multi-target attacks
//! - Results table showing all attempted targets
//! - Event log scrollback

use crate::attacks::pmkid::{
    PmkidAttack, PmkidEvent, PmkidEventKind, PmkidInfo, PmkidParams,
    PmkidPhase, PmkidStatus,
};

use prism::{s, truncate};

// ═══════════════════════════════════════════════════════════════════════════════
//  Phase display
// ═══════════════════════════════════════════════════════════════════════════════

fn phase_label(phase: PmkidPhase) -> &'static str {
    match phase {
        PmkidPhase::Idle => "idle",
        PmkidPhase::ChannelLock => "locking channel",
        PmkidPhase::Authenticating => "authenticating",
        PmkidPhase::WaitingAuthResp => "waiting auth",
        PmkidPhase::Associating => "associating",
        PmkidPhase::WaitingAssocResp => "waiting assoc",
        PmkidPhase::WaitingM1 => "waiting M1",
        PmkidPhase::Cleanup => "cleanup",
        PmkidPhase::Done => "done",
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  Status display for target
// ═══════════════════════════════════════════════════════════════════════════════

fn status_icon(status: PmkidStatus) -> String {
    match status {
        PmkidStatus::Captured => s().green().bold().paint("\u{2714}"),     // ✔
        PmkidStatus::NoPmkid => s().yellow().paint("\u{2212}"),            // −
        PmkidStatus::NoResponse => s().red().paint("\u{2717}"),            // ✗
        PmkidStatus::AssocRejected => s().red().paint("\u{2717}"),         // ✗
        PmkidStatus::Timeout => s().red().dim().paint("\u{23f1}"),         // ⏱
        PmkidStatus::ChannelError => s().red().paint("!"),
        PmkidStatus::Stopped => s().dim().paint("\u{25a0}"),               // ■
        PmkidStatus::InProgress => s().cyan().paint("\u{25cf}"),           // ●
    }
}

fn status_label(status: PmkidStatus) -> &'static str {
    match status {
        PmkidStatus::Captured => "PMKID captured",
        PmkidStatus::NoPmkid => "no PMKID in M1",
        PmkidStatus::NoResponse => "no response",
        PmkidStatus::AssocRejected => "assoc rejected",
        PmkidStatus::Timeout => "timeout",
        PmkidStatus::ChannelError => "channel error",
        PmkidStatus::Stopped => "stopped",
        PmkidStatus::InProgress => "in progress",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Event formatting — for scrollback output
// ═══════════════════════════════════════════════════════════════════════════════

/// Format a PMKID event as a styled terminal line for the output zone.
pub fn format_event(event: &PmkidEvent) -> String {
    let ts = format!("{:>7.3}s", event.timestamp.as_secs_f64());
    let ts_styled = s().dim().paint(&ts);

    match &event.kind {
        PmkidEventKind::TargetStarted { bssid, ssid, channel, rssi, index, total } => {
            format!("  [{}] {} [{}/{}] {}  {}  ch{}  {} dBm",
                ts_styled, s().cyan().bold().paint("TARGET"),
                index, total,
                s().bold().paint(ssid),
                s().dim().paint(&bssid.to_string()),
                channel, rssi)
        }
        PmkidEventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts_styled, s().dim().paint("LOCK"), channel)
        }
        PmkidEventKind::AuthSent { attempt, .. } => {
            format!("  [{}] {} Auth sent (attempt {})", ts_styled, s().dim().paint("AUTH"), attempt)
        }
        PmkidEventKind::AuthResponse { status, .. } => {
            let status_str = if *status == 0 {
                s().green().paint("accepted")
            } else {
                s().red().paint(&format!("rejected ({})", status))
            };
            format!("  [{}] {} Auth response: {}", ts_styled, s().dim().paint("AUTH"), status_str)
        }
        PmkidEventKind::AuthSuccess { .. } => {
            format!("  [{}] {} Authenticated", ts_styled, s().green().paint("AUTH"))
        }
        PmkidEventKind::AuthFailed { .. } => {
            format!("  [{}] {} Authentication failed", ts_styled, s().red().paint("AUTH"))
        }
        PmkidEventKind::AssocSent { attempt, .. } => {
            format!("  [{}] {} Assoc sent (attempt {})", ts_styled, s().dim().paint("ASSOC"), attempt)
        }
        PmkidEventKind::AssocResponse { status, aid, .. } => {
            let status_str = if *status == 0 {
                s().green().paint(&format!("accepted (AID={})", aid))
            } else {
                s().red().paint(&format!("rejected ({})", status))
            };
            format!("  [{}] {} Assoc response: {}", ts_styled, s().dim().paint("ASSOC"), status_str)
        }
        PmkidEventKind::AssocSuccess { .. } => {
            format!("  [{}] {} Associated", ts_styled, s().green().paint("ASSOC"))
        }
        PmkidEventKind::AssocFailed { .. } => {
            format!("  [{}] {} Association failed (trying M1 anyway)", ts_styled, s().yellow().paint("ASSOC"))
        }
        PmkidEventKind::EapolM1Received { has_pmkid, .. } => {
            if *has_pmkid {
                format!("  [{}] {} M1 received — PMKID present!", ts_styled, s().green().bold().paint("EAPOL"))
            } else {
                format!("  [{}] {} M1 received — no PMKID", ts_styled, s().yellow().paint("EAPOL"))
            }
        }
        PmkidEventKind::PmkidCaptured { bssid, ssid, pmkid, channel, rssi, elapsed_ms } => {
            let pmkid_hex: String = pmkid.iter().map(|b| format!("{:02x}", b)).collect();
            format!(
                "  [{}] {} {}  {}  ch{}  {} dBm  {}ms\n  {}         {}",
                ts_styled,
                s().green().bold().paint("PMKID!"),
                s().bold().paint(ssid),
                s().dim().paint(&bssid.to_string()),
                channel, rssi, elapsed_ms,
                " ".repeat(ts.len()),
                s().green().paint(&pmkid_hex),
            )
        }
        PmkidEventKind::NoPmkid { ssid, .. } => {
            format!("  [{}] {} {} — AP doesn't include PMKID in M1",
                ts_styled, s().yellow().paint("NO-PMKID"), s().bold().paint(ssid))
        }
        PmkidEventKind::M1Timeout { ssid, .. } => {
            format!("  [{}] {} {} — timed out waiting for M1",
                ts_styled, s().red().paint("TIMEOUT"), ssid)
        }
        PmkidEventKind::NoResponse { ssid, .. } => {
            format!("  [{}] {} {} — AP not responding",
                ts_styled, s().red().paint("NO-RESP"), ssid)
        }
        PmkidEventKind::DisassocSent { .. } => {
            format!("  [{}] {} Disassociated (cleanup)", ts_styled, s().dim().paint("DISASSOC"))
        }
        PmkidEventKind::ChannelUnlocked => {
            format!("  [{}] {} Channel unlocked — scanner resumes hopping", ts_styled, s().dim().paint("UNLOCK"))
        }
        PmkidEventKind::TargetComplete { ssid, status, elapsed_ms, .. } => {
            let icon = status_icon(*status);
            let label = status_label(*status);
            format!("  [{}] {} {} {} ({}ms)", ts_styled, icon, ssid, s().dim().paint(label), elapsed_ms)
        }
        PmkidEventKind::AttackComplete { captured, failed: _, total, elapsed } => {
            let summary = format!("{}/{} captured", captured, total);
            let summary_styled = if *captured > 0 {
                s().green().bold().paint(&summary)
            } else {
                s().yellow().paint(&summary)
            };
            format!("  [{}] {} PMKID attack complete: {}  ({:.1}s)",
                ts_styled,
                s().bold().paint("DONE"),
                summary_styled,
                elapsed.as_secs_f64())
        }
        PmkidEventKind::Error { message } => {
            format!("  [{}] {} {}", ts_styled, s().red().bold().paint("ERROR"), message)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Results table — rendered in the active zone during/after attack
// ═══════════════════════════════════════════════════════════════════════════════

/// Render the PMKID attack progress view for the Layout active zone.
///
/// Layout (inside exec-style bordered frame):
///   1. Current target header (SSID, BSSID, channel, RSSI)
///   2. Step progress: ✔ AUTH → ✔ ASSOC → ⠋ M1...
///   3. Progress bar (multi-target only)
///   4. Results scroll table
///   5. Footer with stats in border
pub fn render_pmkid_view(info: &PmkidInfo, width: u16, _height: u16, scroll_offset: usize) -> Vec<String> {
    let w = width as usize;
    let inner_w = w.saturating_sub(6); // border + padding

    // ── Border characters (rounded) ──
    let bc = |t: &str| s().dim().paint(t);
    let vline = |content: &str, iw: usize| {
        let display_w = prism::measure_width(content);
        let pad = iw.saturating_sub(display_w);
        format!("  {} {}{}{}",
            bc("\u{2502}"), content, " ".repeat(pad), bc("\u{2502}"))
    };
    let empty_line = || vline("", inner_w);

    let mut lines = Vec::new();

    // ═══ Header border with title ═══
    let title = s().cyan().bold().paint(" pmkid ");
    let title_plain_w = 7; // " pmkid "
    let remaining = inner_w.saturating_sub(title_plain_w + 1);
    lines.push(format!("  {}{}{}{}", bc("\u{256d}\u{2500}"), title,
        bc(&"\u{2500}".repeat(remaining)), bc("\u{256e}")));

    // ═══ Current target ═══
    if let Some(bssid) = &info.current_bssid {
        let ssid_display = if info.current_ssid.is_empty() {
            s().dim().italic().paint("(hidden)")
        } else {
            s().bold().paint(&truncate(&info.current_ssid, 24, "\u{2026}"))
        };

        // RSSI bar
        fn rssi_green(t: &str) -> String { s().green().paint(t) }
        fn rssi_yellow(t: &str) -> String { s().yellow().paint(t) }
        fn rssi_red(t: &str) -> String { s().red().paint(t) }
        let rssi_val = (info.current_rssi + 100).max(0).min(60) as u64;
        let rssi_bar = prism::render_progress_bar(rssi_val, &prism::RenderOptions {
            total: 60,
            width: 8,
            style: prism::BarStyle::Bar,
            color: Some(if info.current_rssi > -50 { rssi_green }
                else if info.current_rssi > -70 { rssi_yellow }
                else { rssi_red }),
            ..Default::default()
        });

        let target_line = format!("{}  {}  ch{}  {} dBm {}",
            ssid_display,
            s().dim().paint(&bssid.to_string()),
            info.current_channel,
            info.current_rssi,
            rssi_bar,
        );
        lines.push(vline(&target_line, inner_w));
    } else if !info.running && info.phase == PmkidPhase::Done {
        lines.push(vline(&s().dim().paint("Attack complete"), inner_w));
    } else if !info.running {
        lines.push(vline(&s().dim().paint("Idle"), inner_w));
    }

    // ═══ Step progress: ✔ AUTH → ✔ ASSOC → ⠋ M1... ═══
    if info.running || info.phase == PmkidPhase::Done {
        let spinner = prism::get_spinner("dots");
        let spin_frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let auth_step = match info.phase {
            PmkidPhase::Idle | PmkidPhase::ChannelLock => format!("{} AUTH", s().dim().paint("\u{25cb}")),
            PmkidPhase::Authenticating | PmkidPhase::WaitingAuthResp =>
                format!("{} AUTH", s().cyan().paint(spin_frame)),
            _ => format!("{} AUTH", s().green().paint("\u{2714}")),
        };

        let assoc_step = match info.phase {
            PmkidPhase::Idle | PmkidPhase::ChannelLock
            | PmkidPhase::Authenticating | PmkidPhase::WaitingAuthResp =>
                format!("{} ASSOC", s().dim().paint("\u{25cb}")),
            PmkidPhase::Associating | PmkidPhase::WaitingAssocResp =>
                format!("{} ASSOC", s().cyan().paint(spin_frame)),
            _ => format!("{} ASSOC", s().green().paint("\u{2714}")),
        };

        let m1_step = match info.phase {
            PmkidPhase::WaitingM1 =>
                format!("{} M1", s().magenta().bold().paint(spin_frame)),
            PmkidPhase::Cleanup | PmkidPhase::Done =>
                format!("{} M1", s().green().paint("\u{2714}")),
            _ => format!("{} M1", s().dim().paint("\u{25cb}")),
        };

        let arrow = s().dim().paint(" \u{2192} ");
        let steps = format!("{}{}{}{}{}", auth_step, arrow, assoc_step, arrow, m1_step);
        lines.push(vline(&steps, inner_w));
    }

    lines.push(empty_line());

    // ═══ Progress bar (multi-target) ═══
    if info.target_total > 1 {
        let bar_w = inner_w.saturating_sub(16); // space for "3/126 targets"
        fn cyan_bar(t: &str) -> String { s().cyan().paint(t) }
        let bar = prism::render_progress_bar(info.target_index as u64, &prism::RenderOptions {
            total: info.target_total as u64,
            width: bar_w,
            style: prism::BarStyle::Smooth,
            color: Some(cyan_bar),
            ..Default::default()
        });

        let label = format!("{}/{} targets", info.target_index, info.target_total);
        let bar_line = format!("{}  {}", bar, s().dim().paint(&label));
        lines.push(vline(&bar_line, inner_w));
        lines.push(empty_line());
    }

    // ═══ Results scroll table ═══
    // Cap the view: use at most 40% of terminal height for this module
    let term_h = prism::term_height() as usize;
    let max_view = term_h * 40 / 100;
    let header_lines = lines.len();
    let footer_lines = 1; // bottom border
    let available_for_results = max_view.saturating_sub(header_lines + footer_lines);

    if !info.results.is_empty() {
        // Build all result rows first
        let mut result_rows: Vec<String> = Vec::new();
        for result in &info.results {
            let icon = status_icon(result.status);
            let ssid_display = truncate(
                if result.ssid.is_empty() { "(hidden)" } else { &result.ssid },
                18, "\u{2026}",
            );
            let ssid_styled = match result.status {
                PmkidStatus::Captured => s().green().bold().paint(&ssid_display),
                _ => s().bold().paint(&ssid_display),
            };

            let bssid_short = {
                let full = result.bssid.to_string();
                if full.len() > 8 { full[..8].to_string() } else { full }
            };

            let elapsed_str = format!("{}ms", result.elapsed.as_millis());

            let status_styled = match result.status {
                PmkidStatus::Captured => s().green().bold().paint(status_label(result.status)),
                PmkidStatus::NoPmkid => s().yellow().paint(status_label(result.status)),
                PmkidStatus::NoResponse | PmkidStatus::Timeout =>
                    s().red().paint(status_label(result.status)),
                _ => s().dim().paint(status_label(result.status)),
            };

            let row = format!("{} {}  {}  ch{:<3} {:>4}  {}  {}",
                icon,
                ssid_styled,
                s().dim().paint(&bssid_short),
                result.channel,
                result.rssi,
                status_styled,
                s().dim().paint(&elapsed_str),
            );
            result_rows.push(vline(&row, inner_w));

            // PMKID hex celebration — the trophy!
            if result.status == PmkidStatus::Captured {
                if let Some(pmkid) = &result.pmkid {
                    let hex: String = pmkid.iter().map(|b| format!("{:02x}", b)).collect();
                    let hex_line = format!("     {}", s().green().paint(&hex));
                    result_rows.push(vline(&hex_line, inner_w));
                }
            }
        }

        // Scroll results within the frame — show visible slice with indicators
        let total_rows = result_rows.len();
        if total_rows <= available_for_results {
            // Everything fits — no scrolling needed
            lines.extend(result_rows);
        } else {
            // Clamp scroll offset
            let max_offset = total_rows.saturating_sub(available_for_results.saturating_sub(2)); // -2 for indicators
            let offset = scroll_offset.min(max_offset);
            let visible_slots = available_for_results.saturating_sub(
                if offset > 0 { 1 } else { 0 } + if offset + available_for_results < total_rows { 1 } else { 0 }
            );
            let end = (offset + visible_slots).min(total_rows);

            // "↑ N above" indicator
            if offset > 0 {
                lines.push(vline(
                    &s().dim().paint(&format!("\u{2191} {} above", offset)),
                    inner_w,
                ));
            }

            // Visible result rows
            lines.extend_from_slice(&result_rows[offset..end]);

            // "↓ N below" indicator
            let remaining_below = total_rows.saturating_sub(end);
            if remaining_below > 0 {
                lines.push(vline(
                    &s().dim().paint(&format!("\u{2193} {} below", remaining_below)),
                    inner_w,
                ));
            }
        }
    } else if info.running && info.phase == PmkidPhase::ChannelLock {
        let spinner = prism::get_spinner("dots");
        let frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(vline(&format!("{} {}",
            s().cyan().paint(frame),
            s().dim().paint("Locking channel...")), inner_w));
    } else if info.results.is_empty() && !info.running {
        lines.push(vline(&s().dim().paint("No targets attacked yet."), inner_w));
    }

    // ═══ Footer border with stats ═══
    // Format: ╰── 3✔ 1− 1✗ ── 847 sent · 312 recv · 23.4 fps ── 4.2s ──╯
    let mut footer_parts = Vec::new();

    // Result summary icons
    if info.pmkids_captured > 0 {
        footer_parts.push(format!("{}{}", s().green().bold().paint(&info.pmkids_captured.to_string()),
            s().green().paint("\u{2714}")));
    }
    if info.aps_no_pmkid > 0 {
        footer_parts.push(format!("{}{}", s().yellow().paint(&info.aps_no_pmkid.to_string()),
            s().yellow().paint("\u{2212}")));
    }
    let total_failed = info.pmkids_failed + info.aps_no_response;
    if total_failed > 0 {
        footer_parts.push(format!("{}{}", s().red().paint(&total_failed.to_string()),
            s().red().paint("\u{2717}")));
    }

    let summary = if footer_parts.is_empty() {
        String::new()
    } else {
        format!(" {} ", footer_parts.join(" "))
    };

    // Frame counters
    let mut stat_parts = Vec::new();
    if info.frames_sent > 0 {
        stat_parts.push(format!("{} sent", prism::format_number(info.frames_sent)));
    }
    if info.frames_received > 0 {
        stat_parts.push(format!("{} recv", prism::format_number(info.frames_received)));
    }
    if info.frames_per_sec > 0.0 {
        stat_parts.push(format!("{:.0} fps", info.frames_per_sec));
    }
    let stats = if stat_parts.is_empty() {
        String::new()
    } else {
        format!(" {} ", stat_parts.join(" \u{00b7} "))
    };

    // Elapsed / status
    let elapsed_secs = info.start_time.elapsed().as_secs_f64();
    let status_text = if !info.running && info.phase == PmkidPhase::Done {
        if info.pmkids_captured > 0 {
            format!(" {} {:.1}s ", s().green().paint("\u{2714}"), elapsed_secs)
        } else {
            format!(" {} {:.1}s ", s().yellow().paint("\u{25a0}"), elapsed_secs)
        }
    } else if info.running {
        format!(" {:.1}s \u{00b7} {} ", elapsed_secs,
            s().dim().paint("running"))
    } else {
        format!(" {:.1}s ", elapsed_secs)
    };

    // Build footer line
    let summary_w = prism::measure_width(&prism::strip_ansi(&summary));
    let stats_w = prism::measure_width(&prism::strip_ansi(&stats));
    let status_w = prism::measure_width(&prism::strip_ansi(&status_text));

    let total_content = summary_w + stats_w + status_w + 4; // separators
    let fill = (inner_w + 2).saturating_sub(total_content);

    let footer = format!("  {}{}{}{}{}{}{}",
        bc("\u{2570}"),
        bc("\u{2500}"),
        summary,
        bc(&"\u{2500}".repeat(fill / 2)),
        s().dim().paint(&stats),
        bc(&"\u{2500}".repeat(fill.saturating_sub(fill / 2))),
        format!("{}{}", status_text, bc("\u{256f}")),
    );
    lines.push(footer);

    lines
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status bar segments
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate status bar segments for the PMKID attack.
pub fn status_segments(info: &PmkidInfo) -> Vec<StatusSegment> {
    let mut segs = Vec::new();

    if !info.running && info.phase == PmkidPhase::Idle {
        return segs;
    }

    let attack_text = if info.current_ssid.is_empty() {
        format!("pmkid: {}", phase_label(info.phase))
    } else {
        format!("pmkid: {} ({})", info.current_ssid, phase_label(info.phase))
    };

    segs.push(StatusSegment::new(attack_text, SegmentStyle::RedBold));

    if info.pmkids_captured > 0 {
        segs.push(StatusSegment::new(
            format!("{}\u{2714}", info.pmkids_captured),
            SegmentStyle::GreenBold,
        ));
    }

    if info.target_total > 0 {
        segs.push(StatusSegment::new(
            format!("{}/{}", info.target_index, info.target_total),
            SegmentStyle::Dim,
        ));
    }

    let elapsed_secs = info.start_time.elapsed().as_secs_f64();
    segs.push(StatusSegment::new(format!("{:.1}s", elapsed_secs), SegmentStyle::Dim));

    segs
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════════════════════════
//  PmkidModule — Module trait implementation for PMKID attack
// ═══════════════════════════════════════════════════════════════════════════════

use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};

/// PmkidModule wraps PmkidAttack with the Module trait for the shell's focus stack.
///
/// Uses SharedAdapter architecture: the attack spawns its own thread via start(),
/// locks the channel for each target, and shares the adapter with the scanner.
pub struct PmkidModule {
    attack: PmkidAttack,
    /// Cached info for rendering — refreshed each render cycle.
    cached_info: Option<PmkidInfo>,
    /// Accumulated events for scrollback printing.
    pending_events: Vec<PmkidEvent>,
    /// Scroll offset for results table (j/k navigation).
    scroll_offset: usize,
}

impl PmkidModule {
    pub fn new(params: PmkidParams) -> Self {
        let attack = PmkidAttack::new(params);
        Self {
            attack,
            cached_info: None,
            pending_events: Vec::new(),
            scroll_offset: 0,
        }
    }

    /// Get the underlying attack for starting with targets.
    pub fn attack(&self) -> &PmkidAttack {
        &self.attack
    }

    /// Drain new events since last call. Used by the shell to print to scrollback.
    pub fn drain_events(&mut self) -> Vec<PmkidEvent> {
        let events = self.attack.events();
        self.pending_events.extend(events.iter().cloned());
        events
    }

}

impl Module for PmkidModule {
    fn name(&self) -> &str { "pmkid" }
    fn description(&self) -> &str { "PMKID extraction attack" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }

    fn start(&mut self, shared: crate::adapter::SharedAdapter) {
        // Targets should be set before calling start().
        // The shell gathers targets from the scanner and passes them in.
        // For now, start with empty targets — the shell will call
        // attack.start(shared, targets) directly.
        //
        // This default start() is a fallback — the shell should use
        // attack().start(shared, targets) for proper operation.
        self.attack.start(shared, Vec::new());
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
        &[] // PMKID uses a single view — no tabs
    }

    fn render(&mut self, _view: usize, width: u16, height: u16) -> Vec<String> {
        let info = self.attack.info();
        self.cached_info = Some(info.clone());
        render_pmkid_view(&info, width, height, self.scroll_offset)
    }

    fn handle_key(&mut self, key: &prism::KeyEvent, _view: usize) -> bool {
        if key.ctrl || key.meta { return false; }
        match key.key.as_str() {
            "j" => { self.scroll_offset = self.scroll_offset.saturating_add(1); true }
            "k" => { self.scroll_offset = self.scroll_offset.saturating_sub(1); true }
            "G" => {
                self.scroll_offset = usize::MAX; // clamped by render
                true
            }
            "g" => { self.scroll_offset = 0; true }
            _ => false,
        }
    }

    fn status_segments(&self) -> Vec<StatusSegment> {
        let info = self.attack.info();
        status_segments(&info)
    }

    fn freeze_summary(&self, width: u16) -> Vec<String> {
        let info = self.cached_info.as_ref().cloned()
            .unwrap_or_else(|| self.attack.info());

        let elapsed_secs = info.start_time.elapsed().as_secs_f64();

        // Build content for the framed result box
        let mut content_lines = Vec::new();

        // Summary line
        let captured_str = if info.pmkids_captured > 0 {
            s().green().bold().paint(&format!("{} captured", info.pmkids_captured))
        } else {
            s().yellow().paint("0 captured")
        };
        content_lines.push(format!("{}  {}  {}  {}",
            captured_str,
            s().dim().paint(&format!("{} no-pmkid", info.aps_no_pmkid)),
            s().dim().paint(&format!("{} failed", info.pmkids_failed)),
            s().dim().paint(&format!("{} no-response", info.aps_no_response)),
        ));

        // Timing
        content_lines.push(format!("{}  {}  {}",
            s().dim().paint(&format!("{:.1}s elapsed", elapsed_secs)),
            s().dim().paint(&format!("{} frames sent", info.frames_sent)),
            s().dim().paint(&format!("{} received", info.frames_received)),
        ));

        // Per-target results
        if !info.results.is_empty() {
            content_lines.push(String::new());
            for result in &info.results {
                let icon = status_icon(result.status);
                let label = status_label(result.status);
                let elapsed_str = format!("{}ms", result.elapsed.as_millis());

                let mut line = format!("  {} {}  {}  ch{}  {}",
                    icon,
                    s().bold().paint(&truncate(&result.ssid, 20, "\u{2026}")),
                    s().dim().paint(&result.bssid.to_string()),
                    result.channel,
                    s().dim().paint(&elapsed_str),
                );

                if result.status == PmkidStatus::Captured {
                    line.push_str(&format!("  {}", s().green().paint(label)));
                } else {
                    line.push_str(&format!("  {}", s().dim().paint(label)));
                }
                content_lines.push(line);

                // Show PMKID hex for captured targets
                if result.status == PmkidStatus::Captured {
                    if let Some(pmkid) = &result.pmkid {
                        let hex: String = pmkid.iter().map(|b| format!("{:02x}", b)).collect();
                        content_lines.push(format!("       {}", s().green().paint(&hex)));
                    }
                }
            }
        }

        // Account for the "  " indent we add when printing to scrollback
        let frame_width = (width as usize).saturating_sub(4);

        // Truncate each content line to fit inside the frame borders
        let inner_width = frame_width.saturating_sub(4); // 2 borders + 2 padding
        let truncated_content: Vec<String> = content_lines.iter().map(|line| {
            let display_w = prism::measure_width(line);
            if display_w > inner_width {
                prism::truncate(line, inner_width, "\u{2026}")
            } else {
                line.clone()
            }
        }).collect();

        let content = truncated_content.join("\n");
        let frame_opts = prism::FrameOptions {
            title: Some("PMKID Attack Results".to_string()),
            width: Some(frame_width),
            ..Default::default()
        };
        let framed = prism::frame(&content, &frame_opts);

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
    use std::time::Duration;
    use crate::attacks::pmkid::PmkidResult;
    use crate::core::MacAddress;

    #[test]
    fn test_phase_labels() {
        assert_eq!(phase_label(PmkidPhase::Idle), "idle");
        assert_eq!(phase_label(PmkidPhase::WaitingM1), "waiting M1");
        assert_eq!(phase_label(PmkidPhase::Done), "done");
    }

    #[test]
    fn test_status_labels() {
        assert_eq!(status_label(PmkidStatus::Captured), "PMKID captured");
        assert_eq!(status_label(PmkidStatus::NoPmkid), "no PMKID in M1");
        assert_eq!(status_label(PmkidStatus::Timeout), "timeout");
    }

    #[test]
    fn test_render_empty_info() {
        let info = PmkidInfo::default();
        let lines = render_pmkid_view(&info, 80, 40, 0);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_format_channel_locked_event() {
        let event = PmkidEvent {
            seq: 1,
            timestamp: Duration::from_millis(100),
            kind: PmkidEventKind::ChannelLocked { channel: 6 },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("LOCK"));
        assert!(formatted.contains("ch6"));
    }

    #[test]
    fn test_format_pmkid_captured_event() {
        let event = PmkidEvent {
            seq: 5,
            timestamp: Duration::from_secs(3),
            kind: PmkidEventKind::PmkidCaptured {
                bssid: MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]),
                ssid: "TestAP".to_string(),
                pmkid: [0xAA; 16],
                channel: 6,
                rssi: -42,
                elapsed_ms: 1200,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("PMKID!"));
        assert!(formatted.contains("TestAP"));
        assert!(formatted.contains("aaaa"));
    }

    #[test]
    fn test_status_segments_idle() {
        let info = PmkidInfo::default();
        let segs = status_segments(&info);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_status_segments_running() {
        let mut info = PmkidInfo::default();
        info.running = true;
        info.phase = PmkidPhase::WaitingM1;
        info.current_ssid = "TestAP".to_string();
        info.target_total = 5;
        info.target_index = 2;
        info.pmkids_captured = 1;
        info.elapsed = Duration::from_secs(4);
        let segs = status_segments(&info);
        assert!(segs.len() >= 3);
    }

    #[test]
    fn test_render_with_results() {
        let mut info = PmkidInfo::default();
        info.running = false;
        info.phase = PmkidPhase::Done;
        info.target_total = 2;
        info.target_index = 2;
        info.results.push(PmkidResult {
            bssid: MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]),
            ssid: "TestAP".to_string(),
            channel: 6,
            rssi: -42,
            status: PmkidStatus::Captured,
            pmkid: Some([0xBB; 16]),
            anonce: None,
            key_version: 2,
            elapsed: Duration::from_millis(1500),
        });
        info.results.push(PmkidResult {
            bssid: MacAddress::new([0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]),
            ssid: "OtherAP".to_string(),
            channel: 11,
            rssi: -65,
            status: PmkidStatus::NoPmkid,
            pmkid: None,
            anonce: None,
            key_version: 0,
            elapsed: Duration::from_millis(3200),
        });
        let lines = render_pmkid_view(&info, 100, 40, 0);
        assert!(lines.len() >= 5);
    }
}
