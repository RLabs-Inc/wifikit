//! CLI renderer + Module implementation for the WPA3/Dragonblood attack.

use crate::attacks::wpa3::{
    Wpa3Attack, Wpa3Event, Wpa3EventKind, Wpa3FinalResult, Wpa3Info, Wpa3Mode, Wpa3Params,
    Wpa3Phase, Wpa3Verdict,
};
use crate::core::MacAddress;

use prism::s;

fn phase_label(phase: Wpa3Phase) -> &'static str {
    match phase {
        Wpa3Phase::Idle => "idle",
        Wpa3Phase::ChannelLock => "locking channel",
        Wpa3Phase::Probing => "probing",
        Wpa3Phase::Flooding => "flooding",
        Wpa3Phase::Analyzing => "analyzing",
        Wpa3Phase::Done => "done",
    }
}

fn verdict_icon(v: Wpa3Verdict) -> String {
    match v {
        Wpa3Verdict::Vulnerable => s().red().bold().paint("VULN"),
        Wpa3Verdict::NotVulnerable => s().green().paint("SAFE"),
        Wpa3Verdict::Skipped => s().dim().paint("SKIP"),
        Wpa3Verdict::Pending => s().dim().paint("...."),
        Wpa3Verdict::Testing => s().cyan().paint("TEST"),
        Wpa3Verdict::Error => s().red().paint("ERR!"),
    }
}

fn verdict_symbol(v: Wpa3Verdict) -> String {
    match v {
        Wpa3Verdict::Vulnerable => s().red().bold().paint("\u{2717}"),
        Wpa3Verdict::NotVulnerable => s().green().paint("\u{2714}"),
        Wpa3Verdict::Skipped => s().dim().paint("\u{2212}"),
        Wpa3Verdict::Pending => s().dim().paint("\u{25cb}"),
        Wpa3Verdict::Testing => s().cyan().paint("\u{25cf}"),
        Wpa3Verdict::Error => s().red().paint("!"),
    }
}

pub fn format_event(event: &Wpa3Event) -> String {
    let ts = format!("{:>7.3}s", event.timestamp.as_secs_f64());
    let ts_styled = s().dim().paint(&ts);

    match &event.kind {
        Wpa3EventKind::AttackStarted { bssid, ssid, channel, is_wpa3, transition } => {
            let flags = format!("{}{}",
                if *is_wpa3 { " [WPA3-SAE]" } else { " [NOT WPA3]" },
                if *transition { " [Transition]" } else { "" });
            format!("  [{}] {} Dragonblood \u{2192} {}  {}  ch{}{}",
                ts_styled, s().cyan().bold().paint("WPA3"),
                s().bold().paint(ssid), s().dim().paint(&bssid.to_string()),
                channel, s().dim().paint(&flags))
        }
        Wpa3EventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts_styled, s().dim().paint("LOCK"), channel)
        }
        Wpa3EventKind::ModeStarted { mode, index, total } => {
            format!("  [{}] {} [{}/{}] {} — {}",
                ts_styled, s().cyan().bold().paint("TEST"), index, total,
                s().bold().paint(mode.cve()), mode.description())
        }
        Wpa3EventKind::TimingSample { group, response_us, sample_num } => {
            format!("  [{}] {} Group {} sample #{}: {}us",
                ts_styled, s().dim().paint("TIMING"), group, sample_num, response_us)
        }
        Wpa3EventKind::TimingResult { mean_us, stddev_us, cv, vulnerable } => {
            let v = if *vulnerable { s().red().bold().paint("VULNERABLE") } else { s().green().paint("safe") };
            format!("  [{}] {} mean={:.0}us stddev={:.0}us CV={:.1}% — {}",
                ts_styled, s().bold().paint("TIMING"), mean_us, stddev_us, cv, v)
        }
        Wpa3EventKind::GroupTested { group, accepted, status } => {
            let result = if *accepted { s().red().bold().paint("ACCEPTED") } else { s().green().paint("rejected") };
            format!("  [{}] {} Group {} — {} (status={})",
                ts_styled, s().dim().paint("GROUP"), group, result, status)
        }
        Wpa3EventKind::InvalidCurveResult { accepted, group } => {
            let result = if *accepted { s().red().bold().paint("ACCEPTED — CRITICAL!") } else { s().green().paint("rejected") };
            format!("  [{}] {} Invalid point on Group {} — {}",
                ts_styled, s().bold().paint("CURVE"), group, result)
        }
        Wpa3EventKind::ReflectionResult { accepted } => {
            let result = if *accepted { s().red().bold().paint("ACCEPTED") } else { s().green().paint("rejected") };
            format!("  [{}] {} Reflected commit — {}", ts_styled, s().bold().paint("REFLECT"), result)
        }
        Wpa3EventKind::TokenTriggered => {
            format!("  [{}] {} Anti-clogging token received", ts_styled, s().cyan().paint("TOKEN"))
        }
        Wpa3EventKind::TokenReplayResult { accepted } => {
            let result = if *accepted { s().yellow().paint("accepted (check binding)") } else { s().green().paint("rejected") };
            format!("  [{}] {} Token replay — {}", ts_styled, s().bold().paint("TOKEN"), result)
        }
        Wpa3EventKind::FloodProgress { sent, responded, tokens, rate } => {
            format!("  [{}] {} {} sent, {} responded, {} tokens, {:.0} c/s",
                ts_styled, s().dim().paint("FLOOD"), sent, responded, tokens, rate)
        }
        Wpa3EventKind::ModeComplete { mode, verdict, elapsed_ms } => {
            format!("  [{}] {} {} {}  ({}ms)",
                ts_styled, verdict_icon(*verdict), s().bold().paint(mode.cve()),
                s().dim().paint(mode.label()), elapsed_ms)
        }
        Wpa3EventKind::ModeSkipped { mode, reason } => {
            format!("  [{}] {} {} — {}", ts_styled, s().dim().paint("SKIP"), mode.cve(), s().dim().paint(reason))
        }
        Wpa3EventKind::AttackComplete { tested, vulnerable, skipped, total, elapsed } => {
            let v = if *vulnerable > 0 { s().red().bold().paint(&format!("{} vulnerable", vulnerable)) }
                else { s().green().bold().paint("0 vulnerable") };
            format!("  [{}] {} Dragonblood complete: {}/{} tested, {}, {} skipped  ({:.1}s)",
                ts_styled, s().bold().paint("DONE"), tested, total, v, skipped, elapsed.as_secs_f64())
        }
        Wpa3EventKind::ChannelUnlocked => {
            format!("  [{}] {} Channel unlocked", ts_styled, s().dim().paint("UNLOCK"))
        }
        Wpa3EventKind::Error { message } => {
            format!("  [{}] {} {}", ts_styled, s().red().bold().paint("ERROR"), message)
        }
        Wpa3EventKind::CommitSent { group } => {
            format!("  [{}] {} SAE Commit sent (Group {})", ts_styled, s().dim().paint("SEND"), group)
        }
        Wpa3EventKind::ResponseReceived { status, got_commit } => {
            format!("  [{}] {} SAE response: status={} commit={}", ts_styled, s().dim().paint("RECV"), status, got_commit)
        }
    }
}

pub fn render_wpa3_view(info: &Wpa3Info, width: u16, _height: u16, scroll_offset: usize) -> Vec<String> {
    let w = width as usize;
    let inner_w = w.saturating_sub(6); // border + padding

    // ── Border helpers ──
    let bc = |t: &str| s().dim().paint(t);
    let vline = |content: &str, iw: usize| {
        let display_w = prism::measure_width(content);
        let pad = iw.saturating_sub(display_w);
        format!("  {} {}{}{}", bc("\u{2502}"), content, " ".repeat(pad), bc("\u{2502}"))
    };
    let empty_line = || vline("", inner_w);

    let mut lines = Vec::new();

    // ═══ Header border with title ═══
    let title = s().red().bold().paint(" dragonblood ");
    let title_plain_w = 13; // " dragonblood "
    let remaining = inner_w.saturating_sub(title_plain_w + 1);
    lines.push(format!("  {}{}{}{}", bc("\u{256d}\u{2500}"), title,
        bc(&"\u{2500}".repeat(remaining)), bc("\u{256e}")));

    // ═══ Current target ═══
    if info.target_bssid != MacAddress::ZERO {
        let ssid_display = if info.target_ssid.is_empty() {
            s().dim().italic().paint("(hidden)")
        } else {
            s().bold().paint(&prism::truncate(&info.target_ssid, 24, "\u{2026}"))
        };

        let wpa3_badge = if info.target_is_wpa3 {
            if info.target_transition {
                s().yellow().paint("[SAE-Transition]")
            } else {
                s().green().bold().paint("[WPA3-SAE]")
            }
        } else {
            s().red().paint("[NOT WPA3]")
        };

        let target_line = format!("{}  {}  ch{}  {}",
            ssid_display,
            s().dim().paint(&info.target_bssid.to_string()),
            info.target_channel,
            wpa3_badge,
        );
        lines.push(vline(&target_line, inner_w));
    } else if !info.running && info.phase == Wpa3Phase::Done {
        lines.push(vline(&s().dim().paint("Attack complete"), inner_w));
    } else if !info.running {
        lines.push(vline(&s().dim().paint("Idle"), inner_w));
    }

    // ═══ Step progress: ○ LOCK → ● PROBE → ⠋ TEST... ═══
    if info.running || info.phase == Wpa3Phase::Done {
        let spinner = prism::get_spinner("dots");
        let spin_frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let lock_step = match info.phase {
            Wpa3Phase::Idle => format!("{} LOCK", s().dim().paint("\u{25cb}")),
            Wpa3Phase::ChannelLock => format!("{} LOCK", s().yellow().paint(spin_frame)),
            _ => format!("{} LOCK", s().green().paint("\u{2714}")),
        };

        let probe_step = match info.phase {
            Wpa3Phase::Idle | Wpa3Phase::ChannelLock =>
                format!("{} PROBE", s().dim().paint("\u{25cb}")),
            Wpa3Phase::Probing => format!("{} PROBE", s().cyan().paint(spin_frame)),
            _ => format!("{} PROBE", s().green().paint("\u{2714}")),
        };

        let test_step = match info.phase {
            Wpa3Phase::Flooding => format!("{} TEST", s().red().bold().paint(spin_frame)),
            Wpa3Phase::Analyzing => format!("{} TEST", s().magenta().bold().paint(spin_frame)),
            Wpa3Phase::Done => format!("{} TEST", s().green().paint("\u{2714}")),
            _ => format!("{} TEST", s().dim().paint("\u{25cb}")),
        };

        let arrow = s().dim().paint(" \u{2192} ");
        let steps = format!("{}{}{}{}{}", lock_step, arrow, probe_step, arrow, test_step);
        lines.push(vline(&steps, inner_w));
    }

    lines.push(empty_line());

    // ═══ Mode progress bar ═══
    if info.mode_total > 0 {
        let bar_w = inner_w.saturating_sub(20);
        fn red_bar(t: &str) -> String { s().red().paint(t) }
        let bar = prism::render_progress_bar(info.mode_index as u64, &prism::RenderOptions {
            total: info.mode_total as u64,
            width: bar_w,
            style: prism::BarStyle::Smooth,
            color: Some(red_bar),
            ..Default::default()
        });

        let vuln_label = if info.modes_vulnerable > 0 {
            s().red().bold().paint(&format!("{}\u{2717}", info.modes_vulnerable))
        } else {
            s().green().paint("0\u{2714}")
        };
        let label = format!("{}/{} modes  {}", info.mode_index, info.mode_total, vuln_label);
        lines.push(vline(&format!("{}  {}", bar, s().dim().paint(&label)), inner_w));

        // Stats line
        let elapsed = info.start_time.elapsed().as_secs_f64();
        let mut stats = format!("{} sent  {} recv  {:.0} fps  {:.1}s",
            prism::format_number(info.commits_sent),
            prism::format_number(info.commits_received),
            info.frames_per_sec,
            elapsed);
        if info.tx_feedback.total_reports > 0 {
            stats.push_str(&format!("  {} ack  {} nack",
                s().green().paint(&prism::format_number(info.tx_feedback.acked)),
                s().red().paint(&prism::format_number(info.tx_feedback.nacked))));
            if let Some(pct) = info.tx_feedback.delivery_pct() {
                stats.push_str(&format!("  {}%", pct as u64));
            }
        }
        lines.push(vline(&s().dim().paint(&stats), inner_w));

        // Current mode indicator
        if let Some(mode) = &info.current_mode {
            let mode_line = format!("{} {}  {}",
                s().cyan().bold().paint("\u{25b6}"),
                s().bold().paint(mode.cve()),
                s().dim().paint(mode.description()));
            lines.push(vline(&mode_line, inner_w));
        }

        lines.push(empty_line());
    }

    // ═══ Results table (scrollable) ═══
    let term_h = prism::term_height() as usize;
    let max_view = term_h * 40 / 100;
    let header_lines = lines.len();
    let footer_lines = 1;
    let available = max_view.saturating_sub(header_lines + footer_lines);

    if !info.results.is_empty() {
        // Table header
        let hdr = format!("{}  {}  {}  {}  {}",
            s().bold().dim().paint(&prism::pad("", 2, "left")),
            s().bold().dim().paint(&prism::pad("CVE", 14, "left")),
            s().bold().dim().paint(&prism::pad("MODE", 18, "left")),
            s().bold().dim().paint(&prism::pad("VERDICT", 6, "left")),
            s().bold().dim().paint("DETAIL"),
        );
        lines.push(vline(&hdr, inner_w));

        let mut result_rows: Vec<String> = Vec::new();
        for r in &info.results {
            let icon = verdict_symbol(r.verdict);

            // Build rich detail based on mode + verdict
            let detail = match (r.verdict, r.mode) {
                (Wpa3Verdict::Vulnerable, Wpa3Mode::Timing) =>
                    format!("mean={:.0}us CV={:.1}% ({}samp)",
                        r.timing_mean_us, r.timing_cv, r.timing_samples_count),
                (Wpa3Verdict::Vulnerable, Wpa3Mode::GroupDowngrade) =>
                    format!("{}/{} groups accepted, weakest={}",
                        r.groups_accepted, r.groups_tested, r.weakest_group),
                (Wpa3Verdict::Vulnerable, Wpa3Mode::CommitFlood) =>
                    format!("{} sent, {} resp, {} tokens",
                        r.flood_sent, r.flood_responded, r.flood_tokens_triggered),
                (Wpa3Verdict::NotVulnerable, _) =>
                    format!("{} sent, {}ms", r.frames_sent, r.elapsed.as_millis()),
                (Wpa3Verdict::Skipped, _) =>
                    prism::truncate(&r.detail, 36, "\u{2026}").to_string(),
                (Wpa3Verdict::Testing, _) => {
                    let spinner = prism::get_spinner("dots");
                    let frame = spinner.as_ref().map(|sp| {
                        let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
                        sp.frames[idx]
                    }).unwrap_or(".");
                    format!("{} testing...", frame)
                }
                _ if !r.detail.is_empty() =>
                    prism::truncate(&r.detail, 36, "\u{2026}").to_string(),
                _ => String::new(),
            };

            let cve_styled = match r.verdict {
                Wpa3Verdict::Vulnerable => s().red().paint(r.mode.cve()),
                _ => s().dim().paint(r.mode.cve()),
            };

            let row = format!("{}  {}  {}  {}  {}",
                icon,
                cve_styled,
                s().bold().paint(&prism::pad(r.mode.label(), 18, "left")),
                verdict_icon(r.verdict),
                s().dim().paint(&detail));
            result_rows.push(vline(&row, inner_w));
        }

        // Scroll results
        let total_rows = result_rows.len();
        if total_rows <= available {
            lines.extend(result_rows);
        } else {
            let max_offset = total_rows.saturating_sub(available.saturating_sub(2));
            let offset = scroll_offset.min(max_offset);
            let visible_slots = available.saturating_sub(
                if offset > 0 { 1 } else { 0 } + if offset + available < total_rows { 1 } else { 0 }
            );
            let end = (offset + visible_slots).min(total_rows);

            if offset > 0 {
                lines.push(vline(&s().dim().paint(&format!("\u{2191} {} above", offset)), inner_w));
            }
            lines.extend_from_slice(&result_rows[offset..end]);
            let remaining_below = total_rows.saturating_sub(end);
            if remaining_below > 0 {
                lines.push(vline(&s().dim().paint(&format!("\u{2193} {} below", remaining_below)), inner_w));
            }
        }
    } else if info.running {
        let spinner = prism::get_spinner("dots");
        let frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(vline(&format!("{} {}", s().cyan().paint(frame),
            s().dim().paint("Initializing Dragonblood scan...")), inner_w));
    }

    // ═══ Bottom border ═══
    lines.push(format!("  {}{}{}", bc("\u{2570}"),
        bc(&"\u{2500}".repeat(inner_w + 1)), bc("\u{256f}")));

    lines
}

pub fn status_segments(info: &Wpa3Info) -> Vec<StatusSegment> {
    let mut segs = Vec::new();
    if !info.running && info.phase == Wpa3Phase::Idle { return segs; }

    let text = if let Some(m) = &info.current_mode {
        format!("wpa3: {} ({})", m.cve(), phase_label(info.phase))
    } else { format!("wpa3: {}", phase_label(info.phase)) };
    segs.push(StatusSegment::new(text, SegmentStyle::RedBold));

    if info.modes_vulnerable > 0 {
        segs.push(StatusSegment::new(format!("{}\u{2717}", info.modes_vulnerable), SegmentStyle::RedBold));
    }
    if info.mode_total > 0 {
        segs.push(StatusSegment::new(format!("{}/{}", info.mode_index, info.mode_total), SegmentStyle::Dim));
    }
    if let Some(pct) = info.tx_feedback.delivery_pct() {
        segs.push(StatusSegment::new(format!("{}%tx", pct as u64), SegmentStyle::Dim));
    }
    segs.push(StatusSegment::new(
        format!("{:.1}s", info.start_time.elapsed().as_secs_f64()),
        SegmentStyle::Dim,
    ));
    segs
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Wpa3Module
// ═══════════════════════════════════════════════════════════════════════════════

use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};

pub struct Wpa3Module {
    attack: Wpa3Attack,
    cached_info: Option<Wpa3Info>,
    pending_events: Vec<Wpa3Event>,
    scroll_offset: usize,
}

impl Wpa3Module {
    pub fn new(params: Wpa3Params) -> Self {
        Self { attack: Wpa3Attack::new(params), cached_info: None, pending_events: Vec::new(), scroll_offset: 0 }
    }
    pub fn attack(&self) -> &Wpa3Attack { &self.attack }
    pub fn drain_events(&mut self) -> Vec<Wpa3Event> {
        let events = self.attack.events();
        self.pending_events.extend(events.iter().cloned());
        events
    }
}

impl Module for Wpa3Module {
    fn name(&self) -> &str { "wpa3" }
    fn description(&self) -> &str { "WPA3/Dragonblood — 8 attack modes" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }
    fn start(&mut self, _shared: crate::adapter::SharedAdapter) { panic!("use attack().start()"); }
    fn signal_stop(&self) { self.attack.signal_stop(); }
    fn is_running(&self) -> bool { self.attack.is_running() }
    fn is_done(&self) -> bool { self.attack.is_done() }
    fn views(&self) -> &[ViewDef] { &[] }
    fn render(&mut self, _view: usize, width: u16, height: u16) -> Vec<String> {
        let info = self.attack.info();
        self.cached_info = Some(info.clone());
        render_wpa3_view(&info, width, height, self.scroll_offset)
    }
    fn handle_key(&mut self, key: &prism::KeyEvent, _view: usize) -> bool {
        if key.ctrl || key.meta { return false; }
        match key.key.as_str() {
            "j" => { self.scroll_offset = self.scroll_offset.saturating_add(1); true }
            "k" => { self.scroll_offset = self.scroll_offset.saturating_sub(1); true }
            "G" => { self.scroll_offset = usize::MAX; true }
            "g" => { self.scroll_offset = 0; true }
            _ => false,
        }
    }
    fn status_segments(&self) -> Vec<StatusSegment> {
        let info = self.attack.info();
        status_segments(&info)
    }
    fn freeze_summary(&self, width: u16) -> Vec<String> {
        let info = self.cached_info.as_ref().cloned().unwrap_or_else(|| self.attack.info());
        let final_result = Wpa3FinalResult {
            results: info.results.clone(),
            modes_tested: info.modes_tested,
            modes_vulnerable: info.modes_vulnerable,
            elapsed: info.start_time.elapsed(),
        };
        let mut content_lines = Vec::new();
        content_lines.push(format!("Target: {} ({})",
            info.target_ssid, info.target_bssid));
        if info.target_is_wpa3 {
            content_lines.push(format!("WPA3: SAE{}", if info.target_transition { " (Transition)" } else { "" }));
        } else {
            content_lines.push("WPA3: Not detected (testing anyway)".to_string());
        }
        content_lines.push(format!("Modes tested: {}/{}",
            final_result.modes_tested, info.mode_total));
        let vuln_str = if final_result.modes_vulnerable > 0 {
            s().red().bold().paint(&format!("{} VULNERABLE", final_result.modes_vulnerable))
        } else {
            s().green().bold().paint("0 vulnerable")
        };
        content_lines.push(format!("Vulnerable: {}", vuln_str));
        content_lines.push(format!("Commits: {} sent, {} received",
            prism::format_number(info.commits_sent),
            prism::format_number(info.commits_received)));
        content_lines.push(format!("Duration: {:.1}s", final_result.elapsed.as_secs_f64()));
        for r in &final_result.results {
            if r.verdict == Wpa3Verdict::Vulnerable {
                content_lines.push(format!("  {} {} {}",
                    s().red().bold().paint("\u{2717}"),
                    s().bold().paint(r.mode.cve()),
                    r.mode.description()));
            }
        }
        let content = content_lines.join("\n");
        let framed = prism::frame(&content, &prism::FrameOptions {
            border: prism::BorderStyle::Rounded,
            title: Some("Dragonblood Complete".into()),
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
    use crate::attacks::wpa3::{Wpa3Mode, Wpa3TestResult};
    use crate::core::MacAddress;

    #[test] fn test_phase_labels() { assert_eq!(phase_label(Wpa3Phase::Probing), "probing"); }
    #[test] fn test_verdict_icons() { let _ = verdict_icon(Wpa3Verdict::Vulnerable); }
    #[test] fn test_render_empty() { assert!(!render_wpa3_view(&Wpa3Info::default(), 80, 40, 0).is_empty()); }
    #[test] fn test_status_idle() { assert!(status_segments(&Wpa3Info::default()).is_empty()); }
    #[test] fn test_module_new() { let m = Wpa3Module::new(Wpa3Params::default()); assert_eq!(m.name(), "wpa3"); }

    #[test]
    fn test_format_attack_started() {
        let e = Wpa3Event { seq: 1, timestamp: Duration::from_millis(50),
            kind: Wpa3EventKind::AttackStarted {
                bssid: MacAddress::new([0xAA; 6]), ssid: "WPA3-AP".to_string(),
                channel: 6, is_wpa3: true, transition: false,
            }};
        assert!(format_event(&e).contains("WPA3"));
    }

    #[test]
    fn test_render_with_results() {
        let mut info = Wpa3Info::default();
        info.phase = Wpa3Phase::Done;
        info.mode_total = 7;
        info.results = Wpa3Mode::all_tests().iter().map(|m| {
            let mut r = Wpa3TestResult::new(*m);
            r.verdict = Wpa3Verdict::NotVulnerable;
            r.detail = "OK".to_string();
            r
        }).collect();
        info.results[3].verdict = Wpa3Verdict::Vulnerable;
        info.results[3].detail = "AP accepted invalid curve point".to_string();
        let lines = render_wpa3_view(&info, 120, 40, 0);
        assert!(lines.len() >= 9);
    }
}
