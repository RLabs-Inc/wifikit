//! CLI renderer + Module implementation for the FragAttacks test suite.
//!
//! Renders the test progress as styled terminal lines:
//! - Current variant being tested with CVE number
//! - Progress bar across all variants
//! - Results table showing verdicts (vulnerable/not/skipped)
//! - Event log scrollback with injection and response details

use crate::attacks::frag::{
    FragAttack, FragEvent, FragEventKind, FragFinalResult, FragInfo, FragParams,
    FragPhase, FragVerdict,
};

use prism::{s, truncate};

// ═══════════════════════════════════════════════════════════════════════════════
//  Phase display
// ═══════════════════════════════════════════════════════════════════════════════

fn phase_label(phase: FragPhase) -> &'static str {
    match phase {
        FragPhase::Idle => "idle",
        FragPhase::ChannelLock => "locking channel",
        FragPhase::MitmSetup => "MitM setup",
        FragPhase::Injecting => "injecting",
        FragPhase::Monitoring => "monitoring",
        FragPhase::Done => "done",
    }
}

fn verdict_icon(verdict: FragVerdict) -> String {
    match verdict {
        FragVerdict::Vulnerable => s().red().bold().paint("VULN"),
        FragVerdict::NotVulnerable => s().green().paint("SAFE"),
        FragVerdict::Skipped => s().dim().paint("SKIP"),
        FragVerdict::Pending => s().dim().paint("...."),
        FragVerdict::Testing => s().cyan().paint("TEST"),
        FragVerdict::Error => s().red().paint("ERR!"),
    }
}

fn verdict_symbol(verdict: FragVerdict) -> String {
    match verdict {
        FragVerdict::Vulnerable => s().red().bold().paint("\u{2717}"),      // ✗
        FragVerdict::NotVulnerable => s().green().paint("\u{2714}"),         // ✔
        FragVerdict::Skipped => s().dim().paint("\u{2212}"),                 // −
        FragVerdict::Pending => s().dim().paint("\u{25cb}"),                 // ○
        FragVerdict::Testing => s().cyan().paint("\u{25cf}"),                // ●
        FragVerdict::Error => s().red().paint("!"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Event formatting — for scrollback output
// ═══════════════════════════════════════════════════════════════════════════════

/// Format a FragAttacks event as a styled terminal line for the output zone.
pub fn format_event(event: &FragEvent) -> String {
    let ts = format!("{:>7.3}s", event.timestamp.as_secs_f64());
    let ts_styled = s().dim().paint(&ts);

    match &event.kind {
        FragEventKind::SuiteStarted { bssid, ssid, channel, variant_count } => {
            format!("  [{}] {} FragAttacks \u{2192} {}  {}  ch{}  ({} tests)",
                ts_styled,
                s().cyan().bold().paint("FRAG"),
                s().bold().paint(ssid),
                s().dim().paint(&bssid.to_string()),
                channel,
                variant_count)
        }
        FragEventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts_styled, s().dim().paint("LOCK"), channel)
        }
        FragEventKind::TestStarted { variant, index, total } => {
            let category = if variant.is_design_flaw() {
                s().yellow().paint("design flaw")
            } else {
                s().cyan().paint("impl bug")
            };
            format!("  [{}] {} [{}/{}] {} ({}) — {}",
                ts_styled,
                s().cyan().bold().paint("TEST"),
                index, total,
                s().bold().paint(variant.cve()),
                category,
                variant.description())
        }
        FragEventKind::FramesInjected { variant, count, retry } => {
            let retry_str = if *retry > 0 {
                format!(" (retry {})", retry)
            } else {
                String::new()
            };
            format!("  [{}] {} {} — {} frames injected{}",
                ts_styled,
                s().dim().paint("INJECT"),
                variant.label(),
                s().bold().paint(&count.to_string()),
                retry_str)
        }
        FragEventKind::MonitoringResponse { variant, timeout_ms } => {
            format!("  [{}] {} {} — waiting {}ms for response...",
                ts_styled,
                s().dim().paint("MONITOR"),
                variant.label(),
                timeout_ms)
        }
        FragEventKind::ResponseReceived { variant, response_time_ms } => {
            format!("  [{}] {} {} — response in {}ms!",
                ts_styled,
                s().red().bold().paint("VULN!"),
                s().bold().paint(variant.cve()),
                response_time_ms)
        }
        FragEventKind::RetryingTest { variant, retry, max_retries } => {
            format!("  [{}] {} {} — retry {}/{}",
                ts_styled,
                s().yellow().paint("RETRY"),
                variant.label(),
                retry, max_retries)
        }
        FragEventKind::TestComplete { variant, verdict, frames_sent, response_time_ms, elapsed_ms } => {
            let verdict_str = verdict_icon(*verdict);
            let time_str = if *verdict == FragVerdict::Vulnerable {
                format!("  {}ms response", response_time_ms)
            } else {
                String::new()
            };
            format!("  [{}] {} {} {}  ({} frames, {}ms){}",
                ts_styled,
                verdict_str,
                s().bold().paint(variant.cve()),
                s().dim().paint(variant.label()),
                frames_sent,
                elapsed_ms,
                time_str)
        }
        FragEventKind::TestSkipped { variant, reason } => {
            format!("  [{}] {} {} — {}",
                ts_styled,
                s().dim().paint("SKIP"),
                variant.cve(),
                s().dim().paint(reason))
        }
        FragEventKind::SuiteComplete { tested, vulnerable, skipped, total, elapsed } => {
            let vuln_str = if *vulnerable > 0 {
                s().red().bold().paint(&format!("{} vulnerable", vulnerable))
            } else {
                s().green().bold().paint("0 vulnerable")
            };
            format!("  [{}] {} FragAttacks complete: {}/{} tested, {}, {} skipped  ({:.1}s)",
                ts_styled,
                s().bold().paint("DONE"),
                tested, total,
                vuln_str,
                skipped,
                elapsed.as_secs_f64())
        }
        FragEventKind::ChannelUnlocked => {
            format!("  [{}] {} Channel unlocked — scanner resumes hopping",
                ts_styled, s().dim().paint("UNLOCK"))
        }
        FragEventKind::Error { message } => {
            format!("  [{}] {} {}", ts_styled, s().red().bold().paint("ERROR"), message)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Results table — rendered in the active zone during/after test suite
// ═══════════════════════════════════════════════════════════════════════════════

/// Render the FragAttacks test progress view for the Layout active zone.
pub fn render_frag_view(info: &FragInfo, width: u16, _height: u16, scroll_offset: usize) -> Vec<String> {
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

    // ═══ Header border ═══
    let title = s().red().bold().paint(" fragattacks ");
    let title_plain_w = 13;
    let remaining = inner_w.saturating_sub(title_plain_w + 1);
    lines.push(format!("  {}{}{}{}", bc("\u{256d}\u{2500}"), title,
        bc(&"\u{2500}".repeat(remaining)), bc("\u{256e}")));

    // ═══ Target ═══
    if info.target_bssid != crate::core::MacAddress::ZERO {
        let ssid_display = if info.target_ssid.is_empty() {
            s().dim().italic().paint("(hidden)")
        } else {
            s().bold().paint(&prism::truncate(&info.target_ssid, 24, "\u{2026}"))
        };

        // RSSI bar
        fn rssi_green(t: &str) -> String { s().green().paint(t) }
        fn rssi_yellow(t: &str) -> String { s().yellow().paint(t) }
        fn rssi_red(t: &str) -> String { s().red().paint(t) }
        let rssi_val = (info.target_rssi + 100).max(0).min(60) as u64;
        let rssi_bar = prism::render_progress_bar(rssi_val, &prism::RenderOptions {
            total: 60, width: 8, style: prism::BarStyle::Bar,
            color: Some(if info.target_rssi > -50 { rssi_green }
                else if info.target_rssi > -70 { rssi_yellow }
                else { rssi_red }),
            ..Default::default()
        });

        lines.push(vline(&format!("{}  {}  ch{}  {} dBm {}",
            ssid_display, s().dim().paint(&info.target_bssid.to_string()),
            info.target_channel, info.target_rssi, rssi_bar), inner_w));
    }

    // ═══ Step progress ═══
    if info.running || info.phase == FragPhase::Done {
        let spinner = prism::get_spinner("dots");
        let spin_frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let lock_step = match info.phase {
            FragPhase::Idle => format!("{} LOCK", s().dim().paint("\u{25cb}")),
            FragPhase::ChannelLock => format!("{} LOCK", s().yellow().paint(spin_frame)),
            _ => format!("{} LOCK", s().green().paint("\u{2714}")),
        };
        let inject_step = match info.phase {
            FragPhase::Injecting => format!("{} INJECT", s().red().bold().paint(spin_frame)),
            FragPhase::Monitoring | FragPhase::Done => format!("{} INJECT", s().green().paint("\u{2714}")),
            _ => format!("{} INJECT", s().dim().paint("\u{25cb}")),
        };
        let monitor_step = match info.phase {
            FragPhase::Monitoring => format!("{} MONITOR", s().magenta().bold().paint(spin_frame)),
            FragPhase::Done => format!("{} MONITOR", s().green().paint("\u{2714}")),
            _ => format!("{} MONITOR", s().dim().paint("\u{25cb}")),
        };

        let arrow = s().dim().paint(" \u{2192} ");
        lines.push(vline(&format!("{}{}{}{}{}", lock_step, arrow, inject_step, arrow, monitor_step), inner_w));
    }

    lines.push(empty_line());

    // ═══ Progress bar + stats ═══
    if info.variant_total > 0 {
        let bar_w = inner_w.saturating_sub(20);
        fn red_bar(t: &str) -> String { s().red().paint(t) }
        let bar = prism::render_progress_bar(info.variant_index as u64, &prism::RenderOptions {
            total: info.variant_total as u64, width: bar_w,
            style: prism::BarStyle::Smooth, color: Some(red_bar),
            ..Default::default()
        });
        let vuln_label = if info.variants_vulnerable > 0 {
            s().red().bold().paint(&format!("{}\u{2717}", info.variants_vulnerable))
        } else { s().green().paint("0\u{2714}") };
        lines.push(vline(&format!("{}  {}/{} tests  {}", bar,
            info.variant_index, info.variant_total, vuln_label), inner_w));

        let elapsed = info.start_time.elapsed().as_secs_f64();
        let retry_str = if info.current_retry > 0 {
            format!("  retry {}", info.current_retry)
        } else { String::new() };
        let mut stats = format!("{} sent  {} recv  {:.0} fps  {:.1}s{}",
            prism::format_number(info.frames_sent),
            prism::format_number(info.frames_received),
            info.frames_per_sec,
            elapsed,
            s().yellow().paint(&retry_str));
        if info.tx_feedback.total_reports > 0 {
            stats.push_str(&format!("  {} ack  {} nack",
                s().green().paint(&prism::format_number(info.tx_feedback.acked)),
                s().red().paint(&prism::format_number(info.tx_feedback.nacked))));
            if let Some(pct) = info.tx_feedback.delivery_pct() {
                stats.push_str(&format!("  {}%", pct as u64));
            }
        }
        lines.push(vline(&s().dim().paint(&stats), inner_w));

        if let Some(variant) = &info.current_variant {
            let category = if variant.is_design_flaw() {
                s().yellow().paint("design flaw")
            } else { s().cyan().paint("impl bug") };
            lines.push(vline(&format!("{} {} ({})  {}",
                s().cyan().bold().paint("\u{25b6}"),
                s().bold().paint(variant.cve()), category,
                s().dim().paint(variant.description())), inner_w));
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
        lines.push(vline(&format!("{}  {}  {}  {}  {}",
            s().bold().dim().paint(&prism::pad("", 2, "left")),
            s().bold().dim().paint(&prism::pad("CVE", 14, "left")),
            s().bold().dim().paint(&prism::pad("VARIANT", 22, "left")),
            s().bold().dim().paint(&prism::pad("VERDICT", 6, "left")),
            s().bold().dim().paint("DETAIL")), inner_w));

        let mut result_rows: Vec<String> = Vec::new();
        for result in &info.results {
            let icon = verdict_symbol(result.verdict);
            let detail = match result.verdict {
                FragVerdict::Vulnerable => format!("{}ms resp, {} frames",
                    result.response_time_ms, result.frames_sent),
                FragVerdict::NotVulnerable => format!("{} frames, {}ms",
                    result.frames_sent, result.elapsed.as_millis()),
                FragVerdict::Skipped => truncate(&result.detail, 30, "\u{2026}").to_string(),
                FragVerdict::Testing => {
                    let sp = prism::get_spinner("dots");
                    let f = sp.as_ref().map(|sp| {
                        let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
                        sp.frames[idx]
                    }).unwrap_or(".");
                    format!("{} retry {}, {} frames", f, result.retries, result.frames_sent)
                }
                _ => String::new(),
            };
            let cve_styled = match result.verdict {
                FragVerdict::Vulnerable => s().red().paint(result.variant.cve()),
                _ => s().dim().paint(result.variant.cve()),
            };
            result_rows.push(vline(&format!("{}  {}  {}  {}  {}",
                icon, cve_styled,
                s().bold().paint(&prism::pad(result.variant.label(), 22, "left")),
                verdict_icon(result.verdict),
                s().dim().paint(&detail)), inner_w));
        }

        let total_rows = result_rows.len();
        if total_rows <= available {
            lines.extend(result_rows);
        } else {
            let max_offset = total_rows.saturating_sub(available.saturating_sub(2));
            let offset = scroll_offset.min(max_offset);
            let visible_slots = available.saturating_sub(
                if offset > 0 { 1 } else { 0 } + if offset + available < total_rows { 1 } else { 0 });
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
    } else if info.running && info.phase == FragPhase::ChannelLock {
        let sp = prism::get_spinner("dots");
        let f = sp.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(vline(&format!("{} {}", s().cyan().paint(f),
            s().dim().paint("Locking channel...")), inner_w));
    }

    lines.push(format!("  {}{}{}", bc("\u{2570}"),
        bc(&"\u{2500}".repeat(inner_w + 1)), bc("\u{256f}")));

    lines
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status bar segments
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate status bar segments for the FragAttacks test suite.
pub fn status_segments(info: &FragInfo) -> Vec<StatusSegment> {
    let mut segs = Vec::new();

    if !info.running && info.phase == FragPhase::Idle {
        return segs;
    }

    let attack_text = if let Some(variant) = &info.current_variant {
        format!("frag: {} ({})", variant.cve(), phase_label(info.phase))
    } else {
        format!("frag: {}", phase_label(info.phase))
    };

    segs.push(StatusSegment::new(attack_text, SegmentStyle::RedBold));

    if info.variants_vulnerable > 0 {
        segs.push(StatusSegment::new(format!("{}\u{2717}", info.variants_vulnerable), SegmentStyle::RedBold));
    }

    if info.variant_total > 0 {
        segs.push(StatusSegment::new(
            format!("{}/{}", info.variant_index, info.variant_total),
            SegmentStyle::Dim,
        ));
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
//  FragModule — Module trait implementation for FragAttacks
// ═══════════════════════════════════════════════════════════════════════════════

use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};

/// FragModule wraps FragAttack with the Module trait for the shell's focus stack.
pub struct FragModule {
    attack: FragAttack,
    cached_info: Option<FragInfo>,
    pending_events: Vec<FragEvent>,
    scroll_offset: usize,
}

impl FragModule {
    pub fn new(params: FragParams) -> Self {
        let attack = FragAttack::new(params);
        Self {
            attack,
            cached_info: None,
            pending_events: Vec::new(),
            scroll_offset: 0,
        }
    }

    /// Get the underlying attack for starting with target.
    pub fn attack(&self) -> &FragAttack {
        &self.attack
    }

    /// Drain new events since last call.
    pub fn drain_events(&mut self) -> Vec<FragEvent> {
        let events = self.attack.events();
        self.pending_events.extend(events.iter().cloned());
        events
    }

    /// Get current attack info. Used by the shell for external state access.
    #[allow(dead_code)]
    pub fn info(&self) -> FragInfo {
        self.attack.info()
    }
}

impl Module for FragModule {
    fn name(&self) -> &str { "frag" }
    fn description(&self) -> &str { "FragAttacks — 12 CVE vulnerability tests" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }

    fn start(&mut self, _shared: crate::adapter::SharedAdapter) {
        // Target should be set before calling start().
        // The shell calls attack().start(shared, target) directly.
        // This fallback creates a dummy target — shell should use
        // attack().start(shared, target) for proper operation.
        panic!("FragModule: use attack().start(shared, target) instead");
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
        &[] // Single view — no tabs
    }

    fn render(&mut self, _view: usize, width: u16, height: u16) -> Vec<String> {
        let info = self.attack.info();
        self.cached_info = Some(info.clone());
        render_frag_view(&info, width, height, self.scroll_offset)
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
        let info = self.cached_info.as_ref().cloned()
            .unwrap_or_else(|| self.attack.info());
        let final_result = FragFinalResult {
            results: info.results.clone(),
            tests_run: info.variants_tested,
            vulnerabilities_found: info.variants_vulnerable,
            elapsed: info.start_time.elapsed(),
        };
        let mut content_lines = Vec::new();
        content_lines.push(format!("Target: {} ({})",
            info.target_ssid, info.target_bssid));
        content_lines.push(format!("Tests run: {}/{}",
            final_result.tests_run, info.variant_total));
        let vuln_str = if final_result.vulnerabilities_found > 0 {
            s().red().bold().paint(&format!("{} VULNERABLE", final_result.vulnerabilities_found))
        } else {
            s().green().bold().paint("0 vulnerable")
        };
        content_lines.push(format!("Vulnerable: {}", vuln_str));
        content_lines.push(format!("Skipped: {}", info.variants_skipped));
        content_lines.push(format!("Frames: {} sent, {} received",
            prism::format_number(info.frames_sent),
            prism::format_number(info.frames_received)));
        content_lines.push(format!("Duration: {:.1}s", final_result.elapsed.as_secs_f64()));
        for result in &final_result.results {
            if result.verdict == FragVerdict::Vulnerable {
                content_lines.push(format!("  {} {} {}  {}ms response",
                    s().red().bold().paint("\u{2717}"),
                    s().bold().paint(result.variant.cve()),
                    result.variant.description(),
                    result.response_time_ms));
            }
        }
        let content = content_lines.join("\n");
        let framed = prism::frame(&content, &prism::FrameOptions {
            border: prism::BorderStyle::Rounded,
            title: Some("FragAttacks Complete".into()),
            width: Some((width as usize).saturating_sub(4)),
            ..Default::default()
        });
        framed.lines().map(|l| l.to_string()).collect()
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use crate::attacks::frag::{FragTestResult, FragVariant};
    use crate::core::MacAddress;

    #[test]
    fn test_phase_labels() {
        assert_eq!(phase_label(FragPhase::Idle), "idle");
        assert_eq!(phase_label(FragPhase::Injecting), "injecting");
        assert_eq!(phase_label(FragPhase::Monitoring), "monitoring");
        assert_eq!(phase_label(FragPhase::Done), "done");
    }

    #[test]
    fn test_verdict_icons() {
        // Just verify they don't panic
        let _ = verdict_icon(FragVerdict::Vulnerable);
        let _ = verdict_icon(FragVerdict::NotVulnerable);
        let _ = verdict_icon(FragVerdict::Skipped);
        let _ = verdict_icon(FragVerdict::Pending);
        let _ = verdict_icon(FragVerdict::Testing);
        let _ = verdict_icon(FragVerdict::Error);
    }

    #[test]
    fn test_render_empty_info() {
        let info = FragInfo::default();
        let lines = render_frag_view(&info, 80, 40, 0);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_render_with_results() {
        let mut info = FragInfo::default();
        info.running = false;
        info.phase = FragPhase::Done;
        info.variant_total = 12;
        info.variant_index = 12;
        info.variants_tested = 9;
        info.variants_vulnerable = 2;
        info.variants_skipped = 3;
        info.results = FragVariant::all().iter().map(|v| {
            let mut r = FragTestResult {
                variant: *v,
                verdict: FragVerdict::NotVulnerable,
                frames_sent: 10,
                frames_received: 0,
                response_time_ms: 0,
                detail: String::new(),
                retries: 3,
                elapsed: Duration::from_secs(5),
            };
            if v.requires_mitm() {
                r.verdict = FragVerdict::Skipped;
                r.detail = "requires MitM".to_string();
            }
            if *v == FragVariant::PlaintextFull {
                r.verdict = FragVerdict::Vulnerable;
                r.response_time_ms = 47;
            }
            if *v == FragVariant::EapolAmsdu {
                r.verdict = FragVerdict::Vulnerable;
                r.response_time_ms = 112;
            }
            r
        }).collect();

        let lines = render_frag_view(&info, 120, 40, 0);
        // Bordered view with target, steps, progress, results, bottom border
        // In test env, term_height may be small so results get scroll-capped
        assert!(lines.len() >= 5, "expected >= 5 lines, got {}", lines.len());
    }

    #[test]
    fn test_format_suite_started_event() {
        let event = FragEvent {
            seq: 1,
            timestamp: Duration::from_millis(50),
            kind: FragEventKind::SuiteStarted {
                bssid: MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
                ssid: "TestAP".to_string(),
                channel: 6,
                variant_count: 12,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("FRAG"));
        assert!(formatted.contains("TestAP"));
        assert!(formatted.contains("12 tests"));
    }

    #[test]
    fn test_format_vuln_event() {
        let event = FragEvent {
            seq: 5,
            timestamp: Duration::from_secs(3),
            kind: FragEventKind::ResponseReceived {
                variant: FragVariant::PlaintextFull,
                response_time_ms: 47,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("VULN!"));
        assert!(formatted.contains("47ms"));
    }

    #[test]
    fn test_format_test_complete_event() {
        let event = FragEvent {
            seq: 10,
            timestamp: Duration::from_secs(8),
            kind: FragEventKind::TestComplete {
                variant: FragVariant::EapolAmsdu,
                verdict: FragVerdict::Vulnerable,
                frames_sent: 3,
                response_time_ms: 112,
                elapsed_ms: 2400,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("CVE-2020-26144"));
        assert!(formatted.contains("VULN"));
    }

    #[test]
    fn test_format_suite_complete_event() {
        let event = FragEvent {
            seq: 20,
            timestamp: Duration::from_secs(67),
            kind: FragEventKind::SuiteComplete {
                tested: 9,
                vulnerable: 4,
                skipped: 3,
                total: 12,
                elapsed: Duration::from_secs_f64(67.3),
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("DONE"));
        assert!(formatted.contains("9/12"));
    }

    #[test]
    fn test_status_segments_idle() {
        let info = FragInfo::default();
        let segs = status_segments(&info);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_status_segments_running() {
        let mut info = FragInfo::default();
        info.running = true;
        info.phase = FragPhase::Injecting;
        info.current_variant = Some(FragVariant::PlaintextFull);
        info.variant_total = 12;
        info.variant_index = 4;
        info.variants_vulnerable = 1;
        let segs = status_segments(&info);
        assert!(segs.len() >= 3);
    }

    #[test]
    fn test_frag_module_new() {
        let module = FragModule::new(FragParams::default());
        assert_eq!(module.name(), "frag");
        assert!(!module.is_running());
        assert!(!module.is_done());
    }

    #[test]
    fn test_freeze_summary_no_vulns() {
        let module = FragModule::new(FragParams::default());
        let summary = module.freeze_summary(80);
        assert!(!summary.is_empty());
    }
}
