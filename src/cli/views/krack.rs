//! CLI renderer + Module implementation for the KRACK attack.

use crate::attacks::krack::{
    KrackAttack, KrackEvent, KrackEventKind, KrackFinalResult, KrackInfo, KrackParams,
    KrackPhase, KrackVerdict,
};
use crate::core::MacAddress;

use prism::s;

// ═══════════════════════════════════════════════════════════════════════════════
//  Phase display
// ═══════════════════════════════════════════════════════════════════════════════

fn phase_label(phase: KrackPhase) -> &'static str {
    match phase {
        KrackPhase::Idle => "idle",
        KrackPhase::ChannelLock => "locking channel",
        KrackPhase::DeauthSent => "deauthing",
        KrackPhase::CapturingHandshake => "capturing handshake",
        KrackPhase::Replaying => "replaying",
        KrackPhase::Monitoring => "monitoring PN",
        KrackPhase::Done => "done",
    }
}

fn verdict_icon(verdict: KrackVerdict) -> String {
    match verdict {
        KrackVerdict::Vulnerable => s().red().bold().paint("VULN"),
        KrackVerdict::NotVulnerable => s().green().paint("SAFE"),
        KrackVerdict::Skipped => s().dim().paint("SKIP"),
        KrackVerdict::Pending => s().dim().paint("...."),
        KrackVerdict::Testing => s().cyan().paint("TEST"),
        KrackVerdict::Error => s().red().paint("ERR!"),
    }
}

fn verdict_symbol(verdict: KrackVerdict) -> String {
    match verdict {
        KrackVerdict::Vulnerable => s().red().bold().paint("\u{2717}"),
        KrackVerdict::NotVulnerable => s().green().paint("\u{2714}"),
        KrackVerdict::Skipped => s().dim().paint("\u{2212}"),
        KrackVerdict::Pending => s().dim().paint("\u{25cb}"),
        KrackVerdict::Testing => s().cyan().paint("\u{25cf}"),
        KrackVerdict::Error => s().red().paint("!"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Event formatting
// ═══════════════════════════════════════════════════════════════════════════════

pub fn format_event(event: &KrackEvent) -> String {
    let ts = format!("{:>7.3}s", event.timestamp.as_secs_f64());
    let ts_styled = s().dim().paint(&ts);

    match &event.kind {
        KrackEventKind::AttackStarted { bssid, ssid, channel, variant_count } => {
            format!("  [{}] {} KRACK \u{2192} {}  {}  ch{}  ({} variants)",
                ts_styled, s().cyan().bold().paint("KRACK"),
                s().bold().paint(ssid), s().dim().paint(&bssid.to_string()),
                channel, variant_count)
        }
        KrackEventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts_styled, s().dim().paint("LOCK"), channel)
        }
        KrackEventKind::DeauthSent { target, count } => {
            format!("  [{}] {} {} deauths \u{2192} {} (force reconnection)",
                ts_styled, s().yellow().paint("DEAUTH"), count, target)
        }
        KrackEventKind::HandshakeMessage { message, from_ap } => {
            let dir = if *from_ap { "AP\u{2192}STA" } else { "STA\u{2192}AP" };
            let msg_name = match message {
                1 => "M1 (ANonce)", 2 => "M2 (SNonce)", 3 => "M3 (Install)",
                4 => "M4 (Complete)", 5 => "Group M1", 6 => "Group M2",
                _ => "???",
            };
            format!("  [{}] {} {} {}", ts_styled, s().cyan().paint("EAPOL"), dir, msg_name)
        }
        KrackEventKind::HandshakeCaptured { has_m1, has_m3, has_group_m1 } => {
            let parts: Vec<&str> = [
                if *has_m1 { Some("M1") } else { None },
                if *has_m3 { Some("M3") } else { None },
                if *has_group_m1 { Some("Group-M1") } else { None },
            ].iter().filter_map(|x| *x).collect();
            format!("  [{}] {} Handshake captured: {}",
                ts_styled, s().green().bold().paint("CAPTURE"), parts.join(", "))
        }
        KrackEventKind::ClientLocked { mac } => {
            format!("  [{}] {} Locked to client {}",
                ts_styled, s().cyan().paint("CLIENT"), s().bold().paint(&mac.to_string()))
        }
        KrackEventKind::VariantStarted { variant, index, total } => {
            format!("  [{}] {} [{}/{}] {} — {}",
                ts_styled, s().cyan().bold().paint("TEST"), index, total,
                s().bold().paint(variant.cve()), variant.description())
        }
        KrackEventKind::M3Replayed { variant, count } => {
            format!("  [{}] {} {} \u{2192} {} replays sent",
                ts_styled, s().red().paint("REPLAY"), variant.replay_frame(), count)
        }
        KrackEventKind::NonceReuse { variant, old_pn, new_pn, count } => {
            format!("  [{}] {} {} — PN {} \u{2192} {} (reuse #{})",
                ts_styled, s().red().bold().paint("REUSE!"),
                variant.cve(), old_pn, new_pn, count)
        }
        KrackEventKind::VariantComplete { variant, verdict, nonce_reuses, elapsed_ms } => {
            let v = verdict_icon(*verdict);
            let reuse_str = if *nonce_reuses > 0 {
                format!("  {} reuse(s)", nonce_reuses)
            } else { String::new() };
            format!("  [{}] {} {} {}  ({}ms){}",
                ts_styled, v, s().bold().paint(variant.cve()),
                s().dim().paint(variant.label()), elapsed_ms, reuse_str)
        }
        KrackEventKind::VariantSkipped { variant, reason } => {
            format!("  [{}] {} {} — {}",
                ts_styled, s().dim().paint("SKIP"), variant.cve(), s().dim().paint(reason))
        }
        KrackEventKind::AttackComplete { tested, vulnerable, skipped, total, elapsed } => {
            let vuln_str = if *vulnerable > 0 {
                s().red().bold().paint(&format!("{} vulnerable", vulnerable))
            } else {
                s().green().bold().paint("0 vulnerable")
            };
            format!("  [{}] {} KRACK complete: {}/{} tested, {}, {} skipped  ({:.1}s)",
                ts_styled, s().bold().paint("DONE"), tested, total, vuln_str, skipped,
                elapsed.as_secs_f64())
        }
        KrackEventKind::ChannelUnlocked => {
            format!("  [{}] {} Channel unlocked", ts_styled, s().dim().paint("UNLOCK"))
        }
        KrackEventKind::Error { message } => {
            format!("  [{}] {} {}", ts_styled, s().red().bold().paint("ERROR"), message)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Active zone render
// ═══════════════════════════════════════════════════════════════════════════════

pub fn render_krack_view(info: &KrackInfo, width: u16, _height: u16, scroll_offset: usize) -> Vec<String> {
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

    // ═══ Header border with title ═══
    let title = s().red().bold().paint(" krack ");
    let title_plain_w = 7;
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

        let client_badge = if let Some(client) = &info.client_mac {
            format!("  client: {}", s().cyan().paint(&client.to_string()))
        } else {
            String::new()
        };

        let target_line = format!("{}  {}  ch{}{}",
            ssid_display,
            s().dim().paint(&info.target_bssid.to_string()),
            info.target_channel,
            client_badge,
        );
        lines.push(vline(&target_line, inner_w));
    } else if !info.running && info.phase == KrackPhase::Done {
        lines.push(vline(&s().dim().paint("Attack complete"), inner_w));
    } else if !info.running {
        lines.push(vline(&s().dim().paint("Idle"), inner_w));
    }

    // ═══ Step progress ═══
    if info.running || info.phase == KrackPhase::Done {
        let spinner = prism::get_spinner("dots");
        let spin_frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let deauth_step = match info.phase {
            KrackPhase::Idle => format!("{} DEAUTH", s().dim().paint("\u{25cb}")),
            KrackPhase::ChannelLock | KrackPhase::DeauthSent =>
                format!("{} DEAUTH", s().yellow().paint(spin_frame)),
            _ => format!("{} DEAUTH", s().green().paint("\u{2714}")),
        };

        let hs_step = match info.phase {
            KrackPhase::Idle | KrackPhase::ChannelLock | KrackPhase::DeauthSent =>
                format!("{} HS", s().dim().paint("\u{25cb}")),
            KrackPhase::CapturingHandshake =>
                format!("{} HS", s().cyan().paint(spin_frame)),
            _ => if info.handshake_captured {
                format!("{} HS", s().green().paint("\u{2714}"))
            } else {
                format!("{} HS", s().dim().paint("\u{25cb}"))
            },
        };

        let replay_step = match info.phase {
            KrackPhase::Replaying => format!("{} REPLAY", s().red().bold().paint(spin_frame)),
            KrackPhase::Monitoring => format!("{} MONITOR", s().magenta().bold().paint(spin_frame)),
            KrackPhase::Done => format!("{} TEST", s().green().paint("\u{2714}")),
            _ => format!("{} REPLAY", s().dim().paint("\u{25cb}")),
        };

        let arrow = s().dim().paint(" \u{2192} ");
        let steps = format!("{}{}{}{}{}", deauth_step, arrow, hs_step, arrow, replay_step);
        lines.push(vline(&steps, inner_w));
    }

    lines.push(empty_line());

    // ═══ Variant progress bar ═══
    if info.variant_total > 0 {
        let bar_w = inner_w.saturating_sub(20);
        fn red_bar(t: &str) -> String { s().red().paint(t) }
        let bar = prism::render_progress_bar(info.variant_index as u64, &prism::RenderOptions {
            total: info.variant_total as u64,
            width: bar_w,
            style: prism::BarStyle::Smooth,
            color: Some(red_bar),
            ..Default::default()
        });

        let vuln_label = if info.variants_vulnerable > 0 {
            s().red().bold().paint(&format!("{}\u{2717}", info.variants_vulnerable))
        } else {
            s().green().paint("0\u{2714}")
        };
        let label = format!("{}/{} variants  {}", info.variant_index, info.variant_total, vuln_label);
        lines.push(vline(&format!("{}  {}", bar, s().dim().paint(&label)), inner_w));

        // Stats line
        let elapsed = info.start_time.elapsed().as_secs_f64();
        let hs_badge = if info.handshake_captured {
            s().green().paint("HS\u{2714}")
        } else { s().dim().paint("HS...") };
        let mut stats = format!("{}  {} replays  {} reuses  {} sent  {:.1}s",
            hs_badge, info.m3_replays_sent, info.nonce_reuses_total,
            prism::format_number(info.frames_sent), elapsed);
        if info.tx_feedback.total_reports > 0 {
            stats.push_str(&format!("  {} ack  {} nack",
                s().green().paint(&prism::format_number(info.tx_feedback.acked)),
                s().red().paint(&prism::format_number(info.tx_feedback.nacked))));
            if let Some(pct) = info.tx_feedback.delivery_pct() {
                stats.push_str(&format!("  {}%", pct as u64));
            }
        }
        lines.push(vline(&s().dim().paint(&stats), inner_w));

        // Current variant indicator
        if let Some(variant) = &info.current_variant {
            let mode_line = format!("{} {}  {}",
                s().cyan().bold().paint("\u{25b6}"),
                s().bold().paint(variant.cve()),
                s().dim().paint(variant.description()));
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
            s().bold().dim().paint(&prism::pad("VARIANT", 14, "left")),
            s().bold().dim().paint(&prism::pad("VERDICT", 6, "left")),
            s().bold().dim().paint("DETAIL"),
        );
        lines.push(vline(&hdr, inner_w));

        let mut result_rows: Vec<String> = Vec::new();
        for result in &info.results {
            let icon = verdict_symbol(result.verdict);
            let detail = match result.verdict {
                KrackVerdict::Vulnerable => format!("{} reuse(s), {} replays",
                    result.nonce_reuses, result.replays_sent),
                KrackVerdict::NotVulnerable => format!("{} replays, {}ms",
                    result.replays_sent, result.elapsed.as_millis()),
                KrackVerdict::Skipped => prism::truncate(&result.detail, 30, "\u{2026}").to_string(),
                KrackVerdict::Testing => {
                    let spinner = prism::get_spinner("dots");
                    let frame = spinner.as_ref().map(|sp| {
                        let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
                        sp.frames[idx]
                    }).unwrap_or(".");
                    format!("{} replaying...", frame)
                }
                _ => String::new(),
            };

            let cve_styled = match result.verdict {
                KrackVerdict::Vulnerable => s().red().paint(result.variant.cve()),
                _ => s().dim().paint(result.variant.cve()),
            };

            let row = format!("{}  {}  {}  {}  {}",
                icon,
                cve_styled,
                s().bold().paint(&prism::pad(result.variant.label(), 14, "left")),
                verdict_icon(result.verdict),
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
    } else if info.running && info.phase == KrackPhase::CapturingHandshake {
        let spinner = prism::get_spinner("dots");
        let frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(vline(&format!("{} {}", s().cyan().paint(frame),
            s().dim().paint("Waiting for handshake...")), inner_w));
    }

    // ═══ Bottom border ═══
    lines.push(format!("  {}{}{}", bc("\u{2570}"),
        bc(&"\u{2500}".repeat(inner_w + 1)), bc("\u{256f}")));

    lines
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status bar segments
// ═══════════════════════════════════════════════════════════════════════════════

pub fn status_segments(info: &KrackInfo) -> Vec<StatusSegment> {
    let mut segs = Vec::new();
    if !info.running && info.phase == KrackPhase::Idle { return segs; }

    let text = if let Some(v) = &info.current_variant {
        format!("krack: {} ({})", v.cve(), phase_label(info.phase))
    } else {
        format!("krack: {}", phase_label(info.phase))
    };
    segs.push(StatusSegment::new(text, SegmentStyle::RedBold));

    if info.variants_vulnerable > 0 {
        segs.push(StatusSegment::new(format!("{}\u{2717}", info.variants_vulnerable), SegmentStyle::RedBold));
    }

    if info.variant_total > 0 {
        segs.push(StatusSegment::new(format!("{}/{}", info.variant_index, info.variant_total), SegmentStyle::Dim));
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
//  KrackModule — Module trait
// ═══════════════════════════════════════════════════════════════════════════════

use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};

pub struct KrackModule {
    attack: KrackAttack,
    cached_info: Option<KrackInfo>,
    pending_events: Vec<KrackEvent>,
    scroll_offset: usize,
}

impl KrackModule {
    pub fn new(params: KrackParams) -> Self {
        Self { attack: KrackAttack::new(params), cached_info: None, pending_events: Vec::new(), scroll_offset: 0 }
    }

    pub fn attack(&self) -> &KrackAttack { &self.attack }

    pub fn drain_events(&mut self) -> Vec<KrackEvent> {
        let events = self.attack.events();
        self.pending_events.extend(events.iter().cloned());
        events
    }
}

impl Module for KrackModule {
    fn name(&self) -> &str { "krack" }
    fn description(&self) -> &str { "KRACK key reinstallation — 11 variants" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }

    fn start(&mut self, _shared: crate::adapter::SharedAdapter) {
        panic!("KrackModule: use attack().start(shared, target) instead");
    }

    fn signal_stop(&self) { self.attack.signal_stop(); }
    fn is_running(&self) -> bool { self.attack.is_running() }
    fn is_done(&self) -> bool { self.attack.is_done() }
    fn views(&self) -> &[ViewDef] { &[] }

    fn render(&mut self, _view: usize, width: u16, height: u16) -> Vec<String> {
        let info = self.attack.info();
        self.cached_info = Some(info.clone());
        render_krack_view(&info, width, height, self.scroll_offset)
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
        let final_result = KrackFinalResult {
            results: info.results.clone(),
            variants_tested: info.variants_tested,
            variants_vulnerable: info.variants_vulnerable,
            elapsed: info.start_time.elapsed(),
        };
        let mut content_lines = Vec::new();
        content_lines.push(format!("Target: {} ({})",
            info.target_ssid, info.target_bssid));
        content_lines.push(format!("Variants tested: {}/{}",
            final_result.variants_tested, info.variant_total));
        let vuln_str = if final_result.variants_vulnerable > 0 {
            s().red().bold().paint(&format!("{} VULNERABLE", final_result.variants_vulnerable))
        } else {
            s().green().bold().paint("0 vulnerable")
        };
        content_lines.push(format!("Vulnerable: {}", vuln_str));
        content_lines.push(format!("Frames: {} sent, {} received",
            prism::format_number(info.frames_sent),
            prism::format_number(info.frames_received)));
        content_lines.push(format!("Duration: {:.1}s", final_result.elapsed.as_secs_f64()));
        for result in &final_result.results {
            if result.verdict == KrackVerdict::Vulnerable {
                content_lines.push(format!("  {} {} {}  {} nonce reuse(s)",
                    s().red().bold().paint("\u{2717}"),
                    s().bold().paint(result.variant.cve()),
                    result.variant.description(), result.nonce_reuses));
            }
        }
        let content = content_lines.join("\n");
        let framed = prism::frame(&content, &prism::FrameOptions {
            border: prism::BorderStyle::Rounded,
            title: Some("KRACK Attack Complete".into()),
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
    use crate::attacks::krack::{KrackTestResult, KrackVariant};
    use crate::core::MacAddress;

    #[test]
    fn test_phase_labels() {
        assert_eq!(phase_label(KrackPhase::Idle), "idle");
        assert_eq!(phase_label(KrackPhase::Replaying), "replaying");
        assert_eq!(phase_label(KrackPhase::Monitoring), "monitoring PN");
    }

    #[test]
    fn test_verdict_icons() {
        let _ = verdict_icon(KrackVerdict::Vulnerable);
        let _ = verdict_icon(KrackVerdict::NotVulnerable);
        let _ = verdict_icon(KrackVerdict::Skipped);
    }

    #[test]
    fn test_render_empty_info() {
        let info = KrackInfo::default();
        let lines = render_krack_view(&info, 80, 40, 0);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_format_attack_started() {
        let event = KrackEvent {
            seq: 1, timestamp: Duration::from_millis(50),
            kind: KrackEventKind::AttackStarted {
                bssid: MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
                ssid: "TestAP".to_string(), channel: 6, variant_count: 11,
            },
        };
        let f = format_event(&event);
        assert!(f.contains("KRACK"));
        assert!(f.contains("TestAP"));
    }

    #[test]
    fn test_format_nonce_reuse() {
        let event = KrackEvent {
            seq: 10, timestamp: Duration::from_secs(5),
            kind: KrackEventKind::NonceReuse {
                variant: KrackVariant::FourWayPtk,
                old_pn: 42, new_pn: 3, count: 1,
            },
        };
        let f = format_event(&event);
        assert!(f.contains("REUSE!"));
    }

    #[test]
    fn test_status_segments_idle() {
        let info = KrackInfo::default();
        assert!(status_segments(&info).is_empty());
    }

    #[test]
    fn test_status_segments_running() {
        let mut info = KrackInfo::default();
        info.running = true;
        info.phase = KrackPhase::Monitoring;
        info.current_variant = Some(KrackVariant::FourWayPtk);
        info.variant_total = 11;
        info.variant_index = 3;
        assert!(status_segments(&info).len() >= 3);
    }

    #[test]
    fn test_module_new() {
        let m = KrackModule::new(KrackParams::default());
        assert_eq!(m.name(), "krack");
        assert!(!m.is_running());
    }

    #[test]
    fn test_render_with_results() {
        let mut info = KrackInfo::default();
        info.phase = KrackPhase::Done;
        info.target_bssid = MacAddress::new([0xAA; 6]);
        info.target_ssid = "KRACK-Test".to_string();
        info.target_channel = 6;
        info.handshake_captured = true;
        info.variant_total = 11;
        info.variant_index = 11;
        info.variants_tested = 11;
        info.variants_vulnerable = 1;
        info.results = KrackVariant::all().iter().map(|v| {
            let mut r = KrackTestResult::new(*v);
            r.verdict = KrackVerdict::NotVulnerable;
            r.replays_sent = 3;
            r.elapsed = Duration::from_secs(5);
            r
        }).collect();
        info.results[0].verdict = KrackVerdict::Vulnerable;
        info.results[0].nonce_reuses = 2;
        let lines = render_krack_view(&info, 120, 40, 0);
        // bordered view with target, steps, progress, results table, bottom border
        // In test env, term_height may be small so results get scroll-capped
        assert!(lines.len() >= 5, "expected >= 5 lines, got {}", lines.len());
    }
}
