//! CLI renderer + Module implementation for the WiFi Fuzzer attack.
//!
//! Renders the attack progress as styled terminal lines:
//! - Target AP info + fuzzing domain/mutations/seed
//! - Iteration counter + rate (fps) + crash count
//! - Baseline probe status
//! - Crash table — the star of the show (prominent RED BOLD)
//! - Health check results
//! - Event log scrollback

use std::collections::VecDeque;
use std::time::Duration;

use crate::attacks::fuzz::{
    FuzzAttack, FuzzCrash, FuzzDomain, FuzzEvent, FuzzEventKind,
    FuzzFrameType, FuzzInfo, FuzzParams, FuzzPhase,
    mutation as FuzzMutation, detect as FuzzDetect,
};
use crate::pipeline::UpdateSubscriber;
use crate::store::update::{AttackEventKind, AttackId, AttackType, StoreUpdate};

use prism::{s, truncate};
use super::{fps_sparkline, tx_stats_line};

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Format frames/sec as a styled rate string.
fn format_rate(fps: f64) -> String {
    let n = fps.round() as u64;
    let compact = prism::format_compact(n);
    if fps > 1000.0 {
        s().yellow().bold().paint(&format!("{} fps", compact))
    } else {
        s().yellow().paint(&format!("{} fps", compact))
    }
}

/// Format a timestamp as `[  0.142s]` style (dim, right-aligned in 7 chars).
fn format_timestamp(d: Duration) -> String {
    s().dim().paint(&format!("{:>7.3}s", d.as_secs_f64()))
}

/// Format an elapsed duration as human-readable: `4.2s` / `1m 23s` / `1h 02m`.
fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{:.1}s", d.as_secs_f64())
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Label formatters — styled type/domain/mutation names
// ═══════════════════════════════════════════════════════════════════════════════

/// Styled frame type name (white bold).
fn frame_type_label(ft: FuzzFrameType) -> String {
    let name = match ft {
        FuzzFrameType::Beacon => "Beacon",
        FuzzFrameType::ProbeReq => "ProbeReq",
        FuzzFrameType::ProbeResp => "ProbeResp",
        FuzzFrameType::Auth => "Auth",
        FuzzFrameType::AssocReq => "AssocReq",
        FuzzFrameType::AssocResp => "AssocResp",
        FuzzFrameType::Deauth => "Deauth",
        FuzzFrameType::Disassoc => "Disassoc",
        FuzzFrameType::Action => "Action",
        FuzzFrameType::Eap => "EAP",
        FuzzFrameType::All => "All",
    };
    s().white().bold().paint(name)
}

/// Styled domain name with domain-specific colors.
fn domain_label(d: FuzzDomain) -> String {
    match d {
        FuzzDomain::Frame => s().cyan().paint("Frame"),
        FuzzDomain::Ie => s().yellow().paint("IE"),
        FuzzDomain::Eap => s().magenta().paint("EAP"),
        FuzzDomain::All => s().bold().paint("All"),
    }
}

/// Styled mutation name — picks the first set bit and colors it.
fn mutation_label(m: u32) -> String {
    if m & FuzzMutation::BIT_FLIP != 0 {
        s().cyan().paint("bit-flip")
    } else if m & FuzzMutation::BYTE_FLIP != 0 {
        s().cyan().paint("byte-flip")
    } else if m & FuzzMutation::BOUNDARY != 0 {
        s().yellow().paint("boundary")
    } else if m & FuzzMutation::OVERFLOW != 0 {
        s().red().paint("overflow")
    } else if m & FuzzMutation::TRUNCATION != 0 {
        s().magenta().paint("truncation")
    } else if m & FuzzMutation::TYPE_CONFUSE != 0 {
        s().yellow().bold().paint("type-confuse")
    } else if m & FuzzMutation::RANDOM != 0 {
        s().blue().paint("random")
    } else if m & FuzzMutation::REPEAT != 0 {
        s().cyan().paint("repeat")
    } else if m & FuzzMutation::KNOWN_BAD != 0 {
        s().red().bold().paint("known-bad")
    } else {
        s().dim().paint("none")
    }
}

/// List all enabled mutations as a comma-separated styled string.
fn mutations_label(mask: u32) -> String {
    let mut parts = Vec::new();
    if mask & FuzzMutation::BIT_FLIP != 0 { parts.push(s().cyan().paint("bit-flip")); }
    if mask & FuzzMutation::BYTE_FLIP != 0 { parts.push(s().cyan().paint("byte-flip")); }
    if mask & FuzzMutation::BOUNDARY != 0 { parts.push(s().yellow().paint("boundary")); }
    if mask & FuzzMutation::OVERFLOW != 0 { parts.push(s().red().paint("overflow")); }
    if mask & FuzzMutation::TRUNCATION != 0 { parts.push(s().magenta().paint("truncation")); }
    if mask & FuzzMutation::TYPE_CONFUSE != 0 { parts.push(s().yellow().bold().paint("type-confuse")); }
    if mask & FuzzMutation::RANDOM != 0 { parts.push(s().blue().paint("random")); }
    if mask & FuzzMutation::REPEAT != 0 { parts.push(s().cyan().paint("repeat")); }
    if mask & FuzzMutation::KNOWN_BAD != 0 { parts.push(s().red().bold().paint("known-bad")); }
    if parts.is_empty() {
        s().dim().paint("none")
    } else {
        parts.join(", ")
    }
}

/// Styled detection method name — picks the first set bit.
fn detect_label(m: u32) -> String {
    if m & FuzzDetect::BEACON_LOSS != 0 {
        "Beacon Loss".to_string()
    } else if m & FuzzDetect::PROBE_TIMEOUT != 0 {
        "Probe Timeout".to_string()
    } else if m & FuzzDetect::DEFORMED_RESPONSE != 0 {
        "Deformed Response".to_string()
    } else if m & FuzzDetect::CLIENT_DROP != 0 {
        "Client Drop".to_string()
    } else {
        "Unknown".to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Phase display
// ═══════════════════════════════════════════════════════════════════════════════

fn phase_label(p: FuzzPhase) -> &'static str {
    match p {
        FuzzPhase::Idle => "idle",
        FuzzPhase::Probing => "probing",
        FuzzPhase::Fuzzing => "fuzzing",
        FuzzPhase::Monitoring => "monitoring",
        FuzzPhase::CrashFound => "crash found",
        FuzzPhase::Done => "done",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Event formatting — for scrollback output
// ═══════════════════════════════════════════════════════════════════════════════

/// Format a fuzz event as a styled terminal line for the output zone.
pub fn format_event(event: &FuzzEvent) -> String {
    let ts = format_timestamp(event.timestamp);

    match &event.kind {
        FuzzEventKind::AttackStarted { bssid, ssid, channel, seed, domain, frame_type, mutations } => {
            let ssid_display = truncate(ssid, 24, "\u{2026}");
            format!("  [{}] {} {}  {}  ch{}  seed:{}\n  {}  domain:{}  frames:{}  mutations:[{}]",
                ts,
                s().yellow().bold().paint("FUZZ"),
                s().bold().paint(&ssid_display),
                s().dim().paint(&bssid.to_string()),
                channel,
                s().cyan().bold().paint(&format!("0x{:08X}", seed)),
                s().dim().paint(&" ".repeat(10)),
                domain_label(*domain),
                frame_type_label(*frame_type),
                mutations_label(*mutations))
        }

        FuzzEventKind::BaselineProbe { probe_num, alive } => {
            if *alive {
                format!("  [{}] {} probe #{} — {}",
                    ts,
                    s().dim().paint("PROBE"),
                    probe_num,
                    s().green().paint("alive \u{2713}"))
            } else {
                format!("  [{}] {} probe #{} — {}",
                    ts,
                    s().dim().paint("PROBE"),
                    probe_num,
                    s().red().paint("NO RESPONSE \u{2717}"))
            }
        }

        FuzzEventKind::BaselineComplete { probes_ok, total } => {
            let status = if *probes_ok == *total {
                s().green().bold().paint(&format!("{}/{} OK", probes_ok, total))
            } else {
                s().yellow().paint(&format!("{}/{} OK", probes_ok, total))
            };
            format!("  [{}] {} Baseline complete: {}",
                ts,
                s().cyan().paint("BASE"),
                status)
        }

        FuzzEventKind::FuzzingStarted => {
            format!("  [{}] {} Fuzzing started — injecting mutated frames",
                ts,
                s().yellow().bold().paint("FUZZ"))
        }

        FuzzEventKind::MutationApplied { iteration, frame_type, domain, mutation, frame_len } => {
            format!("  [{}] {} iter {} — {} {} {} ({}B)",
                ts,
                s().dim().paint("MUT"),
                s().dim().paint(&prism::format_number(*iteration as u64)),
                frame_type_label(*frame_type),
                domain_label(*domain),
                mutation_label(*mutation),
                frame_len)
        }

        FuzzEventKind::FrameInjected { iteration, frame_type, mutation, frame_len } => {
            format!("  [{}] {} iter {} — {} {} ({}B)",
                ts,
                s().dim().paint("TX"),
                s().dim().paint(&prism::format_number(*iteration as u64)),
                frame_type_label(*frame_type),
                mutation_label(*mutation),
                frame_len)
        }

        FuzzEventKind::HealthCheckStarted => {
            format!("  [{}] {} Health check...",
                ts,
                s().dim().paint("PROBE"))
        }

        FuzzEventKind::HealthCheckResult { alive, probes_sent, probes_answered } => {
            if *alive {
                format!("  [{}] {} alive {} ({}/{})",
                    ts,
                    s().dim().paint("PROBE"),
                    s().green().paint("\u{2713}"),
                    probes_answered,
                    probes_sent)
            } else {
                format!("  [{}] {} {} ({}/{})",
                    ts,
                    s().red().bold().paint("PROBE"),
                    s().red().bold().paint("NO RESPONSE \u{2717}"),
                    probes_answered,
                    probes_sent)
            }
        }

        FuzzEventKind::CrashDetected { iteration, frame_type, mutation, domain, detect_method, description } => {
            format!("  [{}] {} at iter {} — {} {} {} via {}\n  {}  {}",
                ts,
                s().red().bold().paint("CRASH!"),
                s().white().bold().paint(&prism::format_number(*iteration as u64)),
                frame_type_label(*frame_type),
                mutation_label(*mutation),
                domain_label(*domain),
                detect_label(*detect_method),
                s().dim().paint(&" ".repeat(10)),
                s().red().bold().paint(description))
        }

        FuzzEventKind::CrashRecovery { crash_num, recovery_ms, description } => {
            format!("  [{}] {} crash #{} {} ({}ms)",
                ts,
                s().green().paint("RECOVER"),
                crash_num,
                s().green().paint(description),
                recovery_ms)
        }

        FuzzEventKind::CrashPermanent { crash_num, description } => {
            format!("  [{}] {} crash #{} — {}",
                ts,
                s().red().bold().paint("PERMANENT"),
                crash_num,
                s().red().bold().paint(description))
        }

        FuzzEventKind::Paused { crash_num } => {
            format!("  [{}] {} Paused after crash #{} — press Enter to continue",
                ts,
                s().yellow().bold().paint("PAUSE"),
                crash_num)
        }

        FuzzEventKind::Resumed => {
            format!("  [{}] {} Fuzzing resumed",
                ts,
                s().cyan().paint("RESUME"))
        }

        FuzzEventKind::RateSnapshot { iteration, frames_sent: _, frames_per_sec, elapsed, crashes_found } => {
            let rate = format_rate(*frames_per_sec);
            let crash_str = if *crashes_found > 0 {
                format!(" | {} {}",
                    s().red().bold().paint(&crashes_found.to_string()),
                    s().red().paint("crashes"))
            } else {
                String::new()
            };
            format!("  [{}] {} {} | {} iter | {}{}",
                ts,
                s().dim().paint("RATE"),
                rate,
                s().dim().paint(&prism::format_number(*iteration as u64)),
                s().dim().paint(&format_elapsed(*elapsed)),
                crash_str)
        }

        FuzzEventKind::AttackComplete { iterations, frames_sent, frames_received: _, crashes_found, crashes_recovered, crashes_permanent, elapsed } => {
            let crash_summary = if *crashes_found > 0 {
                format!(" — {} crashes ({} recovered, {} {})",
                    s().red().bold().paint(&crashes_found.to_string()),
                    crashes_recovered,
                    s().red().bold().paint(&crashes_permanent.to_string()),
                    s().red().bold().paint("permanent"))
            } else {
                format!(" — {}", s().dim().paint("no crashes"))
            };
            format!("  [{}] {} {} iterations, {} frames in {}{}",
                ts,
                s().bold().paint("DONE"),
                prism::format_number(*iterations as u64),
                prism::format_number(*frames_sent),
                format_elapsed(*elapsed),
                crash_summary)
        }

        FuzzEventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts, s().dim().paint("LOCK"), channel)
        }

        FuzzEventKind::ChannelUnlocked => {
            format!("  [{}] {} Channel unlocked — scanner resumes hopping",
                ts, s().dim().paint("UNLOCK"))
        }

        FuzzEventKind::Error { message } => {
            format!("  [{}] {} {}", ts, s().red().bold().paint("ERROR"), message)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Crash table — the money shot
// ═══════════════════════════════════════════════════════════════════════════════

/// Format a table of crashes found during fuzzing.
///
/// ```text
///   #   Iter     Frame Type      Mutation       Domain  Detection       Recovery
///   1   12,456   Beacon          Overflow       Frame   Probe Timeout   recovered (3.2s)
///   2   34,789   Auth            Known Bad      IE      Beacon Loss     PERMANENT
/// ```
pub fn format_crash_table(crashes: &[FuzzCrash]) -> Vec<String> {
    let mut lines = Vec::new();

    if crashes.is_empty() {
        lines.push(format!("  {}", s().dim().paint("No crashes detected.")));
        return lines;
    }

    // Header
    lines.push(format!("  {}  {}  {}  {}  {}  {}  {}",
        s().bold().dim().paint(&prism::pad("#", 3, "right")),
        s().bold().dim().paint(&prism::pad("Iter", 9, "right")),
        s().bold().dim().paint(&prism::pad("Frame Type", 14, "left")),
        s().bold().dim().paint(&prism::pad("Mutation", 14, "left")),
        s().bold().dim().paint(&prism::pad("Domain", 7, "left")),
        s().bold().dim().paint(&prism::pad("Detection", 15, "left")),
        s().bold().dim().paint("Recovery")));

    for (i, crash) in crashes.iter().enumerate() {
        let num = format!("{}", i + 1);
        let iter_str = prism::format_number(crash.iteration as u64);
        let ft = frame_type_label(crash.frame_type);
        let mut_label = mutation_label(crash.mutation);
        let dom = domain_label(crash.domain);
        let det = detect_label(crash.detect_method);

        let recovery = if crash.recovery_ms.is_none() {
            s().red().bold().paint("PERMANENT")
        } else if let Some(ms) = crash.recovery_ms {
            s().green().paint(&format!("recovered ({:.1}s)", ms as f64 / 1000.0))
        } else {
            s().yellow().paint("unknown")
        };

        lines.push(format!("  {}  {}  {}  {}  {}  {}  {}",
            prism::pad(&num, 3, "right"),
            prism::pad(&iter_str, 9, "right"),
            prism::pad(&ft, 14, "left"),
            prism::pad(&mut_label, 14, "left"),
            prism::pad(&dom, 7, "left"),
            prism::pad(&det, 15, "left"),
            recovery));
    }

    lines
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Active zone view — rendered in the Layout active zone during attack
// ═══════════════════════════════════════════════════════════════════════════════

/// Render the fuzz attack progress view for the Layout active zone.
pub fn render_fuzz_view(info: &FuzzInfo, crashes: &[FuzzCrash], width: u16, fps_history: &VecDeque<f64>) -> Vec<String> {
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

    // Breathing room above the frame
    lines.push(String::new());

    // ═══ Header border ═══
    let title = s().yellow().bold().paint(" fuzzer ");
    let title_plain_w = 8;
    let remaining = inner_w.saturating_sub(title_plain_w + 1);
    lines.push(format!("  {}{}{}{}", bc("\u{256d}\u{2500}"), title,
        bc(&"\u{2500}".repeat(remaining)), bc("\u{256e}")));

    // ═══ Target ═══
    if !info.target_ssid.is_empty() || info.target_bssid != crate::core::MacAddress::ZERO {
        let ssid_display = if info.target_ssid.is_empty() {
            s().dim().italic().paint("(hidden)")
        } else {
            s().bold().paint(&prism::truncate(&info.target_ssid, 24, "\u{2026}"))
        };
        lines.push(vline(&format!("{}  {}  ch{}",
            ssid_display,
            s().dim().paint(&info.target_bssid.to_string()),
            info.target_channel), inner_w));
    }

    // ═══ Step progress ═══
    if info.running || info.phase == FuzzPhase::Done {
        let spinner = prism::get_spinner("dots");
        let spin_frame = spinner.as_ref().map(|sp| {
            let idx = (info.elapsed.as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let probe_step = match info.phase {
            FuzzPhase::Idle => format!("{} PROBE", s().dim().paint("\u{25cb}")),
            FuzzPhase::Probing => format!("{} PROBE", s().cyan().paint(spin_frame)),
            _ => format!("{} PROBE", s().green().paint("\u{2714}")),
        };
        let fuzz_step = match info.phase {
            FuzzPhase::Fuzzing => format!("{} FUZZ", s().yellow().bold().paint(spin_frame)),
            FuzzPhase::CrashFound => format!("{} FUZZ", s().red().bold().paint(spin_frame)),
            FuzzPhase::Done | FuzzPhase::Monitoring => format!("{} FUZZ", s().green().paint("\u{2714}")),
            _ => format!("{} FUZZ", s().dim().paint("\u{25cb}")),
        };
        let monitor_step = match info.phase {
            FuzzPhase::Monitoring => format!("{} CHECK", s().magenta().bold().paint(spin_frame)),
            FuzzPhase::Done => format!("{} CHECK", s().green().paint("\u{2714}")),
            _ => format!("{} CHECK", s().dim().paint("\u{25cb}")),
        };

        let arrow = s().dim().paint(" \u{2192} ");
        let steps = format!("{}{}{}{}{}", probe_step, arrow, fuzz_step, arrow, monitor_step);

        // Append FPS sparkline — especially valuable for fuzz since throughput = coverage speed
        if fps_history.len() > 1 {
            let spark = fps_sparkline(fps_history, 12);
            lines.push(vline(&format!("{}  {}", steps, spark), inner_w));
        } else {
            lines.push(vline(&steps, inner_w));
        }

        // TX stats line
        if let Some(tx_line) = tx_stats_line(&info.tx_feedback, info.frames_sent, info.frames_per_sec) {
            lines.push(vline(&tx_line, inner_w));
        }
    }

    lines.push(empty_line());

    // ═══ Config + iteration stats ═══
    if info.actual_seed != 0 {
        let seed_str = format!("seed:{}  domain:{}  frames:{}",
            s().cyan().bold().paint(&format!("0x{:08X}", info.actual_seed)),
            domain_label(info.current_domain),
            frame_type_label(info.current_frame_type));
        lines.push(vline(&seed_str, inner_w));

        // Current mutation (hidden field!)
        if info.current_mutation != 0 {
            lines.push(vline(
                &format!("{} mutation:{}  [{}]",
                    s().yellow().paint("\u{25b6}"),
                    s().bold().paint(&format!("0x{:04X}", info.current_mutation)),
                    mutations_label(info.mutations)),
                inner_w));
        }
    }

    // Counters + rate
    if info.phase == FuzzPhase::Fuzzing || info.phase == FuzzPhase::Monitoring
        || info.phase == FuzzPhase::CrashFound || info.phase == FuzzPhase::Done
    {
        let elapsed = format_elapsed(info.elapsed);
        let rate = format_rate(info.frames_per_sec);

        // Iteration progress (with max if set)
        let iter_str = if info.max_iterations > 0 {
            format!("{}/{} iter",
                prism::format_number(info.iteration as u64),
                prism::format_number(info.max_iterations))
        } else {
            format!("{} iter", prism::format_number(info.iteration as u64))
        };

        let crash_str = if info.crashes_found > 0 {
            format!("  {} {}",
                s().red().bold().paint(&info.crashes_found.to_string()),
                s().red().paint("crashes"))
        } else { String::new() };

        let tx_fb_str = if info.tx_feedback.total_reports > 0 {
            let mut fb = format!("  {} ack  {} nack",
                s().green().paint(&prism::format_number(info.tx_feedback.acked)),
                s().red().paint(&prism::format_number(info.tx_feedback.nacked)));
            if let Some(pct) = info.tx_feedback.delivery_pct() {
                fb.push_str(&format!("  {}%", pct as u64));
            }
            fb
        } else { String::new() };

        lines.push(vline(&format!("{}  {} sent  {} recv  {}  {}{}{}",
            s().yellow().bold().paint(&iter_str),
            prism::format_number(info.frames_sent),
            prism::format_number(info.frames_received),
            rate, s().dim().paint(&elapsed), tx_fb_str, crash_str), inner_w));

        // Probe health check stats
        if info.probes_sent > 0 {
            let health = if info.probes_answered == info.probes_sent {
                s().green().paint("healthy")
            } else if info.probes_answered > 0 {
                s().yellow().paint("degraded")
            } else {
                s().red().bold().paint("unresponsive")
            };
            lines.push(vline(
                &format!("probes: {}/{}  {}",
                    info.probes_answered, info.probes_sent, health),
                inner_w));
        }

        // Progress bar if max_iterations set
        if info.max_iterations > 0 {
            let bar_w = inner_w.saturating_sub(20);
            fn yellow_bar(t: &str) -> String { s().yellow().paint(t) }
            let bar = prism::render_progress_bar(info.iteration as u64, &prism::RenderOptions {
                total: info.max_iterations, width: bar_w,
                style: prism::BarStyle::Smooth, color: Some(yellow_bar),
                ..Default::default()
            });
            let pct = if info.max_iterations > 0 {
                (info.iteration as f64 / info.max_iterations as f64 * 100.0) as u32
            } else { 0 };
            lines.push(vline(&format!("{} {}%", bar, pct), inner_w));
        }

        lines.push(empty_line());
    }

    // ═══ Phase-specific indicators ═══
    match info.phase {
        FuzzPhase::Probing => {
            let sp = prism::get_spinner("dots");
            let f = sp.as_ref().map(|sp| {
                let idx = (info.elapsed.as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
                sp.frames[idx]
            }).unwrap_or(".");
            lines.push(vline(&format!("{} {}", s().cyan().paint(f),
                s().dim().paint("Establishing baseline...")), inner_w));
        }
        FuzzPhase::CrashFound => {
            lines.push(vline(&format!("{} {}",
                s().red().bold().paint("\u{26a0}"),
                s().red().bold().paint("Crash detected! Investigating...")), inner_w));
        }
        _ => {}
    }

    // ═══ Crash table ═══
    if !crashes.is_empty() {
        lines.push(empty_line());
        for crash_line in format_crash_table(crashes) {
            lines.push(vline(&crash_line, inner_w));
        }
    }

    // ═══ Bottom border ═══
    lines.push(format!("  {}{}{}", bc("\u{2570}"),
        bc(&"\u{2500}".repeat(inner_w + 1)), bc("\u{256f}")));

    lines
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status bar segments
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate status bar segments for the fuzz attack.
pub fn status_segments(info: &FuzzInfo) -> Vec<StatusSegment> {
    let mut segs = Vec::new();

    if !info.running && info.phase == FuzzPhase::Idle {
        return segs;
    }

    let attack_text = if info.target_ssid.is_empty() {
        format!("fuzz: {}", phase_label(info.phase))
    } else {
        format!("fuzz: {} ({})", info.target_ssid, phase_label(info.phase))
    };

    segs.push(StatusSegment::new(attack_text, SegmentStyle::YellowBold));

    if info.iteration > 0 {
        segs.push(StatusSegment::new(
            format!("{}iter", prism::format_number(info.iteration as u64)),
            SegmentStyle::Cyan,
        ));
    }

    if info.frames_per_sec > 0.0 {
        segs.push(StatusSegment::new(format!("{:.0} fps", info.frames_per_sec), SegmentStyle::Dim));
    }

    if info.crashes_found > 0 {
        segs.push(StatusSegment::new(
            format!("{} crashes", info.crashes_found),
            SegmentStyle::RedBold,
        ));
    }

    if let Some(pct) = info.tx_feedback.delivery_pct() {
        segs.push(StatusSegment::new(format!("{}%tx", pct as u64), SegmentStyle::Dim));
    }

    segs.push(StatusSegment::new(format_elapsed(info.elapsed), SegmentStyle::Dim));

    segs
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Freeze summary — printed to scrollback when attack ends
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate the final summary when the fuzz attack completes.
///
/// Shows seed (for reproduction), iteration count, frame count, duration,
/// rate, and a crash table if any crashes were found.
pub fn freeze_summary(info: &FuzzInfo, crashes: &[FuzzCrash], width: u16) -> Vec<String> {
    let mut lines = Vec::new();

    // Build summary content for prism::frame()
    let avg_fps = if info.elapsed.as_secs_f64() > 0.0 {
        info.frames_sent as f64 / info.elapsed.as_secs_f64()
    } else {
        0.0
    };
    let avg_fps_compact = prism::format_compact(avg_fps.round() as u64);

    let crash_str = if info.crashes_found > 0 {
        let permanent = info.crashes_permanent;
        let recovered = info.crashes_found.saturating_sub(permanent);
        format!("{} found ({} recovered, {} permanent)", info.crashes_found, recovered, permanent)
    } else {
        "none".to_string()
    };

    let content = format!(
        "Seed:         0x{:08X}\n\
         Iterations:   {}\n\
         Frames TX:    {}\n\
         Frames RX:    {}\n\
         Duration:     {}\n\
         Rate:         {} fps\n\
         Probes:       {}/{} answered\n\
         Crashes:      {}",
        info.actual_seed,
        prism::format_number(info.iteration as u64),
        prism::format_number(info.frames_sent),
        prism::format_number(info.frames_received),
        format_elapsed(info.elapsed),
        avg_fps_compact,
        info.probes_answered,
        info.probes_sent,
        crash_str,
    );

    let frame_width = (width as usize).min(60);
    let framed = prism::frame(&content, &prism::FrameOptions {
        width: Some(frame_width),
        title: Some("FUZZ COMPLETE".to_string()),
        ..Default::default()
    });

    lines.push(String::new());
    for line in framed.lines() {
        lines.push(format!("  {}", line));
    }

    // Crash table (if any crashes found)
    if !crashes.is_empty() {
        lines.push(String::new());
        lines.extend(format_crash_table(crashes));
    }

    lines.push(String::new());
    lines
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FuzzModule — Module trait implementation for Fuzz attack
// ═══════════════════════════════════════════════════════════════════════════════

use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};
use crate::store::Ap;

/// FuzzModule wraps FuzzAttack with the Module trait for the shell's focus stack.
///
/// Uses SharedAdapter architecture: the attack spawns its own thread via start(),
/// locks the channel, and shares the adapter with the scanner.
pub struct FuzzModule {
    attack: FuzzAttack,
    /// Target AP for fuzzing.
    target: Option<Ap>,
    /// Cached info for rendering — refreshed when deltas arrive.
    cached_info: Option<FuzzInfo>,
    /// Cached crashes for rendering and freeze summary.
    cached_crashes: Vec<FuzzCrash>,
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

impl FuzzModule {
    pub fn new(params: FuzzParams) -> Self {
        let attack = FuzzAttack::new(params);
        Self {
            attack,
            target: None,
            cached_info: None,
            cached_crashes: Vec::new(),
            update_sub: None,
            attack_id: None,
            dirty: false,
            scrollback_lines: Vec::new(),
            fps_history: VecDeque::new(),
        }
    }

    /// Get the underlying attack.
    pub fn attack(&self) -> &FuzzAttack {
        &self.attack
    }

    /// Set target AP before starting.
    pub fn set_target(&mut self, target: Ap) {
        self.target = Some(target);
    }

    /// Subscribe to the delta stream. Call BEFORE starting the attack
    /// so we don't miss early deltas (AttackStarted, first events).
    pub fn subscribe(&mut self, shared: &crate::adapter::SharedAdapter) {
        self.update_sub = Some(shared.gate().subscribe_updates("fuzz-ui"));
    }

    /// Process pending deltas from the subscriber.
    /// Filters for this attack's deltas, marks dirty, and accumulates scrollback lines.
    /// CrashDetected events also accumulate into cached_crashes for the crash table.
    fn process_deltas(&mut self) {
        let sub = match &self.update_sub {
            Some(s) => s,
            None => return,
        };

        for update in sub.drain_flat() {
            match &update {
                StoreUpdate::AttackStarted { id, attack_type: AttackType::Fuzz, .. } => {
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
                StoreUpdate::AttackEvent { id, event: AttackEventKind::Fuzz(kind), timestamp, .. }
                    if self.is_our_attack(*id) =>
                {
                    // Accumulate crash data from delta events (replaces render()-side crash accumulation)
                    if let FuzzEventKind::CrashDetected { iteration, frame_type, mutation, domain, detect_method, description } = kind {
                        let crash_num = (self.cached_crashes.len() + 1) as u32;
                        self.cached_crashes.push(FuzzCrash {
                            crash_num,
                            iteration: *iteration,
                            frame_type: *frame_type,
                            mutation: *mutation,
                            domain: *domain,
                            detect_method: *detect_method,
                            elapsed: *timestamp,
                            target_bssid: crate::core::MacAddress::ZERO,
                            trigger_frame: Vec::new(),
                            description: description.clone(),
                            recovery_ms: None,
                        });
                    }
                    if let FuzzEventKind::CrashRecovery { crash_num, recovery_ms, .. } = kind {
                        if let Some(crash) = self.cached_crashes.get_mut(*crash_num as usize - 1) {
                            crash.recovery_ms = Some(*recovery_ms);
                        }
                    }

                    let event = FuzzEvent { seq: 0, timestamp: *timestamp, kind: kind.clone() };
                    self.scrollback_lines.push(format_event(&event));
                    self.dirty = true;
                }
                StoreUpdate::AttackComplete { id, attack_type: AttackType::Fuzz, .. }
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
        // like elapsed, iterations, fps update continuously.
        self.cached_info = Some(self.attack.info());
        self.dirty = false;

        std::mem::take(&mut self.scrollback_lines)
    }

    /// Get current attack info.
    #[allow(dead_code)]
    pub fn info(&self) -> FuzzInfo {
        self.attack.info()
    }
}

impl Module for FuzzModule {
    fn name(&self) -> &str { "fuzz" }
    fn description(&self) -> &str { "WiFi fuzzer" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }

    fn start(&mut self, shared: crate::adapter::SharedAdapter) {
        // Subscribe to delta stream BEFORE starting attack thread
        self.update_sub = Some(shared.gate().subscribe_updates("fuzz-ui"));
        if let Some(target) = self.target.take() {
            self.attack.start(shared, target);
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
        &[] // Fuzz uses a single view — no tabs
    }

    fn render(&mut self, _view: usize, width: u16, _height: u16) -> Vec<String> {
        // tick() is called by poll_modules() before render, so cached_info is fresh.
        let info = self.cached_info.clone().unwrap_or_else(|| self.attack.info());
        render_fuzz_view(&info, &self.cached_crashes, width, &self.fps_history)
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
        freeze_summary(&info, &self.cached_crashes, width)
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_format_number() {
        assert_eq!(prism::format_number(0), "0");
        assert_eq!(prism::format_number(999), "999");
        assert_eq!(prism::format_number(1000), "1,000");
        assert_eq!(prism::format_number(42000), "42,000");
        assert_eq!(prism::format_number(1234567), "1,234,567");
    }

    #[test]
    fn test_format_elapsed_seconds() {
        assert_eq!(format_elapsed(Duration::from_millis(4200)), "4.2s");
    }

    #[test]
    fn test_format_elapsed_minutes() {
        assert_eq!(format_elapsed(Duration::from_secs(83)), "1m 23s");
    }

    #[test]
    fn test_format_elapsed_hours() {
        assert_eq!(format_elapsed(Duration::from_secs(3720)), "1h 02m");
    }

    #[test]
    fn test_phase_labels() {
        assert_eq!(phase_label(FuzzPhase::Idle), "idle");
        assert_eq!(phase_label(FuzzPhase::Probing), "probing");
        assert_eq!(phase_label(FuzzPhase::Fuzzing), "fuzzing");
        assert_eq!(phase_label(FuzzPhase::Monitoring), "monitoring");
        assert_eq!(phase_label(FuzzPhase::CrashFound), "crash found");
        assert_eq!(phase_label(FuzzPhase::Done), "done");
    }

    #[test]
    fn test_mutations_label_single() {
        let label = mutations_label(FuzzMutation::OVERFLOW);
        assert!(label.contains("overflow"));
    }

    #[test]
    fn test_mutations_label_multiple() {
        let label = mutations_label(FuzzMutation::BIT_FLIP | FuzzMutation::BOUNDARY | FuzzMutation::OVERFLOW);
        assert!(label.contains("bit-flip"));
        assert!(label.contains("boundary"));
        assert!(label.contains("overflow"));
    }

    #[test]
    fn test_mutations_label_none() {
        let label = mutations_label(0);
        assert!(label.contains("none"));
    }

    #[test]
    fn test_mutation_label_picks_first_bit() {
        let label = mutation_label(FuzzMutation::BIT_FLIP | FuzzMutation::OVERFLOW);
        assert!(label.contains("bit-flip"));
    }

    #[test]
    fn test_detect_label_variants() {
        assert_eq!(detect_label(FuzzDetect::BEACON_LOSS), "Beacon Loss");
        assert_eq!(detect_label(FuzzDetect::PROBE_TIMEOUT), "Probe Timeout");
        assert_eq!(detect_label(FuzzDetect::DEFORMED_RESPONSE), "Deformed Response");
        assert_eq!(detect_label(FuzzDetect::CLIENT_DROP), "Client Drop");
    }

    #[test]
    fn test_format_crash_table_empty() {
        let lines = format_crash_table(&[]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("No crashes"));
    }

    #[test]
    fn test_format_crash_table_with_crashes() {
        let crashes = vec![
            FuzzCrash {
                crash_num: 1,
                iteration: 12456,
                frame_type: FuzzFrameType::Beacon,
                mutation: FuzzMutation::OVERFLOW,
                domain: FuzzDomain::Frame,
                detect_method: FuzzDetect::PROBE_TIMEOUT,
                elapsed: Duration::from_secs(10),
                target_bssid: crate::core::MacAddress::ZERO,
                trigger_frame: Vec::new(),
                description: "AP stopped responding".to_string(),
                recovery_ms: Some(3200),
            },
            FuzzCrash {
                crash_num: 2,
                iteration: 34789,
                frame_type: FuzzFrameType::Auth,
                mutation: FuzzMutation::KNOWN_BAD,
                domain: FuzzDomain::Ie,
                detect_method: FuzzDetect::BEACON_LOSS,
                elapsed: Duration::from_secs(30),
                target_bssid: crate::core::MacAddress::ZERO,
                trigger_frame: Vec::new(),
                description: "Beacon not seen for 10s".to_string(),
                recovery_ms: None,
            },
        ];
        let lines = format_crash_table(&crashes);
        // Header + 2 crash rows
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("12,456"));
        assert!(lines[2].contains("PERMANENT"));
    }

    #[test]
    fn test_freeze_summary_no_crashes() {
        let info = FuzzInfo {
            actual_seed: 0xDEADBEEF,
            iteration: 42000,
            frames_sent: 38456,
            elapsed: Duration::from_secs(323),
            crashes_found: 0,
            crashes_permanent: 0,
            ..FuzzInfo::default()
        };
        let lines = freeze_summary(&info, &[], 80);
        let joined = lines.join("\n");
        assert!(joined.contains("DEADBEEF"));
        assert!(joined.contains("42,000"));
        assert!(joined.contains("38,456"));
        assert!(joined.contains("none"));
    }

    #[test]
    fn test_freeze_summary_with_crashes() {
        let info = FuzzInfo {
            actual_seed: 0xCAFEBABE,
            iteration: 50000,
            frames_sent: 45000,
            elapsed: Duration::from_secs(120),
            crashes_found: 2,
            crashes_permanent: 1,
            ..FuzzInfo::default()
        };
        let crashes = vec![
            FuzzCrash {
                crash_num: 1,
                iteration: 10000,
                frame_type: FuzzFrameType::Beacon,
                mutation: FuzzMutation::OVERFLOW,
                domain: FuzzDomain::Frame,
                detect_method: FuzzDetect::PROBE_TIMEOUT,
                elapsed: Duration::from_secs(5),
                target_bssid: crate::core::MacAddress::ZERO,
                trigger_frame: Vec::new(),
                description: "test crash 1".to_string(),
                recovery_ms: Some(2500),
            },
        ];
        let lines = freeze_summary(&info, &crashes, 80);
        let joined = lines.join("\n");
        assert!(joined.contains("CAFEBABE"));
        assert!(joined.contains("2"));
        assert!(joined.contains("found"));
    }

    #[test]
    fn test_format_event_attack_started() {
        let event = FuzzEvent {
            seq: 1,
            timestamp: Duration::from_millis(100),
            kind: FuzzEventKind::AttackStarted {
                bssid: crate::core::MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]),
                ssid: "TestAP".to_string(),
                channel: 6,
                seed: 0xDEADBEEF,
                domain: FuzzDomain::Frame,
                frame_type: FuzzFrameType::Beacon,
                mutations: FuzzMutation::ALL,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("FUZZ"));
        assert!(formatted.contains("TestAP"));
        assert!(formatted.contains("DEADBEEF"));
    }

    #[test]
    fn test_format_event_crash_detected() {
        let event = FuzzEvent {
            seq: 42,
            timestamp: Duration::from_secs(15),
            kind: FuzzEventKind::CrashDetected {
                iteration: 12456,
                frame_type: FuzzFrameType::Beacon,
                mutation: FuzzMutation::OVERFLOW,
                domain: FuzzDomain::Frame,
                detect_method: FuzzDetect::PROBE_TIMEOUT,
                description: "AP stopped responding after overflow mutation".to_string(),
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("CRASH"));
        assert!(formatted.contains("12,456"));
        assert!(formatted.contains("AP stopped responding"));
    }

    #[test]
    fn test_format_event_baseline_probe_alive() {
        let event = FuzzEvent {
            seq: 2,
            timestamp: Duration::from_millis(500),
            kind: FuzzEventKind::BaselineProbe { probe_num: 1, alive: true },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("PROBE"));
        assert!(formatted.contains("\u{2713}")); // checkmark
    }

    #[test]
    fn test_format_event_baseline_probe_dead() {
        let event = FuzzEvent {
            seq: 3,
            timestamp: Duration::from_millis(1500),
            kind: FuzzEventKind::BaselineProbe { probe_num: 2, alive: false },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("PROBE"));
        assert!(formatted.contains("NO RESPONSE"));
    }

    #[test]
    fn test_format_event_rate_snapshot() {
        let event = FuzzEvent {
            seq: 100,
            timestamp: Duration::from_secs(10),
            kind: FuzzEventKind::RateSnapshot {
                iteration: 5000,
                frames_sent: 4800,
                frames_per_sec: 480.0,
                elapsed: Duration::from_secs(10),
                crashes_found: 1,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("RATE"));
        assert!(formatted.contains("5,000"));
        assert!(formatted.contains("crashes"));
    }

    #[test]
    fn test_format_event_error() {
        let event = FuzzEvent {
            seq: 50,
            timestamp: Duration::from_secs(5),
            kind: FuzzEventKind::Error { message: "TX failed".to_string() },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("ERROR"));
        assert!(formatted.contains("TX failed"));
    }

    #[test]
    fn test_format_event_channel_locked() {
        let event = FuzzEvent {
            seq: 1,
            timestamp: Duration::from_millis(50),
            kind: FuzzEventKind::ChannelLocked { channel: 11 },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("LOCK"));
        assert!(formatted.contains("ch11"));
    }

    #[test]
    fn test_format_event_complete() {
        let event = FuzzEvent {
            seq: 200,
            timestamp: Duration::from_secs(300),
            kind: FuzzEventKind::AttackComplete {
                iterations: 42000,
                frames_sent: 38456,
                frames_received: 0,
                crashes_found: 2,
                crashes_recovered: 1,
                crashes_permanent: 1,
                elapsed: Duration::from_secs(300),
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("DONE"));
        assert!(formatted.contains("42,000"));
        assert!(formatted.contains("38,456"));
        assert!(formatted.contains("2"));
        assert!(formatted.contains("permanent"));
    }

    #[test]
    fn test_format_event_fuzzing_started() {
        let event = FuzzEvent {
            seq: 5,
            timestamp: Duration::from_secs(2),
            kind: FuzzEventKind::FuzzingStarted,
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("FUZZ"));
        assert!(formatted.contains("injecting"));
    }

    #[test]
    fn test_format_event_health_check_alive() {
        let event = FuzzEvent {
            seq: 10,
            timestamp: Duration::from_secs(5),
            kind: FuzzEventKind::HealthCheckResult { alive: true, probes_sent: 5, probes_answered: 5 },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("PROBE"));
        assert!(formatted.contains("5/5"));
    }

    #[test]
    fn test_format_event_health_check_dead() {
        let event = FuzzEvent {
            seq: 11,
            timestamp: Duration::from_secs(6),
            kind: FuzzEventKind::HealthCheckResult { alive: false, probes_sent: 5, probes_answered: 0 },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("NO RESPONSE"));
        assert!(formatted.contains("0/5"));
    }

    #[test]
    fn test_format_event_crash_recovery() {
        let event = FuzzEvent {
            seq: 43,
            timestamp: Duration::from_secs(20),
            kind: FuzzEventKind::CrashRecovery {
                crash_num: 1,
                recovery_ms: 3200,
                description: "AP responding again".to_string(),
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("RECOVER"));
        assert!(formatted.contains("3200ms"));
    }

    #[test]
    fn test_format_event_crash_permanent() {
        let event = FuzzEvent {
            seq: 44,
            timestamp: Duration::from_secs(25),
            kind: FuzzEventKind::CrashPermanent {
                crash_num: 2,
                description: "AP did not recover after 30s".to_string(),
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("PERMANENT"));
        assert!(formatted.contains("did not recover"));
    }

    #[test]
    fn test_format_event_paused() {
        let event = FuzzEvent {
            seq: 45,
            timestamp: Duration::from_secs(16),
            kind: FuzzEventKind::Paused { crash_num: 1 },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("PAUSE"));
        assert!(formatted.contains("crash #1"));
    }

    #[test]
    fn test_format_event_resumed() {
        let event = FuzzEvent {
            seq: 46,
            timestamp: Duration::from_secs(30),
            kind: FuzzEventKind::Resumed,
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("RESUME"));
    }

    #[test]
    fn test_format_event_channel_unlocked() {
        let event = FuzzEvent {
            seq: 47,
            timestamp: Duration::from_secs(60),
            kind: FuzzEventKind::ChannelUnlocked,
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("UNLOCK"));
    }

    #[test]
    fn test_format_event_baseline_complete() {
        let event = FuzzEvent {
            seq: 4,
            timestamp: Duration::from_secs(1),
            kind: FuzzEventKind::BaselineComplete { probes_ok: 5, total: 5 },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("BASE"));
        assert!(formatted.contains("5/5 OK"));
    }

    #[test]
    fn test_format_event_mutation_applied() {
        let event = FuzzEvent {
            seq: 20,
            timestamp: Duration::from_secs(5),
            kind: FuzzEventKind::MutationApplied {
                iteration: 1234,
                frame_type: FuzzFrameType::Auth,
                domain: FuzzDomain::Ie,
                mutation: FuzzMutation::BOUNDARY,
                frame_len: 128,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("MUT"));
        assert!(formatted.contains("1,234"));
        assert!(formatted.contains("128B"));
    }

    #[test]
    fn test_format_event_frame_injected() {
        let event = FuzzEvent {
            seq: 21,
            timestamp: Duration::from_secs(5),
            kind: FuzzEventKind::FrameInjected {
                iteration: 1234,
                frame_type: FuzzFrameType::Beacon,
                mutation: FuzzMutation::OVERFLOW,
                frame_len: 256,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("TX"));
        assert!(formatted.contains("256B"));
    }

    #[test]
    fn test_format_event_health_check_started() {
        let event = FuzzEvent {
            seq: 9,
            timestamp: Duration::from_secs(4),
            kind: FuzzEventKind::HealthCheckStarted,
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("Health check"));
    }

    #[test]
    fn test_format_rate_low() {
        let rate = format_rate(500.0);
        assert!(rate.contains("500 fps"));
    }

    #[test]
    fn test_format_rate_high() {
        let rate = format_rate(14000.0);
        assert!(rate.contains("14.0K fps"));
    }
}
