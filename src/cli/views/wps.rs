//! CLI renderer + Module implementation for the WPS attack.
//!
//! Renders the attack progress as styled terminal lines:
//! - Attack type (Pixie Dust / Brute Force / Null PIN)
//! - Phase indicator with WPS message exchange progress
//! - AP device info (from M2)
//! - Brute force progress (Phase 1: 0000-9999, Phase 2: 000-999+checksum)
//! - PIN/PSK result when found
//! - Event log scrollback

use crate::attacks::wps::{
    SubAttackInfo, WpsAttack, WpsAttackType, WpsEvent, WpsEventKind, WpsInfo,
    WpsParams, WpsPhase, WpsStatus,
};

use prism::{s, truncate, BorderStyle, FrameOptions};

// ═══════════════════════════════════════════════════════════════════════════════
//  Phase display
// ═══════════════════════════════════════════════════════════════════════════════

fn phase_label(phase: WpsPhase) -> &'static str {
    match phase {
        WpsPhase::Idle => "idle",
        WpsPhase::KeyGeneration => "generating DH keys",
        WpsPhase::Authenticating => "authenticating",
        WpsPhase::Associating => "associating",
        WpsPhase::EapIdentity => "EAP identity",
        WpsPhase::WscStart => "waiting WSC_Start",
        WpsPhase::M1Received => "M1 received",
        WpsPhase::M2Sent => "M2 sent",
        WpsPhase::M3Received => "M3 received",
        WpsPhase::M4Sent => "M4 sent",
        WpsPhase::PixieCracking => "Pixie Dust cracking",
        WpsPhase::M5Received => "M5 received",
        WpsPhase::M6Sent => "M6 sent",
        WpsPhase::M7Received => "M7 received",
        WpsPhase::BruteForcePhase1 => "brute force (half 1)",
        WpsPhase::BruteForcePhase2 => "brute force (half 2)",
        WpsPhase::LockoutWait => "lockout wait",
        WpsPhase::NullPin => "null PIN",
        WpsPhase::Done => "done",
    }
}


/// Map WPS phase to a numeric ordinal for step comparison.
/// Lower = earlier in the exchange.
fn phase_ordinal(phase: WpsPhase) -> u8 {
    match phase {
        WpsPhase::Idle | WpsPhase::KeyGeneration => 0,
        WpsPhase::Authenticating => 1,
        WpsPhase::Associating => 2,
        WpsPhase::EapIdentity | WpsPhase::WscStart => 3,
        WpsPhase::M1Received => 4,
        WpsPhase::M2Sent => 5,
        WpsPhase::M3Received => 6,
        WpsPhase::M4Sent => 7,
        WpsPhase::M5Received => 8,
        WpsPhase::M6Sent => 9,
        WpsPhase::M7Received => 10,
        WpsPhase::PixieCracking => 11,
        WpsPhase::BruteForcePhase1 | WpsPhase::BruteForcePhase2 => 12,
        WpsPhase::LockoutWait => 12,
        WpsPhase::NullPin => 12,
        WpsPhase::Done => 99,
    }
}

/// Render a step icon: ✔ if completed, spinner if active, ○ if pending.
fn step_icon(current_ord: u8, step_ord: u8, spin: &str, ok: &str, pending: &str) -> String {
    if current_ord > step_ord || current_ord == 99 {
        ok.to_string()
    } else if current_ord == step_ord {
        s().cyan().paint(spin).to_string()
    } else {
        pending.to_string()
    }
}

/// Render a WPS message step with direction arrow and label.
#[allow(dead_code)]
fn msg_step(current_ord: u8, step_ord: u8, spin: &str, ok: &str, pending: &str, label: &str) -> String {
    let icon = if current_ord > step_ord || current_ord == 99 {
        ok.to_string()
    } else if current_ord == step_ord {
        s().magenta().bold().paint(spin).to_string()
    } else {
        pending.to_string()
    };
    format!("{}{}", icon, s().bold().paint(label))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status display
// ═══════════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
fn status_icon(status: WpsStatus) -> String {
    match status {
        WpsStatus::InProgress => s().cyan().paint("\u{25cf}"),            // ●
        WpsStatus::Success => s().green().bold().paint("\u{2714}"),       // ✔
        WpsStatus::PixieDataOnly => s().yellow().paint("\u{25cf}"),       // ●
        WpsStatus::PinWrong => s().red().paint("\u{2717}"),              // ✗
        WpsStatus::Locked => s().red().bold().paint("\u{1f512}"),         // 🔒
        WpsStatus::AuthFailed => s().red().paint("\u{2717}"),            // ✗
        WpsStatus::AssocFailed => s().red().paint("\u{2717}"),           // ✗
        WpsStatus::EapFailed => s().red().paint("\u{2717}"),             // ✗
        WpsStatus::M1Failed => s().red().paint("\u{2717}"),              // ✗
        WpsStatus::M3Failed => s().red().paint("\u{2717}"),              // ✗
        WpsStatus::Stopped => s().dim().paint("\u{25a0}"),               // ■
        WpsStatus::Error => s().red().bold().paint("!"),
    }
}

fn status_label(status: WpsStatus) -> &'static str {
    match status {
        WpsStatus::InProgress => "in progress",
        WpsStatus::Success => "PIN found!",
        WpsStatus::PixieDataOnly => "Pixie data only",
        WpsStatus::PinWrong => "PIN wrong",
        WpsStatus::Locked => "AP locked out",
        WpsStatus::AuthFailed => "auth failed",
        WpsStatus::AssocFailed => "assoc failed",
        WpsStatus::EapFailed => "EAP failed",
        WpsStatus::M1Failed => "M1 failed",
        WpsStatus::M3Failed => "M3 failed",
        WpsStatus::Stopped => "stopped",
        WpsStatus::Error => "error",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Event formatting — for scrollback output
// ═══════════════════════════════════════════════════════════════════════════════

/// Format a WPS event as a styled terminal line for the output zone.
pub fn format_event(event: &WpsEvent) -> String {
    let ts = format!("{:>7.3}s", event.timestamp.as_secs_f64());
    let ts_styled = s().dim().paint(&ts);

    match &event.kind {
        WpsEventKind::TargetStarted { bssid, ssid, channel, index, total } => {
            format!("  [{}] {} [{}/{}] {}  {}  ch{}",
                ts_styled, s().cyan().bold().paint("TARGET"),
                index, total,
                s().bold().paint(ssid),
                s().dim().paint(&bssid.to_string()),
                channel)
        }
        WpsEventKind::TargetComplete { ssid, status, elapsed_ms, .. } => {
            let icon = status_icon(*status);
            let label = status_label(*status);
            format!("  [{}] {} {} {} ({}ms)", ts_styled, icon, ssid, s().dim().paint(label), elapsed_ms)
        }
        WpsEventKind::KeyGenerated { elapsed_ms } => {
            format!("  [{}] {} DH keypair generated ({}ms)",
                ts_styled, s().cyan().paint("KEYGEN"), elapsed_ms)
        }
        WpsEventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts_styled, s().dim().paint("LOCK"), channel)
        }
        WpsEventKind::AuthSuccess { bssid } => {
            format!("  [{}] {} Authenticated with {}", ts_styled, s().green().paint("AUTH"), s().dim().paint(&bssid.to_string()))
        }
        WpsEventKind::AuthFailed { bssid, attempt } => {
            format!("  [{}] {} Auth failed {} (attempt {})", ts_styled, s().red().paint("AUTH"), s().dim().paint(&bssid.to_string()), attempt)
        }
        WpsEventKind::AssocSuccess { .. } => {
            format!("  [{}] {} Associated (WPS IE)", ts_styled, s().green().paint("ASSOC"))
        }
        WpsEventKind::AssocFailed { attempt, .. } => {
            format!("  [{}] {} Association failed (attempt {})", ts_styled, s().red().paint("ASSOC"), attempt)
        }
        WpsEventKind::EapIdentitySent => {
            format!("  [{}] {} EAP Identity: WFA-SimpleConfig-Registrar-1-0", ts_styled, s().dim().paint("EAP"))
        }
        WpsEventKind::WscStartReceived => {
            format!("  [{}] {} WSC_Start received — exchange begins", ts_styled, s().cyan().paint("WSC"))
        }
        WpsEventKind::MessageSent { msg_type } => {
            format!("  [{}] {} {} sent", ts_styled, s().cyan().paint("WPS"), s().bold().paint(&format!("{:?}", msg_type)))
        }
        WpsEventKind::MessageReceived { msg_type } => {
            format!("  [{}] {} {} received", ts_styled, s().green().paint("WPS"), s().bold().paint(&format!("{:?}", msg_type)))
        }
        WpsEventKind::KeysDerived => {
            format!("  [{}] {} AuthKey + KeyWrapKey derived", ts_styled, s().green().paint("CRYPTO"))
        }
        WpsEventKind::ApDeviceInfo { manufacturer, model_name, device_name, .. } => {
            format!("  [{}] {} {} {} ({})",
                ts_styled, s().cyan().paint("AP-INFO"),
                s().bold().paint(manufacturer),
                model_name,
                s().dim().paint(device_name))
        }
        WpsEventKind::PixieDataExtracted { has_r_s1 } => {
            let data_str = if *has_r_s1 { "R-S1 decrypted" } else { "R-S1 not available" };
            format!("  [{}] {} Pixie Dust data extracted — {}",
                ts_styled, s().magenta().bold().paint("PIXIE"), data_str)
        }
        WpsEventKind::PixieCrackStarted => {
            format!("  [{}] {} Offline cracking started...", ts_styled, s().magenta().paint("PIXIE"))
        }
        WpsEventKind::PixieCrackSuccess { pin, elapsed_ms } => {
            format!("  [{}] {} PIN found: {} ({}ms)",
                ts_styled, s().green().bold().paint("PIXIE!"),
                s().green().bold().paint(pin), elapsed_ms)
        }
        WpsEventKind::PixieCrackFailed => {
            format!("  [{}] {} Offline crack failed — weak nonces not present",
                ts_styled, s().yellow().paint("PIXIE"))
        }
        WpsEventKind::BruteForcePhase1Started { total } => {
            format!("  [{}] {} Phase 1: testing {} first halves (0000-9999)",
                ts_styled, s().yellow().bold().paint("BRUTE"), total)
        }
        WpsEventKind::BruteForcePhase2Started { half1, total } => {
            format!("  [{}] {} Phase 2: half1={} — testing {} second halves",
                ts_styled, s().yellow().bold().paint("BRUTE"),
                s().green().bold().paint(half1), total)
        }
        WpsEventKind::PinAttempt { pin, attempt } => {
            format!("  [{}] {} PIN {} (attempt #{})",
                ts_styled, s().dim().paint("TRY"), pin, attempt)
        }
        WpsEventKind::Half1Found { half1, attempts } => {
            format!("  [{}] {} First half found: {} (after {} attempts)",
                ts_styled, s().green().bold().paint("HALF1!"),
                s().green().bold().paint(half1), attempts)
        }
        WpsEventKind::PinRejected { pin, half } => {
            format!("  [{}] {} PIN {} rejected (half {})",
                ts_styled, s().dim().paint("NACK"), pin, half)
        }
        WpsEventKind::LockoutDetected { config_error, delay } => {
            format!("  [{}] {} AP locked out (error {}) — waiting {:.0}s",
                ts_styled, s().red().bold().paint("LOCKED"),
                config_error, delay.as_secs_f64())
        }
        WpsEventKind::LockoutWaitComplete => {
            format!("  [{}] {} Lockout wait complete — resuming", ts_styled, s().cyan().paint("RESUME"))
        }
        WpsEventKind::PinSuccess { pin, psk } => {
            format!("  [{}] {} PIN: {}  PSK: {}",
                ts_styled, s().green().bold().paint("SUCCESS!"),
                s().green().bold().paint(pin),
                s().green().bold().paint(psk))
        }
        WpsEventKind::ConfigError { code } => {
            format!("  [{}] {} Config Error: {}", ts_styled, s().yellow().paint("WPS"), code)
        }
        WpsEventKind::EapFailure => {
            format!("  [{}] {} EAP-Failure received", ts_styled, s().red().paint("EAP"))
        }
        WpsEventKind::WscNackReceived { config_error } => {
            let err_str = config_error.map(|c| format!(" (error {})", c)).unwrap_or_default();
            format!("  [{}] {} WSC NACK received{}", ts_styled, s().red().paint("WPS"), err_str)
        }
        WpsEventKind::DisassocSent { .. } => {
            format!("  [{}] {} Disassociated (cleanup)", ts_styled, s().dim().paint("DISASSOC"))
        }
        WpsEventKind::AttackComplete { status, elapsed, attempts } => {
            let icon = status_icon(*status);
            let label = status_label(*status);
            format!("  [{}] {} WPS attack complete: {} {} — {} attempts in {}",
                ts_styled, s().bold().paint("DONE"),
                icon, s().dim().paint(label), attempts, fmt_elapsed(elapsed.as_secs_f64()))
        }
        WpsEventKind::NullPinFailed => {
            format!("  [{}] {} Null PIN (00000000) rejected", ts_styled, s().dim().paint("NULL"))
        }
        WpsEventKind::Error { message } => {
            format!("  [{}] {} {}", ts_styled, s().red().bold().paint("ERROR"), message)
        }
        // PIN generation events
        WpsEventKind::PinGenStarted { candidates } => {
            format!("  [{}] {} Testing {} computed PIN candidates",
                ts_styled, s().cyan().bold().paint("PIN-GEN"), candidates)
        }
        WpsEventKind::PinGenAttempt { pin, algo, attempt, total } => {
            format!("  [{}] {} PIN {} ({}) [{}/{}]",
                ts_styled, s().cyan().paint("TRY-PIN"),
                s().bold().paint(pin), s().dim().paint(algo), attempt, total)
        }
        WpsEventKind::PinGenSuccess { pin, algo, psk } => {
            format!("  [{}] {} PIN: {} ({})  PSK: {}",
                ts_styled, s().green().bold().paint("PIN-GEN!"),
                s().green().bold().paint(pin), algo,
                s().green().bold().paint(psk))
        }
        WpsEventKind::PinGenFailed => {
            format!("  [{}] {} No computed PINs matched", ts_styled, s().yellow().paint("PIN-GEN"))
        }
        // Skip events
        WpsEventKind::AttackSkipped { attack_type } => {
            format!("  [{}] {} {} skipped by user",
                ts_styled, s().yellow().paint("SKIP"), attack_type)
        }
        WpsEventKind::TargetSkipped { idx } => {
            format!("  [{}] {} Target {} skipped by user",
                ts_styled, s().yellow().paint("SKIP"), idx)
        }
        // Enhanced Pixie Dust PRNG events
        WpsEventKind::PixiePrngMode { mode } => {
            format!("  [{}] {} Trying PRNG mode: {}",
                ts_styled, s().magenta().paint("PIXIE"), s().bold().paint(mode))
        }
        WpsEventKind::PixiePrngRecovered { mode, elapsed_ms } => {
            format!("  [{}] {} PRNG recovered via {} ({}ms)",
                ts_styled, s().magenta().bold().paint("PIXIE!"), mode, elapsed_ms)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Active zone view — rendered in the Layout active zone during attack
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
//  Multi-target summary helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Count results by category for the summary bar.
#[allow(dead_code)]
struct ResultCounts {
    success: u32,
    pixie_data: u32,
    locked: u32,
    failed: u32,
    total: u32,
}

fn count_results(results: &[WpsResult]) -> ResultCounts {
    let mut c = ResultCounts { success: 0, pixie_data: 0, locked: 0, failed: 0, total: results.len() as u32 };
    for r in results {
        match r.status {
            WpsStatus::Success => c.success += 1,
            WpsStatus::PixieDataOnly => c.pixie_data += 1,
            WpsStatus::Locked => c.locked += 1,
            _ => c.failed += 1,
        }
    }
    c
}

/// Short max-phase label for results table, colored by how far we got.
#[allow(dead_code)]
fn phase_badge(phase: WpsPhase) -> String {
    let label = phase.short_label();
    let ord = phase_ordinal(phase);
    if ord >= 6 {
        // M3+ = good progress (green)
        s().green().paint(label)
    } else if ord >= 3 {
        // EAP/M1/M2 = partial (yellow)
        s().yellow().paint(label)
    } else if ord >= 1 {
        // AUTH/ASSOC = early fail (red)
        s().red().paint(label)
    } else {
        s().dim().paint(label)
    }
}

use crate::attacks::wps::WpsResult;

/// Convert seconds to milliseconds and format via prism::format_time.
fn fmt_elapsed(secs: f64) -> String {
    prism::format_time((secs * 1000.0) as u64)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Signal Intelligence rendering helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Render signal strength as bar characters.
fn signal_bar(rssi: i8) -> String {
    let bars = match rssi {
        -50..=0 => "\u{2582}\u{2584}\u{2586}\u{2588}",
        -60..=-51 => "\u{2582}\u{2584}\u{2586}\u{2591}",
        -70..=-61 => "\u{2582}\u{2584}\u{2591}\u{2591}",
        -80..=-71 => "\u{2582}\u{2591}\u{2591}\u{2591}",
        _ => "\u{2591}\u{2591}\u{2591}\u{2591}",
    };
    let color_fn = match rssi {
        -50..=0 => |t: &str| s().green().paint(t),
        -70..=-51 => |t: &str| s().yellow().paint(t),
        _ => |t: &str| s().red().paint(t),
    };
    color_fn(bars)
}

/// Render a sub-attack line for the active zone.
fn render_sub_attack(sub: &SubAttackInfo, spinner_frame: &str, inner_w: usize) -> String {
    if sub.active {
        // Active: cyan spinner + bold name
        format!("  {}  {}",
            s().cyan().paint(spinner_frame),
            s().bold().paint(&sub.name))
    } else {
        // Resolved: icon + name + detail + elapsed (per spec color rules)
        let (icon, name_styled, detail_styled) = match sub.status {
            WpsStatus::Success => (
                s().green().bold().paint("\u{2713}"),
                s().green().paint(&sub.name),
                if sub.detail.is_empty() { String::new() }
                    else { format!("  {}", s().green().paint(&sub.detail)) },
            ),
            WpsStatus::Stopped => (
                s().dim().paint("\u{2500}"),
                s().dim().paint(&sub.name),
                format!("  {}", s().dim().paint("skipped")),
            ),
            _ => (
                s().red().paint("\u{2717}"),
                s().dim().paint(&sub.name),
                if sub.detail.is_empty() { String::new() }
                    else { format!("  {}", s().dim().paint(&sub.detail)) },
            ),
        };
        let elapsed_str = fmt_elapsed(sub.elapsed.as_secs_f64());
        // Right-align elapsed
        let left = format!("  {}  {}{}", icon, name_styled, detail_styled);
        let left_w = prism::measure_width(&left);
        let gap = inner_w.saturating_sub(left_w + elapsed_str.len() + 2);
        format!("{}{}  {}", left, " ".repeat(gap), s().dim().paint(&elapsed_str))
    }
}

/// Render the trophy box for a cracked PIN/PSK using prism::frame().
fn render_trophy(pin: &str, psk: &str, inner_w: usize) -> Vec<String> {
    let spaced_pin: String = pin.chars().map(|c| c.to_string()).collect::<Vec<_>>().join(" ");
    let content = if psk.is_empty() {
        format!("PIN  {}", s().green().bold().paint(&spaced_pin))
    } else {
        format!("PIN  {}    PSK  {}",
            s().green().bold().paint(&spaced_pin),
            s().green().bold().paint(psk))
    };
    let content_w = prism::measure_width(&content) + 4; // padding
    let box_w = (content_w + 4).min(inner_w);
    let framed = prism::frame(&content, &FrameOptions {
        border: BorderStyle::Heavy,
        width: Some(box_w),
        padding: 1,
        title: None,
    });
    // Colorize the frame green and indent
    framed.trim_end().split('\n')
        .map(|line| format!("  {}", s().green().paint(line)))
        .collect()
}

/// Render the WPS attack progress view for the Layout active zone.
///
/// "Signal Intelligence" visual language:
///   1. Outer dim rounded frame
///   2. Header: attack badge (magenta bold) + target progress + progress bar
///   3. Dashed separator
///   4. Target info: SSID (white bold) + BSSID (dim) + channel (cyan)
///   5. AP info line (dim italic)
///   6. Sub-attacks list with icons/spinners
///   7. Protocol pipeline (when sub-attack active)
///   8. Live metrics line
///   9. Trophy box (on success)
///   10. Dashed separator
///   11. Footer: result counts + total metrics + key hints
pub fn render_wps_view(info: &WpsInfo, width: u16, _height: u16, _scroll_offset: usize) -> Vec<String> {
    let w = width as usize;
    let inner_w = w.saturating_sub(6);
    // Cap active zone: max 80% of terminal height (spec), leave room for scrollback + REPL
    let term_h = prism::term_height() as usize;
    let max_lines = (term_h * 80) / 100;

    // Width breakpoints (from spec):
    //   >=160: full layout
    //   >=120: compact labels, pipeline wraps to 2 lines
    //   >=80:  drop manufacturer/timing from target line
    //   <80:   no frame border, essential info only
    let no_frame = w < 80;
    let compact = w < 120;
    let minimal = w < 80;

    let bc = |t: &str| s().dim().paint(t);
    let vline = move |content: &str, iw: usize| {
        if no_frame {
            // No border in minimal mode
            format!("  {}", content)
        } else {
            let display_w = prism::measure_width(content);
            let pad = iw.saturating_sub(display_w);
            format!("  {} {}{}{}", bc("\u{2502}"), content, " ".repeat(pad), bc("\u{2502}"))
        }
    };
    let empty_line = || vline("", inner_w);

    let mut lines = Vec::new();

    // Breathing room above the frame
    lines.push(String::new());

    // Get spinner frame (shared across all uses)
    let spinner = prism::get_spinner("dots");
    let spin = spinner.as_ref().map(|sp| {
        let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
        sp.frames[idx]
    }).unwrap_or(".");

    // ═══ 1. Header: ╭─ wps auto ──────── [6/432] ▸▸▸░░░░░░░  1.4% ─╮ ═══
    let title_text = format!(" wps {} ", info.attack_type.short_name());
    let title = s().magenta().bold().paint(&title_text);
    let title_plain_w = title_text.len();

    // Multi-target progress bar in header
    let header_right = if info.target_total > 1 {
        let idx_text = format!("[{}/{}]", info.target_index, info.target_total);
        let pct = info.target_index as f64 / info.target_total as f64 * 100.0;
        fn magenta_bar(t: &str) -> String { s().magenta().paint(t) }
        let bar_w = 20.min(inner_w / 4);
        let bar = prism::render_progress_bar(info.target_index as u64, &prism::RenderOptions {
            total: info.target_total as u64,
            width: bar_w,
            style: prism::BarStyle::Arrows,
            color: Some(magenta_bar),
            ..Default::default()
        });
        format!("{}  {}  {}",
            s().dim().paint(&idx_text),
            bar,
            s().dim().paint(&format!("{:.1}%", pct)))
    } else {
        String::new()
    };

    let right_plain_w = prism::measure_width(&header_right);
    let fill_w = inner_w.saturating_sub(title_plain_w + right_plain_w + 2);

    if no_frame {
        // No border — use prism::header() for a clean title line
        let header_content = if !header_right.is_empty() {
            format!("{}  {}", title, header_right)
        } else {
            title.to_string()
        };
        lines.push(format!("  {}", prism::header(&header_content, inner_w)));
    } else {
        lines.push(format!("  {}{}{}{}{}",
            bc("\u{256d}\u{2500}"), title,
            bc(&"\u{2500}".repeat(fill_w)),
            header_right,
            bc(&format!("{}\u{256e}", if right_plain_w > 0 { "" } else { "\u{2500}" }))));
    }

    lines.push(empty_line());

    // ═══ 3. Target info: SSID + BSSID + ch + RSSI bars + dBm ═══
    if !info.ssid.is_empty() {
        lines.push(empty_line());
        let ssid_max = if compact { 20 } else { 28 };
        let ssid_display = s().white().bold().paint(&truncate(&info.ssid, ssid_max, "\u{2026}"));
        let bssid_str = info.bssid.to_string();
        let ch_str = s().cyan().paint(&format!("ch{}", info.channel));

        // RSSI + signal bars
        let rssi_str = if info.rssi != 0 {
            format!("  {}  {}dBm", signal_bar(info.rssi), s().dim().paint(&format!("{}", info.rssi)))
        } else {
            String::new()
        };

        let target_line = if minimal {
            format!("  {}  {}{}", ssid_display, ch_str, rssi_str)
        } else {
            let ssid_padded = prism::pad(&ssid_display, ssid_max, "left");
            format!("  {}  {}  {}{}", ssid_padded, s().dim().paint(&bssid_str), ch_str, rssi_str)
        };
        lines.push(vline(&target_line, inner_w));

        // ═══ 4. AP info line: vendor · model · wifi gen · WPS version ═══
        if !minimal {
            let mut parts = Vec::new();
            let mfr_max = if compact { 16 } else { 24 };

            // Prefer M1 manufacturer if available, else scanner vendor
            if !info.ap_manufacturer.is_empty() {
                parts.push(truncate(&info.ap_manufacturer, mfr_max, "\u{2026}"));
            } else if !info.vendor.is_empty() {
                parts.push(truncate(&info.vendor, mfr_max, "\u{2026}"));
            }
            if !info.ap_model_name.is_empty() {
                parts.push(truncate(&info.ap_model_name, mfr_max, "\u{2026}"));
            }
            if !compact {
                if !info.ap_device_name.is_empty() {
                    parts.push(info.ap_device_name.clone());
                } else if !info.wps_device_name.is_empty() {
                    parts.push(info.wps_device_name.clone());
                }
            }
            if !info.wifi_gen.is_empty() {
                parts.push(info.wifi_gen.clone());
            }
            if info.wps_version > 0 {
                parts.push(format!("WPS {}.{}", info.wps_version >> 4, info.wps_version & 0xF));
            }
            if !parts.is_empty() {
                let ap_text = parts.join(" \u{00b7} ");
                lines.push(vline(&format!("  {}", s().dim().paint(&ap_text)), inner_w));
            }
        }
    } else if !info.running && info.phase == WpsPhase::Done {
        lines.push(empty_line());
        lines.push(vline(&s().dim().paint("  Attack complete"), inner_w));
    } else if info.running && info.phase == WpsPhase::KeyGeneration {
        // DH key generation spinner (before target is set)
        lines.push(empty_line());
        let keygen_spinner = prism::get_spinner("arc");
        let keygen_frame = keygen_spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(vline(&format!("  {} {}",
            s().cyan().paint(keygen_frame),
            s().dim().paint("Generating 1536-bit DH keypair...")), inner_w));
    }

    // ═══ 5. Sub-attacks list + detail line under active sub-attack ═══
    if !info.sub_attacks.is_empty() {
        lines.push(empty_line());
        for sub in &info.sub_attacks {
            lines.push(vline(&render_sub_attack(sub, spin, inner_w), inner_w));

            // Show detail line with └─ connector under the ACTIVE sub-attack
            if sub.active && !info.detail.is_empty() {
                let detail_text = s().dim().paint(&info.detail);

                // Render timeout progress bar if we have one
                let bar_str = if let Some(timeout) = info.wait_timeout {
                    let elapsed_ms = info.wait_started.elapsed().as_millis() as u64;
                    let total_ms = timeout.as_millis() as u64;
                    let bar_w = 12.min(inner_w / 6);
                    fn dim_bar(t: &str) -> String { s().cyan().paint(t) }
                    let bar = prism::render_progress_bar(elapsed_ms.min(total_ms), &prism::RenderOptions {
                        total: total_ms,
                        width: bar_w,
                        style: prism::BarStyle::Smooth,
                        color: Some(dim_bar),
                        ..Default::default()
                    });
                    let time_label = format!("{:.1}s / {:.1}s",
                        elapsed_ms as f64 / 1000.0,
                        total_ms as f64 / 1000.0);
                    format!("  {}  {}", bar, s().dim().paint(&time_label))
                } else {
                    String::new()
                };

                lines.push(vline(&format!("      {} {}{}",
                    s().dim().paint("\u{2514}\u{2500}"),
                    detail_text,
                    bar_str), inner_w));
            }
        }
    }

    // ═══ 6. Protocol pipeline (only when a sub-attack is active) ═══
    let has_active = info.sub_attacks.iter().any(|s| s.active);
    if has_active && (info.running || info.phase == WpsPhase::Done) {
        let phase_ord = phase_ordinal(info.phase);

        // Build pipeline steps — spec uses heavy dash ━━ for connectors
        let arr = s().dim().paint("\u{2501}\u{2501}");
        let ok = s().green().paint("\u{2713}");
        let pending = s().dim().paint("\u{25cb}");

        let steps: Vec<(u8, &str)> = vec![
            (1, "AUTH"), (2, "ASSOC"), (3, "EAP"),
            (4, "\u{2190}M1"), (5, "\u{2192}M2"), (6, "\u{2190}M3"),
        ];

        // Always show through M3. Show M4-M7 conditionally.
        let mut pipeline_parts = Vec::new();
        for (ord, label) in &steps {
            let icon = step_icon(phase_ord, *ord, spin, &ok, &pending);
            pipeline_parts.push(format!("{} {}", icon, s().bold().paint(label)));
        }

        // Pixie step after M3
        let show_pixie = matches!(info.phase, WpsPhase::PixieCracking)
            || (info.phase == WpsPhase::Done && matches!(info.attack_type, WpsAttackType::PixieDust));

        if show_pixie {
            let pixie_icon = match info.phase {
                WpsPhase::PixieCracking => s().magenta().bold().paint(spin),
                _ if info.pin_found.is_some() => s().green().paint("\u{2713}"),
                _ => s().yellow().paint("\u{2212}"),
            };
            pipeline_parts.push(format!("{} {}",
                pixie_icon,
                s().magenta().bold().paint("PIXIE")));
        }

        // M4-M7 for brute force / full exchange
        let show_m4_plus = !show_pixie && (phase_ord >= 7 || info.attack_type == WpsAttackType::BruteForce
            || (info.phase == WpsPhase::Done && info.pin_found.is_some()));
        if show_m4_plus {
            let extra: Vec<(u8, &str)> = vec![
                (7, "\u{2192}M4"), (8, "\u{2190}M5"), (9, "\u{2192}M6"), (10, "\u{2190}M7"),
            ];
            for (ord, label) in &extra {
                if phase_ord >= *ord || *ord <= phase_ord + 2 {
                    let icon = step_icon(phase_ord, *ord, spin, &ok, &pending);
                    pipeline_parts.push(format!("{} {}", icon, s().bold().paint(label)));
                }
            }
        }

        lines.push(empty_line());
        let pipeline_str = pipeline_parts.join(&format!(" {} ", arr));

        // Elapsed for the pipeline
        let elapsed_str = fmt_elapsed(info.start_time.elapsed().as_secs_f64());
        let pipeline_line = format!("      {}          {}", pipeline_str, s().dim().paint(&elapsed_str));
        let pipeline_w = prism::measure_width(&pipeline_line);

        if pipeline_w <= inner_w {
            lines.push(vline(&pipeline_line, inner_w));
        } else {
            // Two lines if too wide
            lines.push(vline(&format!("      {}", pipeline_str), inner_w));
            lines.push(vline(&format!("      {}", s().dim().paint(&elapsed_str)), inner_w));
        }

        // ═══ 7. Live metrics line ═══
        let mut metrics = Vec::new();
        if info.frames_sent > 0 {
            metrics.push(format!("tx: {}", info.frames_sent));
        }
        if info.frames_received > 0 {
            metrics.push(format!("rx: {}", info.frames_received));
        }
        if let Some(pct) = info.tx_feedback.delivery_pct() {
            metrics.push(format!("ack: {}%", pct as u64));
        }
        if !metrics.is_empty() {
            lines.push(vline(&format!("      {}", s().dim().paint(&metrics.join("  "))), inner_w));
        }
    }

    // ═══ Brute force progress (when active) ═══
    if info.attack_type == WpsAttackType::BruteForce && !info.current_pin.is_empty() {
        lines.push(empty_line());
        let phase_str = if info.half1_found { "phase 2" } else { "phase 1" };
        let pin_styled = if info.half1_found {
            s().yellow().bold().paint(&info.current_pin)
        } else {
            s().yellow().paint(&info.current_pin)
        };
        lines.push(vline(&format!("  PIN: {}  #{} {}",
            pin_styled, info.attempts, s().dim().paint(&format!("({})", phase_str))), inner_w));

        fn magenta_bar_bf(t: &str) -> String { s().magenta().paint(t) }
        let (current, total) = if info.half1_found {
            (info.attempts_half2 as u64, 1000u64)
        } else {
            (info.attempts_half1 as u64, 10000u64)
        };
        let bar_w = inner_w.saturating_sub(20);
        let bar = prism::render_progress_bar(current, &prism::RenderOptions {
            total,
            width: bar_w,
            style: prism::BarStyle::Arrows,
            color: Some(magenta_bar_bf),
            ..Default::default()
        });
        let pct = if total > 0 { current as f64 / total as f64 * 100.0 } else { 0.0 };
        lines.push(vline(&format!("  {}  {}", bar, s().dim().paint(&format!("{:.1}%", pct))), inner_w));

        if info.half1_found {
            lines.push(vline(&format!("  {} Half 1: {}",
                s().green().paint("\u{2713}"),
                s().green().bold().paint(&info.half1_pin)), inner_w));
        }
    }

    // ═══ Lockout warning ═══
    if info.lockouts_detected > 0 {
        let lockout_line = if info.phase == WpsPhase::LockoutWait {
            let lk_spinner = prism::get_spinner("hourglass");
            let lk_frame = lk_spinner.as_ref().map(|sp| {
                let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
                sp.frames[idx]
            }).unwrap_or("\u{231b}");
            format!("  {} {} lockouts \u{00b7} {}",
                s().red().paint(lk_frame),
                s().red().bold().paint(&info.lockouts_detected.to_string()),
                s().red().paint("waiting for AP cooldown..."))
        } else {
            format!("  \u{1f512} {} lockouts",
                s().red().paint(&info.lockouts_detected.to_string()))
        };
        lines.push(empty_line());
        lines.push(vline(&lockout_line, inner_w));
    }

    // ═══ 8. Trophy box (PIN cracked) ═══
    if let Some(ref pin) = info.pin_found {
        lines.push(empty_line());
        let psk = info.psk_found.as_deref().unwrap_or("");
        let trophy = render_trophy(pin, psk, inner_w);
        lines.extend(trophy);
    } else if info.has_pixie_data && info.status == WpsStatus::PixieDataOnly {
        lines.push(empty_line());
        lines.push(vline(&format!("  {} Pixie Dust data collected \u{2014} try external pixiewps",
            s().yellow().paint("\u{25cf}")), inner_w));
    }

    // ═══ 9. Bottom border with stats + metrics + key hints + elapsed ═══
    // Pattern: ╰── 3✔ 1✗ ── 45 tx · 10 rx · 87% ── [s] skip [n] next ── 2m 31s ─╯

    // Left: result counts
    let mut left_parts = Vec::new();
    if info.success_count > 0 {
        left_parts.push(format!("{}{}",
            s().green().bold().paint(&info.success_count.to_string()),
            s().green().paint("\u{2713}")));
    }
    if !info.results.is_empty() {
        let counts = count_results(&info.results);
        if counts.failed > 0 {
            left_parts.push(format!("{}{}",
                s().dim().paint(&counts.failed.to_string()),
                s().dim().paint("\u{2717}")));
        }
        if counts.locked > 0 {
            left_parts.push(format!("{}{}",
                s().red().paint(&counts.locked.to_string()),
                s().red().paint("\u{1f512}")));
        }
    }
    let left_summary = if left_parts.is_empty() {
        String::new()
    } else {
        format!(" {} ", left_parts.join(" \u{00b7} "))
    };

    // Center: frame counters + key hints
    let mut center_parts = Vec::new();
    if info.frames_sent > 0 || info.frames_received > 0 {
        center_parts.push(format!("{} tx \u{00b7} {} rx",
            prism::format_number(info.frames_sent),
            prism::format_number(info.frames_received)));
        if let Some(pct) = info.tx_feedback.delivery_pct() {
            center_parts.push(format!("{}%", pct as u64));
        }
    }
    if info.running {
        if info.target_total > 1 {
            center_parts.push("[s] skip [n] next".to_string());
        } else if matches!(info.attack_type, WpsAttackType::Auto) {
            center_parts.push("[s] skip".to_string());
        }
    }
    let center = if center_parts.is_empty() {
        String::new()
    } else {
        format!(" {} ", center_parts.join(" \u{00b7} "))
    };

    // Right: elapsed + status icon
    let elapsed_str = fmt_elapsed(info.start_time.elapsed().as_secs_f64());
    let status_text = if !info.running && info.phase == WpsPhase::Done {
        if info.pin_found.is_some() {
            format!(" {} {} ", s().green().paint("\u{2713}"), elapsed_str)
        } else {
            format!(" {} {} ", s().dim().paint("\u{25a0}"), elapsed_str)
        }
    } else {
        format!(" {} ", elapsed_str)
    };

    if no_frame {
        let parts: Vec<&str> = [left_summary.trim(), center.trim(), status_text.trim()]
            .iter().filter(|p| !p.is_empty()).copied().collect();
        lines.push(format!("  {}", s().dim().paint(&parts.join("  \u{00b7}  "))));
    } else {
        // Pack into ╰── left ── center ── right ─╯
        let left_w = prism::measure_width(&prism::strip_ansi(&left_summary));
        let center_w = prism::measure_width(&prism::strip_ansi(&center));
        let status_w = prism::measure_width(&prism::strip_ansi(&status_text));
        let total_content = left_w + center_w + status_w + 4;
        let fill = (inner_w + 2).saturating_sub(total_content);

        lines.push(format!("  {}{}{}{}{}{}{}",
            bc("\u{2570}"),
            bc("\u{2500}"),
            left_summary,
            bc(&"\u{2500}".repeat(fill / 2)),
            s().dim().paint(&center),
            bc(&"\u{2500}".repeat(fill.saturating_sub(fill / 2))),
            format!("{}{}", status_text, bc("\u{256f}")),
        ));
    }

    // Breathing room below the frame
    lines.push(String::new());

    // Enforce max height cap — truncate content, always keep footer border + breathing room
    if lines.len() > max_lines {
        let bottom = lines.split_off(lines.len().saturating_sub(2)); // save border + breathing
        lines.truncate(max_lines.saturating_sub(2));
        lines.extend(bottom);
    }

    lines
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Frozen target summaries — printed to scrollback on TargetComplete
// ═══════════════════════════════════════════════════════════════════════════════

/// Produce a frozen summary for a completed target.
/// Called from app.rs when TargetComplete event fires.
///
/// - Success: green framed box with PIN/PSK
/// - Locked: red accent, no frame
/// - Failed: dim, compact
pub fn freeze_target_summary(_info: &WpsInfo, result: &WpsResult) -> Vec<String> {
    let elapsed = fmt_elapsed(result.elapsed.as_secs_f64());
    let mfr = if result.manufacturer.is_empty() { String::new() }
        else { format!(" \u{00b7} {}", truncate(&result.manufacturer, 20, "\u{2026}")) };
    let ssid_display = if result.ssid.is_empty() { "(hidden)" } else { &result.ssid };

    match result.status {
        WpsStatus::Success => {
            // Green framed summary using prism::frame()
            let pin = result.pin.as_deref().unwrap_or("?");
            let psk = result.psk.as_deref().unwrap_or("");
            let spaced_pin: String = pin.chars().map(|c| c.to_string()).collect::<Vec<_>>().join(" ");

            let title = format!("{} {} {}{}  {}",
                s().green().bold().paint(ssid_display),
                s().dim().paint(&result.bssid.to_string()),
                s().cyan().paint(&format!("ch{}", result.channel)),
                mfr, s().dim().paint(&elapsed));

            let pin_line = if psk.is_empty() {
                format!("PIN  {}", s().green().bold().paint(&spaced_pin))
            } else {
                format!("PIN  {}    PSK  {}",
                    s().green().bold().paint(&spaced_pin),
                    s().green().bold().paint(psk))
            };

            let framed = prism::frame(&pin_line, &FrameOptions {
                border: BorderStyle::Rounded,
                width: Some(78),
                padding: 1,
                title: Some(format!(" {} {} ", s().green().bold().paint("\u{2713}"), title)),
            });
            // Colorize frame borders green
            framed.trim_end().split('\n')
                .map(|line| format!("  {}", s().green().paint(line)))
                .collect()
        }
        WpsStatus::Locked => {
            // Red accent, no frame
            vec![
                format!("  {} \u{1f512} {}  {}  ch{}{}  {}",
                    s().red().bold().paint("\u{2500}\u{2500}"),
                    s().bold().paint(ssid_display),
                    s().dim().paint(&result.bssid.to_string()),
                    result.channel, mfr,
                    s().dim().paint(&elapsed)),
            ]
        }
        _ => {
            // Dim compact one-liner
            let label = status_label(result.status);
            vec![
                format!("  {} {} {}  {}  ch{}{}  {}  {}",
                    s().dim().paint("\u{2500}\u{2500}"),
                    s().dim().paint("\u{2717}"),
                    s().dim().paint(ssid_display),
                    s().dim().paint(&result.bssid.to_string()),
                    result.channel, s().dim().paint(&mfr),
                    s().dim().paint(label),
                    s().dim().paint(&elapsed)),
            ]
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Status bar segments
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate status bar segments for the WPS attack.
pub fn status_segments(info: &WpsInfo) -> Vec<StatusSegment> {
    let mut segs = Vec::new();

    if !info.running && info.phase == WpsPhase::Idle {
        return segs;
    }

    let attack_text = if info.target_total > 1 {
        format!("wps {}: {} ({}/{} \u{00b7} {})",
            info.attack_type.short_name(), info.ssid,
            info.target_index, info.target_total,
            phase_label(info.phase))
    } else if info.ssid.is_empty() {
        format!("wps {}: {}", info.attack_type.short_name(), phase_label(info.phase))
    } else {
        format!("wps {}: {} ({})", info.attack_type.short_name(), info.ssid, phase_label(info.phase))
    };

    segs.push(StatusSegment::new(attack_text, SegmentStyle::MagentaBold));

    if info.attempts > 0 {
        segs.push(StatusSegment::new(format!("#{}", info.attempts), SegmentStyle::Yellow));
    }

    if info.success_count > 0 {
        segs.push(StatusSegment::new(format!("{}\u{2714}", info.success_count), SegmentStyle::Green));
    }

    if info.lockouts_detected > 0 {
        segs.push(StatusSegment::new(format!("{}\u{1f512}", info.lockouts_detected), SegmentStyle::Red));
    }

    if let Some(pct) = info.tx_feedback.delivery_pct() {
        segs.push(StatusSegment::new(format!("{}%tx", pct as u64), SegmentStyle::Dim));
    }

    segs.push(StatusSegment::new(fmt_elapsed(info.start_time.elapsed().as_secs_f64()), SegmentStyle::Dim));

    segs
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WpsModule — Module trait implementation for WPS attack
// ═══════════════════════════════════════════════════════════════════════════════

use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};
use crate::store::Ap;

/// WpsModule wraps WpsAttack with the Module trait for the shell's focus stack.
///
/// Uses SharedAdapter architecture: the attack spawns its own thread via start(),
/// locks the channel, and shares the adapter with the scanner.
pub struct WpsModule {
    attack: WpsAttack,
    /// Target APs for starting the attack. Single or multi-target.
    targets: Vec<Ap>,
    /// Cached info for rendering — refreshed each render cycle.
    cached_info: Option<WpsInfo>,
    /// Scroll offset for results table (j/k navigation).
    scroll_offset: usize,
}

impl WpsModule {
    pub fn new(params: WpsParams) -> Self {
        let attack = WpsAttack::new(params);
        Self {
            attack,
            targets: Vec::new(),
            cached_info: None,
            scroll_offset: 0,
        }
    }

    /// Get the underlying attack for starting with targets.
    pub fn attack(&self) -> &WpsAttack {
        &self.attack
    }

    /// Set single target AP before starting.
    #[allow(dead_code)]
    pub fn set_target(&mut self, target: Ap) {
        self.targets = vec![target];
    }

    /// Set multiple targets for --all mode.
    pub fn set_targets(&mut self, targets: Vec<Ap>) {
        self.targets = targets;
    }

    /// Drain new events since last call. Used by the shell to print to scrollback.
    pub fn drain_events(&mut self) -> Vec<WpsEvent> {
        self.attack.events()
    }

    /// Get current attack info.
    #[allow(dead_code)]
    pub fn info(&self) -> WpsInfo {
        self.attack.info()
    }
}

impl Module for WpsModule {
    fn name(&self) -> &str { "wps" }
    fn description(&self) -> &str { "WPS PIN attack" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }

    fn start(&mut self, shared: crate::adapter::SharedAdapter) {
        let targets = std::mem::take(&mut self.targets);
        if !targets.is_empty() {
            self.attack.start(shared, targets);
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
        &[] // WPS uses a single view — no tabs
    }

    fn render(&mut self, _view: usize, width: u16, height: u16) -> Vec<String> {
        let info = self.attack.info();
        self.cached_info = Some(info.clone());
        render_wps_view(&info, width, height, self.scroll_offset)
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
            "s" => {
                // Skip current sub-attack (move to next in Auto chain)
                self.attack.skip_attack();
                true
            }
            "n" => {
                // Skip current target (move to next AP in --all mode)
                self.attack.skip_target();
                true
            }
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

        let result_str = if let Some(ref pin) = info.pin_found {
            if let Some(ref psk) = info.psk_found {
                format!("PIN: {}  PSK: {}", pin, psk)
            } else {
                format!("PIN: {}", pin)
            }
        } else {
            status_label(info.status).to_string()
        };

        let mut content_parts = vec![
            format!("Type: {}", info.attack_type.name()),
        ];
        if !info.ssid.is_empty() {
            content_parts.insert(0, format!("Target: {} ({})", info.ssid, info.bssid));
        }
        content_parts.push(format!("Result: {}", result_str));
        if info.attempts > 0 {
            content_parts.push(format!("Attempts: {}  |  Duration: {}", info.attempts, fmt_elapsed(info.elapsed.as_secs_f64())));
        }
        content_parts.push(format!("Frames: {} sent  {} recv", prism::format_number(info.frames_sent), prism::format_number(info.frames_received)));

        // Multi-target results with category breakdown
        if info.results.len() > 1 {
            let counts = count_results(&info.results);
            let mut parts = vec![format!("{} tested", info.results_count)];
            if counts.success > 0 { parts.push(format!("{} cracked", counts.success)); }
            if counts.pixie_data > 0 { parts.push(format!("{} pixie data", counts.pixie_data)); }
            if counts.locked > 0 { parts.push(format!("{} locked", counts.locked)); }
            if counts.failed > 0 { parts.push(format!("{} failed", counts.failed)); }
            content_parts.push(format!("Targets: {}", parts.join("  ")));
        }

        let frame_width = (width as usize).saturating_sub(4);
        let inner_width = frame_width.saturating_sub(4); // borders + padding

        // Truncate content lines to fit inside frame
        let truncated: Vec<String> = content_parts.iter().map(|line| {
            if prism::measure_width(line) > inner_width {
                prism::truncate(line, inner_width, "\u{2026}")
            } else {
                line.clone()
            }
        }).collect();
        let content = truncated.join("\n");

        let framed = prism::frame(&content, &FrameOptions {
            border: BorderStyle::Rounded,
            title: Some("WPS Attack Complete".into()),
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
    use crate::attacks::wps::WpsAttackType;
    use std::time::Duration;
    use crate::core::MacAddress;

    #[test]
    fn test_phase_labels() {
        assert_eq!(phase_label(WpsPhase::Idle), "idle");
        assert_eq!(phase_label(WpsPhase::KeyGeneration), "generating DH keys");
        assert_eq!(phase_label(WpsPhase::PixieCracking), "Pixie Dust cracking");
        assert_eq!(phase_label(WpsPhase::BruteForcePhase1), "brute force (half 1)");
        assert_eq!(phase_label(WpsPhase::Done), "done");
    }

    #[test]
    fn test_status_labels() {
        assert_eq!(status_label(WpsStatus::Success), "PIN found!");
        assert_eq!(status_label(WpsStatus::Locked), "AP locked out");
        assert_eq!(status_label(WpsStatus::PixieDataOnly), "Pixie data only");
        assert_eq!(status_label(WpsStatus::Stopped), "stopped");
    }

    #[test]
    fn test_render_empty_info() {
        let info = WpsInfo::default();
        let lines = render_wps_view(&info, 80, 40, 0);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_format_key_generated_event() {
        let event = WpsEvent {
            seq: 1,
            timestamp: Duration::from_millis(1500),
            kind: WpsEventKind::KeyGenerated { elapsed_ms: 1500 },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("KEYGEN"));
        assert!(formatted.contains("1500ms"));
    }

    #[test]
    fn test_format_pin_success_event() {
        let event = WpsEvent {
            seq: 5,
            timestamp: Duration::from_secs(3),
            kind: WpsEventKind::PinSuccess {
                pin: "12345670".to_string(),
                psk: "MyPassword123".to_string(),
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("SUCCESS"));
        assert!(formatted.contains("12345670"));
        assert!(formatted.contains("MyPassword123"));
    }

    #[test]
    fn test_format_pixie_crack_success() {
        let event = WpsEvent {
            seq: 4,
            timestamp: Duration::from_millis(5000),
            kind: WpsEventKind::PixieCrackSuccess {
                pin: "48563290".to_string(),
                elapsed_ms: 350,
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("PIXIE!"));
        assert!(formatted.contains("48563290"));
    }

    #[test]
    fn test_status_segments_idle() {
        let info = WpsInfo::default();
        let segs = status_segments(&info);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_status_segments_running() {
        let mut info = WpsInfo::default();
        info.running = true;
        info.phase = WpsPhase::M1Received;
        info.attack_type = WpsAttackType::PixieDust;
        info.ssid = "TestAP".to_string();
        info.attempts = 0;
        let segs = status_segments(&info);
        assert!(!segs.is_empty());
    }

    #[test]
    fn test_render_with_pin_found() {
        let mut info = WpsInfo::default();
        info.running = false;
        info.phase = WpsPhase::Done;
        info.status = WpsStatus::Success;
        info.attack_type = WpsAttackType::PixieDust;
        info.ssid = "VulnerableAP".to_string();
        info.bssid = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        info.channel = 6;
        info.pin_found = Some("48563290".to_string());
        info.psk_found = Some("SecretPassword".to_string());
        let lines = render_wps_view(&info, 100, 40, 0);
        assert!(lines.len() >= 4);
    }

    #[test]
    fn test_render_brute_force_in_progress() {
        let mut info = WpsInfo::default();
        info.running = true;
        info.phase = WpsPhase::BruteForcePhase1;
        info.attack_type = WpsAttackType::BruteForce;
        info.ssid = "TestAP".to_string();
        info.bssid = MacAddress::new([0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]);
        info.channel = 11;
        info.current_pin = "12340000".to_string();
        info.attempts = 1234;
        info.frames_sent = 5000;
        info.frames_received = 3000;
        let lines = render_wps_view(&info, 100, 40, 0);
        assert!(lines.len() >= 4);
    }
}
