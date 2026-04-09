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
    WpsAttack, WpsAttackType, WpsEvent, WpsEventKind, WpsInfo, WpsParams,
    WpsPhase, WpsStatus,
};

use prism::{s, truncate, FrameOptions, BorderStyle};

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

/// Render the WPS attack progress view for the Layout active zone.
///
/// Layout (redesigned dashboard):
///   1. Header with attack type badge
///   2. Current target info + AP device info
///   3. Message exchange pipeline (AUTH→ASSOC→EAP→M1→M2→M3...)
///   4. Brute force progress (PIN + progress bar + half indicators)
///   5. PIN/PSK trophy on success
///   6. Multi-target summary bar (progress + category counts)
///   7. Rich results table (SSID, BSSID, manufacturer, phase, status, time)
///   8. Footer with comprehensive stats
pub fn render_wps_view(info: &WpsInfo, width: u16, _height: u16, scroll_offset: usize) -> Vec<String> {
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

    // ═══ Header border with attack type badge ═══
    // Key hints for skip controls
    let key_hints = if info.running {
        if info.target_total > 1 {
            format!("  {}", s().dim().paint("[s] skip attack  [n] skip target"))
        } else if matches!(info.attack_type, WpsAttackType::Auto) {
            format!("  {}", s().dim().paint("[s] skip attack"))
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let title_text = format!(" wps {} ", info.attack_type.short_name());
    let title = s().magenta().bold().paint(&title_text);
    let title_plain_w = title_text.len();

    // Multi-target progress indicator in header
    let progress_text = if info.target_total > 1 {
        format!(" {}/{} ", info.target_index, info.target_total)
    } else {
        String::new()
    };
    let progress_styled = if !progress_text.is_empty() {
        s().cyan().paint(&progress_text)
    } else {
        String::new()
    };
    let progress_w = if info.target_total > 1 { progress_text.len() } else { 0 };

    let remaining = inner_w.saturating_sub(title_plain_w + progress_w + 1);
    if progress_w > 0 {
        lines.push(format!("  {}{}{}{}{}", bc("\u{256d}\u{2500}"), title,
            bc(&"\u{2500}".repeat(remaining)), progress_styled, bc("\u{256e}")));
    } else {
        lines.push(format!("  {}{}{}{}", bc("\u{256d}\u{2500}"), title,
            bc(&"\u{2500}".repeat(remaining + 1)), bc("\u{256e}")));
    }

    // ═══ Current target info ═══
    if !info.ssid.is_empty() {
        let ssid_display = s().white().bold().paint(&truncate(&info.ssid, 28, "\u{2026}"));
        let bssid_str = info.bssid.to_string();
        let target_line = format!("{}  {}  {}",
            ssid_display,
            s().dim().paint(&bssid_str),
            s().cyan().paint(&format!("ch{}", info.channel)));
        lines.push(vline(&target_line, inner_w));

        // AP Device Info (from M1) — on same line or below
        if !info.ap_manufacturer.is_empty() || !info.ap_device_name.is_empty() {
            let mfr = if !info.ap_manufacturer.is_empty() {
                truncate(&info.ap_manufacturer, 20, "\u{2026}")
            } else {
                String::new()
            };
            let model = if !info.ap_model_name.is_empty() {
                info.ap_model_name.clone()
            } else {
                String::new()
            };
            let dev = if !info.ap_device_name.is_empty() {
                format!("({})", truncate(&info.ap_device_name, 24, "\u{2026}"))
            } else {
                String::new()
            };
            let parts: Vec<&str> = [mfr.as_str(), model.as_str(), dev.as_str()]
                .iter().filter(|p| !p.is_empty()).copied().collect();
            let ap_line = format!("{} {}",
                s().dim().paint("\u{2514}\u{2500}"),
                s().dim().paint(&parts.join("  ")));
            lines.push(vline(&ap_line, inner_w));
        }
    } else if !info.running && info.phase == WpsPhase::Done {
        lines.push(vline(&s().dim().paint("Attack complete"), inner_w));
    }

    // Key hints
    if !key_hints.is_empty() {
        lines.push(vline(&key_hints, inner_w));
    }

    // ═══ Message exchange pipeline ═══
    if info.running || info.phase == WpsPhase::Done {
        let spinner = prism::get_spinner("dots");
        let spin = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let arr = s().dim().paint("\u{2500}");
        let ok = s().green().paint("\u{2714}");
        let pending = s().dim().paint("\u{25cb}");

        let phase_ord = phase_ordinal(info.phase);

        // Setup steps: AUTH ─ ASSOC ─ EAP
        let auth = step_icon(phase_ord, 1, spin, &ok, &pending);
        let assoc = step_icon(phase_ord, 2, spin, &ok, &pending);
        let eap = step_icon(phase_ord, 3, spin, &ok, &pending);

        // WPS messages: ←M1 →M2 ←M3 →M4 ←M5 →M6 ←M7
        let m1 = msg_step(phase_ord, 4, spin, &ok, &pending, "\u{2190}M1");
        let m2 = msg_step(phase_ord, 5, spin, &ok, &pending, "\u{2192}M2");
        let m3 = msg_step(phase_ord, 6, spin, &ok, &pending, "\u{2190}M3");
        let m4 = msg_step(phase_ord, 7, spin, &ok, &pending, "\u{2192}M4");
        let m5 = msg_step(phase_ord, 8, spin, &ok, &pending, "\u{2190}M5");
        let m6 = msg_step(phase_ord, 9, spin, &ok, &pending, "\u{2192}M6");
        let m7 = msg_step(phase_ord, 10, spin, &ok, &pending, "\u{2190}M7");

        // Pixie step
        let pixie = match info.phase {
            WpsPhase::PixieCracking =>
                format!(" {} {} {}", arr, s().magenta().bold().paint(spin), s().magenta().bold().paint("PIXIE")),
            WpsPhase::Done if info.attack_type == WpsAttackType::PixieDust && info.pin_found.is_some() =>
                format!(" {} {} {}", arr, s().green().paint("\u{2714}"), s().green().bold().paint("PIXIE")),
            WpsPhase::Done if info.attack_type == WpsAttackType::PixieDust =>
                format!(" {} {} {}", arr, s().yellow().paint("\u{2212}"), s().yellow().paint("PIXIE")),
            _ => String::new(),
        };

        lines.push(empty_line());

        // Single-line pipeline: AUTH ─ ASSOC ─ EAP ─ ←M1 →M2 ←M3 [→M4...] [PIXIE]
        let setup = format!("{}AUTH {} {}ASSOC {} {}EAP",
            auth, arr, assoc, arr, eap);

        let show_m4_onward = info.attack_type != WpsAttackType::PixieDust || info.pin_found.is_some();
        let show_m5_onward = phase_ord >= 8 || (info.phase == WpsPhase::Done && info.pin_found.is_some() && info.attack_type != WpsAttackType::PixieDust);

        let msg_part = if show_m5_onward {
            format!("{} {} {} {} {} {} {}", m1, m2, m3, m4, m5, m6, m7)
        } else if show_m4_onward && pixie.is_empty() {
            format!("{} {} {} {}", m1, m2, m3, m4)
        } else {
            format!("{} {} {}{}", m1, m2, m3, pixie)
        };

        // Wide enough? Put on one line. Otherwise split into two.
        let setup_plain = format!("AUTH - ASSOC - EAP");
        let full_plain_w = setup_plain.len() + 3 + 20; // rough estimate
        if inner_w >= full_plain_w + 30 {
            // One line
            lines.push(vline(&format!("{} {} {}", setup, arr, msg_part), inner_w));
        } else {
            // Two lines
            lines.push(vline(&setup, inner_w));
            lines.push(vline(&msg_part, inner_w));
        }
    }

    // ═══ DH key generation spinner ═══
    if info.running && info.phase == WpsPhase::KeyGeneration {
        let spinner = prism::get_spinner("arc");
        let frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(empty_line());
        lines.push(vline(&format!("{} {}",
            s().cyan().paint(frame),
            s().dim().paint("Generating 1536-bit DH keypair...")), inner_w));
    }

    // ═══ Brute force progress ═══
    if info.attack_type == WpsAttackType::BruteForce && !info.current_pin.is_empty() {
        lines.push(empty_line());

        // Current PIN with phase indicator
        let phase_str = if info.half1_found { "phase 2" } else { "phase 1" };
        let pin_styled = if info.half1_found {
            s().yellow().bold().paint(&info.current_pin)
        } else {
            s().yellow().paint(&info.current_pin)
        };
        let pin_line = format!("PIN: {}  #{} {}",
            pin_styled, info.attempts, s().dim().paint(&format!("({})", phase_str)));
        lines.push(vline(&pin_line, inner_w));

        // Progress bar
        fn magenta_bar(t: &str) -> String { s().magenta().paint(t) }
        let (current, total, phase_label_str) = if info.half1_found {
            (info.attempts_half2 as u64, 1000u64, "phase 2")
        } else {
            (info.attempts_half1 as u64, 10000u64, "phase 1")
        };
        let bar_w = inner_w.saturating_sub(20);
        let bar = prism::render_progress_bar(current, &prism::RenderOptions {
            total,
            width: bar_w,
            style: prism::BarStyle::Smooth,
            color: Some(magenta_bar),
            ..Default::default()
        });
        let pct = if total > 0 { current as f64 / total as f64 * 100.0 } else { 0.0 };
        let progress_label = format!("{}/{} ({}) {:.1}%", current, total, phase_label_str, pct);
        lines.push(vline(&format!("{}  {}", bar, s().dim().paint(&progress_label)), inner_w));

        // Half 1 found indicator
        if info.half1_found {
            lines.push(vline(&format!("{} Half 1: {}",
                s().green().paint("\u{2714}"),
                s().green().bold().paint(&info.half1_pin)), inner_w));
        }
    }

    // ═══ Lockout warning ═══
    if info.lockouts_detected > 0 {
        let lockout_line = if info.phase == WpsPhase::LockoutWait {
            let spinner = prism::get_spinner("hourglass");
            let frame = spinner.as_ref().map(|sp| {
                let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
                sp.frames[idx]
            }).unwrap_or("\u{231b}");
            format!("{} {} lockouts \u{00b7} {}",
                s().red().paint(frame),
                s().red().bold().paint(&info.lockouts_detected.to_string()),
                s().red().paint("waiting for AP cooldown..."))
        } else {
            format!("{} {} lockouts",
                s().red().paint("\u{1f512}"),
                s().red().paint(&info.lockouts_detected.to_string()))
        };
        lines.push(empty_line());
        lines.push(vline(&lockout_line, inner_w));
    }

    // ═══ PIN/PSK trophy ═══
    if let Some(ref pin) = info.pin_found {
        lines.push(empty_line());
        let pin_line = format!("  {} PIN  {}",
            s().green().bold().paint("\u{2714}"),
            s().green().bold().paint(pin));
        lines.push(vline(&pin_line, inner_w));
        if let Some(ref psk) = info.psk_found {
            let psk_line = format!("  {} PSK  {}",
                s().green().bold().paint("\u{2714}"),
                s().green().bold().paint(psk));
            lines.push(vline(&psk_line, inner_w));
        }
    } else if info.has_pixie_data && info.status == WpsStatus::PixieDataOnly {
        lines.push(empty_line());
        lines.push(vline(&format!("{} Pixie Dust data collected \u{2014} try external pixiewps",
            s().yellow().paint("\u{25cf}")), inner_w));
    }

    // ═══ Multi-target summary bar ═══
    if info.target_total > 1 && !info.results.is_empty() {
        let counts = count_results(&info.results);

        lines.push(empty_line());

        // Mini progress bar for target progress
        fn cyan_bar(t: &str) -> String { s().cyan().paint(t) }
        let done = counts.total as u64;
        let total = info.target_total as u64;
        let bar_w = 20.min(inner_w / 4);
        let bar = prism::render_progress_bar(done, &prism::RenderOptions {
            total,
            width: bar_w,
            style: prism::BarStyle::Smooth,
            color: Some(cyan_bar),
            ..Default::default()
        });

        // Category counts
        let mut cats = Vec::new();
        if counts.success > 0 {
            cats.push(format!("{} {}",
                s().green().bold().paint(&counts.success.to_string()),
                s().green().paint("cracked")));
        }
        if counts.pixie_data > 0 {
            cats.push(format!("{} {}",
                s().yellow().paint(&counts.pixie_data.to_string()),
                s().yellow().paint("pixie")));
        }
        if counts.locked > 0 {
            cats.push(format!("{} {}",
                s().red().paint(&counts.locked.to_string()),
                s().red().paint("locked")));
        }
        if counts.failed > 0 {
            cats.push(format!("{} {}",
                s().dim().paint(&counts.failed.to_string()),
                s().dim().paint("failed")));
        }

        // Average time per target + ETA
        let avg_secs = if counts.total > 0 {
            info.results.iter().map(|r| r.elapsed.as_secs_f64()).sum::<f64>() / counts.total as f64
        } else { 0.0 };
        let remaining_targets = info.target_total.saturating_sub(info.target_index);
        let eta_secs = avg_secs * remaining_targets as f64;

        let eta_str = if remaining_targets > 0 && avg_secs > 0.0 {
            if eta_secs >= 3600.0 {
                format!("~{:.0}h{:.0}m left", eta_secs / 3600.0, (eta_secs % 3600.0) / 60.0)
            } else if eta_secs >= 60.0 {
                format!("~{:.0}m{:.0}s left", eta_secs / 60.0, eta_secs % 60.0)
            } else {
                format!("~{:.0}s left", eta_secs)
            }
        } else {
            String::new()
        };

        let summary_line = format!("{} {}/{}  {}{}",
            bar, done, total,
            cats.join("  "),
            if !eta_str.is_empty() {
                format!("  {}", s().dim().paint(&eta_str))
            } else {
                String::new()
            });
        lines.push(vline(&summary_line, inner_w));

        // Divider before results table
        let divider = "\u{2500}".repeat(inner_w);
        lines.push(vline(&s().dim().paint(&divider), inner_w));
    }

    // ═══ Results table (rich columns, scrollable) ═══
    let term_h = prism::term_height() as usize;
    let max_view = term_h * 45 / 100;
    let header_lines = lines.len();
    let footer_lines = 1;
    let available = max_view.saturating_sub(header_lines + footer_lines);

    if !info.results.is_empty() {
        let mut result_rows: Vec<String> = Vec::new();

        // Column widths
        const COL_SSID: usize = 16;
        const COL_BSSID: usize = 17;
        const COL_MFR: usize = 14;
        const COL_PHASE: usize = 5;
        const COL_STATUS: usize = 14;
        const COL_TIME: usize = 6;

        // Column header (only for multi-target)
        if info.target_total > 1 {
            let hdr = format!("  {}  {}  {}  {}  {}  {}  {}",
                " ",
                prism::pad("SSID", COL_SSID, "left"),
                prism::pad("BSSID", COL_BSSID, "left"),
                prism::pad("Manufacturer", COL_MFR, "left"),
                prism::pad("Phase", COL_PHASE, "right"),
                prism::pad("Status", COL_STATUS, "left"),
                prism::pad("Time", COL_TIME, "right"));
            result_rows.push(vline(&s().dim().paint(&hdr), inner_w));
        }

        for result in &info.results {
            let icon = status_icon(result.status);

            // SSID — padded to column width
            let ssid_raw = if result.ssid.is_empty() { "(hidden)" } else { &result.ssid };
            let ssid_trunc = truncate(ssid_raw, COL_SSID, "\u{2026}");
            let ssid_styled = match result.status {
                WpsStatus::Success => s().green().bold().paint(&ssid_trunc),
                WpsStatus::PixieDataOnly => s().yellow().bold().paint(&ssid_trunc),
                _ => s().bold().paint(&ssid_trunc),
            };
            let ssid_padded = prism::pad(&ssid_styled, COL_SSID, "left");

            // BSSID — always 17 chars
            let bssid_str = result.bssid.to_string();
            let bssid_padded = prism::pad(&s().dim().paint(&bssid_str), COL_BSSID, "left");

            // Manufacturer (truncated + padded)
            let mfr_raw = if result.manufacturer.is_empty() {
                s().dim().paint("\u{2014}")
            } else {
                s().dim().paint(&truncate(&result.manufacturer, COL_MFR, "\u{2026}"))
            };
            let mfr_padded = prism::pad(&mfr_raw, COL_MFR, "left");

            // Max phase badge (right-aligned)
            let phase = phase_badge(result.max_phase);
            let phase_padded = prism::pad(&phase, COL_PHASE, "right");

            // Status with color
            let status_styled = match result.status {
                WpsStatus::Success => s().green().bold().paint(status_label(result.status)),
                WpsStatus::PixieDataOnly => s().yellow().paint(status_label(result.status)),
                WpsStatus::Locked => s().red().bold().paint(status_label(result.status)),
                _ => s().red().paint(status_label(result.status)),
            };
            let status_padded = prism::pad(&status_styled, COL_STATUS, "left");

            // Elapsed time (right-aligned)
            let elapsed_str = fmt_elapsed(result.elapsed.as_secs_f64());
            let time_padded = prism::pad(&s().dim().paint(&elapsed_str), COL_TIME, "right");

            let row = format!("{} {}  {}  {}  {}  {}  {}",
                icon, ssid_padded,
                bssid_padded, mfr_padded,
                phase_padded,
                status_padded,
                time_padded);
            result_rows.push(vline(&row, inner_w));

            // PIN/PSK trophy for successful results
            if result.status == WpsStatus::Success {
                if let Some(ref pin) = result.pin {
                    let psk_str = result.psk.as_deref().unwrap_or("");
                    let trophy = format!("  {} PIN: {}  PSK: {}",
                        s().green().bold().paint("\u{2714}"),
                        s().green().bold().paint(pin),
                        s().green().bold().paint(psk_str));
                    result_rows.push(vline(&trophy, inner_w));
                }
            }
        }

        // Scrollable results
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
                lines.push(vline(&s().dim().paint(&format!("\u{2193} {} more  (j/k to scroll)", remaining_below)), inner_w));
            }
        }
    }

    // ═══ Footer border with comprehensive stats ═══
    let mut left_parts = Vec::new();

    // Attempt counter
    if info.attempts > 0 {
        left_parts.push(format!("#{}", info.attempts));
    }

    // Success/lockout counts
    if info.success_count > 0 {
        left_parts.push(format!("{}{}",
            s().green().bold().paint(&info.success_count.to_string()),
            s().green().paint("\u{2714}")));
    }
    if info.lockouts_detected > 0 {
        left_parts.push(format!("{}{}",
            s().red().paint(&info.lockouts_detected.to_string()),
            s().red().paint("\u{1f512}")));
    }

    let left_summary = if left_parts.is_empty() {
        String::new()
    } else {
        format!(" {} ", left_parts.join(" \u{00b7} "))
    };

    // Center: frame counters + TX feedback
    let mut stat_parts = Vec::new();
    if info.frames_sent > 0 {
        stat_parts.push(format!("{} sent", prism::format_number(info.frames_sent)));
    }
    if info.frames_received > 0 {
        stat_parts.push(format!("{} recv", prism::format_number(info.frames_received)));
    }
    if info.tx_feedback.total_reports > 0 {
        let ack_str = format!("{} ack", s().green().paint(&prism::format_number(info.tx_feedback.acked)));
        let nack_str = format!("{} nack", s().red().paint(&prism::format_number(info.tx_feedback.nacked)));
        stat_parts.push(ack_str);
        stat_parts.push(nack_str);
        if let Some(pct) = info.tx_feedback.delivery_pct() {
            stat_parts.push(format!("{}%", s().dim().paint(&format!("{}", pct as u64))));
        }
    }
    let stats = if stat_parts.is_empty() {
        String::new()
    } else {
        format!(" {} ", stat_parts.join(" \u{00b7} "))
    };

    // Right: elapsed time + status
    let elapsed_str = fmt_elapsed(info.start_time.elapsed().as_secs_f64());
    let status_text = if !info.running && info.phase == WpsPhase::Done {
        if info.pin_found.is_some() {
            format!(" {} {} ", s().green().paint("\u{2714}"), elapsed_str)
        } else {
            format!(" {} {} ", s().yellow().paint("\u{25a0}"), elapsed_str)
        }
    } else if info.running {
        format!(" {} \u{00b7} {} ", elapsed_str, s().dim().paint("running"))
    } else {
        format!(" {} ", elapsed_str)
    };

    let left_w = prism::measure_width(&prism::strip_ansi(&left_summary));
    let stats_w = prism::measure_width(&prism::strip_ansi(&stats));
    let status_w = prism::measure_width(&prism::strip_ansi(&status_text));
    let total_content = left_w + stats_w + status_w + 4;
    let fill = (inner_w + 2).saturating_sub(total_content);

    lines.push(format!("  {}{}{}{}{}{}{}",
        bc("\u{2570}"),
        bc("\u{2500}"),
        left_summary,
        bc(&"\u{2500}".repeat(fill / 2)),
        s().dim().paint(&stats),
        bc(&"\u{2500}".repeat(fill.saturating_sub(fill / 2))),
        format!("{}{}", status_text, bc("\u{256f}")),
    ));

    lines
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
