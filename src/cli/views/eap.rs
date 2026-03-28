//! CLI renderer + Module implementation for the EAP enterprise attack.
//!
//! Renders the attack progress as styled terminal lines:
//! - Attack mode (Evil Twin / Credential Harvest / EAP Downgrade / etc.)
//! - Rogue AP status (beacon count, connected clients)
//! - Credential table (identity, method, cracking tool)
//! - Per-client EAP exchange progress
//! - Event log scrollback

use crate::attacks::eap::{
    EapAttack, EapEvent, EapEventKind, EapInfo,
    EapParams, EapPhase,
};

use prism::{s, truncate};

// ═══════════════════════════════════════════════════════════════════════════════
//  Phase display
// ═══════════════════════════════════════════════════════════════════════════════

fn phase_label(phase: EapPhase) -> &'static str {
    match phase {
        EapPhase::Idle => "idle",
        EapPhase::Starting => "starting",
        EapPhase::Listening => "listening",
        EapPhase::Active => "active",
        EapPhase::Done => "done",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Event formatting — for scrollback output
// ═══════════════════════════════════════════════════════════════════════════════

/// Format an EAP event as a styled terminal line for the output zone.
pub fn format_event(event: &EapEvent) -> String {
    let ts = format!("{:>7.3}s", event.timestamp.as_secs_f64());
    let ts_styled = s().dim().paint(&ts);

    match &event.kind {
        EapEventKind::ChannelLocked { channel } => {
            format!("  [{}] {} Locked to ch{}", ts_styled, s().dim().paint("LOCK"), channel)
        }
        EapEventKind::RogueApStarted { bssid, ssid } => {
            format!("  [{}] {} Rogue AP started: {}  {}",
                ts_styled, s().red().bold().paint("AP"),
                s().bold().paint(ssid),
                s().dim().paint(&bssid.to_string()))
        }
        EapEventKind::ClientAuthenticated { mac, rssi } => {
            format!("  [{}] {} {} ({} dBm)",
                ts_styled, s().cyan().paint("AUTH"),
                s().bold().paint(&mac.to_string()), rssi)
        }
        EapEventKind::ClientAssociated { mac, aid } => {
            format!("  [{}] {} {} (AID={})",
                ts_styled, s().cyan().paint("ASSOC"),
                s().bold().paint(&mac.to_string()), aid)
        }
        EapEventKind::IdentityRequestSent { mac } => {
            format!("  [{}] {} EAP-Request/Identity \u{2192} {}",
                ts_styled, s().dim().paint("EAP"),
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::IdentityReceived { mac, identity, domain } => {
            let domain_str = if domain.is_empty() {
                String::new()
            } else {
                format!("  ({})", s().dim().paint(domain))
            };
            format!("  [{}] {} {}  \u{2190} {}{}",
                ts_styled, s().green().paint("IDENTITY"),
                s().bold().paint(identity),
                s().dim().paint(&mac.to_string()),
                domain_str)
        }
        EapEventKind::ChallengeSent { mac, method } => {
            format!("  [{}] {} {:?} challenge \u{2192} {}",
                ts_styled, s().yellow().paint("CHALLENGE"),
                method,
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::ClientNak { mac, rejected, desired } => {
            let desired_str = desired.map(|d| format!(" wants {:?}", d)).unwrap_or_default();
            format!("  [{}] {} {} rejected {:?}{}",
                ts_styled, s().yellow().paint("NAK"),
                s().dim().paint(&mac.to_string()),
                rejected, desired_str)
        }
        EapEventKind::MethodRetried { mac, new_method } => {
            format!("  [{}] {} Retrying with {:?} \u{2192} {}",
                ts_styled, s().cyan().paint("RETRY"),
                new_method,
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::MsChapV2Captured { mac, identity } => {
            format!("  [{}] {} MSCHAPv2 hash captured!  {}  {}",
                ts_styled, s().green().bold().paint("CRED!"),
                s().bold().paint(identity),
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::LeapCaptured { mac, identity } => {
            format!("  [{}] {} LEAP hash captured!  {}  {}",
                ts_styled, s().green().bold().paint("CRED!"),
                s().bold().paint(identity),
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::GtcCaptured { mac, identity, password } => {
            format!("  [{}] {} GTC plaintext!  {}  password={}  {}",
                ts_styled, s().green().bold().paint("CRED!"),
                s().bold().paint(identity),
                s().green().bold().paint(password),
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::Md5Captured { mac, identity } => {
            format!("  [{}] {} MD5 hash captured!  {}  {}",
                ts_styled, s().green().bold().paint("CRED!"),
                s().bold().paint(identity),
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::IdentityStored { mac, identity } => {
            format!("  [{}] {} Identity stored: {}  {}",
                ts_styled, s().cyan().paint("ID"),
                s().bold().paint(identity),
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::EapFailureSent { mac } => {
            format!("  [{}] {} EAP-Failure \u{2192} {} (capture complete)",
                ts_styled, s().dim().paint("EAP"),
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::DeauthBurst { target_bssid, count } => {
            format!("  [{}] {} {} deauth frames \u{2192} {}",
                ts_styled, s().red().paint("DEAUTH"),
                count,
                s().dim().paint(&target_bssid.to_string()))
        }
        EapEventKind::ClientTimeout { mac } => {
            format!("  [{}] {} {} — no response",
                ts_styled, s().yellow().paint("TIMEOUT"),
                s().dim().paint(&mac.to_string()))
        }
        EapEventKind::MaxCredentialsReached { count } => {
            format!("  [{}] {} Max credentials ({}) reached — stopping",
                ts_styled, s().green().paint("LIMIT"), count)
        }
        EapEventKind::TimeoutReached { elapsed } => {
            format!("  [{}] {} Attack timeout ({:.0}s) reached",
                ts_styled, s().yellow().paint("TIMEOUT"), elapsed.as_secs_f64())
        }
        EapEventKind::AttackComplete { credentials_total, elapsed } => {
            let summary = format!("{} credentials captured", credentials_total);
            let summary_styled = if *credentials_total > 0 {
                s().green().bold().paint(&summary)
            } else {
                s().yellow().paint(&summary)
            };
            format!("  [{}] {} EAP attack complete: {}  ({:.1}s)",
                ts_styled, s().bold().paint("DONE"),
                summary_styled,
                elapsed.as_secs_f64())
        }
        EapEventKind::Error { message } => {
            format!("  [{}] {} {}", ts_styled, s().red().bold().paint("ERROR"), message)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Active zone view — rendered in the Layout active zone during attack
// ═══════════════════════════════════════════════════════════════════════════════

/// Render the EAP attack progress view for the Layout active zone.
pub fn render_eap_view(info: &EapInfo, width: u16) -> Vec<String> {
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

    // ═══ Header border with mode title ═══
    let title = format!(" {} ", info.mode.name());
    let title_styled = s().red().bold().paint(&title);
    let title_plain_w = prism::measure_width(&title);
    let remaining = inner_w.saturating_sub(title_plain_w + 1);
    lines.push(format!("  {}{}{}{}", bc("\u{256d}\u{2500}"), title_styled,
        bc(&"\u{2500}".repeat(remaining)), bc("\u{256e}")));

    // ═══ Target + Rogue AP ═══
    if !info.ssid.is_empty() {
        let ssid_display = s().bold().paint(&truncate(&info.ssid, 24, "\u{2026}"));
        let mut target_line = format!("{}  ch{}", ssid_display, info.channel);
        if info.our_bssid != crate::core::MacAddress::ZERO {
            target_line.push_str(&format!("  rogue: {}", s().dim().paint(&info.our_bssid.to_string())));
        }
        if let Some(target) = &info.target_bssid {
            if Some(*target) != Some(info.our_bssid) {
                target_line.push_str(&format!("  target: {}", s().dim().paint(&target.to_string())));
            }
        }
        lines.push(vline(&target_line, inner_w));
    }

    // ═══ Step progress ═══
    if info.running || info.phase == EapPhase::Done {
        let spinner = prism::get_spinner("dots");
        let spin_frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");

        let setup_step = match info.phase {
            EapPhase::Idle => format!("{} SETUP", s().dim().paint("\u{25cb}")),
            EapPhase::Starting => format!("{} SETUP", s().yellow().paint(spin_frame)),
            _ => format!("{} SETUP", s().green().paint("\u{2714}")),
        };

        let listen_step = match info.phase {
            EapPhase::Idle | EapPhase::Starting =>
                format!("{} LISTEN", s().dim().paint("\u{25cb}")),
            EapPhase::Listening => format!("{} LISTEN", s().cyan().paint(spin_frame)),
            _ => format!("{} LISTEN", s().green().paint("\u{2714}")),
        };

        let harvest_step = match info.phase {
            EapPhase::Active => format!("{} HARVEST", s().green().bold().paint(spin_frame)),
            EapPhase::Done => format!("{} HARVEST", s().green().paint("\u{2714}")),
            _ => format!("{} HARVEST", s().dim().paint("\u{25cb}")),
        };

        let arrow = s().dim().paint(" \u{2192} ");
        lines.push(vline(&format!("{}{}{}{}{}", setup_step, arrow, listen_step, arrow, harvest_step), inner_w));
    }

    lines.push(empty_line());

    // ═══ Live stats ═══
    if info.phase != EapPhase::Idle {
        let elapsed_secs = info.start_time.elapsed().as_secs_f64();

        // Client & credential counters
        let cred_str = if info.credentials_total > 0 {
            s().green().bold().paint(&info.credentials_total.to_string())
        } else { s().dim().paint("0") };
        let connected_str = format!("{}/{}", info.clients_connected, info.clients_total);
        let stats1 = format!("{} creds  {} clients  {} identities  {} challenges  {:.1}s",
            cred_str,
            s().cyan().bold().paint(&connected_str),
            info.identities_captured,
            info.challenges_captured,
            elapsed_secs);
        lines.push(vline(&stats1, inner_w));

        // Frame counters + method offered
        let fps_str = format!("{} fps", prism::format_compact(info.frames_per_sec as u64));
        let method_str = info.offered_method.map(|m| format!("  method: {:?}", m)).unwrap_or_default();
        let stats2 = format!("{} TX  {} RX  {}  {} beacons  {} deauths{}",
            s().dim().paint(&prism::format_number(info.frames_sent)),
            s().dim().paint(&prism::format_number(info.frames_received)),
            s().yellow().paint(&fps_str),
            prism::format_compact(info.beacons_sent),
            prism::format_compact(info.deauths_sent),
            s().dim().paint(&method_str));
        lines.push(vline(&stats2, inner_w));

        // Last captured credential (live indicator)
        if !info.last_identity.is_empty() {
            let domain_str = if info.last_domain.is_empty() {
                String::new()
            } else {
                format!("  ({})", s().dim().paint(&info.last_domain))
            };
            let method_badge = info.last_method
                .map(|m| format!("  {:?}", m))
                .unwrap_or_default();
            lines.push(vline(
                &format!("{} {}{}{}",
                    s().green().paint("\u{25b6}"),
                    s().green().bold().paint(&info.last_identity),
                    domain_str,
                    s().dim().paint(&method_badge)),
                inner_w));
        }

        // Overflow warning
        if info.credential_overflow > 0 {
            lines.push(vline(
                &format!("{} {} credentials dropped (buffer full)",
                    s().yellow().paint("\u{26a0}"),
                    info.credential_overflow),
                inner_w));
        }

        lines.push(empty_line());
    }

    // ═══ Credential table ═══
    if !info.credentials.is_empty() {
        lines.push(vline(
            &format!("{}  {}  {}  {}  {}",
                s().bold().dim().paint(&prism::pad("CLIENT", 17, "left")),
                s().bold().dim().paint(&prism::pad("IDENTITY", 25, "left")),
                s().bold().dim().paint(&prism::pad("METHOD", 10, "left")),
                s().bold().dim().paint(&prism::pad("RSSI", 4, "left")),
                s().bold().dim().paint(&prism::pad("TOOL", 18, "left"))),
            inner_w));

        for cred in &info.credentials {
            let method_str = format!("{:?}", cred.method);
            let identity_display = truncate(&cred.identity, 25, "\u{2026}");
            let tool_str = cred.cracking_tool();

            let icon = if cred.has_plaintext {
                s().green().bold().paint("\u{2714}")
            } else if cred.has_mschapv2 || cred.has_leap || cred.has_md5 {
                s().yellow().paint("\u{25cf}")
            } else {
                s().dim().paint("\u{25cb}")
            };

            lines.push(vline(
                &format!("{} {}  {}  {}  {:>4}  {}",
                    icon,
                    s().dim().paint(&cred.client_mac.to_string()),
                    s().bold().paint(&identity_display),
                    prism::pad(&method_str, 10, "left"),
                    cred.rssi,
                    s().dim().paint(tool_str)),
                inner_w));

            if cred.has_plaintext && !cred.plaintext_password.is_empty() {
                lines.push(vline(
                    &format!("    {} password: {}",
                        " ".repeat(17),
                        s().green().bold().paint(&cred.plaintext_password)),
                    inner_w));
            }
        }
    } else if info.phase == EapPhase::Listening || info.phase == EapPhase::Active {
        let spinner = prism::get_spinner("dots");
        let frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(vline(
            &format!("{} {}", s().cyan().paint(frame), s().dim().paint("Waiting for clients to connect...")),
            inner_w));
    } else if info.phase == EapPhase::Starting {
        let spinner = prism::get_spinner("dots");
        let frame = spinner.as_ref().map(|sp| {
            let idx = (info.start_time.elapsed().as_millis() / sp.interval_ms as u128) as usize % sp.frames.len();
            sp.frames[idx]
        }).unwrap_or(".");
        lines.push(vline(
            &format!("{} {}", s().cyan().paint(frame), s().dim().paint("Setting up rogue AP...")),
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

/// Generate status bar segments for the EAP attack.
pub fn status_segments(info: &EapInfo) -> Vec<StatusSegment> {
    let mut segs = Vec::new();

    if !info.running && info.phase == EapPhase::Idle {
        return segs;
    }

    let attack_text = if info.ssid.is_empty() {
        format!("eap {}: {}", info.mode.short_name(), phase_label(info.phase))
    } else {
        format!("eap {}: {} ({})", info.mode.short_name(), info.ssid, phase_label(info.phase))
    };

    segs.push(StatusSegment::new(attack_text, SegmentStyle::RedBold));

    if info.credentials_total > 0 {
        segs.push(StatusSegment::new(
            format!("{}\u{2714}", info.credentials_total),
            SegmentStyle::GreenBold,
        ));
    }

    if info.clients_total > 0 {
        segs.push(StatusSegment::new(format!("{} clients", info.clients_total), SegmentStyle::Cyan));
    }

    let elapsed_secs = info.start_time.elapsed().as_secs_f64();
    segs.push(StatusSegment::new(format!("{:.1}s", elapsed_secs), SegmentStyle::Dim));

    segs
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EapModule — Module trait implementation for EAP attack
// ═══════════════════════════════════════════════════════════════════════════════

use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};
use crate::store::Ap;

/// EapModule wraps EapAttack with the Module trait for the shell's focus stack.
///
/// Uses SharedAdapter architecture: the attack spawns its own thread via start(),
/// locks the channel, runs a rogue AP + EAP state machine, and shares the adapter
/// with the scanner.
pub struct EapModule {
    attack: EapAttack,
    /// Target AP for starting the attack.
    target: Option<Ap>,
    /// Cached info for rendering — refreshed each render cycle.
    cached_info: Option<EapInfo>,
}

impl EapModule {
    pub fn new(params: EapParams) -> Self {
        let attack = EapAttack::new(params);
        Self {
            attack,
            target: None,
            cached_info: None,
        }
    }

    /// Get the underlying attack.
    pub fn attack(&self) -> &EapAttack {
        &self.attack
    }

    /// Set target AP before starting.
    pub fn set_target(&mut self, target: Ap) {
        self.target = Some(target);
    }

    /// Drain new events since last call. Used by the shell to print to scrollback.
    pub fn drain_events(&mut self) -> Vec<EapEvent> {
        self.attack.events()
    }

    /// Get current attack info.
    #[allow(dead_code)]
    pub fn info(&self) -> EapInfo {
        self.attack.info()
    }
}

impl Module for EapModule {
    fn name(&self) -> &str { "eap" }
    fn description(&self) -> &str { "EAP enterprise credential capture" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack }

    fn start(&mut self, shared: crate::adapter::SharedAdapter) {
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
        &[] // EAP uses a single view — no tabs
    }

    fn render(&mut self, _view: usize, width: u16, _height: u16) -> Vec<String> {
        let info = self.attack.info();
        self.cached_info = Some(info.clone());
        render_eap_view(&info, width)
    }

    fn handle_key(&mut self, _key: &prism::KeyEvent, _view: usize) -> bool {
        false
    }

    fn status_segments(&self) -> Vec<StatusSegment> {
        let info = self.attack.info();
        status_segments(&info)
    }

    fn freeze_summary(&self, width: u16) -> Vec<String> {
        let info = self.cached_info.as_ref().cloned()
            .unwrap_or_else(|| self.attack.info());

        let mut lines = Vec::new();

        // Build summary content for the frame
        let elapsed_secs = info.elapsed.as_secs_f64();
        let cred_str = if info.credentials_total > 0 {
            if info.plaintext_captured > 0 {
                format!("{} captured ({} plaintext!)", info.credentials_total, info.plaintext_captured)
            } else {
                format!("{} captured", info.credentials_total)
            }
        } else {
            "none".to_string()
        };

        let content = format!(
            "Mode:         {}\n\
             Credentials:  {}\n\
             Identities:   {}\n\
             Clients:      {} total, {} completed\n\
             Frames:       {} TX / {} RX ({:.0} fps)\n\
             Beacons:      {}\n\
             Deauths:      {}\n\
             EAP:          {} started, {} completed, {} NAKs\n\
             Duration:     {:.1}s",
            info.mode.name(),
            cred_str,
            info.identities_captured,
            info.clients_total, info.clients_completed,
            prism::format_number(info.frames_sent),
            prism::format_number(info.frames_received),
            info.frames_per_sec,
            prism::format_number(info.beacons_sent),
            prism::format_number(info.deauths_sent),
            info.eap_started, info.eap_completed, info.eap_naks,
            elapsed_secs,
        );

        let frame_width = (width as usize).min(60);
        let framed = prism::frame(&content, &prism::FrameOptions {
            width: Some(frame_width),
            title: Some("EAP COMPLETE".to_string()),
            ..Default::default()
        });

        lines.push(String::new());
        for line in framed.lines() {
            lines.push(format!("  {}", line));
        }

        // Credential details
        if !info.credentials.is_empty() {
            lines.push(String::new());
            for cred in &info.credentials {
                let method_str = format!("{:?}", cred.method);
                let tool = cred.cracking_tool();
                let icon = if cred.has_plaintext {
                    s().green().bold().paint("*")
                } else if cred.has_mschapv2 || cred.has_leap || cred.has_md5 {
                    s().yellow().paint("*")
                } else {
                    s().dim().paint("-")
                };
                lines.push(format!("  {} {}  {}  {}  {}",
                    icon,
                    s().bold().paint(&cred.identity),
                    s().dim().paint(&method_str),
                    s().dim().paint(&cred.client_mac.to_string()),
                    s().dim().paint(tool)));
                if cred.has_plaintext && !cred.plaintext_password.is_empty() {
                    lines.push(format!("    password: {}",
                        s().green().bold().paint(&cred.plaintext_password)));
                }
            }
        }

        // Export hint
        if info.credentials_total > 0 {
            lines.push(String::new());
            lines.push(format!("  {} Use {} to save hash lines for cracking.",
                s().dim().paint("*"),
                s().cyan().paint("/export eap")));
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
    use crate::attacks::eap::EapAttackMode;
    use crate::core::MacAddress;
    #[test]
    fn test_phase_labels() {
        assert_eq!(phase_label(EapPhase::Idle), "idle");
        assert_eq!(phase_label(EapPhase::Listening), "listening");
        assert_eq!(phase_label(EapPhase::Active), "active");
        assert_eq!(phase_label(EapPhase::Done), "done");
    }

    #[test]
    fn test_render_empty_info() {
        let info = EapInfo::default();
        let lines = render_eap_view(&info, 80);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_format_rogue_ap_started() {
        let event = EapEvent {
            seq: 1,
            timestamp: Duration::from_millis(100),
            kind: EapEventKind::RogueApStarted {
                bssid: MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]),
                ssid: "CorpWiFi".to_string(),
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("AP"));
        assert!(formatted.contains("CorpWiFi"));
    }

    #[test]
    fn test_format_credential_captured() {
        let event = EapEvent {
            seq: 5,
            timestamp: Duration::from_secs(15),
            kind: EapEventKind::MsChapV2Captured {
                mac: MacAddress::new([0xA4, 0x83, 0xE7, 0x12, 0x34, 0x56]),
                identity: "user@corp.com".to_string(),
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("CRED!"));
        assert!(formatted.contains("user@corp.com"));
    }

    #[test]
    fn test_format_gtc_plaintext() {
        let event = EapEvent {
            seq: 6,
            timestamp: Duration::from_secs(20),
            kind: EapEventKind::GtcCaptured {
                mac: MacAddress::new([0xA4, 0x83, 0xE7, 0x12, 0x34, 0x56]),
                identity: "admin".to_string(),
                password: "P@ssw0rd!".to_string(),
            },
        };
        let formatted = format_event(&event);
        assert!(formatted.contains("GTC"));
        assert!(formatted.contains("P@ssw0rd!"));
    }

    #[test]
    fn test_status_segments_idle() {
        let info = EapInfo::default();
        let segs = status_segments(&info);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_status_segments_running() {
        let mut info = EapInfo::default();
        info.running = true;
        info.phase = EapPhase::Active;
        info.mode = EapAttackMode::EvilTwin;
        info.ssid = "CorpWiFi".to_string();
        info.credentials_total = 3;
        info.clients_total = 5;
        let segs = status_segments(&info);
        assert!(segs.len() >= 3);
    }
}
