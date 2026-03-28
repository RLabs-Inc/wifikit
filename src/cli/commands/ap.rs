//! Rogue AP / Evil Twin / KARMA command: /ap [mode] [target]

use crate::attacks::ap::{ApParams, ApMode};
use crate::cli::module::Module;
use crate::cli::views::ap::ApModule;
use super::{Ctx, Mode};

/// /ap [mode] [target] | /ap stop
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // /ap stop
    if args == "stop" {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ap_mod) = state.focus_stack.find_as::<ApModule>("ap") {
            ap_mod.attack().signal_stop();
            drop(state);
            ctx.layout.print(&format!("  {} Stopping AP attack...",
                prism::s().dim().paint("\u{25cf}")));
        } else {
            drop(state);
            ctx.layout.print(&format!("  {} No AP attack running.",
                prism::s().dim().paint("\u{25cf}")));
        }
        return;
    }

    // /ap (no args) -> show help
    if args.is_empty() {
        ctx.layout.print(&format!("  {} Usage: {} [mode] [target]",
            prism::s().cyan().paint("?"),
            prism::s().cyan().paint("/ap")));
        ctx.layout.print(&format!("  {}", prism::s().dim().paint("Available modes:")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "evil-twin")),
            prism::s().dim().paint("Clone target AP as open, deauth real AP")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "karma")),
            prism::s().dim().paint("Respond to ALL probe requests")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "mana")),
            prism::s().dim().paint("KARMA + broadcast collected SSIDs")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "known-beacons")),
            prism::s().dim().paint("Broadcast common SSIDs (like mdk4)")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "normal")),
            prism::s().dim().paint("Simple open AP with a fixed SSID")));
        ctx.layout.print(&format!("  {} Default: evil-twin (targets selected AP)",
            prism::s().dim().paint(" ")));
        return;
    }

    // Check no attack already running
    if !ctx.require_no_attack() { return; }

    // Parse: optional mode + optional target
    let tokens: Vec<&str> = args.split_whitespace().collect();
    let (ap_mode, target_start_idx) = match tokens[0].to_lowercase().as_str() {
        "evil-twin" | "eviltwin" | "twin" => (ApMode::EvilTwin, 1),
        "karma" => (ApMode::Karma, 1),
        "mana" | "mana-loud" | "manaloud" => (ApMode::ManaLoud, 1),
        "known-beacons" | "knownbeacons" | "beacons" => (ApMode::KnownBeacons, 1),
        "normal" | "open" => (ApMode::Normal, 1),
        _ => (ApMode::EvilTwin, 0), // No mode given, treat as target
    };

    let target_arg = if target_start_idx < tokens.len() {
        tokens[target_start_idx..].join(" ")
    } else {
        String::new()
    };

    // Modes that need a target AP
    let needs_target = ap_mode == ApMode::EvilTwin;

    // KARMA/MANA/KnownBeacons/Normal don't need scanner
    if needs_target || !target_arg.is_empty() {
        if !ctx.require_scanner() { return; }
    }

    if !ctx.require_adapter() { return; }

    // Resolve target AP (if needed)
    let target_ap: Option<crate::store::Ap> = if needs_target || !target_arg.is_empty() {
        let aps: Vec<crate::store::Ap> = ctx.store.get_aps().into_values().collect();

        if aps.is_empty() && needs_target {
            ctx.layout.print(&format!("  {} No APs discovered yet. Wait for scan results.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }

        if target_arg.is_empty() {
            // Use selected AP via resolve_target
            match ctx.resolve_target("") {
                Ok(Some(ap)) => Some(ap),
                Ok(None) => None,
                Err("no_aps") => {
                    ctx.layout.print(&format!("  {} No APs discovered yet. Wait for scan results.",
                        prism::s().yellow().paint("\u{26a0}")));
                    return;
                }
                Err(_) => {
                    ctx.layout.print(&format!("  {} Scanner not running. Start with {} first.",
                        prism::s().yellow().paint("\u{26a0}"),
                        prism::s().cyan().paint("/scan")));
                    return;
                }
            }
        } else {
            // Search by SSID or BSSID
            let found = aps.iter().find(|ap| {
                ap.ssid.eq_ignore_ascii_case(&target_arg)
                    || ap.bssid.to_string() == target_arg
            });
            match found {
                Some(ap) => Some(ap.clone()),
                None => {
                    ctx.layout.print(&format!("  {} AP not found: {}",
                        prism::s().red().paint("!"), target_arg));
                    return;
                }
            }
        }
    } else {
        None
    };

    let mut params = ApParams::default();
    params.mode = ap_mode;

    // Create and start
    let mut ap_module = ApModule::new(params);
    if let Some(target) = &target_ap {
        ap_module.set_target(target.clone());
    }

    let target_desc = if let Some(t) = &target_ap {
        format!("{} ({})", t.ssid, t.bssid)
    } else {
        format!("{} mode", ap_mode.name())
    };

    ctx.layout.print(&format!("  {} Starting {} AP: {}",
        prism::s().red().bold().paint("\u{25cf}"),
        ap_mode.name(),
        prism::s().bold().paint(&target_desc)));

    // Select adapter for attack
    let attack_adapter = match ctx.select_adapter_for_attack("Rogue AP") {
        Some(a) => a,
        None => return,
    };

    ap_module.start(attack_adapter);
    ctx.layout.print(&format!("  {} Attack started. {} to stop.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/ap stop")));
    ctx.layout.print("");
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(ap_module));
        state.mode = Mode::Normal;
    }
}
