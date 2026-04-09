//! WPS attack command: /wps [type] [target|--all] | /wps stop

use crate::attacks::wps::{WpsParams, WpsAttackType, filter_wps_targets};
use crate::cli::module::Module;
use crate::cli::scanner::{ScannerModule, DetailState};
use crate::cli::views::wps::WpsModule;
use crate::core::mac::MacAddress;
use crate::store::Ap;
use super::{Ctx, Mode};

/// /wps [type] [target|--all] | /wps stop
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // /wps stop → stop active attack
    if args == "stop" {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(wps_mod) = state.focus_stack.find_as::<WpsModule>("wps") {
            wps_mod.attack().signal_stop();
            drop(state);
            ctx.layout.print(&format!("  {} Stopping WPS attack...",
                prism::s().dim().paint("\u{25cf}")));
        } else {
            drop(state);
            ctx.layout.print(&format!("  {} No WPS attack running.",
                prism::s().dim().paint("\u{25cf}")));
        }
        return;
    }

    // /wps (no args) → show help
    if args.is_empty() {
        ctx.layout.print(&format!("  {} Usage: {} [type] [target]",
            prism::s().cyan().paint("?"),
            prism::s().cyan().paint("/wps")));
        ctx.layout.print(&format!("  {}", prism::s().dim().paint("Available types:")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "auto")),
            prism::s().dim().paint("Smart chain: computed PINs → Pixie Dust → Null PIN")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "pins")),
            prism::s().dim().paint("Computed PIN — try vendor-specific algorithms only")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "pixie")),
            prism::s().dim().paint("Pixie Dust — offline crack via weak nonces")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "brute")),
            prism::s().dim().paint("Brute Force — online PIN iteration (11K attempts max)")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<20}", "null-pin")),
            prism::s().dim().paint("Null PIN — try 00000000 (single attempt)")));
        ctx.layout.print(&format!("  {} Default: auto. Keys: {} skip attack  {} skip target",
            prism::s().dim().paint(" "),
            prism::s().cyan().paint("[s]"),
            prism::s().cyan().paint("[n]")));
        return;
    }

    // Preconditions
    if !ctx.require_no_attack() { return; }

    // Parse: optional type + optional target/--all
    let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
    let (wps_type, target_arg) = match parts[0].to_lowercase().as_str() {
        "auto" => (WpsAttackType::Auto, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        "pins" | "computed" | "pin-gen" => (WpsAttackType::ComputedPin, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        "pixie" | "pixie-dust" => (WpsAttackType::PixieDust, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        "brute" | "brute-force" => (WpsAttackType::BruteForce, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        "null" | "null-pin" => (WpsAttackType::NullPin, parts.get(1).map(|s| s.trim()).unwrap_or("")),
        "--all" | "-a" => (WpsAttackType::Auto, "--all"),
        _ => (WpsAttackType::Auto, args), // No type given, default to Auto
    };
    let is_all = target_arg == "--all" || target_arg == "-a";

    // Need scanner running + adapter
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // Resolve targets
    let targets = {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        let scanner_mod = match state.focus_stack.find_as::<ScannerModule>("scanner") {
            Some(m) => m,
            None => return,
        };
        let aps: Vec<Ap> = ctx.store.get_aps().into_values().collect();

        if aps.is_empty() {
            drop(state);
            ctx.layout.print(&format!("  {} No APs discovered yet. Wait for scan results.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }

        if is_all {
            // --all: filter all WPS-enabled APs
            filter_wps_targets(&aps, -90)
        } else if target_arg.is_empty() || target_arg == "--all" {
            // Use detail view AP or selected row
            if let DetailState::Ap { bssid, .. } = &scanner_mod.detail {
                match aps.iter().find(|ap| &ap.bssid == bssid) {
                    Some(ap) => vec![ap.clone()],
                    None => {
                        drop(state);
                        ctx.layout.print(&format!("  {} AP no longer in scan results.",
                            prism::s().red().paint("!")));
                        return;
                    }
                }
            } else {
                let selected_idx = scanner_mod.selected.min(aps.len().saturating_sub(1));
                vec![aps[selected_idx].clone()]
            }
        } else if target_arg.contains(':') && target_arg.len() == 17 {
            let bytes: std::result::Result<Vec<u8>, _> = target_arg.split(':')
                .map(|h| u8::from_str_radix(h, 16))
                .collect();
            match bytes {
                Ok(b) if b.len() == 6 => {
                    let mac = MacAddress::new([b[0], b[1], b[2], b[3], b[4], b[5]]);
                    match aps.iter().find(|ap| ap.bssid == mac) {
                        Some(ap) => vec![ap.clone()],
                        None => {
                            drop(state);
                            ctx.layout.print(&format!("  {} AP not found: {}",
                                prism::s().red().paint("!"), target_arg));
                            return;
                        }
                    }
                }
                _ => {
                    match aps.iter().find(|ap| ap.ssid == target_arg) {
                        Some(ap) => vec![ap.clone()],
                        None => {
                            drop(state);
                            ctx.layout.print(&format!("  {} AP not found: {}",
                                prism::s().red().paint("!"), target_arg));
                            return;
                        }
                    }
                }
            }
        } else {
            match aps.iter().find(|ap| ap.ssid == target_arg) {
                Some(ap) => vec![ap.clone()],
                None => {
                    drop(state);
                    ctx.layout.print(&format!("  {} AP not found: {}",
                        prism::s().red().paint("!"), target_arg));
                    return;
                }
            }
        }
    };

    if targets.is_empty() {
        ctx.layout.print(&format!("  {} No WPS-enabled APs found.",
            prism::s().yellow().paint("\u{26a0}")));
        return;
    }

    // Build params
    let params = WpsParams {
        attack_type: wps_type,
        ..Default::default()
    };

    // Print start message
    if targets.len() == 1 {
        ctx.layout.print(&format!("  {} WPS {} \u{2192} {}  {}  ch{}",
            prism::s().magenta().paint("\u{25b6}"),
            prism::s().cyan().bold().paint(wps_type.name()),
            prism::s().bold().paint(&targets[0].ssid),
            prism::s().dim().paint(&targets[0].bssid.to_string()),
            targets[0].channel));
    } else {
        ctx.layout.print(&format!("  {} WPS {} \u{2192} {} WPS-enabled APs",
            prism::s().magenta().paint("\u{25b6}"),
            prism::s().cyan().bold().paint(wps_type.name()),
            targets.len()));
    }

    // Select adapter for attack (prompt if multiple)
    let attack_adapter = match ctx.select_adapter_for_attack("WPS attack") {
        Some(a) => a,
        None => return,
    };

    // Create WPS module and start
    let mut wps_module = WpsModule::new(params);
    wps_module.set_targets(targets);
    wps_module.start(attack_adapter);

    ctx.layout.print(&format!("  {} Attack started. Scanner continues on locked channel. {} to stop.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/wps stop")));
    ctx.layout.print("");

    // Push to focus stack
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(wps_module));
        state.mode = Mode::Normal;
    }
}
