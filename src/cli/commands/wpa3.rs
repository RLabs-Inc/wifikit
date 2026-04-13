//! WPA3/Dragonblood attack command: /wpa3 [target] [--mode <mode>]

use crate::attacks::wpa3::{Wpa3Mode, Wpa3Params};
use crate::cli::views::wpa3::Wpa3Module;
use super::{Ctx, Mode};

/// /wpa3 [target] [--mode <mode>] | /wpa3 stop
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // /wpa3 stop
    {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.focus_stack.has_active_attack() {
            if args == "stop" {
                state.focus_stack.stop_active_attack();
                drop(state);
                ctx.layout.print(&format!("  {} Stopping WPA3 attack...",
                    prism::s().dim().paint("\u{25cf}")));
                return;
            }
            drop(state);
            ctx.layout.print(&format!("  {} Attack already running. Use {} to stop.",
                prism::s().dim().paint("\u{25cf}"),
                prism::s().cyan().paint("/wpa3 stop")));
            return;
        }
    }

    // Need scanner
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // Parse args: [target] [--mode <name>]
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut target_arg = String::new();
    let mut mode_filter: Option<Wpa3Mode> = None;
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "--mode" | "-m" | "--variant" | "-v" => {
                if i + 1 < parts.len() {
                    match Wpa3Mode::from_str(parts[i + 1]) {
                        Some(m) => mode_filter = Some(m),
                        None => {
                            ctx.layout.print(&format!("  {} Unknown mode: {}. Try: timing, group-downgrade, flood, invalid-curve, reflection, token-replay, full",
                                prism::s().red().paint("!"), parts[i + 1]));
                            return;
                        }
                    }
                    i += 2;
                } else {
                    ctx.layout.print(&format!("  {} --mode requires a name",
                        prism::s().red().paint("!")));
                    return;
                }
            }
            _ => {
                if target_arg.is_empty() { target_arg = parts[i].to_string(); }
                i += 1;
            }
        }
    }

    // Resolve target AP
    let target = match ctx.resolve_target(&target_arg) {
        Ok(Some(ap)) => ap,
        Ok(None) => {
            ctx.layout.print(&format!("  {} Target not found.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }
        Err("no_aps") => {
            ctx.layout.print(&format!("  {} No APs yet.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }
        Err(_) => {
            ctx.layout.print(&format!("  {} Target not found.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }
    };

    // Build params
    let mut params = Wpa3Params::default();
    if let Some(m) = mode_filter { params.mode = m; }

    let mode_desc = match &mode_filter {
        Some(m) => format!("{} ({})", m.cve(), m.label()),
        None => "full Dragonblood scan (7 tests)".to_string(),
    };
    ctx.layout.print(&format!("  {} WPA3/Dragonblood \u{2192} {}  {}  ch{}  [{}]",
        prism::s().cyan().paint("\u{25b6}"),
        prism::s().bold().paint(&target.ssid),
        prism::s().dim().paint(&target.bssid.to_string()),
        target.channel,
        mode_desc));

    // Select adapter for attack
    let attack_adapter = match ctx.select_adapter_for_attack("WPA3 attack") {
        Some(a) => a,
        None => return,
    };

    let mut wpa3_module = Wpa3Module::new(params);
    wpa3_module.subscribe(&attack_adapter);
    wpa3_module.attack().start(attack_adapter, target);
    ctx.layout.print(&format!("  {} Attack started. {} to stop.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/wpa3 stop")));
    ctx.layout.print("");
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(wpa3_module));
        state.mode = Mode::Normal;
    }
}
