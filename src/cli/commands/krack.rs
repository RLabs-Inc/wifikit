//! KRACK key reinstallation attack command: /krack [target] [--variant <name>]

use crate::attacks::krack::{KrackParams, KrackVariant};
use crate::cli::views::krack as krack_cli;
use super::{Ctx, Mode};

/// /krack [target] [--variant <name>] | /krack stop
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // Check for active attack first — handle stop inline
    {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.focus_stack.has_active_attack() {
            if args == "stop" {
                state.focus_stack.stop_active_attack();
                drop(state);
                ctx.layout.print(&format!("  {} Stopping KRACK attack...",
                    prism::s().dim().paint("\u{25cf}")));
                return;
            }
            drop(state);
            ctx.layout.print(&format!("  {} Attack already running. Use {} to stop.",
                prism::s().dim().paint("\u{25cf}"),
                prism::s().cyan().paint("/krack stop")));
            return;
        }
    }

    // Need scanner running
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // Parse args: [target] [--variant <name>]
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut target_arg = String::new();
    let mut variant_filter: Option<KrackVariant> = None;

    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "--variant" | "-v" => {
                if i + 1 < parts.len() {
                    match KrackVariant::from_str(parts[i + 1]) {
                        Some(v) => variant_filter = Some(v),
                        None => {
                            ctx.layout.print(&format!("  {} Unknown variant: {}. Try: ptk, gtk, igtk, group-gtk, group-igtk, ft, peerkey, tdls, wnm-gtk, wnm-igtk, zeroed-tk",
                                prism::s().red().paint("!"), parts[i + 1]));
                            return;
                        }
                    }
                    i += 2;
                } else {
                    ctx.layout.print(&format!("  {} --variant requires a name",
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
            ctx.layout.print(&format!("  {} KRACK requires a single target AP.",
                prism::s().red().paint("!")));
            return;
        }
        Err("no_aps") => {
            ctx.layout.print(&format!("  {} No APs discovered yet.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }
        Err("ap_not_found") => {
            ctx.layout.print(&format!("  {} Target not found in scan results.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }
        Err(_) => {
            ctx.layout.print(&format!("  {} Scanner not running. Start with {} first.",
                prism::s().yellow().paint("\u{26a0}"),
                prism::s().cyan().paint("/scan")));
            return;
        }
    };

    let mut params = KrackParams::default();
    params.variant = variant_filter;

    let variant_count = match params.variant {
        Some(_) => 1,
        None => KrackVariant::all().len(),
    };
    let variant_desc = match &params.variant {
        Some(v) => format!("{} ({})", v.cve(), v.label()),
        None => format!("all {} variants", variant_count),
    };
    ctx.layout.print(&format!("  {} KRACK \u{2192} {}  {}  ch{}  [{}]",
        prism::s().cyan().paint("\u{25b6}"),
        prism::s().bold().paint(&target.ssid),
        prism::s().dim().paint(&target.bssid.to_string()),
        target.channel, variant_desc));

    // Select adapter for attack (prompt if multiple)
    let attack_adapter = match ctx.select_adapter_for_attack("KRACK attack") {
        Some(a) => a,
        None => return,
    };

    let krack_module = krack_cli::KrackModule::new(params);
    krack_module.attack().start(attack_adapter, target);

    ctx.layout.print(&format!("  {} Attack started. {} to stop.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/krack stop")));
    ctx.layout.print("");

    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(krack_module));
        state.mode = Mode::Normal;
    }
}
