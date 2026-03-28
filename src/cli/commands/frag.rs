//! FragAttacks vulnerability test command: /frag [target] [--variant <name>] [--stop-first]

use crate::attacks::frag::{FragParams, FragVariant};
use crate::cli::views::frag::FragModule;
use super::{Ctx, Mode};

/// /frag [target] [--variant <name>] [--stop-first] | /frag stop
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // Check if an attack is already running
    {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.focus_stack.has_active_attack() {
            if args == "stop" {
                state.focus_stack.stop_active_attack();
                drop(state);
                ctx.layout.print(&format!("  {} Stopping FragAttacks...",
                    prism::s().dim().paint("\u{25cf}")));
                return;
            }
            drop(state);
            ctx.layout.print(&format!("  {} Attack already running. Use {} to stop.",
                prism::s().dim().paint("\u{25cf}"),
                prism::s().cyan().paint("/frag stop")));
            return;
        }
    }

    // Need scanner running
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // Parse args: [target] [--variant <name>] [--stop-first]
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut target_arg = String::new();
    let mut variant_filter: Option<FragVariant> = None;
    let mut stop_on_first = false;

    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "--variant" | "-v" => {
                if i + 1 < parts.len() {
                    match FragVariant::from_str(parts[i + 1]) {
                        Some(v) => variant_filter = Some(v),
                        None => {
                            ctx.layout.print(&format!("  {} Unknown variant: {}. Try: amsdu, mixed-key, cache, plaintext, plaintext-frag, broadcast, eapol-amsdu, eapol-fwd, tkip-mic, frag-full, noncons-pn, mixed-enc",
                                prism::s().red().paint("!"), parts[i + 1]));
                            return;
                        }
                    }
                    i += 2;
                } else {
                    ctx.layout.print(&format!("  {} --variant requires a name (e.g., plaintext, amsdu, 26140)",
                        prism::s().red().paint("!")));
                    return;
                }
            }
            "--stop-first" | "--stop-on-first" => {
                stop_on_first = true;
                i += 1;
            }
            _ => {
                if target_arg.is_empty() {
                    target_arg = parts[i].to_string();
                }
                i += 1;
            }
        }
    }

    // Resolve target AP
    let target = match ctx.resolve_target(&target_arg) {
        Ok(Some(ap)) => ap,
        Ok(None) => {
            ctx.layout.print(&format!("  {} Target not found in scan results.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }
        Err("no_aps") => {
            ctx.layout.print(&format!("  {} No APs discovered yet. Wait for scan results.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }
        Err(_) => {
            ctx.layout.print(&format!("  {} Target not found in scan results.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }
    };

    // Build params
    let mut params = FragParams::default();
    params.variant = variant_filter;
    params.stop_on_first_vuln = stop_on_first;

    // Count how many variants will run
    let variant_count = match params.variant {
        Some(_) => 1,
        None => FragVariant::all().len(),
    };

    // Print attack start message
    let variant_desc = match &params.variant {
        Some(v) => format!("{} ({})", v.cve(), v.label()),
        None => format!("all {} CVEs", variant_count),
    };
    ctx.layout.print(&format!("  {} FragAttacks \u{2192} {}  {}  ch{}  [{}]",
        prism::s().cyan().paint("\u{25b6}"),
        prism::s().bold().paint(&target.ssid),
        prism::s().dim().paint(&target.bssid.to_string()),
        target.channel,
        variant_desc));

    // Select adapter for attack
    let attack_adapter = match ctx.select_adapter_for_attack("FragAttacks") {
        Some(a) => a,
        None => return,
    };

    // Create FragModule and start
    let frag_module = FragModule::new(params);
    frag_module.attack().start(attack_adapter, target);

    ctx.layout.print(&format!("  {} Test suite started. {} to stop.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/frag stop")));
    ctx.layout.print("");

    // Push to focus stack
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(frag_module));
        state.mode = Mode::Normal;
    }
}
