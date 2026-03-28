//! WiFi fuzzer command: /fuzz [target] [--options]

use crate::attacks::fuzz::{FuzzParams, FuzzDomain, FuzzFrameType, mutation};
use crate::cli::module::Module;
use crate::cli::views::fuzz as fuzz_cli;
use super::{Ctx, Mode};

/// /fuzz [target] [--options] | /fuzz stop | /fuzz resume
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // /fuzz stop -> stop active fuzzer
    if args == "stop" {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(fuzz_mod) = state.focus_stack.find_as::<fuzz_cli::FuzzModule>("fuzz") {
            fuzz_mod.attack().signal_stop();
            drop(state);
            ctx.layout.print(&format!("  {} Stopping fuzzer...",
                prism::s().dim().paint("\u{25cf}")));
        } else {
            drop(state);
            ctx.layout.print(&format!("  {} No fuzzer running.",
                prism::s().dim().paint("\u{25cf}")));
        }
        return;
    }

    // /fuzz resume -> resume paused fuzzer
    if args == "resume" {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(fuzz_mod) = state.focus_stack.find_as::<fuzz_cli::FuzzModule>("fuzz") {
            fuzz_mod.attack().resume();
            drop(state);
            ctx.layout.print(&format!("  {} Fuzzer resumed.",
                prism::s().green().paint("\u{25cf}")));
        } else {
            drop(state);
            ctx.layout.print(&format!("  {} No fuzzer running.",
                prism::s().dim().paint("\u{25cf}")));
        }
        return;
    }

    // /fuzz (no args) -> show help
    if args.is_empty() {
        ctx.layout.print(&format!("  {} Usage: {} [target] [--options]",
            prism::s().cyan().paint("?"),
            prism::s().cyan().paint("/fuzz")));
        ctx.layout.print(&format!("  {}", prism::s().dim().paint("Options:")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<24}", "--domain <dom>")),
            prism::s().dim().paint("frame, ie, eap, all (default: frame)")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<24}", "--frame <type>")),
            prism::s().dim().paint("beacon, probe, auth, assoc, deauth, action, eap, all")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<24}", "--seed <n>")),
            prism::s().dim().paint("RNG seed for reproducible fuzzing (0 = random)")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<24}", "--max <n>")),
            prism::s().dim().paint("Max iterations (0 = unlimited)")));
        ctx.layout.print(&format!("    {}  {}",
            prism::s().cyan().bold().paint(&format!("{:<24}", "--no-pause")),
            prism::s().dim().paint("Don't pause on crash (continue fuzzing)")));
        ctx.layout.print(&format!("  {} Targets selected AP or specify BSSID/SSID.",
            prism::s().dim().paint(" ")));
        ctx.layout.print(&format!("  {} Commands: {} (stop), {} (resume after crash pause)",
            prism::s().dim().paint(" "),
            prism::s().cyan().paint("/fuzz stop"),
            prism::s().cyan().paint("/fuzz resume")));
        return;
    }

    // Check if an attack is already running
    if !ctx.require_no_attack() { return; }

    // Parse args: extract --flags and target
    let mut domain = FuzzDomain::Frame;
    let mut frame_type = FuzzFrameType::All;
    let mut seed: u32 = 0;
    let mut max_iterations: u64 = 0;
    let mut pause_on_crash = true;
    let mut target_arg = String::new();

    let tokens: Vec<&str> = args.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "--domain" | "-d" => {
                if i + 1 < tokens.len() {
                    domain = match tokens[i + 1].to_lowercase().as_str() {
                        "frame" => FuzzDomain::Frame,
                        "ie" => FuzzDomain::Ie,
                        "eap" => FuzzDomain::Eap,
                        "all" => FuzzDomain::All,
                        _ => {
                            ctx.layout.print(&format!("  {} Unknown domain: {}. Use frame, ie, eap, or all.",
                                prism::s().red().paint("!"), tokens[i + 1]));
                            return;
                        }
                    };
                    i += 2;
                } else { i += 1; }
            }
            "--frame" | "-f" => {
                if i + 1 < tokens.len() {
                    frame_type = match FuzzFrameType::from_str(tokens[i + 1]) {
                        Some(ft) => ft,
                        None => {
                            ctx.layout.print(&format!("  {} Unknown frame type: {}.",
                                prism::s().red().paint("!"), tokens[i + 1]));
                            return;
                        }
                    };
                    i += 2;
                } else { i += 1; }
            }
            "--seed" | "-s" => {
                if i + 1 < tokens.len() {
                    seed = if tokens[i + 1].starts_with("0x") {
                        u32::from_str_radix(&tokens[i + 1][2..], 16).unwrap_or(0)
                    } else {
                        tokens[i + 1].parse().unwrap_or(0)
                    };
                    i += 2;
                } else { i += 1; }
            }
            "--max" | "-m" => {
                if i + 1 < tokens.len() {
                    max_iterations = tokens[i + 1].parse().unwrap_or(0);
                    i += 2;
                } else { i += 1; }
            }
            "--no-pause" => {
                pause_on_crash = false;
                i += 1;
            }
            _ => {
                if target_arg.is_empty() {
                    target_arg = tokens[i].to_string();
                }
                i += 1;
            }
        }
    }

    // Need scanner running
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // Resolve target AP
    let target_ap = match ctx.resolve_target(&target_arg) {
        Ok(Some(ap)) => ap,
        Ok(None) => {
            ctx.layout.print(&format!("  {} Fuzz requires a single target AP.",
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
                prism::s().red().paint("!"), &target_arg));
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
    let params = FuzzParams {
        domain,
        frame_type,
        seed,
        max_iterations,
        pause_on_crash,
        mutations: mutation::ALL,
        ..Default::default()
    };

    // Print start message
    let seed_str = if seed == 0 {
        "random".to_string()
    } else {
        format!("0x{:08X}", seed)
    };
    ctx.layout.print(&format!("  {} FUZZ \u{2192} {}  {}  ch{}  seed={}  domain={}",
        prism::s().yellow().bold().paint("\u{25b6}"),
        prism::s().bold().paint(&target_ap.ssid),
        prism::s().dim().paint(&target_ap.bssid.to_string()),
        target_ap.channel,
        prism::s().cyan().paint(&seed_str),
        prism::s().cyan().paint(domain.label())));

    // Select adapter for attack (prompt if multiple)
    let attack_adapter = match ctx.select_adapter_for_attack("Fuzz attack") {
        Some(a) => a,
        None => return,
    };

    // Create Fuzz module and start
    let mut fuzz_module = fuzz_cli::FuzzModule::new(params);
    fuzz_module.set_target(target_ap);
    fuzz_module.start(attack_adapter);

    ctx.layout.print(&format!("  {} Fuzzer started. {} to stop, {} to resume after crash.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/fuzz stop"),
        prism::s().cyan().paint("/fuzz resume")));
    ctx.layout.print("");

    // Push to focus stack
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(fuzz_module));
        state.mode = Mode::Normal;
    }
}
