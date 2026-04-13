//! PMKID attack command: /pmkid [target|--all|stop]

use crate::attacks::pmkid::{PmkidParams, filter_eligible_targets};
use crate::cli::views::pmkid::PmkidModule;
use super::{Ctx, Mode};

/// /pmkid [target|--all|stop]
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // /pmkid stop → stop active attack
    if args == "stop" {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.focus_stack.has_active_attack() {
            state.focus_stack.stop_active_attack();
            drop(state);
            ctx.layout.print(&format!("  {} Stopping PMKID attack...",
                prism::s().dim().paint("\u{25cf}")));
        } else {
            drop(state);
            ctx.layout.print(&format!("  {} No PMKID attack running.",
                prism::s().dim().paint("\u{25cf}")));
        }
        return;
    }

    // Preconditions
    if !ctx.require_no_attack() { return; }
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // Resolve target from args or selected AP
    // resolve_target_or_all returns Some(Some(ap)) for single, Some(None) for --all, None on error
    let target = match ctx.resolve_target_or_all(args) {
        Some(t) => t,
        None => return,
    };

    // Build params
    let mut params = PmkidParams::default();

    // Determine targets from scanner data — no internal scan needed!
    // The scanner is already running and has discovered APs.
    let aps: Vec<_> = ctx.store.get_aps().into_values().collect();
    let targets = match &target {
        Some(ap) => {
            params.bssid = Some(ap.bssid);
            params.ssid = Some(ap.ssid.clone());
            vec![ap.clone()]
        }
        None => {
            params.attack_all = true;
            params.auth_retries = 2;
            params.assoc_retries = 2;
            filter_eligible_targets(&aps, &params)
        }
    };

    if targets.is_empty() {
        ctx.layout.print(&format!("  {} No eligible targets found for PMKID attack.",
            prism::s().yellow().paint("\u{26a0}")));
        return;
    }

    // Print attack start message
    if target.is_some() {
        let t = &targets[0];
        ctx.layout.print(&format!("  {} PMKID attack \u{2192} {}  {}  ch{}",
            prism::s().cyan().paint("\u{25b6}"),
            prism::s().bold().paint(&t.ssid),
            prism::s().dim().paint(&t.bssid.to_string()),
            t.channel));
    } else {
        ctx.layout.print(&format!("  {} PMKID attack \u{2192} {} eligible APs",
            prism::s().cyan().paint("\u{25b6}"),
            targets.len()));
    }

    // Select adapter for attack (prompt if multiple)
    let attack_adapter = match ctx.select_adapter_for_attack("PMKID attack") {
        Some(a) => a,
        None => return,
    };

    // Create PMKID module and start via SharedAdapter.
    // Scanner keeps running — the attack locks channels as needed.
    let mut pmkid_module = PmkidModule::new(params);
    pmkid_module.subscribe(&attack_adapter);  // subscribe BEFORE starting so we catch AttackStarted
    pmkid_module.attack().start(attack_adapter, targets);

    ctx.layout.print(&format!("  {} Attack started. Scanner continues on locked channel. {} to stop.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/pmkid stop")));
    ctx.layout.print("");

    // Push to focus stack (becomes focused)
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(pmkid_module));
        state.mode = Mode::Normal;
    }
}
