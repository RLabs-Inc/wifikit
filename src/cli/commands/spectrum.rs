//! Spectrum analyzer command: /spectrum | /spectrum stop
//!
//! Launches the spectrum analyzer as an independent module on its own adapter.
//! Requires a MT7921AU adapter (only chipset with testmode/survey support).
//! Cannot use the same adapter as the scanner.

use crate::adapter::AdapterRole;
use crate::cli::module::Module;
use crate::cli::views::spectrum::SpectrumModule;
use crate::core::chip::ChipId;
use super::{Ctx, Mode};

/// /spectrum | /spectrum stop
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    match args {
        "stop" => stop(ctx),
        "" => start(ctx),
        _ => {
            ctx.layout.print(&format!("  {} Usage: {} or {}",
                prism::s().cyan().paint("?"),
                prism::s().cyan().paint("/spectrum"),
                prism::s().cyan().paint("/spectrum stop")));
        }
    }
}

fn stop(ctx: &mut Ctx) {
    let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(idx) = state.focus_stack.find_by_name("spectrum") {
        state.focus_stack.all()[idx].signal_stop();
        // Wait briefly for thread to exit, then remove
        drop(state);
        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(idx) = state.focus_stack.find_by_name("spectrum") {
            let module = state.focus_stack.remove(idx);
            let summary = module.freeze_summary(prism::term_width());
            drop(state);

            for line in &summary {
                ctx.layout.print(line);
            }
        }
    } else {
        drop(state);
        ctx.layout.print(&format!("  {} Spectrum analyzer not running.",
            prism::s().dim().paint("?")));
    }
}

fn start(ctx: &mut Ctx) {
    // Check if already running
    {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.focus_stack.find_by_name("spectrum").is_some() {
            drop(state);
            ctx.layout.print(&format!("  {} Spectrum analyzer already running. Use {} to stop.",
                prism::s().dim().paint("\u{25cf}"),
                prism::s().cyan().paint("/spectrum stop")));
            return;
        }
    }

    // Find MT7921AU adapters that support testmode (spectrum survey)
    let scanner_idx = ctx.manager.scanner_adapter().map(|(idx, _)| idx);

    let eligible: Vec<(usize, String)> = ctx.manager.adapters()
        .filter(|(i, info, _, _)| {
            // Must be MT7921AU (only chip with survey support)
            info.chip == ChipId::Mt7921au
            // Must not be the scanner's adapter
            && Some(*i) != scanner_idx
        })
        .map(|(i, info, _, _)| (i, info.name.to_string()))
        .collect();

    if eligible.is_empty() {
        // Check if there ARE MT7921 adapters but they're used by scanner
        let mt7921_count = ctx.manager.adapters()
            .filter(|(_, info, _, _)| info.chip == ChipId::Mt7921au)
            .count();

        if mt7921_count > 0 {
            ctx.layout.print(&format!("  {} MT7921AU adapter found but used by scanner.",
                prism::s().yellow().paint("\u{26a0}")));
            ctx.layout.print(&format!("  {} Plug in a second MT7921AU for spectrum analysis,",
                prism::s().dim().paint(" ")));
            ctx.layout.print(&format!("  {} or stop the scanner first with {}.",
                prism::s().dim().paint(" "),
                prism::s().cyan().paint("/scan stop")));
        } else {
            ctx.layout.print(&format!("  {} No MT7921AU adapter found.",
                prism::s().red().paint("!")));
            ctx.layout.print(&format!("  {} Spectrum analyzer requires MT7921AU (testmode support).",
                prism::s().dim().paint(" ")));
            ctx.layout.print(&format!("  {} Other adapters: {}",
                prism::s().dim().paint(" "),
                prism::s().dim().paint("RTL8812AU/BU, RTL8852AU — no survey registers")));
        }
        return;
    }

    // Auto-select if only one eligible, otherwise prompt
    let adapter_idx = if eligible.len() == 1 {
        eligible[0].0
    } else {
        // Build selection with only eligible adapters
        let choices: Vec<&str> = eligible.iter()
            .map(|(_, name)| name.as_str())
            .collect();
        match prism::prompt::select(
            "Select adapter for spectrum analyzer:",
            &choices,
            prism::prompt::SelectOptions::default(),
        ) {
            Ok(selected) => {
                // Find which eligible adapter matches the selected name
                eligible.iter()
                    .find(|(_, name)| name.as_str() == selected)
                    .map(|(idx, _)| *idx)
                    .unwrap_or(eligible[0].0)
            }
            Err(_) => {
                ctx.layout.print(&format!("  {} Cancelled.", prism::s().dim().paint("\u{25cf}")));
                return;
            }
        }
    };

    // Open adapter
    let shared = match ctx.open_adapter(adapter_idx) {
        Some(s) => s,
        None => return,
    };

    // Assign attack role (prevents scanner from using it)
    ctx.manager.assign_role(adapter_idx, AdapterRole::Attack);

    let adapter_name = ctx.manager.adapter_info(adapter_idx)
        .map(|a| a.name.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    ctx.layout.print(&format!("  {} Spectrum analyzer starting on {}",
        prism::s().cyan().paint("\u{25c6}"),
        prism::s().bold().paint(&adapter_name)));
    ctx.layout.print(&format!("  {} MIB survey — real RF utilization per channel",
        prism::s().dim().paint(" ")));
    ctx.layout.print(&format!("  {} Keys: {} cycle mode  {} scroll  {} to stop",
        prism::s().dim().paint(" "),
        prism::s().cyan().paint("m"),
        prism::s().cyan().paint("j/k"),
        prism::s().cyan().paint("/spectrum stop")));

    // Create and start module
    let mut spectrum_module = SpectrumModule::new();
    spectrum_module.start(shared);

    // Push to focus stack
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(spectrum_module));
        state.mode = Mode::Normal;
    }

    ctx.layout.print("");
}
