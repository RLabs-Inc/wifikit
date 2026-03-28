//! Attack control command: /attack [stop]

use crate::cli::module::ModuleType;
use super::Ctx;

/// /attack [stop|stop all]
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();
    match args {
        "stop" | "stop all" => {
            let stopped = {
                let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
                state.focus_stack.stop_active_attack().map(|n| n.to_string())
            };
            if let Some(name) = stopped {
                ctx.layout.print(&format!("  {} Stopping {} attack...",
                    prism::s().dim().paint("\u{25cf}"), name));
            } else {
                ctx.layout.print(&format!("  {} No attack running.",
                    prism::s().dim().paint("\u{25cf}")));
            }
        }
        "" => {
            let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.focus_stack.has_active_attack() {
                let name = state.focus_stack.all().iter()
                    .find(|m| m.module_type() == ModuleType::Attack && !m.is_done())
                    .map(|m| m.name().to_string())
                    .unwrap_or_default();
                drop(state);
                ctx.layout.print(&format!("  {} Active: {}",
                    prism::s().green().paint("\u{25cf}"), name));
                ctx.layout.print(&format!("  Use {} to stop.",
                    prism::s().cyan().paint("/attack stop")));
            } else {
                drop(state);
                ctx.layout.print(&format!("  {} No attack running.",
                    prism::s().dim().paint("\u{25cf}")));
            }
        }
        _ => {
            ctx.layout.print(&format!("  {} Unknown subcommand: {}. Use {}",
                prism::s().red().paint("!"), args,
                prism::s().cyan().paint("/attack stop")));
        }
    }
}
