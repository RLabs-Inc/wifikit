//! View switching command: /view [aps|clients|probes|channels|events|handshakes]

use crate::cli::scanner::ScannerModule;
use super::Ctx;

/// /view [aps|clients|probes|channels|events|handshakes]
pub fn run(ctx: &mut Ctx, args: &str) {
    let msg = {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(module) = state.focus_stack.find_as_mut::<ScannerModule>("scanner") {
            let view_name = args.trim().to_lowercase();
            match view_name.as_str() {
                "aps" | "ap" => {
                    module.view = crate::cli::scanner::ScanView::Aps;
                    module.detail = crate::cli::scanner::DetailState::None;
                    module.selected = 0;
                    None
                }
                "clients" | "client" | "stations" | "stas" => {
                    module.view = crate::cli::scanner::ScanView::Clients;
                    module.detail = crate::cli::scanner::DetailState::None;
                    module.selected = 0;
                    None
                }
                "probes" | "probe" => {
                    module.view = crate::cli::scanner::ScanView::Probes;
                    module.detail = crate::cli::scanner::DetailState::None;
                    module.selected = 0;
                    None
                }
                "channels" | "channel" | "ch" => {
                    module.view = crate::cli::scanner::ScanView::Channels;
                    module.detail = crate::cli::scanner::DetailState::None;
                    module.selected = 0;
                    None
                }
                "events" | "event" => {
                    module.view = crate::cli::scanner::ScanView::Events;
                    module.detail = crate::cli::scanner::DetailState::None;
                    module.selected = 0;
                    None
                }
                "handshakes" | "handshake" | "hs" => {
                    module.view = crate::cli::scanner::ScanView::Handshakes;
                    module.detail = crate::cli::scanner::DetailState::None;
                    module.selected = 0;
                    None
                }
                _ => {
                    Some(format!("  {} Unknown view: {}. Options: aps, clients, probes, channels, events, handshakes",
                        prism::s().red().paint("!"), view_name))
                }
            }
        } else {
            Some(format!("  {} Scanner not running. Start with {}.",
                prism::s().dim().paint("?"),
                prism::s().cyan().paint("/scan")))
        }
    };

    if let Some(msg) = msg {
        ctx.layout.print(&msg);
    }
}
