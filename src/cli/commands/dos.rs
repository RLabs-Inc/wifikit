//! DoS attack command: /dos [type] [target] | /dos stop
//! Deauth shortcut:    /deauth [target|@client] | /deauth stop

use std::time::Duration;

use crate::attacks::dos::{DosParams, DosType};
use crate::cli::module::Module;
use crate::cli::scanner::{ScannerModule, DetailState};
use crate::cli::views::dos::DosModule;
use crate::core::mac::MacAddress;
use crate::store::Ap;
use super::{Ctx, Mode};

/// /dos [type] [target] | /dos stop
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // /dos stop → stop active attack
    if args == "stop" {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dos_mod) = state.focus_stack.find_as::<DosModule>("dos") {
            dos_mod.attack().signal_stop();
            drop(state);
            ctx.layout.print(&format!("  {} Stopping DoS attack...",
                prism::s().dim().paint("\u{25cf}")));
        } else {
            drop(state);
            ctx.layout.print(&format!("  {} No DoS attack running.",
                prism::s().dim().paint("\u{25cf}")));
        }
        return;
    }

    // /dos (no args) → show help
    if args.is_empty() {
        ctx.layout.print(&format!("  {} Usage: {} <type> [target]",
            prism::s().cyan().paint("?"),
            prism::s().cyan().paint("/dos")));
        ctx.layout.print(&format!("  {}", prism::s().dim().paint("Available types:")));
        for t in DosType::all() {
            ctx.layout.print(&format!("    {}  {}",
                prism::s().cyan().bold().paint(&format!("{:<20}", t.label())),
                prism::s().dim().paint(t.description())));
        }
        return;
    }

    // Preconditions
    if !ctx.require_no_attack() { return; }

    // Parse: first word is the type, rest is the target
    let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
    let type_str = parts[0];
    let target_arg = parts.get(1).map(|s| s.trim()).unwrap_or("");

    let dos_type = match DosType::from_str(type_str) {
        Some(t) => t,
        None => {
            ctx.layout.print(&format!("  {} Unknown DoS type: {}. Use {} for list.",
                prism::s().red().paint("!"),
                prism::s().bold().paint(type_str),
                prism::s().cyan().paint("/dos")));
            return;
        }
    };

    // Need scanner running + adapter
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // Resolve target AP
    let (target_ap, target_station) = {
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

        let ap = if target_arg.is_empty() {
            // If drilled into AP detail, use that AP (not selected row which shifts)
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
        } else if target_arg.contains(':') && target_arg.len() == 17 {
            // BSSID
            let bytes: std::result::Result<Vec<u8>, _> = target_arg.split(':')
                .map(|h| u8::from_str_radix(h, 16))
                .collect();
            match bytes {
                Ok(b) if b.len() == 6 => {
                    let mac = MacAddress::new([b[0], b[1], b[2], b[3], b[4], b[5]]);
                    match aps.iter().find(|ap| ap.bssid == mac) {
                        Some(ap) => ap.clone(),
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
                        Some(ap) => ap.clone(),
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
            // SSID
            match aps.iter().find(|ap| ap.ssid == target_arg) {
                Some(ap) => ap.clone(),
                None => {
                    drop(state);
                    ctx.layout.print(&format!("  {} AP not found: {}",
                        prism::s().red().paint("!"), target_arg));
                    return;
                }
            }
        };

        // For targeted attacks, get selected station
        let station = if dos_type.requires_station() {
            let stations = ctx.store.get_stations().into_values().collect::<Vec<_>>();
            let sta = stations.iter()
                .find(|s| s.bssid == Some(ap.bssid) && s.is_associated)
                .cloned();
            if sta.is_none() {
                drop(state);
                ctx.layout.print(&format!("  {} {} requires a connected client. No clients associated with {}.",
                    prism::s().yellow().paint("\u{26a0}"),
                    dos_type.label(),
                    prism::s().bold().paint(&ap.ssid)));
                ctx.layout.print(&format!("  {} Use {} for broadcast variant instead.",
                    prism::s().dim().paint(" "),
                    prism::s().cyan().paint("/dos deauth")));
                return;
            }
            sta
        } else {
            None
        };

        (ap, station)
    };

    start_dos_attack(ctx, dos_type, target_ap, target_station);
}

/// /deauth [target|@client] | /deauth stop — convenience shortcut for deauth attacks.
pub fn deauth(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // /deauth stop → stop active attack
    if args == "stop" {
        run(ctx, "stop");
        return;
    }

    // Preconditions
    if !ctx.require_no_attack() { return; }
    if !ctx.require_scanner() { return; }
    if !ctx.require_adapter() { return; }

    // @client → targeted deauth on selected/specified client
    if args.starts_with('@') {
        // Targeted deauth: resolve client from scanner
        let (target_ap, target_station) = {
            let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
            let _scanner_mod = match state.focus_stack.find_as::<ScannerModule>("scanner") {
                Some(m) => m,
                None => return,
            };
            let aps: Vec<Ap> = ctx.store.get_aps().into_values().collect();
            let stations = ctx.store.get_stations().into_values().collect::<Vec<_>>();

            // Find associated station — use selected row from clients view or first associated
            let sta = stations.iter()
                .find(|s| s.is_associated && s.bssid.is_some())
                .cloned();
            match sta {
                Some(station) => {
                    let ap = aps.iter()
                        .find(|ap| Some(ap.bssid) == station.bssid)
                        .cloned();
                    match ap {
                        Some(ap) => (ap, Some(station)),
                        None => {
                            drop(state);
                            ctx.layout.print(&format!("  {} Client's AP not found in scan results.",
                                prism::s().red().paint("!")));
                            return;
                        }
                    }
                }
                None => {
                    drop(state);
                    ctx.layout.print(&format!("  {} No associated clients found.",
                        prism::s().yellow().paint("\u{26a0}")));
                    return;
                }
            }
        };

        start_dos_attack(ctx, DosType::DeauthTargeted, target_ap, target_station);
        return;
    }

    // /deauth [target] → broadcast deauth (DeauthFlood)
    // Resolve target AP
    let (target_ap, _) = {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        let scanner_mod = match state.focus_stack.find_as::<ScannerModule>("scanner") {
            Some(m) => m,
            None => return,
        };
        let aps: Vec<Ap> = ctx.store.get_aps().into_values().collect();

        if aps.is_empty() {
            drop(state);
            ctx.layout.print(&format!("  {} No APs discovered yet.",
                prism::s().yellow().paint("\u{26a0}")));
            return;
        }

        let ap = if args.is_empty() {
            // If drilled into AP detail, use that AP (not selected row which shifts)
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
            let bytes: std::result::Result<Vec<u8>, _> = args.split(':')
                .map(|h| u8::from_str_radix(h, 16))
                .collect();
            match bytes {
                Ok(b) if b.len() == 6 => {
                    let mac = MacAddress::new([b[0], b[1], b[2], b[3], b[4], b[5]]);
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
            match aps.iter().find(|ap| ap.ssid == args) {
                Some(ap) => ap.clone(),
                None => {
                    drop(state);
                    ctx.layout.print(&format!("  {} AP not found: {}",
                        prism::s().red().paint("!"), args));
                    return;
                }
            }
        };

        (ap, None::<crate::store::Station>)
    };

    start_dos_attack(ctx, DosType::DeauthFlood, target_ap, None);
}

/// Shared DoS attack start logic used by both /dos and /deauth.
fn start_dos_attack(
    ctx: &mut Ctx,
    dos_type: DosType,
    target: Ap,
    station: Option<crate::store::Station>,
) {
    // Smart deauth: burst_count is ignored (smart burst builds its own frame set).
    // burst_pause = listen window after each burst — time for clients to reconnect
    // and complete the 4-way handshake. Apple ~200ms, Android ~500ms, Windows ~1s.
    // 2s pause captures most reconnections. 15s cooldown catches stragglers.
    // DoS modes use continuous flooding (default params).
    let is_deauth = matches!(dos_type,
        DosType::DeauthFlood | DosType::DeauthTargeted | DosType::DisassocFlood);
    let params = if is_deauth {
        DosParams {
            attack_type: dos_type,
            burst_count: 1, // smart burst handles its own frame count
            burst_pause: Duration::from_secs(2),
            cooldown: Duration::from_secs(15),
            ..Default::default()
        }
    } else {
        DosParams {
            attack_type: dos_type,
            ..Default::default()
        }
    };

    // Print attack start message
    let station_str = if let Some(ref sta) = station {
        format!("  \u{2192} client {}", prism::s().bold().paint(&sta.mac.to_string()))
    } else {
        String::new()
    };
    ctx.layout.print(&format!("  {} {} \u{2192} {}  {}  ch{}{}",
        prism::s().red().paint("\u{25b6}"),
        prism::s().cyan().bold().paint(dos_type.label()),
        prism::s().bold().paint(&target.ssid),
        prism::s().dim().paint(&target.bssid.to_string()),
        target.channel,
        station_str));

    // Select adapter for attack (prompt if multiple)
    let attack_adapter = match ctx.select_adapter_for_attack("DoS attack") {
        Some(a) => a,
        None => return,
    };

    // Create DoS module and start
    let mut dos_module = DosModule::new(params);
    dos_module.set_targets(target, station);
    dos_module.start(attack_adapter);

    ctx.layout.print(&format!("  {} Attack started. Scanner continues on locked channel. {} to stop.",
        prism::s().green().paint("\u{25cf}"),
        prism::s().cyan().paint("/attack stop")));
    ctx.layout.print("");

    // Push to focus stack
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(dos_module));
        state.mode = Mode::Normal;
    }
}
