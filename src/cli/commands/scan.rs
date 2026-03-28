//! Scanner command: /scan [flags] | /scan stop | /scan clear

use std::sync::Arc;
use std::time::Duration;

use crate::adapter::AdapterRole;
use crate::cli::module::Module;
use crate::cli::scanner::ScannerModule;
use crate::scanner::{Scanner, ScanConfig};
use super::{Ctx, Mode};

/// /scan [flags] | /scan stop | /scan clear
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    match args {
        "stop" => stop(ctx),
        "clear" => {
            ctx.layout.print(&format!("  {} Scan clear not supported in v2 (data accumulates).",
                prism::s().dim().paint("?")));
        }
        _ => start(ctx, args),
    }
}

fn stop(ctx: &mut Ctx) {
    let has_scanner = {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.find_by_name("scanner").is_some()
    };

    if has_scanner {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(idx) = state.focus_stack.find_by_name("scanner") {
            state.focus_stack.all()[idx].signal_stop();
            let module = state.focus_stack.remove(idx);
            let summary = module.freeze_summary(prism::term_width());
            drop(state);

            // Clear scanner role
            if let Some((adapter_idx, _)) = ctx.manager.scanner_adapter() {
                ctx.manager.clear_role(adapter_idx, crate::adapter::AdapterRole::Scanner);
            }

            for line in &summary {
                ctx.layout.print(line);
            }
        }
    } else {
        ctx.layout.print(&format!("  {} Scanner not running.",
            prism::s().dim().paint("?")));
    }
}

fn start(ctx: &mut Ctx, args: &str) {
    // Check if already scanning
    {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.focus_stack.find_by_name("scanner").is_some() {
            drop(state);
            ctx.layout.print(&format!("  {} Scanner already running. Use {} to stop.",
                prism::s().dim().paint("\u{25cf}"),
                prism::s().cyan().paint("/scan stop")));
            return;
        }
    }

    // Select adapter for scanner:
    // - If pre-selected via /adapter N (has Scanner role), use that
    // - If multiple adapters, prompt user to choose
    // - If only one adapter, auto-select
    let adapter_idx = if let Some((idx, _)) = ctx.manager.scanner_adapter() {
        idx
    } else {
        match ctx.select_adapter("scanner") {
            Some(idx) => idx,
            None => return,
        }
    };

    let shared = match ctx.open_adapter(adapter_idx) {
        Some(s) => s,
        None => return,
    };

    // Assign scanner role
    ctx.manager.assign_role(adapter_idx, AdapterRole::Scanner);

    // Parse scan flags from args
    let (config, warnings) = parse_scan_flags(args);
    for w in &warnings {
        ctx.layout.print(&format!("  {} {w}", prism::s().yellow().paint("warning:")));
    }

    // Create scanner + module, start via SharedAdapter
    let sp = prism::spinner("Starting scanner...", prism::SpinnerOptions {
        style: "dots",
        color: |t| prism::s().cyan().paint(t),
        ..Default::default()
    });

    let scanner = Arc::new(Scanner::new(config.clone()));
    let mut scanner_module = ScannerModule::new(Arc::clone(&scanner), ctx.store.clone());
    scanner_module.start(shared);

    let channel_desc = if config.scan_2ghz && config.scan_5ghz {
        "2.4GHz + 5GHz"
    } else if config.scan_5ghz {
        "5GHz only"
    } else {
        "2.4GHz only"
    };
    sp.done(Some(&format!(
        "Scanning {} {} {} navigate, {} commands",
        prism::s().bold().paint(channel_desc),
        prism::s().dim().paint("\u{2500}"),
        prism::s().cyan().paint("j/k/Tab"),
        prism::s().cyan().paint("/ or :"),
    )));

    // Push scanner module to focus stack
    {
        let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.push(Box::new(scanner_module));
        state.mode = Mode::Normal;
    }

    ctx.layout.print("");
}

/// Parse `/scan` flags into a ScanConfig. Returns config + any warnings.
///
/// Supported flags:
///   --passive           Passive-only scan (no probe injection)
///   --channels 1,6,11   Override channel list
///   --dwell N           Dwell time per channel in ms
///   --rounds N          Number of scan rounds (0 = infinite)
///   --no-2ghz           Disable 2.4 GHz channels
///   --no-5ghz           Disable 5 GHz channels
///   --6ghz              Enable 6 GHz channels
pub fn parse_scan_flags(args: &str) -> (ScanConfig, Vec<String>) {
    let mut config = ScanConfig::default();
    let mut warnings = Vec::new();
    let tokens: Vec<&str> = args.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "--passive" => { config.active = false; }
            "--channels" => {
                i += 1;
                if i < tokens.len() {
                    let channels: Vec<u8> = tokens[i]
                        .split(',')
                        .filter_map(|s| s.trim().parse::<u8>().ok())
                        .collect();
                    if !channels.is_empty() {
                        config.custom_channels = Some(channels);
                    }
                } else {
                    warnings.push("--channels requires a value (e.g., --channels 1,6,11)".into());
                }
            }
            "--dwell" => {
                i += 1;
                if i < tokens.len() {
                    match tokens[i].parse::<u64>() {
                        Ok(ms) => config.dwell_time = Duration::from_millis(ms),
                        Err(_) => warnings.push(format!("--dwell: invalid value '{}' (expected ms)", tokens[i])),
                    }
                } else {
                    warnings.push("--dwell requires a value in ms".into());
                }
            }
            "--rounds" => {
                i += 1;
                if i < tokens.len() {
                    match tokens[i].parse::<u32>() {
                        Ok(n) => config.num_rounds = n,
                        Err(_) => warnings.push(format!("--rounds: invalid value '{}' (expected number)", tokens[i])),
                    }
                } else {
                    warnings.push("--rounds requires a value".into());
                }
            }
            "--no-2ghz" => { config.scan_2ghz = false; }
            "--no-5ghz" => { config.scan_5ghz = false; }
            "--6ghz" => { config.scan_6ghz = true; }
            flag if flag.starts_with("--") => {
                warnings.push(format!("unknown flag '{}' (see /help scan)", flag));
            }
            _ => {} // positional args (none defined yet)
        }
        i += 1;
    }
    (config, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scan_flags_defaults() {
        let (config, _) = parse_scan_flags("");
        assert!(config.scan_2ghz);
        assert!(config.scan_5ghz);
        assert!(!config.scan_6ghz);
        assert_eq!(config.num_rounds, 0);
        assert_eq!(config.dwell_time, Duration::from_millis(300));
        assert!(config.custom_channels.is_none());
    }

    #[test]
    fn test_parse_scan_flags_passive() {
        let (config, _) = parse_scan_flags("--passive");
        assert!(!config.active);
    }

    #[test]
    fn test_parse_scan_flags_channels() {
        let (config, _) = parse_scan_flags("--channels 1,6,11");
        assert_eq!(config.custom_channels, Some(vec![1, 6, 11]));
    }

    #[test]
    fn test_parse_scan_flags_dwell() {
        let (config, _) = parse_scan_flags("--dwell 500");
        assert_eq!(config.dwell_time, Duration::from_millis(500));
    }

    #[test]
    fn test_parse_scan_flags_rounds() {
        let (config, _) = parse_scan_flags("--rounds 3");
        assert_eq!(config.num_rounds, 3);
    }

    #[test]
    fn test_parse_scan_flags_band_toggles() {
        let (config, _) = parse_scan_flags("--no-2ghz --6ghz");
        assert!(!config.scan_2ghz);
        assert!(config.scan_5ghz);
        assert!(config.scan_6ghz);
    }

    #[test]
    fn test_parse_scan_flags_combined() {
        let (config, _) = parse_scan_flags("--passive --channels 36,40,44 --dwell 200 --rounds 5 --no-2ghz");
        assert!(!config.active);
        assert_eq!(config.custom_channels, Some(vec![36, 40, 44]));
        assert_eq!(config.dwell_time, Duration::from_millis(200));
        assert_eq!(config.num_rounds, 5);
        assert!(!config.scan_2ghz);
    }

    #[test]
    fn test_parse_scan_flags_warns_unknown() {
        let (config, warnings) = parse_scan_flags("--unknown --foo bar");
        assert_eq!(config.num_rounds, 0);
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("--unknown"));
        assert!(warnings[1].contains("--foo"));
    }
}
