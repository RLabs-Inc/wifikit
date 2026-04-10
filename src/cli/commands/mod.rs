//! Command handlers — one file per command.
//!
//! Each command is a free function: `pub fn run(ctx: &mut Ctx, args: &str)`.
//! The Shell creates Ctx from its resources and dispatches to the handler.

pub mod adapter;
pub mod scan;
pub mod view;
pub mod attack;
pub mod pmkid;
pub mod dos;
pub mod wps;
pub mod eap;
pub mod fuzz;
pub mod krack;
pub mod wpa3;
pub mod ap;
pub mod frag;
pub mod export;
pub mod spectrum;
pub mod help;

use std::sync::{Arc, Mutex};

use crate::adapter::{AdapterManager, AdapterRole, SharedAdapter};
use crate::cli::scanner::{ScannerModule, DetailState};
use crate::core::mac::MacAddress;
use crate::pipeline::FrameGate;
use crate::store::{Ap, FrameStore};
use crate::util::time::local_datetime_file_stamp;

// ═══════════════════════════════════════════════════════════════════════════════
//  Shell state — shared between event loop and Layout render closure
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Mode { Normal, Insert }

/// Snapshot of adapter state for the render closure.
/// Updated once per render cycle from AdapterManager (truth source).
#[derive(Clone, Default)]
pub(crate) struct AdapterStatus {
    pub scanner_name: Option<String>,
    pub scanner_mac: Option<MacAddress>,
    pub attack_name: Option<String>,
}

pub(crate) struct ShellState {
    pub mode: Mode,
    pub input: prism::InputLine,
    pub focus_stack: crate::cli::module::FocusStack,
    pub verbose: bool,
    pub adapter_status: AdapterStatus,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Command context — passed to every command handler
// ═══════════════════════════════════════════════════════════════════════════════

/// Borrows all Shell resources needed by commands.
/// Created fresh for each command dispatch, destroyed when command returns.
pub(crate) struct Ctx<'a> {
    pub manager: &'a mut AdapterManager,
    pub store: &'a FrameStore,
    pub layout: &'a mut prism::Layout,
    pub state: &'a Arc<Mutex<ShellState>>,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Shared helpers — eliminate boilerplate across command handlers
// ═══════════════════════════════════════════════════════════════════════════════

impl<'a> Ctx<'a> {
    /// Check if verbose mode is enabled.
    pub fn is_verbose(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).verbose
    }

    // ── Adapter selection ─────────────────────────────────────────────────

    /// Prompt user to select an adapter. Auto-selects if only one.
    /// Returns discovered index, or None if cancelled/empty.
    pub fn select_adapter(&mut self, purpose: &str) -> Option<usize> {
        if self.manager.count() == 0 {
            self.layout.print(&format!("  {} No adapters detected. Plug in a supported USB adapter.",
                prism::s().yellow().paint("\u{26a0}")));
            return None;
        }

        // Auto-select if only one adapter
        if self.manager.count() == 1 {
            return Some(0);
        }

        // Build choices for select prompt
        let choices: Vec<String> = self.manager.adapters()
            .map(|(i, info, is_open, role)| {
                let status = match role {
                    Some(AdapterRole::Scanner) => format!("  {}", prism::s().green().paint("\u{2605} scanner")),
                    Some(AdapterRole::Attack)  => format!("  {}", prism::s().yellow().paint("\u{2605} attack")),
                    None if is_open            => format!("  {}", prism::s().dim().paint("(initialized)")),
                    None                       => String::new(),
                };
                format!("[{}] {} \u{2014} {}{}", i + 1, info.chip, info.name, status)
            })
            .collect();
        let choice_refs: Vec<&str> = choices.iter().map(|s| s.as_str()).collect();

        // Exit raw mode temporarily for the interactive select
        prism::raw_mode(false);
        let result = prism::prompt::select(
            &format!("Select adapter for {}", purpose),
            &choice_refs,
            prism::prompt::SelectOptions::default(),
        );
        prism::raw_mode(true);

        match result {
            Ok(selected) => choices.iter().position(|c| c == &selected),
            Err(_) => None,
        }
    }

    /// Open adapter by index: USB claim, chip init, monitor mode, RX thread.
    /// Shows spinner with status messages. Returns SharedAdapter, or None on failure.
    pub fn open_adapter(&mut self, idx: usize) -> Option<SharedAdapter> {
        // Already opened?
        if let Some(shared) = self.manager.get_adapter(idx) {
            return Some(shared.clone());
        }

        let info = self.manager.adapter_info(idx)?;
        let name = info.name.to_string();
        let chip_name = format!("{}", info.chip);

        let sp = prism::spinner(
            &format!("Initializing {}...", name),
            prism::SpinnerOptions {
                style: "dots",
                color: |t| prism::s().cyan().paint(t),
                timer: true,
                ..Default::default()
            },
        );

        let verbose = self.is_verbose();
        let layout_ref = self.layout.clone();

        // Create pcap capture path: ~/.wifikit/captures/YYYY-MM-DD_HHMMSS_<chip>.pcap
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let pcap_dir = std::path::PathBuf::from(home)
            .join(".wifikit").join("captures");
        let pcap_path = pcap_dir.join(format!(
            "{}_{}.pcap",
            local_datetime_file_stamp(),
            chip_name,
        ));

        // Create FrameGate — the pipeline thread that parses RX frames and updates the store
        let gate = FrameGate::new(self.store.clone(), Some(pcap_path));

        match self.manager.open_adapter(idx, gate, self.store.clone(), move |status| {
            if verbose {
                layout_ref.print(&format!("    {} {}",
                    prism::s().dim().paint("\u{00b7}"),
                    prism::s().dim().paint(status),
                ));
            }
        }) {
            Ok(shared) => {
                let mac = shared.mac();
                sp.done(Some(&format!(
                    "Adapter ready {} MAC={}",
                    prism::s().dim().paint(&name),
                    prism::s().bold().paint(&format!("{}", mac)),
                )));
                Some(shared)
            }
            Err(e) => {
                sp.fail(Some(&format!("Adapter init failed: {}", e)));
                None
            }
        }
    }

    /// Select + open adapter for attack use. Assigns Attack role.
    /// Prints dual-adapter message if scanner runs on a different adapter.
    /// Returns SharedAdapter, or None if cancelled/failed.
    pub fn select_adapter_for_attack(&mut self, attack_name: &str) -> Option<SharedAdapter> {
        let idx = self.select_adapter(attack_name)?;
        let shared = self.open_adapter(idx)?;

        // Check if scanner runs on a different adapter -> dual-adapter mode
        if let Some((scanner_idx, _)) = self.manager.scanner_adapter() {
            if scanner_idx != idx {
                let scanner_chip = self.manager.adapter_info(scanner_idx)
                    .map(|a| format!("{}", a.chip))
                    .unwrap_or_default();
                let attack_chip = self.manager.adapter_info(idx)
                    .map(|a| format!("{}", a.chip))
                    .unwrap_or_default();
                self.layout.print(&format!("  {} Dual-adapter: scanner on {}, attack on {} \u{2014} frames merged via FrameGate",
                    prism::s().cyan().paint("\u{2726}"),
                    prism::s().bold().paint(&scanner_chip),
                    prism::s().bold().paint(&attack_chip)));
            }
        }

        // Assign attack role
        self.manager.assign_role(idx, AdapterRole::Attack);

        Some(shared)
    }

    // ── Precondition checks ───────────────────────────────────────────────

    /// Check scanner is running. Prints error if not. Returns true if running.
    pub fn require_scanner(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let running = state.focus_stack.find_by_name("scanner").is_some();
        drop(state);
        if !running {
            self.layout.print(&format!("  {} Scanner not running. Start with {} first.",
                prism::s().yellow().paint("\u{26a0}"),
                prism::s().cyan().paint("/scan")));
        }
        running
    }

    /// Check no attack is currently running. Prints error if one is. Returns true if clear.
    pub fn require_no_attack(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let has_attack = state.focus_stack.has_active_attack();
        drop(state);
        if has_attack {
            self.layout.print(&format!("  {} Attack already running. Use {} to stop.",
                prism::s().dim().paint("\u{25cf}"),
                prism::s().cyan().paint("/attack stop")));
        }
        !has_attack
    }

    /// Check at least one adapter has been opened (any role).
    pub fn require_adapter(&self) -> bool {
        let has = self.manager.first_opened().is_some();
        if !has {
            self.layout.print(&format!("  {} No adapter available.",
                prism::s().red().paint("!")));
        }
        has
    }

    // ── Target resolution ─────────────────────────────────────────────────

    /// Resolve target AP from args string.
    ///
    /// Resolution order:
    ///   1. "--all" / "-a" -> returns Ok(None) (meaning all targets)
    ///   2. MAC address (17-char colon-separated hex) -> lookup by BSSID
    ///   3. Non-empty string -> lookup by SSID
    ///   4. Empty string -> use drilled-in AP detail, or selected row
    ///
    /// Returns Ok(Some(ap)) for single target, Ok(None) for "all", Err(msg) on failure.
    pub fn resolve_target(&self, args: &str) -> Result<Option<Ap>, &'static str> {
        let args = args.trim();
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Get AP list from store
        let aps: Vec<Ap> = self.store.get_aps().into_values().collect();

        if args == "--all" || args == "-a" {
            return Ok(None);
        }

        if args.is_empty() {
            if aps.is_empty() {
                return Err("no_aps");
            }
            // If drilled into AP detail view, use THAT AP
            if let Some(scanner_mod) = state.focus_stack.find_as::<ScannerModule>("scanner") {
                if let DetailState::Ap { bssid, .. } = &scanner_mod.detail {
                    return Ok(aps.iter().find(|ap| &ap.bssid == bssid).cloned());
                }
                // Use selected row
                let selected_idx = scanner_mod.selected.min(aps.len().saturating_sub(1));
                return Ok(Some(aps[selected_idx].clone()));
            }
            return Err("no_scanner");
        }

        // Try as MAC address
        if args.contains(':') && args.len() == 17 {
            let bytes: std::result::Result<Vec<u8>, _> = args.split(':')
                .map(|h| u8::from_str_radix(h, 16))
                .collect();
            if let Ok(b) = bytes {
                if b.len() == 6 {
                    let mac = MacAddress::new([b[0], b[1], b[2], b[3], b[4], b[5]]);
                    return match aps.iter().find(|ap| ap.bssid == mac).cloned() {
                        Some(ap) => Ok(Some(ap)),
                        None => Err("ap_not_found"),
                    };
                }
            }
        }

        // Try as SSID
        match aps.iter().find(|ap| ap.ssid == args).cloned() {
            Some(ap) => Ok(Some(ap)),
            None => Err("ap_not_found"),
        }
    }

    /// Resolve target with user-friendly error messages printed.
    /// Returns Some(Some(ap)) for single target, Some(None) for --all, None on error.
    pub fn resolve_target_or_all(&mut self, args: &str) -> Option<Option<Ap>> {
        match self.resolve_target(args) {
            Ok(target) => Some(target),
            Err("no_aps") => {
                self.layout.print(&format!("  {} No APs discovered yet. Wait for scan results.",
                    prism::s().yellow().paint("\u{26a0}")));
                None
            }
            Err("ap_not_found") => {
                self.layout.print(&format!("  {} AP not found: {}",
                    prism::s().red().paint("!"), args.trim()));
                None
            }
            Err(_) => {
                self.layout.print(&format!("  {} Scanner not running. Start with {} first.",
                    prism::s().yellow().paint("\u{26a0}"),
                    prism::s().cyan().paint("/scan")));
                None
            }
        }
    }
}
