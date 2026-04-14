// wifikit CLI shell — unified event loop with vim-modal input
//
// Built on prism-rs primitives:
//   - Layout: two-zone rendering (scrollback + active zone)
//   - InputLine: REPL input with history, line editing
//   - StatusBar: segmented bottom status display
//   - CommandRouter: slash command parsing with tab completion
//   - keypress_poll: non-blocking key input with timeout
//   - raw_mode: terminal state for direct key capture
//
// Architecture: FocusStack + AdapterManager + FrameStore
//   Modules (scanner, attacks) live in the FocusStack. Each module spawns
//   its own background thread via start() and shares the adapter through
//   SharedAdapter. Channel contention is managed by SharedAdapter's lock
//   mechanism: attacks lock the channel, scanner pauses hopping.
//   AdapterManager owns all adapter lifecycle (discovery, open, role, release).

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::adapter::AdapterManager;
use crate::cli::banner;
use crate::cli::commands::{self, Ctx, ShellState, Mode, AdapterStatus};
use crate::cli::views::pmkid as pmkid_cli;
use crate::cli::views::dos as dos_cli;
use crate::cli::views::wps as wps_cli;
use crate::cli::views::eap as eap_cli;
use crate::cli::views::fuzz as fuzz_cli;
use crate::cli::views::frag as frag_cli;
use crate::cli::views::krack as krack_cli;
use crate::cli::views::ap as ap_cli;
use crate::cli::views::wpa3 as wpa3_cli;
use crate::cli::module::{ModuleType, SegmentStyle};
use crate::cli::scanner::ScannerModule;
use crate::core::Result;
use crate::store::FrameStore;
use crate::util::time::local_clock_hms;

/// Debug logging to file.
#[allow(unused)]
fn debug_log(msg: &str) {
    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/wifikit-debug.log")
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let _ = writeln!(f, "[{:.3}] [shell] {}", now.as_secs_f64(), msg);
        }
    }
}

const REFRESH_INTERVAL: Duration = Duration::from_millis(50);

/// Format an EAPOL/handshake scanner event for scrollback output during attacks.
/// Uses `attack_start` to compute timestamps relative to the attack, not the scanner.
fn format_eapol_event_relative(event: &crate::store::ScanEvent, attack_start: std::time::Instant) -> String {
    use crate::store::{ScanEventType, EventDetail};
    let now_since_attack = attack_start.elapsed().as_secs_f64();
    let ts = format!("{:>7.3}s", now_since_attack);
    let ts_styled = prism::s().dim().paint(&ts);

    match event.event_type {
        ScanEventType::EapolM1 => {
            format!("  [{}] {} {} \u{2192} {}  \u{2014} ANonce received",
                ts_styled,
                prism::s().cyan().bold().paint("\u{2726} M1"),
                prism::s().bold().paint(&event.source.to_string()),
                &event.target.to_string())
        }
        ScanEventType::EapolM2 => {
            format!("  [{}] {} {} \u{2192} {}  \u{2014} SNonce + MIC",
                ts_styled,
                prism::s().cyan().bold().paint("\u{2726} M2"),
                prism::s().bold().paint(&event.source.to_string()),
                &event.target.to_string())
        }
        ScanEventType::EapolM3 => {
            format!("  [{}] {} {} \u{2192} {}  \u{2014} GTK encrypted",
                ts_styled,
                prism::s().cyan().bold().paint("\u{2726} M3"),
                prism::s().bold().paint(&event.source.to_string()),
                &event.target.to_string())
        }
        ScanEventType::EapolM4 => {
            format!("  [{}] {} {} \u{2192} {}  \u{2014} install keys",
                ts_styled,
                prism::s().green().bold().paint("\u{2726} M4"),
                prism::s().bold().paint(&event.source.to_string()),
                &event.target.to_string())
        }
        ScanEventType::PmkidCaptured => {
            format!("  [{}] {} {} \u{2014} PMKID extracted from M1!",
                ts_styled,
                prism::s().green().bold().paint("\u{2605} PMKID"),
                prism::s().bold().paint(&event.source.to_string()))
        }
        ScanEventType::HandshakeComplete => {
            let quality_str = match &event.detail {
                EventDetail::HandshakeComplete { quality } => {
                    use crate::protocol::eapol::HandshakeQuality;
                    match quality {
                        HandshakeQuality::Full => "Full 4-way handshake",
                        HandshakeQuality::M1M2M3 => "M1+M2+M3 handshake",
                        HandshakeQuality::M1M2 => "M1+M2 handshake",
                        _ => "Handshake",
                    }
                }
                _ => "Handshake",
            };
            format!("  [{}] {} {} \u{2192} {} \u{2014} {} captured!",
                ts_styled,
                prism::s().green().bold().paint("\u{2605} CAPTURED"),
                prism::s().bold().paint(&event.source.to_string()),
                &event.target.to_string(),
                quality_str)
        }
        _ => String::new(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════════════════════════

enum Action { None, Execute(String), Quit }

struct RawModeGuard;
impl RawModeGuard {
    fn enable() -> Self { prism::raw_mode(true); RawModeGuard }
}
impl Drop for RawModeGuard {
    fn drop(&mut self) { prism::raw_mode(false); }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Shell — main controller
// ═══════════════════════════════════════════════════════════════════════════════

struct Shell {
    state: Arc<Mutex<ShellState>>,
    layout: prism::Layout,
    router: prism::CommandRouter,
    running: Arc<AtomicBool>,
    manager: AdapterManager,
    pub store: FrameStore,
}

impl Shell {
    fn new() -> Self {
        let state = Arc::new(Mutex::new(ShellState {
            mode: Mode::Insert,
            input: prism::InputLine::new(prism::InputLineOptions {
                prompt: prism::PromptSource::Static("wifikit > ".into()),
                prompt_color: Box::new(|t| prism::s().cyan().bold().paint(t)),
                history: Vec::new(),
                history_size: Some(500),
                mask: None,
            }),
            focus_stack: crate::cli::module::FocusStack::new(),
            verbose: false,
            adapter_status: AdapterStatus::default(),
        }));

        let layout = prism::layout(Some(prism::LayoutOptions {
            on_close: None,
            tty: None,
        }));

        Shell {
            state,
            layout,
            router: prism::CommandRouter::new(build_commands(), "/"),
            running: Arc::new(AtomicBool::new(true)),
            manager: AdapterManager::new(),
            store: FrameStore::new(),
        }
    }

    fn run(&mut self) -> Result<()> {
        if prism::is_tty() {
            banner::print_banner();
        }

        // Detect adapters on startup
        {
            let mut ctx = Ctx {
                manager: &mut self.manager,
                store: &self.store,
                layout: &mut self.layout,
                state: &self.state,
            };
            commands::adapter::detect(&mut ctx);
        }

        // Set up Layout active zone — render closure reads shared state
        let state_ref = Arc::clone(&self.state);
        self.layout.set_active(Box::new(move || {
            let mut s = state_ref.lock().unwrap_or_else(|e| e.into_inner());
            render_active_zone(&mut s)
        }));

        let _guard = RawModeGuard::enable();

        while self.running.load(Ordering::Relaxed) {
            match prism::keypress_poll(REFRESH_INTERVAL) {
                Ok(Some(key)) => {
                    let action = {
                        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                        handle_key(&key, &mut s, &self.router)
                    };
                    match action {
                        Action::None => {}
                        Action::Execute(input) => {
                            self.execute_command(&input);
                            // Return to Normal mode after command if any module is active
                            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                            if !s.focus_stack.is_empty() {
                                s.mode = Mode::Normal;
                            }
                        }
                        Action::Quit => {
                            self.shutdown_all();
                            self.running.store(false, Ordering::SeqCst);
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => break,
            }

            // Poll all modules for completion, drain events, handle lifecycle
            self.poll_modules();

            // Snapshot adapter status into ShellState for the render closure
            {
                let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                s.adapter_status = AdapterStatus {
                    scanner_name: self.manager.scanner_adapter()
                        .and_then(|(i, _)| self.manager.adapter_info(i).map(|a| a.name.to_string())),
                    scanner_mac: self.manager.scanner_adapter().map(|(_, s)| s.mac()),
                    attack_name: self.manager.attack_adapter()
                        .and_then(|(i, _)| self.manager.adapter_info(i).map(|a| a.name.to_string())),
                };
            }

            self.layout.refresh();
        }

        self.layout.close(None);
        drop(_guard);
        if prism::is_tty() {
            prism::writeln(&prism::s().dim().paint("Goodbye."));
        }
        Ok(())
    }

    /// Graceful shutdown: stop all modules, release all adapters.
    fn shutdown_all(&mut self) {
        // Stop all running modules
        {
            let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            for module in s.focus_stack.all() {
                module.signal_stop();
            }
        }
        // Release all adapters — shuts down RX threads, closes USB
        self.manager.release_all();
    }

    // ── Module polling ────────────────────────────────────────────────────

    fn poll_modules(&mut self) {
        // PMKID: delta-driven — tick() processes deltas, returns formatted scrollback lines
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(pmkid_mod) = state.focus_stack.find_as_mut::<pmkid_cli::PmkidModule>("pmkid") {
                let lines = pmkid_mod.tick();
                drop(state);
                for line in &lines {
                    self.layout.print(line);
                }
            }
        }

        // DoS: delta-driven — tick() processes deltas, returns formatted scrollback lines
        // Also update target clients from scanner for the client monitoring view
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(dos_mod) = state.focus_stack.find_as_mut::<dos_cli::DosModule>("dos") {
                let lines = dos_mod.tick();
                let dos_info = dos_mod.info();
                let target_bssid = dos_info.target_bssid;

                // Get scanner clients associated with target AP for client monitoring
                let clients: Vec<dos_cli::ClientSnapshot> =
                    if let Some(scanner_mod) = state.focus_stack.find_as::<ScannerModule>("scanner") {
                        let stations = scanner_mod.store.get_stations().into_values().collect::<Vec<_>>();
                        stations.iter()
                            .filter(|sta| sta.bssid == Some(target_bssid) && sta.is_associated)
                            .map(|sta| dos_cli::ClientSnapshot {
                                mac: sta.mac,
                                rssi: sta.rssi,
                                snr: sta.snr,
                                last_seen: sta.last_seen,
                                frame_count: sta.frame_count,
                                vendor: sta.vendor.clone(),
                                reconnect_at: None,
                                rssi_samples: sta.rssi_samples.clone(),
                                snr_samples: sta.snr_samples.clone(),
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };

                // Update DoS module with client data (for CLI display)
                if let Some(dos_mod) = state.focus_stack.find_as_mut::<dos_cli::DosModule>("dos") {
                    dos_mod.update_target_clients(clients.clone());
                    let client_macs: Vec<crate::core::mac::MacAddress> = clients.iter()
                        .map(|c| c.mac)
                        .collect();
                    dos_mod.attack().update_clients(client_macs);
                }

                // Also drain EAPOL/handshake events from the scanner
                let attack_start = dos_info.start_time;
                let eapol_lines: Vec<String> =
                    if let Some(scanner_mod) = state.focus_stack.find_as::<ScannerModule>("scanner") {
                        let scan_events = scanner_mod.store.drain_events();
                        scan_events.iter()
                            .filter(|e| matches!(e.event_type,
                                crate::store::ScanEventType::EapolM1
                                | crate::store::ScanEventType::EapolM2
                                | crate::store::ScanEventType::EapolM3
                                | crate::store::ScanEventType::EapolM4
                                | crate::store::ScanEventType::PmkidCaptured
                                | crate::store::ScanEventType::HandshakeComplete
                            ))
                            .map(|e| format_eapol_event_relative(e, attack_start))
                            .collect()
                    } else {
                        Vec::new()
                    };

                drop(state);
                for line in &lines {
                    self.layout.print(line);
                }
                for line in &eapol_lines {
                    self.layout.print(line);
                }
            }
        }

        // WPS: delta-driven — tick() processes deltas, returns formatted scrollback lines
        // (including freeze summaries for TargetComplete events)
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(wps_mod) = state.focus_stack.find_as_mut::<wps_cli::WpsModule>("wps") {
                let lines = wps_mod.tick();
                drop(state);
                for line in &lines {
                    self.layout.print(line);
                }
            }
        }

        // EAP: delta-driven
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(eap_mod) = state.focus_stack.find_as_mut::<eap_cli::EapModule>("eap") {
                let lines = eap_mod.tick();
                drop(state);
                for line in &lines {
                    self.layout.print(line);
                }
            }
        }

        // Fuzz: delta-driven
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(fuzz_mod) = state.focus_stack.find_as_mut::<fuzz_cli::FuzzModule>("fuzz") {
                let lines = fuzz_mod.tick();
                drop(state);
                for line in &lines {
                    self.layout.print(line);
                }
            }
        }

        // FragAttacks: delta-driven — tick() processes deltas, returns formatted scrollback lines
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(frag_mod) = state.focus_stack.find_as_mut::<frag_cli::FragModule>("frag") {
                let lines = frag_mod.tick();
                drop(state);
                for line in &lines {
                    self.layout.print(line);
                }
            }
        }

        // KRACK: delta-driven — tick() processes deltas, returns formatted scrollback lines
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(krack_mod) = state.focus_stack.find_as_mut::<krack_cli::KrackModule>("krack") {
                let lines = krack_mod.tick();
                drop(state);
                for line in &lines {
                    self.layout.print(line);
                }
            }
        }

        // WPA3: delta-driven — tick() processes deltas, returns formatted scrollback lines
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(wpa3_mod) = state.focus_stack.find_as_mut::<wpa3_cli::Wpa3Module>("wpa3") {
                let lines = wpa3_mod.tick();
                drop(state);
                for line in &lines {
                    self.layout.print(line);
                }
            }
        }

        // AP: delta-driven
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ap_mod) = state.focus_stack.find_as_mut::<ap_cli::ApModule>("ap") {
                let lines = ap_mod.tick();
                drop(state);
                for line in &lines {
                    self.layout.print(line);
                }
            }
        }

        // Check for completed attack modules
        let completed = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.focus_stack.drain_completed()
        };

        for module in &completed {
            debug_log(&format!("poll_modules: module '{}' completed", module.name()));

            // Freeze results to scrollback
            let summary = module.freeze_summary(prism::term_width());
            for line in &summary {
                self.layout.print(line);
            }

            // Clear attack adapter role when attack completes.
            // AdapterManager.clear_role() handles RX thread lifecycle:
            // if the adapter has no remaining roles, its RX thread is idled.
            if module.module_type() == ModuleType::Attack {
                if let Some((atk_idx, _)) = self.manager.attack_adapter() {
                    self.manager.clear_role(atk_idx, crate::adapter::AdapterRole::Attack);
                }
            }
        }
    }

    // ── Command dispatch ──────────────────────────────────────────────────

    fn execute_command(&mut self, raw_input: &str) {
        let input = raw_input.trim();
        if input.is_empty() { return; }

        if let Some(matched) = self.router.match_input(input) {
            // Inline commands that don't need Ctx
            match matched.name.as_str() {
                "quit" | "exit" => { self.running.store(false, Ordering::SeqCst); return; }
                "clear" => { prism::write("\x1b[2J\x1b[H"); return; }
                "verbose" => {
                    let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    state.verbose = !state.verbose;
                    let status = if state.verbose { "enabled" } else { "disabled" };
                    let icon = if state.verbose { "\u{2713}" } else { "\u{2717}" };
                    let color = if state.verbose { prism::s().green() } else { prism::s().dim() };
                    drop(state);
                    self.layout.print(&format!("  {} Verbose mode {}",
                        color.paint(icon), color.paint(status)));
                    return;
                }
                _ => {}
            }

            // Build Ctx for commands that need Shell resources
            let mut ctx = Ctx {
                manager: &mut self.manager,
                store: &self.store,
                layout: &mut self.layout,
                state: &self.state,
            };

            match matched.name.as_str() {
                "help"               => commands::help::run(&mut ctx, &matched.args),
                "version"            => commands::help::version(&mut ctx),
                "adapter" | "adapters" => commands::adapter::run(&mut ctx, &matched.args),
                "scan"               => commands::scan::run(&mut ctx, &matched.args),
                "spectrum"           => commands::spectrum::run(&mut ctx, &matched.args),
                "view"               => commands::view::run(&mut ctx, &matched.args),
                "attack"             => commands::attack::run(&mut ctx, &matched.args),
                "pmkid"              => commands::pmkid::run(&mut ctx, &matched.args),
                "dos"                => commands::dos::run(&mut ctx, &matched.args),
                "deauth"             => commands::dos::deauth(&mut ctx, &matched.args),
                "wps"                => commands::wps::run(&mut ctx, &matched.args),
                "eap"                => commands::eap::run(&mut ctx, &matched.args),
                "fuzz"               => commands::fuzz::run(&mut ctx, &matched.args),
                "frag"               => commands::frag::run(&mut ctx, &matched.args),
                "krack"              => commands::krack::run(&mut ctx, &matched.args),
                "wpa3"               => commands::wpa3::run(&mut ctx, &matched.args),
                "ap"                 => commands::ap::run(&mut ctx, &matched.args),
                "export"             => commands::export::run(&mut ctx, &matched.args),
                "mac"                => commands::help::mac_stub(&mut ctx),
                _ => {
                    ctx.layout.print(&format!("  {} Unknown command: {}",
                        prism::s().red().paint("!"), input));
                }
            }
        } else {
            self.layout.print(&format!("  {} Type {} for available commands.",
                prism::s().dim().paint("?"), prism::s().cyan().paint("/help")));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Rendering
// ═══════════════════════════════════════════════════════════════════════════════

fn render_active_zone(state: &mut ShellState) -> prism::ActiveFrame {
    let width = prism::term_width();
    let term_h = prism::term_height() as usize;

    // Hard cap: active zone never exceeds 80% of terminal height
    let max_active = (term_h * 80 / 100).max(4);

    // Build status bar first to know its height (may wrap to multiple lines)
    let status_lines = build_status(state, width as usize);
    let status_height = status_lines.len();

    // Chrome: input(1) + status(N) lines
    let chrome = 1 + status_height;

    // Viewport: whatever remains after chrome, for the current module block
    let viewport_h = max_active.saturating_sub(chrome);

    let mut lines = Vec::new();

    // Render focused module (scanner, attack, or nothing)
    if let Some(module) = state.focus_stack.focused_mut() {
        let block = module.render(0, width, viewport_h as u16);
        lines.extend(block);
    }

    // Input line
    let input_render = state.input.render();
    let input_start_row = lines.len();
    lines.extend(input_render.lines);

    // Status bar (may be multiple lines when content wraps)
    lines.extend(status_lines);

    let cursor = if state.mode == Mode::Insert {
        Some(((input_start_row + input_render.cursor.0) as u16, input_render.cursor.1 as u16))
    } else {
        None
    };

    prism::ActiveFrame { lines, cursor }
}

fn build_status(state: &mut ShellState, width: usize) -> Vec<String> {
    let mode_seg = match state.mode {
        Mode::Normal => prism::Segment::Styled { text: "NORMAL".into(), color: Some(|t| prism::s().cyan().bold().render(t)) },
        Mode::Insert => prism::Segment::Styled { text: "INSERT".into(), color: Some(|t| prism::s().green().bold().render(t)) },
    };

    // Adapter status — derived from AdapterStatus snapshot (truth from AdapterManager)
    let adapter_seg = if let Some(ref name) = state.adapter_status.scanner_name {
        if let Some(ref atk_name) = state.adapter_status.attack_name {
            if atk_name != name {
                // Different adapters: "scan:BU atk:7921"
                prism::Segment::Styled {
                    text: format!("scan:{name} \u{2502} atk:{atk_name}"),
                    color: Some(|t| prism::s().green().render(t)),
                }
            } else {
                prism::Segment::Styled {
                    text: format!("\u{25cf} {name}"),
                    color: Some(|t| prism::s().green().render(t)),
                }
            }
        } else {
            prism::Segment::Styled {
                text: format!("\u{25cf} {name}"),
                color: Some(|t| prism::s().green().render(t)),
            }
        }
    } else {
        prism::Segment::Styled {
            text: "\u{25cf} none".into(),
            color: Some(|t| prism::s().dim().render(t)),
        }
    };

    let mut left = vec![
        adapter_seg,
        mode_seg,
    ];

    // MAC address segment (shown when adapter is connected, hidden in dual-adapter to save space)
    if state.adapter_status.attack_name.is_none() {
        if let Some(mac) = state.adapter_status.scanner_mac {
            left.push(prism::Segment::Styled {
                text: format!("{mac}"),
                color: Some(|t| prism::s().dim().render(t)),
            });
        }
    }

    // Collect status segments from ALL running modules
    for module in state.focus_stack.all() {
        let segments = module.status_segments();
        for seg in segments {
            left.push(prism::Segment::Styled {
                text: seg.text,
                color: Some(match seg.style {
                    SegmentStyle::Normal => |t: &str| t.to_string(),
                    SegmentStyle::Dim => |t: &str| prism::s().dim().render(t),
                    SegmentStyle::Bold => |t: &str| prism::s().bold().render(t),
                    SegmentStyle::Green => |t: &str| prism::s().green().render(t),
                    SegmentStyle::GreenBold => |t: &str| prism::s().green().bold().render(t),
                    SegmentStyle::Yellow => |t: &str| prism::s().yellow().render(t),
                    SegmentStyle::YellowBold => |t: &str| prism::s().yellow().bold().render(t),
                    SegmentStyle::Red => |t: &str| prism::s().red().render(t),
                    SegmentStyle::RedBold => |t: &str| prism::s().red().bold().render(t),
                    SegmentStyle::Cyan => |t: &str| prism::s().cyan().render(t),
                    SegmentStyle::CyanBold => |t: &str| prism::s().cyan().bold().render(t),
                    SegmentStyle::Magenta => |t: &str| prism::s().magenta().render(t),
                    SegmentStyle::MagentaBold => |t: &str| prism::s().magenta().bold().render(t),
                }),
            });
        }
    }

    // Focus hint: show what ^N switches to (only when multiple modules exist)
    if state.focus_stack.len() > 1 {
        let next_idx = (state.focus_stack.focus_index() + 1) % state.focus_stack.len();
        if let Some(next_module) = state.focus_stack.all().get(next_idx) {
            left.push(prism::Segment::Styled {
                text: format!("^N:{}", next_module.name()),
                color: Some(|t| prism::s().dim().render(t)),
            });
        }
    }

    // Right side: clock
    let clock = local_clock_hms();

    prism::statusbar_render_wrapped(&prism::StatusBarConfig {
        left,
        right: Some(prism::Segment::Styled { text: clock, color: Some(|t| prism::s().dim().render(t)) }),
        separator: None,
        indent: Some(2),
        separator_color: Some(|t| prism::s().dim().render(t)),
    }, width)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Key handling (uses prism::KeyEvent)
// ═══════════════════════════════════════════════════════════════════════════════

fn handle_key(key: &prism::KeyEvent, state: &mut ShellState, router: &prism::CommandRouter) -> Action {
    match state.mode {
        Mode::Normal => handle_normal(key, state),
        Mode::Insert => handle_insert(key, state, router),
    }
}

fn handle_normal(key: &prism::KeyEvent, state: &mut ShellState) -> Action {
    if key.ctrl {
        return match key.key.as_str() {
            "c" | "d" => Action::Quit,
            "n" => { state.focus_stack.focus_next(); Action::None }
            "p" => { state.focus_stack.focus_prev(); Action::None }
            _ => Action::None,
        };
    }

    // Try focused module first
    if let Some(module) = state.focus_stack.focused_mut() {
        if module.handle_key(key, 0) {
            return Action::None;
        }
    }

    // Shell-level Normal mode keys
    match key.key.as_str() {
        "/" | ":" => { state.mode = Mode::Insert; state.input.set_value("/", None); Action::None }
        "q" => {
            if state.focus_stack.is_empty() {
                Action::Quit
            } else {
                Action::None
            }
        }
        _ => Action::None,
    }
}

fn handle_insert(key: &prism::KeyEvent, state: &mut ShellState, router: &prism::CommandRouter) -> Action {
    if key.ctrl {
        return match key.key.as_str() {
            "c" => { if state.input.buffer().is_empty() { Action::Quit } else { state.input.clear_line(); Action::None } }
            "d" => { if state.input.buffer().is_empty() { Action::Quit } else { state.input.delete_char(); Action::None } }
            "a" => { state.input.home(); Action::None }
            "e" => { state.input.end(); Action::None }
            "u" => { state.input.clear_before(); Action::None }
            "k" => { state.input.clear_after(); Action::None }
            "w" => { state.input.delete_word(); Action::None }
            _ => Action::None,
        };
    }
    if key.meta {
        return match key.key.as_str() {
            "left" => { state.input.word_left(); Action::None }
            "right" => { state.input.word_right(); Action::None }
            _ => Action::None,
        };
    }
    match key.key.as_str() {
        "escape" => {
            state.input.clear_line();
            if !state.focus_stack.is_empty() {
                state.mode = Mode::Normal;
            }
            Action::None
        }
        "enter" => { let t = state.input.submit(); if t.trim().is_empty() { Action::None } else { Action::Execute(t) } }
        "backspace" => { state.input.backspace(); Action::None }
        "delete" => { state.input.delete_char(); Action::None }
        "left" => { state.input.cursor_left(); Action::None }
        "right" => { state.input.cursor_right(); Action::None }
        "wordleft" => { state.input.word_left(); Action::None }
        "wordright" => { state.input.word_right(); Action::None }
        "home" => { state.input.home(); Action::None }
        "end" => { state.input.end(); Action::None }
        "up" => { state.input.history_up(); Action::None }
        "down" => { state.input.history_down(); Action::None }
        "tab" => {
            let partial = state.input.buffer().to_string();
            let completions = router.completions(&partial);
            if completions.len() == 1 { state.input.set_value(&format!("{} ", completions[0]), None); }
            Action::None
        }
        _ => { if let Some(c) = key.char_val { state.input.insert_char(&c.to_string()); } Action::None }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Command registry
// ═══════════════════════════════════════════════════════════════════════════════

fn build_commands() -> Vec<(String, prism::Command)> {
    let c = |n: &str, d: &str, a: &[&str]| (n.into(), prism::Command {
        description: Some(d.into()), aliases: a.iter().map(|s| s.to_string()).collect(), hidden: false,
    });
    vec![
        c("help", "Show available commands", &["h", "?"]),
        c("quit", "Exit wifikit", &["q", "exit"]),
        c("clear", "Clear the terminal screen", &[]),
        c("version", "Show version information", &["v"]),
        c("adapter", "List/select/switch adapters", &["adapters"]),
        c("mac", "Set/randomize MAC address", &[]),
        c("scan", "Start WiFi scanner", &[]),
        c("spectrum", "RF spectrum analyzer (MT7921AU)", &[]),
        c("view", "Switch scanner view (aps, clients, probes, channels, events, handshakes)", &[]),
        c("attack", "Attack control (stop)", &[]),
        c("export", "Export data (pcap, hccapx, hc22000, csv)", &[]),
        c("pmkid", "PMKID extraction attack", &[]),
        c("wps", "WPS Pixie Dust + brute force", &[]),
        c("deauth", "Deauthentication attack", &[]),
        c("dos", "Denial of service (14 types)", &[]),
        c("ap", "Rogue AP / Evil Twin / KARMA", &[]),
        c("eap", "Enterprise credential capture", &[]),
        c("krack", "KRACK key reinstallation (11 variants)", &[]),
        c("frag", "FragAttacks (12 CVEs)", &[]),
        c("fuzz", "WiFi protocol fuzzer", &[]),
        c("wpa3", "WPA3/Dragonblood attacks", &[]),
        c("verbose", "Toggle verbose output", &[]),
    ]
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════════

pub fn run(verbose: bool) -> Result<()> {
    let mut shell = Shell::new();
    if verbose {
        let mut state = shell.state.lock().unwrap_or_else(|e| e.into_inner());
        state.verbose = true;
    }
    shell.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commands() {
        assert!(build_commands().len() >= 15);
    }
}
