//! Adapter management commands: /adapter [list|rescan|N]
//!
//! Handles USB adapter discovery, listing, selection, and hot-switching.
//! All adapter state lives in AdapterManager — no scattered fields.

use std::sync::Arc;

use crate::adapter::AdapterRole;
use crate::cli::module::Module;
use crate::cli::scanner::ScannerModule;
use super::{Ctx, Mode};

/// Run on startup: scan USB bus, list discovered adapters.
pub fn detect(ctx: &mut Ctx) {
    if !prism::is_tty() { return; }

    let sp = prism::spinner("Scanning for WiFi adapters...", prism::SpinnerOptions {
        style: "dots",
        color: |t| prism::s().cyan().paint(t),
        ..Default::default()
    });

    // scan_usb returns Result<&[AdapterInfo]> — consume the result to release the borrow
    let scan_err = ctx.manager.scan_usb().err().map(|e| format!("{}", e));

    if let Some(err) = scan_err {
        sp.fail(Some(&format!("USB scan failed: {}", err)));
        ctx.layout.print("");
        return;
    }

    if ctx.manager.count() > 0 {
        let count = ctx.manager.count();
        sp.done(Some(&format!(
            "Found {} adapter{}",
            prism::s().green().bold().paint(&count.to_string()),
            if count == 1 { "" } else { "s" },
        )));
        for (i, info, _is_open, _role) in ctx.manager.adapters() {
            ctx.layout.print(&format!(
                "  {} {} {}",
                prism::badge(
                    &format!("{}", i + 1),
                    prism::BadgeVariant::Bracket,
                    Some(|t| prism::s().cyan().bold().paint(t)),
                ),
                prism::s().bold().paint(info.name),
                prism::s().dim().paint(&format!(
                    "{} \u{2014} VID={:#06x} PID={:#06x} bus={} addr={}",
                    info.chip, info.vid, info.pid, info.bus, info.address,
                )),
            ));
        }
        ctx.layout.print("");
    } else {
        sp.fail(Some("No compatible adapters found"));
        ctx.layout.print("");
        ctx.layout.print(&format!("  {}",
            prism::s().bold().paint("Supported adapters:")));
        let adapters_list = prism::list(
            &["RTL8812BU  (TP-Link Archer T4U V3, ALFA AWUS036ACM)",
              "RTL8812AU  (ALFA AWUS036ACH, TP-Link T4UHP)",
              "MT7921AU   (ALFA AWUS036AXML, Comfast CF-953AX)",
              "MT7612U    (COMFAST CF-WU785AC, Alfa AWUS036ACM)"],
            &prism::ListOptions {
                style: prism::ListStyle::Bullet,
                indent: 2,
            },
        );
        for line in adapters_list.lines() {
            ctx.layout.print(line);
        }
        ctx.layout.print("");
        ctx.layout.print(&format!("  {}",
            prism::s().dim().paint("Plug in a compatible adapter and restart.")));
        ctx.layout.print("");
    }
}

/// /adapter [list|rescan|N]
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    match args {
        "" | "list" => list(ctx),
        "rescan" => rescan(ctx),
        _ => {
            // Try to parse as adapter number: /adapter 2
            if let Ok(n) = args.parse::<usize>() {
                select(ctx, n);
            } else {
                ctx.layout.print(&format!("  {} Usage: {} [list|rescan|<N>]",
                    prism::s().dim().paint("?"),
                    prism::s().cyan().paint("/adapter")));
            }
        }
    }
}

/// List all discovered adapters with status.
fn list(ctx: &mut Ctx) {
    // Fresh USB scan — detect newly plugged/unplugged adapters
    let _ = ctx.manager.scan_usb();

    if ctx.manager.count() == 0 {
        ctx.layout.print(&format!("\n  {} No adapters detected. Plug in a supported USB adapter.\n",
            prism::s().yellow().paint("\u{26a0}")));
        return;
    }

    ctx.layout.print("");
    for (i, info, is_open, role) in ctx.manager.adapters() {
        let status = match role {
            Some(AdapterRole::Scanner) => prism::s().green().bold().paint(" \u{2605} scanner"),
            Some(AdapterRole::Attack)  => prism::s().yellow().bold().paint(" \u{2605} attack"),
            None if is_open            => prism::s().cyan().paint(" \u{25cf} initialized"),
            None                       => prism::s().dim().paint(" \u{25cb} available"),
        };
        ctx.layout.print(&format!("  {} {} {}  {}",
            prism::badge(
                &format!("{}", i + 1),
                prism::BadgeVariant::Bracket,
                Some(|t| prism::s().cyan().bold().paint(t)),
            ),
            prism::s().bold().paint(info.name),
            prism::s().dim().paint(&format!("{}", info.chip)),
            status,
        ));
    }
    ctx.layout.print("");
    if ctx.manager.count() > 1 {
        ctx.layout.print(&format!("  {} Use {} to switch scanner adapter.",
            prism::s().dim().paint("tip:"),
            prism::s().cyan().paint("/adapter <N>")));
        ctx.layout.print("");
    }
}

/// Rescan USB bus for adapters.
fn rescan(ctx: &mut Ctx) {
    let sp = prism::spinner("Rescanning USB bus...", prism::SpinnerOptions {
        style: "dots",
        color: |t| prism::s().cyan().paint(t),
        ..Default::default()
    });
    match ctx.manager.scan_usb() {
        Ok(_) => {
            let count = ctx.manager.count();
            sp.done(Some(&format!("Found {} adapter{}",
                prism::s().green().bold().paint(&count.to_string()),
                if count == 1 { "" } else { "s" })));
            list(ctx);
        }
        Err(e) => {
            sp.fail(Some(&format!("USB scan failed: {}", e)));
        }
    }
}

/// Select adapter N (1-indexed). Hot-switch scanner if running.
fn select(ctx: &mut Ctx, n: usize) {
    let idx = n.saturating_sub(1); // 1-indexed for user
    if idx >= ctx.manager.count() {
        ctx.layout.print(&format!("  {} Adapter {} not found. {} detected.",
            prism::s().red().paint("\u{2717}"), n, ctx.manager.count()));
        return;
    }

    // Check if scanner is running
    let scanner_running = {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        state.focus_stack.find_by_name("scanner").is_some()
    };

    if scanner_running {
        // Hot-switch scanner to new adapter
        if ctx.manager.role(idx) == Some(AdapterRole::Scanner) {
            ctx.layout.print(&format!("  {} Adapter {} is already the scanner adapter.",
                prism::s().dim().paint("\u{25cf}"), n));
            return;
        }

        // Open new adapter if needed
        let new_shared = match ctx.open_adapter(idx) {
            Some(s) => s,
            None => return,
        };

        // Stop current scanner, restart on new adapter.
        // Get the Scanner Arc (preserves AP state), then remove the module.
        let scanner_arc = {
            let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
            let arc = state.focus_stack.find_as::<ScannerModule>("scanner")
                .map(|m| Arc::clone(&m.scanner));
            if let Some(pos) = state.focus_stack.find_by_name("scanner") {
                state.focus_stack.all()[pos].signal_stop();
                state.focus_stack.remove(pos);
            }
            arc
        };

        // Clear old scanner role
        if let Some((old_idx, _)) = ctx.manager.scanner_adapter() {
            ctx.manager.clear_role(old_idx, AdapterRole::Scanner);
        }

        if let Some(scanner) = scanner_arc {
            // Create new module with same scanner state (preserves AP list)
            let mut new_module = ScannerModule::new(scanner, ctx.store.clone());
            new_module.start(new_shared);

            // Assign new scanner role
            ctx.manager.assign_role(idx, AdapterRole::Scanner);

            {
                let mut state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
                state.focus_stack.push(Box::new(new_module));
                state.mode = Mode::Normal;
            }

            let name = ctx.manager.adapter_info(idx)
                .map(|a| a.name)
                .unwrap_or("unknown");
            ctx.layout.print(&format!("  {} Scanner switched to adapter {} \u{2014} {}",
                prism::s().green().paint("\u{2713}"),
                prism::s().bold().paint(&n.to_string()),
                prism::s().cyan().paint(name)));
        }
    } else {
        // No scanner running — just assign for next scan
        // If there was a previous scanner role, clear it
        if let Some((old_idx, _)) = ctx.manager.scanner_adapter() {
            ctx.manager.clear_role(old_idx, AdapterRole::Scanner);
        }
        ctx.manager.assign_role(idx, AdapterRole::Scanner);

        let name = ctx.manager.adapter_info(idx)
            .map(|a| a.name)
            .unwrap_or("unknown");
        ctx.layout.print(&format!("  {} Adapter {} selected \u{2014} {}. Start with {}.",
            prism::s().green().paint("\u{2713}"),
            prism::s().bold().paint(&n.to_string()),
            prism::s().cyan().paint(name),
            prism::s().cyan().paint("/scan")));
    }
}
