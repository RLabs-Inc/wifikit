//! Shared styling functions for the scanner CLI.
//!
//! RSSI color ranges, security classification colors, WiFi generation labels,
//! WPS indicators, and formatting helpers used across all scanner views.
//!
#![allow(dead_code)]
#![allow(unused_imports)]
//! All formatting delegates to prism-rs primitives. Domain-specific styling
//! (RSSI thresholds, security colors, etc.) lives here as thin wrappers.

use crate::core::Bandwidth;
use crate::store::WpsState;
use crate::protocol::ieee80211::{Security, WifiGeneration};

// Color helpers for prism callbacks (must be fn pointers, not closures)
fn green_color(t: &str) -> String { prism::s().green().paint(t) }
fn yellow_color(t: &str) -> String { prism::s().yellow().paint(t) }
fn red_color(t: &str) -> String { prism::s().red().paint(t) }
fn cyan_bold_color(t: &str) -> String { prism::s().cyan().bold().paint(t) }
fn cyan_color(t: &str) -> String { prism::s().cyan().paint(t) }

/// Pick a color function based on RSSI thresholds.
fn rssi_color(rssi: i8) -> fn(&str) -> String {
    if rssi >= -50 { green_color }
    else if rssi >= -70 { yellow_color }
    else { red_color }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RSSI — color-coded signal strength
// ═══════════════════════════════════════════════════════════════════════════════

/// Compact RSSI number for table columns: `-65` in green/yellow/red.
pub fn style_rssi(rssi: i8) -> String {
    rssi_color(rssi)(&format!("{rssi}"))
}

/// RSSI with unit for detail views: `-65 dBm` in color.
pub fn style_rssi_dbm(rssi: i8) -> String {
    let color = rssi_color(rssi);
    format!("{} {}", color(&format!("{rssi}")), prism::s().dim().paint("dBm"))
}

/// RSSI signal bar — smooth sub-character rendering via prism::render_progress_bar.
/// `bar_width` controls the number of character cells (default 10, use 4 for compact).
pub fn rssi_bar(rssi: i8, bar_width: usize) -> String {
    let normalized = ((rssi + 100).max(0).min(60) as u64 * 100) / 60;
    prism::render_progress_bar(normalized, &prism::RenderOptions {
        total: 100,
        width: bar_width,
        style: prism::BarStyle::Bar,
        color: Some(rssi_color(rssi)),
        smooth: true,
        empty_char: Some(" "),
    })
}

/// Combined RSSI number + bar for detail views: `-65 dBm ██████░░░░`
pub fn rssi_compact(rssi: i8) -> String {
    format!("{} {}", style_rssi_dbm(rssi), rssi_bar(rssi, 10))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Security — color-coded by protection level
// ═══════════════════════════════════════════════════════════════════════════════

/// Compact security label for table columns: `WPA2` / `WPA2-E` in color.
/// Uses short_name() (max 6 chars) to fit narrow SEC column.
pub fn style_security(sec: &Security) -> String {
    let text = sec.short_name();
    match sec {
        Security::Open => prism::s().red().bold().paint(text),
        Security::Wep => prism::s().red().paint(text),
        Security::Wpa => prism::s().yellow().paint(text),
        Security::Wpa2 | Security::Wpa2Enterprise => prism::s().green().paint(text),
        Security::Wpa3 | Security::Wpa3Enterprise => prism::s().cyan().bold().paint(text),
        Security::Owe => prism::s().cyan().paint(text),
    }
}

/// Full security label for detail views.
pub fn style_security_full(sec: &Security) -> String {
    let text = sec.name();
    match sec {
        Security::Open => prism::s().red().bold().paint(text),
        Security::Wep => prism::s().red().paint(text),
        Security::Wpa => prism::s().yellow().paint(text),
        Security::Wpa2 | Security::Wpa2Enterprise => prism::s().green().paint(text),
        Security::Wpa3 | Security::Wpa3Enterprise => prism::s().cyan().bold().paint(text),
        Security::Owe => prism::s().cyan().paint(text),
    }
}

/// Security as a bracket badge for detail views: `[WPA2]`, `[⚠ OPEN]`, `[⚠ WEP]`.
pub fn security_badge(sec: &Security) -> String {
    let (label, color_fn): (&str, fn(&str) -> String) = match sec {
        Security::Open => ("⚠ OPEN", red_color),
        Security::Wep => ("⚠ WEP", red_color),
        Security::Wpa => ("WPA", yellow_color),
        Security::Wpa2 => ("WPA2", green_color),
        Security::Wpa2Enterprise => ("WPA2-ENT", green_color),
        Security::Wpa3 => ("WPA3", cyan_bold_color),
        Security::Wpa3Enterprise => ("WPA3-ENT", cyan_bold_color),
        Security::Owe => ("OWE", cyan_color),
    };
    prism::badge(label, prism::BadgeVariant::Bracket, Some(color_fn))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WiFi generation
// ═══════════════════════════════════════════════════════════════════════════════

pub fn wifi_gen_short(wg: &WifiGeneration) -> &'static str {
    match wg {
        WifiGeneration::Legacy => "Lgcy",
        WifiGeneration::Wifi4 => "WiFi4",
        WifiGeneration::Wifi5 => "WiFi5",
        WifiGeneration::Wifi6 => "WiFi6",
        WifiGeneration::Wifi6e => "WiFi6E",
        WifiGeneration::Wifi7 => "WiFi7",
    }
}

pub fn style_wifi_gen(wg: &WifiGeneration) -> String {
    let text = wifi_gen_short(wg);
    match wg {
        WifiGeneration::Legacy => prism::s().dim().paint(text),
        WifiGeneration::Wifi4 => prism::s().white().paint(text),
        WifiGeneration::Wifi5 => prism::s().cyan().paint(text),
        WifiGeneration::Wifi6 | WifiGeneration::Wifi6e => prism::s().green().bold().paint(text),
        WifiGeneration::Wifi7 => prism::s().magenta().bold().paint(text),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  WPS indicator
// ═══════════════════════════════════════════════════════════════════════════════

/// WPS indicator for table columns: colored dot when enabled, empty when disabled.
/// Empty rows make the enabled ones pop out visually.
pub fn style_wps(wps: &WpsState) -> String {
    match wps {
        WpsState::None => String::new(),
        WpsState::Configured => prism::s().green().paint("●"),
        WpsState::NotConfigured => prism::s().yellow().paint("●"),
    }
}

/// WPS badge for detail views: `[WPS]` or `[WPS Configured]`.
pub fn wps_badge(wps: &WpsState) -> String {
    match wps {
        WpsState::None => String::new(),
        WpsState::Configured => prism::badge("WPS", prism::BadgeVariant::Bracket, Some(green_color)),
        WpsState::NotConfigured => prism::badge("WPS", prism::BadgeVariant::Bracket, Some(yellow_color)),
    }
}

pub fn wps_plain(wps: &WpsState) -> &'static str {
    match wps {
        WpsState::None => "",
        WpsState::Configured | WpsState::NotConfigured => "●",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Bandwidth display
// ═══════════════════════════════════════════════════════════════════════════════

pub fn bandwidth_str(bw: &Bandwidth) -> &'static str {
    match bw {
        Bandwidth::Bw20 => "20MHz",
        Bandwidth::Bw40 => "40MHz",
        Bandwidth::Bw80 => "80MHz",
        Bandwidth::Bw160 => "160MHz",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MFP (Management Frame Protection) styling
// ═══════════════════════════════════════════════════════════════════════════════

/// MFP status with leading icon for quick scanning.
pub fn style_mfp(required: bool, capable: bool) -> String {
    if required {
        format!("{} {}", prism::s().green().paint("✓"), prism::s().green().bold().paint("required"))
    } else if capable {
        format!("{} {}", prism::s().yellow().paint("~"), prism::s().yellow().paint("optional"))
    } else {
        format!("{} {}", prism::s().red().paint("✗"), prism::s().red().paint("none"))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Boolean feature indicators
// ═══════════════════════════════════════════════════════════════════════════════

pub fn yes_no(val: bool) -> String {
    if val {
        prism::s().green().paint("yes")
    } else {
        prism::s().dim().paint("no")
    }
}

pub fn check_mark(val: bool) -> String {
    if val {
        prism::s().green().paint("✓")
    } else {
        prism::s().dim().paint("✗")
    }
}

pub fn present_absent(val: bool) -> String {
    if val {
        prism::s().green().paint("present")
    } else {
        prism::s().dim().paint("absent")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Time formatting — delegates to prism::format_time / prism::format_bytes
// ═══════════════════════════════════════════════════════════════════════════════

/// Format a duration as human-readable elapsed time via prism::format_time.
pub fn format_elapsed(d: std::time::Duration) -> String {
    prism::format_time(d.as_millis() as u64)
}

/// Alias for format_elapsed.
pub fn format_elapsed_precise(d: std::time::Duration) -> String {
    format_elapsed(d)
}

/// Format byte count with proper units via prism::format_bytes.
pub fn format_bytes(bytes: u64) -> String {
    prism::format_bytes(bytes)
}

/// Format TSF timestamp (microseconds) as coarse uptime: "5m", "2h30m", "3d5h".
pub fn format_tsf_uptime(tsf: u64) -> String {
    let secs = tsf / 1_000_000;
    if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{}h", secs / 86400, (secs % 86400) / 3600)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Padding — delegates to prism::pad (ANSI-aware)
// ═══════════════════════════════════════════════════════════════════════════════

/// Pad styled text to target width, left-aligned.
/// The `_plain` parameter is ignored — prism::pad strips ANSI internally.
/// Kept for backward compatibility; prefer calling `prism::pad()` directly.
pub fn pad_right(styled: &str, target_width: usize, _plain: &str) -> String {
    prism::pad(styled, target_width, "left")
}

/// Pad styled text to target width, right-aligned.
/// The `_plain` parameter is ignored — prism::pad strips ANSI internally.
/// Kept for backward compatibility; prefer calling `prism::pad()` directly.
pub fn pad_left(styled: &str, target_width: usize, _plain: &str) -> String {
    prism::pad(styled, target_width, "right")
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Layout helpers — delegates to prism primitives
// ═══════════════════════════════════════════════════════════════════════════════

/// Key-value line for detail views: indented, bold key with colon, then value.
/// Bold keys are more readable than dim — the eye finds the label first,
/// then follows to the value.
pub fn kv(key: &str, value: &str, indent: usize) -> String {
    format!(
        "{}{}  {}",
        " ".repeat(indent),
        prism::s().bold().paint(&format!("{}:", key)),
        value,
    )
}

/// Section header with centered dashes: `──── Title ────`
pub fn section_header(title: &str, indent: usize) -> String {
    let w = prism::term_width() as usize;
    let available = w.saturating_sub(indent);
    let title_styled = prism::s().bold().paint(title);
    let title_vis = prism::measure_width(title);
    let text_section = title_vis + 2;
    if text_section + 2 > available {
        return format!("{}{}", " ".repeat(indent), title_styled);
    }
    let remaining = available.saturating_sub(text_section);
    let left = remaining / 2;
    let right = remaining - left;
    format!("{}{} {} {}",
        " ".repeat(indent),
        prism::s().dim().paint(&prism::divider("─", left)),
        title_styled,
        prism::s().dim().paint(&prism::divider("─", right)),
    )
}

/// Heavy section header for critical sections: `═══ Vulnerabilities ═══`
pub fn section_header_heavy(title: &str, indent: usize) -> String {
    let w = prism::term_width() as usize;
    let available = w.saturating_sub(indent);
    let title_styled = prism::s().bold().paint(title);
    let title_vis = prism::measure_width(title);
    let text_section = title_vis + 2;
    if text_section + 2 > available {
        return format!("{}{}", " ".repeat(indent), title_styled);
    }
    let remaining = available.saturating_sub(text_section);
    let left = remaining / 2;
    let right = remaining - left;
    format!("{}{} {} {}",
        " ".repeat(indent),
        prism::s().dim().paint(&prism::divider("═", left)),
        title_styled,
        prism::s().dim().paint(&prism::divider("═", right)),
    )
}

/// Horizontal rule via prism::divider.
pub fn hr(width: usize, indent: usize) -> String {
    format!(
        "{}{}",
        " ".repeat(indent),
        prism::s().dim().paint(&prism::divider("─", width.saturating_sub(indent))),
    )
}

/// Density/activity bar for channel view — smooth rendering via prism progress bar.
pub fn density_bar(value: u32, max_value: u32, max_width: usize) -> String {
    if max_value == 0 {
        return String::new();
    }
    let color_fn: fn(&str) -> String = if value > max_value * 2 / 3 {
        red_color
    } else if value > max_value / 3 {
        yellow_color
    } else {
        green_color
    };
    prism::render_progress_bar(value as u64, &prism::RenderOptions {
        total: max_value as u64,
        width: max_width,
        style: prism::BarStyle::Bar,
        color: Some(color_fn),
        smooth: true,
        empty_char: Some(" "),
    })
}
