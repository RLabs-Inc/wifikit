pub mod info;
pub mod pmkid;
pub mod wps;
pub mod dos;
pub mod csa;
pub mod ap;
pub mod eap;
pub mod krack;
pub mod frag;
pub mod fuzz;
pub mod wpa3;
pub mod spectrum;

// ═══════════════════════════════════════════════════════════════════════════════
//  Shared visual helpers for attack views
// ═══════════════════════════════════════════════════════════════════════════════

use std::collections::VecDeque;
use prism::s;

/// Signal strength as compact 4-char bar characters, colored by quality.
/// Green ≥-50dBm, yellow ≥-70dBm, red below.
pub fn signal_bar(rssi: i8) -> String {
    let bars = match rssi {
        -50..=0   => "\u{2582}\u{2584}\u{2586}\u{2588}",
        -60..=-51 => "\u{2582}\u{2584}\u{2586}\u{2591}",
        -70..=-61 => "\u{2582}\u{2584}\u{2591}\u{2591}",
        -80..=-71 => "\u{2582}\u{2591}\u{2591}\u{2591}",
        _         => "\u{2591}\u{2591}\u{2591}\u{2591}",
    };
    let color_fn: fn(&str) -> String = match rssi {
        -50..=0   => |t| s().green().paint(t),
        -70..=-51 => |t| s().yellow().paint(t),
        _         => |t| s().red().paint(t),
    };
    color_fn(bars)
}

/// FPS sparkline — throughput history as Unicode block characters.
/// Each character is one sample at one of 8 heights, colored by throughput level.
/// Green ≥100fps, yellow ≥30fps, red <30fps.
pub fn fps_sparkline(samples: &VecDeque<f64>, width: usize) -> String {
    const BLOCKS: [char; 8] = ['\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}'];

    if samples.is_empty() {
        return s().dim().paint(&"\u{00b7}".repeat(width));
    }

    let n = samples.len();
    let start = if n > width { n - width } else { 0 };
    let visible = n - start;

    let max = samples.iter().skip(start).cloned().fold(100.0_f64, f64::max);

    let mut out = String::new();
    for &fps in samples.iter().skip(start) {
        let level = ((fps / max) * 7.0).round().clamp(0.0, 7.0) as usize;
        let ch = BLOCKS[level];
        let color: fn(&str) -> String = if fps >= 100.0 {
            |t| s().green().paint(t)
        } else if fps >= 30.0 {
            |t| s().yellow().paint(t)
        } else {
            |t| s().red().paint(t)
        };
        out.push_str(&color(&ch.to_string()));
    }

    let pad = width.saturating_sub(visible);
    if pad > 0 {
        out.push_str(&s().dim().paint(&"\u{00b7}".repeat(pad)));
    }
    out
}

/// TX delivery bar — dual-color bar showing ack% (green) and nack% (red).
/// Returns empty string if no TX feedback data.
pub fn tx_delivery_bar(tx: &crate::core::TxFeedbackSnapshot, bar_width: usize) -> String {
    if tx.total_reports == 0 {
        return String::new();
    }

    let ack_pct = tx.acked as f64 / tx.total_reports as f64;
    let ack_chars = (ack_pct * bar_width as f64).round() as usize;
    let nack_chars = bar_width.saturating_sub(ack_chars);

    fn green(t: &str) -> String { s().green().paint(t) }
    fn red(t: &str) -> String { s().red().paint(t) }

    let pct_val = (ack_pct * 100.0) as u64;
    let pct_label = if pct_val >= 95 {
        s().green().paint(&format!("{}%", pct_val))
    } else if pct_val >= 70 {
        s().yellow().paint(&format!("{}%", pct_val))
    } else {
        s().red().paint(&format!("{}%", pct_val))
    };

    format!("{}{} {}",
        green(&"\u{2588}".repeat(ack_chars)),
        red(&"\u{2591}".repeat(nack_chars)),
        pct_label,
    )
}

/// Format a TX stats line for attack views. Shows delivery bar + sent count + fps.
/// Returns None if no frames sent yet.
pub fn tx_stats_line(tx: &crate::core::TxFeedbackSnapshot, frames_sent: u64, fps: f64) -> Option<String> {
    if frames_sent == 0 { return None; }

    let bar = tx_delivery_bar(tx, 12);
    let sent = s().dim().paint(&format!("{} sent", prism::format_compact(frames_sent)));
    let fps_str = if fps > 0.0 {
        s().dim().paint(&format!(" \u{00b7} {:.0} fps", fps))
    } else { String::new() };

    if bar.is_empty() {
        Some(format!("  {}  {}{}", s().dim().paint("TX"), sent, fps_str))
    } else {
        Some(format!("  {} {}  {}{}", s().dim().paint("TX"), bar, sent, fps_str))
    }
}
