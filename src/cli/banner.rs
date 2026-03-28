// wifikit CLI banner — custom ASCII art with signal motif
//
// Hand-crafted FIGlet "ANSI Shadow" style lettering with WiFi signal
// waves radiating from an antenna source. Colored per-character for
// depth: bright cyan body, dim shadow, gradient signal arcs.
#![allow(dead_code)]
//
// Skipped when piped (respects prism::is_tty()).

/// Version string, sourced from Cargo.toml at compile time.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

// WiFi signal arcs — radiating upward from antenna source
const SIGNAL: &[&str] = &[
    "                       ╱ ╱ ╱ ╲ ╲ ╲",
    "                         ╱ ╱ ╲ ╲",
    "                           ╱ ╲",
    "                            ●",
];

// WIFIKIT in FIGlet "ANSI Shadow" — 6 rows × 50 columns
const NAME: &[&str] = &[
    "   ██╗    ██╗ ██╗ ███████╗ ██╗ ██╗  ██╗ ██╗ ████████╗",
    "   ██║    ██║ ██║ ██╔════╝ ██║ ██║ ██╔╝ ██║ ╚══██╔══╝",
    "   ██║ █╗ ██║ ██║ █████╗   ██║ █████╔╝  ██║    ██║   ",
    "   ██║███╗██║ ██║ ██╔══╝   ██║ ██╔═██╗  ██║    ██║   ",
    "   ╚███╔███╔╝ ██║ ██║      ██║ ██║  ██╗ ██║    ██║   ",
    "    ╚══╝╚══╝  ╚═╝ ╚═╝      ╚═╝ ╚═╝  ╚═╝ ╚═╝    ╚═╝   ",
];

/// Print the wifikit startup banner to stdout.
pub fn print_banner() {
    if !prism::is_tty() {
        return;
    }

    let width = prism::term_width() as usize;

    // Need at least 56 columns for the full banner
    if width < 56 {
        print_version_line();
        return;
    }

    prism::writeln("");

    // Signal arcs — gradient from dim (outer) to bright (inner)
    let signal_colors: &[fn(&str) -> String] = &[
        |t| prism::s().dim().paint(t),                    // outer arc — fading signal
        |t| prism::s().cyan().paint(t),                   // middle arc
        |t| prism::s().cyan().bold().paint(t),            // inner arc
        |t| prism::s().green().bold().paint(t),           // source dot — strong signal
    ];

    for (i, line) in SIGNAL.iter().enumerate() {
        prism::writeln(&signal_colors[i](line));
    }

    prism::writeln("");

    // Name — per-character coloring for depth effect
    // █ chars: bright cyan (body)
    // ╔═╗║╚╝ chars: dim (shadow gives 3D depth)
    for (row, line) in NAME.iter().enumerate() {
        let colored = color_name_line(line, row == NAME.len() - 1);
        prism::writeln(&colored);
    }

    prism::writeln("");

    // Subtitle
    prism::writeln(&format!(
        "   {}  {}",
        prism::s().green().bold().paint("WiFi Pentesting Research Lab"),
        prism::s().dim().paint(&format!("v{VERSION}")),
    ));

    // Divider
    prism::writeln(&prism::s().dim().paint(
        &format!("   {}", prism::divider("─", width.saturating_sub(6)))
    ));

    prism::writeln("");
}

/// Color a name line: bright cyan for block chars, dim for shadow/structure chars.
/// The last row (bottom shadow) gets extra dim treatment.
fn color_name_line(line: &str, is_bottom: bool) -> String {
    let mut result = String::with_capacity(line.len() * 4);
    let mut run = String::new();
    let mut is_block = false;

    for ch in line.chars() {
        let ch_is_block = ch == '█';
        let ch_is_shadow = matches!(ch, '╔' | '═' | '╗' | '║' | '╚' | '╝');

        if ch_is_block {
            if !is_block && !run.is_empty() {
                // Flush shadow/space run
                result.push_str(&flush_shadow_run(&run, is_bottom));
                run.clear();
            }
            is_block = true;
            run.push(ch);
        } else if ch_is_shadow {
            if is_block && !run.is_empty() {
                // Flush block run
                result.push_str(&flush_block_run(&run, is_bottom));
                run.clear();
            }
            is_block = false;
            run.push(ch);
        } else {
            // Space or other — flush current run, pass through
            if !run.is_empty() {
                if is_block {
                    result.push_str(&flush_block_run(&run, is_bottom));
                } else {
                    result.push_str(&flush_shadow_run(&run, is_bottom));
                }
                run.clear();
            }
            is_block = false;
            result.push(ch);
        }
    }

    // Flush remaining
    if !run.is_empty() {
        if is_block {
            result.push_str(&flush_block_run(&run, is_bottom));
        } else {
            result.push_str(&flush_shadow_run(&run, is_bottom));
        }
    }

    result
}

/// Render a run of block chars (█) — bright cyan, or dimmer on bottom row.
fn flush_block_run(run: &str, is_bottom: bool) -> String {
    if is_bottom {
        prism::s().cyan().paint(run)
    } else {
        prism::s().cyan().bold().paint(run)
    }
}

/// Render a run of shadow chars (╔═╗║╚╝) — dim for 3D depth effect.
fn flush_shadow_run(run: &str, _is_bottom: bool) -> String {
    prism::s().dim().paint(run)
}

/// Print a minimal one-line version header (for narrow terminals or piped output).
pub fn print_version_line() {
    prism::writeln(&format!(
        "{}  {}",
        prism::badge("wifikit", prism::BadgeVariant::Bracket, Some(|t| prism::s().cyan().bold().paint(t))),
        prism::s().dim().paint(&format!("v{VERSION}")),
    ));
}

/// Return the banner as plain text (no ANSI colors) for README / documentation.
pub fn banner_plain() -> String {
    let mut lines = Vec::new();
    lines.push(String::new());
    for line in SIGNAL {
        lines.push(line.to_string());
    }
    lines.push(String::new());
    for line in NAME {
        lines.push(line.to_string());
    }
    lines.push(String::new());
    lines.push(format!("   WiFi Pentesting Research Lab  v{VERSION}"));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_not_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_name_rows_consistent_count() {
        assert_eq!(NAME.len(), 6);
    }

    #[test]
    fn test_signal_rows_count() {
        assert_eq!(SIGNAL.len(), 4);
    }

    #[test]
    fn test_banner_plain_contains_name() {
        let plain = banner_plain();
        assert!(plain.contains("██╗"));
        assert!(plain.contains("WIFIKIT") || plain.contains("██║"));
    }

    #[test]
    fn test_banner_plain_contains_version() {
        let plain = banner_plain();
        assert!(plain.contains(VERSION));
    }

    #[test]
    fn test_print_version_line_no_panic() {
        print_version_line();
    }
}
