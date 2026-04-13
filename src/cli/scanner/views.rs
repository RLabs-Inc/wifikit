//! Scan-level view renderers — APs, Clients, Probes, Channels, Events, Handshakes.
//!
//! Each view renders into a Vec<String> that gets placed in the Layout active zone.
//! All renderers take a ScanSnapshot (already cloned from Arc<Mutex>) so no locks
//! are held during rendering.

use prism::{s, truncate, ScrollCol, ScrollTableConfig, scroll_table};

use crate::store::{EventDetail, ScanEvent, ScanEventType};
use crate::protocol::eapol::HandshakeQuality;

use super::style::*;
use super::{FilterBand, FilterMenuItem, ScanFilter, ScanSnapshot, SortField};

// ═══════════════════════════════════════════════════════════════════════════════
//  APs View — the main AP table
// ═══════════════════════════════════════════════════════════════════════════════

// ── Shared column widths ─────────────────────────────────────────────────
const COL_SEL: usize = 2;       // ▶ + space
const COL_RSSI: usize = 9;      // "-65 ██▌░" = number(4) + space(1) + bar(4) — default for bar views
const COL_RSSI_BAR: usize = 4;  // smooth sub-character bar width
const COL_SEP: usize = 2;       // "  " separator between columns

// ── APs view column widths ──────────────────────────────────────────────
const AP_COL_RSSI: usize = 13;  // "-65 ▁▃█▅▃▅▇▃" = number(4) + space(1) + sparkline(8)
const COL_SPARKLINE: usize = 8; // sparkline character width
const COL_CLI: usize = 3;       // client count
const COL_CAP: usize = 2;       // capture indicator: PH / P· / ·H
const COL_SSID_MIN: usize = 8;  // minimum SSID width
const COL_SSID_MAX: usize = 32; // WiFi spec max (32 bytes)
const COL_SEC: usize = 6;       // security (short_name: WPA2-E max)
const COL_WPS: usize = 3;       // WPS dot (centered)
const COL_GEN: usize = 5;       // WiFi generation
const COL_CH: usize = 3;        // channel number
const COL_VENDOR: usize = 12;   // vendor name (capped, truncated)
const COL_BSSID: usize = 17;    // XX:XX:XX:XX:XX:XX

/// Determine which optional columns are visible based on terminal width.
/// Returns (show_cap, show_wps, show_sec, show_gen, show_ch, show_bssid, show_vendor).
///
/// Column order: SSID RSSI CLI [CAP] [WPS] [SEC] [GEN] [CH] [BSSID] [VENDOR]
/// Core (never drop): SSID, RSSI (with sparkline), CLI
/// Drop order (first to go): VENDOR → BSSID → CH → GEN → WPS → SEC → CAP
fn auto_columns(width: usize) -> (bool, bool, bool, bool, bool, bool, bool) {
    let core = 1 + COL_SEL + COL_SSID_MIN + AP_COL_RSSI + COL_CLI + (2 * COL_SEP);
    let budget = width.saturating_sub(core);

    let mut remaining = budget;

    // Add in reverse drop order (most important optional first)
    let show_cap = remaining >= COL_CAP + COL_SEP;
    if show_cap { remaining -= COL_CAP + COL_SEP; }
    let show_sec = remaining >= COL_SEC + COL_SEP;
    if show_sec { remaining -= COL_SEC + COL_SEP; }
    let show_wps = remaining >= COL_WPS + COL_SEP;
    if show_wps { remaining -= COL_WPS + COL_SEP; }
    let show_gen = remaining >= COL_GEN + COL_SEP;
    if show_gen { remaining -= COL_GEN + COL_SEP; }
    let show_ch = remaining >= COL_CH + COL_SEP;
    if show_ch { remaining -= COL_CH + COL_SEP; }
    let show_bssid = remaining >= COL_BSSID + COL_SEP;
    if show_bssid { remaining -= COL_BSSID + COL_SEP; }
    let show_vendor = remaining >= COL_VENDOR + COL_SEP;

    (show_cap, show_wps, show_sec, show_gen, show_ch, show_bssid, show_vendor)
}

/// Render the APs table view. Returns the data row capacity (for scroll bounds).
pub fn render_aps(
    snap: &ScanSnapshot,
    width: u16,
    selected: usize,
    scroll_offset: usize,
    max_rows: usize,
    sort_field: super::SortField,
    filter: &super::ScanFilter,
    lines: &mut Vec<String>,
) -> usize {
    let w = width as usize;
    let (show_cap, show_wps, show_sec, show_gen, show_ch, show_bssid, show_vendor) = auto_columns(w);

    // Calculate SSID width: takes remaining space after fixed columns
    // indent(1) + cursor merged into SSID(COL_SEL) + RSSI + CLI + separators
    let mut fixed = 1 + COL_SEL + AP_COL_RSSI + COL_CLI;
    let mut sep_count = 2; // ssid|rssi, rssi|cli
    if show_cap { fixed += COL_CAP; sep_count += 1; }
    if show_wps { fixed += COL_WPS; sep_count += 1; }
    if show_sec { fixed += COL_SEC; sep_count += 1; }
    if show_gen { fixed += COL_GEN; sep_count += 1; }
    if show_ch { fixed += COL_CH; sep_count += 1; }
    if show_bssid { fixed += COL_BSSID; sep_count += 1; }
    if show_vendor { fixed += COL_VENDOR; sep_count += 1; }
    fixed += sep_count * COL_SEP;

    let ssid_w = w.saturating_sub(fixed).max(COL_SSID_MIN).min(COL_SSID_MAX);

    // ── Column definitions ───────────────────────────────────────────────
    // Cursor (▶/space) is merged into the SSID cell — no gap between them
    let ssid_col_w = COL_SEL + ssid_w; // cursor(2) + ssid text
    let mut cols = vec![
        ScrollCol::new("  SSID", ssid_col_w),
        ScrollCol::new("RSSI", AP_COL_RSSI),
        ScrollCol::right("CLI", COL_CLI),
    ];
    if show_cap { cols.push(ScrollCol::center("HS", COL_CAP)); }
    if show_wps { cols.push(ScrollCol::center("WPS", COL_WPS)); }
    if show_sec { cols.push(ScrollCol::new("SEC", COL_SEC)); }
    if show_gen { cols.push(ScrollCol::new("GEN", COL_GEN)); }
    if show_ch { cols.push(ScrollCol::right("CH", COL_CH)); }
    if show_bssid { cols.push(ScrollCol::new("BSSID", COL_BSSID)); }
    if show_vendor { cols.push(ScrollCol::new("VENDOR", COL_VENDOR)); }

    // ── Data rows ────────────────────────────────────────────────────────
    let mut data_rows: Vec<Vec<String>> = Vec::with_capacity(snap.aps.len());

    for (i, ap) in snap.aps.iter().enumerate() {
        let is_sel = i == selected;

        // Cursor + SSID merged into one cell: "▶ NetworkName" or "  NetworkName"
        let ssid_text = if ap.is_hidden || ap.ssid.is_empty() {
            s().dim().italic().paint("<hidden>")
        } else {
            let t = truncate(&ap.ssid, ssid_w, "…");
            if is_sel { s().cyan().bold().paint(&t) } else { s().bold().paint(&t) }
        };
        let ssid_cell = if is_sel {
            format!("{} {}", s().cyan().bold().paint("▶"), ssid_text)
        } else {
            format!("  {}", ssid_text)
        };

        // Sparkline + RSSI number (visual pattern first, exact value second)
        let spark = rssi_sparkline(&ap.rssi_samples, COL_SPARKLINE);
        let num = style_rssi(ap.rssi);
        let rssi_combined = format!("{} {}", spark, prism::pad(&num, 4, "left"));

        let cli_str = if ap.client_count > 0 {
            let styled = format!("{:>3}", ap.client_count);
            if is_sel { s().cyan().bold().paint(&styled) } else { s().bold().paint(&styled) }
        } else {
            String::new()
        };

        let mut row = vec![ssid_cell, rssi_combined, cli_str];

        if show_cap { row.push(style_capture(&ap.handshake_quality, ap.has_pmkid)); }
        if show_wps { row.push(style_wps(&ap.wps_state)); }
        if show_sec { row.push(style_security(&ap.security)); }
        if show_gen { row.push(style_wifi_gen(&ap.wifi_gen)); }
        if show_ch { row.push(format!("{}", ap.channel)); }
        if show_bssid {
            let bssid_str = format!("{}", ap.bssid);
            let bssid = if is_sel { s().cyan().bold().paint(&bssid_str) } else { s().bold().paint(&bssid_str) };
            row.push(bssid);
        }
        if show_vendor {
            let vendor_display = if ap.vendor.is_empty() {
                s().dim().paint("—")
            } else {
                s().dim().paint(&truncate(&ap.vendor, COL_VENDOR, "…"))
            };
            row.push(vendor_display);
        }

        data_rows.push(row);
    }

    // ── Footer hints ─────────────────────────────────────────────────────
    let mut hints = vec![
        format!("{} scroll", s().dim().paint("j/k")),
        format!("{} detail", s().dim().paint("Enter")),
        format!("{} views", s().dim().paint("Tab")),
    ];
    if sort_field != super::SortField::Rssi {
        hints.push(format!("{} {}", s().dim().paint("sort:"), s().yellow().paint(sort_field.label())));
    } else {
        hints.push(format!("{} sort", s().dim().paint("S")));
    }
    let fc = filter.active_count();
    if fc > 0 {
        let mut active_filters = Vec::new();
        if let Some(band) = filter.band { active_filters.push(band.label()); }
        if filter.wps_only { active_filters.push("WPS"); }
        if filter.hidden_only { active_filters.push("hidden"); }
        hints.push(format!("{} {}", s().dim().paint("filter:"), s().yellow().paint(&active_filters.join("+"))));
    } else {
        hints.push(format!("{} filter", s().dim().paint("F")));
    }
    let footer = vec![
        String::new(),
        format!("  {}", hints.join(&s().dim().paint(" │ "))),
        String::new(),
    ];

    // ── Render via prism::scroll_table ───────────────────────────────────
    let result = scroll_table(&ScrollTableConfig {
        columns: &cols,
        rows: &data_rows,
        height: max_rows,
        scroll_offset,
        separator: "  ",
        indent: 1,
        footer: &footer,
        empty_message: Some("No APs discovered yet. Waiting for beacons..."),
    });

    let capacity = result.capacity;
    lines.extend(result.lines);
    capacity
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Sort Menu — inline overlay for choosing sort field
// ═══════════════════════════════════════════════════════════════════════════════

pub fn render_sort_menu(
    current_field: SortField,
    current_ascending: bool,
    cursor: usize,
    _width: u16,
    _max_rows: usize,
    lines: &mut Vec<String>,
) {
    lines.push(String::new());
    lines.push(format!("  {}", s().bold().paint("Sort by:")));
    lines.push(String::new());

    for (i, field) in SortField::ALL.iter().enumerate() {
        let is_cursor = i == cursor;
        let is_current = *field == current_field;

        let pointer = if is_cursor { s().cyan().bold().paint("\u{25b6} ") } else { "  ".to_string() };

        let label = field.label();
        let styled_label = if is_cursor {
            s().cyan().bold().paint(label)
        } else if is_current {
            s().bold().paint(label)
        } else {
            s().dim().paint(label)
        };

        // Show direction indicator for current sort field
        let direction = if is_current {
            let arrow = if current_ascending { "\u{2191}" } else { "\u{2193}" };
            format!(" {}", s().yellow().paint(arrow))
        } else {
            String::new()
        };

        lines.push(format!("  {}  {}{}", pointer, styled_label, direction));
    }

    lines.push(String::new());
    lines.push(format!("  {}  {}  {}",
        format!("{} navigate", s().dim().paint("j/k")),
        format!("{} select", s().dim().paint("Enter")),
        format!("{} cancel", s().dim().paint("Esc")),
    ));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Filter Menu — inline overlay for toggling AP filters
// ═══════════════════════════════════════════════════════════════════════════════

pub fn render_filter_menu(
    filter: &ScanFilter,
    cursor: usize,
    _width: u16,
    _max_rows: usize,
    lines: &mut Vec<String>,
) {
    lines.push(String::new());
    lines.push(format!("  {}", s().bold().paint("Filter APs:")));
    lines.push(String::new());

    for (i, item) in FilterMenuItem::ALL.iter().enumerate() {
        let is_cursor = i == cursor;
        let pointer = if is_cursor { s().cyan().bold().paint("\u{25b6} ") } else { "  ".to_string() };

        let (label, value) = match item {
            FilterMenuItem::Band => {
                let val = match filter.band {
                    None => s().dim().paint("All"),
                    Some(FilterBand::Band2g) => s().yellow().paint("2.4 GHz"),
                    Some(FilterBand::Band5g) => s().yellow().paint("5 GHz"),
                };
                ("Band", val)
            }
            FilterMenuItem::Security => {
                let val = match filter.security {
                    None => s().dim().paint("All"),
                    Some(sec) => s().yellow().paint(sec.name()),
                };
                ("Security", val)
            }
            FilterMenuItem::WpsOnly => {
                let val = if filter.wps_only {
                    s().green().paint("\u{2713} Yes")
                } else {
                    s().dim().paint("No")
                };
                ("WPS Only", val)
            }
            FilterMenuItem::HiddenOnly => {
                let val = if filter.hidden_only {
                    s().green().paint("\u{2713} Yes")
                } else {
                    s().dim().paint("No")
                };
                ("Hidden Only", val)
            }
            FilterMenuItem::WifiGen => {
                let val = match filter.wifi_gen {
                    None => s().dim().paint("All"),
                    Some(wg) => s().yellow().paint(wg.name()),
                };
                ("WiFi Gen", val)
            }
            FilterMenuItem::MinClients => {
                let val = if filter.min_clients == 0 {
                    s().dim().paint("Any")
                } else {
                    s().yellow().paint(&format!("{}", filter.min_clients))
                };
                ("Min Clients", val)
            }
        };

        let styled_label = if is_cursor {
            s().cyan().bold().paint(label)
        } else {
            s().bold().paint(label)
        };

        lines.push(format!("  {}  {}  {}", pointer, pad_right(&styled_label, 14, label), value));
    }

    lines.push(String::new());

    let fc = filter.active_count();
    if fc > 0 {
        lines.push(format!("  {} {} active",
            s().yellow().bold().paint(&format!("{}", fc)),
            s().dim().paint(if fc == 1 { "filter" } else { "filters" }),
        ));
    }

    lines.push(format!("  {}  {}  {}  {}",
        format!("{} navigate", s().dim().paint("j/k")),
        format!("{} toggle", s().dim().paint("Enter")),
        format!("{} clear all", s().dim().paint("x")),
        format!("{} close", s().dim().paint("Esc")),
    ));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Clients View — all tracked stations across all APs
// ═══════════════════════════════════════════════════════════════════════════════

// Client column widths
const CLI_COL_MAC: usize = 17;     // XX:XX:XX:XX:XX:XX
const CLI_COL_AP_MIN: usize = 8;   // minimum AP name width
const CLI_COL_AP_MAX: usize = 20;  // maximum AP name width
const CLI_COL_FRAMES: usize = 7;   // frame count
const CLI_COL_DATA: usize = 7;     // data bytes (e.g. "14.6 KB")
const CLI_COL_GEN: usize = 5;      // WiFi generation
const CLI_COL_PS: usize = 2;       // power save flag
const CLI_COL_PROBES: usize = 6;   // probe count
const CLI_COL_VENDOR: usize = 12;  // vendor name
const CLI_COL_AGE: usize = 4;      // last-seen age ("3s", "1m", "5m")

/// Adaptive columns for Clients table.
/// Returns (show_data, show_gen, show_ps, show_probes, show_age, show_vendor).
///
/// Core (never drop): MAC, AP, RSSI, FRAMES
/// Drop order (first to go): VENDOR → AGE → PS → GEN → DATA → PROBES
fn auto_columns_clients(width: usize) -> (bool, bool, bool, bool, bool, bool) {
    let core = 1 + COL_SEL + CLI_COL_MAC + CLI_COL_AP_MIN + AP_COL_RSSI + CLI_COL_FRAMES + (3 * COL_SEP);
    let budget = width.saturating_sub(core);
    let mut remaining = budget;

    // Add in reverse drop order (most important optional first)
    let show_probes = remaining >= CLI_COL_PROBES + COL_SEP;
    if show_probes { remaining -= CLI_COL_PROBES + COL_SEP; }
    let show_data = remaining >= CLI_COL_DATA + COL_SEP;
    if show_data { remaining -= CLI_COL_DATA + COL_SEP; }
    let show_gen = remaining >= CLI_COL_GEN + COL_SEP;
    if show_gen { remaining -= CLI_COL_GEN + COL_SEP; }
    let show_ps = remaining >= CLI_COL_PS + COL_SEP;
    if show_ps { remaining -= CLI_COL_PS + COL_SEP; }
    let show_age = remaining >= CLI_COL_AGE + COL_SEP;
    if show_age { remaining -= CLI_COL_AGE + COL_SEP; }
    let show_vendor = remaining >= CLI_COL_VENDOR + COL_SEP;

    (show_data, show_gen, show_ps, show_probes, show_age, show_vendor)
}

pub fn render_clients(
    snap: &ScanSnapshot,
    width: u16,
    selected: usize,
    scroll_offset: usize,
    max_rows: usize,
    lines: &mut Vec<String>,
) -> usize {
    let w = width as usize;
    let (show_data, show_gen, show_ps, show_probes, show_age, show_vendor) = auto_columns_clients(w);

    // Sort: associated first, then strongest signal (RSSI descending)
    // Closest client = best target for deauth/capture
    let mut stations = snap.stations.clone();
    stations.sort_by(|a, b| {
        b.is_associated.cmp(&a.is_associated)
            .then(b.rssi.cmp(&a.rssi))
    });

    // AP column absorbs remaining width (like SSID in APs table)
    let mut fixed = 1 + COL_SEL + CLI_COL_MAC + AP_COL_RSSI + CLI_COL_FRAMES;
    let mut sep_count = 3; // mac|ap, ap|rssi, rssi|frames
    if show_data { fixed += CLI_COL_DATA; sep_count += 1; }
    if show_gen { fixed += CLI_COL_GEN; sep_count += 1; }
    if show_ps { fixed += CLI_COL_PS; sep_count += 1; }
    if show_probes { fixed += CLI_COL_PROBES; sep_count += 1; }
    if show_age { fixed += CLI_COL_AGE; sep_count += 1; }
    if show_vendor { fixed += CLI_COL_VENDOR; sep_count += 1; }
    fixed += sep_count * COL_SEP;

    let ap_w = w.saturating_sub(fixed).max(CLI_COL_AP_MIN).min(CLI_COL_AP_MAX);

    // Build columns
    let mut cols = vec![
        ScrollCol::new("  MAC", COL_SEL + CLI_COL_MAC),
        ScrollCol::new("AP", ap_w),
        ScrollCol::new("RSSI", AP_COL_RSSI),
        ScrollCol::right("FRAMES", CLI_COL_FRAMES),
    ];
    if show_data { cols.push(ScrollCol::right("DATA", CLI_COL_DATA)); }
    if show_gen { cols.push(ScrollCol::new("GEN", CLI_COL_GEN)); }
    if show_ps { cols.push(ScrollCol::center("PS", CLI_COL_PS)); }
    if show_probes { cols.push(ScrollCol::right("PROBES", CLI_COL_PROBES)); }
    if show_age { cols.push(ScrollCol::right("AGE", CLI_COL_AGE)); }
    if show_vendor { cols.push(ScrollCol::new("VENDOR", CLI_COL_VENDOR)); }

    // Build data rows
    let mut data_rows: Vec<Vec<String>> = Vec::with_capacity(stations.len());

    for (i, sta) in stations.iter().enumerate() {
        let is_sel = i == selected;

        // MAC — yellow for randomized, cyan for selected, bold white otherwise
        let mac_str = format!("{}", sta.mac);
        let mac_styled = if sta.mac.is_locally_administered() {
            s().yellow().paint(&mac_str)
        } else if is_sel {
            s().cyan().bold().paint(&mac_str)
        } else {
            s().bold().paint(&mac_str)
        };
        let mac_cell = if is_sel {
            format!("{} {}", s().cyan().bold().paint("▶"), mac_styled)
        } else {
            format!("  {}", mac_styled)
        };

        // AP — SSID if known, BSSID dimmed if hidden, italic if unassociated
        let ap_display = if let Some(ref bssid) = sta.bssid {
            if let Some(ap) = snap.aps.iter().find(|a| &a.bssid == bssid) {
                if ap.ssid.is_empty() {
                    s().dim().paint(&truncate(&format!("{}", bssid), ap_w, "…"))
                } else {
                    let t = truncate(&ap.ssid, ap_w, "…");
                    if is_sel { s().cyan().bold().paint(&t) } else { t }
                }
            } else {
                s().dim().paint(&truncate(&format!("{}", bssid), ap_w, "…"))
            }
        } else {
            s().dim().italic().paint("(unassoc)")
        };

        // RSSI — sparkline + number (same pattern as APs table)
        let spark = rssi_sparkline(&sta.rssi_samples, COL_SPARKLINE);
        let num = style_rssi(sta.rssi);
        let rssi_combined = format!("{} {}", spark, prism::pad(&num, 4, "left"));

        // Frames — activity indicator, cyan when selected
        let frames = {
            let f = format!("{}", sta.frame_count);
            if is_sel { s().cyan().bold().paint(&f) } else { f }
        };

        let mut row = vec![mac_cell, ap_display, rssi_combined, frames];

        // DATA — bytes transferred
        if show_data {
            let d = format_bytes(sta.data_bytes);
            row.push(if is_sel { s().cyan().bold().paint(&d) } else { d });
        }

        // GEN — WiFi generation from fingerprinting
        if show_gen {
            row.push(if sta.wifi_gen != crate::protocol::ieee80211::WifiGeneration::Legacy {
                style_wifi_gen(&sta.wifi_gen)
            } else {
                String::new()
            });
        }

        // PS — power save flag
        if show_ps {
            row.push(if sta.power_save { s().yellow().paint("Z") } else { String::new() });
        }

        // Probes — only show when > 0, bold to catch attention
        if show_probes {
            row.push(if sta.probe_ssid_count > 0 {
                let p = format!("{}", sta.probe_ssid_count);
                if is_sel { s().cyan().bold().paint(&p) } else { s().bold().paint(&p) }
            } else {
                String::new()
            });
        }

        // AGE — time since last seen, green when fresh, dim when stale
        if show_age {
            row.push(format_age(sta.last_seen));
        }

        // Vendor — dimmed, truncated
        if show_vendor {
            row.push(if sta.vendor.is_empty() {
                String::new()
            } else {
                s().dim().paint(&truncate(&sta.vendor, CLI_COL_VENDOR, "…"))
            });
        }

        data_rows.push(row);
    }

    // Footer hints
    let mut hint_parts = vec![
        format!("{} scroll", s().dim().paint("j/k")),
        format!("{} detail", s().dim().paint("Enter")),
        format!("{} = randomized", s().yellow().paint("MAC")),
    ];
    if show_ps {
        hint_parts.push(format!("{} = sleep", s().yellow().paint("Z")));
    }

    let footer = vec![
        String::new(),
        format!("  {}", hint_parts.join(&s().dim().paint(" │ "))),
        String::new(),
    ];

    let result = scroll_table(&ScrollTableConfig {
        columns: &cols,
        rows: &data_rows,
        height: max_rows,
        scroll_offset,
        separator: "  ",
        indent: 1,
        footer: &footer,
        empty_message: Some("No stations tracked yet."),
    });

    let capacity = result.capacity;
    lines.extend(result.lines);
    capacity
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Probes View — probe requests grouped by station
// ═══════════════════════════════════════════════════════════════════════════════

// Probe column widths
const PRB_COL_SSID_MIN: usize = 10; // minimum probed SSID width
const PRB_COL_SSID_MAX: usize = 28; // maximum probed SSID width
const PRB_COL_COUNT: usize = 5;     // probe count
const PRB_COL_CH: usize = 3;        // channel
const PRB_COL_FIRST: usize = 10;    // "first seen" timestamp
const PRB_COL_LAST: usize = 10;     // "last seen" timestamp

/// Adaptive columns for Probes table.
/// Returns (show_ch, show_first, show_last).
///
/// Core (never drop): STATION, SSID, RSSI, COUNT
/// Drop order (first to go): FIRST SEEN → CH → LAST SEEN
fn auto_columns_probes(width: usize) -> (bool, bool, bool) {
    let core = 1 + COL_SEL + 17 + PRB_COL_SSID_MIN + COL_RSSI + PRB_COL_COUNT + (3 * COL_SEP);
    let budget = width.saturating_sub(core);
    let mut remaining = budget;

    let show_last = remaining >= PRB_COL_LAST + COL_SEP;
    if show_last { remaining -= PRB_COL_LAST + COL_SEP; }
    let show_ch = remaining >= PRB_COL_CH + COL_SEP;
    if show_ch { remaining -= PRB_COL_CH + COL_SEP; }
    let show_first = remaining >= PRB_COL_FIRST + COL_SEP;

    (show_ch, show_first, show_last)
}

pub fn render_probes(
    snap: &ScanSnapshot,
    width: u16,
    selected: usize,
    scroll_offset: usize,
    max_rows: usize,
    lines: &mut Vec<String>,
) -> usize {
    let w = width as usize;
    let (show_ch, show_first, show_last) = auto_columns_probes(w);

    // Sort probes: most recent first
    let mut probes = snap.probes.clone();
    probes.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

    // SSID absorbs remaining width
    let mut fixed = 1 + COL_SEL + 17 + COL_RSSI + PRB_COL_COUNT;
    let mut sep_count = 3; // station|ssid, ssid|rssi, rssi|count
    if show_ch { fixed += PRB_COL_CH; sep_count += 1; }
    if show_first { fixed += PRB_COL_FIRST; sep_count += 1; }
    if show_last { fixed += PRB_COL_LAST; sep_count += 1; }
    fixed += sep_count * COL_SEP;

    let ssid_w = w.saturating_sub(fixed).max(PRB_COL_SSID_MIN).min(PRB_COL_SSID_MAX);

    let mut cols = vec![
        ScrollCol::new("  STATION", COL_SEL + 17),
        ScrollCol::new("SSID", ssid_w),
        ScrollCol::new("RSSI", COL_RSSI),
        ScrollCol::right("COUNT", PRB_COL_COUNT),
    ];
    if show_ch { cols.push(ScrollCol::right("CH", PRB_COL_CH)); }
    if show_first { cols.push(ScrollCol::new("FIRST SEEN", PRB_COL_FIRST)); }
    if show_last { cols.push(ScrollCol::new("LAST SEEN", PRB_COL_LAST)); }

    let mut data_rows: Vec<Vec<String>> = Vec::with_capacity(probes.len());

    for (i, probe) in probes.iter().enumerate() {
        let is_sel = i == selected;

        // STATION — yellow for randomized MAC, cyan for selected
        let mac_str = format!("{}", probe.sta_mac);
        let is_rand = probe.sta_mac.is_locally_administered();
        let mac_styled = if is_rand {
            s().yellow().paint(&mac_str)
        } else if is_sel {
            s().cyan().bold().paint(&mac_str)
        } else {
            s().bold().paint(&mac_str)
        };
        let mac_cell = if is_sel {
            format!("{} {}", s().cyan().bold().paint("▶"), mac_styled)
        } else if is_rand {
            format!("{} {}", s().yellow().dim().paint("R"), mac_styled)
        } else {
            format!("  {}", mac_styled)
        };

        // SSID — the probed network name, cyan when selected
        let ssid_display = if probe.ssid.is_empty() {
            s().dim().italic().paint("(wildcard)")
        } else {
            let t = truncate(&probe.ssid, ssid_w, "…");
            if is_sel { s().cyan().bold().paint(&t) } else { s().bold().paint(&t) }
        };

        // RSSI — number + bar
        let num = style_rssi(probe.rssi);
        let bar = rssi_bar(probe.rssi, COL_RSSI_BAR);
        let rssi_combined = format!("{} {}", prism::pad(&num, 4, "right"), bar);

        // COUNT — cyan when selected
        let count = {
            let c = format!("{}", probe.count);
            if is_sel { s().cyan().bold().paint(&c) } else { c }
        };

        let mut row = vec![mac_cell, ssid_display, rssi_combined, count];

        if show_ch { row.push(format!("{}", probe.channel)); }
        if show_first {
            row.push(s().dim().paint(&format_elapsed(probe.first_seen.elapsed())));
        }
        if show_last {
            row.push(s().dim().paint(&format!("{} ago", format_elapsed(probe.last_seen.elapsed()))));
        }

        data_rows.push(row);
    }

    let footer = vec![
        String::new(),
        format!("  {}",
            vec![
                format!("{} scroll", s().dim().paint("j/k")),
                format!("{} client detail", s().dim().paint("Enter")),
                format!("{} views", s().dim().paint("Tab")),
                format!("{} total", s().bold().paint(&probes.len().to_string())),
            ].join(&s().dim().paint(" │ ")),
        ),
        String::new(),
    ];

    let result = scroll_table(&ScrollTableConfig {
        columns: &cols,
        rows: &data_rows,
        height: max_rows,
        scroll_offset,
        separator: "  ",
        indent: 1,
        footer: &footer,
        empty_message: Some("No probe requests captured yet."),
    });

    let capacity = result.capacity;
    lines.extend(result.lines);
    capacity
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Channels View — per-channel RF environment
// ═══════════════════════════════════════════════════════════════════════════════

// Channel column widths
const CHN_COL_DENSITY: usize = 12;  // density bar width
const CHN_COL_FRAMES: usize = 8;    // frame count
const CHN_COL_FPS: usize = 6;       // frames per second
const CHN_COL_UTIL: usize = 5;      // utilization % ("99.9")
const CHN_COL_NOISE: usize = 4;     // noise floor ("-95")

/// Adaptive columns for Channels table.
/// Returns (show_frames, show_fps, show_util, show_noise).
///
/// Core (never drop): CH, BAND, APs, STAs, RETRY%, DENSITY
/// Drop order (first to go): NOISE → FRAMES → FPS → UTIL
fn auto_columns_channels(width: usize) -> (bool, bool, bool, bool) {
    let core = 1 + COL_SEL + 3 + 4 + 4 + 4 + 6 + CHN_COL_DENSITY + (5 * COL_SEP);
    let budget = width.saturating_sub(core);
    let mut remaining = budget;

    let show_util = remaining >= CHN_COL_UTIL + COL_SEP;
    if show_util { remaining -= CHN_COL_UTIL + COL_SEP; }
    let show_fps = remaining >= CHN_COL_FPS + COL_SEP;
    if show_fps { remaining -= CHN_COL_FPS + COL_SEP; }
    let show_frames = remaining >= CHN_COL_FRAMES + COL_SEP;
    if show_frames { remaining -= CHN_COL_FRAMES + COL_SEP; }
    let show_noise = remaining >= CHN_COL_NOISE + COL_SEP;

    (show_frames, show_fps, show_util, show_noise)
}

pub fn render_channels(
    snap: &ScanSnapshot,
    width: u16,
    selected: usize,
    scroll_offset: usize,
    max_rows: usize,
    lines: &mut Vec<String>,
) -> usize {
    let w = width as usize;
    let (show_frames, show_fps, show_util, show_noise) = auto_columns_channels(w);

    // Merge AP-derived data with real ChannelStats
    // Key is (band<<8 | channel) to separate 6GHz channels from 2.4GHz.
    let mut channel_map: std::collections::BTreeMap<u16, ChannelEntry> = std::collections::BTreeMap::new();

    for ap in &snap.aps {
        let band = if ap.channel <= 14 { 0u8 } else { 1 };
        let key = crate::store::stats::channel_key(ap.channel, band);
        let entry = channel_map.entry(key).or_insert_with(|| ChannelEntry::new(ap.channel));
        entry.ap_count += 1;
        entry.beacon_total += ap.beacon_count;
    }

    for sta in &snap.stations {
        if let Some(bssid) = &sta.bssid {
            if let Some(ap) = snap.aps.iter().find(|a| &a.bssid == bssid) {
                let band = if ap.channel <= 14 { 0u8 } else { 1 };
                let key = crate::store::stats::channel_key(ap.channel, band);
                if let Some(entry) = channel_map.get_mut(&key) {
                    entry.sta_count += 1;
                }
            }
        }
    }

    // Overlay real ChannelStats data (band comes directly from the stats)
    for cs in &snap.channel_stats {
        let key = crate::store::stats::channel_key(cs.channel, cs.band);
        let entry = channel_map.entry(key).or_insert_with(|| ChannelEntry::with_band(cs.channel, cs.band));
        entry.frames = cs.frame_count;
        entry.fps = cs.fps;
        entry.retries = cs.retry_count;
        entry.retry_rate = cs.retry_rate;
        entry.noise_floor = cs.noise_floor;
        entry.utilization_pct = cs.utilization_pct;
        if cs.ap_count > 0 { entry.ap_count = cs.ap_count as u32; }
        if cs.sta_count > 0 { entry.sta_count = cs.sta_count as u32; }
    }

    let mut cols = vec![
        ScrollCol::right("  CH", COL_SEL + 3),
        ScrollCol::new("BAND", 4),
        ScrollCol::right("APs", 4),
        ScrollCol::right("STAs", 4),
    ];
    if show_frames { cols.push(ScrollCol::right("FRAMES", CHN_COL_FRAMES)); }
    if show_fps { cols.push(ScrollCol::right("FPS", CHN_COL_FPS)); }
    cols.push(ScrollCol::right("RETRY%", 6));
    if show_util { cols.push(ScrollCol::right("UTIL%", CHN_COL_UTIL)); }
    if show_noise { cols.push(ScrollCol::right("NF", CHN_COL_NOISE)); }
    cols.push(ScrollCol::new("DENSITY", CHN_COL_DENSITY));

    let max_frames = channel_map.values().map(|e| e.frames.max(e.beacon_total as u64)).max().unwrap_or(1);
    let entries: Vec<_> = channel_map.values().collect();

    let mut data_rows: Vec<Vec<String>> = Vec::with_capacity(entries.len());

    for (i, entry) in entries.iter().enumerate() {
        let is_sel = i == selected;

        let ch_cell = if is_sel {
            format!("{} {:>3}", s().cyan().bold().paint("▶"), entry.channel)
        } else {
            format!("  {:>3}", entry.channel)
        };

        let band = s().dim().paint(entry.band);

        let aps = {
            let a = format!("{}", entry.ap_count);
            if is_sel { s().cyan().bold().paint(&a) } else { a }
        };
        let stas = {
            let st = format!("{}", entry.sta_count);
            if is_sel { s().cyan().bold().paint(&st) } else { st }
        };

        let mut row = vec![ch_cell, band, aps, stas];

        if show_frames { row.push(format!("{}", entry.frames)); }
        if show_fps { row.push(format!("{:.0}", entry.fps)); }

        let retry_styled = if entry.retry_rate > 10.0 {
            s().red().paint(&format!("{:.1}", entry.retry_rate))
        } else if entry.retry_rate > 5.0 {
            s().yellow().paint(&format!("{:.1}", entry.retry_rate))
        } else {
            s().dim().paint(&format!("{:.1}", entry.retry_rate))
        };
        row.push(retry_styled);

        // UTIL% — channel utilization (from MIB survey), color-coded
        if show_util {
            let util = entry.utilization_pct;
            row.push(if util > 0.0 {
                let text = format!("{:.1}", util);
                if util > 70.0 { s().red().bold().paint(&text) }
                else if util > 40.0 { s().yellow().paint(&text) }
                else { s().green().paint(&text) }
            } else {
                String::new()
            });
        }

        // NF — noise floor in dBm
        if show_noise {
            row.push(if entry.noise_floor > -100 && entry.noise_floor < 0 {
                s().dim().paint(&format!("{}", entry.noise_floor))
            } else {
                String::new()
            });
        }

        let density_val = entry.frames.max(entry.beacon_total as u64);
        row.push(density_bar(density_val as u32, max_frames as u32, CHN_COL_DENSITY));

        data_rows.push(row);
    }

    let footer = vec![
        String::new(),
        format!("  {}",
            vec![
                format!("{} scroll", s().dim().paint("j/k")),
                format!("{} APs on channel", s().dim().paint("Enter")),
                format!("{} views", s().dim().paint("Tab")),
            ].join(&s().dim().paint(" │ ")),
        ),
        String::new(),
    ];

    let result = scroll_table(&ScrollTableConfig {
        columns: &cols,
        rows: &data_rows,
        height: max_rows,
        scroll_offset,
        separator: "  ",
        indent: 1,
        footer: &footer,
        empty_message: Some("No channel data yet."),
    });

    let capacity = result.capacity;
    lines.extend(result.lines);
    capacity
}

struct ChannelEntry {
    channel: u8,
    band: &'static str,
    ap_count: u32,
    sta_count: u32,
    beacon_total: u32,
    frames: u64,
    fps: f32,
    retries: u64,
    retry_rate: f32,
    noise_floor: i8,
    utilization_pct: f32,
}

impl ChannelEntry {
    fn new(channel: u8) -> Self {
        Self::with_band(channel, if channel <= 14 { 0 } else { 1 })
    }

    fn with_band(channel: u8, band: u8) -> Self {
        Self {
            channel,
            band: match band {
                0 => "2.4G",
                1 => "5G",
                2 => "6G",
                _ => "?",
            },
            ap_count: 0,
            sta_count: 0,
            beacon_total: 0,
            frames: 0,
            fps: 0.0,
            retries: 0,
            retry_rate: 0.0,
            noise_floor: -95,
            utilization_pct: 0.0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Events View — unified management + EAPOL event stream
// ═══════════════════════════════════════════════════════════════════════════════

pub fn render_events(
    snap: &ScanSnapshot,
    _width: u16,
    scroll_offset: usize,
    max_rows: usize,
    lines: &mut Vec<String>,
) {
    let events = &snap.scan_events;

    if events.is_empty() {
        lines.push(String::new());
        lines.push(format!("  {}", s().dim().paint("No events captured yet.")));
        lines.push(format!("  {}", s().dim().paint("Management frames (AUTH, DEAUTH, ASSOC) and EAPOL appear here.")));
        lines.push(String::new());
        lines.push(format!("  {} {} frames processed",
            s().bold().paint(&snap.stats.frame_count.to_string()),
            s().dim().paint("total"),
        ));
        return;
    }

    // Build log-style rows — each event is a flowing line, not columnar
    let log_rows: Vec<String> = events.iter().map(format_event_log).collect();

    // Stream-style: newest at bottom, scroll_offset pushes viewport back in time
    let total = log_rows.len();
    let end = total.saturating_sub(scroll_offset);

    // Footer: summary stats + hints
    let footer = vec![
        String::new(),
        format!("  {}",
            vec![
                format!("{} {}", s().bold().paint(&total.to_string()), s().dim().paint("events")),
                format!("{} hs", s().bold().paint(&snap.stats.handshake_count.to_string())),
                format!("{} pmkid", if snap.stats.pmkid_count > 0 {
                    s().green().bold().paint(&snap.stats.pmkid_count.to_string())
                } else {
                    s().dim().paint("0")
                }),
                format!("{:.1}% retry", snap.stats.retry_rate_pct),
            ].join(&s().dim().paint(" │ ")),
        ),
        format!("  {}",
            vec![
                format!("{} older", s().dim().paint("k")),
                format!("{} newer", s().dim().paint("j")),
                format!("{} oldest", s().dim().paint("g")),
                format!("{} latest", s().dim().paint("G")),
                format!("{} views", s().dim().paint("Tab")),
            ].join(&s().dim().paint(" │ ")),
        ),
        String::new(),
    ];

    // Use scroll_view — the rows up to `end` are what we show, newest at bottom
    let visible_rows = &log_rows[..end];

    let result = prism::scroll_view(&prism::ScrollViewConfig {
        header: &[],
        rows: visible_rows,
        footer: &footer,
        // scroll_offset here means "offset from the top of the visible slice"
        // We want to show the LAST N rows, so offset = max(0, visible - capacity)
        scroll_offset: visible_rows.len().saturating_sub(max_rows.saturating_sub(footer.len() + 2)),
        max_rows,
        indent: 2,
        empty_message: None,
    });

    lines.extend(result.lines);
}

/// Format a scan event as a log-style line: icon + timestamp + type + MACs + detail
fn format_event_log(event: &ScanEvent) -> String {
    let time = s().dim().paint(&format!("{:.1}s", event.timestamp.as_secs_f64()));
    let (icon, type_styled) = event_icon_and_type(event.event_type);
    let source = s().bold().paint(&format!("{}", event.source));

    // Only show target if it's not broadcast
    let target_str = format!("{}", event.target);
    let target_part = if target_str == "FF:FF:FF:FF:FF:FF" {
        String::new()
    } else {
        format!(" → {}", target_str)
    };

    let detail = format_event_detail(&event.detail, event.rssi);
    let detail_part = if detail.is_empty() { String::new() } else { format!("  {}", detail) };

    format!("  {} {} {} {}{}{}", icon, time, type_styled, source, target_part, detail_part)
}

/// Map event type to a colored icon + styled label.
fn event_icon_and_type(event_type: ScanEventType) -> (String, String) {
    match event_type {
        // Success — captures, completions
        ScanEventType::PmkidCaptured => (
            s().green().bold().paint("✔"),
            s().green().bold().paint("PMKID"),
        ),
        ScanEventType::HandshakeComplete => (
            s().green().bold().paint("✔"),
            s().green().bold().paint("Handshake"),
        ),

        // Warning — disconnections, attacks
        ScanEventType::Deauth => (
            s().red().bold().paint("⚠"),
            s().red().bold().paint("Deauth"),
        ),
        ScanEventType::Disassoc => (
            s().red().bold().paint("⚠"),
            s().red().bold().paint("Disassoc"),
        ),

        // Steps — EAPOL handshake progress
        ScanEventType::EapolM1 => (s().cyan().paint("▸"), s().cyan().paint("EAPOL M1")),
        ScanEventType::EapolM2 => (s().yellow().paint("▸"), s().yellow().paint("EAPOL M2")),
        ScanEventType::EapolM3 => (s().cyan().paint("▸"), s().cyan().paint("EAPOL M3")),
        ScanEventType::EapolM4 => (s().yellow().paint("▸"), s().yellow().paint("EAPOL M4")),

        // Info — associations, auth
        ScanEventType::Auth => (s().green().paint("ℹ"), s().green().paint("Auth")),
        ScanEventType::AssocReq => (s().cyan().paint("ℹ"), s().cyan().paint("AssocReq")),
        ScanEventType::AssocResp => (s().green().paint("ℹ"), s().green().paint("AssocResp")),
        ScanEventType::ReassocReq => (s().cyan().paint("ℹ"), s().cyan().paint("ReassocReq")),
        ScanEventType::ReassocResp => (s().cyan().paint("ℹ"), s().cyan().paint("ReassocResp")),

        // Enterprise
        ScanEventType::EapIdentity => (s().yellow().paint("▸"), s().yellow().paint("EAP Identity")),
        ScanEventType::EapMethod => (s().yellow().paint("▸"), s().yellow().paint("EAP Method")),

        // Quiet — management, action frames
        ScanEventType::BssTransitionReq => (s().dim().paint("·"), s().dim().paint("BSS TransReq")),
        ScanEventType::BssTransitionResp => (s().dim().paint("·"), s().dim().paint("BSS TransResp")),
        ScanEventType::SaQueryReq => (s().dim().paint("·"), s().dim().paint("SA Query")),
        ScanEventType::SaQueryResp => (s().dim().paint("·"), s().dim().paint("SA Reply")),
        ScanEventType::TdlsSetup => (s().dim().paint("·"), s().dim().paint("TDLS Setup")),
        ScanEventType::TdlsTeardown => (s().dim().paint("·"), s().dim().paint("TDLS Teardown")),
        ScanEventType::RadioMeasurementReq => (s().dim().paint("·"), s().dim().paint("Radio Meas")),
        ScanEventType::RadioMeasurementResp => (s().dim().paint("·"), s().dim().paint("Radio Resp")),
        ScanEventType::WnmSleepReq => (s().dim().paint("·"), s().dim().paint("WNM Sleep")),
        ScanEventType::WnmSleepResp => (s().dim().paint("·"), s().dim().paint("WNM Wake")),
        ScanEventType::FtRequest => (s().dim().paint("·"), s().dim().paint("FT Request")),
        ScanEventType::FtResponse => (s().dim().paint("·"), s().dim().paint("FT Response")),
        ScanEventType::SpectrumAction => (s().dim().paint("·"), s().dim().paint("Spectrum")),
        ScanEventType::ControlRts => (s().dim().paint("·"), s().dim().paint("RTS")),
        ScanEventType::ControlCts => (s().dim().paint("·"), s().dim().paint("CTS")),
        ScanEventType::ControlBlockAckReq => (s().dim().paint("·"), s().dim().paint("BAR")),
        ScanEventType::ControlBlockAck => (s().dim().paint("·"), s().dim().paint("BA")),
        ScanEventType::ActionOther => (s().dim().paint("·"), s().dim().paint("Action")),
    }
}

fn format_event_detail(detail: &EventDetail, rssi: i8) -> String {
    match detail {
        EventDetail::None => format!("{}", s().dim().paint(&format!("{} dBm", rssi))),
        EventDetail::Auth { algorithm, seq_num, status } => {
            let algo = match algorithm {
                0 => "Open",
                1 => "Shared Key",
                3 => "SAE",
                _ => "Unknown",
            };
            format!("{} seq={} status={}", s().dim().paint(algo), seq_num, status)
        }
        EventDetail::Deauth { reason, reason_str } => {
            format!("{} ({})", s().red().paint(*reason_str), s().dim().paint(&format!("reason={}", reason)))
        }
        EventDetail::Disassoc { reason, reason_str } => {
            format!("{} ({})", s().red().paint(*reason_str), s().dim().paint(&format!("reason={}", reason)))
        }
        EventDetail::AssocReq { ssid, listen_interval } => {
            format!("{} {}", s().bold().paint(ssid), s().dim().paint(&format!("listen={}", listen_interval)))
        }
        EventDetail::AssocResp { status, aid } => {
            if *status == 0 {
                format!("{} AID={}", s().green().paint("Success"), aid)
            } else {
                format!("{} status={}", s().red().paint("Rejected"), status)
            }
        }
        EventDetail::ReassocReq { ssid, current_ap } => {
            format!("{} from {}", s().bold().paint(ssid), s().dim().paint(&format!("{}", current_ap)))
        }
        EventDetail::Action { category_name, category, action } => {
            format!("{} cat={} act={}", s().dim().paint(*category_name), category, action)
        }
        EventDetail::Eapol { message_num } => {
            format!("{}", s().dim().paint(&format!("4-way {}/4", message_num)))
        }
        EventDetail::Pmkid => {
            s().green().bold().paint("PMKID extracted!").to_string()
        }
        EventDetail::HandshakeComplete { quality } => {
            format!("{} {}", s().green().bold().paint("Complete!"), style_quality(*quality))
        }
        EventDetail::EapIdentity { identity } => {
            let id_trunc = truncate(identity, 40, "\u{2026}");
            s().yellow().bold().paint(&id_trunc).to_string()
        }
        EventDetail::EapMethod { method } => {
            s().bold().paint(method).to_string()
        }
        EventDetail::SaQuery { transaction_id, is_request } => {
            let dir = if *is_request { "Request" } else { "Response" };
            format!("{} txid={:#06x}", s().dim().paint(dir), transaction_id)
        }
        EventDetail::BssTransition { action, dialog_token, status, target_bssid } => {
            let act = match *action {
                6 => "Query",
                7 => "Request",
                8 => "Response",
                _ => "Unknown",
            };
            let mut parts = format!("{} tok={}", s().dim().paint(act), dialog_token);
            if let Some(st) = status {
                parts.push_str(&format!(" status={}", st));
            }
            if let Some(bssid) = target_bssid {
                parts.push_str(&format!(" target={}", s().bold().paint(&format!("{}", bssid))));
            }
            parts
        }
        EventDetail::FtAction { action, sta_addr, target_ap, status } => {
            let act = match *action {
                1 => "Request",
                2 => "Response",
                3 => "Confirm",
                4 => "Ack",
                _ => "Unknown",
            };
            let mut parts = format!("{} sta={} ap={}", s().dim().paint(act), sta_addr, s().bold().paint(&format!("{}", target_ap)));
            if let Some(st) = status {
                parts.push_str(&format!(" status={}", st));
            }
            parts
        }
        EventDetail::SpectrumMgmt { action, dialog_token } => {
            let act = match *action {
                0 => "MeasReq",
                1 => "MeasResp",
                2 => "TpcReq",
                3 => "TpcResp",
                4 => "ChSwitch",
                _ => "Unknown",
            };
            format!("{} tok={}", s().dim().paint(act), dialog_token)
        }
        EventDetail::RadioMeasurement { action, dialog_token, num_repetitions } => {
            let act = match *action {
                0 => "MeasReq",
                1 => "MeasResp",
                2 => "LinkMeasReq",
                3 => "LinkMeasResp",
                4 => "NeighborReq",
                5 => "NeighborResp",
                _ => "Unknown",
            };
            let mut parts = format!("{} tok={}", s().dim().paint(act), dialog_token);
            if let Some(rep) = num_repetitions {
                parts.push_str(&format!(" rep={}", rep));
            }
            parts
        }
        EventDetail::ControlFrame { subtype_name } => {
            format!("{}", s().dim().paint(*subtype_name))
        }
    }
}

fn style_quality(quality: HandshakeQuality) -> String {
    match quality {
        HandshakeQuality::None => s().dim().paint("None"),
        HandshakeQuality::Pmkid => s().green().bold().paint("PMKID"),
        HandshakeQuality::M1M2 => s().cyan().bold().paint("M1+M2"),
        HandshakeQuality::M1M2M3 => s().cyan().bold().paint("M1-M3"),
        HandshakeQuality::Full => s().green().bold().paint("Full"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Handshakes View — captured EAPOL handshakes with selection + scroll
// ═══════════════════════════════════════════════════════════════════════════════

pub fn render_handshakes(
    snap: &ScanSnapshot,
    _width: u16,
    selected: usize,
    scroll_offset: usize,
    max_rows: usize,
    lines: &mut Vec<String>,
) -> usize {
    // Filter out None/None entries — empty shells from partial EAPOL captures during channel hopping
    let handshakes: Vec<_> = snap.handshakes.iter()
        .filter(|hs| hs.quality != HandshakeQuality::None)
        .collect();

    let cols = vec![
        ScrollCol::new("  AP", COL_SEL + 17),
        ScrollCol::new("SSID", 16),
        ScrollCol::new("CLIENT", 17),
        ScrollCol::new("STATE", 10),
        ScrollCol::new("QUALITY", 8),
        ScrollCol::center("PMKID", 5),
    ];

    let mut data_rows: Vec<Vec<String>> = Vec::with_capacity(handshakes.len());

    for (i, hs) in handshakes.iter().enumerate() {
        let is_sel = i == selected;

        let ap_str = format!("{}", hs.ap_mac);
        let ap_styled = if is_sel {
            s().cyan().bold().paint(&ap_str)
        } else {
            s().bold().paint(&ap_str)
        };
        let ap_cell = if is_sel {
            format!("{} {}", s().cyan().bold().paint("▶"), ap_styled)
        } else {
            format!("  {}", ap_styled)
        };

        let ssid_plain = if hs.ssid.is_empty() { "(hidden)" } else { &hs.ssid };
        let ssid_trunc = truncate(ssid_plain, 16, "…");
        let ssid_styled = if hs.ssid.is_empty() {
            s().dim().italic().paint(&ssid_trunc)
        } else if is_sel {
            s().cyan().bold().paint(&ssid_trunc)
        } else {
            ssid_trunc
        };

        let sta_str = format!("{}", hs.sta_mac);
        let sta_styled = if is_sel { s().cyan().bold().paint(&sta_str) } else { sta_str.clone() };

        let state_str = format_hs_state(hs);
        let state_styled = match hs.quality {
            HandshakeQuality::Full => s().green().bold().paint(&state_str),
            HandshakeQuality::M1M2 | HandshakeQuality::M1M2M3 => s().cyan().paint(&state_str),
            HandshakeQuality::Pmkid => s().green().paint(&state_str),
            HandshakeQuality::None => s().dim().paint(&state_str),
        };

        let quality_styled = style_quality(hs.quality);

        let pmkid = if hs.has_pmkid {
            s().green().bold().paint("●")
        } else {
            " ".to_string()
        };

        data_rows.push(vec![
            ap_cell, ssid_styled, sta_styled, state_styled, quality_styled, pmkid,
        ]);
    }

    // Stats line: captured / full / crackable / PMKIDs / unique APs
    let mut stat_parts = vec![
        format!("{} captured", s().bold().paint(&handshakes.len().to_string())),
    ];
    if snap.stats.complete_handshake_count > 0 {
        stat_parts.push(format!("{} full", s().green().bold().paint(&snap.stats.complete_handshake_count.to_string())));
    }
    if snap.stats.crackable_count > 0 {
        stat_parts.push(format!("{} crackable", s().cyan().bold().paint(&snap.stats.crackable_count.to_string())));
    }
    if snap.stats.pmkid_count > 0 {
        stat_parts.push(format!("{} PMKID", s().green().paint(&snap.stats.pmkid_count.to_string())));
    }
    if snap.stats.unique_capture_aps > 0 {
        stat_parts.push(format!("{} APs", s().dim().paint(&snap.stats.unique_capture_aps.to_string())));
    }

    let footer = vec![
        String::new(),
        format!("  {}", stat_parts.join(&s().dim().paint(" │ "))),
        format!("  {}",
            vec![
                format!("{} scroll", s().dim().paint("j/k")),
                format!("{} top/end", s().dim().paint("g/G")),
                format!("{} AP detail", s().dim().paint("Enter")),
                format!("{} = PMKID", s().green().bold().paint("●")),
            ].join(&s().dim().paint(" │ ")),
        ),
        String::new(),
    ];

    let result = scroll_table(&ScrollTableConfig {
        columns: &cols,
        rows: &data_rows,
        height: max_rows,
        scroll_offset,
        separator: "  ",
        indent: 1,
        footer: &footer,
        empty_message: Some("No handshakes captured yet. They appear automatically during scanning."),
    });

    lines.extend(result.lines);
    result.capacity
}

/// Format handshake message state as compact string (e.g., "M1+M2+M3").
fn format_hs_state(hs: &crate::engine::capture::Handshake) -> String {
    let mut parts = Vec::new();
    if hs.has_m1 { parts.push("M1"); }
    if hs.has_m2 { parts.push("M2"); }
    if hs.has_m3 { parts.push("M3"); }
    if hs.has_m4 { parts.push("M4"); }
    if parts.is_empty() {
        if hs.has_pmkid { "PMKID".to_string() }
        else { "none".to_string() }
    } else {
        parts.join("+")
    }
}
