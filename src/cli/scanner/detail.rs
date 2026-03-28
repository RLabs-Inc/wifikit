//! Detail view renderers — AP detail (9 tabs) + Client detail (6 tabs).
//!
//! Each tab renders structured information from the Ap/Station struct fields.
//! All data that the scanner captures is visible in exactly one tab.

use prism::{s, truncate};

use crate::core::MacAddress;
use crate::store::{Ap, BeaconTiming, ProbeReq, Station, WpsState};
use crate::protocol::eapol::HandshakeQuality;
use crate::protocol::ieee80211::{AkmSuite, CipherSuite, Security};

use super::style::*;

// ═══════════════════════════════════════════════════════════════════════════════
//  AP Detail — 9 tabs
// ═══════════════════════════════════════════════════════════════════════════════

pub fn ap_tab_name(tab: u8) -> &'static str {
    match tab {
        1 => "Overview",
        2 => "Security",
        3 => "Radio",
        4 => "Clients",
        5 => "Probes",
        6 => "Features",
        7 => "Timing",
        8 => "Attack Surface",
        9 => "IEs",
        _ => "?",
    }
}

fn ap_tab_short(tab: u8) -> &'static str {
    match tab {
        1 => "Ovrw",
        2 => "Sec",
        3 => "Rad",
        4 => "Cli",
        5 => "Prb",
        6 => "Feat",
        7 => "Tim",
        8 => "Atk",
        9 => "IE",
        _ => "?",
    }
}

fn client_tab_short(tab: u8) -> &'static str {
    match tab {
        1 => "Ovrw",
        2 => "FP",
        3 => "Prb",
        4 => "Seq",
        5 => "Act",
        6 => "Raw",
        _ => "?",
    }
}

/// Render an adaptive tab bar that adjusts to terminal width.
/// - Wide: `[1]Overview [2]Security [3]Radio ...`
/// - Medium: `[1]Ovrw [2]Sec [3]Rad ...`
/// - Narrow: `[1] [2] [3]Radio [4] ...` (only active gets name)
fn render_adaptive_tabs(
    active: u8,
    count: u8,
    name_fn: fn(u8) -> &'static str,
    short_fn: fn(u8) -> &'static str,
    available: usize,
) -> String {
    // Try full names first
    let full = build_tab_line(active, count, |i| name_fn(i).to_string());
    if prism::measure_width(&full) <= available {
        return full;
    }

    // Try short names
    let short = build_tab_line(active, count, |i| short_fn(i).to_string());
    if prism::measure_width(&short) <= available {
        return short;
    }

    // Narrow: only active tab gets its name, rest are just numbers
    build_tab_line(active, count, |i| {
        if i == active {
            name_fn(i).to_string()
        } else {
            String::new()
        }
    })
}

fn build_tab_line(active: u8, count: u8, label_fn: impl Fn(u8) -> String) -> String {
    let mut tabs = Vec::new();
    for i in 1..=count {
        let label = label_fn(i);
        let text = if label.is_empty() {
            format!("[{}]", i)
        } else {
            format!("[{}]{}", i, label)
        };
        if i == active {
            tabs.push(s().cyan().bold().paint(&text));
        } else {
            tabs.push(s().dim().paint(&text));
        }
    }
    tabs.join(" ")
}

/// Render AP detail view. Returns the number of lines that should be pinned
/// (not scrolled) — includes the 3 shared header lines plus any tab-specific
/// table headers that should stay visible when scrolling.
pub fn render_ap_detail(
    ap: &Ap,
    clients: &[Station],
    probes: &[ProbeReq],
    beacon_timing: Option<&BeaconTiming>,
    tab: u8,
    width: u16,
    lines: &mut Vec<String>,
) -> usize {
    // Adaptive tab bar
    let available = (width as usize).saturating_sub(2); // 2-space indent
    let tab_line = render_adaptive_tabs(tab, 9, ap_tab_name, ap_tab_short, available);
    let tab_vis_width = prism::measure_width(&tab_line);
    lines.push(format!("  {}", tab_line));
    lines.push(format!("  {}", s().dim().paint(&prism::divider("─", tab_vis_width))));
    lines.push(String::new());

    match tab {
        1 => render_ap_overview(ap, width, lines),
        2 => render_ap_security(ap, width, lines),
        3 => render_ap_radio(ap, width, lines),
        4 => render_ap_clients(ap, clients, width, lines),
        5 => render_ap_probes(ap, probes, clients, width, lines),
        6 => render_ap_features(ap, width, lines),
        7 => render_ap_timing(ap, beacon_timing, width, lines),
        8 => render_ap_attack_surface(ap, lines),
        9 => render_ap_ies(ap, width, lines),
        _ => { lines.push(format!("  {}", s().dim().paint("Unknown tab"))); }
    }

    // 3 shared headers (tab bar + separator + blank) + tab-specific table headers
    // Each number is how many lines the tab renders BEFORE the scrollable data rows
    let tab_pin = match tab {
        4 => 4, // Clients: title + blank + ScrollTable header + separator
        8 => 4, // Attack Surface: section header + blank + header row + separator
        9 => 4, // IEs: section header + blank + header row + separator
        _ => 0, // Non-table tabs scroll all content
    };
    let pin_count = 3 + tab_pin;

    // Footer
    lines.push(String::new());
    lines.push(format!("  {}  {}  {}",
        s().dim().paint("1-9: switch tabs"),
        s().dim().paint("Tab: next tab"),
        s().dim().paint("Esc: back to table"),
    ));

    pin_count
}

// ───────────────────────────────────────────────────────────────────────────────
//  Tab 1: Overview
// ───────────────────────────────────────────────────────────────────────────────

fn render_ap_overview(ap: &Ap, width: u16, lines: &mut Vec<String>) {

    // ── Identity block ─────────────────────────────────────────────────
    let identity = {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        pairs.push(("SSID", if ap.is_hidden { "<hidden>".into() } else { ap.ssid.clone() }));
        if !ap.ssid_raw.is_empty() && ap.ssid_raw.iter().any(|b| *b < 0x20 || *b > 0x7E) {
            let hex: String = ap.ssid_raw.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
            pairs.push(("SSID (hex)", hex));
        }
        pairs.push(("BSSID", format!("{}", ap.bssid)));
        pairs.push(("Vendor", if ap.vendor.is_empty() { "Unknown".into() } else { ap.vendor.clone() }));
        if let Some(cc) = ap.country {
            pairs.push(("Country", String::from_utf8_lossy(&cc).into_owned()));
        }
        make_section("Identity", &pairs)
    };

    // ── Radio block ────────────────────────────────────────────────────
    let radio = {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        pairs.push(("Channel", format!("{}", ap.channel)));
        if ap.freq_mhz > 0 {
            pairs.push(("Frequency", format!("{} MHz", ap.freq_mhz)));
        }
        if ap.channel_center > 0 {
            pairs.push(("Center Freq", format!("{} MHz", ap.channel_center)));
        }
        pairs.push(("Bandwidth", bandwidth_str(&ap.bandwidth).to_string()));
        pairs.push(("Band", if ap.channel <= 14 { "2.4 GHz" } else { "5 GHz" }.into()));
        pairs.push(("WiFi Gen", ap.wifi_gen.name().to_string()));
        pairs.push(("Streams", format!("{}x{}", ap.max_nss, ap.max_nss)));
        if ap.max_rate_mbps > 0 {
            pairs.push(("Max Rate", format!("{} Mbps", ap.max_rate_mbps)));
        }
        make_section("Radio", &pairs)
    };

    // ── Beacon block ───────────────────────────────────────────────────
    let beacon = {
        let pairs: Vec<(&str, String)> = vec![
            ("Interval", format!("{} TU ({:.1} ms)", ap.beacon_interval, ap.beacon_interval as f64 * 1.024)),
            ("Capability", format!("{:#06X}", ap.capability)),
            ("Beacons", format!("{}", ap.beacon_count)),
            ("Clients", format!("{}", ap.client_count)),
        ];
        make_section("Beacon", &pairs)
    };

    // ── Timing block ───────────────────────────────────────────────────
    let timing = {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        pairs.push(("TSF", format!("{}", ap.tsf)));
        if ap.tsf > 0 {
            pairs.push(("Est. Uptime", format_tsf_uptime(ap.tsf)));
        }
        pairs.push(("First Seen", format!("{} ago", format_elapsed(ap.first_seen.elapsed()))));
        pairs.push(("Last Seen", format!("{} ago", format_elapsed(ap.last_seen.elapsed()))));
        let observed = ap.last_seen.duration_since(ap.first_seen);
        pairs.push(("Observed", format_elapsed(observed)));
        make_section("Timing", &pairs)
    };

    emit_flex(vec![identity, radio, beacon, timing], width, lines);

    // ── Attack Surface (framed) ────────────────────────────────────────
    render_attack_surface_frame(ap, width, lines);
}

/// Render the attack surface frame for the overview tab.
/// Content-width frame (max 75 cols), centered, with severity badges.
fn render_attack_surface_frame(ap: &Ap, width: u16, lines: &mut Vec<String>) {
    // Collect vulnerability findings: (severity, name, reason, command)
    let mut vulns: Vec<(&str, &str, &str, &str)> = Vec::new();

    if let Some(ref rsn) = ap.rsn {
        if !rsn.mfp_required {
            vulns.push(("HIGH", "Deauth vulnerable", "PMF not required", "/deauth"));
        }
    } else if ap.security != Security::Open {
        vulns.push(("HIGH", "Deauth vulnerable", "No RSN IE", "/deauth"));
    }
    if ap.wps_state != WpsState::None && !ap.wps_locked {
        vulns.push(("HIGH", "WPS Pixie Dust", "WPS enabled, not locked", "/wps --pixie"));
    }
    if matches!(ap.security, Security::Wpa2Enterprise | Security::Wpa3Enterprise) {
        vulns.push(("HIGH", "Enterprise creds", "802.1X AKM", "/eap"));
    }
    if ap.wps_state != WpsState::None {
        vulns.push(("MEDIUM", "WPS Brute Force", "WPS present", "/wps"));
    }
    if matches!(ap.security, Security::Wpa2 | Security::Wpa3) {
        if ap.rsn.as_ref().map_or(false, |r| r.akm_suites.iter().any(|a| matches!(a, AkmSuite::Psk | AkmSuite::PskSha256 | AkmSuite::Sae))) {
            if !ap.has_pmkid {
                vulns.push(("MEDIUM", "PMKID extraction", "PSK/SAE AKM", "/pmkid"));
            }
        }
    }
    if ap.has_ft {
        vulns.push(("MEDIUM", "KRACK FT", "CVE-2017-13082", "/krack --variant ft"));
    }
    if ap.ext_cap_wnm_sleep {
        vulns.push(("MEDIUM", "KRACK WNM-Sleep", "CVE-2017-13087", "/krack --variant wnm-gtk"));
    }
    if ap.ext_cap_tdls {
        vulns.push(("MEDIUM", "KRACK TDLS", "CVE-2017-13086", "/krack --variant tdls"));
    }
    if matches!(ap.security, Security::Wpa3) {
        if ap.rsn.as_ref().map_or(false, |r| r.akm_suites.contains(&AkmSuite::Psk)) {
            vulns.push(("MEDIUM", "WPA3 Downgrade", "SAE+PSK transition", "/wpa3 --transition"));
        }
        vulns.push(("LOW", "WPA3 Timing", "SAE side-channel", "/wpa3 --timing"));
    }
    if let Some(ref rsn) = ap.rsn {
        if rsn.pairwise_ciphers.contains(&CipherSuite::Tkip) {
            vulns.push(("LOW", "TKIP Michael", "Beck-Tews attack", ""));
        }
    }
    vulns.push(("LOW", "FragAttacks", "CVE-2020-24586+", "/frag"));

    // Severity counts
    let high = vulns.iter().filter(|(sev, ..)| *sev == "HIGH").count();
    let med = vulns.iter().filter(|(sev, ..)| *sev == "MEDIUM").count();
    let low = vulns.iter().filter(|(sev, ..)| *sev == "LOW").count();

    // Capture status
    let pmkid_status = if ap.has_pmkid {
        format!("{} {}", s().green().paint("\u{2714}"), s().green().bold().paint("PMKID"))
    } else {
        format!("{} {}", s().dim().paint("\u{2718}"), s().dim().paint("PMKID"))
    };
    let hs_status = match ap.handshake_quality {
        HandshakeQuality::None => format!("{} {}", s().dim().paint("\u{2718}"), s().dim().paint("Handshake")),
        HandshakeQuality::Pmkid => format!("{} {}", s().dim().paint("\u{2718}"), s().dim().paint("Handshake")),
        HandshakeQuality::M1M2 => format!("{} {}", s().green().paint("\u{2714}"), s().green().bold().paint("Handshake M1+M2")),
        HandshakeQuality::M1M2M3 => format!("{} {}", s().green().paint("\u{2714}"), s().green().bold().paint("Handshake M1-M3")),
        HandshakeQuality::Full => format!("{} {}", s().green().paint("\u{2714}"), s().green().bold().paint("Handshake Full")),
    };

    // Build content lines
    let max_frame = 75usize;
    let available_frame = (width as usize).saturating_sub(2); // 2-space indent
    let frame_width = available_frame.min(max_frame);
    let inner = frame_width.saturating_sub(4); // borders + padding

    let mut content_lines: Vec<String> = Vec::new();

    // Summary line
    let mut summary_parts = Vec::new();
    summary_parts.push(s().bold().paint(&format!("{} findings:", vulns.len())));
    if high > 0 { summary_parts.push(s().red().bold().paint(&format!("{} HIGH", high))); }
    if med > 0 { summary_parts.push(s().yellow().paint(&format!("{} MEDIUM", med))); }
    if low > 0 { summary_parts.push(s().dim().paint(&format!("{} LOW", low))); }
    content_lines.push(summary_parts.join("  "));
    content_lines.push(String::new());

    // Vulnerability lines (cap at 8, overflow to tab 8)
    let max_shown = 8;
    let shown = vulns.len().min(max_shown);
    for (sev, name, reason, cmd) in &vulns[..shown] {
        let sev_styled = match *sev {
            "HIGH" => s().red().bold().paint(&format!("{:<6}", sev)),
            "MEDIUM" => s().yellow().paint(&format!("{:<6}", sev)),
            _ => s().dim().paint(&format!("{:<6}", sev)),
        };
        let icon = s().yellow().paint("\u{26a0}");
        let name_styled = s().bold().paint(name);
        let cmd_styled = if cmd.is_empty() { String::new() } else { s().cyan().paint(cmd) };
        let reason_styled = s().dim().paint(reason);

        if inner >= 65 && !cmd.is_empty() {
            // Wide: icon SEV  name  reason  /command
            let left = format!("{} {}  {}  {}", icon, sev_styled, name_styled, reason_styled);
            let left_vis = prism::measure_width(&left);
            let gap = inner.saturating_sub(left_vis).saturating_sub(prism::measure_width(cmd));
            content_lines.push(format!("{}{}{}", left, " ".repeat(gap), cmd_styled));
        } else if inner >= 40 && !cmd.is_empty() {
            // Medium: icon SEV  name  /command
            let left = format!("{} {}  {}", icon, sev_styled, name_styled);
            let left_vis = prism::measure_width(&left);
            let gap = inner.saturating_sub(left_vis).saturating_sub(prism::measure_width(cmd));
            content_lines.push(format!("{}{}{}", left, " ".repeat(gap), cmd_styled));
        } else {
            // Narrow: stacked
            content_lines.push(format!("{} {}  {}", icon, sev_styled, name_styled));
            if !cmd.is_empty() {
                content_lines.push(format!("    {}", cmd_styled));
            }
        }
    }
    if vulns.len() > max_shown {
        content_lines.push(format!("  {} more \u{2192} {}",
            s().dim().paint(&format!("...and {}", vulns.len() - max_shown)),
            s().dim().paint("[8]Attack Surface")));
    }

    // Capture status line
    content_lines.push(String::new());
    content_lines.push(format!("{}    {}", pmkid_status, hs_status));

    let content = content_lines.join("\n");

    // Center the frame if terminal is wider than frame
    let left_pad = if available_frame > frame_width {
        (available_frame - frame_width) / 2
    } else {
        0
    };
    let pad_str = " ".repeat(left_pad);

    lines.push(String::new());
    let framed = prism::frame(&content, &prism::FrameOptions {
        border: prism::BorderStyle::Rounded,
        width: Some(frame_width),
        padding: 1,
        title: Some(s().bold().yellow().paint(" Attack Surface ")),
    });
    for line in framed.lines() {
        if !line.is_empty() {
            lines.push(format!("  {}{}", pad_str, line));
        }
    }
}

/// Build a section block: header line + prism::kv() aligned pairs.
/// Returns a FlexBlock with measured width.
fn make_section(title: &str, pairs: &[(&str, String)]) -> prism::FlexBlock {
    let kv_pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let kv_str = prism::kv(&kv_pairs, &prism::KvOptions {
        separator: "  ".to_string(),
        indent: 1,
    });

    // Measure the kv block width to size the header
    let kv_width = kv_str.lines().map(|l| prism::measure_width(l)).max().unwrap_or(0);
    let header_width = kv_width.max(title.len() + 6); // at least enough for "── Title ──"

    let header = prism::header(&s().bold().paint(title), header_width);

    let mut block_lines = vec![header];
    for line in kv_str.lines() {
        block_lines.push(line.to_string());
    }

    prism::FlexBlock::measured(block_lines)
}

/// Emit flex blocks with standard 2-space indent into lines.
fn emit_flex(blocks: Vec<prism::FlexBlock>, width: u16, lines: &mut Vec<String>) {
    use prism::{FlexOptions, FlexAlign};
    let w = width as usize;
    let flex_lines = prism::flex(&blocks, &FlexOptions {
        total_width: w.saturating_sub(2),
        gap: 3,
        row_gap: 1,
        indent: 0,
        min_block_width: 30,
        align: FlexAlign::Stretch,
    });
    for line in flex_lines {
        lines.push(format!("  {}", line));
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  Tab 2: Security
// ───────────────────────────────────────────────────────────────────────────────

fn render_ap_security(ap: &Ap, width: u16, lines: &mut Vec<String>) {
    let mut blocks = Vec::new();

    // ── Classification + RSN ───────────────────────────────────────────
    let classification = {
        let mut pairs: Vec<(&str, String)> = vec![
            ("Security", style_security(&ap.security)),
        ];
        if let Some(ref rsn) = ap.rsn {
            pairs.push(("Group Cipher", rsn.group_cipher.name().to_string()));
            let pairwise: Vec<&str> = rsn.pairwise_ciphers.iter().map(|c| c.name()).collect();
            pairs.push(("Pairwise", pairwise.join(", ")));
            let akm: Vec<&str> = rsn.akm_suites.iter().map(|a| a.name()).collect();
            pairs.push(("AKM Suites", akm.join(", ")));
            pairs.push(("RSN Caps", format!("{:#06X}", rsn.rsn_caps)));
            pairs.push(("MFP (802.11w)", style_mfp(rsn.mfp_required, rsn.mfp_capable)));
            if rsn.pmkid_count > 0 {
                pairs.push(("PMKID Count", format!("{}", rsn.pmkid_count)));
            }
            pairs.push(("Pre-auth", yes_no(rsn.pre_auth).to_string()));
        }
        make_section("RSN", &pairs)
    };
    blocks.push(classification);

    // ── Handshake State ────────────────────────────────────────────────
    let handshake = {
        let hs_state = match ap.handshake_quality {
            HandshakeQuality::None => s().dim().paint("none"),
            HandshakeQuality::Pmkid => s().green().paint("PMKID captured"),
            HandshakeQuality::M1M2 => s().green().paint("M1+M2 (crackable)"),
            HandshakeQuality::M1M2M3 => s().green().paint("M1+M2+M3 (good)"),
            HandshakeQuality::Full => s().green().bold().paint("Full (M1-M4)"),
        };
        let pmkid_val = if ap.has_pmkid {
            s().green().bold().paint("YES")
        } else {
            s().dim().paint("no")
        };
        make_section("Handshake", &[
            ("State", hs_state),
            ("PMKID", pmkid_val),
        ])
    };
    blocks.push(handshake);

    // ── WPS ────────────────────────────────────────────────────────────
    let wps = {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        match ap.wps_state {
            WpsState::None => {
                pairs.push(("State", s().dim().paint("not enabled")));
            }
            state => {
                let state_str = match state {
                    WpsState::Configured => "Configured",
                    WpsState::NotConfigured => "Not Configured",
                    _ => "Unknown",
                };
                pairs.push(("State", state_str.to_string()));
                pairs.push(("Locked", if ap.wps_locked {
                    s().red().bold().paint("YES")
                } else {
                    s().green().paint("no")
                }));
                if ap.wps_version > 0 {
                    pairs.push(("Version", format!("{}.{}", ap.wps_version >> 4, ap.wps_version & 0xF)));
                }
                if !ap.wps_device_name.is_empty() {
                    pairs.push(("Device", ap.wps_device_name.clone()));
                }
                if !ap.wps_model.is_empty() {
                    pairs.push(("Model", ap.wps_model.clone()));
                }
            }
        }
        make_section("WPS", &pairs)
    };
    blocks.push(wps);

    emit_flex(blocks, width, lines);
}

// ───────────────────────────────────────────────────────────────────────────────
//  Tab 3: Radio
// ───────────────────────────────────────────────────────────────────────────────

fn render_ap_radio(ap: &Ap, width: u16, lines: &mut Vec<String>) {
    let mut blocks = Vec::new();

    // ── Supported Rates ────────────────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if ap.supported_rates.is_empty() {
            p.push(("Rates", s().dim().paint("none captured")));
        } else {
            let rates: Vec<String> = ap.supported_rates.iter().map(|r| {
                let basic = r & 0x80 != 0;
                let rate_val = (r & 0x7F) as f64 / 2.0;
                if basic { s().bold().paint(&format!("{:.1}*", rate_val)) }
                else { format!("{:.1}", rate_val) }
            }).collect();
            p.push(("Rates (Mbps)", rates.join(", ")));
        }
        blocks.push(make_section("Rates", &p));
    }

    // ── HT Capabilities (IE 45) ───────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if ap.ht_cap_raw == 0 {
            p.push(("Status", s().dim().paint("not present")));
        } else {
            let ht40 = ap.ht_cap_raw & 0x0002 != 0;
            let sgi20 = ap.ht_cap_raw & 0x0020 != 0;
            let sgi40 = ap.ht_cap_raw & 0x0040 != 0;
            let tx_stbc = ap.ht_cap_raw & 0x0080 != 0;
            let rx_stbc = (ap.ht_cap_raw >> 8) & 0x03;
            let ldpc = ap.ht_cap_raw & 0x0001 != 0;
            let greenfield = ap.ht_cap_raw & 0x0010 != 0;
            let dsss_cck = ap.ht_cap_raw & 0x1000 != 0;
            let max_amsdu = if ap.ht_cap_raw & 0x0800 != 0 { 7935 } else { 3839 };
            let sm_ps = match (ap.ht_cap_raw >> 2) & 0x03 {
                0 => "static", 1 => "dynamic", 3 => "disabled", _ => "reserved",
            };
            p.push(("Raw", format!("{:#06X}", ap.ht_cap_raw)));
            p.push(("HT40", yes_no(ht40).to_string()));
            p.push(("SGI 20/40", format!("{}/{}", yes_no(sgi20), yes_no(sgi40))));
            p.push(("LDPC", yes_no(ldpc).to_string()));
            p.push(("TX STBC", yes_no(tx_stbc).to_string()));
            p.push(("RX STBC", format!("{} stream(s)", rx_stbc)));
            p.push(("Greenfield", yes_no(greenfield).to_string()));
            p.push(("SM Power Save", sm_ps.to_string()));
            p.push(("Max A-MSDU", format!("{} bytes", max_amsdu)));
            p.push(("DSSS/CCK 40MHz", yes_no(dsss_cck).to_string()));
            p.push(("A-MPDU Max Len", format!("{}KB", 8u32 << ap.ampdu_max_len_exp)));
            let spacing = match ap.ampdu_min_spacing {
                0 => "none", 1 => "1/4\u{00b5}s", 2 => "1/2\u{00b5}s",
                3 => "1\u{00b5}s", 4 => "2\u{00b5}s", 5 => "4\u{00b5}s",
                6 => "8\u{00b5}s", 7 => "16\u{00b5}s", _ => "?",
            };
            p.push(("A-MPDU Spacing", spacing.to_string()));
        }
        blocks.push(make_section("HT (IE 45)", &p));
    }

    // ── VHT Capabilities (IE 191) ─────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if ap.vht_cap_raw == 0 {
            p.push(("Status", s().dim().paint("not present")));
        } else {
            let max_mpdu = match ap.vht_cap_raw & 0x03 { 0 => 3895, 1 => 7991, 2 => 11454, _ => 3895 };
            let width_str = match (ap.vht_cap_raw >> 2) & 0x03 {
                0 => "80 MHz", 1 => "160 MHz", 2 => "80+80 MHz", _ => "reserved",
            };
            let rx_ldpc = ap.vht_cap_raw & (1 << 4) != 0;
            let sgi80 = ap.vht_cap_raw & (1 << 5) != 0;
            let sgi160 = ap.vht_cap_raw & (1 << 6) != 0;
            let tx_stbc = ap.vht_cap_raw & (1 << 7) != 0;
            let su_bf = ap.vht_cap_raw & (1 << 11) != 0;
            let mu_bf = ap.vht_cap_raw & (1 << 19) != 0;
            let bf_sts = ((ap.vht_cap_raw >> 13) & 0x07) + 1;

            p.push(("Max MPDU", format!("{} bytes", max_mpdu)));
            p.push(("Ch Width", width_str.to_string()));
            p.push(("RX LDPC", yes_no(rx_ldpc).to_string()));
            p.push(("SGI 80/160", format!("{}/{}", yes_no(sgi80), yes_no(sgi160))));
            p.push(("TX STBC", yes_no(tx_stbc).to_string()));
            p.push(("SU Beamformee", yes_no(su_bf).to_string()));
            p.push(("MU Beamformee", yes_no(mu_bf).to_string()));
            p.push(("BF STS", format!("{}", bf_sts)));
            if ap.vht_sounding_dims > 0 {
                p.push(("Sounding Dims", format!("{}", ap.vht_sounding_dims + 1)));
            }
        }
        blocks.push(make_section("VHT (IE 191)", &p));
    }

    // ── HE Capabilities (WiFi 6) ──────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if ap.has_he_oper {
            p.push(("BSS Color", format!("{}", ap.he_bss_color)));
            p.push(("Default PE Dur", format!("{}", ap.he_default_pe_dur)));
            p.push(("TWT Required", yes_no(ap.he_twt_required).to_string()));
        } else {
            p.push(("Status", s().dim().paint("not present")));
        }
        blocks.push(make_section("HE (WiFi 6)", &p));
    }

    // ── Operation IEs (conditional) ────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if ap.has_erp {
            p.push(("ERP Protection", yes_no(ap.erp_use_protection).to_string()));
            p.push(("Barker Preamble", yes_no(ap.erp_barker_preamble).to_string()));
        }
        if ap.has_ds {
            p.push(("DS Channel", format!("{}", ap.ds_channel)));
        }
        if ap.has_ht_oper {
            p.push(("HT Primary Ch", format!("{}", ap.ht_oper_primary_ch)));
            let offset = match ap.ht_oper_secondary_offset {
                0 => "none", 1 => "above", 3 => "below", _ => "reserved",
            };
            p.push(("HT 2nd Offset", offset.to_string()));
            p.push(("HT STA Width", if ap.ht_oper_sta_ch_width != 0 { "any" } else { "20 MHz" }.to_string()));
        }
        if ap.has_vht_oper {
            let vht_w = match ap.vht_oper_ch_width {
                0 => "20/40", 1 => "80", 2 => "160", 3 => "80+80", _ => "?",
            };
            p.push(("VHT Width", format!("{} MHz", vht_w)));
            if ap.vht_oper_center_seg0 > 0 {
                let f = if ap.vht_oper_center_seg0 <= 14 { 2407 + ap.vht_oper_center_seg0 as u16 * 5 }
                        else { 5000 + ap.vht_oper_center_seg0 as u16 * 5 };
                p.push(("VHT Seg0", format!("ch {} ({} MHz)", ap.vht_oper_center_seg0, f)));
            }
            if ap.vht_oper_center_seg1 > 0 {
                let f = if ap.vht_oper_center_seg1 <= 14 { 2407 + ap.vht_oper_center_seg1 as u16 * 5 }
                        else { 5000 + ap.vht_oper_center_seg1 as u16 * 5 };
                p.push(("VHT Seg1", format!("ch {} ({} MHz)", ap.vht_oper_center_seg1, f)));
            }
        }
        if !p.is_empty() {
            blocks.push(make_section("Operation", &p));
        }
    }

    emit_flex(blocks, width, lines);
}

// ───────────────────────────────────────────────────────────────────────────────
//  Tab 4: Clients (associated with THIS AP)
// ───────────────────────────────────────────────────────────────────────────────

fn render_ap_clients(ap: &Ap, clients: &[Station], width: u16, lines: &mut Vec<String>) {
    use prism::{ScrollCol, ScrollTableConfig};

    let w = width as usize;
    let ap_label = if ap.ssid.is_empty() { format!("{}", ap.bssid) } else { ap.ssid.clone() };
    lines.push(format!("  Stations associated with {} ({})",
        s().bold().paint(&ap_label),
        s().dim().paint(&format!("{} total", clients.len())),
    ));
    lines.push(String::new());

    if clients.is_empty() {
        lines.push(format!("  {}", s().dim().paint("No associated clients observed.")));
        return;
    }

    // Adaptive columns: MAC(17) RSSI(4) are core, rest drop as terminal narrows
    const COL_MAC: usize = 17;
    const COL_RSSI: usize = 4;
    const COL_GEN: usize = 5;
    const COL_FRAMES: usize = 7;
    const COL_DATA: usize = 7;
    const COL_PROBES: usize = 6;
    const COL_PS: usize = 2;
    const COL_VENDOR: usize = 12;
    const COL_SEP: usize = 2;

    let mut remaining = w.saturating_sub(4); // 2 indent + 2 buffer
    remaining -= COL_MAC + COL_RSSI + COL_SEP; // always show

    let show_gen = remaining >= COL_GEN + COL_SEP;
    if show_gen { remaining -= COL_GEN + COL_SEP; }
    let show_frames = remaining >= COL_FRAMES + COL_SEP;
    if show_frames { remaining -= COL_FRAMES + COL_SEP; }
    let show_data = remaining >= COL_DATA + COL_SEP;
    if show_data { remaining -= COL_DATA + COL_SEP; }
    let show_probes = remaining >= COL_PROBES + COL_SEP;
    if show_probes { remaining -= COL_PROBES + COL_SEP; }
    let show_ps = remaining >= COL_PS + COL_SEP;
    if show_ps { remaining -= COL_PS + COL_SEP; }
    let show_vendor = remaining >= COL_VENDOR;

    let mut cols = vec![
        ScrollCol::new("MAC", COL_MAC),
        ScrollCol::right("RSSI", COL_RSSI),
    ];
    if show_gen { cols.push(ScrollCol::new("GEN", COL_GEN)); }
    if show_frames { cols.push(ScrollCol::right("FRAMES", COL_FRAMES)); }
    if show_data { cols.push(ScrollCol::new("DATA", COL_DATA)); }
    if show_probes { cols.push(ScrollCol::right("PROBES", COL_PROBES)); }
    if show_ps { cols.push(ScrollCol::center("PS", COL_PS)); }
    if show_vendor { cols.push(ScrollCol::new("VENDOR", remaining.min(20))); }

    let rows: Vec<Vec<String>> = clients.iter().map(|sta| {
        let mac_str = format!("{}", sta.mac);
        let mac = if sta.mac.is_locally_administered() {
            s().yellow().paint(&mac_str)
        } else {
            s().bold().paint(&mac_str)
        };
        let mut row = vec![
            mac,
            style_rssi(sta.rssi),
        ];
        if show_gen { row.push(wifi_gen_short(&sta.wifi_gen).to_string()); }
        if show_frames { row.push(format!("{}", sta.frame_count)); }
        if show_data { row.push(format_bytes(sta.data_bytes)); }
        if show_probes { row.push(format!("{}", sta.probe_ssid_count)); }
        if show_ps { row.push(if sta.power_save { s().yellow().paint("Z") } else { " ".into() }); }
        if show_vendor {
            row.push(if sta.vendor.is_empty() { s().dim().paint("Unknown") } else { s().dim().paint(&sta.vendor) });
        }
        row
    }).collect();

    let result = prism::scroll_table(&ScrollTableConfig {
        columns: &cols,
        rows: &rows,
        height: 200, // no scroll limit here, outer scroll handles it
        indent: 2,
        empty_message: Some("No clients."),
        ..Default::default()
    });
    lines.extend(result.lines);
}

// ───────────────────────────────────────────────────────────────────────────────
//  Tab 5: Probes (related to THIS AP)
// ───────────────────────────────────────────────────────────────────────────────

fn render_ap_probes(ap: &Ap, probes: &[ProbeReq], clients: &[Station], width: u16, lines: &mut Vec<String>) {
    use prism::{ScrollCol, ScrollTableConfig};

    let w = width as usize;

    // ── Section 1: Probes FOR this SSID ────────────────────────────────
    let ssid_display = if ap.ssid.is_empty() { "<hidden>" } else { &ap.ssid };
    lines.push(format!("  {}", prism::header(
        &s().bold().paint(&format!("Probes FOR \"{}\"", ssid_display)),
        w.saturating_sub(4).min(60),
    )));

    let probes_for: Vec<&ProbeReq> = if !ap.ssid.is_empty() {
        probes.iter().filter(|p| p.ssid == ap.ssid).collect()
    } else {
        Vec::new()
    };

    if probes_for.is_empty() {
        lines.push(format!("  {}", s().dim().paint("No probes for this SSID observed.")));
    } else {
        // Adaptive: STATION(17) RSSI(4) always, COUNT and LAST SEEN drop
        let mut remaining = w.saturating_sub(4);
        remaining -= 17 + 4 + 2; // MAC + RSSI + sep
        let show_count = remaining >= 7;
        if show_count { remaining -= 7; }
        let show_last = remaining >= 10;

        let mut cols = vec![
            ScrollCol::new("STATION", 17),
            ScrollCol::right("RSSI", 4),
        ];
        if show_count { cols.push(ScrollCol::right("COUNT", 5)); }
        if show_last { cols.push(ScrollCol::new("LAST SEEN", 12)); }

        let rows: Vec<Vec<String>> = probes_for.iter().map(|probe| {
            let mac_str = format!("{}", probe.sta_mac);
            let mut row = vec![
                s().bold().paint(&mac_str),
                style_rssi(probe.rssi),
            ];
            if show_count { row.push(format!("{}", probe.count)); }
            if show_last { row.push(format!("{} ago", format_elapsed(probe.last_seen.elapsed()))); }
            row
        }).collect();

        let result = prism::scroll_table(&ScrollTableConfig {
            columns: &cols,
            rows: &rows,
            height: 200,
            indent: 2,
            ..Default::default()
        });
        lines.extend(result.lines);
    }

    // ── Section 2: Probes FROM this AP's clients ──────────────────────
    lines.push(String::new());
    lines.push(format!("  {}", prism::header(
        &s().bold().paint("Probes FROM this AP's clients"),
        w.saturating_sub(4).min(60),
    )));

    let client_macs: std::collections::HashSet<MacAddress> = clients.iter()
        .map(|sta| sta.mac)
        .collect();

    if client_macs.is_empty() {
        lines.push(format!("  {}", s().dim().paint("No associated clients.")));
        return;
    }

    let client_probes: Vec<&ProbeReq> = probes.iter()
        .filter(|p| client_macs.contains(&p.sta_mac))
        .filter(|p| !p.ssid.is_empty())
        .filter(|p| p.ssid != ap.ssid)
        .collect();

    if client_probes.is_empty() {
        lines.push(format!("  {}",
            s().dim().paint(&format!("{} clients associated, no other SSIDs probed.", client_macs.len()))));
        return;
    }

    // Group by client MAC
    let mut by_client: std::collections::HashMap<MacAddress, Vec<&ProbeReq>> = std::collections::HashMap::new();
    for probe in &client_probes {
        by_client.entry(probe.sta_mac).or_default().push(probe);
    }
    let mut client_keys: Vec<MacAddress> = by_client.keys().copied().collect();
    client_keys.sort_by(|a, b| {
        let a_count: u32 = by_client[a].iter().map(|p| p.count).sum();
        let b_count: u32 = by_client[b].iter().map(|p| p.count).sum();
        b_count.cmp(&a_count)
    });

    lines.push(format!("  {}",
        s().dim().paint(&format!("{} clients probing for {} other SSIDs:",
            by_client.len(), client_probes.len()))));
    lines.push(String::new());

    // Adaptive: CLIENT(17) SSID(variable) always, RSSI COUNT LAST drop
    let mut remaining = w.saturating_sub(4);
    remaining -= 17 + 2; // CLIENT + sep
    let show_rssi = remaining >= 6;
    if show_rssi { remaining -= 6; }
    let show_count = remaining >= 7;
    if show_count { remaining -= 7; }
    let show_last = remaining >= 12;
    if show_last { remaining -= 12; }
    let ssid_width = remaining.min(24).max(10);

    let mut cols = vec![
        ScrollCol::new("CLIENT", 17),
        ScrollCol::new("PROBED SSID", ssid_width),
    ];
    if show_rssi { cols.push(ScrollCol::right("RSSI", 4)); }
    if show_count { cols.push(ScrollCol::right("COUNT", 5)); }
    if show_last { cols.push(ScrollCol::new("LAST SEEN", 10)); }

    // Flatten: each probe is a row, MAC shown only on first row per client
    let mut rows: Vec<Vec<String>> = Vec::new();
    for mac in &client_keys {
        let probes_list = &by_client[mac];
        let mac_str = format!("{}", mac);
        let is_random = mac.is_locally_administered();

        let mut sorted_probes = probes_list.clone();
        sorted_probes.sort_by(|a, b| b.count.cmp(&a.count));

        for (j, probe) in sorted_probes.iter().enumerate() {
            let mac_cell = if j == 0 {
                if is_random { s().yellow().paint(&mac_str) }
                else { s().bold().paint(&mac_str) }
            } else {
                String::new()
            };

            let ssid_cell = truncate(&probe.ssid, ssid_width, "\u{2026}");

            let mut row = vec![mac_cell, s().bold().paint(&ssid_cell)];
            if show_rssi { row.push(style_rssi(probe.rssi)); }
            if show_count { row.push(format!("{}", probe.count)); }
            if show_last { row.push(format!("{} ago", format_elapsed(probe.last_seen.elapsed()))); }
            rows.push(row);
        }
    }

    let result = prism::scroll_table(&ScrollTableConfig {
        columns: &cols,
        rows: &rows,
        height: 200,
        indent: 2,
        ..Default::default()
    });
    lines.extend(result.lines);

    lines.push(String::new());
    lines.push(format!("  {}",
        s().dim().paint("Clients probing other SSIDs are potential evil twin targets.")));
}

// ───────────────────────────────────────────────────────────────────────────────
//  Tab 6: Features
// ───────────────────────────────────────────────────────────────────────────────

fn render_ap_features(ap: &Ap, width: u16, lines: &mut Vec<String>) {
    let mut blocks = Vec::new();

    // ── 802.11r Fast Transition ────────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = vec![("Supported", yes_no(ap.has_ft).to_string())];
        if ap.has_ft {
            p.push(("FT over DS", yes_no(ap.ft_over_ds).to_string()));
            p.push(("Mobility Domain", format!("{:#06X}", ap.ft_mdid)));
        }
        blocks.push(make_section("802.11r FT", &p));
    }

    // ── 802.11k Radio Measurement ──────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = vec![("Enabled", yes_no(ap.has_rm).to_string())];
        if ap.has_rm {
            p.push(("Link Meas", yes_no(ap.rm_link_meas).to_string()));
            p.push(("Neighbor Rpt", yes_no(ap.rm_neighbor_report).to_string()));
            p.push(("Bcn Passive", yes_no(ap.rm_beacon_passive).to_string()));
            p.push(("Bcn Active", yes_no(ap.rm_beacon_active).to_string()));
            p.push(("Bcn Table", yes_no(ap.rm_beacon_table).to_string()));
        }
        blocks.push(make_section("802.11k RM", &p));
    }

    // ── 802.11v Extended Capabilities ──────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = vec![("Present", yes_no(ap.has_ext_cap).to_string())];
        if ap.has_ext_cap {
            p.push(("BSS Transition", yes_no(ap.ext_cap_bss_transition).to_string()));
            p.push(("WNM Sleep", yes_no(ap.ext_cap_wnm_sleep).to_string()));
            p.push(("TFS", yes_no(ap.ext_cap_tfs).to_string()));
            p.push(("Proxy ARP", yes_no(ap.ext_cap_proxy_arp).to_string()));
            p.push(("FMS", yes_no(ap.ext_cap_fms).to_string()));
            p.push(("TIM Broadcast", yes_no(ap.ext_cap_tim_broadcast).to_string()));
            p.push(("Interworking", yes_no(ap.ext_cap_interworking).to_string()));
        }
        blocks.push(make_section("802.11v ExtCap", &p));
    }

    // ── QoS / QBSS ────────────────────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if ap.has_qbss {
            p.push(("Stations", format!("{}", ap.qbss_station_count)));
            let util_pct = (ap.qbss_utilization as f64 / 255.0) * 100.0;
            p.push(("Ch Utilization", format!("{:.1}% ({}/255)", util_pct, ap.qbss_utilization)));
            p.push(("Admission Cap", format!("{}", ap.qbss_admission_cap)));
        } else {
            p.push(("QBSS", s().dim().paint("not present")));
        }
        if ap.has_tim {
            p.push(("DTIM Period", format!("{}", ap.dtim_period)));
            p.push(("DTIM Count", format!("{}", ap.dtim_count)));
        }
        if ap.has_qos {
            p.push(("QoS Info", format!("{:#04X}", ap.qos_info)));
        }
        blocks.push(make_section("QoS", &p));
    }

    // ── Other Features ─────────────────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = vec![
            ("Hotspot 2.0", present_absent(ap.has_hs20).to_string()),
            ("WMM", present_absent(ap.has_wmm).to_string()),
            ("P2P", present_absent(ap.has_p2p).to_string()),
        ];
        if ap.has_interworking {
            let net_type = match ap.interworking_type & 0x0F {
                0 => "Private", 1 => "Private+Guest", 2 => "Chargeable",
                3 => "Free Public", 4 => "Personal", 5 => "Emergency",
                14 => "Test", 15 => "Wildcard", _ => "Reserved",
            };
            p.push(("Net Type", net_type.to_string()));
            p.push(("Internet", yes_no(ap.has_internet).to_string()));
        }
        if ap.is_mesh {
            p.push(("Mesh ID", if ap.mesh_id.is_empty() { "<empty>".into() } else { ap.mesh_id.clone() }));
        }
        if ap.has_multi_bssid {
            let virtual_aps = 1u32 << ap.max_bssid_indicator;
            p.push(("Multi-BSSID", format!("{} virtual APs", virtual_aps)));
        }
        if ap.has_rnr {
            p.push(("Neighbors (RNR)", format!("{}", ap.rnr_ap_count)));
        }
        if ap.has_csa {
            p.push(("CSA", format!("ch {} (count {})", ap.csa_new_channel, ap.csa_count)));
        }
        if !ap.operating_classes.is_empty() {
            let classes: Vec<String> = ap.operating_classes.iter().map(|c| format!("{}", c)).collect();
            p.push(("Op Classes", classes.join(", ")));
        }
        blocks.push(make_section("Other", &p));
    }

    emit_flex(blocks, width, lines);
}

// ───────────────────────────────────────────────────────────────────────────────
//  Tab 7: Timing
// ───────────────────────────────────────────────────────────────────────────────

fn render_ap_timing(ap: &Ap, bt: Option<&BeaconTiming>, width: u16, lines: &mut Vec<String>) {
    let mut blocks = Vec::new();

    // ── TSF & Uptime ───────────────────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = vec![
            ("TSF", format!("{} \u{00b5}s", ap.tsf)),
        ];
        if ap.tsf > 0 {
            p.push(("Est. Uptime", format_tsf_uptime(ap.tsf)));
        }
        blocks.push(make_section("TSF & Uptime", &p));
    }

    // ── Beacon Timing ──────────────────────────────────────────────────
    {
        let mut p: Vec<(&str, String)> = vec![
            ("Interval", format!("{} TU ({:.1} ms)", ap.beacon_interval, ap.beacon_interval as f64 * 1.024)),
            ("Beacons Rx", format!("{}", ap.beacon_count)),
        ];
        if let Some(bt) = bt {
            let measured_ms = bt.measured_mean.as_micros() as f64 / 1000.0;
            p.push(("Measured Mean", format!("{:.2} ms", measured_ms)));
            p.push(("Jitter", format!("{:.2} ms", bt.jitter_stddev / 1000.0)));
            p.push(("Loss Count", format!("{}", bt.beacon_loss_count)));
            p.push(("Loss Rate", if bt.beacon_loss_rate > 5.0 {
                s().red().paint(&format!("{:.1}%", bt.beacon_loss_rate))
            } else {
                format!("{:.1}%", bt.beacon_loss_rate)
            }));
            p.push(("Samples", format!("{}", bt.samples)));
        } else {
            let observed_secs = ap.last_seen.duration_since(ap.first_seen).as_secs_f64();
            if observed_secs > 0.0 && ap.beacon_count > 0 {
                let beacons_per_sec = ap.beacon_count as f64 / observed_secs;
                let expected_per_sec = 1000.0 / (ap.beacon_interval as f64 * 1.024);
                p.push(("Measured Rate", format!("{:.1}/sec", beacons_per_sec)));
                p.push(("Expected Rate", format!("{:.1}/sec", expected_per_sec)));
                if expected_per_sec > 0.0 {
                    let expected_total = (expected_per_sec * observed_secs) as u32;
                    let loss = expected_total.saturating_sub(ap.beacon_count);
                    let loss_pct = if expected_total > 0 { loss as f64 / expected_total as f64 * 100.0 } else { 0.0 };
                    p.push(("Beacon Loss", format!("{} ({:.1}%)", loss, loss_pct)));
                }
            }
        }
        blocks.push(make_section("Beacon Timing", &p));
    }

    // ── TSF Drift (only with BeaconTiming) ─────────────────────────────
    if let Some(bt) = bt {
        let mut p: Vec<(&str, String)> = vec![
            ("Drift Rate", format!("{:.2} ppm", bt.tsf_drift_ppm)),
        ];
        if bt.tsf_jumps > 0 {
            p.push(("TSF Jumps", s().yellow().bold().paint(&format!("{} (reboot)", bt.tsf_jumps))));
        } else {
            p.push(("TSF Jumps", s().green().paint("0")));
        }
        blocks.push(make_section("TSF Drift", &p));
    }

    // ── RSSI Trend ─────────────────────────────────────────────────────
    {
        let p: Vec<(&str, String)> = vec![
            ("Current", style_rssi(ap.rssi)),
            ("Best", style_rssi(ap.rssi_best)),
            ("Worst", style_rssi(ap.rssi_worst)),
            ("Signal", rssi_bar(ap.rssi, 10)),
        ];
        blocks.push(make_section("RSSI", &p));
    }

    // ── Observation Window ─────────────────────────────────────────────
    {
        let p: Vec<(&str, String)> = vec![
            ("First Seen", format!("{} ago", format_elapsed(ap.first_seen.elapsed()))),
            ("Last Seen", format!("{} ago", format_elapsed(ap.last_seen.elapsed()))),
            ("Observed", format_elapsed(ap.last_seen.duration_since(ap.first_seen))),
        ];
        blocks.push(make_section("Observation", &p));
    }

    emit_flex(blocks, width, lines);
}

// ───────────────────────────────────────────────────────────────────────────────
//  Tab 8: Attack Surface
// ───────────────────────────────────────────────────────────────────────────────

fn render_ap_attack_surface(ap: &Ap, lines: &mut Vec<String>) {
    let ind = 4;

    lines.push(section_header("Automated Vulnerability Assessment", ind));
    lines.push(String::new());

    // Table header
    lines.push(format!("{}{}  {}  {}",
        " ".repeat(ind),
        pad_right(&s().bold().dim().paint("FINDING"), 30, "FINDING"),
        pad_right(&s().bold().dim().paint("SEVERITY"), 8, "SEVERITY"),
        s().bold().dim().paint("COMMAND"),
    ));
    lines.push(format!("{}{}", " ".repeat(ind), s().dim().paint(&prism::divider("\u{2500}",65))));

    let mut findings = Vec::new();

    // Deauth vulnerable
    if let Some(ref rsn) = ap.rsn {
        if !rsn.mfp_required {
            findings.push(("Deauth vulnerable", "HIGH", "/deauth", "PMF not required"));
        }
    } else if ap.security != Security::Open {
        findings.push(("Deauth vulnerable", "HIGH", "/deauth", "No RSN IE"));
    }

    // WPS Pixie Dust
    if ap.wps_state != WpsState::None && !ap.wps_locked {
        findings.push(("WPS Pixie Dust", "HIGH", "/wps --pixie", "WPS enabled, not locked"));
    }

    // WPS Brute Force (even if locked)
    if ap.wps_state != WpsState::None {
        findings.push(("WPS Brute Force", "MEDIUM", "/wps", "WPS present"));
    }

    // PMKID
    if matches!(ap.security, Security::Wpa2 | Security::Wpa3) {
        if ap.rsn.as_ref().map_or(false, |r| r.akm_suites.iter().any(|a| matches!(a, AkmSuite::Psk | AkmSuite::PskSha256 | AkmSuite::Sae))) {
            findings.push(("PMKID extraction", "MEDIUM", "/pmkid", "PSK/SAE AKM"));
        }
    }

    // KRACK FT
    if ap.has_ft {
        findings.push(("KRACK FT variant", "MEDIUM", "/krack --variant ft", "FT enabled (CVE-2017-13082)"));
    }

    // KRACK WNM
    if ap.ext_cap_wnm_sleep {
        findings.push(("KRACK WNM-Sleep", "MEDIUM", "/krack --variant wnm-gtk", "WNM Sleep (CVE-2017-13087)"));
    }

    // KRACK TDLS
    if ap.ext_cap_tdls {
        findings.push(("KRACK TDLS", "MEDIUM", "/krack --variant tdls", "TDLS capable (CVE-2017-13086)"));
    }

    // WPA3 Downgrade
    if matches!(ap.security, Security::Wpa3) {
        if ap.rsn.as_ref().map_or(false, |r| r.akm_suites.contains(&AkmSuite::Psk)) {
            findings.push(("WPA3 Downgrade", "MEDIUM", "/wpa3 --transition", "SAE+PSK transition mode"));
        }
    }

    // WPA3 Timing
    if matches!(ap.security, Security::Wpa3) {
        findings.push(("WPA3 Timing Attack", "LOW", "/wpa3 --timing", "SAE enabled"));
    }

    // Enterprise credential capture
    if matches!(ap.security, Security::Wpa2Enterprise | Security::Wpa3Enterprise) {
        findings.push(("Enterprise credentials", "HIGH", "/eap", "Enterprise AKM"));
    }

    // FragAttacks (always applicable)
    findings.push(("FragAttacks", "LOW", "/frag", "Design flaw (CVE-2020-24586+)"));

    // TKIP
    if let Some(ref rsn) = ap.rsn {
        if rsn.pairwise_ciphers.contains(&CipherSuite::Tkip) {
            findings.push(("TKIP Michael", "LOW", "(info)", "TKIP in pairwise"));
        }
    }

    for (finding, severity, cmd, reason) in &findings {
        let sev_styled = match *severity {
            "HIGH" => s().red().bold().paint(severity),
            "MEDIUM" => s().yellow().paint(severity),
            "LOW" => s().dim().paint(severity),
            _ => severity.to_string(),
        };
        let cmd_styled = if *cmd == "(info)" {
            s().dim().paint(cmd)
        } else {
            s().cyan().paint(cmd)
        };

        lines.push(format!("{}{}  {}  {}",
            " ".repeat(ind),
            pad_right(finding, 30, finding),
            pad_right(&sev_styled, 8, severity),
            cmd_styled,
        ));
        lines.push(format!("{}  {}", " ".repeat(ind), s().dim().paint(&format!("\u{2514} {}", reason))));
    }

    if findings.is_empty() {
        lines.push(format!("{}{}", " ".repeat(ind), s().green().paint("No significant vulnerabilities detected.")));
    }

    lines.push(String::new());
    lines.push(format!("{}{} findings", " ".repeat(ind), s().bold().paint(&format!("{}", findings.len()))));
}

// ───────────────────────────────────────────────────────────────────────────────
//  Tab 9: IEs (Raw)
// ───────────────────────────────────────────────────────────────────────────────

fn render_ap_ies(ap: &Ap, _width: u16, lines: &mut Vec<String>) {
    let ind = 4;

    lines.push(section_header("Information Element Inventory", ind));
    lines.push(String::new());

    if ap.raw_ies.is_empty() {
        lines.push(format!("{}{}", " ".repeat(ind), s().dim().paint("No raw IEs captured.")));
        return;
    }

    // Table header
    lines.push(format!("{}{}  {}  {}  {}",
        " ".repeat(ind),
        pad_right(&s().bold().dim().paint("TAG"), 4, "TAG"),
        pad_right(&s().bold().dim().paint("NAME"), 28, "NAME"),
        pad_right(&s().bold().dim().paint("LEN"), 4, "LEN"),
        s().bold().dim().paint("BODY (hex)"),
    ));
    lines.push(format!("{}{}", " ".repeat(ind), s().dim().paint(&prism::divider("\u{2500}",70))));

    // Parse raw IE blob
    let mut offset = 0;
    let data = &ap.raw_ies;
    while offset + 2 <= data.len() {
        let tag = data[offset];
        let len = data[offset + 1] as usize;

        if offset + 2 + len > data.len() {
            break; // malformed
        }

        let body = &data[offset + 2..offset + 2 + len];

        // IE name lookup
        let name = ie_tag_name(tag);

        // For IE 255, check extension element ID
        let (display_tag, display_name) = if tag == 255 && !body.is_empty() {
            let ext_id = body[0];
            let ext_name = ie_ext_tag_name(ext_id);
            (format!("255/{}", ext_id), ext_name.to_string())
        } else {
            (format!("{:>3}", tag), name.to_string())
        };

        // For Vendor IEs (221), decode OUI
        let display_name = if tag == 221 && body.len() >= 3 {
            let oui = [body[0], body[1], body[2]];
            let vendor = vendor_oui_name(&oui);
            format!("Vendor: {}", vendor)
        } else {
            display_name
        };

        // Hex body (truncated for display)
        let hex: String = body.iter().take(24).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
        let truncated = if body.len() > 24 { format!("{} ...", hex) } else { hex };

        lines.push(format!("{}{}  {}  {}  {}",
            " ".repeat(ind),
            pad_right(&s().dim().paint(&display_tag), 4, &display_tag),
            pad_right(&display_name, 28, &display_name),
            pad_right(&format!("{:>3}", len), 4, &format!("{}", len)),
            s().dim().paint(&truncated),
        ));

        offset += 2 + len;
    }

    lines.push(String::new());
    lines.push(format!("{}{} IEs, {} bytes total",
        " ".repeat(ind),
        s().bold().paint(&format!("{}", {
            let mut count = 0;
            let mut o = 0;
            while o + 2 <= data.len() {
                let l = data[o + 1] as usize;
                if o + 2 + l > data.len() { break; }
                count += 1;
                o += 2 + l;
            }
            count
        })),
        s().dim().paint(&format!("{}", data.len())),
    ));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Client Detail — 6 tabs
// ═══════════════════════════════════════════════════════════════════════════════

pub fn client_tab_name(tab: u8) -> &'static str {
    match tab {
        1 => "Overview",
        2 => "Fingerprint",
        3 => "Probes",
        4 => "Sequences",
        5 => "Activity",
        6 => "Raw",
        _ => "?",
    }
}

/// Render Client detail view. Returns the number of lines that should be pinned.
pub fn render_client_detail(
    sta: &Station,
    probes: &[ProbeReq],
    tab: u8,
    width: u16,
    lines: &mut Vec<String>,
) -> usize {
    // Adaptive tab bar
    let available = (width as usize).saturating_sub(2);
    let tab_line = render_adaptive_tabs(tab, 6, client_tab_name, client_tab_short, available);
    let tab_vis_width = prism::measure_width(&tab_line);
    lines.push(format!("  {}", tab_line));
    lines.push(format!("  {}", s().dim().paint(&prism::divider("─", tab_vis_width))));
    lines.push(String::new());

    match tab {
        1 => render_client_overview(sta, probes, width, lines),
        2 => render_client_fingerprint(sta, width, lines),
        3 => render_client_probes(sta, probes, width, lines),
        4 => render_client_sequences(sta, width, lines),
        5 => render_client_activity(sta, width, lines),
        6 => render_client_raw(sta, width, lines),
        _ => { lines.push(format!("  {}", s().dim().paint("Unknown tab"))); }
    }

    // 3 shared headers (tab bar + separator + blank) + tab-specific table headers
    let tab_pin = match tab {
        3 => 4, // Probes: title + blank + header row + separator
        5 => 4, // Activity TID table: section headers before TID table
        _ => 0,
    };
    let pin_count = 3 + tab_pin;

    lines.push(String::new());
    lines.push(format!("  {}  {}  {}",
        s().dim().paint("1-6: switch tabs"),
        s().dim().paint("Tab: next tab"),
        s().dim().paint("Esc: back"),
    ));

    pin_count
}

// ───────────────────────────────────────────────────────────────────────────────
//  Client Tab 1: Overview
// ───────────────────────────────────────────────────────────────────────────────

fn render_client_overview(sta: &Station, _probes: &[ProbeReq], width: u16, lines: &mut Vec<String>) {
    let mut blocks = Vec::new();

    let identity = {
        let mut p: Vec<(&str, String)> = vec![
            ("MAC", format!("{}", sta.mac)),
            ("Vendor", if sta.vendor.is_empty() { "Unknown".into() } else { sta.vendor.clone() }),
            ("Randomized", yes_no(sta.mac.is_locally_administered()).to_string()),
            ("Associated", yes_no(sta.is_associated).to_string()),
        ];
        if let Some(ref bssid) = sta.bssid {
            p.push(("AP (BSSID)", format!("{}", bssid)));
        }
        make_section("Identity", &p)
    };
    blocks.push(identity);

    blocks.push(make_section("Signal", &[
        ("Current", style_rssi(sta.rssi)),
        ("Best", style_rssi(sta.rssi_best)),
        ("Signal", rssi_bar(sta.rssi, 10)),
        ("Channel", format!("{}", sta.last_channel)),
    ]));

    let activity = {
        let mut p: Vec<(&str, String)> = vec![
            ("Frames", format!("{}", sta.frame_count)),
            ("Data", format_bytes(sta.data_bytes)),
            ("Probe SSIDs", format!("{}", sta.probe_ssid_count)),
        ];
        if !sta.last_probe_ssid.is_empty() {
            p.push(("Last Probe", sta.last_probe_ssid.clone()));
        }
        make_section("Activity", &p)
    };
    blocks.push(activity);

    blocks.push(make_section("Timing", &[
        ("First Seen", format!("{} ago", format_elapsed(sta.first_seen.elapsed()))),
        ("Last Seen", format!("{} ago", format_elapsed(sta.last_seen.elapsed()))),
        ("Observed", format_elapsed(sta.last_seen.duration_since(sta.first_seen))),
    ]));

    emit_flex(blocks, width, lines);
}

// ───────────────────────────────────────────────────────────────────────────────
//  Client Tab 2: Fingerprint
// ───────────────────────────────────────────────────────────────────────────────

fn render_client_fingerprint(sta: &Station, width: u16, lines: &mut Vec<String>) {
    let mut blocks = Vec::new();

    // Identity
    {
        let mut p: Vec<(&str, String)> = vec![
            ("Vendor", if sta.vendor.is_empty() { "Unknown".into() } else { sta.vendor.clone() }),
            ("Randomized", yes_no(sta.is_randomized).to_string()),
            ("WiFi Gen", sta.wifi_gen.name().to_string()),
        ];
        if sta.is_randomized {
            p.push(("Note", s().yellow().paint("MAC randomized")));
        }
        blocks.push(make_section("Identity", &p));
    }

    // IE Tag Ordering
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if sta.ie_tag_order.is_empty() {
            p.push(("Status", s().dim().paint("no IEs captured")));
        } else {
            let tags: Vec<String> = sta.ie_tag_order.iter().map(|t| format!("{}", t)).collect();
            p.push(("Tag Count", format!("{}", sta.ie_tag_count)));
            p.push(("Tag Order", tags.join(", ")));
        }
        blocks.push(make_section("IE Fingerprint", &p));
    }

    // Rates
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if sta.supported_rates.is_empty() {
            p.push(("Rates", s().dim().paint("none captured")));
        } else {
            let rates: Vec<String> = sta.supported_rates.iter().map(|r| {
                let basic = r & 0x80 != 0;
                let rate_val = (r & 0x7F) as f64 / 2.0;
                if basic { s().bold().paint(&format!("{:.1}*", rate_val)) }
                else { format!("{:.1}", rate_val) }
            }).collect();
            p.push(("Rates (Mbps)", rates.join(", ")));
        }
        blocks.push(make_section("Rates", &p));
    }

    // HT
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if !sta.has_ht {
            p.push(("Status", s().dim().paint("not present")));
        } else {
            let ht40 = sta.ht_cap_raw & 0x0002 != 0;
            let sgi20 = sta.ht_cap_raw & 0x0020 != 0;
            let sgi40 = sta.ht_cap_raw & 0x0040 != 0;
            let ldpc = sta.ht_cap_raw & 0x0001 != 0;
            let tx_stbc = sta.ht_cap_raw & 0x0080 != 0;
            let rx_stbc = (sta.ht_cap_raw >> 8) & 0x03;
            let sm_ps = match (sta.ht_cap_raw >> 2) & 0x03 {
                0 => "static", 1 => "dynamic", 3 => "disabled", _ => "reserved",
            };
            p.push(("HT40", yes_no(ht40).to_string()));
            p.push(("SGI 20/40", format!("{}/{}", yes_no(sgi20), yes_no(sgi40))));
            p.push(("LDPC", yes_no(ldpc).to_string()));
            p.push(("TX STBC", yes_no(tx_stbc).to_string()));
            p.push(("RX STBC", format!("{} stream(s)", rx_stbc)));
            p.push(("SM PS", sm_ps.to_string()));
        }
        blocks.push(make_section("HT", &p));
    }

    // VHT
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if !sta.has_vht {
            p.push(("Status", s().dim().paint("not present")));
        } else {
            let max_mpdu = match sta.vht_cap_raw & 0x03 { 0 => 3895, 1 => 7991, 2 => 11454, _ => 3895 };
            let w = match (sta.vht_cap_raw >> 2) & 0x03 { 0 => "80 MHz", 1 => "160 MHz", 2 => "80+80", _ => "reserved" };
            let sgi80 = sta.vht_cap_raw & (1 << 5) != 0;
            let sgi160 = sta.vht_cap_raw & (1 << 6) != 0;
            let su_bf = sta.vht_cap_raw & (1 << 11) != 0;
            let mu_bf = sta.vht_cap_raw & (1 << 19) != 0;
            p.push(("Max MPDU", format!("{} B", max_mpdu)));
            p.push(("Width", w.to_string()));
            p.push(("SGI 80/160", format!("{}/{}", yes_no(sgi80), yes_no(sgi160))));
            p.push(("SU BF", yes_no(su_bf).to_string()));
            p.push(("MU BF", yes_no(mu_bf).to_string()));
        }
        blocks.push(make_section("VHT", &p));
    }

    // HE + Association Params
    {
        let spacing = match sta.ampdu_min_spacing {
            0 => "none", 1 => "1/4\u{00b5}s", 2 => "1/2\u{00b5}s",
            3 => "1\u{00b5}s", 4 => "2\u{00b5}s", 5 => "4\u{00b5}s",
            6 => "8\u{00b5}s", 7 => "16\u{00b5}s", _ => "?",
        };
        let mut p: Vec<(&str, String)> = vec![
            ("HE (WiFi 6)", yes_no(sta.has_he).to_string()),
            ("Listen Int", if sta.listen_interval > 0 { format!("{}", sta.listen_interval) } else { s().dim().paint("n/a") }),
            ("A-MPDU Max", format!("{}KB", 8 << sta.ampdu_max_len_exp)),
            ("A-MPDU Spacing", spacing.to_string()),
            ("Streams", format!("{}x{}", sta.max_nss, sta.max_nss)),
        ];
        if sta.max_rate_mbps > 0 {
            p.push(("Max Rate", format!("{} Mbps", sta.max_rate_mbps)));
        }
        blocks.push(make_section("HE & Assoc", &p));
    }

    emit_flex(blocks, width, lines);
}

// ───────────────────────────────────────────────────────────────────────────────
//  Client Tab 3: Probes
// ───────────────────────────────────────────────────────────────────────────────

fn render_client_probes(sta: &Station, probes: &[ProbeReq], width: u16, lines: &mut Vec<String>) {
    use prism::{ScrollCol, ScrollTableConfig};

    lines.push(format!("  {} ({})",
        prism::header(&s().bold().paint(&format!("Probes from {}", sta.mac)), 40),
        s().dim().paint(&format!("{} total", probes.len())),
    ));

    if probes.is_empty() {
        lines.push(format!("  {}", s().dim().paint("No probe requests captured.")));
        return;
    }

    let w = width as usize;
    let mut remaining = w.saturating_sub(4);
    remaining -= 24 + 4 + 2; // SSID + RSSI + sep
    let show_count = remaining >= 7;
    if show_count { remaining -= 7; }
    let show_last = remaining >= 12;

    let mut cols = vec![
        ScrollCol::new("SSID", 24),
        ScrollCol::right("RSSI", 4),
    ];
    if show_count { cols.push(ScrollCol::right("COUNT", 5)); }
    if show_last { cols.push(ScrollCol::new("LAST SEEN", 12)); }

    let mut sorted = probes.to_vec();
    sorted.sort_by(|a, b| b.count.cmp(&a.count));

    let rows: Vec<Vec<String>> = sorted.iter().map(|probe| {
        let ssid = if probe.ssid.is_empty() {
            s().dim().italic().paint("(wildcard)")
        } else {
            s().bold().paint(&truncate(&probe.ssid, 24, "\u{2026}"))
        };
        let mut row = vec![ssid, style_rssi(probe.rssi)];
        if show_count { row.push(format!("{}", probe.count)); }
        if show_last { row.push(format!("{} ago", format_elapsed(probe.last_seen.elapsed()))); }
        row
    }).collect();

    let result = prism::scroll_table(&ScrollTableConfig {
        columns: &cols,
        rows: &rows,
        height: 200,
        indent: 2,
        ..Default::default()
    });
    lines.extend(result.lines);

    let wildcard_count = probes.iter().filter(|p| p.ssid.is_empty()).count();
    if wildcard_count > 0 {
        lines.push(format!("  {}", s().dim().paint(&format!("{} wildcard probes (scanning for any network)", wildcard_count))));
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  Client Tab 4: Sequences
// ───────────────────────────────────────────────────────────────────────────────

fn render_client_sequences(sta: &Station, width: u16, lines: &mut Vec<String>) {
    if sta.frame_count == 0 {
        lines.push(format!("  {}", s().dim().paint("No frames captured yet.")));
        return;
    }

    let mut blocks = Vec::new();

    // Sequence Tracking
    {
        let range = if sta.seq_num_last >= sta.seq_num_first {
            sta.seq_num_last - sta.seq_num_first
        } else {
            (4096 - sta.seq_num_first as u32 + sta.seq_num_last as u32) as u16
        };
        let gaps_val = if sta.seq_num_gaps > 0 {
            s().yellow().bold().paint(&format!("{}", sta.seq_num_gaps))
        } else {
            s().green().paint("0")
        };
        blocks.push(make_section("Seq Tracking", &[
            ("First Seq#", format!("{}", sta.seq_num_first)),
            ("Last Seq#", format!("{}", sta.seq_num_last)),
            ("Range", format!("{} / 4096", range)),
            ("Gaps", gaps_val),
            ("Frames", format!("{}", sta.frame_count)),
        ]));
    }

    // Continuity Analysis
    {
        let range = if sta.seq_num_last >= sta.seq_num_first {
            sta.seq_num_last - sta.seq_num_first
        } else {
            (4096 - sta.seq_num_first as u32 + sta.seq_num_last as u32) as u16
        };
        let mut p: Vec<(&str, String)> = Vec::new();
        if range > 0 && sta.frame_count > 1 {
            let expected = range as u32 + 1;
            let coverage = (sta.frame_count as f64 / expected as f64 * 100.0).min(100.0);
            p.push(("Expected", format!("{}", expected)));
            p.push(("Captured", format!("{} ({:.1}%)", sta.frame_count, coverage)));
            if sta.seq_num_gaps > 0 {
                let gap_rate = sta.seq_num_gaps as f64 / sta.frame_count as f64 * 100.0;
                p.push(("Gap Rate", format!("{:.1}%", gap_rate)));
            }
        } else {
            p.push(("Status", s().dim().paint("insufficient data")));
        }
        blocks.push(make_section("Continuity", &p));
    }

    // MAC Randomization
    {
        let mut p: Vec<(&str, String)> = Vec::new();
        if sta.is_randomized {
            p.push(("MAC Type", s().yellow().paint("randomized")));
            p.push(("Seq Range", format!("{}\u{2013}{}", sta.seq_num_first, sta.seq_num_last)));
            p.push(("Note", s().dim().paint("seq# persists across MAC changes")));
        } else {
            p.push(("MAC Type", s().green().paint("globally unique")));
        }
        blocks.push(make_section("MAC Tracking", &p));
    }

    emit_flex(blocks, width, lines);
}

// ───────────────────────────────────────────────────────────────────────────────
//  Client Tab 5: Activity
// ───────────────────────────────────────────────────────────────────────────────

fn render_client_activity(sta: &Station, width: u16, lines: &mut Vec<String>) {
    let mut blocks = Vec::new();

    // Traffic Summary
    {
        let mut p: Vec<(&str, String)> = vec![
            ("Frames", format!("{}", sta.frame_count)),
            ("Data", format_bytes(sta.data_bytes)),
        ];
        let observed_secs = sta.last_seen.duration_since(sta.first_seen).as_secs_f64();
        if observed_secs > 0.0 {
            p.push(("Frames/sec", format!("{:.1}", sta.frame_count as f64 / observed_secs)));
            p.push(("Data Rate", format!("{}/s", format_bytes((sta.data_bytes as f64 / observed_secs) as u64))));
        }
        blocks.push(make_section("Traffic", &p));
    }

    // Power Management
    {
        let ps_val = if sta.power_save { s().yellow().paint("sleeping (Z)") } else { s().green().paint("awake") };
        blocks.push(make_section("Power Mgmt", &[
            ("State", ps_val),
            ("Transitions", format!("{}", sta.power_save_transitions)),
        ]));
    }

    // Probe Timing
    if sta.avg_probe_interval_ms > 0 {
        blocks.push(make_section("Probe Timing", &[
            ("Avg Interval", format!("{} ms", sta.avg_probe_interval_ms)),
        ]));
    }

    emit_flex(blocks, width, lines);

    // QoS TID distribution — full-width table (not flexed)
    lines.push(String::new());
    lines.push(format!("  {}", prism::header(&s().bold().paint("QoS TID Distribution"), 50)));

    let total_tid: u32 = sta.tid_counts.iter().sum();
    if total_tid == 0 {
        lines.push(format!("  {}", s().dim().paint("No QoS data frames captured.")));
    } else {
        let tid_names = [
            "Best Effort (BE)", "Background (BK)", "Background (BK)", "Best Effort (BE)",
            "Video (VI)", "Video (VI)", "Voice (VO)", "Voice (VO)",
        ];

        lines.push(format!("  {}  {}  {}  {}",
            pad_right(&s().bold().dim().paint("TID"), 3, "TID"),
            pad_right(&s().bold().dim().paint("ACCESS CAT"), 20, "ACCESS CAT"),
            pad_right(&s().bold().dim().paint("FRAMES"), 14, "FRAMES"),
            s().bold().dim().paint("BAR"),
        ));
        lines.push(format!("  {}", s().dim().paint(&prism::divider("\u{2500}",55))));

        let max_count = *sta.tid_counts.iter().max().unwrap_or(&1);

        for (tid, count) in sta.tid_counts.iter().enumerate() {
            let pct = if total_tid > 0 { *count as f64 / total_tid as f64 * 100.0 } else { 0.0 };
            let bar_len = if max_count > 0 { (*count as f64 / max_count as f64 * 20.0) as usize } else { 0 };
            let bar = "\u{2588}".repeat(bar_len);
            let bar_styled = match tid {
                6 | 7 => s().red().paint(&bar),
                4 | 5 => s().yellow().paint(&bar),
                0 | 3 => s().cyan().paint(&bar),
                _ => s().dim().paint(&bar),
            };
            let count_str = if *count > 0 {
                format!("{:>6} ({:>4.1}%)", count, pct)
            } else {
                s().dim().paint("     0").to_string()
            };

            lines.push(format!("  {}  {}  {}  {}",
                pad_right(&format!("{}", tid), 3, &format!("{}", tid)),
                pad_right(tid_names[tid], 20, tid_names[tid]),
                count_str,
                bar_styled,
            ));
        }

        let voice_pct = (sta.tid_counts[6] + sta.tid_counts[7]) as f64 / total_tid as f64 * 100.0;
        let video_pct = (sta.tid_counts[4] + sta.tid_counts[5]) as f64 / total_tid as f64 * 100.0;
        if voice_pct > 30.0 {
            lines.push(format!("  {}", s().cyan().paint("Profile: Voice call active (VoIP/FaceTime)")));
        } else if video_pct > 30.0 {
            lines.push(format!("  {}", s().cyan().paint("Profile: Video streaming active")));
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  Client Tab 6: Raw
// ───────────────────────────────────────────────────────────────────────────────

fn render_client_raw(sta: &Station, _width: u16, lines: &mut Vec<String>) {
    let ind = 2;

    lines.push(format!("  {}", prism::header(&s().bold().paint("Raw Station Data"), 30)));
    lines.push(String::new());

    lines.push(kv("mac", &format!("{}", sta.mac), ind));
    lines.push(kv("bssid", &format!("{:?}", sta.bssid), ind));
    lines.push(kv("is_associated", &format!("{}", sta.is_associated), ind));
    lines.push(kv("is_randomized", &format!("{}", sta.is_randomized), ind));
    lines.push(kv("vendor", &format!("{:?}", sta.vendor), ind));

    lines.push(String::new());
    lines.push(kv("rssi", &format!("{}", sta.rssi), ind));
    lines.push(kv("rssi_best", &format!("{}", sta.rssi_best), ind));
    lines.push(kv("noise", &format!("{}", sta.noise), ind));
    lines.push(kv("last_channel", &format!("{}", sta.last_channel), ind));

    lines.push(String::new());
    lines.push(kv("frame_count", &format!("{}", sta.frame_count), ind));
    lines.push(kv("data_bytes", &format!("{}", sta.data_bytes), ind));
    lines.push(kv("probe_ssid_count", &format!("{}", sta.probe_ssid_count), ind));
    lines.push(kv("last_probe_ssid", &format!("{:?}", sta.last_probe_ssid), ind));

    lines.push(String::new());
    lines.push(kv("wifi_gen", &format!("{:?}", sta.wifi_gen), ind));
    lines.push(kv("max_nss", &format!("{}", sta.max_nss), ind));
    lines.push(kv("max_rate_mbps", &format!("{}", sta.max_rate_mbps), ind));
    lines.push(kv("has_ht", &format!("{}", sta.has_ht), ind));
    lines.push(kv("has_vht", &format!("{}", sta.has_vht), ind));
    lines.push(kv("has_he", &format!("{}", sta.has_he), ind));
    lines.push(kv("ht_cap_raw", &format!("{:#06X}", sta.ht_cap_raw), ind));
    lines.push(kv("vht_cap_raw", &format!("{:#010X}", sta.vht_cap_raw), ind));
    lines.push(kv("supported_rates", &format!("{:?}", sta.supported_rates), ind));

    lines.push(String::new());
    lines.push(kv("ie_tag_order", &format!("{:?}", sta.ie_tag_order), ind));
    lines.push(kv("ie_tag_count", &format!("{}", sta.ie_tag_count), ind));
    lines.push(kv("listen_interval", &format!("{}", sta.listen_interval), ind));
    lines.push(kv("ampdu_max_len_exp", &format!("{}", sta.ampdu_max_len_exp), ind));
    lines.push(kv("ampdu_min_spacing", &format!("{}", sta.ampdu_min_spacing), ind));

    lines.push(String::new());
    lines.push(kv("seq_num_first", &format!("{}", sta.seq_num_first), ind));
    lines.push(kv("seq_num_last", &format!("{}", sta.seq_num_last), ind));
    lines.push(kv("seq_num_gaps", &format!("{}", sta.seq_num_gaps), ind));

    lines.push(String::new());
    lines.push(kv("power_save", &format!("{}", sta.power_save), ind));
    lines.push(kv("power_save_transitions", &format!("{}", sta.power_save_transitions), ind));

    lines.push(String::new());
    lines.push(kv("tid_counts", &format!("{:?}", sta.tid_counts), ind));

    lines.push(String::new());
    lines.push(kv("avg_probe_interval_ms", &format!("{}", sta.avg_probe_interval_ms), ind));
    lines.push(kv("handshake_state", &format!("{}", sta.handshake_state), ind));
    lines.push(kv("first_seen", &format!("{:?}", sta.first_seen.elapsed()), ind));
    lines.push(kv("last_seen", &format!("{:?}", sta.last_seen.elapsed()), ind));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  IE tag name lookups
// ═══════════════════════════════════════════════════════════════════════════════

fn ie_tag_name(tag: u8) -> &'static str {
    match tag {
        0 => "SSID",
        1 => "Supported Rates",
        2 => "FH Parameter Set",
        3 => "DS Parameter Set",
        4 => "CF Parameter Set",
        5 => "TIM",
        6 => "IBSS Parameter Set",
        7 => "Country",
        10 => "Request",
        11 => "QBSS Load",
        16 => "Challenge Text",
        32 => "Power Constraint",
        33 => "Power Capability",
        36 => "Supported Channels",
        37 => "CSA",
        38 => "Measurement Request",
        39 => "Measurement Report",
        42 => "ERP Information",
        45 => "HT Capabilities",
        46 => "QoS Capability",
        48 => "RSN",
        50 => "Extended Rates",
        54 => "Mobility Domain (FT)",
        55 => "Fast BSS Transition",
        59 => "Supported Operating Classes",
        61 => "HT Operation",
        70 => "RM Enabled Capabilities",
        71 => "Multiple BSSID",
        107 => "Interworking",
        113 => "Mesh Configuration",
        114 => "Mesh ID",
        127 => "Extended Capabilities",
        191 => "VHT Capabilities",
        192 => "VHT Operation",
        195 => "VHT TX Power Envelope",
        201 => "Reduced Neighbor Report",
        221 => "Vendor Specific",
        255 => "Extension Element",
        _ => "Unknown",
    }
}

fn ie_ext_tag_name(ext_id: u8) -> &'static str {
    match ext_id {
        35 => "HE Capabilities",
        36 => "HE Operation",
        37 => "UORA Parameter Set",
        38 => "MU EDCA Parameter Set",
        39 => "Spatial Reuse Parameter Set",
        41 => "NDP Feedback Report",
        42 => "BSS Color Change",
        _ => "Unknown Extension",
    }
}

fn vendor_oui_name(oui: &[u8; 3]) -> String {
    match oui {
        [0x00, 0x50, 0xF2] => {
            "Microsoft (WMM/WPS)".into()
        }
        [0x00, 0x0C, 0xE7] => "MediaTek".into(),
        [0x00, 0x10, 0x18] => "Broadcom".into(),
        [0x00, 0x17, 0xF2] => "Apple".into(),
        [0x00, 0x03, 0x7F] => "Atheros".into(),
        [0x00, 0x90, 0x4C] => "Epigram (Broadcom)".into(),
        [0x50, 0x6F, 0x9A] => "Wi-Fi Alliance".into(),
        _ => format!("{:02X}:{:02X}:{:02X}", oui[0], oui[1], oui[2]),
    }
}
