//! Spectrum analyzer CLI view — real-time RF energy visualization.
//!
//! Renders a braille-based spectrum display showing signal strength across
//! all WiFi channels, with summary stats and a scrollable AP table.
//!
//! Full panel layout:
//! ```text
//! ╭─ SPECTRUM ANALYZER ──────────── [PEAK] ── Ch 1-177 ─╮
//! │ -20 ┊                                                │
//! │     ┊    ⣿⣿                                         │  ← braille graph
//! │ -40 ┊  ⣿⣿⣿⣿       ⣿⣿                               │
//! │     ┊ ⣿⣿⣿⣿⣿⣿    ⣿⣿⣿⣿⣿   ⣿⣿                      │
//! │ -60 ┊⣿⣿⣿⣿⣿⣿⣿⣿  ⣿⣿⣿⣿⣿⣿⣿ ⣿⣿⣿⣿⣿                  │
//! │ -80 ┊⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿         │
//! │-100 ┊──────────────────────────────────────           │
//! │      1  3  6  9  11 13│36 44 52 ... 173              │
//! │      ◄── 2.4 GHz ───►│◄──── 5 GHz ────►             │
//! ├──────────────────────────────────────────────────────────┤
//! │ ● Strongest: MyRouter5G   Ch 161  -28 dBm  [WPA3]   │  ← kv()
//! │ ● Busiest:   Ch 6         12 APs                     │
//! │ ● Total: 42 APs  1,234 frames  146/s                 │
//! ├──────────────────────────────────────────────────────────┤
//! │ Ch │ SSID              │ RSSI │ APs │ Enc   │ Gen    │  ← scroll_table()
//! │ ────┼───────────────────┼──────┼─────┼───────┼──────  │
//! │ 161│ MyRouter5G        │ -28  │  4  │ WPA3  │ WiFi6  │
//! │   1│ MyRouter2G        │ -32  │  8  │ WPA2  │ WiFi4  │
//! │ ...│                   │      │     │       │        │
//! ╰──────────────────────────────────────────────────────────╯
//! ```

use crate::core::{Band, Channel};
use crate::cli::scanner::ScanSnapshot;

/// Per-channel spectrum measurement.
#[derive(Debug, Clone)]
pub struct ChannelMeasurement {
    pub channel: Channel,
    /// Peak RSSI seen on this channel (dBm, typically -20 to -100).
    pub peak_rssi: i16,
    /// Average RSSI across all frames on this channel (dBm).
    pub avg_rssi: i16,
    /// Current/latest RSSI reading (dBm).
    pub current_rssi: i16,
    /// Number of frames seen on this channel.
    pub frame_count: u32,
    /// Number of distinct APs (BSSIDs) on this channel.
    pub ap_count: u16,
    /// Noise floor estimate (dBm).
    pub noise_floor: i16,
    /// MIB survey: channel busy time (microseconds, last dwell).
    pub busy_us: u32,
    /// MIB survey: TX airtime (microseconds, last dwell).
    pub tx_us: u32,
    /// MIB survey: RX airtime (microseconds, last dwell).
    pub rx_us: u32,
    /// MIB survey: OBSS airtime (microseconds, last dwell).
    pub obss_us: u32,
    /// Channel utilization percentage (from MIB survey).
    pub utilization_pct: f32,
}

impl ChannelMeasurement {
    pub fn new(channel: Channel) -> Self {
        Self {
            channel,
            peak_rssi: -100,
            avg_rssi: -100,
            current_rssi: -100,
            frame_count: 0,
            ap_count: 0,
            noise_floor: -95,
            busy_us: 0,
            tx_us: 0,
            rx_us: 0,
            obss_us: 0,
            utilization_pct: 0.0,
        }
    }

    /// Signal-to-noise ratio in dB.
    pub fn snr(&self) -> i16 {
        self.current_rssi.saturating_sub(self.noise_floor)
    }
}

/// Spectrum data — a snapshot of all channel measurements.
#[derive(Debug, Clone)]
pub struct SpectrumData {
    pub measurements: Vec<ChannelMeasurement>,
    /// Which RSSI field to display
    pub display_mode: SpectrumDisplayMode,
    /// Y-axis range
    pub rssi_min: i16,  // bottom of display (e.g., -100 dBm)
    pub rssi_max: i16,  // top of display (e.g., -20 dBm)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectrumDisplayMode {
    Peak,
    Average,
    Current,
}

impl SpectrumData {
    pub fn new(channels: &[Channel]) -> Self {
        let measurements: Vec<ChannelMeasurement> = channels.iter()
            .map(|ch| ChannelMeasurement::new(*ch))
            .collect();
        Self {
            measurements,
            display_mode: SpectrumDisplayMode::Peak,
            rssi_min: -100,
            rssi_max: -20,
        }
    }

    /// Update a channel's RSSI measurement.
    pub fn update_rssi(&mut self, channel_num: u8, rssi: i16) {
        if let Some(m) = self.measurements.iter_mut().find(|m| m.channel.number == channel_num) {
            m.current_rssi = rssi;
            if rssi > m.peak_rssi {
                m.peak_rssi = rssi;
            }
            // Exponential moving average
            if m.frame_count == 0 {
                m.avg_rssi = rssi;
            } else {
                m.avg_rssi = (m.avg_rssi * 7 + rssi) / 8;
            }
            m.frame_count += 1;
        }
    }

    /// Update AP count for a channel.
    pub fn update_ap_count(&mut self, channel_num: u8, count: u16) {
        if let Some(m) = self.measurements.iter_mut().find(|m| m.channel.number == channel_num) {
            m.ap_count = count;
        }
    }

    /// Get the RSSI value to display based on current mode.
    pub fn display_rssi(&self, m: &ChannelMeasurement) -> i16 {
        match self.display_mode {
            SpectrumDisplayMode::Peak => m.peak_rssi,
            SpectrumDisplayMode::Average => m.avg_rssi,
            SpectrumDisplayMode::Current => m.current_rssi,
        }
    }

    /// Cycle through display modes.
    pub fn cycle_mode(&mut self) {
        self.display_mode = match self.display_mode {
            SpectrumDisplayMode::Peak => SpectrumDisplayMode::Average,
            SpectrumDisplayMode::Average => SpectrumDisplayMode::Current,
            SpectrumDisplayMode::Current => SpectrumDisplayMode::Peak,
        };
    }

    fn mode_label(&self) -> &'static str {
        match self.display_mode {
            SpectrumDisplayMode::Peak => "PEAK",
            SpectrumDisplayMode::Average => "AVG",
            SpectrumDisplayMode::Current => "LIVE",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Full spectrum panel — braille graph + kv stats + scroll_table
// ═══════════════════════════════════════════════════════════════════════════════

/// Render the full spectrum analyzer panel for the scanner's Spectrum view.
///
/// Layout splits available height:
///   - Braille graph: ~55% of height
///   - KV summary: 3 lines
///   - AP scroll table: remaining space
pub fn render_spectrum_panel(
    data: &SpectrumData,
    snap: &ScanSnapshot,
    width: u16,
    height: u16,
    scroll_offset: usize,
) -> Vec<String> {
    let w = width as usize;
    let h = height as usize;

    if data.measurements.is_empty() || w < 30 || h < 10 {
        return vec![
            String::new(),
            format!("  {} Waiting for spectrum data...",
                prism::s().dim().paint("\u{25cb}")),
            format!("  {} Start scanning to collect per-channel signal data.",
                prism::s().dim().paint(" ")),
        ];
    }

    let mut lines = Vec::new();

    // ── Proportional layout ──
    // Graph gets ~55%, kv gets 4 lines (3 + separator), table gets rest
    let graph_height = (h * 55 / 100).max(6);
    let kv_height = 4; // 3 kv lines + separator
    let table_height = h.saturating_sub(graph_height + kv_height);

    // ═══ Braille spectrum graph ═══
    render_braille_graph(data, w, graph_height, &mut lines);

    // ═══ Separator ═══
    lines.push(format!("  {}",
        prism::s().dim().paint(&"\u{2500}".repeat(w.saturating_sub(4)))));

    // ═══ KV summary stats ═══
    render_kv_summary(data, snap, w, &mut lines);

    // ═══ Separator ═══
    lines.push(format!("  {}",
        prism::s().dim().paint(&"\u{2500}".repeat(w.saturating_sub(4)))));

    // ═══ AP table sorted by signal ═══
    render_ap_table(snap, data, w, table_height, scroll_offset, &mut lines);

    lines
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Braille graph renderer
// ═══════════════════════════════════════════════════════════════════════════════

fn render_braille_graph(data: &SpectrumData, width: usize, height: usize, lines: &mut Vec<String>) {
    // Y-axis uses 6 chars, separator 1 char
    let spectrum_width = width.saturating_sub(9); // indent(2) + y-axis(5) + sep(1) + margin(1)
    if spectrum_width < 10 || height < 4 {
        lines.push(format!("  {} Terminal too small for spectrum graph",
            prism::s().dim().paint("?")));
        return;
    }

    // Reserve 2 lines for x-axis labels + band labels
    let chart_height = height.saturating_sub(2);

    // Pixel grid dimensions (braille: 2 pixels wide, 4 pixels tall per char)
    let px_width = spectrum_width * 2;
    let px_height = chart_height * 4;

    let n_channels = data.measurements.len();
    let px_per_channel = if n_channels > 0 { px_width / n_channels } else { 1 };
    let bar_px = px_per_channel.max(1);
    let gap_px = if px_per_channel > 2 { 1 } else { 0 };
    let bar_actual = bar_px.saturating_sub(gap_px);

    let range = (data.rssi_max - data.rssi_min) as f64;
    if range <= 0.0 { return; }

    // Build pixel grid
    let mut grid: Vec<Vec<bool>> = vec![vec![false; px_width]; px_height];

    for (i, m) in data.measurements.iter().enumerate() {
        let rssi = data.display_rssi(m);
        let clamped = rssi.clamp(data.rssi_min, data.rssi_max);
        let normalized = (clamped - data.rssi_min) as f64 / range;
        let bar_height = (normalized * px_height as f64) as usize;

        let x_start = i * bar_px;
        for dy in 0..bar_height {
            let y = px_height - 1 - dy;
            for dx in 0..bar_actual.min(px_width.saturating_sub(x_start)) {
                let x = x_start + dx;
                if x < px_width && y < px_height {
                    grid[y][x] = true;
                }
            }
        }
    }

    // Convert to braille
    let braille = prism::braille::grid_to_braille(&grid);
    let braille_lines: Vec<&str> = braille.split('\n').collect();

    // Render chart with Y-axis labels
    let mid_rssi = (data.rssi_max + data.rssi_min) / 2;
    for (line_idx, braille_line) in braille_lines.iter().enumerate() {
        let y_label = if line_idx == 0 {
            format!("{:>4} ", data.rssi_max)
        } else if line_idx == braille_lines.len() / 2 {
            format!("{:>4} ", mid_rssi)
        } else if line_idx == braille_lines.len().saturating_sub(1) {
            format!("{:>4} ", data.rssi_min)
        } else {
            "     ".to_string()
        };

        let colored_line = color_spectrum_line(braille_line, line_idx, braille_lines.len());

        lines.push(format!("  {}{}{}",
            prism::s().dim().paint(&y_label),
            prism::s().dim().paint("\u{250A}"),
            colored_line,
        ));
    }

    // X-axis: channel numbers
    let chars_per_channel = if n_channels > 0 { spectrum_width / n_channels } else { 1 };
    let chars_per_channel = chars_per_channel.max(1);
    let mut ch_label = String::new();

    for (i, m) in data.measurements.iter().enumerate() {
        let ch = m.channel.number;
        if chars_per_channel >= 4 {
            let label = format!("{:>width$}", ch, width = chars_per_channel);
            ch_label.push_str(&label);
        } else if chars_per_channel >= 3 {
            let label = format!("{:>3}", ch);
            ch_label.push_str(&label);
        } else if i % 2 == 0 {
            ch_label.push_str(&format!("{}", ch % 100));
        } else if chars_per_channel >= 2 {
            ch_label.push(' ');
        }
    }
    lines.push(format!("        {}", prism::s().dim().paint(ch_label.trim_end())));

    // Band labels
    let bands_2g = data.measurements.iter().filter(|m| m.channel.band == Band::Band2g).count();
    let bands_5g = data.measurements.iter().filter(|m| m.channel.band == Band::Band5g).count();
    let bands_6g = data.measurements.iter().filter(|m| m.channel.band == Band::Band6g).count();

    let mut band_label = String::new();
    if bands_2g > 0 {
        let w = bands_2g * chars_per_channel;
        let lbl = "2.4 GHz";
        let pad = w.saturating_sub(lbl.len()) / 2;
        band_label.push_str(&" ".repeat(pad));
        band_label.push_str(&prism::s().cyan().paint(lbl));
        band_label.push_str(&" ".repeat(w.saturating_sub(pad + lbl.len())));
    }
    if bands_5g > 0 {
        if bands_2g > 0 {
            band_label.push_str(&prism::s().dim().paint("\u{2502}"));
        }
        let w = bands_5g * chars_per_channel;
        let lbl = "5 GHz";
        let pad = w.saturating_sub(lbl.len()) / 2;
        band_label.push_str(&" ".repeat(pad));
        band_label.push_str(&prism::s().yellow().paint(lbl));
        band_label.push_str(&" ".repeat(w.saturating_sub(pad + lbl.len())));
    }
    if bands_6g > 0 {
        if bands_2g > 0 || bands_5g > 0 {
            band_label.push_str(&prism::s().dim().paint("\u{2502}"));
        }
        let w = bands_6g * chars_per_channel;
        let lbl = "6 GHz";
        let pad = w.saturating_sub(lbl.len()) / 2;
        band_label.push_str(&" ".repeat(pad));
        band_label.push_str(&prism::s().magenta().paint(lbl));
        band_label.push_str(&" ".repeat(w.saturating_sub(pad + lbl.len())));
    }
    lines.push(format!("        {}", band_label));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KV summary stats
// ═══════════════════════════════════════════════════════════════════════════════

fn render_kv_summary(data: &SpectrumData, snap: &ScanSnapshot, _width: usize, lines: &mut Vec<String>) {
    let total_aps: u16 = data.measurements.iter().map(|m| m.ap_count).sum();
    let total_frames: u32 = data.measurements.iter().map(|m| m.frame_count).sum();
    let has_survey = data.measurements.iter().any(|m| m.busy_us > 0);

    // Find strongest AP
    let strongest = snap.aps.iter()
        .max_by_key(|ap| ap.rssi);

    let strongest_str = if let Some(ap) = strongest {
        let ssid = if ap.ssid.is_empty() {
            prism::s().dim().italic().paint("(hidden)")
        } else {
            prism::s().bold().paint(&prism::truncate(&ap.ssid, 18, "\u{2026}"))
        };
        let sec = prism::badge(
            &format!("{}", ap.security),
            prism::BadgeVariant::Bracket,
            Some(|t: &str| prism::s().cyan().paint(t)),
        );
        format!("{}  ch{}  {} dBm  {}",
            ssid, ap.channel, ap.rssi, sec)
    } else {
        prism::s().dim().paint("none").to_string()
    };

    // Find busiest channel — by utilization if survey data available, else by AP count
    let busiest_str = if has_survey {
        let busiest = data.measurements.iter()
            .filter(|m| m.busy_us > 0)
            .max_by(|a, b| a.utilization_pct.partial_cmp(&b.utilization_pct).unwrap_or(std::cmp::Ordering::Equal));
        if let Some(m) = busiest {
            let util_color = if m.utilization_pct > 50.0 {
                |t: &str| prism::s().red().bold().paint(t)
            } else if m.utilization_pct > 20.0 {
                |t: &str| prism::s().yellow().paint(t)
            } else {
                |t: &str| prism::s().green().paint(t)
            };
            format!("ch{}  {}  {}",
                m.channel.number,
                util_color(&format!("{:.1}% util", m.utilization_pct)),
                prism::s().dim().paint(&format!("{}us busy", format_us(m.busy_us))),
            )
        } else {
            prism::s().dim().paint("no survey data").to_string()
        }
    } else {
        let busiest = data.measurements.iter()
            .filter(|m| m.ap_count > 0)
            .max_by_key(|m| m.ap_count);
        if let Some(m) = busiest {
            format!("ch{}  {} APs", m.channel.number, m.ap_count)
        } else {
            prism::s().dim().paint("none").to_string()
        }
    };

    // Mode badge
    let mode_badge = prism::badge(
        data.mode_label(),
        prism::BadgeVariant::Bracket,
        Some(match data.display_mode {
            SpectrumDisplayMode::Peak => |t: &str| prism::s().green().bold().paint(t),
            SpectrumDisplayMode::Average => |t: &str| prism::s().yellow().bold().paint(t),
            SpectrumDisplayMode::Current => |t: &str| prism::s().cyan().bold().paint(t),
        }),
    );

    lines.push(format!("  {} {}  {}  {}  {}",
        prism::s().green().paint("\u{25cf}"),
        prism::s().bold().dim().paint("Strongest:"),
        strongest_str,
        prism::s().dim().paint("\u{2502}"),
        mode_badge,
    ));
    lines.push(format!("  {} {}  {}",
        prism::s().yellow().paint("\u{25cf}"),
        prism::s().bold().dim().paint("Busiest: "),
        busiest_str,
    ));

    // Total line — include survey source indicator
    let source = if has_survey {
        prism::s().green().paint("\u{25cf} MIB survey")
    } else {
        prism::s().dim().paint("\u{25cb} passive RSSI")
    };
    lines.push(format!("  {} {}  {}  {}  {}  {}",
        prism::s().cyan().paint("\u{25cf}"),
        prism::s().bold().dim().paint("Total:   "),
        prism::s().bold().paint(&format!("{} APs", total_aps)),
        prism::s().dim().paint(&format!("{} frames", prism::format_number(total_frames as u64))),
        prism::s().dim().paint(&format!("{}/s", snap.stats.frames_per_sec)),
        source,
    ));
}

/// Format microseconds in a human-readable compact form.
fn format_us(us: u32) -> String {
    if us >= 1_000_000 {
        format!("{:.1}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.1}ms", us as f64 / 1_000.0)
    } else {
        format!("{}us", us)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AP scroll table — APs sorted by signal strength
// ═══════════════════════════════════════════════════════════════════════════════

fn render_ap_table(
    snap: &ScanSnapshot,
    data: &SpectrumData,
    width: usize,
    height: usize,
    scroll_offset: usize,
    lines: &mut Vec<String>,
) {
    use prism::{ScrollCol, ScrollTableConfig, scroll_table};

    if height < 3 { return; }

    // Sort APs by signal strength (strongest first)
    let mut aps = snap.aps.clone();
    aps.sort_by(|a, b| b.rssi.cmp(&a.rssi));

    let has_survey = data.measurements.iter().any(|m| m.busy_us > 0);

    // Build column definitions — show utilization when survey data available
    let show_util = has_survey && width >= 55;
    let show_busy = has_survey && width >= 70;
    let show_enc = width >= 80;
    let show_gen = width >= 95;

    let ssid_width = if show_gen { 20 } else if show_enc { 22 } else { 26 };

    let mut columns = vec![
        ScrollCol::right("Ch", 3),
        ScrollCol::new("SSID", ssid_width),
        ScrollCol::right("RSSI", 5),
        ScrollCol::right("APs", 3),
    ];
    if show_util {
        columns.push(ScrollCol::right("Util", 5));
    }
    if show_busy {
        columns.push(ScrollCol::right("Busy", 8));
    }
    if show_enc {
        columns.push(ScrollCol::new("Enc", 6));
    }
    if show_gen {
        columns.push(ScrollCol::new("Gen", 5));
    }

    // Build rows
    let rows: Vec<Vec<String>> = aps.iter().map(|ap| {
        let ssid = if ap.ssid.is_empty() {
            prism::s().dim().italic().paint("(hidden)")
        } else {
            prism::truncate(&ap.ssid, ssid_width, "\u{2026}")
        };

        // RSSI with color
        let rssi_str = if ap.rssi > -50 {
            prism::s().green().bold().paint(&format!("{}", ap.rssi))
        } else if ap.rssi > -70 {
            prism::s().yellow().paint(&format!("{}", ap.rssi))
        } else {
            prism::s().red().paint(&format!("{}", ap.rssi))
        };

        // Per-channel data from spectrum measurements
        let ch_data = data.measurements.iter()
            .find(|m| m.channel.number == ap.channel);
        let ch_aps = ch_data.map(|m| m.ap_count).unwrap_or(0);

        let mut row = vec![
            format!("{}", ap.channel),
            ssid,
            rssi_str,
            format!("{}", ch_aps),
        ];
        if show_util {
            let util = ch_data.map(|m| m.utilization_pct).unwrap_or(0.0);
            let util_str = if util > 0.0 {
                let s = format!("{:.1}%", util);
                if util > 50.0 {
                    prism::s().red().bold().paint(&s)
                } else if util > 20.0 {
                    prism::s().yellow().paint(&s)
                } else {
                    prism::s().green().paint(&s)
                }
            } else {
                prism::s().dim().paint("-")
            };
            row.push(util_str);
        }
        if show_busy {
            let busy = ch_data.map(|m| m.busy_us).unwrap_or(0);
            let busy_str = if busy > 0 {
                prism::s().dim().paint(&format_us(busy))
            } else {
                prism::s().dim().paint("-")
            };
            row.push(busy_str);
        }
        if show_enc {
            row.push(format!("{}", ap.security));
        }
        if show_gen {
            let wifi_gen = format!("{}", ap.wifi_gen);
            row.push(wifi_gen);
        }
        row
    }).collect();

    // Key hints footer
    let footer_line = format!("  {}",
        prism::s().dim().paint("p:peak  a:avg  c:current  m:cycle  j/k:scroll"));
    let footer = vec![footer_line];

    let result = scroll_table(&ScrollTableConfig {
        columns: &columns,
        rows: &rows,
        height,
        scroll_offset,
        separator: "  ",
        indent: 2,
        footer: &footer,
        empty_message: Some("No APs discovered yet"),
    });

    lines.extend(result.lines);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Color spectrum braille lines based on vertical position (signal strength).
/// Top = strong (green), middle = moderate (yellow), bottom = weak (red/dim).
fn color_spectrum_line(line: &str, line_idx: usize, total_lines: usize) -> String {
    if total_lines == 0 { return line.to_string(); }

    let position = line_idx as f64 / total_lines as f64;

    if position < 0.33 {
        prism::s().green().bold().paint(line)
    } else if position < 0.66 {
        prism::s().yellow().paint(line)
    } else {
        prism::s().red().dim().paint(line)
    }
}

/// Render the standalone spectrum view (used by test binary).
pub fn render_spectrum(data: &SpectrumData, width: u16, height: u16) -> Vec<String> {
    let mut lines = Vec::new();

    if data.measurements.is_empty() || width < 20 || height < 6 {
        lines.push(prism::s().dim().paint("  No spectrum data"));
        return lines;
    }

    // Header
    let total_frames: u32 = data.measurements.iter().map(|m| m.frame_count).sum();
    let total_aps: u16 = data.measurements.iter().map(|m| m.ap_count).sum();
    lines.push(format!(
        " {} {} {} {} {} {} {}",
        prism::s().cyan().bold().paint("SPECTRUM"),
        prism::s().dim().paint("|"),
        prism::s().white().bold().paint(data.mode_label()),
        prism::s().dim().paint("|"),
        prism::s().green().paint(&format!("{} APs", total_aps)),
        prism::s().dim().paint("|"),
        prism::s().yellow().paint(&format!("{} frames", total_frames)),
    ));

    // Use shared graph renderer
    render_braille_graph(data, width as usize, (height as usize).saturating_sub(1), &mut lines);

    lines
}

/// Render a compact single-line spectrum bar for the status bar or inline display.
/// Uses block characters for compact representation.
pub fn render_spectrum_mini(data: &SpectrumData, width: usize) -> String {
    if data.measurements.is_empty() {
        return prism::s().dim().paint("no data");
    }

    let blocks = [' ', '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}'];
    let range = (data.rssi_max - data.rssi_min) as f64;
    if range <= 0.0 { return String::new(); }
    let chars_per_ch = (width / data.measurements.len().max(1)).max(1);

    let mut result = String::new();
    for m in &data.measurements {
        let rssi = data.display_rssi(m);
        let clamped = rssi.clamp(data.rssi_min, data.rssi_max);
        let normalized = (clamped - data.rssi_min) as f64 / range;
        let idx = (normalized * 8.0).round() as usize;
        let block = blocks[idx.min(8)];
        let block_str = block.to_string();

        let colored = if normalized > 0.66 {
            prism::s().green().paint(&block_str)
        } else if normalized > 0.33 {
            prism::s().yellow().paint(&block_str)
        } else {
            prism::s().red().paint(&block_str)
        };

        for _ in 0..chars_per_ch {
            result.push_str(&colored);
        }
    }

    result
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SpectrumModule — Module trait implementation for spectrum analyzer
// ═══════════════════════════════════════════════════════════════════════════════

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::adapter::SharedAdapter;
use crate::cli::module::{Module, ModuleType, ViewDef, StatusSegment, SegmentStyle};

/// SpectrumModule runs the spectrum analyzer as an independent module
/// on its own adapter (MT7921AU with testmode support).
///
/// Background thread hops channels, reads MIB survey registers per channel,
/// captures frames for RSSI data, and feeds SpectrumData via Arc<Mutex>.
/// The UI thread reads the snapshot for rendering.
pub struct SpectrumModule {
    /// Shared spectrum data — written by background thread, read by UI.
    data: Arc<Mutex<SpectrumData>>,
    /// Background thread running flag.
    running: Arc<AtomicBool>,
    /// Background thread done flag.
    done: Arc<AtomicBool>,
    /// Start time for elapsed display.
    start_time: Instant,
    /// Scroll offset for the AP table.
    scroll_offset: usize,
    /// Round counter.
    round: Arc<std::sync::atomic::AtomicU32>,
    /// Channel count for status display.
    channel_count: usize,
}

impl SpectrumModule {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(SpectrumData::new(&[]))),
            running: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
            start_time: Instant::now(),
            scroll_offset: 0,
            round: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            channel_count: 0,
        }
    }
}

impl Module for SpectrumModule {
    fn name(&self) -> &str { "spectrum" }
    fn description(&self) -> &str { "RF spectrum analyzer — MIB survey + braille display" }
    fn module_type(&self) -> ModuleType { ModuleType::Attack } // uses Attack lifecycle (auto-pop on done)

    fn start(&mut self, shared: SharedAdapter) {
        self.start_time = Instant::now();
        self.running.store(true, Ordering::SeqCst);
        self.done.store(false, Ordering::SeqCst);
        self.round.store(0, Ordering::SeqCst);

        let data = Arc::clone(&self.data);
        let running = Arc::clone(&self.running);
        let done = Arc::clone(&self.done);
        let round = Arc::clone(&self.round);

        std::thread::Builder::new()
            .name("spectrum".into())
            .spawn(move || {
                spectrum_thread(shared, data, running, done, round);
            })
            .expect("failed to spawn spectrum thread");
    }

    fn signal_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    fn views(&self) -> &[ViewDef] {
        &[] // single view, no tabs
    }

    fn render(&mut self, _view: usize, width: u16, height: u16) -> Vec<String> {
        let data = self.data.lock().unwrap_or_else(|e| e.into_inner()).clone();
        self.channel_count = data.measurements.len();

        // Build a minimal ScanSnapshot for the panel renderer (no APs — spectrum has its own data)
        let snap = ScanSnapshot {
            stats: crate::store::ScanStats {
                frames_per_sec: 0,
                round: self.round.load(Ordering::SeqCst),
                elapsed: self.start_time.elapsed(),
                ..Default::default()
            },
            ..Default::default()
        };

        render_spectrum_panel(&data, &snap, width, height, self.scroll_offset)
    }

    fn handle_key(&mut self, key: &prism::KeyEvent, _view: usize) -> bool {
        if key.ctrl || key.meta { return false; }
        match key.key.as_str() {
            "m" => {
                let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
                data.cycle_mode();
                true
            }
            "p" => {
                let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
                data.display_mode = SpectrumDisplayMode::Peak;
                true
            }
            "a" => {
                let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
                data.display_mode = SpectrumDisplayMode::Average;
                true
            }
            "c" => {
                let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
                data.display_mode = SpectrumDisplayMode::Current;
                true
            }
            "j" | "down" => { self.scroll_offset = self.scroll_offset.saturating_add(1); true }
            "k" | "up" => { self.scroll_offset = self.scroll_offset.saturating_sub(1); true }
            "g" => { self.scroll_offset = 0; true }
            "G" => { self.scroll_offset = usize::MAX; true }
            _ => false,
        }
    }

    fn status_segments(&self) -> Vec<StatusSegment> {
        if !self.running.load(Ordering::SeqCst) && self.done.load(Ordering::SeqCst) {
            return vec![];
        }

        let data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let total_frames: u32 = data.measurements.iter().map(|m| m.frame_count).sum();
        let round = self.round.load(Ordering::SeqCst);
        let mode = data.mode_label();
        let elapsed = self.start_time.elapsed();

        let mut segs = vec![
            StatusSegment::new("spectrum", SegmentStyle::CyanBold),
            StatusSegment::new(
                format!("{} ch", data.measurements.len()),
                SegmentStyle::Bold,
            ),
        ];
        if round > 0 {
            segs.push(StatusSegment::new(format!("r:{}", round), SegmentStyle::Dim));
        }
        if total_frames > 0 {
            segs.push(StatusSegment::new(
                format!("{} frames", prism::format_number(total_frames as u64)),
                SegmentStyle::Yellow,
            ));
        }
        segs.push(StatusSegment::new(format!("[{}]", mode), SegmentStyle::Bold));
        segs.push(StatusSegment::new(
            format!("{:.0}s", elapsed.as_secs_f64()),
            SegmentStyle::Dim,
        ));
        segs
    }

    fn freeze_summary(&self, width: u16) -> Vec<String> {
        let data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let total_frames: u32 = data.measurements.iter().map(|m| m.frame_count).sum();
        let round = self.round.load(Ordering::SeqCst);
        let elapsed = self.start_time.elapsed();

        // Find busiest channel
        let busiest = data.measurements.iter()
            .filter(|m| m.busy_us > 0)
            .max_by(|a, b| a.utilization_pct.partial_cmp(&b.utilization_pct).unwrap_or(std::cmp::Ordering::Equal));
        let busiest_str = if let Some(m) = busiest {
            format!("ch{} ({:.1}% util, {}us busy)", m.channel.number, m.utilization_pct, m.busy_us)
        } else {
            "none".to_string()
        };

        let content = format!(
            "Channels: {}\nRounds: {}\nFrames: {}\nDuration: {:.1}s\nBusiest: {}",
            data.measurements.len(),
            round,
            prism::format_number(total_frames as u64),
            elapsed.as_secs_f64(),
            busiest_str,
        );

        let frame_width = (width as usize).saturating_sub(4);
        let framed = prism::frame(&content, &prism::FrameOptions {
            border: prism::BorderStyle::Rounded,
            title: Some("Spectrum Analyzer Complete".into()),
            width: Some(frame_width),
            ..Default::default()
        });

        let mut lines = Vec::new();
        lines.push(String::new());
        for line in framed.lines() {
            lines.push(format!("  {}", line));
        }
        lines.push(String::new());
        lines
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Spectrum background thread
// ═══════════════════════════════════════════════════════════════════════════════

/// Background thread: hops channels, reads MIB survey + captures frames.
fn spectrum_thread(
    shared: SharedAdapter,
    data: Arc<Mutex<SpectrumData>>,
    running: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    round: Arc<std::sync::atomic::AtomicU32>,
) {
    let channels = shared.supported_channels();
    if channels.is_empty() {
        done.store(true, Ordering::SeqCst);
        running.store(false, Ordering::SeqCst);
        return;
    }

    // Initialize SpectrumData with all supported channels
    {
        let mut d = data.lock().unwrap_or_else(|e| e.into_inner());
        *d = SpectrumData::new(&channels);
    }

    let settle_time = shared.channel_settle_time();
    let dwell_time = Duration::from_millis(300); // shorter dwell for spectrum — we want responsiveness

    // Main sweep loop
    while running.load(Ordering::SeqCst) {
        let mut prev_band_idx: u8 = 0;

        for ch in &channels {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            let band_idx = match ch.band {
                Band::Band2g => 0u8,
                Band::Band5g => 1,
                Band::Band6g => 2,
            };

            // Reset MIB counters before dwelling on this channel
            let _ = shared.survey_reset(band_idx);

            // Switch channel
            if shared.set_channel_full(*ch).is_err() {
                continue;
            }

            // Wait for PHY settle + dwell
            // Survey counters accumulate RF energy during this dwell period
            let total_wait = settle_time + dwell_time;
            let slice = Duration::from_millis(50);
            let dwell_start = Instant::now();
            while dwell_start.elapsed() < total_wait && running.load(Ordering::SeqCst) {
                std::thread::sleep(slice.min(total_wait.saturating_sub(dwell_start.elapsed())));
            }

            // Read MIB survey after dwell — this is the real spectrum data
            let survey = shared.survey_read(band_idx).ok();
            let dwell_us = dwell_start.elapsed().as_micros() as f32;

            // Update SpectrumData with survey results
            {
                let mut d = data.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref s) = survey {
                    if let Some(m) = d.measurements.iter_mut()
                        .find(|m| m.channel.number == ch.number)
                    {
                        m.busy_us = s.busy_us;
                        m.tx_us = s.tx_us;
                        m.rx_us = s.rx_us;
                        m.obss_us = s.obss_us;
                        m.frame_count += 1; // count survey reads as "frames"

                        if dwell_us > 0.0 {
                            m.utilization_pct = (s.busy_us as f32 / dwell_us) * 100.0;
                        }

                        // Convert busy_us to a pseudo-RSSI for the braille graph
                        // More busy = stronger signal presence on this channel
                        // Scale: 0us=-100dBm, 300000us(full dwell)=-20dBm
                        let busy_ratio = (s.busy_us as f32 / dwell_us).min(1.0);
                        let pseudo_rssi = -100.0 + (busy_ratio * 80.0); // -100 to -20
                        d.update_rssi(ch.number, pseudo_rssi as i16);
                    }
                }
            }

            prev_band_idx = band_idx;
        }

        // Completed one round
        round.fetch_add(1, Ordering::SeqCst);
    }

    running.store(false, Ordering::SeqCst);
    done.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::channel::Bandwidth;

    fn ch(number: u8, band: Band, freq: u16) -> Channel {
        Channel { number, band, bandwidth: Bandwidth::Bw20, center_freq_mhz: freq }
    }

    #[test]
    fn test_channel_measurement_new() {
        let m = ChannelMeasurement::new(ch(1, Band::Band2g, 2412));
        assert_eq!(m.peak_rssi, -100);
        assert_eq!(m.frame_count, 0);
        assert_eq!(m.snr(), -5); // -100 - (-95)
    }

    #[test]
    fn test_spectrum_data_update() {
        let channels = vec![
            ch(1, Band::Band2g, 2412),
            ch(6, Band::Band2g, 2437),
            ch(11, Band::Band2g, 2462),
        ];
        let mut data = SpectrumData::new(&channels);
        data.update_rssi(1, -45);
        data.update_rssi(1, -42);
        data.update_rssi(6, -70);

        assert_eq!(data.measurements[0].peak_rssi, -42);
        assert_eq!(data.measurements[0].frame_count, 2);
        assert_eq!(data.measurements[1].peak_rssi, -70);
        assert_eq!(data.measurements[1].frame_count, 1);
        assert_eq!(data.measurements[2].peak_rssi, -100); // untouched
    }

    #[test]
    fn test_render_spectrum_empty() {
        let data = SpectrumData::new(&[]);
        let lines = render_spectrum(&data, 80, 20);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_render_spectrum_basic() {
        let channels = vec![
            ch(1, Band::Band2g, 2412),
            ch(6, Band::Band2g, 2437),
            ch(11, Band::Band2g, 2462),
        ];
        let mut data = SpectrumData::new(&channels);
        data.update_rssi(1, -45);
        data.update_rssi(6, -60);
        data.update_rssi(11, -30);

        let lines = render_spectrum(&data, 60, 15);
        assert!(lines.len() > 3, "should have header + chart + footer");
    }

    #[test]
    fn test_render_spectrum_mini() {
        let channels = vec![
            ch(1, Band::Band2g, 2412),
            ch(6, Band::Band2g, 2437),
        ];
        let mut data = SpectrumData::new(&channels);
        data.update_rssi(1, -40);
        data.update_rssi(6, -80);

        let mini = render_spectrum_mini(&data, 20);
        assert!(!mini.is_empty());
    }

    #[test]
    fn test_display_mode_cycle() {
        let mut data = SpectrumData::new(&[]);
        assert_eq!(data.display_mode, SpectrumDisplayMode::Peak);
        data.cycle_mode();
        assert_eq!(data.display_mode, SpectrumDisplayMode::Average);
        data.cycle_mode();
        assert_eq!(data.display_mode, SpectrumDisplayMode::Current);
        data.cycle_mode();
        assert_eq!(data.display_mode, SpectrumDisplayMode::Peak);
    }

    #[test]
    fn test_render_panel_empty() {
        let data = SpectrumData::new(&[]);
        let snap = ScanSnapshot::default();
        let lines = render_spectrum_panel(&data, &snap, 80, 30, 0);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_render_panel_with_data() {
        let channels = vec![
            ch(1, Band::Band2g, 2412),
            ch(6, Band::Band2g, 2437),
            ch(11, Band::Band2g, 2462),
            ch(36, Band::Band5g, 5180),
        ];
        let mut data = SpectrumData::new(&channels);
        data.update_rssi(1, -45);
        data.update_rssi(6, -60);
        data.update_rssi(11, -30);
        data.update_rssi(36, -55);
        data.update_ap_count(1, 5);
        data.update_ap_count(6, 3);
        data.update_ap_count(11, 2);
        data.update_ap_count(36, 4);

        let snap = ScanSnapshot::default();
        let lines = render_spectrum_panel(&data, &snap, 100, 40, 0);
        // Should have graph + separator + kv + separator + table
        assert!(lines.len() > 10, "panel should have substantial content");
    }
}
