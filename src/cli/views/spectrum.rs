//! Spectrum analyzer CLI view — real-time RF energy visualization.
//!
//! Renders a braille-based spectrum display showing signal strength across
//! all WiFi channels. Uses data from the scanner's per-channel RSSI tracking
//! for immediate visualization, with testmode spectrum data when available.
//!
//! Display layout:
//! ```text
//!  SPECTRUM | PEAK | 42 APs | 1234 frames
//!  -20 ┊
//!      ┊    ⣿⣿
//!  -40 ┊  ⣿⣿⣿⣿       ⣿⣿
//!      ┊ ⣿⣿⣿⣿⣿⣿    ⣿⣿⣿⣿⣿   ⣿⣿
//!  -60 ┊⣿⣿⣿⣿⣿⣿⣿⣿  ⣿⣿⣿⣿⣿⣿⣿ ⣿⣿⣿⣿⣿  ⣿⣿
//!      ┊⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
//!  -80 ┊⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
//! -100 ┊───────────────────────────────────────
//!        1  2  3  4  5  6  7  8  9 10 11 12 13│36 40 44 ...
//!              2.4 GHz                         |    5 GHz
//! ```

use crate::core::{Band, Channel};

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
    fn display_rssi(&self, m: &ChannelMeasurement) -> i16 {
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
}

/// Render the spectrum analyzer view using braille characters.
///
/// Returns styled lines ready for display.
pub fn render_spectrum(data: &SpectrumData, width: u16, height: u16) -> Vec<String> {
    let mut lines = Vec::new();

    if data.measurements.is_empty() || width < 20 || height < 6 {
        lines.push(prism::s().dim().paint("  No spectrum data"));
        return lines;
    }

    // Layout: Y-axis label (6 chars) + separator (1) + spectrum area
    let spectrum_width = (width as usize).saturating_sub(7);
    if spectrum_width < 10 {
        lines.push(prism::s().dim().paint("  Terminal too narrow"));
        return lines;
    }

    // Reserve lines for header + footer
    let chart_height = (height as usize).saturating_sub(3);
    if chart_height < 3 {
        lines.push(prism::s().dim().paint("  Terminal too short"));
        return lines;
    }

    // Pixel grid dimensions (braille: 2 pixels wide, 4 pixels tall per char)
    let px_width = spectrum_width * 2;
    let px_height = chart_height * 4;

    // Calculate how many pixels per channel
    let n_channels = data.measurements.len();
    let px_per_channel = if n_channels > 0 { px_width / n_channels } else { 1 };
    let bar_px = px_per_channel.max(1);
    let gap_px = if px_per_channel > 2 { 1 } else { 0 };
    let bar_actual = bar_px.saturating_sub(gap_px);

    // RSSI range
    let range = (data.rssi_max - data.rssi_min) as f64;
    if range <= 0.0 { return lines; }

    // Build pixel grid
    let mut grid: Vec<Vec<bool>> = vec![vec![false; px_width]; px_height];

    for (i, m) in data.measurements.iter().enumerate() {
        let rssi = data.display_rssi(m);
        let clamped = rssi.clamp(data.rssi_min, data.rssi_max);
        let normalized = (clamped - data.rssi_min) as f64 / range;
        let bar_height = (normalized * px_height as f64) as usize;

        let x_start = i * bar_px;
        for dy in 0..bar_height {
            let y = px_height - 1 - dy; // bottom-up
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

    // Header
    let mode_str = match data.display_mode {
        SpectrumDisplayMode::Peak => "PEAK",
        SpectrumDisplayMode::Average => "AVG",
        SpectrumDisplayMode::Current => "LIVE",
    };
    let total_frames: u32 = data.measurements.iter().map(|m| m.frame_count).sum();
    let total_aps: u16 = data.measurements.iter().map(|m| m.ap_count).sum();
    lines.push(format!(
        " {} {} {} {} {} {} {}",
        prism::s().cyan().bold().paint("SPECTRUM"),
        prism::s().dim().paint("|"),
        prism::s().white().bold().paint(mode_str),
        prism::s().dim().paint("|"),
        prism::s().green().paint(&format!("{} APs", total_aps)),
        prism::s().dim().paint("|"),
        prism::s().yellow().paint(&format!("{} frames", total_frames)),
    ));

    // Spectrum chart with Y-axis labels
    let mid_rssi = (data.rssi_max + data.rssi_min) / 2;
    for (line_idx, braille_line) in braille_lines.iter().enumerate() {
        // Y-axis label at top, middle, bottom
        let y_label = if line_idx == 0 {
            format!("{:>4} ", data.rssi_max)
        } else if line_idx == braille_lines.len() / 2 {
            format!("{:>4} ", mid_rssi)
        } else if line_idx == braille_lines.len().saturating_sub(1) {
            format!("{:>4} ", data.rssi_min)
        } else {
            "     ".to_string()
        };

        // Color the braille based on vertical position
        let colored_line = color_spectrum_line(braille_line, line_idx, braille_lines.len());

        lines.push(format!(
            "{}{}{}",
            prism::s().dim().paint(&y_label),
            prism::s().dim().paint("\u{250A}"),
            colored_line
        ));
    }

    // X-axis: channel numbers
    let chars_per_channel = if n_channels > 0 { spectrum_width / n_channels } else { 1 };
    let chars_per_channel = chars_per_channel.max(1);
    let mut ch_label = String::new();

    for (i, m) in data.measurements.iter().enumerate() {
        let ch = m.channel.number;
        if chars_per_channel >= 3 {
            let label = format!("{:>width$}", ch, width = chars_per_channel);
            ch_label.push_str(&label);
        } else if i % 2 == 0 {
            ch_label.push_str(&format!("{}", ch % 100));
        } else if chars_per_channel >= 2 {
            ch_label.push(' ');
        }
    }

    lines.push(format!("      {}", prism::s().dim().paint(ch_label.trim_end())));

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
        let w = bands_5g * chars_per_channel;
        let lbl = "5 GHz";
        let pad = w.saturating_sub(lbl.len()) / 2;
        band_label.push_str(&" ".repeat(pad));
        band_label.push_str(&prism::s().yellow().paint(lbl));
        band_label.push_str(&" ".repeat(w.saturating_sub(pad + lbl.len())));
    }
    if bands_6g > 0 {
        let w = bands_6g * chars_per_channel;
        let lbl = "6 GHz";
        let pad = w.saturating_sub(lbl.len()) / 2;
        band_label.push_str(&" ".repeat(pad));
        band_label.push_str(&prism::s().magenta().paint(lbl));
        band_label.push_str(&" ".repeat(w.saturating_sub(pad + lbl.len())));
    }
    lines.push(format!("      {}", band_label));

    lines
}

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
}
