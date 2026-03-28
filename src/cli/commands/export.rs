//! Export command: /export [pcap|hccapx|hc22000|csv] [filename]

use crate::engine::export;
use super::{Ctx, local_datetime_file_stamp};

/// /export [format] [filename]
pub fn run(ctx: &mut Ctx, args: &str) {
    let args = args.trim();

    // Check scanner is running (store has data only if scanner has been started)
    {
        let state = ctx.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.focus_stack.find_by_name("scanner").is_none() {
            drop(state);
            ctx.layout.print(&format!("  {} No scan data to export. Run {} first.",
                prism::s().yellow().paint("!"),
                prism::s().cyan().paint("/scan")));
            return;
        }
    }

    let store = ctx.store.clone();

    let parts: Vec<&str> = args.split_whitespace().collect();
    let format = parts.first().copied().unwrap_or("");
    let stamp = local_datetime_file_stamp();
    let default_base = format!("wifikit-{stamp}");

    match format {
        "pcap" => {
            let handshakes = store.with_capture_db_read(|db| db.handshakes().to_vec());
            if handshakes.is_empty() {
                ctx.layout.print(&format!("  {} No handshakes captured. PCAP export requires captured handshake data.",
                    prism::s().yellow().paint("!")));
                return;
            }
            let filename = parts.get(1).map(|s| s.to_string())
                .unwrap_or_else(|| format!("{default_base}.pcap"));
            let beacon_frames = std::collections::HashMap::new();
            match export::export_all(".", &filename.trim_end_matches(".pcap"), &handshakes, &beacon_frames) {
                Ok(result) => {
                    if let Some(ref stats) = result.pcap_stats {
                        ctx.layout.print(&format!("  {} PCAP exported: {} ({} packets, {} bytes)",
                            prism::s().green().paint("\u{2713}"),
                            prism::s().bold().paint(&stats.path),
                            stats.packets, stats.bytes));
                    }
                    if result.hc22000_count > 0 {
                        ctx.layout.print(&format!("  {} hc22000 also written ({} entries)",
                            prism::s().green().paint("\u{2713}"), result.hc22000_count));
                    }
                    if result.hccapx_count > 0 {
                        ctx.layout.print(&format!("  {} hccapx also written ({} records)",
                            prism::s().green().paint("\u{2713}"), result.hccapx_count));
                    }
                }
                Err(e) => {
                    ctx.layout.print(&format!("  {} Export failed: {}",
                        prism::s().red().paint("!"), e));
                }
            }
        }
        "hccapx" => {
            let handshakes = store.with_capture_db_read(|db| db.handshakes().to_vec());
            if handshakes.is_empty() {
                ctx.layout.print(&format!("  {} No handshakes captured.",
                    prism::s().yellow().paint("!")));
                return;
            }
            let filename = parts.get(1).map(|s| s.to_string())
                .unwrap_or_else(|| format!("{default_base}.hccapx"));
            let beacon_frames = std::collections::HashMap::new();
            match export::export_all(".", &filename.trim_end_matches(".hccapx"), &handshakes, &beacon_frames) {
                Ok(result) => {
                    ctx.layout.print(&format!("  {} hccapx exported: {} records to {}",
                        prism::s().green().paint("\u{2713}"),
                        result.hccapx_count,
                        prism::s().bold().paint(&filename)));
                }
                Err(e) => {
                    ctx.layout.print(&format!("  {} Export failed: {}",
                        prism::s().red().paint("!"), e));
                }
            }
        }
        "hc22000" | "22000" => {
            let handshakes = store.with_capture_db_read(|db| db.handshakes().to_vec());
            if handshakes.is_empty() {
                ctx.layout.print(&format!("  {} No handshakes captured.",
                    prism::s().yellow().paint("!")));
                return;
            }
            let filename = parts.get(1).map(|s| s.to_string())
                .unwrap_or_else(|| format!("{default_base}.hc22000"));
            let beacon_frames = std::collections::HashMap::new();
            match export::export_all(".", &filename.trim_end_matches(".hc22000"), &handshakes, &beacon_frames) {
                Ok(result) => {
                    ctx.layout.print(&format!("  {} hc22000 exported: {} entries ({} PMKID, {} EAPOL) to {}",
                        prism::s().green().paint("\u{2713}"),
                        result.hc22000_count,
                        result.pmkid_count,
                        result.hc22000_count - result.pmkid_count,
                        prism::s().bold().paint(&filename)));
                }
                Err(e) => {
                    ctx.layout.print(&format!("  {} Export failed: {}",
                        prism::s().red().paint("!"), e));
                }
            }
        }
        "csv" => {
            let aps: Vec<_> = store.get_aps().into_values().collect();
            if aps.is_empty() {
                ctx.layout.print(&format!("  {} No APs discovered yet.",
                    prism::s().yellow().paint("!")));
                return;
            }
            let filename = parts.get(1).map(|s| s.to_string())
                .unwrap_or_else(|| format!("{default_base}.csv"));
            match export_csv(&filename, &aps) {
                Ok(count) => {
                    ctx.layout.print(&format!("  {} CSV exported: {} APs to {}",
                        prism::s().green().paint("\u{2713}"),
                        count,
                        prism::s().bold().paint(&filename)));
                }
                Err(e) => {
                    ctx.layout.print(&format!("  {} CSV export failed: {}",
                        prism::s().red().paint("!"), e));
                }
            }
        }
        "" => {
            ctx.layout.print(&format!("\n  {} Usage:",
                prism::s().cyan().bold().paint("/export")));
            ctx.layout.print(&format!("    {}  Export handshakes as PCAP (aircrack-ng)",
                prism::s().dim().paint("/export pcap [filename]")));
            ctx.layout.print(&format!("    {}  Export for hashcat (-m 2500)",
                prism::s().dim().paint("/export hccapx [filename]")));
            ctx.layout.print(&format!("    {}  Export for hashcat (-m 22000)",
                prism::s().dim().paint("/export hc22000 [filename]")));
            ctx.layout.print(&format!("    {}  Export AP list as CSV",
                prism::s().dim().paint("/export csv [filename]")));
            ctx.layout.print("");
        }
        _ => {
            ctx.layout.print(&format!("  {} Unknown export format: {}. Options: pcap, hccapx, hc22000, csv",
                prism::s().red().paint("!"), format));
        }
    }
}

/// Write AP list to CSV file.
fn export_csv(path: &str, aps: &[crate::store::Ap]) -> std::result::Result<usize, std::io::Error> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    writeln!(file, "BSSID,SSID,Channel,RSSI,Security,Vendor,WiFiGen,Clients")?;
    for ap in aps {
        // Escape SSID: double-quote if it contains comma/quote/newline
        let ssid_escaped = if ap.ssid.contains(',') || ap.ssid.contains('"') || ap.ssid.contains('\n') {
            format!("\"{}\"", ap.ssid.replace('"', "\"\""))
        } else {
            ap.ssid.clone()
        };
        writeln!(file, "{},{},{},{},{:?},{},{:?},{}",
            ap.bssid, ssid_escaped, ap.channel, ap.rssi,
            ap.security, ap.vendor, ap.wifi_gen, ap.client_count)?;
    }
    file.flush()?;
    Ok(aps.len())
}
