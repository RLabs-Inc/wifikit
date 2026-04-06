//! RTL8852AU RX diagnostic dumper — complete channel hop
//!
//! Initializes the chip, hops through ALL channels, reads raw USB bulk IN,
//! and dumps EVERYTHING: raw hex, parsed descriptor fields, physts bytes,
//! packet boundaries, RSSI values, IE contents — no assumptions, no filtering.
//!
//! Output: /tmp/wifikit_8852au_rx_dump.log

use std::time::{Duration, Instant};
use std::io::Write;
use wifikit::core::chip::ChipDriver;

const DWELL_SECS: u64 = 2;
const MAX_DETAILED_READS: u32 = 5; // full hex dump for this many USB reads per channel

fn main() {
    eprintln!("=== RTL8852AU RX Diagnostic Dump — Full Channel Hop ===");
    eprintln!("Output: /tmp/wifikit_8852au_rx_dump.log\n");

    let (mut driver, _endpoints) = match wifikit::chips::rtl8852au::Rtl8852au::open_usb(0x2357, 0x013F) {
        Ok(d) => d,
        Err(e) => { eprintln!("Failed to open: {}", e); std::process::exit(1); }
    };
    match driver.init() {
        Ok(()) => eprintln!("INIT OK"),
        Err(e) => { eprintln!("INIT FAILED: {}", e); std::process::exit(1); }
    };
    eprintln!("MAC: {}", driver.mac());

    let handle = driver.usb_handle();
    let ep_in = driver.bulk_in_ep();
    let channels = driver.supported_channels().to_vec();

    let mut log = std::fs::OpenOptions::new()
        .create(true).write(true).truncate(true)
        .open("/tmp/wifikit_8852au_rx_dump.log")
        .expect("open log");

    writeln!(log, "=== RTL8852AU RX Diagnostic Dump — Full Channel Hop ===").unwrap();
    writeln!(log, "MAC: {}  Channels: {}", driver.mac(), channels.len()).unwrap();
    writeln!(log, "Dwell: {}s per channel\n", DWELL_SECS).unwrap();

    let mut buf = vec![0u8; 32768];
    let mut grand_total = Stats::default();
    let ie_len_table: [u8; 32] = [
        2, 4, 3, 3, 1, 1, 1, 1,
        0xFF, 1, 0xFF, 22, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 2, 3, 0xFF, 0xFF, 0xFF, 0,
        3, 3, 3, 3, 4, 4, 4, 4,
    ];

    #[derive(Default, Clone)]
    struct Slot { occupied: bool, pkt_idx: u32, frame_len: usize, fc: u16, src: [u8;6] }

    for ch_info in &channels {
        let ch = ch_info.number;
        let band_name = if ch <= 14 { "2.4GHz" } else { "5GHz" };

        eprintln!("--- Ch {} ({}) ---", ch, band_name);
        driver.set_channel(ch_info.clone()).unwrap();
        std::thread::sleep(Duration::from_millis(100));

        writeln!(log, "\n{}", "=".repeat(70)).unwrap(); writeln!(log, "").unwrap();
        writeln!(log, "  CHANNEL {} ({}) — freq {} MHz", ch, band_name, ch_info.center_freq_mhz).unwrap();
        writeln!(log, "{}", "=".repeat(70)).unwrap(); writeln!(log, "\n").unwrap();

        let mut st = Stats::default();
        let mut slots: [Slot; 8] = std::array::from_fn(|_| Slot::default());
        let mut usb_reads = 0u32;
        let ch_start = Instant::now();

        while ch_start.elapsed() < Duration::from_secs(DWELL_SECS) {
            let actual = match handle.read_bulk(ep_in, &mut buf, Duration::from_millis(100)) {
                Ok(n) => n,
                Err(rusb::Error::Timeout) => continue,
                Err(e) => { eprintln!("  USB error: {}", e); break; }
            };
            usb_reads += 1;
            st.bytes += actual;
            let detailed = usb_reads <= MAX_DETAILED_READS;

            if detailed {
                writeln!(log, "  ── USB READ #{} — {} bytes ──", usb_reads, actual).unwrap();
                // Full hex dump
                let mut p = 0;
                while p < actual {
                    let end = (p + 16).min(actual);
                    let hex: String = buf[p..end].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                    let ascii: String = buf[p..end].iter().map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' }).collect();
                    writeln!(log, "    {:04X}: {:<48} |{}|", p, hex, ascii).unwrap();
                    p += 16;
                }
                writeln!(log, "").unwrap();
            }

            // Parse packets
            let mut pos = 0;
            while pos + 4 <= actual {
                let dw0 = u32::from_le_bytes([buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]]);
                let pkt_len = (dw0 & 0x3FFF) as usize;
                let shift_val = ((dw0 >> 14) & 0x3) as usize;
                let mac_info_vld = (dw0 >> 23) & 1 != 0;
                let rpkt_type = ((dw0 >> 24) & 0xF) as u8;
                let drv_info_sz = ((dw0 >> 28) & 0x7) as usize;
                let long_rxd = (dw0 >> 31) & 1 != 0;
                let desc_len: usize = if long_rxd { 32 } else { 16 };

                let dw1 = if pos+8 <= actual { u32::from_le_bytes([buf[pos+4],buf[pos+5],buf[pos+6],buf[pos+7]]) } else { 0 };
                let dw3 = if pos+16 <= actual { u32::from_le_bytes([buf[pos+12],buf[pos+13],buf[pos+14],buf[pos+15]]) } else { 0 };

                let ppdu_cnt = ((dw1 >> 4) & 0x7) as usize;
                let rx_rate = ((dw1 >> 16) & 0x1FF) as u16;
                let crc32_err = long_rxd && (dw3 >> 9) & 1 != 0;

                let payload_offset = desc_len + (drv_info_sz * 8) + (shift_val * 2);
                let total_len = payload_offset + pkt_len;
                let consumed = (total_len + 7) & !7;

                let sane = pkt_len > 0 && pkt_len < 16384 && rpkt_type <= 10 && consumed <= actual - pos;

                st.packets += 1;
                let type_name = match rpkt_type {
                    0=>"WIFI",1=>"PPDU",2=>"CH_INFO",3=>"BB_SCOPE",4=>"F2P",
                    5=>"SS2FW",6=>"TX_RPT",7=>"TX_PD",8=>"DFS",9=>"TX_PD2",10=>"C2H",_=>"???"
                };

                if !sane {
                    st.garbage += 1;
                    if detailed {
                        writeln!(log, "    PKT @{:04X}: GARBAGE DW0=0x{:08X} rpkt={} pkt_len={}", pos, dw0, rpkt_type, pkt_len).unwrap();
                    }
                    break; // stop parsing this USB read
                }

                if detailed {
                    writeln!(log, "    PKT @{:04X}: {} ppdu_cnt={} pkt_len={} rate=0x{:03X} desc={} consumed={}",
                        pos, type_name, ppdu_cnt, pkt_len, rx_rate, desc_len, consumed).unwrap();
                }

                match rpkt_type {
                    0 => { // WIFI
                        st.wifi += 1;
                        let extra = if mac_info_vld { 4 } else { 0 };
                        let data_start = pos + payload_offset + extra;
                        let frame_len = if pkt_len >= 4 + extra { pkt_len - 4 - extra } else { 0 };
                        let fc = if data_start+2 <= actual { u16::from_le_bytes([buf[data_start],buf[data_start+1]]) } else { 0 };
                        let src = if data_start+16 <= actual { [buf[data_start+10],buf[data_start+11],buf[data_start+12],buf[data_start+13],buf[data_start+14],buf[data_start+15]] } else { [0;6] };

                        if detailed {
                            let ftype = (fc >> 2) & 0x3;
                            let fsub = (fc >> 4) & 0xF;
                            writeln!(log, "           fc=0x{:04X} type={} sub={} len={} src={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} crc={}",
                                fc, ftype, fsub, frame_len, src[0],src[1],src[2],src[3],src[4],src[5], crc32_err).unwrap();
                        }
                        if !crc32_err && frame_len > 0 {
                            slots[ppdu_cnt] = Slot { occupied: true, pkt_idx: st.packets, frame_len, fc, src };
                        }
                    }
                    1 => { // PPDU
                        st.ppdu += 1;
                        let slot = &slots[ppdu_cnt];
                        let matched = slot.occupied;
                        if matched { st.matched += 1; } else { st.nomatch += 1; }

                        // Parse physts
                        let ppdu_start = pos + payload_offset;
                        let ppdu_end = (ppdu_start + pkt_len).min(actual);
                        let ppdu_payload = &buf[ppdu_start..ppdu_end];

                        let physts_data = if mac_info_vld && ppdu_payload.len() >= 8 {
                            let mi0 = u32::from_le_bytes([ppdu_payload[0],ppdu_payload[1],ppdu_payload[2],ppdu_payload[3]]);
                            let mi1 = u32::from_le_bytes([ppdu_payload[4],ppdu_payload[5],ppdu_payload[6],ppdu_payload[7]]);
                            let usr_num = (mi0 & 0xF) as usize;
                            let rx_cnt_vld = mi0 & (1<<29) != 0;
                            let plcp_len = (((mi1 >> 16) & 0xFF) as usize) * 8;
                            let mut off = 8 + usr_num * 4;
                            if usr_num & 1 != 0 { off += 4; }
                            if rx_cnt_vld { off += 96; }
                            off += plcp_len;
                            if detailed {
                                writeln!(log, "           MAC_INFO: usr={} rx_cnt={} plcp={} → offset={}", usr_num, rx_cnt_vld, plcp_len, off).unwrap();
                            }
                            if off < ppdu_payload.len() { Some(&ppdu_payload[off..]) } else { None }
                        } else if !mac_info_vld { Some(ppdu_payload) } else { None };

                        if let Some(ps) = physts_data {
                            if ps.len() >= 8 {
                                let valid = (ps[0] >> 7) & 1 != 0;
                                let total_physts_len = (ps[1] as usize) * 8;
                                let rssi_raw = ps[3];
                                let rssi_dbm = if rssi_raw != 0 { (rssi_raw >> 1) as i16 - 110 } else { 0 };
                                let path_a = if ps[4] != 0 { (ps[4] >> 1) as i16 - 110 } else { 0 };
                                let path_b = if ps[5] != 0 { (ps[5] >> 1) as i16 - 110 } else { 0 };

                                if detailed {
                                    writeln!(log, "           {} slot[{}] src={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} fc=0x{:04X} flen={}",
                                        if matched {"MATCH"} else {"NO_MATCH"}, ppdu_cnt,
                                        slot.src[0],slot.src[1],slot.src[2],slot.src[3],slot.src[4],slot.src[5],
                                        slot.fc, slot.frame_len).unwrap();
                                    writeln!(log, "           RSSI: avg_raw=0x{:02X} → {} dBm  paths=[{},{}] dBm  valid={} physts_len={}",
                                        rssi_raw, rssi_dbm, path_a, path_b, valid, total_physts_len).unwrap();

                                    // Dump full physts hex
                                    let show = ps.len().min(64);
                                    let hex: String = ps[..show].iter().map(|b| format!("{:02X}",b)).collect::<Vec<_>>().join(" ");
                                    writeln!(log, "           PHYSTS[0..{}]: {}", show, hex).unwrap();

                                    // Parse IEs
                                    if valid && total_physts_len > 8 && total_physts_len <= ps.len() {
                                        let ie_area = &ps[8..total_physts_len];
                                        let mut ie_pos = 0;
                                        while ie_pos < ie_area.len() {
                                            let ie_id = ie_area[ie_pos] & 0x1F;
                                            let ie_len = if (ie_id as usize) < 32 && ie_len_table[ie_id as usize] != 0xFF {
                                                (ie_len_table[ie_id as usize] as usize) * 8
                                            } else if ie_pos + 1 < ie_area.len() {
                                                let hi3 = ((ie_area[ie_pos] >> 5) & 0x7) as usize;
                                                let lo4 = (ie_area[ie_pos+1] & 0xF) as usize;
                                                ((lo4 << 3) | hi3) * 8
                                            } else { break };
                                            if ie_len == 0 || ie_pos + ie_len > ie_area.len() { break; }

                                            let d = &ie_area[ie_pos..ie_pos+ie_len];
                                            let ie_name = match ie_id { 0=>"CCK",1=>"OFDM",2=>"HE",3=>"SEG1",4=>"PATH_A",5=>"PATH_B",6=>"PATH_C",7=>"PATH_D",8=>"CH",9=>"PLCP",_=>"?" };
                                            let ie_hex: String = d.iter().map(|b| format!("{:02X}",b)).collect::<Vec<_>>().join(" ");
                                            writeln!(log, "           IE{:<2} ({:6}): {}", ie_id, ie_name, ie_hex).unwrap();

                                            // Key field extraction
                                            if ie_id == 0 && ie_len >= 10 {
                                                writeln!(log, "                  noise={} evm_hdr={} evm_pld={} rx_path=0x{:X}",
                                                    d[4], d[8], d[9], (d[15]>>4)&0xF).unwrap();
                                            }
                                            if ie_id == 1 && ie_len >= 20 {
                                                let noise = d[4]; let snr = d[8]&0x3F;
                                                let rssi_fd = d[1]; let ch_idx = d[2];
                                                let ldpc=(d[11]>>4)&1; let stbc=(d[11]>>6)&1; let bf=d[13]&1;
                                                writeln!(log, "                  rssi_fd=0x{:02X}({}) noise=0x{:02X}({}) snr={} ch={} ldpc={} stbc={} bf={}",
                                                    rssi_fd, if rssi_fd!=0{(rssi_fd>>1)as i16-110}else{0},
                                                    noise, if noise!=0{noise as i16-110}else{0},
                                                    snr, ch_idx, ldpc, stbc, bf).unwrap();
                                            }
                                            if ie_id >= 4 && ie_id <= 7 && ie_len >= 8 {
                                                writeln!(log, "                  sig={} rf_gain={} tia={} snr={} evm={} dc=({},{})",
                                                    d[1],d[2],d[3]&1,(d[3]>>2)&0x3F,d[4],d[6],d[7]).unwrap();
                                            }

                                            ie_pos += ie_len;
                                        }
                                    }
                                }
                            }
                        } else if detailed {
                            writeln!(log, "           {} slot[{}] — NO PHYSTS (offset exceeded payload)",
                                if matched {"MATCH"} else {"NO_MATCH"}, ppdu_cnt).unwrap();
                        }

                        slots[ppdu_cnt].occupied = false;
                    }
                    _ => {} // other types just counted
                }

                pos += consumed;
            }
        }

        // Per-channel summary
        let ch_elapsed = ch_start.elapsed();
        let summary = format!(
            "  Ch {:<3}: {:>4} pkts, {:>4} wifi, {:>3} ppdu, {:>3} match ({:.0}%), {:>3} garbage, {:>5} B/s",
            ch, st.packets, st.wifi, st.ppdu,
            st.matched, if st.ppdu > 0 { st.matched as f64 / st.ppdu as f64 * 100.0 } else { 0.0 },
            st.garbage,
            (st.bytes as f64 / ch_elapsed.as_secs_f64()) as u64,
        );
        eprintln!("{}", summary);
        writeln!(log, "\n{}", summary).unwrap();

        grand_total.add(&st);
    }

    // Grand summary
    writeln!(log, "\n\n{}", "=".repeat(70)).unwrap(); writeln!(log, "").unwrap();
    writeln!(log, "  GRAND TOTAL").unwrap();
    writeln!(log, "{}", "=".repeat(70)).unwrap(); writeln!(log, "").unwrap();
    let gs = format!(
        "Channels: {}\nPackets: {}\nWiFi: {}\nPPDU: {}\nMatched: {} ({:.1}%)\nNo match: {} ({:.1}%)\nGarbage: {}\nWiFi:PPDU ratio: {:.2}:1",
        channels.len(), grand_total.packets, grand_total.wifi, grand_total.ppdu,
        grand_total.matched, if grand_total.ppdu > 0 { grand_total.matched as f64 / grand_total.ppdu as f64 * 100.0 } else { 0.0 },
        grand_total.nomatch, if grand_total.ppdu > 0 { grand_total.nomatch as f64 / grand_total.ppdu as f64 * 100.0 } else { 0.0 },
        grand_total.garbage,
        if grand_total.ppdu > 0 { grand_total.wifi as f64 / grand_total.ppdu as f64 } else { 0.0 },
    );
    eprintln!("\n{}", gs);
    writeln!(log, "{}", gs).unwrap();
    eprintln!("\nDump saved to /tmp/wifikit_8852au_rx_dump.log");
}

#[derive(Default)]
struct Stats {
    packets: u32,
    wifi: u32,
    ppdu: u32,
    matched: u32,
    nomatch: u32,
    garbage: u32,
    bytes: usize,
}

impl Stats {
    fn add(&mut self, other: &Stats) {
        self.packets += other.packets;
        self.wifi += other.wifi;
        self.ppdu += other.ppdu;
        self.matched += other.matched;
        self.nomatch += other.nomatch;
        self.garbage += other.garbage;
        self.bytes += other.bytes;
    }
}
