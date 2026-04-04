// MT7921AU usbmon pcap parser — extract MCU commands around channel switches
//
// Parses USB bulk OUT packets on the MCU endpoint (EP 0x08) to find
// CHANNEL_SWITCH, SET_RX_PATH, and sniffer config commands.
// Compares 2.4GHz vs 5GHz vs 6GHz sequences to find what's different.
//
// Usage:
//   cargo run --bin parse_usbmon_mt7921 -- references/mt7921au-edup-6dbi/usbmon_full_init.pcap

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: parse_usbmon_mt7921 <pcap_file>");
        return;
    }

    let mut data = Vec::new();
    std::fs::File::open(&args[1]).unwrap().read_to_end(&mut data).unwrap();
    eprintln!("Loaded {} bytes from {}", data.len(), args[1]);

    // Parse pcap global header
    if data.len() < 24 {
        eprintln!("File too small for pcap header");
        return;
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (le, nsec) = match magic {
        0xa1b2c3d4 => (true, false),   // LE microseconds
        0xa1b23c4d => (true, true),    // LE nanoseconds
        0xd4c3b2a1 => (false, false),  // BE microseconds
        0x4d3cb2a1 => (false, true),   // BE nanoseconds
        _ => { eprintln!("Not a pcap file (magic: {:#010x})", magic); return; }
    };

    let link_type = if le {
        u32::from_le_bytes([data[20], data[21], data[22], data[23]])
    } else {
        u32::from_be_bytes([data[20], data[21], data[22], data[23]])
    };
    eprintln!("Link type: {} (expected 220 for USB, 249 for usbmon)", link_type);

    // Parse packets
    let mut offset = 24usize; // after global header
    let mut pkt_num = 0u32;
    let mut mcu_commands: Vec<McuCommand> = Vec::new();

    while offset + 16 <= data.len() {
        let (ts_sec, ts_frac, incl_len, orig_len) = if le {
            (
                u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]),
                u32::from_le_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]),
                u32::from_le_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]) as usize,
                u32::from_le_bytes([data[offset+12], data[offset+13], data[offset+14], data[offset+15]]) as usize,
            )
        } else {
            (
                u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]),
                u32::from_be_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]),
                u32::from_be_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]) as usize,
                u32::from_be_bytes([data[offset+12], data[offset+13], data[offset+14], data[offset+15]]) as usize,
            )
        };
        offset += 16; // past packet header

        if offset + incl_len > data.len() {
            break;
        }

        let pkt_data = &data[offset..offset + incl_len];
        pkt_num += 1;

        // Parse usbmon packet
        // usbmon pcap format (USB_HEADER_LEN = 64 bytes for usbmon_packet):
        //   [0]       id (u64)
        //   [8]       type: 'S'=submit, 'C'=complete
        //   [9]       xfer_type: 0=ISO, 1=Intr, 2=Control, 3=Bulk
        //   [10]      epnum (endpoint number, bit 7 = direction)
        //   [11]      devnum
        //   [12-13]   busnum (le16)
        //   [14]      flag_setup
        //   [15]      flag_data
        //   [16-19]   ts_sec
        //   [20-23]   ts_usec
        //   [24-27]   status
        //   [28-31]   length (actual data length)
        //   [32-35]   len_cap (captured data length)
        //   ... (up to 64 bytes header)
        //   [64..]    USB payload data

        if pkt_data.len() < 65 {
            offset += incl_len;
            continue;
        }

        let pkt_type = pkt_data[8] as char;
        let xfer_type = pkt_data[9];
        let epnum = pkt_data[10];
        let data_len = u32::from_le_bytes([pkt_data[28], pkt_data[29], pkt_data[30], pkt_data[31]]) as usize;

        // We want: Submit ('S') bulk transfers (3) on OUT endpoints
        // EP 0x08 = MCU commands (bit 7=0 means OUT)
        // EP 0x05 = data TX
        let is_out = epnum & 0x80 == 0;
        let ep_addr = epnum & 0x7F;

        if pkt_type == 'S' && xfer_type == 3 && is_out && pkt_data.len() > 64 {
            let payload = &pkt_data[64..];

            // MCU endpoint (EP 0x08) — parse MCU commands
            if ep_addr == 0x08 && payload.len() >= 68 {
                // SDIO_HDR (4) + TXD (64) + payload
                // Skip SDIO header, look at TXD
                let txd = &payload[4..];
                if txd.len() >= 64 {
                    let dw0 = u32::from_le_bytes([txd[0], txd[1], txd[2], txd[3]]);
                    let pkt_fmt = (dw0 >> 23) & 0x3;

                    if pkt_fmt == 1 { // CMD format
                        // MCU TXD at offset 32
                        let m = 32;
                        if txd.len() > m + 12 {
                            let cid = txd[m + 4];
                            let set_query = txd[m + 6];
                            let seq = txd[m + 7];
                            let ext_cid = txd[m + 9];

                            // Check for EXT commands (cid=0xED)
                            if cid == 0xED {
                                let cmd_payload = if payload.len() > 68 { &payload[68..] } else { &[] };
                                let ts = ts_sec as f64 + ts_frac as f64 / if nsec { 1e9 } else { 1e6 };

                                if ext_cid == 0x08 || ext_cid == 0x4E {
                                    // CHANNEL_SWITCH (0x08) or SET_RX_PATH (0x4E)
                                    let cmd_name = if ext_cid == 0x08 { "CHANNEL_SWITCH" } else { "SET_RX_PATH" };
                                    let mut info = format!("ext_cmd={:#04x} ({})", ext_cid, cmd_name);

                                    if cmd_payload.len() >= 11 {
                                        let control_ch = cmd_payload[0];
                                        let center_ch = cmd_payload[1];
                                        let bw = cmd_payload[2];
                                        let tx_streams = cmd_payload[3];
                                        let rx_streams = cmd_payload[4];
                                        let switch_reason = cmd_payload[5];
                                        let band_idx = cmd_payload[6];
                                        let center_ch2 = cmd_payload[7];
                                        let channel_band = cmd_payload[10];

                                        let band_name = match channel_band {
                                            0 => "2.4GHz",
                                            1 => "5GHz",
                                            2 => "6GHz",
                                            _ => "???",
                                        };
                                        let bw_name = match bw {
                                            0 => "20MHz",
                                            1 => "40MHz",
                                            2 => "80MHz",
                                            3 => "160MHz",
                                            _ => "?",
                                        };

                                        info = format!("{} ch={} center={} bw={} ({}) band={} ({}) tx_str={} rx_str={:#x} reason={} band_idx={}",
                                            cmd_name, control_ch, center_ch, bw, bw_name,
                                            channel_band, band_name, tx_streams, rx_streams,
                                            switch_reason, band_idx);
                                    }

                                    mcu_commands.push(McuCommand {
                                        pkt_num,
                                        timestamp: ts,
                                        cmd_type: CmdType::ChannelSwitch,
                                        ext_cid,
                                        info,
                                        raw: cmd_payload.to_vec(),
                                    });
                                } else {
                                    // Other EXT commands
                                    let cmd_name = match ext_cid {
                                        0x07 => "PM_STATE_CTRL",
                                        0x21 => "EFUSE_BUFFER_MODE",
                                        0x32 => "WTBL_UPDATE",
                                        0x3E => "PROTECT_CTRL",
                                        0x46 => "MAC_INIT_CTRL",
                                        0x58 => "TX_POWER_FEATURE_CTRL",
                                        _ => "",
                                    };
                                    mcu_commands.push(McuCommand {
                                        pkt_num,
                                        timestamp: ts,
                                        cmd_type: CmdType::ExtCmd,
                                        ext_cid,
                                        info: format!("ext_cmd={:#04x} {} payload={}B", ext_cid, cmd_name, cmd_payload.len()),
                                        raw: cmd_payload.to_vec(),
                                    });
                                }
                            } else if cid == 0xED {
                                // Already handled above
                            } else {
                                // CE or other commands
                                let cmd_payload = if payload.len() > 68 { &payload[68..] } else { &[] };
                                let ts = ts_sec as f64 + ts_frac as f64 / if nsec { 1e9 } else { 1e6 };

                                let cmd_name = match cid {
                                    0x01 => "TEST_CTRL",
                                    0x05 => "SET_PS_PROFILE",
                                    0x0A => "SET_RX_FILTER",
                                    0x0F => "SET_CHAN_DOMAIN",
                                    0x17 => "SET_BSS_ABORT",
                                    0x8A => "NIC_CAPS",
                                    0xC5 => "FW_LOG",
                                    0xCA => "CHIP_CONFIG",
                                    _ => "",
                                };
                                mcu_commands.push(McuCommand {
                                    pkt_num,
                                    timestamp: ts,
                                    cmd_type: CmdType::CeCmd,
                                    ext_cid: cid,
                                    info: format!("ce_cmd={:#04x} {} sq={} payload={}B", cid, cmd_name, set_query, cmd_payload.len()),
                                    raw: cmd_payload.to_vec(),
                                });
                            }
                        }
                    }

                    // Check for UNI commands (different TXD format — 48 byte header)
                    // UNI commands have a 16-byte UNI header after the 32-byte HW TXD
                    if pkt_fmt == 1 && txd.len() >= 48 {
                        let m = 32; // UNI header at offset 32
                        let uni_cid = u16::from_le_bytes([txd[m + 2], txd[m + 3]]);
                        let option = txd[m + 11];
                        let is_uni = option & 0x02 != 0; // UNI_CMD_OPT_BIT_UNI_CMD

                        if is_uni {
                            let cmd_payload = if payload.len() > 52 { &payload[52..] } else { &[] };
                            let ts = ts_sec as f64 + ts_frac as f64 / if nsec { 1e9 } else { 1e6 };

                            let cmd_name = match uni_cid {
                                0x01 => "DEV_INFO_UPDATE",
                                0x02 => "BSS_INFO_UPDATE",
                                0x24 => "SNIFFER",
                                _ => "",
                            };

                            let mut info = format!("uni_cmd={:#06x} {} payload={}B", uni_cid, cmd_name, cmd_payload.len());

                            // Parse SNIFFER config TLV
                            if uni_cid == 0x24 && cmd_payload.len() >= 17 {
                                let band_idx = cmd_payload[0];
                                let tag = u16::from_le_bytes([cmd_payload[4], cmd_payload[5]]);
                                if tag == 0 {
                                    let enable = cmd_payload[8];
                                    info = format!("SNIFFER enable={} band_idx={}", enable, band_idx);
                                } else if tag == 1 && cmd_payload.len() >= 17 {
                                    let ch_band = cmd_payload[10];
                                    let bw = cmd_payload[11];
                                    let control_ch = cmd_payload[12];
                                    let sco = cmd_payload[13];
                                    let center_ch = cmd_payload[14];
                                    let drop_err = cmd_payload[16];
                                    let band_name = match ch_band {
                                        1 => "2.4GHz",
                                        2 => "5GHz",
                                        3 => "6GHz",
                                        _ => "???",
                                    };
                                    let bw_name = match bw {
                                        0 => "20/40",
                                        1 => "80",
                                        2 => "160",
                                        _ => "?",
                                    };
                                    info = format!("SNIFFER_CONFIG ch={} center={} ch_band={} ({}) bw={} ({}) sco={} drop_err={}",
                                        control_ch, center_ch, ch_band, band_name, bw, bw_name, sco, drop_err);
                                }
                            }

                            mcu_commands.push(McuCommand {
                                pkt_num,
                                timestamp: ts,
                                cmd_type: if uni_cid == 0x24 { CmdType::Sniffer } else { CmdType::UniCmd },
                                ext_cid: uni_cid as u8,
                                info,
                                raw: cmd_payload.to_vec(),
                            });
                        }
                    }
                }
            }
        }

        offset += incl_len;
    }

    eprintln!("Parsed {} packets, found {} MCU commands\n", pkt_num, mcu_commands.len());

    // ═══════════════════════════════════════════════════════════════
    // Output: Group commands around channel switches
    // ═══════════════════════════════════════════════════════════════

    eprintln!("═══ ALL CHANNEL SWITCH / RX_PATH COMMANDS ═══\n");

    let channel_cmds: Vec<&McuCommand> = mcu_commands.iter()
        .filter(|c| c.cmd_type == CmdType::ChannelSwitch)
        .collect();

    for cmd in &channel_cmds {
        eprintln!("  pkt#{:<5} t={:.6}  {}", cmd.pkt_num, cmd.timestamp, cmd.info);
    }

    eprintln!("\n═══ ALL SNIFFER COMMANDS ═══\n");

    let sniffer_cmds: Vec<&McuCommand> = mcu_commands.iter()
        .filter(|c| c.cmd_type == CmdType::Sniffer)
        .collect();

    for cmd in &sniffer_cmds {
        eprintln!("  pkt#{:<5} t={:.6}  {}", cmd.pkt_num, cmd.timestamp, cmd.info);
    }

    // ═══════════════════════════════════════════════════════════════
    // Compare: what commands surround each channel switch?
    // Show ±5 commands around each CHANNEL_SWITCH/SET_RX_PATH
    // ═══════════════════════════════════════════════════════════════

    eprintln!("\n═══ CONTEXT: Commands around each channel switch (±5) ═══\n");

    for (ci, cmd) in mcu_commands.iter().enumerate() {
        if cmd.cmd_type != CmdType::ChannelSwitch {
            continue;
        }

        eprintln!("── {} (pkt#{}, t={:.6}) ──", cmd.info, cmd.pkt_num, cmd.timestamp);

        let start = ci.saturating_sub(5);
        let end = (ci + 6).min(mcu_commands.len());
        for j in start..end {
            let c = &mcu_commands[j];
            let marker = if j == ci { ">>>" } else { "   " };
            eprintln!("  {} pkt#{:<5} t={:.6}  {}", marker, c.pkt_num, c.timestamp, c.info);
        }
        eprintln!();
    }

    // ═══════════════════════════════════════════════════════════════
    // Band comparison: what's different between 2.4/5/6GHz sequences?
    // ═══════════════════════════════════════════════════════════════

    eprintln!("═══ FULL COMMAND TIMELINE ═══\n");
    for cmd in &mcu_commands {
        let tag = match cmd.cmd_type {
            CmdType::ChannelSwitch => "CH_SW",
            CmdType::Sniffer => "SNIFF",
            CmdType::ExtCmd => "EXT  ",
            CmdType::CeCmd => "CE   ",
            CmdType::UniCmd => "UNI  ",
        };
        eprintln!("  [{}] pkt#{:<5} t={:.6}  {}", tag, cmd.pkt_num, cmd.timestamp, cmd.info);
    }
}

#[derive(Debug, Clone, PartialEq)]
enum CmdType {
    ChannelSwitch,
    Sniffer,
    ExtCmd,
    CeCmd,
    UniCmd,
}

#[derive(Debug, Clone)]
struct McuCommand {
    pkt_num: u32,
    timestamp: f64,
    cmd_type: CmdType,
    ext_cid: u8,
    info: String,
    raw: Vec<u8>,
}
