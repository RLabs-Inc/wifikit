#!/usr/bin/env python3
"""Generate verbatim Rust driver replay code from USB pcap capture.

Segments the capture into phases and generates Rust functions
that replay every register write and H2C bulk command exactly
as captured from the Linux driver.

Output: references/rtl8852au_usb3_20260330_125324/driver_phases/
  - phase_00_power_on.rs      (INIT_START → FW download start)
  - phase_01_fw_download.rs   (FW sections on EP7)
  - phase_02_post_boot.rs     (after FW ready → MONITOR_START)
  - phase_03_monitor_mode.rs  (MONITOR_START → MONITOR_DONE)
  - phase_04_ch_2g.rs         (2.4GHz channel switch template)
  - phase_05_ch_5g.rs         (5GHz channel switch template with H2C)
  - phase_06_tx.rs            (TX test)
  - phase_07_bw.rs            (bandwidth switching)
"""

import struct
import os
import sys
from collections import defaultdict

PCAP = 'references/rtl8852au_usb3_20260330_125324/full_capture_bus4.pcap'
OUTDIR = 'references/rtl8852au_usb3_20260330_125324/driver_phases'

# Timestamps from pcap_phases.log
PHASES = [
    ('INIT_START',     1774886301.152),
    ('INIT_INSMOD',    1774886301.339),
    ('MONITOR_START',  1774886309.344),
    ('MONITOR_DONE',   1774886309.615),
    ('CH_START',       1774886310.617),
    ('CH_1',           1774886310.637),
    ('CH_6',           1774886311.153),
    ('CH_11',          1774886311.669),
    ('CH_36',          1774886312.189),
    ('CH_48',          1774886312.707),
    ('CH_149',         1774886313.223),
    ('CH_165',         1774886313.740),
    ('CH_DONE',        1774886314.242),
    ('TXP_START',      1774886314.244),
    ('TXP_100',        1774886314.246),
    ('TXP_1000',       1774886314.548),
    ('TXP_2000',       1774886314.850),
    ('TXP_3000',       1774886315.153),
    ('TXP_DONE',       1774886315.456),
    ('RX_START',       1774886315.456),
    ('RX_DONE',        1774886318.501),
    ('TX_START',       1774886318.502),
    ('TX_DONE',        1774886318.549),
    ('BW_START',       1774886318.550),
    ('BW_DONE',        1774886319.486),
    ('RMMOD_START',    1774886319.487),
    ('RMMOD_DONE',     1774886319.584),
]


def parse_full_pcap(filename):
    """Parse pcap and return all USB events with timestamps."""
    events = []

    with open(filename, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        f.read(20)  # rest of global header

        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            if len(pkt_data) < 64:
                continue

            ts = ts_sec + ts_usec / 1_000_000.0
            urb_type = chr(pkt_data[8])
            xfer_type = pkt_data[9]
            epnum = pkt_data[10]
            devnum = pkt_data[11]
            flag_setup = pkt_data[14]
            status = struct.unpack('<i', pkt_data[28:32])[0]
            length = struct.unpack('<I', pkt_data[32:36])[0]
            len_cap = struct.unpack('<I', pkt_data[36:40])[0]
            setup = pkt_data[40:48]
            data = pkt_data[64:64+len_cap] if len_cap > 0 else b''

            ep_dir = 'IN' if (epnum & 0x80) else 'OUT'
            ep_addr = epnum & 0x0F

            events.append({
                'ts': ts,
                'urb_type': urb_type,
                'xfer_type': xfer_type,
                'ep': ep_addr,
                'ep_dir': ep_dir,
                'devnum': devnum,
                'flag_setup': flag_setup,
                'status': status,
                'length': length,
                'setup': setup,
                'data': data,
            })

    return events


def pair_control_transfers(events):
    """Match Submit+Complete pairs for control transfers, return ordered ops."""
    ops = []
    pending = {}

    for evt in events:
        if evt['xfer_type'] != 2:  # not CONTROL
            # Bulk transfers
            if evt['xfer_type'] == 3 and evt['urb_type'] == 'S' and evt['ep_dir'] == 'OUT' and len(evt['data']) > 0:
                ops.append({
                    'type': 'BULK_OUT',
                    'ts': evt['ts'],
                    'ep': evt['ep'],
                    'data': evt['data'],
                })
            continue

        # Control transfer
        urb_key = (evt['devnum'], evt['ep'], evt['ts'])

        if evt['urb_type'] == 'S' and evt['flag_setup'] == 0:
            bmReq = evt['setup'][0]
            bReq = evt['setup'][1]
            wValue = struct.unpack('<H', evt['setup'][2:4])[0]
            wIndex = struct.unpack('<H', evt['setup'][4:6])[0]
            wLength = struct.unpack('<H', evt['setup'][6:8])[0]
            is_read = (bmReq & 0x80) != 0

            if bReq == 0x05:  # RTL vendor request
                pending_key = id(evt)  # unique key
                # Encode wIndex into address: full_addr = (wIndex << 16) | wValue
                # BB/RF registers use wIndex=0x0001, MAC regs use wIndex=0x0000
                full_addr = (wIndex << 16) | wValue
                pending[evt['ts']] = {
                    'addr': full_addr,
                    'size': wLength,
                    'is_read': is_read,
                    'data': evt['data'],
                    'ts': evt['ts'],
                }

        elif evt['urb_type'] == 'C':
            # Find matching submit (closest timestamp)
            best_key = None
            best_diff = float('inf')
            for k, v in pending.items():
                diff = abs(evt['ts'] - k)
                if diff < best_diff:
                    best_diff = diff
                    best_key = k

            if best_key is not None and best_diff < 0.1:
                submit = pending.pop(best_key)
                if submit['is_read']:
                    ops.append({
                        'type': 'REG_R',
                        'ts': submit['ts'],
                        'addr': submit['addr'],
                        'size': submit['size'],
                        'data': evt['data'],
                    })
                else:
                    ops.append({
                        'type': 'REG_W',
                        'ts': submit['ts'],
                        'addr': submit['addr'],
                        'size': submit['size'],
                        'data': submit['data'],
                    })

    return ops


def get_phase(ts):
    """Determine which phase a timestamp belongs to."""
    current = 'PRE_INIT'
    for name, phase_ts in PHASES:
        if ts >= phase_ts:
            current = name
        else:
            break
    return current


def ops_to_rust_writes(ops, phase_name):
    """Convert operations to Rust code for write-only replay."""
    lines = []
    lines.append(f'/// Phase: {phase_name}')
    lines.append(f'/// Generated from usbmon pcap capture — DO NOT EDIT')
    lines.append(f'/// Verbatim replay of Linux driver USB transactions')
    lines.append(f'///')

    write_count = 0
    h2c_count = 0
    poll_count = 0

    i = 0
    while i < len(ops):
        op = ops[i]

        if op['type'] == 'REG_W':
            addr = op['addr']
            data = op['data']
            # Use 8-digit hex for full addr (includes wIndex in upper 16 bits)
            if op['size'] == 1 and len(data) >= 1:
                lines.append(f'self.write8(0x{addr:08X}, 0x{data[0]:02X})?;')
                write_count += 1
            elif op['size'] == 2 and len(data) >= 2:
                val = struct.unpack('<H', data[:2])[0]
                lines.append(f'self.write16(0x{addr:08X}, 0x{val:04X})?;')
                write_count += 1
            elif op['size'] == 4 and len(data) >= 4:
                val = struct.unpack('<I', data[:4])[0]
                lines.append(f'self.write32(0x{addr:08X}, 0x{val:08X})?;')
                write_count += 1
            elif len(data) > 0:
                val = int.from_bytes(data[:min(4, len(data))], 'little')
                lines.append(f'self.write{op["size"]*8}(0x{addr:08X}, 0x{val:0{op["size"]*2}X})?;')
                write_count += 1

        elif op['type'] == 'REG_R':
            addr = op['addr']
            data = op['data']
            # Check if this is a poll (repeated reads of same register)
            poll_reads = 1
            while i + poll_reads < len(ops) and ops[i + poll_reads]['type'] == 'REG_R' and ops[i + poll_reads]['addr'] == addr:
                poll_reads += 1

            if poll_reads > 2:
                if len(data) >= 4:
                    expected = struct.unpack('<I', data[:4])[0]
                    lines.append(f'// Poll 0x{addr:08X} ({poll_reads}x) -> 0x{expected:08X}')
                else:
                    expected = data[0] if data else 0
                    lines.append(f'// Poll 0x{addr:08X} ({poll_reads}x) -> 0x{expected:02X}')
                lines.append(f'let _ = self.read32(0x{addr:08X})?;')
                poll_count += 1
                i += poll_reads
                continue
            else:
                if op['size'] == 4 and len(data) >= 4:
                    val = struct.unpack('<I', data[:4])[0]
                    lines.append(f'let _ = self.read32(0x{addr:08X})?; // -> 0x{val:08X}')
                elif op['size'] == 1 and len(data) >= 1:
                    lines.append(f'let _ = self.read8(0x{addr:08X})?; // -> 0x{data[0]:02X}')
                else:
                    lines.append(f'let _ = self.read32(0x{addr:08X})?;')

        elif op['type'] == 'BULK_OUT':
            ep = op['ep']
            data = op['data']
            h2c_count += 1

            if len(data) <= 64:
                hex_bytes = ', '.join(f'0x{b:02X}' for b in data)
                lines.append(f'self.bulk_out(0x{ep:02X}, &[{hex_bytes}])?; // H2C #{h2c_count} ({len(data)}B)')
            else:
                # Large payload — use const array
                lines.append(f'// H2C #{h2c_count}: EP{ep}, {len(data)} bytes')
                lines.append(f'const H2C_{h2c_count}: [u8; {len(data)}] = [')
                for chunk_start in range(0, len(data), 16):
                    chunk = data[chunk_start:chunk_start+16]
                    hex_bytes = ', '.join(f'0x{b:02X}' for b in chunk)
                    lines.append(f'    {hex_bytes},')
                lines.append(f'];')
                lines.append(f'self.bulk_out(0x{ep:02X}, &H2C_{h2c_count})?;')

        i += 1

    return lines, write_count, h2c_count


def main():
    print(f"=== Generating driver phases from {PCAP} ===\n")

    os.makedirs(OUTDIR, exist_ok=True)

    print("Parsing pcap...")
    events = parse_full_pcap(PCAP)
    print(f"  {len(events)} raw USB events")

    print("Pairing control transfers...")
    ops = pair_control_transfers(events)
    print(f"  {len(ops)} operations")

    # Group by phase
    phase_ops = defaultdict(list)
    for op in ops:
        phase = get_phase(op['ts'])
        phase_ops[phase].append(op)

    print(f"\n{'Phase':22s} {'Ops':>6s} {'RegR':>6s} {'RegW':>6s} {'H2C':>5s}")
    print("=" * 50)
    for name, _ in PHASES:
        pops = phase_ops.get(name, [])
        if not pops:
            continue
        rr = sum(1 for o in pops if o['type'] == 'REG_R')
        rw = sum(1 for o in pops if o['type'] == 'REG_W')
        h2c = sum(1 for o in pops if o['type'] == 'BULK_OUT')
        print(f"  {name:20s} {len(pops):6d} {rr:6d} {rw:6d} {h2c:5d}")

    # Generate combined init (INIT_START + INIT_INSMOD before FW download)
    # We need to separate FW download sections from H2C commands
    # FW download goes to EP7 with specific header patterns
    # H2C commands go to EP5 (and some EP7 after boot)

    # Let's output each phase as a separate file with all operations
    output_phases = [
        ('00_init', ['INIT_START']),
        ('01_fw_and_post_boot', ['INIT_INSMOD']),
        ('02_monitor', ['MONITOR_START', 'MONITOR_DONE']),
        ('03_ch1_2g', ['CH_1']),
        ('04_ch6_2g', ['CH_6']),
        ('05_ch11_2g', ['CH_11']),
        ('06_ch36_5g', ['CH_36']),
        ('07_ch48_5g', ['CH_48']),
        ('08_ch149_5g', ['CH_149']),
        ('09_ch165_5g', ['CH_165']),
        ('10_txpower', ['TXP_100', 'TXP_1000', 'TXP_2000', 'TXP_3000']),
        ('11_rx_and_tx', ['RX_START', 'TX_START']),
        ('12_bandwidth', ['BW_START']),
        ('13_rmmod', ['RMMOD_START']),
    ]

    for filename, phase_names in output_phases:
        combined_ops = []
        for pn in phase_names:
            combined_ops.extend(phase_ops.get(pn, []))

        if not combined_ops:
            continue

        lines, wc, hc = ops_to_rust_writes(combined_ops, ', '.join(phase_names))

        outpath = os.path.join(OUTDIR, f'{filename}.rs')
        with open(outpath, 'w') as f:
            f.write('\n'.join(lines))

        rr = sum(1 for o in combined_ops if o['type'] == 'REG_R')
        rw = sum(1 for o in combined_ops if o['type'] == 'REG_W')
        h2c = sum(1 for o in combined_ops if o['type'] == 'BULK_OUT')
        print(f"\n  Wrote {outpath}")
        print(f"    {len(combined_ops)} ops: {rr} reads, {rw} writes, {h2c} H2C")

    # Also output raw binary H2C data for each phase
    h2c_dir = os.path.join(OUTDIR, 'h2c_raw')
    os.makedirs(h2c_dir, exist_ok=True)

    total_h2c = 0
    for name, _ in PHASES:
        pops = phase_ops.get(name, [])
        h2c_ops = [o for o in pops if o['type'] == 'BULK_OUT']
        for j, h in enumerate(h2c_ops):
            fname = f'{name}_{j:03d}_ep{h["ep"]}_{len(h["data"])}B.bin'
            with open(os.path.join(h2c_dir, fname), 'wb') as f:
                f.write(h['data'])
            total_h2c += 1

    print(f"\n  Wrote {total_h2c} raw H2C binaries to {h2c_dir}/")

    print("\nDone!")


if __name__ == '__main__':
    main()
