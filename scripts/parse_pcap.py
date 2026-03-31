#!/usr/bin/env python3
"""Parse USB pcap (USB_LINUX_MMAPPED) and extract all control + bulk transfers.
Outputs structured data for driver reimplementation."""

import struct
import sys
from collections import defaultdict

# USB_LINUX_MMAPPED header: 64 bytes
# See: https://www.kernel.org/doc/html/latest/usb/usbmon.html
# struct usbmon_packet {
#   u64 id;           // URB id
#   u8  type;         // 'S'ubmit, 'C'omplete, 'E'rror
#   u8  xfer_type;    // 0=ISO, 1=INT, 2=CONTROL, 3=BULK
#   u8  epnum;        // endpoint number (bit 7 = direction: 0=OUT, 1=IN)
#   u8  devnum;
#   u16 busnum;
#   char flag_setup;  // 0 = setup present, '-' = not
#   char flag_data;   // 0 = data present
#   s64 ts_sec;
#   s32 ts_usec;
#   s32 status;
#   u32 length;       // data length
#   u32 len_cap;      // captured data length
#   union { setup[8], iso_desc } s;
#   s32 interval;
#   s32 start_frame;
#   u32 xfer_flags;
#   u32 ndesc;
# };
# Total: 64 bytes

PCAP_GLOBAL_HDR = 24
PCAP_PKT_HDR = 16  # ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
USBMON_HDR = 64

def parse_pcap(filename, target_dev=None):
    with open(filename, 'rb') as f:
        # Global header
        magic = struct.unpack('<I', f.read(4))[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            print(f"Unknown pcap magic: 0x{magic:08x}")
            sys.exit(1)

        ver_major, ver_minor, _, _, snaplen, linktype = struct.unpack(
            f'{endian}HHiIII', f.read(20))
        print(f"pcap v{ver_major}.{ver_minor}, snaplen={snaplen}, linktype={linktype}")
        # linktype 220 = USB_LINUX_MMAPPED (DLT_USB_LINUX_MMAPPED)
        if linktype not in (220, 189):
            print(f"Warning: unexpected linktype {linktype}")

        packets = []
        pkt_num = 0

        while True:
            hdr = f.read(PCAP_PKT_HDR)
            if len(hdr) < PCAP_PKT_HDR:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f'{endian}IIII', hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            pkt_num += 1

            if len(pkt_data) < USBMON_HDR:
                continue

            # Parse usbmon header
            urb_id = struct.unpack('<Q', pkt_data[0:8])[0]
            urb_type = chr(pkt_data[8])    # 'S' or 'C'
            xfer_type = pkt_data[9]        # 0=ISO, 1=INT, 2=CONTROL, 3=BULK
            epnum = pkt_data[10]           # bit7=dir (1=IN), bits 0-3=ep number
            devnum = pkt_data[11]
            busnum = struct.unpack('<H', pkt_data[12:14])[0]
            flag_setup = pkt_data[14]      # 0 = setup present
            flag_data = pkt_data[15]       # 0 = data urb present
            ts_s = struct.unpack('<q', pkt_data[16:24])[0]
            ts_u = struct.unpack('<i', pkt_data[24:28])[0]
            status = struct.unpack('<i', pkt_data[28:32])[0]
            length = struct.unpack('<I', pkt_data[32:36])[0]
            len_cap = struct.unpack('<I', pkt_data[36:40])[0]
            setup = pkt_data[40:48]
            # interval, start_frame, xfer_flags, ndesc at 48-64

            ep_dir = 'IN' if (epnum & 0x80) else 'OUT'
            ep_addr = epnum & 0x0F

            # Filter to target device
            if target_dev and devnum != target_dev:
                continue

            # Data starts after the 64-byte header
            data = pkt_data[USBMON_HDR:USBMON_HDR + len_cap] if len_cap > 0 else b''

            timestamp = ts_s + ts_u / 1_000_000.0

            if xfer_type == 2:  # CONTROL
                if urb_type == 'S' and flag_setup == 0:
                    # Setup packet present
                    bmReq = setup[0]
                    bReq = setup[1]
                    wValue = struct.unpack('<H', setup[2:4])[0]
                    wIndex = struct.unpack('<H', setup[4:6])[0]
                    wLength = struct.unpack('<H', setup[6:8])[0]
                    is_read = (bmReq & 0x80) != 0

                    packets.append({
                        'num': pkt_num,
                        'type': 'CTRL_SUBMIT',
                        'urb_id': urb_id,
                        'ts': timestamp,
                        'bmReq': bmReq,
                        'bReq': bReq,
                        'wValue': wValue,
                        'wIndex': wIndex,
                        'wLength': wLength,
                        'is_read': is_read,
                        'data': data,
                        'ep': ep_addr,
                        'devnum': devnum,
                    })
                elif urb_type == 'C':
                    packets.append({
                        'num': pkt_num,
                        'type': 'CTRL_COMPLETE',
                        'urb_id': urb_id,
                        'ts': timestamp,
                        'status': status,
                        'data': data,
                        'ep': ep_addr,
                        'devnum': devnum,
                    })

            elif xfer_type == 3:  # BULK
                packets.append({
                    'num': pkt_num,
                    'type': f'BULK_{urb_type}',
                    'urb_id': urb_id,
                    'ts': timestamp,
                    'ep': ep_addr,
                    'ep_dir': ep_dir,
                    'status': status if urb_type == 'C' else None,
                    'data': data,
                    'data_len': length,
                    'devnum': devnum,
                })

    return packets


def match_control_pairs(packets):
    """Match CTRL_SUBMIT with their CTRL_COMPLETE to get full register read/write ops."""
    pending = {}  # urb_id -> submit packet
    ops = []

    for pkt in packets:
        if pkt['type'] == 'CTRL_SUBMIT':
            pending[pkt['urb_id']] = pkt
        elif pkt['type'] == 'CTRL_COMPLETE':
            submit = pending.pop(pkt['urb_id'], None)
            if submit and submit['bReq'] == 0x05:  # RTL vendor request
                addr = submit['wValue']
                size = submit['wLength']
                if submit['is_read']:
                    # Read: data comes in the complete
                    val = pkt['data']
                    ops.append({
                        'op': 'R',
                        'addr': addr,
                        'size': size,
                        'data': val,
                        'ts': submit['ts'],
                        'num': submit['num'],
                    })
                else:
                    # Write: data was in the submit
                    val = submit['data']
                    ops.append({
                        'op': 'W',
                        'addr': addr,
                        'size': size,
                        'data': val,
                        'ts': submit['ts'],
                        'num': submit['num'],
                    })

    return ops


def extract_bulk_out(packets):
    """Extract BULK OUT (H2C) commands — submit with data."""
    h2c = []
    for pkt in packets:
        if pkt['type'] == 'BULK_S' and pkt['ep_dir'] == 'OUT' and len(pkt['data']) > 0:
            h2c.append({
                'ep': pkt['ep'],
                'data': pkt['data'],
                'data_len': pkt['data_len'],
                'ts': pkt['ts'],
                'num': pkt['num'],
            })
    return h2c


def format_data(data, max_bytes=32):
    """Format bytes as hex string."""
    if len(data) <= max_bytes:
        return data.hex()
    return data[:max_bytes].hex() + f'... ({len(data)} bytes total)'


def analyze_h2c(data):
    """Parse H2C firmware command header if present."""
    if len(data) < 32:  # Need at least WD (24) + FWCMD header (8)
        return None

    # TX Write Descriptor (WD) is first 24 bytes
    # Then FWCMD header at offset 24
    dw0 = struct.unpack('<I', data[0:4])[0]
    dw1 = struct.unpack('<I', data[4:8])[0]

    # WD body DW0: bits[7:0] = HDR_LLC_LEN, bits[13:8] = WD_INFO_EN fields
    # WD body DW1: bits[13:0] = TXPKTSIZE, bits[23:14] = QSEL
    txpktsize = dw1 & 0x3FFF
    qsel = (dw1 >> 14) & 0x3FF

    # FWCMD header at offset 24
    if len(data) >= 32:
        cmd_dw0 = struct.unpack('<I', data[24:28])[0]
        cmd_dw1 = struct.unpack('<I', data[28:32])[0]

        # cat (bits 1:0), class (bits 7:2), func (bits 15:8), type(bit 6 of dw1?)
        cat = cmd_dw0 & 0x03
        cls = (cmd_dw0 >> 2) & 0x3F
        func = (cmd_dw0 >> 8) & 0xFF
        cmd_len = (cmd_dw0 >> 16) & 0xFFFF  # might not be standard

        return {
            'txpktsize': txpktsize,
            'qsel': qsel,
            'cat': cat,
            'cls': cls,
            'func': func,
            'payload_len': len(data) - 24,
        }
    return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file> [device_num]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    target_dev = int(sys.argv[2]) if len(sys.argv) > 2 else None

    print(f"\n=== Parsing {pcap_file} ===\n")

    packets = parse_pcap(pcap_file, target_dev)
    print(f"Total packets for device: {len(packets)}")

    # Categorize
    ctrl_submits = [p for p in packets if p['type'] == 'CTRL_SUBMIT']
    ctrl_completes = [p for p in packets if p['type'] == 'CTRL_COMPLETE']
    bulk_s_out = [p for p in packets if p['type'] == 'BULK_S' and p['ep_dir'] == 'OUT']
    bulk_c_out = [p for p in packets if p['type'] == 'BULK_C' and p['ep_dir'] == 'OUT']
    bulk_s_in = [p for p in packets if p['type'] == 'BULK_S' and p['ep_dir'] == 'IN']
    bulk_c_in = [p for p in packets if p['type'] == 'BULK_C' and p['ep_dir'] == 'IN']

    print(f"\n--- Packet breakdown ---")
    print(f"CONTROL Submit:  {len(ctrl_submits)}")
    print(f"CONTROL Complete:{len(ctrl_completes)}")
    print(f"BULK OUT Submit: {len(bulk_s_out)}")
    print(f"BULK OUT Complete:{len(bulk_c_out)}")
    print(f"BULK IN Submit:  {len(bulk_s_in)}")
    print(f"BULK IN Complete:{len(bulk_c_in)}")

    # Match control pairs
    reg_ops = match_control_pairs(packets)
    reads = [op for op in reg_ops if op['op'] == 'R']
    writes = [op for op in reg_ops if op['op'] == 'W']
    print(f"\n--- Register operations (bRequest=0x05) ---")
    print(f"Reads:  {len(reads)}")
    print(f"Writes: {len(writes)}")

    # Extract H2C
    h2c_cmds = extract_bulk_out(packets)
    print(f"\n--- H2C bulk OUT commands ---")
    print(f"Total: {len(h2c_cmds)}")

    # EP distribution
    ep_counts = defaultdict(int)
    ep_sizes = defaultdict(list)
    for cmd in h2c_cmds:
        ep_counts[cmd['ep']] += 1
        ep_sizes[cmd['ep']].append(len(cmd['data']))
    for ep, count in sorted(ep_counts.items()):
        sizes = ep_sizes[ep]
        print(f"  EP{ep}: {count} commands, sizes: min={min(sizes)} max={max(sizes)} avg={sum(sizes)//len(sizes)}")

    # Output everything to files
    base = pcap_file.rsplit('.', 1)[0]

    # 1. Register operations (chronological)
    with open(f'{base}_reg_ops.txt', 'w') as f:
        f.write(f"# Register operations from {pcap_file}\n")
        f.write(f"# {len(reg_ops)} total ({len(reads)} reads, {len(writes)} writes)\n")
        f.write(f"# Format: OP ADDR SIZE DATA [TIMESTAMP]\n\n")
        for op in reg_ops:
            data_hex = op['data'].hex() if op['data'] else ''
            f.write(f"{op['op']} 0x{op['addr']:04X} {op['size']} {data_hex}\n")
    print(f"\nWrote {base}_reg_ops.txt")

    # 2. H2C commands with analysis
    with open(f'{base}_h2c_cmds.txt', 'w') as f:
        f.write(f"# H2C bulk OUT commands from {pcap_file}\n")
        f.write(f"# {len(h2c_cmds)} total\n\n")
        for i, cmd in enumerate(h2c_cmds):
            info = analyze_h2c(cmd['data'])
            info_str = ''
            if info:
                info_str = f" cat={info['cat']} cls=0x{info['cls']:02X} func=0x{info['func']:02X} payload={info['payload_len']}B qsel={info['qsel']}"
            f.write(f"# H2C[{i}] EP{cmd['ep']} {len(cmd['data'])}B{info_str}\n")
            f.write(f"{cmd['data'].hex()}\n\n")
    print(f"Wrote {base}_h2c_cmds.txt")

    # 3. Full chronological trace (reg ops + H2C interleaved)
    all_events = []
    for op in reg_ops:
        all_events.append((op['ts'], op['num'], 'REG', op))
    for cmd in h2c_cmds:
        all_events.append((cmd['ts'], cmd['num'], 'H2C', cmd))
    all_events.sort(key=lambda x: x[1])  # sort by packet number

    with open(f'{base}_full_trace.txt', 'w') as f:
        f.write(f"# Full chronological trace from {pcap_file}\n")
        f.write(f"# {len(all_events)} events\n\n")
        for ts, num, etype, evt in all_events:
            if etype == 'REG':
                data_hex = evt['data'].hex() if evt['data'] else ''
                if evt['op'] == 'W':
                    f.write(f"[{num:6d}] REG_W 0x{evt['addr']:04X} {data_hex}\n")
                else:
                    f.write(f"[{num:6d}] REG_R 0x{evt['addr']:04X} -> {data_hex}\n")
            else:
                info = analyze_h2c(evt['data'])
                info_str = ''
                if info:
                    info_str = f" cat={info['cat']} cls=0x{info['cls']:02X} func=0x{info['func']:02X}"
                f.write(f"[{num:6d}] H2C EP{evt['ep']} {len(evt['data'])}B{info_str}\n")
                # First 64 bytes of data
                f.write(f"         {format_data(evt['data'], 64)}\n")
    print(f"Wrote {base}_full_trace.txt")

    # 4. Summary of first 50 events (for quick review)
    print(f"\n--- First 50 events ---")
    for ts, num, etype, evt in all_events[:50]:
        if etype == 'REG':
            data_hex = evt['data'].hex() if evt['data'] else ''
            if len(data_hex) > 16:
                data_hex = data_hex[:16] + '...'
            if evt['op'] == 'W':
                print(f"  [{num:6d}] W 0x{evt['addr']:04X} = {data_hex}")
            else:
                print(f"  [{num:6d}] R 0x{evt['addr']:04X} -> {data_hex}")
        else:
            info = analyze_h2c(evt['data'])
            info_str = ''
            if info:
                info_str = f" cat={info['cat']} cls=0x{info['cls']:02X} func=0x{info['func']:02X}"
            print(f"  [{num:6d}] H2C EP{evt['ep']} {len(evt['data'])}B{info_str}")


if __name__ == '__main__':
    main()
