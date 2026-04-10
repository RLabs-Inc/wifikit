#!/usr/bin/env python3
"""Convert a usbmon pcap init capture into a Rust source file.

Parses all USB operations (control read/write, bulk OUT) from a usbmon pcap,
filtered by bus/device, and emits a .rs file with structured operation arrays.
Stops at first EP5 bulk OUT (TX frame), matching replay_pcap_init() behavior.

The generated .rs file contains:
  - UsbInitOp enum: ControlWrite, ControlRead, BulkOut
  - Bulk payload data as const byte arrays
  - INIT_SEQUENCE: ordered array of all operations

Usage:
  python3 scripts/pcap_to_init_rs.py <pcap_file> --bus N --dev N [--module-name NAME]

Example:
  python3 scripts/pcap_to_init_rs.py src/chips/runtime/captures/rtl8852au_init.pcap \\
      --bus 1 --dev 16 --module-name rtl8852a_init
"""

import struct
import sys
import argparse
from pathlib import Path


# ─── PCAP Parsing ────────────────────────────────────────────────────────────

PCAP_GLOBAL_HDR = 24
PCAP_PKT_HDR = 16
USBMON_HDR = 64


def parse_pcap_init(filename, target_bus, target_dev):
    """Parse usbmon pcap and extract init operations up to first EP5 TX.

    Returns list of tuples:
      ('ControlWrite', wValue, wIndex, bytes)
      ('ControlRead', wValue, wIndex, length)
      ('BulkOut', endpoint_num, bytes)
    """
    ops = []

    with open(filename, 'rb') as f:
        # Global header
        magic = struct.unpack('<I', f.read(4))[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            print(f"Unknown pcap magic: 0x{magic:08x}", file=sys.stderr)
            sys.exit(1)

        _ver_major, _ver_minor, _, _, _snaplen, linktype = struct.unpack(
            f'{endian}HHiIII', f.read(20))

        if linktype not in (220, 189):
            print(f"Warning: unexpected linktype {linktype} (expected 220=USB_LINUX_MMAPPED)", file=sys.stderr)

        pkt_num = 0
        while True:
            hdr = f.read(PCAP_PKT_HDR)
            if len(hdr) < PCAP_PKT_HDR:
                break

            if endian == '<':
                _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack('<IIII', hdr)
            else:
                _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack('>IIII', hdr)

            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            pkt_num += 1

            if incl_len < USBMON_HDR:
                continue

            # Parse usbmon header
            pkt_type = pkt_data[8]     # 'S'=0x53 submit, 'C'=0x43 complete
            xfer_type = pkt_data[9]    # 2=control, 3=bulk
            ep = pkt_data[10]          # endpoint (bit 7 = direction)
            devnum = pkt_data[11]
            busnum = struct.unpack('<H', pkt_data[12:14])[0]

            ep_num = ep & 0x7F
            ep_dir_in = (ep & 0x80) != 0
            payload = pkt_data[USBMON_HDR:]

            # Filter: submit events for our device only
            if pkt_type != 0x53:
                continue
            if busnum != target_bus or devnum != target_dev:
                continue

            # ── Control WRITE (vendor OUT with payload) ──
            if xfer_type == 2 and not ep_dir_in and len(payload) > 0:
                setup = pkt_data[40:48]
                bm_req_type = setup[0]
                b_req = setup[1]
                w_val = struct.unpack('<H', setup[2:4])[0]
                w_idx = struct.unpack('<H', setup[4:6])[0]
                w_len = struct.unpack('<H', setup[6:8])[0]

                if b_req == 0x05 and bm_req_type == 0x40:
                    data = payload[:min(w_len, len(payload))]
                    ops.append(('ControlWrite', w_val, w_idx, bytes(data)))

            # ── Control READ (vendor IN) ──
            elif xfer_type == 2 and ep_dir_in:
                setup = pkt_data[40:48]
                bm_req_type = setup[0]
                b_req = setup[1]
                w_val = struct.unpack('<H', setup[2:4])[0]
                w_idx = struct.unpack('<H', setup[4:6])[0]
                w_len = struct.unpack('<H', setup[6:8])[0]

                if b_req == 0x05 and bm_req_type == 0xC0:
                    ops.append(('ControlRead', w_val, w_idx, w_len))

            # ── Bulk OUT ──
            elif xfer_type == 3 and not ep_dir_in and len(payload) > 0:
                # EP5 TX frame = init is done
                if ep_num == 5 and len(payload) > 48:
                    print(f"  Stopped at pkt #{pkt_num}: first EP5 TX frame ({len(payload)}B)", file=sys.stderr)
                    break

                ops.append(('BulkOut', ep_num, bytes(payload)))

    return ops


# ─── Rust Code Generation ────────────────────────────────────────────────────

def format_bytes_rust(data, indent=4):
    """Format byte slice as Rust hex literals, 16 bytes per line."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
        lines.append(' ' * indent + hex_str + ',')
    return '\n'.join(lines)


def generate_rust(ops, module_name, pcap_path, target_bus, target_dev):
    """Generate a complete Rust module from parsed operations."""
    out = []

    # Header
    out.append(f'//! {module_name} — USB init sequence extracted from usbmon pcap.')
    out.append(f'//! Source: {pcap_path}')
    out.append(f'//! Device: bus{target_bus} dev{target_dev}')
    out.append(f'//! DO NOT EDIT — generated by scripts/pcap_to_init_rs.py')
    out.append('')
    out.append('#![allow(dead_code)]')
    out.append('')

    # Stats
    ctrl_writes = sum(1 for o in ops if o[0] == 'ControlWrite')
    ctrl_reads = sum(1 for o in ops if o[0] == 'ControlRead')
    bulk_outs = sum(1 for o in ops if o[0] == 'BulkOut')
    total_bulk_bytes = sum(len(o[2]) for o in ops if o[0] == 'BulkOut')

    out.append(f'// Stats: {ctrl_writes} control writes, {ctrl_reads} control reads, {bulk_outs} bulk OUT ({total_bulk_bytes} bytes)')
    out.append(f'// Total: {len(ops)} operations')
    out.append('')

    # Enum definition
    out.append('/// USB init operation — faithfully represents one usbmon packet.')
    out.append('/// Addresses encode wIndex in upper 16 bits: full_addr = (wIndex << 16) | wValue')
    out.append('pub enum UsbInitOp {')
    out.append('    /// Vendor control write: (wValue, wIndex, data)')
    out.append('    ControlWrite(u16, u16, &\'static [u8]),')
    out.append('    /// Vendor control read: (wValue, wIndex, length)')
    out.append('    ControlRead(u16, u16, u16),')
    out.append('    /// Bulk OUT: (endpoint_number, data)')
    out.append('    BulkOut(u8, &\'static [u8]),')
    out.append('}')
    out.append('')

    # Generate bulk data constants
    bulk_idx = 0
    bulk_map = {}  # op index -> const name
    for i, op in enumerate(ops):
        if op[0] == 'ControlWrite' and len(op[3]) > 0:
            name = f'CW_{i}'
            bulk_map[i] = name
            out.append(f'const {name}: [u8; {len(op[3])}] = [{", ".join(f"0x{b:02X}" for b in op[3])}];')
        elif op[0] == 'BulkOut':
            name = f'BULK_{bulk_idx}'
            bulk_map[i] = name
            if len(op[2]) <= 32:
                # Short payload — inline
                out.append(f'const {name}: [u8; {len(op[2])}] = [{", ".join(f"0x{b:02X}" for b in op[2])}];')
            else:
                # Long payload — multi-line
                out.append(f'const {name}: [u8; {len(op[2])}] = [')
                out.append(format_bytes_rust(op[2]))
                out.append('];')
            bulk_idx += 1

    out.append('')

    # Generate the operation sequence
    out.append(f'/// Complete init sequence: {len(ops)} operations in exact pcap order.')
    out.append(f'pub const INIT_SEQUENCE: &[UsbInitOp] = &[')

    for i, op in enumerate(ops):
        if op[0] == 'ControlWrite':
            w_val, w_idx = op[1], op[2]
            addr = (w_idx << 16) | w_val
            if i in bulk_map:
                out.append(f'    UsbInitOp::ControlWrite(0x{w_val:04X}, 0x{w_idx:04X}, &{bulk_map[i]}), // W 0x{addr:08X}')
            else:
                out.append(f'    UsbInitOp::ControlWrite(0x{w_val:04X}, 0x{w_idx:04X}, &[]), // W 0x{addr:08X}')
        elif op[0] == 'ControlRead':
            w_val, w_idx, w_len = op[1], op[2], op[3]
            addr = (w_idx << 16) | w_val
            out.append(f'    UsbInitOp::ControlRead(0x{w_val:04X}, 0x{w_idx:04X}, {w_len}), // R 0x{addr:08X}')
        elif op[0] == 'BulkOut':
            ep_num = op[1]
            name = bulk_map[i]
            out.append(f'    UsbInitOp::BulkOut({ep_num}, &{name}), // EP{ep_num} {len(op[2])}B')

    out.append('];')

    return '\n'.join(out)


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Convert usbmon pcap init capture to Rust source file.')
    parser.add_argument('pcap_file', help='Path to usbmon pcap file')
    parser.add_argument('--bus', type=int, required=True, help='Target USB bus number')
    parser.add_argument('--dev', type=int, required=True, help='Target USB device number')
    parser.add_argument('--module-name', default='init_sequence',
                        help='Rust module name (default: init_sequence)')
    parser.add_argument('--output', '-o', help='Output .rs file (default: stdout)')

    args = parser.parse_args()

    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        print(f"Error: {pcap_path} not found", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing {pcap_path} (bus={args.bus}, dev={args.dev})...", file=sys.stderr)

    ops = parse_pcap_init(str(pcap_path), args.bus, args.dev)

    ctrl_writes = sum(1 for o in ops if o[0] == 'ControlWrite')
    ctrl_reads = sum(1 for o in ops if o[0] == 'ControlRead')
    bulk_outs = sum(1 for o in ops if o[0] == 'BulkOut')
    total_bulk_bytes = sum(len(o[2]) for o in ops if o[0] == 'BulkOut')

    print(f"  Control writes: {ctrl_writes}", file=sys.stderr)
    print(f"  Control reads:  {ctrl_reads}", file=sys.stderr)
    print(f"  Bulk OUT:       {bulk_outs} ({total_bulk_bytes} bytes)", file=sys.stderr)
    print(f"  Total ops:      {len(ops)}", file=sys.stderr)

    rust_code = generate_rust(ops, args.module_name, str(pcap_path),
                               args.bus, args.dev)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(rust_code)
            f.write('\n')
        print(f"  Written to {args.output}", file=sys.stderr)
    else:
        print(rust_code)


if __name__ == '__main__':
    main()
