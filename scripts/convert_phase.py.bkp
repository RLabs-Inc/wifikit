#!/usr/bin/env python3
"""Convert driver phase .rs pseudo-code into proper Rust PostBootOp arrays.

Reads phase files from references/rtl8852au_usb3_20260330_125324/driver_phases/
and generates compilable Rust modules using the PostBootOp enum.

Usage: python3 scripts/convert_phase.py <phase_file> <module_name>
"""

import re
import sys
import os


def parse_phase_file(path):
    """Parse a phase .rs file and extract operations in order."""
    ops = []
    bulk_arrays = {}  # name -> bytes

    with open(path) as f:
        lines = f.readlines()

    # First pass: collect all const arrays
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Match: const H2C_1: [u8; 90] = [
        m = re.match(r'const\s+(\w+):\s*\[u8;\s*(\d+)\]\s*=\s*\[', line)
        if m:
            name = m.group(1)
            size = int(m.group(2))
            # Collect hex bytes until ];
            hex_bytes = []
            i += 1
            while i < len(lines):
                bline = lines[i].strip()
                if bline.startswith('];'):
                    break
                # Extract hex values
                for hm in re.finditer(r'0x([0-9A-Fa-f]{2})', bline):
                    hex_bytes.append(int(hm.group(1), 16))
                i += 1
            bulk_arrays[name] = hex_bytes
            i += 1
            continue
        i += 1

    # Second pass: extract operations in order
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Skip comments, empty lines, const declarations (handled above)
        if not line or line.startswith('//') or line.startswith('///') or line.startswith('const '):
            # Skip const array bodies
            if line.startswith('const ') and '[' in line:
                while i < len(lines) and not lines[i].strip().startswith('];'):
                    i += 1
            i += 1
            continue

        # Match: let _ = self.read8(0xABCD)?; or let _ = self.read32(0x0001ABCD)?;
        m = re.match(r'let\s+_\s*=\s*self\.read(\d+)\(0x([0-9A-Fa-f]+)\)\?', line)
        if m:
            width = int(m.group(1)) // 8
            addr = int(m.group(2), 16)
            ops.append(('Read', addr, width))
            i += 1
            continue

        # Match: self.write32(0xABCD, 0x12345678)?; or self.write32(0x0001ABCD, 0x12345678)?;
        m = re.match(r'self\.write(\d+)\(0x([0-9A-Fa-f]+),\s*0x([0-9A-Fa-f]+)\)\?', line)
        if m:
            width = int(m.group(1)) // 8
            addr = int(m.group(2), 16)
            val = int(m.group(3), 16)
            ops.append(('Write', addr, val, width))
            i += 1
            continue

        # Match: self.bulk_out(0x05, &H2C_1)?;
        m = re.match(r'self\.bulk_out\(0x([0-9A-Fa-f]+),\s*&(\w+)\)\?', line)
        if m:
            ep = int(m.group(1), 16)
            name = m.group(2)
            if name in bulk_arrays:
                ops.append(('BulkOut', ep, bulk_arrays[name]))
            else:
                print(f"WARNING: bulk array {name} not found!", file=sys.stderr)
            i += 1
            continue

        # Match inline bulk: self.bulk_out(0x07, &[0x00, 0x01, ...])?;
        m = re.match(r'self\.bulk_out\(0x([0-9A-Fa-f]+),\s*&\[([^\]]+)\]\)\?', line)
        if m:
            ep = int(m.group(1), 16)
            hex_str = m.group(2)
            data = []
            for hm in re.finditer(r'0x([0-9A-Fa-f]{2})', hex_str):
                data.append(int(hm.group(1), 16))
            ops.append(('BulkOut', ep, data))
            i += 1
            continue

        i += 1

    return ops


def format_bytes(data, indent=4):
    """Format byte array as Rust hex literal."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
        lines.append(' ' * indent + hex_str + ',')
    return '\n'.join(lines)


def generate_rust_module(ops, module_name, phase_comment):
    """Generate a Rust module with PostBootOp array."""
    out = []
    out.append(f'//! RTL8852AU {phase_comment}')
    out.append('//! Generated from usbmon pcap capture — DO NOT EDIT')
    out.append('')
    out.append('#![allow(dead_code)]')
    out.append('')
    out.append('use super::rtl8852a_post_boot::PostBootOp;')
    out.append('')

    # Generate bulk data constants
    bulk_idx = 0
    bulk_names = {}
    for op in ops:
        if op[0] == 'BulkOut':
            name = f'BULK_{bulk_idx}'
            bulk_names[id(op)] = (name, len(op[2]))
            out.append(f'const {name}: [u8; {len(op[2])}] = [')
            out.append(format_bytes(op[2]))
            out.append('];')
            out.append('')
            bulk_idx += 1

    # Generate the operation sequence
    reads = sum(1 for o in ops if o[0] == 'Read')
    writes = sum(1 for o in ops if o[0] == 'Write')
    bulks = sum(1 for o in ops if o[0] == 'BulkOut')

    out.append(f'/// {phase_comment}: {reads} reads, {writes} writes, {bulks} bulk commands')
    out.append(f'pub const {module_name.upper()}_SEQUENCE: &[PostBootOp] = &[')

    for op in ops:
        if op[0] == 'Read':
            out.append(f'    PostBootOp::Read(0x{op[1]:08X}, {op[2]}),')
        elif op[0] == 'Write':
            out.append(f'    PostBootOp::Write(0x{op[1]:08X}, 0x{op[2]:08X}, {op[3]}),')
        elif op[0] == 'BulkOut':
            name, _size = bulk_names[id(op)]
            out.append(f'    PostBootOp::BulkOut({op[1]}, &{name}),')

    out.append('];')

    return '\n'.join(out)


def main():
    if len(sys.argv) < 3:
        print("Usage: convert_phase.py <phase_file> <module_name> [phase_comment]")
        sys.exit(1)

    phase_file = sys.argv[1]
    module_name = sys.argv[2]
    phase_comment = sys.argv[3] if len(sys.argv) > 3 else module_name

    ops = parse_phase_file(phase_file)

    reads = sum(1 for o in ops if o[0] == 'Read')
    writes = sum(1 for o in ops if o[0] == 'Write')
    bulks = sum(1 for o in ops if o[0] == 'BulkOut')

    print(f"// Parsed: {reads} reads, {writes} writes, {bulks} bulk commands", file=sys.stderr)

    rust_code = generate_rust_module(ops, module_name, phase_comment)
    print(rust_code)


if __name__ == '__main__':
    main()
