#!/usr/bin/env python3
"""Convert RTL8852A C header tables to Rust const arrays."""

import re
import sys

BASE = "/Users/rusty/Documents/Projects/Ethical-Hacking/wifikit/references/rtl8852au/phl/hal_g6/phy"
OUT = "/Users/rusty/Documents/Projects/Ethical-Hacking/wifikit/src/chips/rtl8852a_tables.rs"

def extract_hex_pairs(lines):
    """Extract all hex value pairs from C array lines."""
    pairs = []
    # Collect all hex values from all lines
    all_values = []
    for line in lines:
        # Remove comments (// style)
        line = re.sub(r'//.*', '', line)
        # Remove /* */ comments
        line = re.sub(r'/\*.*?\*/', '', line)
        # Find all hex values
        hexvals = re.findall(r'0x[0-9A-Fa-f]+', line)
        all_values.extend(hexvals)

    # Group into pairs
    for i in range(0, len(all_values) - 1, 2):
        pairs.append((all_values[i], all_values[i+1]))

    return pairs

def read_file_lines(path):
    with open(path, 'r') as f:
        return f.readlines()

def format_pairs(pairs, name):
    """Format pairs as Rust const array."""
    lines = [f"pub const {name}: &[(u32, u32)] = &["]
    for addr, val in pairs:
        # Normalize to lowercase 0x prefix
        addr_lower = "0x" + addr[2:].upper()
        val_lower = "0x" + val[2:].upper()
        lines.append(f"    ({addr_lower}, {val_lower}),")
    lines.append("];")
    return "\n".join(lines)

def main():
    output_parts = []

    # Header
    output_parts.append("""\
//! RTL8852A register init tables — converted from lwfinger/rtl8852au vendor driver
//! Source: references/rtl8852au/phl/hal_g6/phy/
//! DO NOT EDIT: generated from halbb_hwimg_raw_data_8852a.h + halrf_hwimg_raw_data_8852a.h
#![allow(dead_code)]
""")

    # 1. BB PHY registers
    bb_path = f"{BASE}/bb/halbb_8852a/halbb_hwimg_raw_data_8852a.h"
    bb_lines = read_file_lines(bb_path)
    # Array starts at line 35 (0-indexed: 34), ends before };
    start = None
    end = None
    for i, line in enumerate(bb_lines):
        if 'array_mp_8852a_phy_reg[]' in line:
            start = i + 1  # skip the declaration line
        if start is not None and line.strip() == '};':
            end = i
            break

    bb_pairs = extract_hex_pairs(bb_lines[start:end])
    print(f"BB_PHY_REG: {len(bb_pairs)} pairs")
    output_parts.append(format_pairs(bb_pairs, "BB_PHY_REG"))
    output_parts.append("")

    # 2. RF Path A (lines 141 to 20529 in 1-indexed)
    rf_path = f"{BASE}/rf/halrf_8852a/halrf_hwimg_raw_data_8852a.h"
    rf_lines = read_file_lines(rf_path)

    # Find radioa array
    start_a = None
    end_a = None
    for i, line in enumerate(rf_lines):
        if 'array_mp_8852a_radioa[]' in line:
            start_a = i + 1
        if start_a is not None and end_a is None and line.strip() == '};':
            end_a = i
            break

    rfa_pairs = extract_hex_pairs(rf_lines[start_a:end_a])
    print(f"RF_A_INIT: {len(rfa_pairs)} pairs")
    output_parts.append(format_pairs(rfa_pairs, "RF_A_INIT"))
    output_parts.append("")

    # 3. RF Path B
    start_b = None
    end_b = None
    for i, line in enumerate(rf_lines):
        if 'array_mp_8852a_radiob[]' in line:
            start_b = i + 1
        if start_b is not None and end_b is None and line.strip() == '};':
            end_b = i
            break

    rfb_pairs = extract_hex_pairs(rf_lines[start_b:end_b])
    print(f"RF_B_INIT: {len(rfb_pairs)} pairs")
    output_parts.append(format_pairs(rfb_pairs, "RF_B_INIT"))
    output_parts.append("")

    # 4. NCTL
    nctl_path = f"{BASE}/rf/halrf_8852a/halrf_hwimg_nctl_raw_data_8852a.h"
    nctl_lines = read_file_lines(nctl_path)

    start_n = None
    end_n = None
    for i, line in enumerate(nctl_lines):
        if 'array_mp_8852ab_nctl_reg[]' in line:
            start_n = i + 1
        if start_n is not None and end_n is None and line.strip() == '};':
            end_n = i
            break

    nctl_pairs = extract_hex_pairs(nctl_lines[start_n:end_n])
    print(f"RF_NCTL: {len(nctl_pairs)} pairs")
    output_parts.append(format_pairs(nctl_pairs, "RF_NCTL"))
    output_parts.append("")

    # Write output
    with open(OUT, 'w') as f:
        f.write("\n".join(output_parts))

    print(f"\nWrote {OUT}")

if __name__ == '__main__':
    main()
