#!/usr/bin/env python3
"""Extract RTL8852BU register operations from usbmon pcap captures into Rust source files.

Reads the segmented monitor-mode pcap captures and generates:
  - rtl8852b_channel_switch.rs: per-channel-per-bandwidth switch functions
  - rtl8852b_init.rs: full init sequence (register ops + firmware chunks + H2C)
  - rtl8852b_monitor.rs: monitor mode setup sequence

Output pattern matches rtl8852a_channel_switch.rs — hardcoded write32/read32 calls.
"""

import struct
import sys
import os
from collections import OrderedDict
from pathlib import Path

# ─── Configuration ───────────────────────────────────────────────────────────

PCAP_DIR = Path("references/rtl8852bu_monitor_20260407")
OUT_DIR = Path("src/chips")

TARGET_BUS = 3
TARGET_DEV = 5

# Channel+BW order from FULL_CHBW capture (phases.log ret0 entries only)
CHBW_ORDER = [
    (1, "ht20"), (1, "ht40p"),
    (2, "ht20"), (2, "ht40p"),
    (3, "ht20"), (3, "ht40p"),
    (4, "ht20"), (4, "ht40p"),
    (5, "ht20"), (5, "ht40p"), (5, "ht40m"),
    (6, "ht20"), (6, "ht40p"), (6, "ht40m"),
    (7, "ht20"), (7, "ht40p"), (7, "ht40m"),
    (8, "ht20"), (8, "ht40m"),
    (9, "ht20"), (9, "ht40m"),
    (10, "ht20"), (10, "ht40m"),
    (11, "ht20"), (11, "ht40m"),
    (36, "ht20"), (36, "ht40p"), (36, "vht80"),
    (40, "ht20"), (40, "ht40p"), (40, "ht40m"), (40, "vht80"),
    (44, "ht20"), (44, "ht40p"), (44, "ht40m"), (44, "vht80"),
    (48, "ht20"), (48, "ht40p"), (48, "ht40m"), (48, "vht80"),
    (52, "ht20"), (52, "ht40p"), (52, "ht40m"), (52, "vht80"),
    (56, "ht20"), (56, "ht40p"), (56, "ht40m"), (56, "vht80"),
    (60, "ht20"), (60, "ht40p"), (60, "ht40m"), (60, "vht80"),
    (64, "ht20"), (64, "ht40m"), (64, "vht80"),
    (100, "ht20"), (100, "ht40p"), (100, "vht80"),
    (104, "ht20"), (104, "ht40p"), (104, "ht40m"), (104, "vht80"),
    (108, "ht20"), (108, "ht40p"), (108, "ht40m"), (108, "vht80"),
    (112, "ht20"), (112, "ht40p"), (112, "ht40m"), (112, "vht80"),
    (116, "ht20"), (116, "ht40p"), (116, "ht40m"), (116, "vht80"),
    (120, "ht20"), (120, "ht40p"), (120, "ht40m"), (120, "vht80"),
    (124, "ht20"), (124, "ht40p"), (124, "ht40m"), (124, "vht80"),
    (128, "ht20"), (128, "ht40p"), (128, "ht40m"), (128, "vht80"),
    (132, "ht20"), (132, "ht40p"), (132, "ht40m"),
    (136, "ht20"), (136, "ht40p"), (136, "ht40m"),
    (140, "ht20"), (140, "ht40m"),
    (149, "ht20"), (149, "ht40p"), (149, "vht80"),
    (153, "ht20"), (153, "ht40p"), (153, "ht40m"), (153, "vht80"),
    (157, "ht20"), (157, "ht40p"), (157, "ht40m"), (157, "vht80"),
    (161, "ht20"), (161, "ht40p"), (161, "ht40m"), (161, "vht80"),
    (165, "ht20"), (165, "ht40m"),
]

BW_CODE = {"ht20": 0, "ht40p": 1, "ht40m": 2, "vht80": 3}


# ─── PCAP Parsing ────────────────────────────────────────────────────────────

def parse_pcap_ops(pcap_path):
    """Parse usbmon pcap and extract register operations for target device.

    Returns list of (timestamp, op_type, addr, value, payload_bytes) tuples.
    op_type: 'W1'=write8, 'W2'=write16, 'W4'=write32, 'R'=read, 'EP7'=bulk out
    """
    data = pcap_path.read_bytes()
    if len(data) < 24:
        return []

    # Verify pcap magic
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0xA1B2C3D4:
        print(f"  WARNING: {pcap_path.name} has unexpected magic 0x{magic:08X}")
        return []

    ops = []
    offset = 24  # skip global header

    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from('<IIII', data, offset)
        offset += 16

        if offset + incl_len > len(data) or incl_len < 64:
            offset += incl_len
            continue

        pkt = data[offset:offset + incl_len]
        offset += incl_len

        pkt_type = pkt[8]
        xfer_type = pkt[9]
        ep = pkt[10]
        devnum = pkt[11]
        busnum = struct.unpack_from('<H', pkt, 12)[0]

        if busnum != TARGET_BUS or devnum != TARGET_DEV or pkt_type != 0x53:
            continue

        ts = ts_sec + ts_usec / 1e6
        ep_num = ep & 0x7F
        ep_dir_in = ep & 0x80 != 0
        payload = pkt[64:]

        if xfer_type == 2:  # control transfer
            setup = pkt[40:48]
            bm, breq = setup[0], setup[1]
            wval = struct.unpack_from('<H', setup, 2)[0]
            widx = struct.unpack_from('<H', setup, 4)[0]
            wlen = struct.unpack_from('<H', setup, 6)[0]
            addr = (widx << 16) | wval

            if breq != 0x05:
                continue

            if bm == 0x40 and payload:  # write
                val = int.from_bytes(payload[:min(4, len(payload))], 'little')
                write_len = min(wlen, len(payload))
                if write_len == 1:
                    ops.append((ts, 'W1', addr, val & 0xFF, payload[:write_len]))
                elif write_len == 2:
                    ops.append((ts, 'W2', addr, val & 0xFFFF, payload[:write_len]))
                else:
                    ops.append((ts, 'W4', addr, val, payload[:write_len]))
            elif bm == 0xC0:  # read
                ops.append((ts, 'R', addr, wlen, b''))
        elif xfer_type == 3 and not ep_dir_in and ep_num == 7 and payload:  # EP7 bulk
            ops.append((ts, 'EP7', 0, 0, bytes(payload)))

    return ops


def find_switch_groups(ops):
    """Find channel switch boundaries (0x8140 = 0x00000205) and group by time gap."""
    switch_starts = [i for i, o in enumerate(ops)
                     if o[1] == 'W4' and o[2] == 0x8140 and o[3] == 0x00000205]

    if not switch_starts:
        return []

    # Group by 200ms gap
    groups = []
    current = [switch_starts[0]]
    for i in range(1, len(switch_starts)):
        gap = ops[switch_starts[i]][0] - ops[switch_starts[i-1]][0]
        if gap > 0.15:
            groups.append(current)
            current = [switch_starts[i]]
        else:
            current.append(switch_starts[i])
    groups.append(current)

    return groups


def ops_to_rust(ops_slice, indent="    "):
    """Convert a slice of operations to Rust code lines."""
    lines = []
    for ts, op_type, addr, val, payload in ops_slice:
        if op_type == 'W1':
            if addr > 0xFFFF:
                # Extended write8 — not common, use write32_ext with mask if needed
                lines.append(f"{indent}self.write32_ext(0x{addr:08X}, 0x{val:08X})?;")
            else:
                lines.append(f"{indent}self.write8(0x{addr:04X}, 0x{val:02X})?;")
        elif op_type == 'W2':
            if addr > 0xFFFF:
                lines.append(f"{indent}self.write32_ext(0x{addr:08X}, 0x{val:08X})?;")
            else:
                lines.append(f"{indent}self.write16(0x{addr:04X}, 0x{val:04X})?;")
        elif op_type == 'W4':
            if addr > 0xFFFF:
                lines.append(f"{indent}self.write32_ext(0x{addr:08X}, 0x{val:08X})?;")
            else:
                lines.append(f"{indent}self.write32(0x{addr:04X}, 0x{val:08X})?;")
        elif op_type == 'R':
            if addr > 0xFFFF:
                lines.append(f"{indent}let _ = self.read32_ext(0x{addr:08X});")
            else:
                lines.append(f"{indent}let _ = self.read32(0x{addr:04X});")
        elif op_type == 'EP7':
            # Firmware/H2C bulk write
            hex_bytes = ', '.join(f'0x{b:02X}' for b in payload)
            lines.append(f"{indent}self.write_ep7(&[{hex_bytes}])?;")
    return lines


# ─── Channel Switch Extraction ────────────────────────────────────────────────

def extract_channel_switches():
    """Extract per-channel-per-bandwidth switch functions from 03_channel_hop_all.pcap."""
    pcap = PCAP_DIR / "03_channel_hop_all.pcap"
    print(f"Parsing {pcap.name}...")
    ops = parse_pcap_ops(pcap)
    print(f"  {len(ops)} register ops from bus{TARGET_BUS}dev{TARGET_DEV}")

    groups = find_switch_groups(ops)
    print(f"  {len(groups)} switch groups (expected {len(CHBW_ORDER)})")

    if len(groups) != len(CHBW_ORDER):
        print(f"  ERROR: expected {len(CHBW_ORDER)} groups, got {len(groups)}")
        print(f"  Group sizes: {[len(g) for g in groups]}")
        sys.exit(1)

    # Generate Rust file
    lines = []
    lines.append("//! RTL8852BU per-channel+bandwidth switch register sequences.")
    lines.append("//!")
    lines.append("//! Each function replays the EXACT USB register operations from the rtw89")
    lines.append("//! Linux driver's channel switch. Extracted from monitor-mode usbmon capture.")
    lines.append("//!")
    lines.append(f"//! Generated from: {pcap}")
    lines.append(f"//! Device: bus{TARGET_BUS} dev{TARGET_DEV} (RTL8852BU)")
    lines.append(f"//! Channel+BW combos: {len(CHBW_ORDER)}")
    lines.append("")
    lines.append("use crate::core::error::Error;")
    lines.append("type Result<T> = std::result::Result<T, Error>;")
    lines.append("")
    lines.append("use super::rtl8852bu::Rtl8852bu;")
    lines.append("")
    lines.append("#[allow(dead_code)]")
    lines.append("#[allow(unused_variables)]")
    lines.append("impl Rtl8852bu {")

    # Dispatcher function
    lines.append("/// Channel+BW switch via pcap replay.")
    lines.append("/// bw: 0=HT20, 1=HT40+, 2=HT40-, 3=VHT80")
    lines.append("pub(crate) fn pcap_channel_switch(&self, ch: u8, bw: u8) -> Result<()> {")
    lines.append("    match (ch, bw) {")

    for ch, bw_name in CHBW_ORDER:
        bw = BW_CODE[bw_name]
        fn_name = f"pcap_ch_{ch}_{bw_name}"
        lines.append(f"        ({ch}, {bw}) => self.{fn_name}(),")

    lines.append("        _ => Err(Error::UnsupportedChannel {")
    lines.append("            channel: ch,")
    lines.append('            chip: format!("RTL8852BU (no pcap for ch{} bw{})", ch, bw),')
    lines.append("        }),")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    # Per-channel functions
    total_ops = 0
    for idx, (ch, bw_name) in enumerate(CHBW_ORDER):
        group = groups[idx]
        fn_name = f"pcap_ch_{ch}_{bw_name}"

        # Collect all ops for this group (both sub-switches)
        all_ops = []
        for si, start_idx in enumerate(group):
            # Find end of this sub-switch (next switch start or end of ops)
            if si + 1 < len(group):
                end_idx = group[si + 1]
            elif idx + 1 < len(groups):
                end_idx = groups[idx + 1][0]
            else:
                end_idx = len(ops)

            all_ops.extend(ops[start_idx:end_idx])

        rust_lines = ops_to_rust(all_ops)
        total_ops += len(all_ops)

        lines.append(f"fn {fn_name}(&self) -> Result<()> {{")
        lines.extend(rust_lines)
        lines.append("    Ok(())")
        lines.append("}")
        lines.append("")

    lines.append("} // impl Rtl8852bu")

    out_path = OUT_DIR / "rtl8852b_channel_switch.rs"
    out_path.write_text('\n'.join(lines) + '\n')
    print(f"  Wrote {out_path}: {len(CHBW_ORDER)} functions, {total_ops} total ops, {len(lines)} lines")
    return len(CHBW_ORDER)


# ─── Init + Monitor Extraction ────────────────────────────────────────────────

def extract_init_and_monitor():
    """Extract init and monitor sequences from 01_device_init.pcap + 02_monitor_setup.pcap."""

    # ── Init ──
    init_pcap = PCAP_DIR / "01_device_init.pcap"
    print(f"Parsing {init_pcap.name}...")
    init_ops = parse_pcap_ops(init_pcap)
    print(f"  {len(init_ops)} register ops")

    # Count op types
    writes = sum(1 for o in init_ops if o[1].startswith('W'))
    reads = sum(1 for o in init_ops if o[1] == 'R')
    ep7s = sum(1 for o in init_ops if o[1] == 'EP7')
    print(f"  {writes} writes, {reads} reads, {ep7s} EP7 bulk")

    # ── Monitor ──
    mon_pcap = PCAP_DIR / "02_monitor_setup.pcap"
    print(f"Parsing {mon_pcap.name}...")
    mon_ops = parse_pcap_ops(mon_pcap)
    print(f"  {len(mon_ops)} register ops")

    mon_writes = sum(1 for o in mon_ops if o[1].startswith('W'))
    mon_reads = sum(1 for o in mon_ops if o[1] == 'R')
    mon_ep7s = sum(1 for o in mon_ops if o[1] == 'EP7')
    print(f"  {mon_writes} writes, {mon_reads} reads, {mon_ep7s} EP7 bulk")

    # ── Detect firmware download boundary ──
    # FWDL chunks are EP7 with DW0 bit 20 (FWDL_EN) set
    # After FWDL, the WCPU enable write to 0x0088 happens
    # We need to separate: pre-FWDL regs, FWDL chunks, post-FWDL regs + H2C

    wcpu_enable_idx = None
    fwdl_start_idx = None
    fwdl_end_idx = None

    for i, (ts, op_type, addr, val, payload) in enumerate(init_ops):
        if op_type == 'EP7' and len(payload) >= 4:
            dw0 = struct.unpack_from('<I', payload, 0)[0]
            if dw0 & (1 << 20):  # FWDL_EN
                if fwdl_start_idx is None:
                    fwdl_start_idx = i
                fwdl_end_idx = i
        if op_type == 'W1' and addr == 0x0088:
            # Check if this enables WCPU (bit 1)
            if val & 0x02:
                wcpu_enable_idx = i
        elif op_type == 'W4' and addr == 0x0088:
            if val & 0x02:
                wcpu_enable_idx = i

    print(f"  FWDL range: ops[{fwdl_start_idx}]-ops[{fwdl_end_idx}]")
    print(f"  WCPU enable: op[{wcpu_enable_idx}]")

    # ── Generate init Rust file ──
    lines = []
    lines.append("//! RTL8852BU complete init + monitor mode register sequences.")
    lines.append("//!")
    lines.append("//! Extracted from monitor-mode usbmon captures. Contains:")
    lines.append("//!   - Pre-FWDL register configuration")
    lines.append("//!   - Firmware download chunks (EP7 bulk)")
    lines.append("//!   - Post-FWDL H2C commands and register setup")
    lines.append("//!   - Monitor mode configuration")
    lines.append("//!")
    lines.append(f"//! Generated from: {init_pcap}, {mon_pcap}")
    lines.append(f"//! Device: bus{TARGET_BUS} dev{TARGET_DEV} (RTL8852BU)")
    lines.append("")
    lines.append("use crate::core::error::Error;")
    lines.append("type Result<T> = std::result::Result<T, Error>;")
    lines.append("")
    lines.append("use super::rtl8852bu::Rtl8852bu;")
    lines.append("")
    lines.append("impl Rtl8852bu {")

    # ── Phase 1: Pre-FWDL registers ──
    pre_fwdl_ops = init_ops[:fwdl_start_idx] if fwdl_start_idx else init_ops
    lines.append("/// Phase 1: Pre-firmware-download register configuration.")
    lines.append(f"/// {len(pre_fwdl_ops)} operations: power on, DMAC setup, HCI init.")
    lines.append("pub(crate) fn pcap_pre_fwdl(&self) -> Result<()> {")
    lines.extend(ops_to_rust(pre_fwdl_ops))
    lines.append("    Ok(())")
    lines.append("}")
    lines.append("")

    # ── Phase 2: Firmware download ──
    if fwdl_start_idx is not None and fwdl_end_idx is not None:
        fwdl_ops = init_ops[fwdl_start_idx:fwdl_end_idx + 1]
        lines.append("/// Phase 2: Firmware download via EP7 bulk.")
        lines.append(f"/// {len(fwdl_ops)} operations: FW header + section data.")
        lines.append("pub(crate) fn pcap_fwdl(&self) -> Result<()> {")
        lines.extend(ops_to_rust(fwdl_ops))
        lines.append("    Ok(())")
        lines.append("}")
        lines.append("")

        post_fwdl_start = fwdl_end_idx + 1
    else:
        post_fwdl_start = 0

    # ── Phase 3: Post-FWDL (WCPU enable, H2C, remaining init) ──
    post_fwdl_ops = init_ops[post_fwdl_start:]

    # Split at WCPU enable — need special handling there
    if wcpu_enable_idx is not None and wcpu_enable_idx >= post_fwdl_start:
        pre_wcpu = init_ops[post_fwdl_start:wcpu_enable_idx]
        post_wcpu = init_ops[wcpu_enable_idx:]

        lines.append("/// Phase 3a: Post-FWDL setup before WCPU enable.")
        lines.append(f"/// {len(pre_wcpu)} operations.")
        lines.append("pub(crate) fn pcap_post_fwdl_pre_wcpu(&self) -> Result<()> {")
        lines.extend(ops_to_rust(pre_wcpu))
        lines.append("    Ok(())")
        lines.append("}")
        lines.append("")

        lines.append("/// Phase 3b: WCPU enable and post-boot H2C/register setup.")
        lines.append(f"/// {len(post_wcpu)} operations. Caller must handle WCPU ready polling + EP7 halt clear.")
        lines.append("pub(crate) fn pcap_post_wcpu(&self) -> Result<()> {")
        lines.extend(ops_to_rust(post_wcpu))
        lines.append("    Ok(())")
        lines.append("}")
        lines.append("")
    else:
        lines.append("/// Phase 3: Post-FWDL register + H2C setup.")
        lines.append(f"/// {len(post_fwdl_ops)} operations.")
        lines.append("pub(crate) fn pcap_post_fwdl(&self) -> Result<()> {")
        lines.extend(ops_to_rust(post_fwdl_ops))
        lines.append("    Ok(())")
        lines.append("}")
        lines.append("")

    # ── Monitor mode ──
    lines.append("/// Monitor mode setup: RX filters, CMAC, PHY configuration.")
    lines.append(f"/// {len(mon_ops)} operations.")
    lines.append("pub(crate) fn pcap_monitor_mode(&self) -> Result<()> {")
    lines.extend(ops_to_rust(mon_ops))
    lines.append("    Ok(())")
    lines.append("}")
    lines.append("")

    lines.append("} // impl Rtl8852bu")

    out_path = OUT_DIR / "rtl8852b_init.rs"
    out_path.write_text('\n'.join(lines) + '\n')
    print(f"  Wrote {out_path}: {len(lines)} lines")


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parent.parent)

    print("=== RTL8852BU PCAP → Rust Extractor ===\n")

    print("─── Init + Monitor ───")
    extract_init_and_monitor()
    print()

    print("─── Channel Switches ───")
    n = extract_channel_switches()
    print()

    print(f"Done. {n} channel+BW functions extracted.")
    print("Next: add 'mod rtl8852b_channel_switch;' and 'mod rtl8852b_init;' to mod.rs")
