#!/bin/bash
# RTL8852AU full setup: eject CD-ROM → USB3 switch → verify WiFi 6 mode
# Run after plugging in the TP-Link TX20U Plus adapter.
#
# Usage: ./scripts/setup_8852au.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
info() { echo -e "  ${CYAN}→${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }

echo ""
echo "═══════════════════════════════════════════"
echo "  RTL8852AU Setup — TP-Link TX20U Plus"
echo "═══════════════════════════════════════════"
echo ""

# ── Step 1: Check if already in WiFi mode on USB3 ──

check_wifi_device() {
    # Returns 0 if any WiFi device found (ac = USB2, ax = USB3)
    ioreg -p IOUSB 2>/dev/null | grep -qi "WLAN Adapter" 2>/dev/null
}

check_wifi_ax() {
    # Returns 0 only if 802.11ax (USB3 mode) — "ac" means still USB2
    ioreg -p IOUSB 2>/dev/null | grep -q "802.11ax WLAN Adapter" 2>/dev/null
}

check_cdrom() {
    # Find TP-Link CD-ROM disk — shows as external physical disk named "TP-Link" (~16MB)
    # diskutil list output: /dev/diskN (external, physical): ... TP-Link ... *16.6 MB
    local disk=""
    # Method 1: Look for "TP-Link" in diskutil list (most reliable)
    disk=$(diskutil list 2>/dev/null | grep -B2 "TP-Link" | grep "^/dev/disk" | head -1 | awk '{print $1}')
    if [ -z "$disk" ]; then
        # Method 2: Look for "Realtek" or "DISK" named devices
        disk=$(diskutil list 2>/dev/null | grep -B2 "Realtek\|DISK" | grep "^/dev/disk" | head -1 | awk '{print $1}')
    fi
    if [ -z "$disk" ]; then
        # Method 3: Small external physical disk (< 50MB)
        for d in $(diskutil list 2>/dev/null | grep "external, physical" | awk '{print $1}'); do
            local size_line=$(diskutil list "$d" 2>/dev/null | grep -E "^\s+0:" | head -1)
            if echo "$size_line" | grep -qE '[0-9.]+ MB'; then
                local mb=$(echo "$size_line" | grep -oE '[0-9.]+\s+MB' | grep -oE '^[0-9]+')
                if [ -n "$mb" ] && [ "$mb" -lt 50 ]; then
                    disk="$d"
                    break
                fi
            fi
        done
    fi
    echo "$disk"
}

# Check if we're already done (802.11ax = USB3 mode)
if check_wifi_ax; then
    ok "Device already in 802.11ax mode (USB 3.0)"
    ok "Ready to use!"
    echo ""
    exit 0
fi

# ── Step 2: Find and eject CD-ROM ──

echo "Step 1: CD-ROM eject"

# Check if device is in CD-ROM mode (shows as "DISK" on USB bus)
CDROM_DISK=$(check_cdrom)
if [ -n "$CDROM_DISK" ]; then
    info "Found TP-Link CD-ROM at $CDROM_DISK"
elif ioreg -p IOUSB -w0 2>/dev/null | grep -qi "DISK\|0x1a2b"; then
    info "Found USB mass storage device (CD-ROM mode)"
else
    # Maybe it's already ejected but not yet in USB3
    if check_wifi_device; then
        ok "Already in WiFi mode (no CD-ROM found)"
    else
        warn "No TP-Link USB device detected"
        fail "Is the adapter plugged in? Check USB connection."
        exit 1
    fi
fi

if [ -z "$CDROM_DISK" ]; then
    CDROM_DISK=$(check_cdrom)
fi
if [ -n "$CDROM_DISK" ]; then
    info "Ejecting $CDROM_DISK..."
    info "Ejecting..."
    if diskutil eject "$CDROM_DISK" 2>/dev/null; then
        ok "Ejected $CDROM_DISK"
    else
        # Try unmount + eject
        diskutil unmountDisk "$CDROM_DISK" 2>/dev/null || true
        diskutil eject "$CDROM_DISK" 2>/dev/null || true
        ok "Ejected $CDROM_DISK (forced)"
    fi

    # Wait for device to re-enumerate as WiFi adapter
    info "Waiting for WiFi device to appear..."
    for i in $(seq 1 15); do
        sleep 1
        if check_wifi_device; then
            ok "WiFi device appeared after ${i}s"
            break
        fi
        if [ "$i" -eq 15 ]; then
            fail "WiFi device did not appear after 15s"
            warn "Try unplugging and replugging the adapter"
            exit 1
        fi
    done
else
    if check_wifi_device; then
        ok "Already in WiFi mode"
    else
        warn "No CD-ROM disk found to eject"
        info "Trying to proceed anyway..."
    fi
fi

# Longer delay for USB stabilization — device needs time to fully enumerate
sleep 3

# ── Step 3: USB2 → USB3 mode switch ──

echo ""
echo "Step 2: USB3 mode switch"

# Build if needed (quietly)
info "Building usb3_switch..."
if ! cargo build --release --bin usb3_switch 2>/dev/null; then
    fail "Build failed"
    exit 1
fi
ok "Built"

# Run the switch
info "Running USB2→USB3 switch..."
SWITCH_OUTPUT=$(cargo run --release --bin usb3_switch 2>&1)

if echo "$SWITCH_OUTPUT" | grep -q "Already in USB 3.0"; then
    ok "Already USB 3.0"
elif echo "$SWITCH_OUTPUT" | grep -q "USB 3.0 ✓"; then
    ok "Switched to USB 3.0"
elif echo "$SWITCH_OUTPUT" | grep -q "Switch command sent"; then
    info "Switch command sent, waiting for 802.11ax re-enumeration..."
    for i in $(seq 1 10); do
        sleep 1
        if check_wifi_ax; then
            ok "802.11ax WLAN Adapter appeared after ${i}s"
            break
        fi
        if [ "$i" -eq 10 ]; then
            warn "Device did not appear as 802.11ax after 10s"
        fi
    done
elif echo "$SWITCH_OUTPUT" | grep -q "not found"; then
    fail "Device not found for USB3 switch"
    warn "The WiFi mode device may not have appeared yet"
    info "Try: sleep 3 && cargo run --release --bin usb3_switch"
    exit 1
else
    warn "Unexpected output from usb3_switch:"
    echo "$SWITCH_OUTPUT" | tail -5
fi

# ── Step 4: Final verification ──

echo ""
echo "Step 3: Verification"

sleep 1

if check_wifi_ax; then
    ok "802.11ax WLAN Adapter confirmed (USB 3.0)"
elif check_wifi_device; then
    warn "802.11ac WLAN Adapter detected (still USB 2.0)"
    warn "USB3 switch may have failed — try replugging"
else
    fail "No WLAN Adapter detected"
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════"
ok "RTL8852AU ready — run bench or scanner"
echo "═══════════════════════════════════════════"
echo ""
