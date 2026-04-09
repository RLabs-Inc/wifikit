#!/bin/bash
# RTL8852BU setup: SCSI eject → verify WiFi 6 mode
# Run after plugging in the Chinese AX5400 6E adapter.
#
# Usage: ./scripts/setup_8852bu.sh

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
echo "  RTL8852BU Setup — AX5400 6E Adapter"
echo "═══════════════════════════════════════════"
echo ""

# ── Step 1: Check if already in WiFi mode ──

check_wifi_device() {
    ioreg -p IOUSB 2>/dev/null | grep -q "802.11ax WLAN Adapter" 2>/dev/null
}

check_disk() {
    # Check for Realtek DISK on USB bus (PID 0x1A2B = 6699)
    ioreg -p IOUSB -w0 2>/dev/null | grep -qi "DISK" 2>/dev/null
}

if check_wifi_device; then
    ok "Device already in 802.11ax WiFi mode (0BDA:C832)"
    ok "Ready to use!"
    echo ""
    exit 0
fi

# ── Step 2: Modeswitch via SCSI eject ──

echo "Step 1: USB modeswitch"

if ! check_disk; then
    fail "No Realtek DISK device found"
    warn "Is the adapter plugged in?"
    exit 1
fi

info "Found Realtek DISK (storage mode)"
info "Sending SCSI eject via pyusb..."

SWITCH_OUTPUT=$(sudo python3 -c "
import usb.core, usb.util, time
dev = usb.core.find(idVendor=0x0BDA, idProduct=0x1A2B)
if not dev:
    print('FAIL: No DISK device')
    exit(1)
try: dev.detach_kernel_driver(0)
except: pass
usb.util.claim_interface(dev, 0)
dev.clear_halt(0x05)
dev.clear_halt(0x84)
# Drain stale data
for _ in range(5):
    try: dev.read(0x84, 512, timeout=200)
    except: break
# SCSI START STOP UNIT (eject)
eject = bytes([0x55,0x53,0x42,0x43,0x01,0,0,0,0,0,0,0,0,0,0x06,0x1B,0,0,0,0x02,0,0,0,0,0,0,0,0,0,0,0])
dev.write(0x05, eject, timeout=3000)
try: dev.read(0x84, 512, timeout=3000)
except: pass
usb.util.release_interface(dev, 0)
print('OK: Eject sent')
" 2>&1)

if echo "$SWITCH_OUTPUT" | grep -q "OK:"; then
    ok "SCSI eject sent"
else
    fail "Modeswitch failed: $SWITCH_OUTPUT"
    exit 1
fi

# ── Step 3: Wait for WiFi device ──

echo ""
echo "Step 2: Waiting for WiFi device"

for i in $(seq 1 15); do
    sleep 1
    if check_wifi_device; then
        ok "802.11ax WLAN Adapter appeared after ${i}s"
        break
    fi
    if [ "$i" -eq 15 ]; then
        fail "WiFi device did not appear after 15s"
        warn "Try unplugging and replugging the adapter"
        exit 1
    fi
done

# ── Step 4: Verification ──

echo ""
echo "Step 3: Verification"

sleep 1

if check_wifi_device; then
    # Get PID
    PID=$(ioreg -p IOUSB -l 2>/dev/null | grep -B5 "802.11ax" | grep "idProduct" | head -1 | awk '{print $NF}')
    ok "802.11ax WLAN Adapter confirmed (PID: ${PID:-unknown})"
else
    fail "No WLAN Adapter detected"
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════"
ok "RTL8852BU ready"
echo "═══════════════════════════════════════════"
echo ""
