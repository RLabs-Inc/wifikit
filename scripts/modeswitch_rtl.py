#!/usr/bin/env python3
"""USB mode switch for Realtek WiFi adapters that present as CD-ROM (0x0BDA:0x1A2B)"""
import subprocess, time, sys, re

VID_RTL = "0x0bda"
PID_CDROM = "0x1a2b"

def find_disk_device():
    """Find the Realtek DISK device via ioreg"""
    r = subprocess.run(['ioreg', '-p', 'IOUSB', '-l', '-w0'], capture_output=True, text=True)
    # Look for Realtek DISK
    if 'Realtek' in r.stdout and 'DISK' in r.stdout:
        return True
    return False

def eject_disk():
    """Try to eject the Realtek DISK via diskutil"""
    # Find the disk device
    r = subprocess.run(['diskutil', 'list'], capture_output=True, text=True)
    lines = r.stdout.split('\n')
    disk_id = None
    for line in lines:
        if 'Realtek' in line or 'CDROM' in line or 'external' in line.lower():
            # Extract disk identifier
            m = re.search(r'(disk\d+)', line)
            if m:
                disk_id = m.group(1)
                break

    if not disk_id:
        # Try to find by listing all external/removable
        r2 = subprocess.run(['diskutil', 'list', 'external'], capture_output=True, text=True)
        for line in r2.stdout.split('\n'):
            m = re.search(r'(disk\d+)', line)
            if m:
                disk_id = m.group(1)
                break

    if disk_id:
        print(f"Found disk: {disk_id}, ejecting...")
        r = subprocess.run(['diskutil', 'eject', disk_id], capture_output=True, text=True)
        print(r.stdout.strip())
        if r.returncode == 0:
            return True
        print(f"diskutil eject failed: {r.stderr.strip()}")

    # Fallback: try all external disks
    r = subprocess.run(['diskutil', 'list'], capture_output=True, text=True)
    print("\nAll disks:")
    print(r.stdout)
    return False

def check_wifi_mode():
    """Check if device re-appeared in WiFi mode"""
    r = subprocess.run(['ioreg', '-p', 'IOUSB', '-l', '-w0'], capture_output=True, text=True)
    for known in ['013f', '802.11', 'WLAN']:
        if known in r.stdout:
            # Extract VID:PID
            vid_match = re.findall(r'"idVendor" = (\d+)', r.stdout)
            pid_match = re.findall(r'"idProduct" = (\d+)', r.stdout)
            name_match = re.findall(r'"USB Product Name" = "([^"]*)"', r.stdout)
            for v, p, n in zip(vid_match, pid_match, name_match):
                if 'WLAN' in n or '802.11' in n or int(p) == 0x013f:
                    print(f"\n*** WiFi mode! VID:PID = {int(v):04x}:{int(p):04x} — {n} ***")
                    return True
    return False

if __name__ == '__main__':
    print("=== Realtek USB Mode Switch (CD-ROM → WiFi) ===\n")

    if check_wifi_mode():
        print("Already in WiFi mode!")
        sys.exit(0)

    if not find_disk_device():
        print("No Realtek DISK found. Is the adapter plugged in?")
        sys.exit(1)

    print("Found Realtek DISK device")

    if eject_disk():
        print("\nWaiting for re-enumeration (3s)...")
        time.sleep(3)

        if check_wifi_mode():
            print("Mode switch successful!")
        else:
            print("Device not yet in WiFi mode. May need more time or replug.")
    else:
        print("\nCouldn't eject automatically. Try:")
        print("  diskutil list  (find the Realtek disk)")
        print("  diskutil eject diskN")
