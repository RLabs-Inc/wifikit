```
                       ╱ ╱ ╱ ╲ ╲ ╲
                         ╱ ╱ ╲ ╲
                           ╱ ╲
                            ●

   ██╗    ██╗ ██╗ ███████╗ ██╗ ██╗  ██╗ ██╗ ████████╗
   ██║    ██║ ██║ ██╔════╝ ██║ ██║ ██╔╝ ██║ ╚══██╔══╝
   ██║ █╗ ██║ ██║ █████╗   ██║ █████╔╝  ██║    ██║
   ██║███╗██║ ██║ ██╔══╝   ██║ ██╔═██╗  ██║    ██║
   ╚███╔███╔╝ ██║ ██║      ██║ ██║  ██╗ ██║    ██║
    ╚══╝╚══╝  ╚═╝ ╚═╝      ╚═╝ ╚═╝  ╚═╝ ╚═╝    ╚═╝
```

# wifikit

WiFi pentesting toolkit for macOS. Pure Rust. No kernel extensions, no aircrack-ng, no VM.

Plug in a USB adapter, run `wifikit`, and you have a full pentesting lab — scanner, 10 attack engines, packet capture, handshake export — all in a terminal UI that doesn't look like it was made in 2004.

> **Status: MVP** — Core features are tested on real hardware. Some things are rough, some are missing.
> This is a working tool, not a finished product.

## Why This Exists

There is no WiFi pentesting tool that runs natively on macOS with Apple Silicon. Zero.

- **aircrack-ng**: Linux only. Monitor mode requires patched kernel drivers.
- **hashcat**: CUDA/OpenCL. No Metal support. CPU-only on Mac.
- **Kismet/Wireshark**: Passive only. No injection, no attacks.
- **Kali Linux VM**: Works, but you're running a VM to use a USB adapter.

wifikit talks directly to WiFi chipsets over USB. No kernel drivers. No root (beyond USB access). Pure userspace Rust, from register writes to the TUI.

## What Works

### Scanner

- Channel hopping across 2.4 GHz, 5 GHz, and 6 GHz (WiFi 6E)
- AP discovery with SSID, BSSID, channel, signal strength, security detection
- Client/station tracking and association mapping
- Active probing or passive-only mode
- OUI vendor lookup (IEEE MA-L/MA-M/MA-S databases)

### Attacks

| Module | What It Does | Variants |
|--------|-------------|----------|
| **PMKID** | Clientless WPA2 key extraction — no deauth, no disruption | Active association + EAPOL M1 capture |
| **WPS** | PIN cracking via Pixie Dust (offline, seconds), brute force, or null PIN | 3 modes, lockout detection, MAC rotation |
| **DoS** | Denial of service — 14 types from surgical to scorched earth | Deauth, disassoc, auth/assoc flood, beacon flood, CTS/RTS, NAV abuse, TKIP Michael, CSA, BSS transition, power save |
| **Rogue AP** | Fake access points | Open, Evil Twin, KARMA, MANA Loud, Known Beacons |
| **EAP** | Enterprise network attacks | Evil Twin, credential harvest (MSCHAPv2/LEAP/GTC/MD5), EAP downgrade, identity theft, cert bypass |
| **KRACK** | Key reinstallation attacks (11 CVEs) | 4-way handshake, group key, FT, TDLS, WNM — test mode with PN reuse detection |
| **FragAttacks** | Frame aggregation/fragmentation vulnerabilities (12 CVEs) | A-MSDU injection, mixed key, cache poisoning, plaintext injection, and more |
| **WPA3** | Dragonblood SAE attacks (8 modes) | Timing side-channel, group downgrade, transition downgrade, SAE DoS, invalid curve, reflection, anti-clogging |
| **Fuzzer** | Protocol fuzzing with crash detection | Frame/IE/EAP domains, 9 mutation strategies, seedable RNG for reproducibility |

### Capture & Export

- Full packet capture to pcap during any operation
- 4-way handshake detection and capture (WPA2, Group, FT, TDLS, WNM, SAE)
- Export to hashcat (.hc22000), John, asleap formats
- Feeds directly into [metal-crack](https://github.com/RLabs-Inc/metal-crack) for GPU cracking on Apple Silicon

### TX Feedback

- ACK/NACK reporting for injected frames — know if your packets are actually landing
- Per-rate optimization (CCK 1M for range, LDPC, STBC)
- TX power control up to 31 dBm (adapter dependent)

## Supported Hardware

wifikit includes full userspace drivers for these chipsets. No kernel modules, no airmon-ng — plug in and go.

| Chipset | Standard | Bands | Status | Adapters |
|---------|----------|-------|--------|----------|
| **RTL8812BU** | 802.11ac | 2.4 + 5 GHz | Production | TP-Link Archer T4U V3, ASUS USB-AC53 Nano, Netgear A6100 |
| **RTL8812AU** | 802.11ac | 2.4 + 5 GHz | Production | Alfa AWUS036ACH/AC, TP-Link Archer T4U V1/V2 |
| **RTL8852AU** | 802.11ax (WiFi 6) | 2.4 + 5 GHz | Production | Comfast CF-953AX, BrosTrend AX4L, ASUS USB-AX56 |
| **MT7921AU** | 802.11ax (WiFi 6E) | 2.4 + 5 + 6 GHz | Production | Fenvi FU-AX1800, COMFAST CF-952AX, Netgear A8000 |
| **MT7612U** | 802.11ac | 2.4 + 5 GHz | Basic — RX works, limited features | COMFAST CF-WU785AC, Netgear A6210 |

40+ specific USB VID/PID combinations recognized. If your adapter uses one of these chipsets, it should work.

**Recommended first adapter**: RTL8812BU-based (TP-Link Archer T4U V3 or similar). Most tested, most stable, widely available, ~$20.

## Building

### Requirements

- macOS (tested on Apple Silicon, should work on Intel)
- Rust toolchain (`rustup` — stable channel)
- A supported USB WiFi adapter

### Build & Run

```bash
git clone https://github.com/RLabs-Inc/wifikit.git
cd wifikit
cargo build --release
./target/release/wifikit
```

That's it. No drivers to install, no kernel extensions to load, no SIP to disable.

### Firmware

The RTL8852AU driver requires firmware (`rtl8852au_fw.bin`) included in the repo. All other chipsets have firmware embedded or loaded from on-chip ROM.

## Usage

wifikit launches into an interactive TUI. The workflow:

1. **Adapter selection** — auto-detects plugged adapters, pick one (or use multiple)
2. **Scanner** — starts channel hopping, builds AP/client map
3. **Attack** — select target, choose attack module, go
4. **Capture** — handshakes are captured automatically, export when ready

### Key Commands

```
/scan              Start/stop scanning
/attack <type>     Launch attack module (pmkid, wps, dos, ap, eap, krack, frag, wpa3, fuzz)
/export <format>   Export captures (hc22000, pcap, john, asleap)
/adapter           Switch adapter or view adapter info
/spectrum          MT7921AU spectrum analyzer (hardware MIB survey)
/help              Show all commands
```

### Multi-Adapter

wifikit supports running multiple adapters simultaneously. Use one for scanning while another runs an attack — the scanner never stops.

## What Doesn't Work (Yet)

What's missing or incomplete:

- **40/80/160 MHz channels** — all scanning and injection is 20 MHz only. You'll see every AP, but bandwidth-dependent attacks are limited.
- **KRACK full MitM mode** — test mode works (handshake capture + replay + PN detection), but the dual-adapter channel-based MitM engine is still to be implemented.
- **FragAttacks MitM variants** — design flaw CVEs (A-MSDU, mixed key, cache poison) need the MitM engine.
- **MAC address spoofing** — partially implemented. Works on some chipsets, no-op on others.
- **WEP attacks** — defined in taxonomy but not implemented. It's 2026.
- **MT7612U** — basic RX works but the driver is minimal. Not recommended for serious use.
- **6 GHz scanning** — MT7921AU supports it in hardware, but reception is weak. Investigation ongoing.
- **Windows/Linux** — theoretically possible (rusb is cross-platform), but untested and unbuilt.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   CLI (TUI)                      │
│         prism-rs framework + crossterm           │
├─────────────────────────────────────────────────┤
│              Attack Engines (10)                  │
│    PMKID · WPS · DoS · AP · EAP · KRACK         │
│    FragAttacks · WPA3 · Fuzz · Spectrum          │
├─────────────────────────────────────────────────┤
│              Frame Pipeline                       │
│   FrameGate → Parse → FrameStore → Subscribers   │
│                  ↓                                │
│              pcap writer                          │
├─────────────────────────────────────────────────┤
│           Scanner + Channel Hopper               │
│         SharedAdapter (Arc<Mutex>)               │
├─────────────────────────────────────────────────┤
│           Protocol Stack (802.11)                │
│  IEEE 802.11 · WPA/RSN · EAP · WPS · SAE        │
├─────────────────────────────────────────────────┤
│            Chip Drivers (userspace)              │
│  RTL8812AU · RTL8812BU · RTL8852AU · MT7921AU   │
├─────────────────────────────────────────────────┤
│                rusb (USB)                         │
└─────────────────────────────────────────────────┘
```

~245,000 lines of Rust. 1,027 tests. Zero unsafe blocks in application code. Pure Rust cryptography (RustCrypto).

## Related: metal-crack

[metal-crack](https://github.com/RLabs-Inc/metal-crack) is a companion tool — the first WPA/WPA2 password cracker running on Apple Metal GPU. Capture handshakes with wifikit, crack them with metal-crack. 200K PMKs/sec peak on M1 Max, no CUDA, no OpenCL, just `swift build && swift run`.

## Contributing

This is an MVP. There's a lot to improve:

- **New chipset drivers** — if you have a USB WiFi adapter and Linux driver source, it can probably be ported
- **40/80 MHz support** — the PHY register sequences exist in vendor drivers, they need porting
- **MitM engine** — needed for KRACK full mode and FragAttacks design flaw CVEs
- **Better 6 GHz** — MT7921AU hardware supports it, firmware configuration needs work
- **Bug reports** — especially from hardware we haven't tested

If you're interested in WiFi security research on macOS, this is probably the only tool that will let you do it without a Linux box.

## Legal

This tool is for **authorized security testing and research only**. WiFi pentesting without explicit authorization is illegal in most jurisdictions. You are responsible for how you use this software.

## License

MIT
