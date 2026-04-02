# RTL8812BU Driver Roadmap — Complete Implementation Guide

**Chip**: Realtek RTL8822B (WiFi 5 802.11ac)
**Adapter**: TP-Link Archer T4U V3 (VID=0x2357 PID=0x0115)
**Architecture**: MAC gen2, host-driven BB/RF with H2C, 2x2 MIMO, USB 3.0
**Reference data**: `references/captures/rtl8812bu_efuse/` (iw_info, EFUSE), `references/captures/rtl8812bu-usb3/`
**Current driver**: `src/chips/rtl8812bu.rs` (~2500 lines)
**Status**: Most complete driver — IQK/DPK/LCK, EFUSE, TX power cal, H2C, aggregation, 420 APs/311fps

---

## A. FOUNDATION — Minor Gaps in Otherwise Good Driver

### A1. HT/VHT Rate Injection
- [ ] `tx_rate_to_hw()` falls back ALL HT/VHT rates to OFDM 6M (0x04) — same bug as 8812AU
- [ ] Map TxRate::Ht0-Ht15 → MCS 0-15 (0x10-0x1F in Realtek encoding)
- [ ] Map TxRate::Ht32 → MCS 32 (40MHz duplicate rate)
- [ ] Map TxRate::Vht1ss_mcs0-9, Vht2ss_mcs0-9 → (NSS, MCS) tuples
- [ ] Validate against Linux 88x2bu rate tables
- [ ] Rate adaptive masks exist (0x06C0/0x06C4) — may need updating for injection
- **Verification**: Inject at every MCS rate, capture verifies correct encoding

### A2. TX Descriptor Bandwidth Field
- [ ] BW field in TX descriptor always 20MHz even when channel is 40/80
- [ ] Store current bandwidth in driver state
- [ ] Set descriptor BW to match channel bandwidth
- [ ] Important for matching AP's expected reception bandwidth
- **Verification**: TX on HT40 ch6 shows BW=40 in descriptor

### A3. Firmware Version
- [ ] Empty string — not extracted from FW blob header
- [ ] Parse at load time (Realtek FW header has version fields)
- [ ] Store in chip_info()
- **Verification**: chip_info reports actual FW version

---

## B. OPERATING MODES

### B1. AP Mode
- [ ] Hardware supports AP (from Linux driver capabilities)
- [ ] Beacon generation and transmission
- [ ] Association handling (open, WPA2-PSK)
- [ ] Client tracking via MACID table
- [ ] Enables: evil twin, karma, rogue AP, MITM, captive portal
- [ ] H2C interface already exists — extend for AP commands

### B2. Managed (STA) Mode
- [ ] Associate to target AP as client
- [ ] WPA2 4-way handshake
- [ ] H2C commands for STA association
- [ ] Enables: client attacks, credential capture, network probing

### B3. Monitor Mode Improvements
- [ ] Verify CRC error frames can be optionally captured
- [ ] Verify ALL frame subtypes pass RX filter
- [ ] PLCP header capture for PHY-layer analysis

---

## C. CHANNELS — FULL UNLOCK

### C1. DFS Channels
- [ ] Channels 52-144 have radar detection flag — currently respected
- [ ] Remove CAC wait / regulatory filtering for pentesting
- [ ] iw shows 24 dBm on DFS channels (52-140), 30 dBm on ch144
- **Verification**: APs on DFS channels visible

### C2. Extended 5GHz
- [ ] Channels 169, 173, 177 currently disabled
- [ ] Channel 144 may need special handling
- [ ] Enable all for maximum coverage
- **Verification**: Full 5GHz channel list in scanner

### C3. Channel 14 (2.4GHz)
- [ ] Disabled by regulatory — enable for pentesting
- [ ] Japan-only channel, rarely used but should be available

---

## D. TX FEATURES — Build on Strong Foundation

### D1. STBC TX
- [ ] Hardware supports TX STBC (from iw phy)
- [ ] Set STBC bit in TX descriptor
- [ ] Better injection reliability at range
- **Verification**: STBC-encoded frames visible in capture

### D2. LDPC TX
- [ ] Hardware supports LDPC
- [ ] Enable in TX descriptor
- [ ] Error correction improvement at range

### D3. Retry Control
- [ ] TX descriptor has retry fields
- [ ] Set 0 retries for deauth (fire-and-forget)
- [ ] Set high retries for EAPOL (must arrive)
- [ ] Expose via TxOptions

### D4. TX Aggregation
- [ ] A-MPDU construction for bulk frame injection
- [ ] Multiple frames per USB transfer (USB3 — high bandwidth)
- [ ] AGG_EN in TX descriptor
- [ ] Dramatically improves deauth flood throughput

### D5. Per-Frame Power Control
- [ ] EFUSE calibration already works — extend to per-frame power in TxOptions
- [ ] Different power for management vs data frames
- [ ] Max power for deauth range, reduced for stealth injection

### D6. Raw Injection
- [ ] Accept any raw 802.11 frame
- [ ] No validation — driver wraps in descriptor and sends
- [ ] All frame types: management, control, data
- [ ] FCS hardware append

---

## E. RX OPTIMIZATION

### E1. RX Sensitivity Control
- [ ] IGI (Initial Gain) currently hardcoded to 0x32
- [ ] Save/restore on BW change exists but no user control
- [ ] Expose `set_rx_sensitivity(level: u8)` — 0-127 range
- [ ] Higher IGI = better weak signal detection but more noise
- **Verification**: Weak APs appear/disappear with IGI changes

### E2. Antenna Control
- [ ] 2x2 TX/RX configured at init, no runtime switching
- [ ] Add `set_tx_antenna(idx)` and `set_rx_antenna(idx)`
- [ ] SISO fallback (single antenna) for testing
- [ ] Per-antenna RSSI reporting
- **Reference**: Linux driver has antenna mux register control

### E3. Beamformee
- [ ] VHT SU Beamformee supported (from iw phy caps)
- [ ] +HTC-VHT capability
- [ ] Enable so APs steer signal toward us — free RX improvement
- **Verification**: RSSI improvement from beamforming-capable APs

---

## F. HARDWARE CRYPTO

### F1. Supported Ciphers (from iw phy)
- [ ] WEP40, WEP104
- [ ] TKIP
- [ ] CCMP-128
- [ ] CMAC (802.11w)
- [ ] Hardware encryption/decryption engine
- [ ] Security CAM for key storage
- [ ] Enable for: encrypted injection, MFP frame crafting
- **Note**: No WPA3 ciphers — WiFi 5 chip limitation

---

## G. H2C COMMAND EXTENSIONS

### G1. H2C Already Working — Extend
- [ ] H2C command interface with sequence tracking already implemented
- [ ] Add AP mode H2C commands
- [ ] Add STA association H2C commands
- [ ] Add rate adaptation H2C commands
- [ ] Add DFS-related H2C commands
- **Advantage**: Foundation already exists, just add command types

---

## H. SCAN MODES

### H1. Active Scanning
- [ ] Probe request injection per channel
- [ ] Hidden SSID discovery

### H2. DFS Scanning
- [ ] Enable DFS channels in scan list
- [ ] Enterprise APs on DFS currently invisible

### H3. 40/80MHz Scanning
- [ ] BW switching already works — use for scanning
- [ ] Wider BW during dwell catches more traffic
- **Verification**: More APs/frames found with 80MHz scan

---

## I. PERFORMANCE TUNING

### I1. USB3 Optimization
- [ ] Device is USB3 SuperSpeed — verify bulk transfer sizes optimal
- [ ] RX aggregation already good (8-frame, 512-byte timeout)
- [ ] TX aggregation could batch more frames per USB transfer
- [ ] Current: 420 APs/311fps/18% noise — room for improvement

### I2. Calibration Tuning
- [ ] IQK/DPK/LCK all implemented — verify running at optimal intervals
- [ ] LCK should run periodically (temperature drift)
- [ ] DPK tables should be refreshed after temperature changes
- **Verification**: Sustained TX power accuracy over long sessions

---

## J. DIAGNOSTICS & REPORTING

### J1. TX Status Feedback
- [ ] Parse TX completion reports from hardware
- [ ] Know if injected frame was ACKed
- [ ] Enables: adaptive attack strategies, injection success rate

### J2. PHY Status Enhancement
- [ ] 40-byte PHY status already parsed for RSSI
- [ ] Add: data rate, bandwidth, LDPC/STBC detection per frame
- [ ] Add: noise floor, SNR from extended PHY status words
- **Verification**: Per-frame PHY info visible in scanner detail view

---

## K. CAPABILITIES THE AGENT MISSED (from iw phy dump — identical to 8812AU)

### K1. TDLS — Native Support
- [ ] `Device supports T-DLS` + `tdls_mgmt` + `tdls_oper`
- [ ] Direct station-to-station tunneled links
- [ ] Enables: TDLS teardown attacks, traffic interception

### K2. Mesh Networking — Full 802.11s
- [ ] `new_mpath`, `set_mesh_config`, `join_mesh`
- [ ] TX/RX on mesh: ALL frame types (0x00-0xF0)
- [ ] Enables: mesh routing attacks, path manipulation

### K3. NAN (Neighbor Awareness Networking)
- [ ] `NAN` in supported TX/RX — ALL subtypes!
- [ ] Wi-Fi Aware discovery without AP
- [ ] UNIQUE: neither 8852AU nor MT7921AU has NAN TX
- [ ] Enables: NAN spoofing, proximity attacks

### K4. MAC Address Tricks
- [ ] `POWERED_ADDR_CHANGE` — MAC change while UP
- [ ] `configuring vdev MAC-addr on create`
- [ ] `randomizing MAC-addr in scans`
- [ ] `SCAN_RANDOM_SN` — random sequence numbers in scans (stealth!)
- [ ] Enables: stealth scanning, identity switching

### K5. TX Status Socket
- [ ] Per-frame delivery confirmation
- [ ] Know which injections were ACKed

### K6. Per-VIF TX Power
- [ ] `per-vif TX power setting`
- [ ] Different power per virtual interface

### K7. SAE (WPA3)
- [ ] `SAE with AUTHENTICATE command`
- [ ] WPA3 dragonfly attacks

### K8. FILS + RRM + Control Port
- [ ] `FILS_STA`, `RRM`, `CONTROL_PORT_OVER_NL80211`
- [ ] `CAN_REPLACE_PTK0` — KRACK research
- [ ] `SET_SCAN_DWELL`, `SCAN_FREQ_KHZ`
- [ ] `DEL_IBSS_STA`, `HT-IBSS`

### K9. NAN + Mesh + AP/VLAN
- [ ] All three: NAN, mesh, AP/VLAN multi-BSSID
- [ ] TX all frame types on all modes

### K10. Probe Client + NoAck Map + QoS Map
- [ ] `probe_client`, `register_beacons`
- [ ] `set_noack_map`, `set_qos_map`
- [ ] `set_multicast_to_unicast`, `set_mcast_rate`
- [ ] `set_sar_specs`

### K11. HT Capability Overrides
- [ ] Full MCS override (ff x 10 bytes)
- [ ] All parameter overrides
- [ ] Available Antennas TX 0x3 RX 0x3

---

## Priority Order

1. **A1** — Rate injection (enables all HT/VHT attacks)
2. **A2** — TX BW field (correct injection on 40/80MHz)
3. **D1+D2+D3** — STBC + LDPC + retry control (reliable injection)
4. **C1+C2+C3** — Full channel unlock (DFS + ch14)
5. **D4+D5+D6** — TX aggregation + power + raw inject
6. **B1** — AP mode (evil twin — H2C foundation already exists)
7. **E1+E2+E3** — RX sensitivity + antenna + beamformee
8. **F1** — Hardware crypto
9. **B2+B3** — Managed mode + monitor improvements
10. **H1+H2+H3** — Scan modes
11. **G1** — H2C extensions
12. **I1+I2** — Performance tuning
13. **J1+J2** — Diagnostics

---

*Created: 2026-03-31, Session 6*
*Last updated: 2026-03-31*
