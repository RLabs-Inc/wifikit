# RTL8812AU Driver Roadmap — Complete Implementation Guide

**Chip**: Realtek RTL8812A (WiFi 5 802.11ac)
**Adapters**: Alfa AWUS036ACH, various (VID=0x0BDA PID=0x8812)
**Architecture**: MAC gen1, host-driven BB/RF, 2x2 MIMO, USB 2.0
**Reference data**: `references/captures/rtl8812au_efuse/` (iw_info, EFUSE)
**Reference driver**: Linux rtl8812au out-of-tree
**Current driver**: `src/chips/rtl8812au.rs` (~1600 lines)
**Status**: Monitor + inject working (409 APs confirmed), RSSI from PHY status, all channels

---

## A. FOUNDATION — What's Broken or Missing

### A1. TX Power Control
- [ ] `set_tx_power()` returns Ok(()) without any action — complete no-op
- [ ] Need to read EFUSE TX power calibration tables (bytes 0x10-0x24 path A, 0x3A-0x50 path B)
- [ ] Implement per-channel TXAGC register writes (0x1908-0x191F patterns for CCK/OFDM/HT/VHT)
- [ ] Per-channel max power from iw: 30 dBm @ 2.4G, 23-24 dBm @ 5G
- [ ] Currently hardcoded to 20 dBm report — leaving 10 dBm on table
- **Verification**: TX power measurably different at different settings

### A2. Calibration Engine (IQK/DPK/LCK)
- [ ] `calibrate()` is a complete no-op — no IQK, no DPK, no LCK
- [ ] RTL8812BU has FULL implementation — port directly with register address verification
- [ ] IQK: Load IQK_RF_PREP tables (path A/B), IQK_SETUP, upload IQK_MICROCODE to 0x1B80
- [ ] DPK: Load DPK_INIT + DPK_ACTIVATE tables (64-register PA linearization LUT)
- [ ] LCK: Poll RF0x18 bit 15 after writing LC calibration command
- [ ] Run at init after firmware load AND at every channel switch
- **Verification**: IQK converges after 3 runs with stable values

### A3. EFUSE Reading
- [ ] Not implemented at all — EFUSE struct exists but unused
- [ ] Read RFE type (EFUSE 0xCA-0xCB) — affects antenna switch config, table selection
- [ ] Read per-channel TX power limits per path/rate
- [ ] Read antenna configuration
- [ ] Store calibration data for TX power and RSSI accuracy
- **Verification**: RFE type reported correctly in chip_info()

### A4. RSSI Accuracy
- [ ] PHY status parsing exists but offset may be wrong
- [ ] Need to verify byte offset in PHY status matches actual RSSI
- [ ] Compare with RTL8812BU implementation (known good)
- [ ] RTL8812BU reads `buf[RX_DESC_SIZE + 1]` and subtracts 110
- **Verification**: RSSI values match RTL8812BU for same APs at same distance

### A5. Firmware Version
- [ ] Currently returns empty string
- [ ] Extract from FW blob header during firmware load
- [ ] Store and report in chip_info()

### A6. RX Aggregation
- [ ] Init code does NOT enable RX DMA aggregation (differs from 8812BU)
- [ ] Enable for better throughput
- [ ] Implement multi-frame parsing loop for aggregated USB transfers
- **Verification**: FPS improves after enabling AGG

---

## B. BANDWIDTH — Currently 20MHz Only

### B1. HT40 Mode (2.4GHz + 5GHz)
- [ ] Implement `set_bb_bandwidth()`: Register 0x08AC with CHANNEL_WIDTH fields
- [ ] RX DFIR filter selection per bandwidth (0x0948, 0x094C, 0x0C20, 0x0E20)
- [ ] IGI toggle + save/restore for RX sensitivity on BW change
- [ ] HT40 allow map shows which channels support +/- offset
- [ ] Reference: RTL8812BU has full implementation (lines ~1254-1335)
- **Verification**: Capture HT40 frames from APs using 40MHz

### B2. VHT80 Mode (5GHz)
- [ ] Set center channel for 80MHz groups
- [ ] BB/RF bandwidth registers for 80MHz
- [ ] Per-path RF BW setting
- **Verification**: Capture VHT80 frames from modern APs

---

## C. RATE CONTROL

### C1. HT/VHT Rate Injection
- [ ] `tx_rate_to_hw()` falls back ALL HT/VHT rates to OFDM 6M (0x04)
- [ ] Implement real mapping: HT MCS 0-15, VHT MCS 0-9 NSS 1-2
- [ ] Per-rate power staircase (PA back-off for higher modulation)
- [ ] Reference: RTL8812BU line 640 shows staircase pattern
- **Verification**: Inject at HT MCS15 and VHT MCS9, verify in capture

### C2. TX Descriptor Enhancement
- [ ] TX descriptor is 40 bytes (10 DWORDs) — many fields unused
- [ ] Rate selection field (USERATE_SEL + DATARATE)
- [ ] BW field for 40/80 MHz injection
- [ ] STBC/LDPC flags
- [ ] Retry count control
- [ ] AGG_EN for TX aggregation
- **Verification**: All TX descriptor fields produce correct over-the-air frames

---

## D. OPERATING MODES

### D1. AP Mode
- [ ] RTL8812A supports AP mode in Linux
- [ ] Beacon generation and transmission
- [ ] Association handling
- [ ] Enables: evil twin, karma, rogue AP
- **Reference**: Linux rtl8812au driver supports AP interface

### D2. Managed (STA) Mode
- [ ] Associate to target AP
- [ ] WPA2 4-way handshake as client
- [ ] Enables: client attacks, credential capture

### D3. Monitor Mode Improvements
- [ ] Verify RX filter accepts ALL frame types
- [ ] CRC error frames optional
- [ ] Control frame capture verification

---

## E. MIMO & ANTENNA

### E1. Antenna Configuration
- [ ] 2x2 MIMO — verify both paths active for TX and RX
- [ ] Antenna selection control
- [ ] Per-path RSSI reporting
- [ ] RFE type determines antenna switch configuration

### E2. STBC/LDPC
- [ ] Enable RX LDPC (hardware supports it per iw phy)
- [ ] RX STBC 1-stream (2.4GHz band supports it)
- [ ] TX STBC for better injection reliability
- **Verification**: Can decode LDPC and STBC frames

---

## F. CHANNELS — FULL UNLOCK

### F1. All Channels
- [ ] 2.4 GHz: 1-14 (include ch14, no regulatory filtering)
- [ ] 5 GHz: 36-165 (include DFS 52-144, no CAC wait)
- [ ] Remove disabled channel filtering
- **Verification**: All channels in scanner list

---

## G. TX FEATURES

### G1. Per-Frame Power Control
- [ ] EFUSE-calibrated power per channel/rate
- [ ] TxOptions power level override
- [ ] Max power: 30 dBm on 2.4G

### G2. Retry Control
- [ ] TX retry limit per frame
- [ ] Disable for fire-and-forget (deauth)
- [ ] Enable with high count for EAPOL

### G3. TX Aggregation
- [ ] A-MPDU construction for bulk injection
- [ ] Multiple frames per USB transfer
- [ ] Dramatically improves injection throughput

### G4. Raw Injection
- [ ] Accept any raw 802.11 frame — no validation in driver
- [ ] FCS handling (hardware append)
- [ ] All frame types: management, control, data

---

## H. HARDWARE CRYPTO

### H1. Supported Ciphers (from iw phy)
- [ ] WEP40, WEP104
- [ ] TKIP
- [ ] CCMP-128
- [ ] CMAC (802.11w)
- [ ] Hardware encryption engine for TX
- [ ] Security CAM for key storage
- **Note**: No WPA3 ciphers (GCMP/CCMP-256) — this is a WiFi 5 chip

---

## I. SCAN MODES

### I1. Active Scanning
- [ ] Probe request injection per channel
- [ ] Hidden SSID discovery via directed probes

### I2. DFS Scanning
- [ ] Enable DFS channels without CAC wait
- [ ] Enterprise APs hide on DFS — invisible to us now

### I3. 40/80MHz Scanning
- [ ] Wider BW captures more traffic
- [ ] Currently missing all non-20MHz frames

---

## J. DIAGNOSTICS

### J1. TX Status Feedback
- [ ] Parse TX completion reports
- [ ] Know if injected frame was acknowledged
- [ ] Enables: adaptive attack strategies

---

## K. CAPABILITIES THE AGENT MISSED (from iw phy dump)

### K1. TDLS — Native Support
- [ ] `Device supports T-DLS` + `tdls_mgmt` + `tdls_oper` commands
- [ ] Direct station-to-station tunneled links
- [ ] Enables: TDLS teardown attacks, traffic interception between clients

### K2. Mesh Networking — Full 802.11s
- [ ] `new_mpath`, `set_mesh_config`, `join_mesh` commands
- [ ] Full mesh path management
- [ ] TX/RX on mesh point: ALL frame types (0x00-0xF0)
- [ ] Enables: mesh routing attacks, path manipulation

### K3. NAN (Neighbor Awareness Networking)
- [ ] `NAN` in supported TX/RX frame types — ALL subtypes!
- [ ] Wi-Fi Aware — device discovery without AP
- [ ] Enables: NAN attacks, service discovery spoofing, proximity detection
- [ ] NEITHER the 8852AU NOR MT7921AU lists NAN TX support!

### K4. MAC Address Tricks
- [ ] `POWERED_ADDR_CHANGE` — change MAC while interface is UP
- [ ] `configuring vdev MAC-addr on create` — set MAC at interface creation
- [ ] `randomizing MAC-addr in scans` — random MAC per scan
- [ ] `SCAN_RANDOM_SN` — random sequence numbers in scans (stealth scanning!)
- [ ] Enables: seamless identity switching, stealth reconnaissance

### K5. TX Status Socket
- [ ] `Device supports TX status socket option`
- [ ] Per-frame delivery confirmation
- [ ] Know which injections were ACKed
- [ ] Critical for: reliable attack feedback

### K6. Per-VIF TX Power
- [ ] `Device supports per-vif TX power setting`
- [ ] Different TX power per virtual interface
- [ ] Enables: scanner at low power + attack at max power simultaneously

### K7. SAE (WPA3)
- [ ] `Device supports SAE with AUTHENTICATE command`
- [ ] WPA3 dragonfly handshake
- [ ] Enables: WPA3 dictionary attacks, dragonblood

### K8. FILS (Fast Initial Link Setup)
- [ ] `FILS_STA` — fast reassociation
- [ ] Enables: FILS attack research

### K9. RRM (Radio Resource Management)
- [ ] `RRM` — 802.11k radio measurements
- [ ] Enables: environment mapping, AP discovery

### K10. Scan Capabilities
- [ ] `SET_SCAN_DWELL` — configurable per-channel dwell
- [ ] `SCAN_FREQ_KHZ` — kHz precision scanning
- [ ] `scan flush` — abort and restart
- [ ] Enables: fine-grained scan control

### K11. Control Port
- [ ] `CONTROL_PORT_OVER_NL80211` + TX status
- [ ] `CONTROL_PORT_NO_PREAUTH`
- [ ] Precise EAPOL injection with delivery confirmation
- [ ] Enables: reliable 4-way handshake attacks

### K12. PTK0 Replace
- [ ] `CAN_REPLACE_PTK0` — safe key replacement during rekey
- [ ] Enables: KRACK-related research

### K13. IBSS Capabilities
- [ ] `HT-IBSS` — HT rates in ad-hoc mode
- [ ] `DEL_IBSS_STA` — remove IBSS station
- [ ] Enables: high-speed ad-hoc networks, IBSS manipulation

### K14. HT Capability Overrides
- [ ] Full MCS mask (ff x 10 bytes)
- [ ] A-MSDU length, channel width, SGI, A-MPDU, spacing overrides
- [ ] Enables: capability spoofing, forced negotiation

### K15. Probe Client
- [ ] `probe_client` — verify client presence
- [ ] `register_beacons` — receive beacon frames
- [ ] `set_noack_map` — per-TID ACK control
- [ ] `set_qos_map` — QoS manipulation
- [ ] `set_multicast_to_unicast`
- [ ] `set_mcast_rate`
- [ ] `set_sar_specs` — fine-grained power control

### K16. Available Antennas
- [ ] TX 0x3 RX 0x3 — both antennas properly configured!
- [ ] (The 8852AU reports TX 0 RX 0 — broken antenna reporting)

### K17. AP/VLAN
- [ ] AP/VLAN mode — multi-BSSID support
- [ ] Multiple SSIDs on single radio
- [ ] Enables: multi-target rogue AP

---

## Priority Order

1. **A1+A2+A3** — TX power + calibration + EFUSE (max range + accuracy)
2. **A4** — RSSI accuracy verification
3. **B1+B2** — Bandwidth (captures real traffic)
4. **C1+C2** — Rate injection (all attacks work)
5. **G1+G2+G4** — TX features (reliable injection)
6. **D1** — AP mode (evil twin)
7. **E1+E2** — MIMO/antenna
8. **F1** — Channel unlock
9. **H1** — Hardware crypto
10. **D2+D3** — Managed/monitor improvements

---

*Created: 2026-03-31, Session 6*
*Last updated: 2026-03-31*
