# MT7921AU Driver Roadmap — Complete Implementation Guide

**Chip**: MediaTek MT7921AU (WiFi 6E 802.11ax)
**Adapters**: Fenvi FU-AX1800P (USB3), Comfast CF-952AX
**Architecture**: MCU command-driven, CONNAC2, 2x2 MIMO, tri-band (2.4/5/6 GHz)
**Reference data**: `references/mt7921au-fenvi-usb3/` (phy_info, txpower_sku, dmesg, debugfs, usbmon)
**Current driver**: `src/chips/mt7921au.rs` (~3400 lines)
**Status**: Monitor mode working, 6GHz broken, TX working, no bandwidth control, hardcoded eFuse

---

## A. FOUNDATION — Fix What's Broken

### A1. 6GHz Channel Switching
- [ ] Parse mt7921au-fenvi-usb3/usbmon pcap for 6GHz channel switch MCU commands
- [ ] Compare MCU commands Linux sends for 6GHz vs what we send
- [ ] Check if additional firmware init needed for 6GHz radio path (band_idx=2)
- [ ] Fix ch_band in sniffer config: must be band_idx + 1 (1/2/3 for 2.4/5/6GHz)
- [ ] Verify 6GHz channel domain command sends all 59 channels correctly
- [ ] Test on all 6GHz channels (1, 5, 9, ... 233)
- **Verification**: Bench --bands 6g shows frames on 6GHz channels

### A2. MAC Address Setting
- [ ] `set_mac()` currently only stores in driver struct — doesn't write to hardware
- [ ] Implement via MCU command to actually change MAC on-air
- [ ] Verify with 2nd adapter that spoofed MAC appears in frames
- **Verification**: Set custom MAC, capture frames from 2nd adapter, verify

### A3. Per-Antenna RSSI
- [ ] Currently takes max of all RCPI streams — discard per-path data
- [ ] Track all 4 RCPI values separately in RxFrame
- [ ] Add SNR calculation if C-RXV contains noise floor reference
- [ ] Filter RCPI: 0 and 255 are invalid (already done), verify edge cases
- **Verification**: Both paths show different RSSI values for non-LOS signals

### A4. mac_init() Firmware Assert
- [ ] Line 2293: `mac_init()` causes firmware assert — currently disabled
- [ ] Investigate: capture Linux usbmon to see if/how Linux calls MAC init
- [ ] May not be needed for monitor mode, but required for AP/managed mode
- [ ] Document root cause or fix
- **Verification**: mac_init() completes without firmware assert

---

## B. BANDWIDTH — Currently Locked to 20MHz

### B1. 40MHz Mode
- [ ] Add bandwidth parameter to `set_channel()` and Channel struct
- [ ] Map BW enum to MCU bw field: 0=20, 1=40, 2=80, 3=160
- [ ] Update `mcu_config_sniffer_channel()` payload[11] from hardcoded 0
- [ ] Set center_ch correctly for HT40 (primary +/- 10 MHz)
- [ ] Update TX TXWI FIXED_BW field for 40MHz injection
- [ ] HT40 allow map from debugfs shows which channels support +/-
- **Verification**: Park on ch36 40MHz, capture shows HT40 frames

### B2. 80MHz Mode
- [ ] Set center_ch for VHT80 groups (42, 58, 106, 122, 138, 155)
- [ ] Update sniffer config with bw=2
- [ ] Update TX for 80MHz rate injection
- **Verification**: Park on ch36 80MHz (center 42), capture VHT80 frames

### B3. 160MHz Mode
- [ ] Set center_ch and center_ch2 for 160MHz
- [ ] Update sniffer config with bw=3
- [ ] Handle HE160/VHT160 on 5GHz
- **Verification**: Capture 160MHz HE frames

---

## C. TX POWER — Currently Hardcoded from Single Device

### C1. Dynamic eFuse Reading
- [ ] Read actual eFuse calibration data from device (not hardcoded Fenvi values)
- [ ] `MCU_EXT_CMD_EFUSE_BUFFER_MODE` currently sets mode but doesn't READ
- [ ] Parse eFuse for: PA calibration, temperature compensation, per-channel limits
- [ ] Create device variant detection (Fenvi vs Comfast vs others)
- **Verification**: eFuse values match device-specific calibration

### C2. Respect set_tx_power() Parameter
- [ ] Currently ignores the dBm argument — always sends max
- [ ] Clamp all per-rate values to requested max dBm
- [ ] Allow per-rate power override for advanced testing
- **Verification**: Set 10 dBm, measure actual TX power is reduced

### C3. Temperature Compensation
- [ ] Poll firmware for thermal sensor data
- [ ] Adjust TX power based on temperature (firmware may do this internally)
- [ ] Log temperature alongside TX power in diagnostics
- **Verification**: Monitor TX power after sustained operation

### C4. Per-Rate TX Power Control
- [ ] Expose individual rate power limits via API
- [ ] Allow setting different power for management vs data frames
- [ ] Useful for: strong deauth (max power) + subtle data injection (low power)
- **Verification**: Inject at MCS0 max power and MCS11 reduced power

---

## D. RATE CONTROL & INJECTION

### D1. Guard Interval Selection
- [ ] Currently hardcoded 0.8us via FIXED_BW
- [ ] Add GI parameter: 0.8us (HE normal), 1.6us (HT), 3.2us (HE extended)
- [ ] Set in TXWI per-frame
- **Verification**: Inject with different GI, verify in capture

### D2. NSS (Spatial Streams) Control
- [ ] Add NSS parameter to TxOptions (1x1 vs 2x2)
- [ ] Rate encoding: MODE[9:6] | NSS[12:10] | IDX[5:0]
- [ ] Test 1SS and 2SS injection separately
- **Verification**: Inject at 2SS MCS9, verify rate in capture

### D3. Enable Block ACK
- [ ] Currently BA_DISABLE=1 in TXWI DW3 — no ACK feedback
- [ ] Enable BA for TX status reporting
- [ ] Implement rate adaptation based on ACK/BA success ratio
- [ ] Critical for: reliable EAPOL injection, WPS exchanges
- **Verification**: TX status reports received for injected frames

### D4. STBC TX
- [ ] Implement STBC control flags in TXWI
- [ ] Use for diversity on 2x2 paths
- [ ] Better reliability at range for attack frames
- **Verification**: STBC-encoded frames visible in capture

### D5. All Rate Modes
- [ ] Test injection on every rate mode:
  - CCK: 1, 2, 5.5, 11 Mbps (2.4G only)
  - OFDM: 6-54 Mbps
  - HT: MCS 0-15 (2SS), MCS 32 (40MHz duplicate)
  - VHT: MCS 0-9, NSS 1-2 (20/40/80)
  - HE: MCS 0-11, NSS 1-2 (20/40/80/160)
- **Verification**: Each rate injects successfully and is decoded by receiver

---

## E. OPERATING MODES

### E1. AP Mode
- [ ] Create rogue access point with custom SSID/BSSID
- [ ] Beacon generation and transmission
- [ ] Association handling (open, WPA2-PSK, WPA3-SAE)
- [ ] Client tracking via MACID table
- [ ] Multi-BSSID (AP/VLAN support — hardware supports it)
- [ ] Enables: evil twin, karma, rogue AP, MITM, captive portal
- **Reference**: phy_info shows AP, AP/VLAN in supported modes

### E2. Managed (STA) Mode
- [ ] Associate to target AP as client
- [ ] WPA2 4-way handshake
- [ ] WPA3 SAE (check if firmware supports offload)
- [ ] EAP/802.1X client
- [ ] Enables: client-side attacks, credential capture, network probing

### E3. P2P Modes
- [ ] P2P client and GO modes
- [ ] P2P device mode (discovery)
- [ ] P2P service discovery
- [ ] Enables: P2P relay attacks, Wi-Fi Direct exploitation

### E4. ACK in Monitor Mode
- [ ] Configure firmware to send ACKs for received frames
- [ ] Enables: active attacks from monitor mode (associate without mode switch)
- [ ] Critical for: EAP attacks, WPS exchanges, any bidirectional protocol

---

## F. MIMO & ANTENNA

### F1. Antenna Configuration
- [ ] Currently no antenna selection — both paths active by default
- [ ] Add antenna mask parameter (both, TX1 only, TX2 only)
- [ ] Per-antenna RX power reporting (all 4 RCPI values)
- [ ] MIMO mode selection: SISO (1x1) vs MIMO (2x2)
- **Verification**: Switching antenna mask affects RSSI pattern

### F2. Beamforming
- [ ] Hardware supports SU Beamformee on 2.4/5/6 GHz
- [ ] MU Beamformee on 5/6 GHz
- [ ] 3 BFee STS capability
- [ ] Enable beamformee so APs steer signal toward us
- **Verification**: RSSI improvement from beamforming-capable APs

---

## G. SCAN MODES

### G1. Active Scanning
- [ ] Implement probe request injection per channel
- [ ] Custom SSID in probe requests (directed probes)
- [ ] Wildcard SSID for broadcast probes
- [ ] Enables: faster AP discovery, hidden SSID revelation

### G2. Scheduled Scan
- [ ] phy_info shows sched_scan support
- [ ] Background scanning via MCU command
- [ ] Long-running passive recon while main activity continues

### G3. DFS Channel Scanning
- [ ] Channels 52-144 have radar detection flag
- [ ] No CAC wait needed for monitor mode (hacking tool, not compliance)
- [ ] Enable all DFS channels without regulatory filtering
- [ ] Process DFS radar events (for awareness, not compliance)
- **Verification**: APs on DFS channels visible in scan

### G4. 40/80/160 MHz Scanning
- [ ] Scan with wider bandwidth captures more traffic
- [ ] 80MHz scan on 5GHz catches all VHT/HE traffic
- [ ] Currently missing all traffic on non-20MHz channels
- **Verification**: Frame count increases with wider BW scan

---

## H. AGGREGATION & PERFORMANCE

### H1. TX Aggregation
- [ ] Currently single-frame TX — no A-MPDU construction
- [ ] Implement multi-frame TX for bulk injection (deauth flood, beacon storm)
- [ ] A-MPDU with proper BA sequence numbering
- **Verification**: Sustained injection rate improves with TX aggregation

### H2. RX Aggregation Tuning
- [ ] Currently AGG_TO=255us, AGG_LMT=64
- [ ] Tune for latency vs throughput per use case
- [ ] Monitor mode: maximize throughput (high AGG_LMT)
- [ ] Attack mode: minimize latency (low AGG_TO)
- **Verification**: Measure FPS at different AGG settings

### H3. USB3 SuperSpeed Optimization
- [ ] Fenvi adapter is USB3 — 5 Gbps link
- [ ] Verify USB transfer sizes are optimal for SuperSpeed
- [ ] Bulk IN buffer sizing for aggregated RX
- [ ] Compare USB2 vs USB3 performance (some ports may fall back)

---

## I. HARDWARE CRYPTO

### I1. Supported Ciphers (from phy_info)
- [ ] WEP40, WEP104 (legacy)
- [ ] TKIP (WPA1)
- [ ] CCMP-128 (WPA2)
- [ ] CCMP-256 (WPA3)
- [ ] GCMP-128 (WPA3)
- [ ] GCMP-256 (WPA3 Enterprise 192-bit)
- [ ] CMAC, CMAC-256 (802.11w MFP)
- [ ] GMAC-128, GMAC-256 (802.11w BIP)
- [ ] BIP-GMAC-128, BIP-GMAC-256

### I2. Hardware Encryption Engine
- [ ] Implement security CAM configuration for key storage
- [ ] Enable hardware encryption in TXWI for encrypted injection
- [ ] Support MFP (Management Frame Protection) for 802.11w attacks
- [ ] Enables: encrypted frame injection, WPA3 attack frames

---

## J. CALIBRATION & DIAGNOSTICS

### J1. eFuse Calibration Reading
- [ ] Read full eFuse map after firmware boot
- [ ] Parse: PA calibration, RSSI offsets, temperature cal, antenna gain
- [ ] Store per-device calibration for accurate TX power and RSSI
- **Reference**: txpower_sku.txt has captured eeprom column values

### J2. Firmware Diagnostics
- [ ] Parse C2H (chip-to-host) firmware events
- [ ] Temperature monitoring
- [ ] TX/RX statistics from firmware
- [ ] Error counters and status

### J3. Error Recovery
- [ ] Currently retries USB requests up to 10x with 5ms delay
- [ ] Implement exponential backoff
- [ ] MCU command timeout recovery
- [ ] USB re-enumeration recovery without replug

---

## K. DFS & RADAR

### K1. DFS Channel Access
- [ ] Enable channels 52-144 without CAC wait
- [ ] No regulatory compliance needed — penetration testing tool
- [ ] Many enterprise APs hide on DFS to avoid congestion
- **Verification**: APs on ch52-144 visible

### K2. Radar Event Processing
- [ ] Firmware sends RDD (Radar Detection) events
- [ ] Log radar events for awareness (don't act on them)
- [ ] Useful for understanding DFS environment

---

## L. CHANNEL LIST — FULL UNLOCK

### L1. All Channels Enabled
- [ ] 2.4 GHz: 1-14 (include ch14 — no regulatory filtering)
- [ ] 5 GHz: 36-177 (include DFS 52-144, include disabled 169/173/177)
- [ ] 6 GHz: All 59 channels (1-233 step 4)
- [ ] Remove all regulatory disabling
- **Verification**: Full channel list available in scanner

---

## M. DEAD CODE & CLEANUP

### M1. Simplified Implementations to Fix
- [ ] Deep sleep sends ASCII "KeepFullPwr" — unconventional, verify it works
- [ ] Sniffer channel config tries with wait, falls back to fire-and-forget — fix reliability
- [ ] Client MAC tracking not implemented in RX parser
- [ ] Firmware paths hardcoded — make configurable

### M2. Diagnostic Code
- [ ] Remove temporary debug logging
- [ ] Ensure no eprintln! in hot paths
- [ ] Clean up unused variables

---

## N. MT7921AU-EXCLUSIVE CAPABILITIES (not on RTL8852AU)

### N1. TDLS (Tunneled Direct Link Setup) — Hardware T-DLS Support
- [ ] `Device supports T-DLS` — explicit in iw phy
- [ ] `tdls_mgmt` and `tdls_oper` in supported commands
- [ ] Direct station-to-station tunneled links
- [ ] Enables: TDLS teardown attacks, traffic interception between clients
- [ ] 8852AU does NOT have native TDLS support

### N2. Mesh Networking — Full 802.11s
- [ ] `new_mpath`, `set_mesh_config`, `join_mesh` in supported commands
- [ ] Full mesh path table management (HWMP)
- [ ] Mesh peer link management
- [ ] Enables: mesh network attacks, path manipulation, routing poisoning
- [ ] 8852AU has vendor driver mesh but not exposed in iw

### N3. Multi-Interface Combinations
- [ ] Up to 3 simultaneous interfaces (managed + P2P + AP)
- [ ] 2 channels simultaneously in P2P mode
- [ ] `#{ managed, P2P-client } <= 2, #{ AP } <= 1, #{ P2P-device } <= 1`
- [ ] Enables: scanner on one interface + rogue AP on another — SIMULTANEOUSLY
- [ ] 8852AU: "interface combinations are not supported"

### N4. TX Bitrate Mask Control
- [ ] `set_tx_bitrate_mask` — fine-grained rate filtering
- [ ] Can restrict TX to specific rate sets
- [ ] Enables: rate manipulation attacks, forcing downgrades

### N5. Probe Client
- [ ] `probe_client` — actively probe connected clients
- [ ] Enables: client presence detection, association state verification

### N6. Register Beacons
- [ ] `register_beacons` — receive beacon frames from firmware
- [ ] Useful for AP impersonation, beacon analysis

### N7. Set NoAck Map
- [ ] `set_noack_map` — per-TID NoAck configuration
- [ ] Control which traffic gets acknowledged
- [ ] Enables: selective ACK suppression attacks

### N8. Channel Switch (In-Band)
- [ ] `channel_switch` — CSA (Channel Switch Announcement) support
- [ ] Enables: forced channel migration attacks, CSA spoofing

### N9. Set QoS Map
- [ ] `set_qos_map` — QoS priority remapping
- [ ] Enables: traffic priority manipulation

### N10. Set Multicast-to-Unicast
- [ ] `set_multicast_to_unicast` — convert multicast to unicast delivery
- [ ] Useful in AP mode for reliable multicast delivery

### N11. SAR Specs
- [ ] `set_sar_specs` — Specific Absorption Rate limits
- [ ] Control TX power at granular level for regulatory/testing

### N12. POWERED_ADDR_CHANGE
- [ ] `can change MAC address while up` — MAC spoofing without interface down!
- [ ] 8852AU requires restart to change MAC
- [ ] Critical advantage for active attacks where MAC changes frequently

### N13. FILS (Fast Initial Link Setup)
- [ ] `FILS_STA` — Fast association for reconnecting clients
- [ ] Enables: FILS attack research, fast reassociation exploitation

### N14. RRM (Radio Resource Management)
- [ ] `RRM` — 802.11k radio measurements
- [ ] Channel load, noise, beacon, link measurements
- [ ] Enables: environment mapping, AP capability discovery

### N15. Airtime Fairness / AQL
- [ ] `AIRTIME_FAIRNESS` + `AQL` (Airtime Queue Limits)
- [ ] Fine-grained TX scheduling
- [ ] Enables: airtime manipulation, DoS via queue starvation

### N16. CQM RSSI Monitoring
- [ ] `CQM_RSSI_LIST` — multiple RSSI threshold triggers
- [ ] Continuous RSSI monitoring with threshold alerts
- [ ] Enables: automatic signal quality tracking, proximity detection

### N17. ACK Signal Level
- [ ] `ACK_SIGNAL_SUPPORT` — get signal level of ACK frames
- [ ] Tells you how well the TARGET hears YOUR signal
- [ ] Critical for: TX power optimization, range estimation for attacks

### N18. Scan Dwell Setting
- [ ] `SET_SCAN_DWELL` — configurable per-channel scan time
- [ ] Fine-tune scanning speed vs thoroughness

### N19. Scan Frequency in kHz
- [ ] `SCAN_FREQ_KHZ` — sub-MHz frequency precision
- [ ] Useful for 6GHz channels with different channel widths

### N20. Beacon Rate Control (All Modes)
- [ ] `BEACON_RATE_LEGACY`, `BEACON_RATE_HT`, `BEACON_RATE_VHT`, `BEACON_RATE_HE`
- [ ] Control beacon transmission rate in AP mode
- [ ] Enables: beacons at any rate — HE beacons for WiFi 6 AP impersonation

### N21. WoWLAN (Wake on Wireless LAN)
- [ ] Wake on disconnect, magic packet, pattern match (up to 128 bytes)
- [ ] GTK rekeying in sleep
- [ ] Network detection wake (10 match sets)
- [ ] Enables: persistent monitoring, wake-on-target-detection

### N22. HT Capability Overrides
- [ ] MCS mask override (ff ff ff ff ff ff ff ff ff ff — all MCS)
- [ ] A-MSDU length override
- [ ] Channel width override
- [ ] SGI override
- [ ] A-MPDU exponent override
- [ ] Enables: capability spoofing, forced negotiation parameters

### N23. HT-IBSS
- [ ] `Device supports HT-IBSS` — HT rates in ad-hoc mode
- [ ] High-speed ad-hoc networking
- [ ] Enables: fast ad-hoc data exfiltration

### N24. TX Status Socket
- [ ] `Device supports TX status socket option`
- [ ] Get per-frame TX delivery status
- [ ] Know EXACTLY which injected frames were delivered and ACKed
- [ ] Critical for: reliable injection feedback, attack verification

### N25. OFDMA (WiFi 6 Multi-User)
- [ ] `Full Bandwidth UL MU-MIMO` — uplink multi-user MIMO
- [ ] `Partial Bandwidth UL MU-MIMO` — partial BW uplink MU-MIMO
- [ ] `242 tone RUs` — full OFDMA resource unit allocation
- [ ] Enables: OFDMA sniffing, trigger frame analysis, UL MU capture

### N26. DCM (Dual Carrier Modulation)
- [ ] `DCM Max Constellation: 2` — TX DCM
- [ ] `DCM Max Constellation Rx: 2` — RX DCM
- [ ] HE reliability feature — redundant modulation for range
- [ ] Enables: extended range injection with DCM

### N27. BSS Color / OBSS
- [ ] `Non-Triggered CQI Feedback` — BSS color support in HE
- [ ] BSS color attacks (color confusion, OBSS interference)

### N28. 6GHz Specific HE Capabilities
- [ ] Band 4: Full HE80, LDPC, STBC, beamformee, 1024-QAM
- [ ] 59 channels from 5955-6415 MHz
- [ ] AP mode on 6GHz (HE-only band — no legacy devices)
- [ ] Unique attack surface: WPA3-only networks, new security models
- [ ] 8852AU has NO 6GHz support at all

### N29. Control Port over NL80211
- [ ] `CONTROL_PORT_OVER_NL80211` + TX status
- [ ] EAPOL frame handling via control path
- [ ] `CONTROL_PORT_NO_PREAUTH` — pre-auth control
- [ ] Enables: precise EAPOL injection with delivery confirmation

### N30. PTK0 Safe Replace
- [ ] `CAN_REPLACE_PTK0` — safe pairwise key replacement during rekeying
- [ ] Enables: key reinstallation attack research (KRACK-related)

---

## O. COMPARISON: MT7921AU vs RTL8852AU

| Capability | MT7921AU | RTL8852AU | Winner |
|-----------|----------|-----------|--------|
| **Bands** | 2.4 + 5 + 6 GHz | 2.4 + 5 GHz | MT7921AU |
| **6GHz channels** | 59 channels | None | MT7921AU |
| **Multi-interface** | 3 simultaneous, 2 channels | None | MT7921AU |
| **TDLS** | Native | No | MT7921AU |
| **Mesh** | Full 802.11s | Vendor-only | MT7921AU |
| **MAC change while up** | Yes | No | MT7921AU |
| **TX status feedback** | Socket option | Via TX reports | MT7921AU |
| **ACK signal level** | Yes | No | MT7921AU |
| **Scan dwell control** | Yes | No | MT7921AU |
| **Beacon rate control** | All modes (HE) | No | MT7921AU |
| **OFDMA** | Full UL MU-MIMO | Partial | MT7921AU |
| **WoWLAN** | Full (patterns, GTK) | Basic | MT7921AU |
| **Fake AP code** | No | Yes (vendor driver) | RTL8852AU |
| **FT (802.11r)** | No (in driver) | Yes (vendor driver) | RTL8852AU |
| **MBO** | No (in driver) | Yes (vendor driver) | RTL8852AU |
| **USB speed** | USB 3.0 | USB 3.0 | Tie |
| **Open source driver** | mt76 (kernel) | Out-of-tree | MT7921AU |

The MT7921AU is the more capable device for pentesting. The 6GHz band alone opens an entire new attack surface. Multi-interface support means scanner + rogue AP simultaneously. MAC change while up means seamless identity switching during active attacks.

---

## Priority Order

1. **A1** — 6GHz channel switching (hardware differentiator)
2. **B1+B2** — 40/80 MHz bandwidth (captures real-world traffic)
3. **C1+C2** — Dynamic eFuse + TX power control (max range)
4. **D1+D2+D3** — Rate control, GI, BA enable (reliable injection)
5. **E4** — ACK in monitor (enables all bidirectional attacks)
6. **E1** — AP mode (evil twin)
7. **A2** — MAC address setting (operational necessity)
8. **G3+L1** — DFS + full channel unlock
9. **I1+I2** — Hardware crypto (WPA3 attacks)
10. **F1+F2** — MIMO/antenna/beamforming
11. **E2** — Managed mode
12. **H1+H2+H3** — Aggregation tuning
13. **G1+G2+G4** — Scan modes
14. **D4+D5** — STBC, all rate modes
15. **J+K+M** — Diagnostics, radar, cleanup

---

*Created: 2026-03-31, Session 6*
*Last updated: 2026-03-31*
