# RTL8852AU Driver Roadmap — Complete Implementation Guide

**Chip**: RTL8852AU / RTL8832AU (WiFi 6 802.11ax)
**Adapter**: TP-Link Archer TX20U Plus (VID=0x2357 PID=0x013F)
**Architecture**: MAC AX gen2, firmware-centric, 2x2 MIMO
**Reference driver**: `references/rtl8852au/` (Realtek vendor driver v1.15.0)
**USB3 captures**: `references/rtl8852au_usb3_20260330_125324/`
**Current driver**: `src/chips/rtl8852au.rs` (2299 lines)
**Status**: Boots FW, receives frames, channel switching (7 of 39 channels), no RSSI, basic inject

---

## A. FOUNDATION — Fix What's Broken

### A1. RSSI via PPDU Status Correlation
- [ ] Parse rpkt_type=1 (PPDU status) packets — extract physts_hdr_info from payload
- [ ] Store RSSI per ppdu_cnt slot (3-bit counter, 8 slots) — `[i8; 8]` array
- [ ] Read ppdu_cnt from WiFi frame DW1 bits [6:4] — correlate to stored RSSI
- [ ] Extract rssi_avg_td (byte 3 of physts header) — convert: `(val >> 1) - 110` dBm
- [ ] Extract per-path RSSI: rssi_td[0..3] (bytes 4-7) for path A and B
- [ ] Fallback to -80 dBm only when no PPDU status available for this ppdu_cnt
- [ ] Remove hardcoded `let rssi = -80i8` placeholder
- **Verification**: Run bench, check RSSI values vary per AP (not all identical)
- **Reference**: `halbb_physts_ie_l_endian.h:34-43`, `hal_api_bb.c:826`

### A2. RX Descriptor Full Parse (DW1 — free data, just read it)
- [ ] Parse ppdu_type DW1[3:0] — 0=Legacy, 1=HT, 2=HT-GF, 3=VHT, 4=HE-SU, 5=HE-ER-SU, 6=HE-MU, 7=HE-TB
- [ ] Parse rx_datarate DW1[24:16] — 9-bit rate encoding
- [ ] Parse rx_gi_ltf DW1[27:25] — guard interval / LTF type
- [ ] Parse bw DW1[31:30] — 0=20, 1=40, 2=80, 3=160 MHz
- [ ] Parse ppdu_cnt DW1[6:4] — for PPDU correlation
- [ ] Parse AMPDU/AMSDU from DW3[3:5]
- [ ] Store all parsed fields in RxFrame (extend struct)
- **Verification**: Log frame types — should see mix of Legacy/HT/VHT/HE

### A3. PPDU Status Full Parse (rpkt_type=1 payload)
- [ ] Parse physts_hdr_info (8 bytes): rssi_avg, rssi[4], ie_bitmap, is_valid
- [ ] Parse IE0 (CCK): noise floor (avg_idle_noise_pwr), CFO, rx_path_en_bitmap
- [ ] Parse IE1 (OFDM/HT/VHT/HE): avg_snr, ch_idx, is_ldpc, is_stbc, is_bf, bw_idx, rxsc
- [ ] Track noise floor per-channel for environment RF quality metrics
- [ ] Track SNR alongside RSSI for better link quality assessment
- **Verification**: Check SNR/noise values are reasonable (SNR > 0, noise ~ -90 to -100 dBm)
- **Reference**: `halbb_physts_ie_l_endian.h:50-144`, `halbb_physts.c:828-860`

### A4. Clean Up Init — Remove Spinner-Breaking eprintln
- [ ] Line 631, 686: BB/RF table write failures — return Err instead
- [ ] Line 913: DMA ready timeout — already returns Err, remove eprintln
- [ ] Lines 1005-1006: H2C path not ready — already returns Err, remove eprintln
- [ ] Line 1078: FWDL path not ready — already returns Err, remove eprintln
- [ ] Line 1117: FW not ready — already returns Err, remove eprintln
- [ ] Lines 1589, 1607: replay_phase write/bulk failures — log to file, not stderr
- [ ] Lines 1671, 1701: replay_phase_complete failures — log to file, not stderr
- [ ] Lines 1796, 1817: replay_pcap_post_fwdl failures — log to file, not stderr
- [ ] Line 1873: pre_fwdl H2C not ready — log to file, not stderr
- [ ] Remove all empty `if` blocks (dead progress logging): lines 1009, 1101, 1614, 1709
- **Verification**: Init shows single spinner line resolving to checkmark

### A5. Dirty Firmware Reset (DONE)
- [x] Detect dirty FW state (0x01E0 != 0) at chip_init start
- [x] Call disable_cpu() + power_off() before fresh power_on()
- **Verification**: Device initializes without replug after dirty exit

### A6. MAC Address
- [ ] Fix MAC reading — currently shows 00:00:00:00:60:31
- [ ] Read from EFUSE (0x0036-0x003B) after FW boot, not before
- [ ] Write to R_AX_MACID_REG (0xC100) when set_mac() is called
- **Verification**: MAC matches sticker on device

---

## B. H2C COMMAND BUILDER — The Key That Unlocks Everything

### B1. H2C Framework
- [ ] Build generic H2C command builder: category, class, function, sequence, payload
- [ ] H2C DW0: CAT[1:0] | CLASS[7:2] | FUNC[15:8] | DEL_TYPE[17:16] | SEQ[31:24]
- [ ] H2C DW1: TOTAL_LEN[13:0]
- [ ] WD prepend: DW0 = CH_DMA(12) << 16, DW2 = payload_len
- [ ] Send via EP5 (not EP7 — EP7 is for FWDL only)
- [ ] Track h2c_seq for proper sequencing
- [ ] Parse C2H responses (rpkt_type=0x0A) for firmware acknowledgments
- **Reference**: `references/rtl8852au/phl/hal_g6/mac/fw_ax/inc_hdr/fwcmd_intf.h`

### B2. Channel Switch via H2C
- [ ] Implement MAC_AX channel switch H2C command
- [ ] Set central_ch, primary_ch, bandwidth, band
- [ ] BB channel setting via halbb_ctrl_bw_ch (RF reg 0x18 + BB regs)
- [ ] RF PLL relock per path
- [ ] SCO compensation table
- [ ] CCK parameters for 2.4GHz, disable for 5GHz
- [ ] BB reset cycle after channel change
- [ ] ALL 39 channels work (not just 7 from pcap)
- [ ] Channel 14 enabled (no regulatory filtering)
- [ ] DFS channels 52-144 enabled (no CAC wait)
- **Verification**: Bench --hop through all 39 channels, all receive frames

### B3. TX Power via H2C
- [ ] Read EFUSE TX power calibration tables per channel/path/rate
- [ ] Implement set_tx_power H2C command
- [ ] Per-channel max power from EFUSE (30 dBm 2.4G, 23-30 dBm 5G)
- [ ] Per-rate power offset
- [ ] Power tracking (thermal compensation)
- [ ] Expose actual TX power in chip_info, not hardcoded 20
- **Verification**: Set max power, measure with another adapter at distance

### B4. Bandwidth via H2C
- [ ] 40MHz mode: set central_ch, primary position (upper/lower), BB BW regs
- [ ] 80MHz mode: set central_ch, primary position, VHT BW regs
- [ ] Per-path RF BW setting (RF reg 0x18 BW bits)
- [ ] MAC WMAC_RFMOD register for BW
- [ ] TX sub-carrier configuration
- **Verification**: Set 80MHz on ch36, capture shows 80MHz frames

---

## C. TX — Full Injection Capability

### C1. TX Descriptor Complete Build
- [ ] DW0: STF_MODE, CH_DMA, EN_HWSEQ_MODE, WD_PAGE, WDINFO_EN
- [ ] DW2: TXPKTSIZE, QSEL, MACID, TID_IND
- [ ] DW3: DATA_TC, RTS_TC, AGG_EN, BK, WIFI_SEQ
- [ ] DW4: AES_IV (when needed)
- [ ] DW5: AES_IV_H
- [ ] DW6 (the important one): USERATE_SEL=1, DATARATE, DATA_BW, GI_LTF, DATA_LDPC, DATA_STBC, DISDATAFB, DISRTSFB
- [ ] DW7: DATA_TXCNT_LMT, DATA_RTY_LOWEST_RATE
- [ ] Queue mapping: MGMT→B0MG(8), BE→ACH0(0), VO→ACH6(6)
- **Reference**: `references/rtl8852au/phl/hal_g6/mac/txdesc.h`

### C2. Rate Selection for TX
- [ ] Legacy OFDM: 6/9/12/18/24/36/48/54 Mbps
- [ ] CCK: 1/2/5.5/11 Mbps (2.4G only)
- [ ] HT MCS 0-15 (2x2 MIMO, 20/40MHz)
- [ ] VHT MCS 0-9, 1-2 NSS (20/40/80MHz)
- [ ] HE MCS 0-11, 1-2 NSS (20/40/80MHz, GI 0.8/1.6/3.2us)
- [ ] Rate encoding: Legacy=0x00-0x0B, HT=0x80+MCS, VHT=(NSS<<4)|MCS, HE=(NSS<<4)|MCS
- [ ] Expose rate selection in TxOptions
- **Verification**: Inject beacon at HE MCS11, verify with 2nd adapter

### C3. TX Power Per-Frame
- [ ] Use EFUSE-calibrated power tables
- [ ] Allow TxOptions to specify power level
- [ ] OFDM/CCK/HT/VHT/HE separate power offsets
- **Verification**: Inject at max power, measure signal on 2nd adapter

### C4. TX Features
- [ ] LDPC TX (AX_TXD_DATA_LDPC) — better reliability at range
- [ ] STBC TX (AX_TXD_DATA_STBC) — on 5GHz where supported
- [ ] Retry control: TXCNT_LMT for deauth (1 = fire-and-forget), higher for EAPOL
- [ ] Disable rate fallback (DISDATAFB) for injection
- [ ] Hardware sequence numbers (EN_HWSEQ_MODE) when appropriate
- [ ] TX aggregation (AGG_EN, DMA_TXAGG_NUM) for bulk injection
- **Verification**: Deauth with STBC+LDPC at max power from across the room

### C5. Raw Packet Injection
- [ ] Accept ANY raw 802.11 frame from the tool — driver just wraps in WD and sends
- [ ] No frame validation in driver — the tool decides what to send
- [ ] Support for all frame types: management, control, data
- [ ] Proper FCS handling (let hardware append)
- **Verification**: Inject custom beacon, association request, deauth, EAPOL

---

## D. OPERATING MODES

### D1. Monitor Mode (improve current)
- [ ] Proper RX filter configuration via H2C (not pcap replay)
- [ ] Accept ALL frame types (management + control + data)
- [ ] Sniffer mode bit (R_AX_RX_FLTR_OPT bit 0)
- [ ] CRC error frames optional (for analysis)
- [ ] PLCP header capture for PHY-layer analysis
- **Verification**: Capture all frame types, including control frames

### D2. AP Mode
- [ ] Firmware AP mode H2C command
- [ ] Beacon generation and transmission
- [ ] Association handling (assoc req/resp)
- [ ] Authentication handling (open, WPA2-PSK, WPA3-SAE)
- [ ] BSSID configuration
- [ ] Channel and bandwidth setting in AP context
- [ ] Client tracking (MACID table)
- [ ] Enables: evil twin, karma, rogue AP, MITM, captive portal attacks
- **Reference**: `references/rtl8852au/core/rtw_ap.c`

### D3. Managed (STA) Mode
- [ ] STA association to target AP
- [ ] WPA2 4-way handshake as client
- [ ] WPA3 SAE (hardware SAE offload available!)
- [ ] EAP/802.1X client
- [ ] Enables: client-side attacks, credential capture, network probing
- **Reference**: `references/rtl8852au/core/rtw_mlme.c`

### D4. ACK in Monitor Mode
- [ ] Configure firmware to send ACKs for received frames
- [ ] NAV handling for proper 802.11 timing
- [ ] Enables: managed-mode-from-monitor attacks (associate without leaving monitor)
- [ ] This is what makes active attacks work reliably
- **Reference**: Check extended TX descriptor NAV_USE_HDR fields

---

## E. RX OPTIMIZATION

### E1. EFUSE / Calibration Data
- [ ] Read full EFUSE map after FW boot
- [ ] Parse RFE type — affects antenna switch config, table selection
- [ ] Parse per-channel TX power limits
- [ ] Parse per-path RSSI offset calibration
- [ ] Parse thermal sensor calibration
- [ ] Parse crystal cap calibration
- [ ] Parse antenna gain values
- **Reference**: `references/rtl8852au_efuse/`, efuse map in vendor driver

### E2. MIMO / Antenna Configuration
- [ ] Configure 2x2 MIMO properly (both paths active for RX and TX)
- [ ] Verify Available Antennas (currently TX=0 RX=0 — wrong, should be 0x3)
- [ ] Antenna diversity / selection
- [ ] Per-path gain calibration from EFUSE
- **Verification**: Per-path RSSI shows both paths active (not one stuck at 0)

### E3. Beamformee Enable
- [ ] Enable SU Beamformee in HE/VHT capabilities
- [ ] Configure Beamformee STS (3 STS available)
- [ ] This tells APs to steer their signal toward us — free RX gain
- **Verification**: RSSI improves by 3-6 dB from beamforming-capable APs

### E4. RX Aggregation Optimization
- [ ] Set optimal AMPDU length (65535 bytes max)
- [ ] Set AMSDU length (7935 bytes max)
- [ ] Configure per-USB-speed AGG settings (USB3 vs USB2)
- [ ] Tune AGG timeout for latency vs throughput
- **Verification**: FPS improves with proper AGG config

### E5. Short GI / LDPC RX
- [ ] Verify RX LDPC is enabled (hardware supports it)
- [ ] Enable short GI for HT20/HT40/VHT80
- [ ] These should be handled by FW but verify via register reads
- **Verification**: Can decode SGI and LDPC frames (see in PPDU type analysis)

### E6. IQK / LCK Calibration
- [ ] Implement IQ Calibration at init and channel switch
- [ ] Implement LC Calibration
- [ ] These improve TX/RX accuracy significantly
- **Reference**: `references/rtl8852au/phl/hal_g6/phy/bb/halbb_8852a/`

---

## F. SCAN MODES

### F1. Fast Scan (LOW_SPAN_SCAN)
- [ ] Shorter dwell time per channel
- [ ] Skip channels with no activity quickly
- [ ] Useful for rapid recon

### F2. Deep Scan (HIGH_ACCURACY_SCAN)
- [ ] Longer dwell per channel
- [ ] Better for finding hidden SSIDs, weak APs
- [ ] Passive + active probe combination

### F3. 40/80 MHz Scan
- [ ] Scan in 40MHz or 80MHz bandwidth
- [ ] Captures traffic from APs using wider channels
- [ ] Currently missing all 40/80MHz-only traffic

### F4. DFS Channel Scan
- [ ] Enable DFS channels 52-144 without CAC wait (no regulatory compliance needed)
- [ ] Many enterprise APs use DFS channels to avoid congestion
- [ ] Currently invisible to our scanner

---

## G. DEAD CODE CLEANUP

- [ ] Remove `usb_init()` (line 826-849) — never called
- [ ] Remove `mac_init()` (line 1242-1271) — never called
- [ ] Remove `set_monitor_internal()` (line 1279-1333) — never called, breaks RX
- [ ] Remove `enable_cpu_for_fwdl()` (line 1134-1164) — never called
- [ ] Remove empty `dump_key_regs()` (line 1877-1894) — empty loop body
- [ ] Remove empty progress blocks throughout replay functions
- [ ] Clean up all unused variables (prefix with _)
- [ ] Remove diagnostic logging code (TEMPORARY - added this session)

---

## H. RxFrame Struct Extension

When implementing A1-A3, extend RxFrame with:
- [ ] `data_rate: u16` — RX data rate encoding from DW1
- [ ] `bandwidth: u8` — 0=20, 1=40, 2=80, 3=160 MHz
- [ ] `rssi_path: [i8; 4]` — per-path RSSI for MIMO analysis
- [ ] `noise_floor: i8` — from PPDU IE0/IE1
- [ ] `snr: u8` — from PPDU IE1
- [ ] `ppdu_type: u8` — Legacy/HT/VHT/HE
- [ ] `is_ldpc: bool` — LDPC coding detected
- [ ] `is_stbc: bool` — STBC detected
- [ ] Update all RxFrame construction sites (15 locations across all drivers)
- [ ] Use default values (0/false) for drivers that don't populate these yet

---

## I. HARDWARE CRYPTO ENGINE

### I1. Supported Ciphers (all hardware-accelerated)
- [ ] WEP40 (00-0f-ac:1) — legacy, needed for old AP attacks
- [ ] WEP104 (00-0f-ac:5) — legacy
- [ ] TKIP (00-0f-ac:2) — WPA1
- [ ] CCMP-128 (00-0f-ac:4) — WPA2 standard
- [ ] CMAC (00-0f-ac:6) — 802.11w management frame protection
- [ ] GCMP-128 (00-0f-ac:8) — WPA3
- [ ] GCMP-256 (00-0f-ac:9) — WPA3 Enterprise 192-bit
- [ ] CCMP-256 (00-0f-ac:10) — WPA3 Enterprise 192-bit
- [ ] GMAC-128 (00-0f-ac:11) — BIP for 802.11w
- [ ] GMAC-256 (00-0f-ac:12) — BIP for 802.11w
- [ ] CMAC-256 (00-0f-ac:13) — BIP for 802.11w

### I2. Hardware Encryption TX
- [ ] TX descriptor SECTYPE field (DW8 bits [12:9]) — select cipher type
- [ ] SEC_HW_ENC (DW8 bit 8) — enable hardware encryption
- [ ] SEC_CAM_IDX (DW8 bits [7:0]) — security CAM index
- [ ] AES_IV fields (DW4/DW5) — IV for hardware crypto
- [ ] HW_SEC_IV (DW0 bit 6, v1) — hardware generates IV
- [ ] SEC_KEYID (DW1 bits [5:4], v1) — key ID selection
- [ ] Security CAM configuration for storing keys
- [ ] Enables: encrypted injection, MFP frame crafting, WPA3 attacks

### I3. SAE / WPA3 Offload
- [ ] SAE authentication offload (4WAY_HANDSHAKE_STA_PSK)
- [ ] SAE offload in AP mode (SAE_OFFLOAD_AP)
- [ ] 802.1X offload (4WAY_HANDSHAKE_STA_1X)
- [ ] Enables: WPA3 dragonfly side-channel attacks, downgrade attacks

---

## J. ADVANCED TX FEATURES (from complete TX descriptor analysis)

### J1. RTS/CTS Control
- [ ] RTS_EN (DW10 bit 27) — enable RTS before data
- [ ] CTS2SELF (DW10 bit 28) — CTS-to-self protection
- [ ] HW_RTS_EN (DW10 bit 31) — hardware RTS
- [ ] CCA_RTS (DW10 bits [30:29]) — CCA RTS mode
- [ ] Enables: NAV manipulation, channel reservation attacks

### J2. Sounding / Beamforming TX
- [ ] NDPA (DW9 bits [2:1]) — NDP Announcement
- [ ] SND_PKT_SEL (DW9 bits [5:3]) — sounding packet select
- [ ] HT_DATA_SND (DW9 bit 7) — HT sounding
- [ ] NDPA_DURATION (DW11 bits [31:16]) — NDP duration
- [ ] Enables: beamforming spoofing, CSI extraction attacks

### J3. Timing / NAV Control
- [ ] NAVUSEHDR (DW7 bit 10) — use NAV from 802.11 header
- [ ] SIFS_TX (DW9 bit 6) — transmit after SIFS interval (immediate response)
- [ ] FORCE_TXOP (DW8 bit 17) — force TXOP
- [ ] LSIG_TXOP_EN (DW8 bit 21) — L-SIG TXOP protection
- [ ] LIFETIME_SEL (DW8 bits [15:13]) — packet lifetime
- [ ] Enables: timing attacks, TXOP manipulation, ACK spoofing

### J4. Broadcast/Multicast
- [ ] BMC (DW7 bit 11) — broadcast/multicast flag
- [ ] FORCE_BSS_CLR (DW9 bit 31) — force BSS color clear
- [ ] Enables: broadcast injection, BSS color attacks

### J5. Special Frames
- [ ] RAW (DW9 bit 15) — raw frame mode (no firmware processing)
- [ ] NULL_0/NULL_1 (DW9 bits [14:13]) — null function frames
- [ ] BT_NULL (DW9 bit 11) — Bluetooth null
- [ ] TRI_FRAME (DW9 bit 12) — trigger frame
- [ ] RTT_EN (DW9 bit 9) — Round Trip Time measurement
- [ ] SPE_RPT (DW9 bit 10) — special report
- [ ] SIGNALING_TA_PKT_EN (DW9 bit 0) — signaling TA packet
- [ ] Enables: RTT spoofing, trigger frame injection, BT coex exploitation

### J6. TX Status / Reporting
- [ ] ACK_CH_INFO (DW6 bit 31) — request ACK channel info
- [ ] UPD_WLAN_HDR (DW0 bit 30, v1) — firmware updates 802.11 header
- [ ] TX status feedback via rpkt_type=4 (TXCMD_RPT) and rpkt_type=6 (TXRPT)
- [ ] Parse TX completion reports — know if injection succeeded
- [ ] Enables: injection verification, adaptive attack strategies

### J7. NO_ACK Mode (v1 descriptor)
- [ ] NO_ACK (DW0 bit 31, v1) — suppress ACK for this frame
- [ ] Enables: stealth injection, fire-and-forget attacks

---

## K. BLUETOOTH COEXISTENCE

### K1. BT Coex Control
- [ ] R_AX_SCOREBOARD register (0x00AC) — BT/WiFi arbitration
- [ ] BT_NULL frame generation
- [ ] Coex grant control
- [ ] Enables: understand/exploit BT coex timing, BT interference attacks
- **Reference**: `references/rtl8852au/core/rtw_btc.c`

---

## L. ADDITIONAL OPERATING MODES

### L1. Mesh Networking
- [ ] 802.11s mesh mode
- [ ] HWMP path selection
- [ ] Mesh peer link management
- [ ] Enables: mesh network attacks, path manipulation
- **Reference**: `references/rtl8852au/core/mesh/rtw_mesh.c`

### L2. Fake AP (built into vendor driver!)
- [ ] rtw_fake_ap.c — Realtek's own fake AP implementation
- [ ] Study and port — may reveal optimal AP spoofing patterns
- **Reference**: `references/rtl8852au/core/rtw_fake_ap.c`

### L3. Fast Transition (802.11r)
- [ ] FT authentication
- [ ] FT action frames
- [ ] Enables: FT key hierarchy attacks, PMKR0/PMKR1 extraction
- **Reference**: `references/rtl8852au/core/rtw_ft.c`

### L4. MBO / 802.11k/v
- [ ] MBO (Multi-Band Operation)
- [ ] BSS Transition Management
- [ ] Enables: forced roaming attacks, network steering
- **Reference**: `references/rtl8852au/core/rtw_mbo.c`

### L5. TDLS
- [ ] Tunneled Direct Link Setup
- [ ] Direct client-to-client links
- [ ] Enables: TDLS teardown attacks, traffic interception
- **Reference**: `references/rtl8852au/core/rtw_tdls.c`

### L6. P2P / Wi-Fi Direct
- [ ] P2P client and GO modes
- [ ] P2P service discovery
- [ ] Enables: P2P relay attacks, service spoofing
- **Reference**: `references/rtl8852au/core/rtw_p2p.c`

### L7. Remain-on-Channel
- [ ] Stay on a specific channel while main interface operates normally
- [ ] Enables: targeted monitoring of specific channels during attacks
- **Reference**: Supported command in iw phy output

### L8. WoWLAN
- [ ] Wake-on-WLAN patterns
- [ ] Device continues operating normally
- [ ] Enables: persistent monitoring even during "sleep"

---

## M. RADIO MEASUREMENT / LOCATION

### M1. Radio Resource Management (802.11k)
- [ ] Channel load measurement
- [ ] Noise histogram
- [ ] Beacon measurement
- [ ] Link measurement
- [ ] Neighbor report
- [ ] Enables: environment mapping, site survey, target selection
- **Reference**: `references/rtl8852au/core/rtw_rm.c`, `rtw_rm_fsm.c`, `rtw_rm_util.c`

### M2. RTT (Round Trip Time)
- [ ] RTT_EN in TX descriptor
- [ ] Fine Timing Measurement (FTM)
- [ ] Enables: distance estimation to APs, location tracking

---

## N. MANUFACTURING TEST / DEBUG

### N1. MP (Manufacturing Protocol) Mode
- [ ] Direct register read/write
- [ ] Continuous TX/RX test modes
- [ ] Per-rate TX power calibration
- [ ] Antenna testing
- [ ] Enables: deep hardware diagnostics, custom signal generation
- **Reference**: `references/rtl8852au/core/rtw_mp.c`

---

## O. POWER MANAGEMENT

### O1. Power States
- [ ] Active / LPS (Low Power State) / Deep Sleep
- [ ] Wake-on-WLAN configuration
- [ ] Power save poll frame generation
- [ ] Enables: power state manipulation attacks

---

## Priority Order

1. **A1+A2+A3** — RSSI + RX descriptor parse (immediate, high impact)
2. **A4** — eprintln cleanup (quick win)
3. **B1** — H2C command builder (unlocks everything)
4. **B2** — Channel switch via H2C (all 39+ channels)
5. **C1+C2+C5** — Complete TX descriptor + rate selection + raw inject
6. **B3** — TX power (max range)
7. **B4** — Bandwidth (40/80 MHz)
8. **E1+E2** — EFUSE + MIMO config
9. **D1** — Monitor mode improvements
10. **D2** — AP mode (evil twin)
11. **D3** — Managed mode (client attacks)
12. **E3+E4+E5+E6** — RX optimization
13. **F1-F4** — Scan modes
14. **D4** — ACK in monitor
15. **G** — Dead code cleanup (ongoing)

---

*Created: 2026-03-31, Session 6*
*Last updated: 2026-03-31*
