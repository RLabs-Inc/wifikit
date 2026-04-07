#![allow(dead_code)]

use std::time::Duration;

use super::MacAddress;

// Simple bitflags without external crate
macro_rules! bitflags_manual {
    ($name:ident : $ty:ty { $($flag:ident = $val:expr,)* }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name($ty);

        impl $name {
            $(pub const $flag: Self = Self($val);)*

            pub const fn empty() -> Self { Self(0) }

            pub fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }
        }

        impl std::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
        }

        impl std::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
        }
    };
}
// Re-export for use in taxonomy.rs (macro re-exports trigger false unused_imports warning in rustc)
#[allow(unused_imports)]
pub(crate) use bitflags_manual;

/// PPDU type as reported by MAC AX gen2 RX descriptor DW1[3:0].
/// Values from mac_def.h: mac_ax_rx_ppdu_type enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PpduType {
    #[default]
    Cck = 0,
    Ofdm = 1,
    HT = 2,
    VhtSu = 3,
    VhtMu = 4,
    HeSu = 5,
    HeMu = 6,
    HeTb = 7,
}

impl PpduType {
    pub fn from_raw(val: u8) -> Self {
        match val {
            0 => Self::Cck,
            1 => Self::Ofdm,
            2 => Self::HT,
            3 => Self::VhtSu,
            4 => Self::VhtMu,
            5 => Self::HeSu,
            6 => Self::HeMu,
            7 => Self::HeTb,
            _ => Self::Cck,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cck => "CCK",
            Self::Ofdm => "OFDM",
            Self::HT => "HT",
            Self::VhtSu => "VHT-SU",
            Self::VhtMu => "VHT-MU",
            Self::HeSu => "HE-SU",
            Self::HeMu => "HE-MU",
            Self::HeTb => "HE-TB",
        }
    }
}

/// Guard interval / LTF type from RX descriptor DW1[27:25].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum GuardInterval {
    #[default]
    Gi800ns = 0,
    Gi400ns = 1,
    Gi1600ns = 2,
    Gi3200ns = 3,
}

impl GuardInterval {
    pub fn from_raw(val: u8) -> Self {
        match val {
            0 => Self::Gi800ns,
            1 => Self::Gi400ns,
            2 => Self::Gi1600ns,
            3 => Self::Gi3200ns,
            _ => Self::Gi800ns,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gi800ns => "0.8μs",
            Self::Gi400ns => "0.4μs",
            Self::Gi1600ns => "1.6μs",
            Self::Gi3200ns => "3.2μs",
        }
    }
}

/// Bandwidth from RX descriptor DW1[31:30].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RxBandwidth {
    #[default]
    Bw20 = 0,
    Bw40 = 1,
    Bw80 = 2,
    Bw160 = 3,
}

impl RxBandwidth {
    pub fn from_raw(val: u8) -> Self {
        match val {
            0 => Self::Bw20,
            1 => Self::Bw40,
            2 => Self::Bw80,
            3 => Self::Bw160,
            _ => Self::Bw20,
        }
    }

    pub fn mhz(&self) -> u16 {
        match self {
            Self::Bw20 => 20,
            Self::Bw40 => 40,
            Self::Bw80 => 80,
            Self::Bw160 => 160,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RxFrame {
    pub data: Vec<u8>,
    pub rssi: i8,
    pub channel: u8,
    /// Band index: 0=2.4GHz, 1=5GHz, 2=6GHz.
    /// Set by the RX thread from the adapter's current band.
    pub band: u8,
    pub timestamp: Duration,

    // --- PHY status fields (populated by drivers that support PPDU correlation) ---

    /// Per-path RSSI in dBm. [path_a, path_b, path_c, path_d].
    /// 0 = not populated.
    pub rssi_path: [i8; 4],
    /// Average noise floor in dBm from PPDU IE0/IE1.
    /// 0 = not populated.
    pub noise_floor: i8,
    /// Average SNR from PPDU IE1 (OFDM/HT/VHT/HE). 6-bit unsigned, 0-63 dB.
    /// 0 = not populated.
    pub snr: u8,
    /// RX data rate encoding from DW1[24:16]. 9-bit value.
    /// Legacy: 0x00-0x0B, HT: 0x80+MCS, VHT: (NSS<<4)|MCS, HE: (NSS<<4)|MCS.
    pub data_rate: u16,
    /// PPDU type — Legacy/HT/VHT/HE-SU/HE-MU etc.
    pub ppdu_type: PpduType,
    /// Channel bandwidth.
    pub bandwidth: RxBandwidth,
    /// Guard interval / LTF type.
    pub gi_ltf: GuardInterval,
    /// LDPC coding detected in this PPDU.
    pub is_ldpc: bool,
    /// STBC detected in this PPDU.
    pub is_stbc: bool,
    /// Beamforming detected in this PPDU.
    pub is_bf: bool,
    /// AMPDU aggregate flag from DW3.
    pub is_ampdu: bool,
    /// AMSDU aggregate flag from DW3.
    pub is_amsdu: bool,

    // --- Extended PHY status (IE1 OFDM/HT/VHT/HE) ---

    /// Frequency-domain RSSI average, U(8,1). Different from time-domain rssi.
    /// Gives a second RSSI measurement from the FD equalizer path.
    pub rssi_fd: u8,
    /// Maximum EVM across subcarriers. U(8,0) dB.
    pub evm_max: u8,
    /// Minimum EVM across subcarriers. U(8,0) dB.
    pub evm_min: u8,
    /// Carrier frequency offset in kHz (signed). Average over data symbols.
    pub cfo: i16,
    /// Preamble CFO in kHz (signed). Measured from preamble only.
    pub cfo_preamble: i16,
    /// Sub-channel index (rxsc) — which 20MHz sub-channel within wider BW.
    pub rxsc: u8,
    /// RX path enable bitmap. Bit 0=path A, bit 1=path B, etc.
    pub rx_path_en: u8,
    /// SU (single-user) packet flag.
    pub is_su: bool,
    /// NDP (Null Data Packet) flag.
    pub is_ndp: bool,
    /// AWGN (additive white Gaussian noise) channel detected.
    pub is_awgn: bool,
    /// Bluetooth grant active during RX (coexistence).
    pub grant_bt: bool,
    /// Beamforming gain maximum. 7-bit, U(7,0).
    pub bf_gain_max: u8,
    /// Average condition number segment 0. 7-bit. Higher = worse channel.
    pub condition_number: u8,
    /// Tones with signal value below threshold.
    pub sigval_below_th_cnt: u8,
    /// Tones with condition number exceeding threshold.
    pub cn_excess_th_cnt: u8,
    /// Power-to-CCA timing (μs). Time from power detect to CCA.
    pub pwr_to_cca: u16,
    /// CCA-to-AGC timing (μs). Time from CCA to AGC settled.
    pub cca_to_agc: u8,
    /// CCA-to-SBD timing (μs). Time from CCA to symbol boundary detect.
    pub cca_to_sbd: u8,
    /// EDCCA report count.
    pub edcca_rpt_cnt: u8,
    /// EDCCA total sample count.
    pub edcca_total_smp_cnt: u8,
    /// EDCCA current BW max power.
    pub edcca_rpt_bw_max: u8,
    /// EDCCA current BW min power.
    pub edcca_rpt_bw_min: u8,
    /// BB-reported bandwidth index (0=5MHz .. 6=80+80MHz).
    pub bw_from_phy: u8,
    /// Packet detection index (pop_idx). 2-bit.
    pub pop_idx: u8,

    // --- IE0 CCK-specific fields ---

    /// Received power level (RPL) from CCK IE0. 9-bit raw.
    pub cck_rpl: u16,
    /// CCA time for CCK detection (μs).
    pub cck_cca_time: u8,
    /// CCK EVM for header.
    pub cck_evm_hdr: u8,
    /// CCK EVM for payload.
    pub cck_evm_pld: u8,
    /// CCK signal length (PSDU length from PLCP).
    pub cck_sig_len: u16,
    /// CCK preamble type: 0=long, 1=short.
    pub cck_preamble_type: u8,
    /// CCK DAGC gain per path [A, B, C, D]. 5-bit each.
    pub cck_dagc: [u8; 4],
    /// CCK antenna diversity result per path [A, B, C, D].
    pub cck_antdiv_rslt: [bool; 4],
    /// CCK HW antenna switch occurred per path [A, B, C, D].
    pub cck_hw_antsw: [bool; 4],
    /// CCK antenna weight gain difference. 5-bit.
    pub cck_antwgt_gain_diff: u8,
    /// CCK sync mode.
    pub cck_sync_mode: u8,

    // --- IE2 HE/AX extended fields ---

    /// Maximum spatial streams (NSTS).
    pub max_nsts: u8,
    /// Midamble present flag.
    pub midamble: bool,
    /// LTF type from PHY (not descriptor). 2-bit.
    pub ltf_type: u8,
    /// Guard interval from PHY (not descriptor). 2-bit.
    pub gi_from_phy: u8,
    /// MU-MIMO flag.
    pub is_mu_mimo: bool,
    /// Downlink OFDMA flag.
    pub is_dl_ofdma: bool,
    /// Dual carrier modulation (HE-specific).
    pub is_dcm: bool,
    /// Doppler detected.
    pub is_doppler: bool,
    /// Packet extension. 3-bit.
    pub pkt_extension: u8,
    /// Coarse CFO I component (signed 18-bit).
    pub coarse_cfo_i: i32,
    /// Coarse CFO Q component (signed 18-bit).
    pub coarse_cfo_q: i32,
    /// Fine CFO I component (signed 18-bit).
    pub fine_cfo_i: i32,
    /// Fine CFO Q component (signed 18-bit).
    pub fine_cfo_q: i32,
    /// Estimated compensated phase. 8-bit.
    pub est_cmped_phase: u8,
    /// Number of LTF symbols.
    pub n_ltf: u8,
    /// Number of OFDM symbols.
    pub n_sym: u16,

    // --- IE4-7 per-path detailed stats [path A, B, C, D] ---

    /// Per-path signal value. U(8,0).
    pub path_sig_val: [u8; 4],
    /// Per-path RF gain index.
    pub path_rf_gain_idx: [u8; 4],
    /// Per-path TIA gain index.
    pub path_tia_gain_idx: [u8; 4],
    /// Per-path SNR. 6-bit unsigned.
    pub path_snr: [u8; 4],
    /// Per-path EVM per spatial stream.
    pub path_evm: [u8; 4],
    /// Per-path antenna weight. 7-bit.
    pub path_ant_weight: [u8; 4],
    /// Per-path DC offset estimate (real component).
    pub path_dc_re: [u8; 4],
    /// Per-path DC offset estimate (imaginary component).
    pub path_dc_im: [u8; 4],

    // --- Frequency-domain SNR (derived from IE1 + header) ---

    /// Frequency-domain SNR average. U(8,0) dB. OFDM only.
    pub snr_fd_avg: u8,
    /// Per-path frequency-domain SNR. Derived from snr_fd_avg + rssi_avg - rssi[i].
    pub snr_fd: [u8; 4],
    /// Per-path time-domain SNR. Derived from rssi[i] - idle_noise_pwr.
    pub snr_td: [u8; 4],
}

impl Default for RxFrame {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            rssi: 0,
            channel: 0,
            band: 0,
            timestamp: Duration::ZERO,
            rssi_path: [0; 4],
            noise_floor: 0,
            snr: 0,
            data_rate: 0,
            ppdu_type: PpduType::Cck,
            bandwidth: RxBandwidth::Bw20,
            gi_ltf: GuardInterval::Gi800ns,
            is_ldpc: false,
            is_stbc: false,
            is_bf: false,
            is_ampdu: false,
            is_amsdu: false,
            rssi_fd: 0,
            evm_max: 0,
            evm_min: 0,
            cfo: 0,
            cfo_preamble: 0,
            rxsc: 0,
            rx_path_en: 0,
            is_su: false,
            is_ndp: false,
            is_awgn: false,
            grant_bt: false,
            bf_gain_max: 0,
            condition_number: 0,
            sigval_below_th_cnt: 0,
            cn_excess_th_cnt: 0,
            pwr_to_cca: 0,
            cca_to_agc: 0,
            cca_to_sbd: 0,
            edcca_rpt_cnt: 0,
            edcca_total_smp_cnt: 0,
            edcca_rpt_bw_max: 0,
            edcca_rpt_bw_min: 0,
            bw_from_phy: 0,
            pop_idx: 0,
            cck_rpl: 0,
            cck_cca_time: 0,
            cck_evm_hdr: 0,
            cck_evm_pld: 0,
            cck_sig_len: 0,
            cck_preamble_type: 0,
            cck_dagc: [0; 4],
            cck_antdiv_rslt: [false; 4],
            cck_hw_antsw: [false; 4],
            cck_antwgt_gain_diff: 0,
            cck_sync_mode: 0,
            max_nsts: 0,
            midamble: false,
            ltf_type: 0,
            gi_from_phy: 0,
            is_mu_mimo: false,
            is_dl_ofdma: false,
            is_dcm: false,
            is_doppler: false,
            pkt_extension: 0,
            coarse_cfo_i: 0,
            coarse_cfo_q: 0,
            fine_cfo_i: 0,
            fine_cfo_q: 0,
            est_cmped_phase: 0,
            n_ltf: 0,
            n_sym: 0,
            path_sig_val: [0; 4],
            path_rf_gain_idx: [0; 4],
            path_tia_gain_idx: [0; 4],
            path_snr: [0; 4],
            path_evm: [0; 4],
            path_ant_weight: [0; 4],
            path_dc_re: [0; 4],
            path_dc_im: [0; 4],
            snr_fd_avg: 0,
            snr_fd: [0; 4],
            snr_td: [0; 4],
        }
    }
}

impl RxFrame {
    pub fn frame_control(&self) -> u16 {
        if self.data.len() >= 2 {
            u16::from_le_bytes([self.data[0], self.data[1]])
        } else {
            0
        }
    }

    pub fn frame_type(&self) -> u8 {
        ((self.frame_control() >> 2) & 0x03) as u8
    }

    pub fn frame_subtype(&self) -> u8 {
        ((self.frame_control() >> 4) & 0x0F) as u8
    }

    pub fn addr1(&self) -> Option<MacAddress> {
        MacAddress::from_slice(self.data.get(4..10)?)
    }

    pub fn addr2(&self) -> Option<MacAddress> {
        MacAddress::from_slice(self.data.get(10..16)?)
    }

    pub fn addr3(&self) -> Option<MacAddress> {
        MacAddress::from_slice(self.data.get(16..22)?)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TxOptions {
    pub rate: TxRate,
    pub retries: u8,
    pub flags: TxFlags,
    /// Guard interval: 0=normal (0.8μs), 1=short (0.4μs HT/VHT, 1.6μs HE), 2=extended (3.2μs HE)
    pub gi: u8,
    /// Bandwidth for TX: 0=20MHz, 1=40MHz, 2=80MHz, 3=160MHz
    pub bw: u8,
    /// HE LTF type: 0=1x LTF (0.8μs), 1=2x LTF (1.6μs), 2=4x LTF (3.2μs)
    pub ltf: u8,
    /// TX antenna mask: 0=default (all), 0x1=ant0, 0x2=ant1, 0x3=both
    pub antenna_mask: u8,
    /// Per-frame TX power in 0.5 dBm units. 0 = use adapter default.
    /// Example: 40 = 20 dBm, 10 = 5 dBm (stealth), 60 = 30 dBm (max range)
    pub tx_power_half_dbm: u8,
    /// Sounding packet type for beamforming: 0=normal, 2=VHT/HE NDPA, 3=VHT/HE NDP
    pub ndpa: u8,
    /// Sounding packet role: 0=unicast NDPA, 1=broadcast NDPA, 2=last NDP, 3=mid NDP
    pub snd_pkt_sel: u8,
    /// NDPA duration (μs) — how long firmware waits for beamforming feedback report
    pub ndpa_duration_us: u16,
}

impl Default for TxOptions {
    fn default() -> Self {
        Self {
            rate: TxRate::Ofdm6m,
            retries: 12,
            flags: TxFlags::empty(),
            gi: 0,
            bw: 0,
            ltf: 0,
            antenna_mask: 0,
            tx_power_half_dbm: 0,
            ndpa: 0,
            snd_pkt_sel: 0,
            ndpa_duration_us: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxRate {
    Cck1m,
    Cck2m,
    Cck5_5m,
    Cck11m,
    Ofdm6m,
    Ofdm9m,
    Ofdm12m,
    Ofdm18m,
    Ofdm24m,
    Ofdm36m,
    Ofdm48m,
    Ofdm54m,
    // HT rates (802.11n) — MCS index, 1 or 2 spatial streams
    HtMcs(u8),
    // VHT rates (802.11ac) — MCS 0-9, NSS 1-2
    VhtMcs { mcs: u8, nss: u8 },
    // HE rates (802.11ax / WiFi 6) — MCS 0-11, NSS 1-2
    HeMcs { mcs: u8, nss: u8 },
    // HE Extended SU — extended range, better for long-distance injection
    HeExtSuMcs { mcs: u8, nss: u8 },
    // HE Trigger-Based — uplink OFDMA (for trigger frame responses)
    HeTbMcs { mcs: u8, nss: u8 },
    // HE Multi-User — MU-MIMO injection
    HeMuMcs { mcs: u8, nss: u8 },
}

impl TxRate {
    /// Legacy hw_rate value (used by RTL drivers).
    /// For HT/VHT/HE rates, returns the MCS index.
    pub fn hw_rate(&self) -> u8 {
        match self {
            Self::Cck1m => 0x02,
            Self::Cck2m => 0x04,
            Self::Cck5_5m => 0x0B,
            Self::Cck11m => 0x16,
            Self::Ofdm6m => 0x0C,
            Self::Ofdm9m => 0x12,
            Self::Ofdm12m => 0x18,
            Self::Ofdm18m => 0x24,
            Self::Ofdm24m => 0x30,
            Self::Ofdm36m => 0x48,
            Self::Ofdm48m => 0x60,
            Self::Ofdm54m => 0x6C,
            Self::HtMcs(mcs) => *mcs,
            Self::VhtMcs { mcs, .. } => *mcs,
            Self::HeMcs { mcs, .. } | Self::HeExtSuMcs { mcs, .. }
            | Self::HeTbMcs { mcs, .. } | Self::HeMuMcs { mcs, .. } => *mcs,
        }
    }

    pub fn is_cck(&self) -> bool {
        matches!(self, Self::Cck1m | Self::Cck2m | Self::Cck5_5m | Self::Cck11m)
    }

    pub fn is_ht(&self) -> bool {
        matches!(self, Self::HtMcs(_))
    }

    pub fn is_vht(&self) -> bool {
        matches!(self, Self::VhtMcs { .. })
    }

    pub fn is_he(&self) -> bool {
        matches!(self, Self::HeMcs { .. } | Self::HeExtSuMcs { .. }
            | Self::HeTbMcs { .. } | Self::HeMuMcs { .. })
    }

    /// MT76 rate encoding: MODE[9:6] | NSS[12:10] | IDX[5:0]
    /// MODE: 0=CCK, 1=OFDM, 2=HT, 3=VHT, 4=HE_SU, 5=HE_EXT_SU, 6=HE_TB, 7=HE_MU
    pub fn mt76_rate(&self) -> u16 {
        match self {
            Self::Cck1m   => (0 << 6) | 0,
            Self::Cck2m   => (0 << 6) | 1,
            Self::Cck5_5m => (0 << 6) | 2,
            Self::Cck11m  => (0 << 6) | 3,
            // OFDM rate indices: 6M=11, 9M=15, 12M=10, 18M=14, 24M=9, 36M=13, 48M=8, 54M=12
            Self::Ofdm6m  => (1 << 6) | 11,
            Self::Ofdm9m  => (1 << 6) | 15,
            Self::Ofdm12m => (1 << 6) | 10,
            Self::Ofdm18m => (1 << 6) | 14,
            Self::Ofdm24m => (1 << 6) | 9,
            Self::Ofdm36m => (1 << 6) | 13,
            Self::Ofdm48m => (1 << 6) | 8,
            Self::Ofdm54m => (1 << 6) | 12,
            // HT: MODE=2, NSS from MCS index (0-7=NSS1, 8-15=NSS2)
            Self::HtMcs(mcs) => {
                let nss = (*mcs / 8) as u16;
                let idx = (*mcs % 8) as u16;
                (2 << 6) | (nss << 10) | idx
            }
            // VHT: MODE=3, explicit NSS
            Self::VhtMcs { mcs, nss } => {
                (3 << 6) | (((*nss - 1) as u16) << 10) | (*mcs as u16)
            }
            // HE_SU: MODE=4 — standard single-user HE
            Self::HeMcs { mcs, nss } => {
                (4 << 6) | (((*nss - 1) as u16) << 10) | (*mcs as u16)
            }
            // HE_EXT_SU: MODE=5 — extended range SU (better for long-distance attacks)
            Self::HeExtSuMcs { mcs, nss } => {
                (5 << 6) | (((*nss - 1) as u16) << 10) | (*mcs as u16)
            }
            // HE_TB: MODE=6 — trigger-based (uplink OFDMA response)
            Self::HeTbMcs { mcs, nss } => {
                (6 << 6) | (((*nss - 1) as u16) << 10) | (*mcs as u16)
            }
            // HE_MU: MODE=7 — multi-user MIMO
            Self::HeMuMcs { mcs, nss } => {
                (7 << 6) | (((*nss - 1) as u16) << 10) | (*mcs as u16)
            }
        }
    }
}

bitflags_manual! {
    TxFlags: u16 {
        NO_ACK       = 0x0001,
        NO_RETRY     = 0x0002,
        HW_SEQ       = 0x0004,
        WANT_ACK     = 0x0008,  // Request ACK (clears NO_ACK and BA_DISABLE in TXWI)
        LDPC         = 0x0010,  // Enable LDPC coding
        STBC         = 0x0020,  // Enable Space-Time Block Coding (2x2 diversity)
        SHORT_PRE    = 0x0040,  // Short preamble (CCK only)
        PROTECT      = 0x0080,  // RTS/CTS protection before frame
        DYN_BW       = 0x0100,  // Dynamic bandwidth — allow fallback to narrower BW
        FORCE_TX_STATUS = 0x0200, // Force TX status report for this frame
        SIFS_TX      = 0x0400,  // Insert SIFS after TX (for sounding: NDPA→NDP chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_beacon_frame() -> RxFrame {
        // Minimal 802.11 beacon: FC=0x0080 (type=0 mgmt, subtype=8 beacon)
        let mut data = vec![0u8; 24];
        data[0] = 0x80; // FC byte 0: subtype=8, type=0
        data[1] = 0x00; // FC byte 1
        // addr1 (DA) = broadcast
        data[4..10].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // addr2 (SA) = AP BSSID
        data[10..16].copy_from_slice(&[0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        // addr3 (BSSID) = same as SA
        data[16..22].copy_from_slice(&[0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
        RxFrame { data, rssi: -42, channel: 6, band: 0, timestamp: Duration::from_millis(100), ..Default::default() }
    }

    #[test]
    fn test_rxframe_frame_control() {
        let frame = make_beacon_frame();
        assert_eq!(frame.frame_control(), 0x0080);
    }

    #[test]
    fn test_rxframe_frame_type_management() {
        let frame = make_beacon_frame();
        assert_eq!(frame.frame_type(), 0); // management
    }

    #[test]
    fn test_rxframe_frame_subtype_beacon() {
        let frame = make_beacon_frame();
        assert_eq!(frame.frame_subtype(), 8); // beacon
    }

    #[test]
    fn test_rxframe_addr1_broadcast() {
        let frame = make_beacon_frame();
        let addr1 = frame.addr1().unwrap();
        assert_eq!(addr1.as_bytes(), &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_rxframe_addr2_bssid() {
        let frame = make_beacon_frame();
        let addr2 = frame.addr2().unwrap();
        assert_eq!(addr2.as_bytes(), &[0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
    }

    #[test]
    fn test_rxframe_addr3_bssid() {
        let frame = make_beacon_frame();
        let addr3 = frame.addr3().unwrap();
        assert_eq!(addr3.as_bytes(), &[0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE0]);
    }

    #[test]
    fn test_rxframe_too_short_returns_none() {
        let frame = RxFrame { data: vec![0x80], rssi: 0, channel: 1, band: 0, timestamp: Duration::ZERO, ..Default::default() };
        assert!(frame.addr1().is_none());
        assert!(frame.addr2().is_none());
        assert!(frame.addr3().is_none());
        assert_eq!(frame.frame_control(), 0); // not enough bytes
    }

    #[test]
    fn test_txoptions_default() {
        let opts = TxOptions::default();
        assert_eq!(opts.rate, TxRate::Ofdm6m);
        assert_eq!(opts.retries, 12);
    }

    #[test]
    fn test_txrate_hw_rate() {
        assert_eq!(TxRate::Ofdm6m.hw_rate(), 0x0C);
        assert_eq!(TxRate::Cck1m.hw_rate(), 0x02);
        assert_eq!(TxRate::Ofdm54m.hw_rate(), 0x6C);
    }

    #[test]
    fn test_txrate_is_cck() {
        assert!(TxRate::Cck1m.is_cck());
        assert!(TxRate::Cck11m.is_cck());
        assert!(!TxRate::Ofdm6m.is_cck());
        assert!(!TxRate::Ofdm54m.is_cck());
    }

    #[test]
    fn test_txflags_contains() {
        let flags = TxFlags::NO_ACK | TxFlags::HW_SEQ;
        assert!(flags.contains(TxFlags::NO_ACK));
        assert!(flags.contains(TxFlags::HW_SEQ));
        assert!(!flags.contains(TxFlags::NO_RETRY));
    }
}
