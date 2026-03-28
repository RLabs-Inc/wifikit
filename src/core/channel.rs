#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Band {
    Band2g,
    Band5g,
    Band6g,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bandwidth {
    Bw20,
    Bw40,
    Bw80,
    Bw160,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Channel {
    pub number: u8,
    pub band: Band,
    pub bandwidth: Bandwidth,
    pub center_freq_mhz: u16,
}

impl Channel {
    /// Create a Channel from a channel number.
    /// Valid 2.4GHz: 1-14, valid 5GHz: 36-177, valid 6GHz: 1-233 (mapped via UNII bands).
    /// Channel 0 and invalid numbers (15-35) default to channel 1 (2412 MHz).
    pub fn new(number: u8) -> Self {
        let (band, freq) = match number {
            1..=14 => (Band::Band2g, 2407 + (number as u16) * 5),
            36..=177 => (Band::Band5g, 5000 + (number as u16) * 5),
            // Channels 15-35 and 0 are invalid — default to ch1 frequency.
            // Channels 178+ could be 6GHz in future; treat as 5GHz best-effort.
            0 | 15..=35 => (Band::Band2g, 2412),
            _ => (Band::Band5g, 5000 + (number as u16) * 5),
        };
        Self {
            number,
            band,
            bandwidth: Bandwidth::Bw20,
            center_freq_mhz: freq,
        }
    }

    /// Try to create a Channel, returning None for invalid channel numbers.
    /// Valid channels: 1-14 (2.4GHz), 36-177 (5GHz).
    pub fn try_new(number: u8) -> Option<Self> {
        match number {
            1..=14 | 36..=177 => Some(Self::new(number)),
            _ => None,
        }
    }

    /// Create a 6 GHz channel from a channel number.
    /// 6 GHz channels: 1, 5, 9, ..., 233 (center freq = 5950 + number * 5)
    pub fn new_6ghz(number: u8) -> Self {
        Self {
            number,
            band: Band::Band6g,
            bandwidth: Bandwidth::Bw20,
            center_freq_mhz: 5950 + (number as u16) * 5,
        }
    }

    pub fn with_bandwidth(mut self, bw: Bandwidth) -> Self {
        self.bandwidth = bw;
        self
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ch{}", self.number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_new_2ghz() {
        let ch = Channel::new(6);
        assert_eq!(ch.number, 6);
        assert_eq!(ch.band, Band::Band2g);
        assert_eq!(ch.center_freq_mhz, 2437);
        assert_eq!(ch.bandwidth, Bandwidth::Bw20);
    }

    #[test]
    fn test_channel_new_5ghz() {
        let ch = Channel::new(36);
        assert_eq!(ch.number, 36);
        assert_eq!(ch.band, Band::Band5g);
        assert_eq!(ch.center_freq_mhz, 5180);
    }

    #[test]
    fn test_channel_new_5ghz_high() {
        let ch = Channel::new(165);
        assert_eq!(ch.number, 165);
        assert_eq!(ch.band, Band::Band5g);
        assert_eq!(ch.center_freq_mhz, 5825);
    }

    #[test]
    fn test_channel_new_channel1() {
        let ch = Channel::new(1);
        assert_eq!(ch.center_freq_mhz, 2412);
    }

    #[test]
    fn test_channel_new_channel14() {
        let ch = Channel::new(14);
        assert_eq!(ch.band, Band::Band2g);
        assert_eq!(ch.center_freq_mhz, 2477);
    }

    #[test]
    fn test_channel_new_invalid_defaults() {
        // Invalid channels 0 and 15-35 default to ch1 frequency
        let ch0 = Channel::new(0);
        assert_eq!(ch0.center_freq_mhz, 2412);
        let ch20 = Channel::new(20);
        assert_eq!(ch20.center_freq_mhz, 2412);
    }

    #[test]
    fn test_channel_try_new_valid() {
        assert!(Channel::try_new(1).is_some());
        assert!(Channel::try_new(11).is_some());
        assert!(Channel::try_new(36).is_some());
        assert!(Channel::try_new(165).is_some());
    }

    #[test]
    fn test_channel_try_new_invalid() {
        assert!(Channel::try_new(0).is_none());
        assert!(Channel::try_new(15).is_none());
        assert!(Channel::try_new(35).is_none());
    }

    #[test]
    fn test_channel_with_bandwidth() {
        let ch = Channel::new(36).with_bandwidth(Bandwidth::Bw80);
        assert_eq!(ch.bandwidth, Bandwidth::Bw80);
        assert_eq!(ch.number, 36); // unchanged
    }

    #[test]
    fn test_channel_display() {
        assert_eq!(Channel::new(6).to_string(), "ch6");
        assert_eq!(Channel::new(149).to_string(), "ch149");
    }
}
