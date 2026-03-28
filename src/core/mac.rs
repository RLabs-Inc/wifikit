use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = Self([0x00; 6]);

    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() >= 6 {
            let mut bytes = [0u8; 6];
            bytes.copy_from_slice(&slice[..6]);
            Some(Self(bytes))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    pub fn randomized(oui: [u8; 3]) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        // Simple xoshiro-derived random
        let mut s = seed;
        let mut bytes = [0u8; 6];
        bytes[0] = oui[0];
        bytes[1] = oui[1];
        bytes[2] = oui[2];
        for b in &mut bytes[3..] {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = (s & 0xFF) as u8;
        }
        Self(bytes)
    }

    pub fn randomized_with_seed(oui: [u8; 3], seed: u64) -> Self {
        let mut s = seed;
        let mut bytes = [0u8; 6];
        bytes[0] = oui[0];
        bytes[1] = oui[1];
        bytes[2] = oui[2];
        for b in &mut bytes[3..] {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = (s & 0xFF) as u8;
        }
        Self(bytes)
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_display() {
        let mac = MacAddress::new([0x7C, 0x10, 0xC9, 0x03, 0x10, 0xE4]);
        assert_eq!(format!("{mac}"), "7C:10:C9:03:10:E4");
    }

    #[test]
    fn test_mac_broadcast() {
        assert!(MacAddress::BROADCAST.is_broadcast());
        assert!(MacAddress::BROADCAST.is_multicast());
    }

    #[test]
    fn test_mac_oui() {
        let mac = MacAddress::new([0x8C, 0x88, 0x2B, 0x01, 0x02, 0x03]);
        assert_eq!(mac.oui(), [0x8C, 0x88, 0x2B]);
    }

    #[test]
    fn test_mac_randomized_with_seed_deterministic() {
        let a = MacAddress::randomized_with_seed([0x8C, 0x88, 0x2B], 42);
        let b = MacAddress::randomized_with_seed([0x8C, 0x88, 0x2B], 42);
        assert_eq!(a, b);
    }
}
