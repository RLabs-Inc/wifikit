#![allow(dead_code)]
//! ProbeReq — tracked per (MAC, SSID) pair.

use std::time::Instant;

use crate::core::MacAddress;

// ═══════════════════════════════════════════════════════════════════════════════
//  Probe Request — tracked per (MAC, SSID) pair
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ProbeReq {
    pub sta_mac: MacAddress,
    pub ssid: String,
    pub rssi: i8,
    pub channel: u8,
    pub count: u32,
    pub first_seen: Instant,
    pub last_seen: Instant,
}
