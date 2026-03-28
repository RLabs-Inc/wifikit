// WiFi Attack Taxonomy — the north star for wifikit
//
// Every known WiFi attack type, organized by category.
// Each variant maps to a specific attack module.
// Implementation status tracked per variant.
#![allow(dead_code)]
//
// Ported and expanded from wifi_attack_taxonomy.h (138 types, 22 categories).

use std::fmt;

// ============================================================================
// Capability flags — what the adapter/driver must support
// ============================================================================

use super::frame::bitflags_manual;

bitflags_manual! {
    Capability: u32 {
        MONITOR_MODE       = 1 << 0,
        PACKET_INJECTION   = 1 << 1,
        AP_MODE            = 1 << 2,
        ASSOCIATION        = 1 << 3,
        PROMISCUOUS        = 1 << 4,
        CHANNEL_HOP        = 1 << 5,
        MULTI_INTERFACE    = 1 << 6,
        BAND_5GHZ          = 1 << 7,
        BAND_6GHZ          = 1 << 8,
        HT                 = 1 << 9,
        VHT                = 1 << 10,
        HE                 = 1 << 11,
    }
}

// ============================================================================
// Attack categories
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Reconnaissance,
    Wep,
    WpaPsk,
    Enterprise,
    Wpa3Sae,
    Wps,
    Protocol,
    Tkip,
    Dos,
    RogueAp,
    Mitm,
    CaptivePortal,
    MacIdentity,
    WifiDirect,
    FrameLevel,
    Fuzzing,
    PmfBypass,
    NetworkInfra,
    Advanced,
    Wifi6e7,
    SocialEngineering,
    PostExploitation,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reconnaissance => write!(f, "Reconnaissance"),
            Self::Wep => write!(f, "WEP"),
            Self::WpaPsk => write!(f, "WPA/WPA2-PSK"),
            Self::Enterprise => write!(f, "Enterprise/EAP"),
            Self::Wpa3Sae => write!(f, "WPA3/SAE"),
            Self::Wps => write!(f, "WPS"),
            Self::Protocol => write!(f, "Protocol"),
            Self::Tkip => write!(f, "TKIP"),
            Self::Dos => write!(f, "DoS"),
            Self::RogueAp => write!(f, "Rogue AP"),
            Self::Mitm => write!(f, "MitM"),
            Self::CaptivePortal => write!(f, "Captive Portal"),
            Self::MacIdentity => write!(f, "MAC/Identity"),
            Self::WifiDirect => write!(f, "WiFi Direct"),
            Self::FrameLevel => write!(f, "Frame-Level"),
            Self::Fuzzing => write!(f, "Fuzzing"),
            Self::PmfBypass => write!(f, "PMF Bypass"),
            Self::NetworkInfra => write!(f, "Network Infra"),
            Self::Advanced => write!(f, "Advanced"),
            Self::Wifi6e7 => write!(f, "WiFi 6/6E/7"),
            Self::SocialEngineering => write!(f, "Social Engineering"),
            Self::PostExploitation => write!(f, "Post-Exploitation"),
        }
    }
}

// ============================================================================
// Implementation status — honest tracking
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Fully implemented and tested in C, ready to port
    PortFromC,
    /// Not yet implemented anywhere — new code needed
    NotImplemented,
    /// Stub exists in C but not real implementation
    Stub,
    /// Requires infrastructure we don't have (L3 stack, SDR, etc.)
    NeedsInfra,
    /// Ported to Rust and working
    Done,
}

// ============================================================================
// The attack enum — every known WiFi attack type
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackType {
    // === 1. RECONNAISSANCE (7) ===
    // Rust module: engine/scanner.rs
    PassiveScan,
    HiddenSsidReveal,
    ClientEnumeration,
    ProbeRequestTracking,
    DeviceFingerprinting,
    PassiveHandshakeCapture,
    TrafficAnalysis,
    SignalStrengthMapping,

    // === 2. WEP (9) ===
    // Rust module: attacks/wep.rs (NEW)
    WepFms,
    WepKorek,
    WepPtw,
    WepArpReplay,
    WepInteractiveReplay,
    WepChopchop,
    WepFragmentation,
    WepCaffeLatte,
    WepHirte,
    WepFakeAuth,

    // === 3. WPA/WPA2-PSK (4) ===
    // Rust module: attacks/pmkid.rs + engine/capture.rs
    WpaHandshakeCapture,
    WpaDictionary,
    WpaBruteforce,
    WpaRainbowTable,
    WpaPmkid,

    // === 4. ENTERPRISE/EAP (6) ===
    // Rust module: attacks/eap.rs
    EnterpriseEvilTwin,
    EnterpriseEapDowngrade,
    EnterpriseCredentialHarvest,
    EnterprisePeapRelay,
    EnterpriseCertBypass,
    EnterpriseIdentityTheft,

    // === 5. WPA3/SAE (7) ===
    // Rust module: attacks/wpa3.rs
    Wpa3TimingSideChannel,
    Wpa3CacheSideChannel,
    Wpa3GroupDowngrade,
    Wpa3SaeDos,
    Wpa3InvalidCurve,
    Wpa3PasswordPartition,
    Wpa3TransitionDowngrade,

    // === 6. WPS (4) ===
    // Rust module: attacks/wps.rs
    WpsPinBruteforce,
    WpsPixieDust,
    WpsNullPin,
    WpsPinLockoutBypass,

    // === 7. PROTOCOL (11) ===
    // Rust module: attacks/krack.rs, attacks/frag.rs, attacks/protocol.rs (NEW)
    Krack4wayHandshake,
    KrackGroupKey,
    KrackFtReassociation,
    KrackTdls,
    KrackWnmSleep,
    FragAggregationDesign,
    FragMixedKey,
    FragFragmentCache,
    FragPlaintextInjection,
    FragAmsduInjection,
    SsidConfusion,
    MacStealer,
    Airsnitch,
    Hole196,

    // === 8. TKIP (4) ===
    // Rust module: attacks/tkip.rs (NEW)
    TkipBeckTews,
    TkipOhigashiMorii,
    TkipMichaelShutdown,
    TkipSideChannel,

    // === 9. DoS (15) ===
    // Rust module: attacks/dos.rs
    DeauthFlood,
    DeauthTargeted,
    DisassocFlood,
    AuthFlood,
    AssocFlood,
    BeaconFlood,
    ProbeFlood,
    RfJamming,
    SelectiveJamming,
    CtsFlood,
    RtsFlood,
    NavManipulation,
    FtReassocDos,
    BssTransitionDos,
    PowerSaveDos,

    // === 10. ROGUE AP (6) ===
    // Rust module: attacks/ap.rs
    EvilTwinOpen,
    EvilTwinCaptivePortal,
    Karma,
    ManaLoud,
    KnownBeacons,
    HostilePortal,

    // === 11. MitM (8) ===
    // Rust module: engine/mitm.rs + engine/l3.rs (NEW)
    ArpSpoofing,
    DnsSpoofing,
    DhcpSpoofing,
    Dhcpv6Spoofing,
    NdpSpoofing,
    SslStrip,
    HstsBypass,
    WpadInjection,
    CredentialSniffing,

    // === 12. CAPTIVE PORTAL BYPASS (5) ===
    // Rust module: attacks/portal.rs (NEW)
    CaptivePortalMacClone,
    CaptivePortalDnsTunnel,
    CaptivePortalIcmpTunnel,
    CaptivePortalSessionHijack,
    CaptivePortalHttpTunnel,

    // === 13. MAC/IDENTITY (3) ===
    // Rust module: core/mac.rs + attacks/dos.rs
    MacSpoofing,
    MacFilterBypass,
    MacRandomizationDefeat,

    // === 14. WiFi Direct (3) ===
    // Rust module: attacks/wifi_direct.rs (NEW)
    WifiDirectDeauth,
    WifiDirectEvilTwin,
    WifiDirectPinBruteforce,

    // === 15. 802.11n/ac/ax FRAME-LEVEL (5) ===
    // Rust module: attacks/frame_attacks.rs (NEW)
    AmsduInjection,
    AmpduInjection,
    OfdmaResourceExhaust,
    BssColoringConfusion,
    TwtManipulation,

    // === 16. FUZZING (5) ===
    // Rust module: attacks/fuzz.rs
    ManagementFrameFuzz,
    EapFuzz,
    IeOverflow,
    FirmwareOtaExploit,
    WifiCoexistenceEscalation,

    // === 17. PMF BYPASS (4) ===
    // Rust module: attacks/pmf.rs (NEW)
    PmfDowngrade,
    PmfSaQueryFlood,
    PmfCsaAbuse,
    PmfTimingAttack,

    // === 18. NETWORK INFRA (4) ===
    // Rust module: attacks/infra.rs (NEW) — needs L3 stack
    RogueRadius,
    VlanHopping,
    ApFirmwareExploit,
    UpnpExploit,

    // === 19. ADVANCED (7) ===
    // Rust module: attacks/advanced.rs (NEW)
    ChannelBasedMitm,
    TimingBasedTracking,
    CsiBasedSensing,
    RfFingerprinting,
    SsidStripping,
    BeaconStuffing,
    DeauthRaceCondition,

    // === 20. WiFi 6/6E/7 (5) ===
    // Rust module: attacks/wifi67.rs (NEW)
    Wifi6MuMimoAbuse,
    Wifi6e6ghzDiscovery,
    Wifi7MloConfusion,
    Wifi7_4096qamAmplification,
    WifiSensingPrivacy,

    // === 21. SOCIAL ENGINEERING (3) ===
    // Rust module: attacks/social.rs (NEW) — needs L3 + web server
    CredentialPhishingPortal,
    FirmwareUpdatePhishing,
    OauthPhishing,

    // === 22. POST-EXPLOITATION (3) ===
    // Rust module: attacks/post_exploit.rs (NEW) — needs L3 stack
    WirelessPivot,
    CredentialRelayNtlm,
    WifiCovertChannel,
}

// ============================================================================
// Attack metadata — the roadmap
// ============================================================================

pub struct AttackMeta {
    pub attack: AttackType,
    pub name: &'static str,
    pub description: &'static str,
    pub category: Category,
    pub required_caps: Capability,
    pub status: Status,
    pub rust_module: &'static str,
    pub cve: &'static str,
}

impl AttackType {
    pub fn meta(&self) -> AttackMeta {
        use AttackType::*;
        use Category::*;
        use Status::*;
        let m = Capability::MONITOR_MODE;
        let i = Capability::PACKET_INJECTION;
        let a = Capability::AP_MODE;
        let s = Capability::ASSOCIATION;
        let mi = Capability::MULTI_INTERFACE;

        match self {
            // === 1. RECONNAISSANCE ===
            PassiveScan => AttackMeta {
                attack: *self, name: "passive_scan",
                description: "Capture beacons/probe responses to enumerate APs",
                category: Reconnaissance, required_caps: m,
                status: PortFromC, rust_module: "engine::scanner", cve: "",
            },
            HiddenSsidReveal => AttackMeta {
                attack: *self, name: "hidden_ssid_reveal",
                description: "Discover hidden SSIDs from probe requests/responses",
                category: Reconnaissance, required_caps: m,
                status: PortFromC, rust_module: "engine::scanner", cve: "",
            },
            ClientEnumeration => AttackMeta {
                attack: *self, name: "client_enumeration",
                description: "Discover associated clients per AP from data/management frames",
                category: Reconnaissance, required_caps: m,
                status: PortFromC, rust_module: "engine::scanner", cve: "",
            },
            ProbeRequestTracking => AttackMeta {
                attack: *self, name: "probe_request_tracking",
                description: "Track devices via probe request patterns and PNL",
                category: Reconnaissance, required_caps: m,
                status: PortFromC, rust_module: "engine::scanner", cve: "",
            },
            DeviceFingerprinting => AttackMeta {
                attack: *self, name: "device_fingerprinting",
                description: "Identify device type/driver/OS from 802.11 frame characteristics",
                category: Reconnaissance, required_caps: m,
                status: Stub, rust_module: "engine::scanner", cve: "",
            },
            PassiveHandshakeCapture => AttackMeta {
                attack: *self, name: "passive_handshake_capture",
                description: "Wait for natural WPA 4-way handshake",
                category: Reconnaissance, required_caps: m,
                status: PortFromC, rust_module: "engine::capture", cve: "",
            },
            TrafficAnalysis => AttackMeta {
                attack: *self, name: "traffic_analysis",
                description: "Analyze encrypted traffic patterns without decryption",
                category: Reconnaissance, required_caps: m,
                status: NotImplemented, rust_module: "engine::scanner", cve: "",
            },
            SignalStrengthMapping => AttackMeta {
                attack: *self, name: "signal_strength_mapping",
                description: "Map physical locations of APs/clients via RSSI",
                category: Reconnaissance, required_caps: m,
                status: Stub, rust_module: "engine::scanner", cve: "",
            },

            // === 2. WEP ===
            WepFms => AttackMeta {
                attack: *self, name: "wep_fms",
                description: "FMS statistical attack on RC4 key scheduling (~5M IVs)",
                category: Wep, required_caps: m | i,
                status: NotImplemented, rust_module: "attacks::wep", cve: "",
            },
            WepKorek => AttackMeta {
                attack: *self, name: "wep_korek",
                description: "17 statistical attacks improving on FMS (~700K IVs)",
                category: Wep, required_caps: m | i,
                status: NotImplemented, rust_module: "attacks::wep", cve: "",
            },
            WepPtw => AttackMeta {
                attack: *self, name: "wep_ptw",
                description: "Pyshkin-Tews-Weinmann, most efficient WEP attack (~40K pkts)",
                category: Wep, required_caps: m | i,
                status: NotImplemented, rust_module: "attacks::wep", cve: "",
            },
            WepArpReplay => AttackMeta {
                attack: *self, name: "wep_arp_replay",
                description: "Replay ARP requests to generate IV traffic",
                category: Wep, required_caps: m | i,
                status: NotImplemented, rust_module: "attacks::wep", cve: "",
            },
            WepInteractiveReplay => AttackMeta {
                attack: *self, name: "wep_interactive_replay",
                description: "Choose specific packet to replay for traffic generation",
                category: Wep, required_caps: m | i,
                status: NotImplemented, rust_module: "attacks::wep", cve: "",
            },
            WepChopchop => AttackMeta {
                attack: *self, name: "wep_chopchop",
                description: "Decrypt WEP packet byte-by-byte without knowing the key",
                category: Wep, required_caps: m | i,
                status: NotImplemented, rust_module: "attacks::wep", cve: "",
            },
            WepFragmentation => AttackMeta {
                attack: *self, name: "wep_fragmentation",
                description: "Obtain keystream from single packet, inject via fragments",
                category: Wep, required_caps: m | i,
                status: NotImplemented, rust_module: "attacks::wep", cve: "",
            },
            WepCaffeLatte => AttackMeta {
                attack: *self, name: "wep_caffe_latte",
                description: "Recover WEP key from disconnected client (no AP needed)",
                category: Wep, required_caps: m | i | a,
                status: Stub, rust_module: "attacks::wep", cve: "",
            },
            WepHirte => AttackMeta {
                attack: *self, name: "wep_hirte",
                description: "Fast WEP key recovery via fragmentation (no AP needed)",
                category: Wep, required_caps: m | i | a,
                status: Stub, rust_module: "attacks::wep", cve: "",
            },
            WepFakeAuth => AttackMeta {
                attack: *self, name: "wep_fake_auth",
                description: "Fake authentication with AP to enable injection",
                category: Wep, required_caps: i,
                status: NotImplemented, rust_module: "attacks::wep", cve: "",
            },

            // === 3. WPA/WPA2-PSK ===
            WpaHandshakeCapture => AttackMeta {
                attack: *self, name: "wpa_handshake_capture",
                description: "Force and capture WPA 4-way handshake for offline cracking",
                category: WpaPsk, required_caps: m | i,
                status: PortFromC, rust_module: "engine::capture", cve: "",
            },
            WpaDictionary => AttackMeta {
                attack: *self, name: "wpa_dictionary",
                description: "Offline dictionary attack against captured handshake",
                category: WpaPsk, required_caps: Capability::empty(),
                status: PortFromC, rust_module: "engine::export", cve: "",
            },
            WpaBruteforce => AttackMeta {
                attack: *self, name: "wpa_bruteforce",
                description: "Exhaustive key space search (GPU-accelerated offline)",
                category: WpaPsk, required_caps: Capability::empty(),
                status: PortFromC, rust_module: "engine::export", cve: "",
            },
            WpaRainbowTable => AttackMeta {
                attack: *self, name: "wpa_rainbow_table",
                description: "Pre-computed PMK tables for common SSIDs",
                category: WpaPsk, required_caps: Capability::empty(),
                status: NotImplemented, rust_module: "engine::export", cve: "",
            },
            WpaPmkid => AttackMeta {
                attack: *self, name: "wpa_pmkid",
                description: "Extract PMKID from AP's first EAPOL message — no client needed",
                category: WpaPsk, required_caps: m | i,
                status: PortFromC, rust_module: "attacks::pmkid", cve: "",
            },

            // === 4. ENTERPRISE ===
            EnterpriseEvilTwin => AttackMeta {
                attack: *self, name: "enterprise_evil_twin",
                description: "Rogue AP mimicking enterprise SSID with fake RADIUS",
                category: Enterprise, required_caps: a | i,
                status: PortFromC, rust_module: "attacks::eap", cve: "",
            },
            EnterpriseEapDowngrade => AttackMeta {
                attack: *self, name: "enterprise_eap_downgrade",
                description: "Force client to use weaker EAP method (e.g. GTC plaintext)",
                category: Enterprise, required_caps: a,
                status: PortFromC, rust_module: "attacks::eap", cve: "",
            },
            EnterpriseCredentialHarvest => AttackMeta {
                attack: *self, name: "enterprise_credential_harvest",
                description: "Capture MSCHAPv2 challenge/response hashes",
                category: Enterprise, required_caps: a,
                status: PortFromC, rust_module: "attacks::eap", cve: "",
            },
            EnterprisePeapRelay => AttackMeta {
                attack: *self, name: "enterprise_peap_relay",
                description: "Relay PEAP authentication to legitimate RADIUS server",
                category: Enterprise, required_caps: a,
                status: Stub, rust_module: "attacks::eap", cve: "",
            },
            EnterpriseCertBypass => AttackMeta {
                attack: *self, name: "enterprise_cert_bypass",
                description: "Exploit clients that don't validate RADIUS server certs",
                category: Enterprise, required_caps: a,
                status: NotImplemented, rust_module: "attacks::eap", cve: "",
            },
            EnterpriseIdentityTheft => AttackMeta {
                attack: *self, name: "enterprise_identity_theft",
                description: "Capture EAP identities from unencrypted EAP-Identity frames",
                category: Enterprise, required_caps: m,
                status: PortFromC, rust_module: "attacks::eap", cve: "",
            },

            // === 5. WPA3/SAE ===
            Wpa3TimingSideChannel => AttackMeta {
                attack: *self, name: "wpa3_timing_side_channel",
                description: "Recover password via timing analysis of SAE handshake",
                category: Wpa3Sae, required_caps: s,
                status: PortFromC, rust_module: "attacks::wpa3",
                cve: "CVE-2019-9494",
            },
            Wpa3CacheSideChannel => AttackMeta {
                attack: *self, name: "wpa3_cache_side_channel",
                description: "Recover password via microarchitectural cache-timing",
                category: Wpa3Sae, required_caps: Capability::empty(),
                status: NeedsInfra, rust_module: "attacks::wpa3",
                cve: "CVE-2019-9494",
            },
            Wpa3GroupDowngrade => AttackMeta {
                attack: *self, name: "wpa3_group_downgrade",
                description: "Force weaker elliptic curve group during SAE handshake",
                category: Wpa3Sae, required_caps: i,
                status: PortFromC, rust_module: "attacks::wpa3",
                cve: "CVE-2019-9495",
            },
            Wpa3SaeDos => AttackMeta {
                attack: *self, name: "wpa3_sae_dos",
                description: "Resource exhaustion via SAE commit flooding",
                category: Wpa3Sae, required_caps: i,
                status: PortFromC, rust_module: "attacks::wpa3",
                cve: "CVE-2019-9497",
            },
            Wpa3InvalidCurve => AttackMeta {
                attack: *self, name: "wpa3_invalid_curve",
                description: "Send points on invalid elliptic curve during SAE exchange",
                category: Wpa3Sae, required_caps: i | s,
                status: PortFromC, rust_module: "attacks::wpa3",
                cve: "CVE-2019-9498/9499",
            },
            Wpa3PasswordPartition => AttackMeta {
                attack: *self, name: "wpa3_password_partition",
                description: "Combine side-channel leaks with offline dictionary search",
                category: Wpa3Sae, required_caps: Capability::empty(),
                status: NotImplemented, rust_module: "attacks::wpa3", cve: "",
            },
            Wpa3TransitionDowngrade => AttackMeta {
                attack: *self, name: "wpa3_transition_downgrade",
                description: "Force WPA3 network to use WPA2 via transition mode",
                category: Wpa3Sae, required_caps: a | i,
                status: PortFromC, rust_module: "attacks::wpa3",
                cve: "CVE-2019-9496",
            },

            // === 6. WPS ===
            WpsPinBruteforce => AttackMeta {
                attack: *self, name: "wps_pin_bruteforce",
                description: "Online brute force of WPS PIN (11K combinations)",
                category: Wps, required_caps: s,
                status: PortFromC, rust_module: "attacks::wps", cve: "",
            },
            WpsPixieDust => AttackMeta {
                attack: *self, name: "wps_pixie_dust",
                description: "Offline WPS PIN recovery via weak RNG in chipsets",
                category: Wps, required_caps: s,
                status: PortFromC, rust_module: "attacks::wps", cve: "",
            },
            WpsNullPin => AttackMeta {
                attack: *self, name: "wps_null_pin",
                description: "Some routers accept empty/null PIN",
                category: Wps, required_caps: s,
                status: PortFromC, rust_module: "attacks::wps", cve: "",
            },
            WpsPinLockoutBypass => AttackMeta {
                attack: *self, name: "wps_pin_lockout_bypass",
                description: "Bypass WPS lockout timer via MAC rotation and timing",
                category: Wps, required_caps: s,
                status: PortFromC, rust_module: "attacks::wps", cve: "",
            },

            // === 7. PROTOCOL ===
            Krack4wayHandshake => AttackMeta {
                attack: *self, name: "krack_4way",
                description: "Reinstall PTK by replaying message 3 of 4-way handshake",
                category: Protocol, required_caps: m | i | mi,
                status: PortFromC, rust_module: "attacks::krack",
                cve: "CVE-2017-13077/78",
            },
            KrackGroupKey => AttackMeta {
                attack: *self, name: "krack_group_key",
                description: "Reinstall GTK by replaying group key handshake message 1",
                category: Protocol, required_caps: m | i | mi,
                status: PortFromC, rust_module: "attacks::krack",
                cve: "CVE-2017-13080",
            },
            KrackFtReassociation => AttackMeta {
                attack: *self, name: "krack_ft_reassociation",
                description: "Reinstall PTK during 802.11r Fast BSS Transition",
                category: Protocol, required_caps: m | i | mi,
                status: PortFromC, rust_module: "attacks::krack",
                cve: "CVE-2017-13082",
            },
            KrackTdls => AttackMeta {
                attack: *self, name: "krack_tdls",
                description: "Key reinstallation in TDLS handshake",
                category: Protocol, required_caps: m | i | mi,
                status: PortFromC, rust_module: "attacks::krack",
                cve: "CVE-2017-13086",
            },
            KrackWnmSleep => AttackMeta {
                attack: *self, name: "krack_wnm_sleep",
                description: "Key reinstallation via WNM Sleep Mode response replay",
                category: Protocol, required_caps: m | i | mi,
                status: PortFromC, rust_module: "attacks::krack",
                cve: "CVE-2017-13087/88",
            },
            FragAggregationDesign => AttackMeta {
                attack: *self, name: "frag_aggregation_design",
                description: "A-MSDU flag not authenticated — inject via aggregation",
                category: Protocol, required_caps: m | i,
                status: PortFromC, rust_module: "attacks::frag",
                cve: "CVE-2020-24588",
            },
            FragMixedKey => AttackMeta {
                attack: *self, name: "frag_mixed_key",
                description: "Reassemble fragments encrypted under different keys",
                category: Protocol, required_caps: m | i,
                status: PortFromC, rust_module: "attacks::frag",
                cve: "CVE-2020-24587",
            },
            FragFragmentCache => AttackMeta {
                attack: *self, name: "frag_fragment_cache",
                description: "Inject frames by poisoning AP reassembly cache",
                category: Protocol, required_caps: m | i,
                status: PortFromC, rust_module: "attacks::frag",
                cve: "CVE-2020-24586",
            },
            FragPlaintextInjection => AttackMeta {
                attack: *self, name: "frag_plaintext_injection",
                description: "Inject plaintext frames processed as if encrypted",
                category: Protocol, required_caps: m | i,
                status: PortFromC, rust_module: "attacks::frag",
                cve: "CVE-2020-26140/44/45",
            },
            FragAmsduInjection => AttackMeta {
                attack: *self, name: "frag_amsdu_injection",
                description: "A-MSDU frame accepted as handshake frame or in plaintext",
                category: Protocol, required_caps: m | i,
                status: PortFromC, rust_module: "attacks::frag",
                cve: "CVE-2020-26139/41/43",
            },
            SsidConfusion => AttackMeta {
                attack: *self, name: "ssid_confusion",
                description: "Trick client into connecting to wrong network",
                category: Protocol, required_caps: a | i | mi,
                status: NotImplemented, rust_module: "attacks::protocol",
                cve: "CVE-2023-52424",
            },
            MacStealer => AttackMeta {
                attack: *self, name: "macstealer",
                description: "WiFi client isolation bypass via MAC address stealing",
                category: Protocol, required_caps: s | m,
                status: NotImplemented, rust_module: "attacks::protocol",
                cve: "CVE-2022-47522",
            },
            Airsnitch => AttackMeta {
                attack: *self, name: "airsnitch",
                description: "Generalized client isolation bypass (extends MacStealer)",
                category: Protocol, required_caps: s | m,
                status: NotImplemented, rust_module: "attacks::protocol", cve: "",
            },
            Hole196 => AttackMeta {
                attack: *self, name: "hole196",
                description: "WPA2 insider attack via shared GTK — ARP poison without deauth",
                category: Protocol, required_caps: s,
                status: NotImplemented, rust_module: "attacks::protocol", cve: "",
            },

            // === 8. TKIP ===
            TkipBeckTews => AttackMeta {
                attack: *self, name: "tkip_beck_tews",
                description: "Decrypt and inject short packets on TKIP networks",
                category: Tkip, required_caps: m | i,
                status: NotImplemented, rust_module: "attacks::tkip", cve: "",
            },
            TkipOhigashiMorii => AttackMeta {
                attack: *self, name: "tkip_ohigashi_morii",
                description: "Faster TKIP injection via MitM (no QoS requirement)",
                category: Tkip, required_caps: m | i | mi,
                status: NotImplemented, rust_module: "attacks::tkip", cve: "",
            },
            TkipMichaelShutdown => AttackMeta {
                attack: *self, name: "tkip_michael_shutdown",
                description: "Trigger Michael countermeasures for 60-second network shutdown",
                category: Tkip, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            TkipSideChannel => AttackMeta {
                attack: *self, name: "tkip_side_channel",
                description: "Side-channel attacks on RC4 in TKIP",
                category: Tkip, required_caps: m,
                status: NotImplemented, rust_module: "attacks::tkip", cve: "",
            },

            // === 9. DoS ===
            DeauthFlood => AttackMeta {
                attack: *self, name: "deauth_flood",
                description: "Mass deauthentication frame flood",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            DeauthTargeted => AttackMeta {
                attack: *self, name: "deauth_targeted",
                description: "Targeted deauthentication of specific client",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            DisassocFlood => AttackMeta {
                attack: *self, name: "disassoc_flood",
                description: "Disassociation frame flood",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            AuthFlood => AttackMeta {
                attack: *self, name: "auth_flood",
                description: "Authentication frame flood — overwhelm AP association table",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            AssocFlood => AttackMeta {
                attack: *self, name: "assoc_flood",
                description: "Association request flood — exhaust AP client table",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            BeaconFlood => AttackMeta {
                attack: *self, name: "beacon_flood",
                description: "Flood airspace with thousands of fake beacon frames",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            ProbeFlood => AttackMeta {
                attack: *self, name: "probe_flood",
                description: "Flood with probe request/response frames",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            RfJamming => AttackMeta {
                attack: *self, name: "rf_jamming",
                description: "Continuous wave or noise jamming (requires SDR)",
                category: Dos, required_caps: Capability::empty(),
                status: NeedsInfra, rust_module: "attacks::dos", cve: "",
            },
            SelectiveJamming => AttackMeta {
                attack: *self, name: "selective_jamming",
                description: "Jam only specific frame types or stations (requires SDR)",
                category: Dos, required_caps: Capability::empty(),
                status: NeedsInfra, rust_module: "attacks::dos", cve: "",
            },
            CtsFlood => AttackMeta {
                attack: *self, name: "cts_flood",
                description: "CTS frame flood — silence all stations via NAV timer",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            RtsFlood => AttackMeta {
                attack: *self, name: "rts_flood",
                description: "RTS flood with large duration — reserve medium",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            NavManipulation => AttackMeta {
                attack: *self, name: "nav_manipulation",
                description: "Set large NAV in data frames — virtual jamming",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            FtReassocDos => AttackMeta {
                attack: *self, name: "ft_reassoc_dos",
                description: "Malicious 802.11r reassociation causing AP crash",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            BssTransitionDos => AttackMeta {
                attack: *self, name: "bss_transition_dos",
                description: "Abuse 802.11v BTM to force client roaming",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            PowerSaveDos => AttackMeta {
                attack: *self, name: "power_save_dos",
                description: "Abuse power save protocol to drop buffered frames",
                category: Dos, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },

            // === 10. ROGUE AP ===
            EvilTwinOpen => AttackMeta {
                attack: *self, name: "evil_twin_open",
                description: "Clone target AP as open network, deauth clients",
                category: RogueAp, required_caps: a | i | mi,
                status: PortFromC, rust_module: "attacks::ap", cve: "",
            },
            EvilTwinCaptivePortal => AttackMeta {
                attack: *self, name: "evil_twin_captive_portal",
                description: "Evil twin with phishing captive portal",
                category: RogueAp, required_caps: a | i,
                status: NeedsInfra, rust_module: "attacks::ap", cve: "",
            },
            Karma => AttackMeta {
                attack: *self, name: "karma",
                description: "Respond to ALL probe requests with matching SSID",
                category: RogueAp, required_caps: a | m,
                status: PortFromC, rust_module: "attacks::ap", cve: "",
            },
            ManaLoud => AttackMeta {
                attack: *self, name: "mana_loud",
                description: "Enhanced KARMA: broadcast observed SSIDs as beacons",
                category: RogueAp, required_caps: a | m,
                status: PortFromC, rust_module: "attacks::ap", cve: "",
            },
            KnownBeacons => AttackMeta {
                attack: *self, name: "known_beacons",
                description: "Broadcast thousands of common SSIDs to trigger auto-connect",
                category: RogueAp, required_caps: a,
                status: PortFromC, rust_module: "attacks::ap", cve: "",
            },
            HostilePortal => AttackMeta {
                attack: *self, name: "hostile_portal",
                description: "Rogue AP serving exploit payloads via captive portal",
                category: RogueAp, required_caps: a,
                status: NeedsInfra, rust_module: "attacks::ap", cve: "",
            },

            // === 11. MitM ===
            ArpSpoofing => AttackMeta {
                attack: *self, name: "arp_spoofing",
                description: "ARP cache poisoning to redirect traffic",
                category: Mitm, required_caps: s,
                status: NeedsInfra, rust_module: "engine::l3", cve: "",
            },
            DnsSpoofing => AttackMeta {
                attack: *self, name: "dns_spoofing",
                description: "Serve false DNS responses to redirect traffic",
                category: Mitm, required_caps: s,
                status: NeedsInfra, rust_module: "engine::l3", cve: "",
            },
            DhcpSpoofing => AttackMeta {
                attack: *self, name: "dhcp_spoofing",
                description: "Rogue DHCP server to set attacker as gateway",
                category: Mitm, required_caps: s,
                status: NeedsInfra, rust_module: "engine::l3", cve: "",
            },
            Dhcpv6Spoofing => AttackMeta {
                attack: *self, name: "dhcpv6_spoofing",
                description: "IPv6 DHCP spoofing for MitM",
                category: Mitm, required_caps: s,
                status: NeedsInfra, rust_module: "engine::l3", cve: "",
            },
            NdpSpoofing => AttackMeta {
                attack: *self, name: "ndp_spoofing",
                description: "IPv6 Neighbor Discovery Protocol spoofing",
                category: Mitm, required_caps: s,
                status: NeedsInfra, rust_module: "engine::l3", cve: "",
            },
            SslStrip => AttackMeta {
                attack: *self, name: "ssl_strip",
                description: "Downgrade HTTPS to HTTP for credential interception",
                category: Mitm, required_caps: s,
                status: NeedsInfra, rust_module: "engine::l3", cve: "",
            },
            HstsBypass => AttackMeta {
                attack: *self, name: "hsts_bypass",
                description: "Bypass HSTS via domain manipulation",
                category: Mitm, required_caps: s,
                status: NeedsInfra, rust_module: "engine::l3", cve: "",
            },
            WpadInjection => AttackMeta {
                attack: *self, name: "wpad_injection",
                description: "Inject WPAD to route traffic through attacker",
                category: Mitm, required_caps: s,
                status: NeedsInfra, rust_module: "engine::l3", cve: "",
            },
            CredentialSniffing => AttackMeta {
                attack: *self, name: "credential_sniffing",
                description: "Capture cleartext credentials from network traffic",
                category: Mitm, required_caps: Capability::PROMISCUOUS,
                status: NeedsInfra, rust_module: "engine::l3", cve: "",
            },

            // === 12. CAPTIVE PORTAL BYPASS ===
            CaptivePortalMacClone => AttackMeta {
                attack: *self, name: "captive_portal_mac_clone",
                description: "Clone MAC of authenticated client to bypass portal",
                category: CaptivePortal, required_caps: m,
                status: NotImplemented, rust_module: "attacks::portal", cve: "",
            },
            CaptivePortalDnsTunnel => AttackMeta {
                attack: *self, name: "captive_portal_dns_tunnel",
                description: "Tunnel traffic through DNS queries",
                category: CaptivePortal, required_caps: s,
                status: NeedsInfra, rust_module: "attacks::portal", cve: "",
            },
            CaptivePortalIcmpTunnel => AttackMeta {
                attack: *self, name: "captive_portal_icmp_tunnel",
                description: "Tunnel traffic through ICMP echo",
                category: CaptivePortal, required_caps: s,
                status: NeedsInfra, rust_module: "attacks::portal", cve: "",
            },
            CaptivePortalSessionHijack => AttackMeta {
                attack: *self, name: "captive_portal_session_hijack",
                description: "Steal authenticated session cookies/tokens",
                category: CaptivePortal, required_caps: m,
                status: NeedsInfra, rust_module: "attacks::portal", cve: "",
            },
            CaptivePortalHttpTunnel => AttackMeta {
                attack: *self, name: "captive_portal_http_tunnel",
                description: "Tunnel through HTTP to allowed hosts",
                category: CaptivePortal, required_caps: s,
                status: NeedsInfra, rust_module: "attacks::portal", cve: "",
            },

            // === 13. MAC/IDENTITY ===
            MacSpoofing => AttackMeta {
                attack: *self, name: "mac_spoofing",
                description: "Change adapter MAC to impersonate another device",
                category: MacIdentity, required_caps: Capability::empty(),
                status: PortFromC, rust_module: "core::mac", cve: "",
            },
            MacFilterBypass => AttackMeta {
                attack: *self, name: "mac_filter_bypass",
                description: "Bypass MAC-based access control by spoofing whitelisted MAC",
                category: MacIdentity, required_caps: m,
                status: PortFromC, rust_module: "core::mac", cve: "",
            },
            MacRandomizationDefeat => AttackMeta {
                attack: *self, name: "mac_randomization_defeat",
                description: "De-anonymize devices using MAC randomization",
                category: MacIdentity, required_caps: m,
                status: NotImplemented, rust_module: "engine::scanner", cve: "",
            },

            // === 14. WiFi Direct ===
            WifiDirectDeauth => AttackMeta {
                attack: *self, name: "wifi_direct_deauth",
                description: "Deauthenticate WiFi Direct P2P group connections",
                category: WifiDirect, required_caps: i,
                status: NotImplemented, rust_module: "attacks::wifi_direct", cve: "",
            },
            WifiDirectEvilTwin => AttackMeta {
                attack: *self, name: "wifi_direct_evil_twin",
                description: "Impersonate WiFi Direct group owner",
                category: WifiDirect, required_caps: a | i,
                status: NotImplemented, rust_module: "attacks::wifi_direct", cve: "",
            },
            WifiDirectPinBruteforce => AttackMeta {
                attack: *self, name: "wifi_direct_pin_bruteforce",
                description: "WPS PIN attack against WiFi Direct group formation",
                category: WifiDirect, required_caps: s,
                status: NotImplemented, rust_module: "attacks::wifi_direct", cve: "",
            },

            // === 15. FRAME-LEVEL ===
            AmsduInjection => AttackMeta {
                attack: *self, name: "amsdu_injection",
                description: "Inject arbitrary frames via A-MSDU aggregation abuse",
                category: FrameLevel, required_caps: i | Capability::HT,
                status: NotImplemented, rust_module: "attacks::frame_attacks", cve: "",
            },
            AmpduInjection => AttackMeta {
                attack: *self, name: "ampdu_injection",
                description: "Exploit A-MPDU delimiter handling for frame injection",
                category: FrameLevel, required_caps: i | Capability::HT,
                status: NotImplemented, rust_module: "attacks::frame_attacks", cve: "",
            },
            OfdmaResourceExhaust => AttackMeta {
                attack: *self, name: "ofdma_resource_exhaust",
                description: "WiFi 6 OFDMA scheduling abuse for DoS",
                category: FrameLevel, required_caps: i | Capability::HE,
                status: NeedsInfra, rust_module: "attacks::frame_attacks", cve: "",
            },
            BssColoringConfusion => AttackMeta {
                attack: *self, name: "bss_coloring_confusion",
                description: "WiFi 6 BSS Color manipulation for interference/DoS",
                category: FrameLevel, required_caps: i | Capability::HE,
                status: NeedsInfra, rust_module: "attacks::frame_attacks", cve: "",
            },
            TwtManipulation => AttackMeta {
                attack: *self, name: "twt_manipulation",
                description: "WiFi 6 Target Wake Time abuse for client DoS/tracking",
                category: FrameLevel, required_caps: i | Capability::HE,
                status: NeedsInfra, rust_module: "attacks::frame_attacks", cve: "",
            },

            // === 16. FUZZING ===
            ManagementFrameFuzz => AttackMeta {
                attack: *self, name: "management_frame_fuzz",
                description: "Fuzz 802.11 management frames for firmware crashes/RCE",
                category: Fuzzing, required_caps: i,
                status: PortFromC, rust_module: "attacks::fuzz", cve: "",
            },
            EapFuzz => AttackMeta {
                attack: *self, name: "eap_fuzz",
                description: "Fuzz EAP protocol exchange for driver/supplicant vulns",
                category: Fuzzing, required_caps: a | i,
                status: PortFromC, rust_module: "attacks::fuzz", cve: "",
            },
            IeOverflow => AttackMeta {
                attack: *self, name: "ie_overflow",
                description: "Malformed IE overflow in beacon/probe frames",
                category: Fuzzing, required_caps: i,
                status: PortFromC, rust_module: "attacks::fuzz", cve: "",
            },
            FirmwareOtaExploit => AttackMeta {
                attack: *self, name: "firmware_ota_exploit",
                description: "Exploit firmware update mechanism over-the-air",
                category: Fuzzing, required_caps: i | a,
                status: NeedsInfra, rust_module: "attacks::fuzz", cve: "",
            },
            WifiCoexistenceEscalation => AttackMeta {
                attack: *self, name: "wifi_coexistence_escalation",
                description: "Exploit shared WiFi/BT/LTE resources on combo chips",
                category: Fuzzing, required_caps: Capability::empty(),
                status: NeedsInfra, rust_module: "attacks::fuzz", cve: "",
            },

            // === 17. PMF BYPASS ===
            PmfDowngrade => AttackMeta {
                attack: *self, name: "pmf_downgrade",
                description: "Force client to connect to AP without PMF",
                category: PmfBypass, required_caps: a | i,
                status: NotImplemented, rust_module: "attacks::pmf", cve: "",
            },
            PmfSaQueryFlood => AttackMeta {
                attack: *self, name: "pmf_sa_query_flood",
                description: "SA Query frame flood to disrupt PMF protection",
                category: PmfBypass, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            PmfCsaAbuse => AttackMeta {
                attack: *self, name: "pmf_csa_abuse",
                description: "CSA to force client off channel (bypasses PMF)",
                category: PmfBypass, required_caps: i,
                status: PortFromC, rust_module: "attacks::dos", cve: "",
            },
            PmfTimingAttack => AttackMeta {
                attack: *self, name: "pmf_timing_attack",
                description: "Timing-based disconnect despite PMF (race conditions)",
                category: PmfBypass, required_caps: i,
                status: NotImplemented, rust_module: "attacks::pmf", cve: "",
            },

            // === 18. NETWORK INFRA ===
            RogueRadius => AttackMeta {
                attack: *self, name: "rogue_radius",
                description: "Rogue RADIUS server to accept any credentials",
                category: NetworkInfra, required_caps: s,
                status: PortFromC, rust_module: "attacks::eap", cve: "",
            },
            VlanHopping => AttackMeta {
                attack: *self, name: "vlan_hopping",
                description: "Break out of wireless VLAN segmentation",
                category: NetworkInfra, required_caps: s,
                status: NeedsInfra, rust_module: "attacks::infra", cve: "",
            },
            ApFirmwareExploit => AttackMeta {
                attack: *self, name: "ap_firmware_exploit",
                description: "Exploit vulnerabilities in AP management interfaces",
                category: NetworkInfra, required_caps: s,
                status: NeedsInfra, rust_module: "attacks::infra", cve: "",
            },
            UpnpExploit => AttackMeta {
                attack: *self, name: "upnp_exploit",
                description: "Exploit UPnP services on AP for config change or RCE",
                category: NetworkInfra, required_caps: s,
                status: NeedsInfra, rust_module: "attacks::infra", cve: "",
            },

            // === 19. ADVANCED ===
            ChannelBasedMitm => AttackMeta {
                attack: *self, name: "channel_based_mitm",
                description: "Multi-channel MitM: AP on ch X, client on ch Y, relay",
                category: Advanced, required_caps: mi | a | m,
                status: PortFromC, rust_module: "engine::mitm", cve: "",
            },
            TimingBasedTracking => AttackMeta {
                attack: *self, name: "timing_based_tracking",
                description: "Track devices via 802.11 frame timing characteristics",
                category: Advanced, required_caps: m,
                status: NotImplemented, rust_module: "engine::scanner", cve: "",
            },
            CsiBasedSensing => AttackMeta {
                attack: *self, name: "csi_based_sensing",
                description: "Use Channel State Information for physical environment sensing",
                category: Advanced, required_caps: Capability::empty(),
                status: NeedsInfra, rust_module: "attacks::advanced", cve: "",
            },
            RfFingerprinting => AttackMeta {
                attack: *self, name: "rf_fingerprinting",
                description: "Identify specific transmitter hardware via RF signal",
                category: Advanced, required_caps: Capability::empty(),
                status: NeedsInfra, rust_module: "attacks::advanced", cve: "",
            },
            SsidStripping => AttackMeta {
                attack: *self, name: "ssid_stripping",
                description: "Use Unicode/special characters for visually identical SSIDs",
                category: Advanced, required_caps: a,
                status: NotImplemented, rust_module: "attacks::ap", cve: "",
            },
            BeaconStuffing => AttackMeta {
                attack: *self, name: "beacon_stuffing",
                description: "Embed data in beacon vendor IEs for covert channel",
                category: Advanced, required_caps: a | i,
                status: NotImplemented, rust_module: "attacks::advanced", cve: "",
            },
            DeauthRaceCondition => AttackMeta {
                attack: *self, name: "deauth_race_condition",
                description: "Race condition during 4-way handshake for key manipulation",
                category: Advanced, required_caps: m | i,
                status: NotImplemented, rust_module: "attacks::advanced", cve: "",
            },

            // === 20. WiFi 6/6E/7 ===
            Wifi6MuMimoAbuse => AttackMeta {
                attack: *self, name: "wifi6_mu_mimo_abuse",
                description: "Exploit MU-MIMO scheduling for DoS or info leakage",
                category: Wifi6e7, required_caps: i | Capability::HE,
                status: NeedsInfra, rust_module: "attacks::wifi67", cve: "",
            },
            Wifi6e6ghzDiscovery => AttackMeta {
                attack: *self, name: "wifi6e_6ghz_discovery",
                description: "Reconnaissance on 6 GHz band (FILS Discovery, UPR)",
                category: Wifi6e7, required_caps: m | Capability::BAND_6GHZ,
                status: NeedsInfra, rust_module: "attacks::wifi67", cve: "",
            },
            Wifi7MloConfusion => AttackMeta {
                attack: *self, name: "wifi7_mlo_confusion",
                description: "Multi-Link Operation confusion/downgrade attacks",
                category: Wifi6e7, required_caps: i | Capability::HE,
                status: NeedsInfra, rust_module: "attacks::wifi67", cve: "",
            },
            Wifi7_4096qamAmplification => AttackMeta {
                attack: *self, name: "wifi7_4096qam_amplification",
                description: "Exploit higher-order modulation for targeted interference",
                category: Wifi6e7, required_caps: Capability::empty(),
                status: NeedsInfra, rust_module: "attacks::wifi67", cve: "",
            },
            WifiSensingPrivacy => AttackMeta {
                attack: *self, name: "wifi_sensing_privacy",
                description: "Use WiFi sensing capabilities for surveillance",
                category: Wifi6e7, required_caps: Capability::empty(),
                status: NeedsInfra, rust_module: "attacks::wifi67", cve: "",
            },

            // === 21. SOCIAL ENGINEERING ===
            CredentialPhishingPortal => AttackMeta {
                attack: *self, name: "credential_phishing_portal",
                description: "Fake login page mimicking target organization",
                category: SocialEngineering, required_caps: a,
                status: NeedsInfra, rust_module: "attacks::social", cve: "",
            },
            FirmwareUpdatePhishing => AttackMeta {
                attack: *self, name: "firmware_update_phishing",
                description: "Fake firmware update required page",
                category: SocialEngineering, required_caps: a,
                status: NeedsInfra, rust_module: "attacks::social", cve: "",
            },
            OauthPhishing => AttackMeta {
                attack: *self, name: "oauth_phishing",
                description: "Fake OAuth/social login portal",
                category: SocialEngineering, required_caps: a,
                status: NeedsInfra, rust_module: "attacks::social", cve: "",
            },

            // === 22. POST-EXPLOITATION ===
            WirelessPivot => AttackMeta {
                attack: *self, name: "wireless_pivot",
                description: "Use compromised WiFi as pivot into wired network",
                category: PostExploitation, required_caps: s,
                status: NeedsInfra, rust_module: "attacks::post_exploit", cve: "",
            },
            CredentialRelayNtlm => AttackMeta {
                attack: *self, name: "credential_relay_ntlm",
                description: "Relay NTLM hashes from WiFi to domain services",
                category: PostExploitation, required_caps: a,
                status: NeedsInfra, rust_module: "attacks::post_exploit", cve: "",
            },
            WifiCovertChannel => AttackMeta {
                attack: *self, name: "wifi_covert_channel",
                description: "Establish covert data channel via WiFi frames",
                category: PostExploitation, required_caps: i | a,
                status: NotImplemented, rust_module: "attacks::post_exploit", cve: "",
            },
        }
    }
}

// ============================================================================
// Iterator over all attack types
// ============================================================================

pub const ALL_ATTACKS: &[AttackType] = &[
    // 1. Reconnaissance
    AttackType::PassiveScan,
    AttackType::HiddenSsidReveal,
    AttackType::ClientEnumeration,
    AttackType::ProbeRequestTracking,
    AttackType::DeviceFingerprinting,
    AttackType::PassiveHandshakeCapture,
    AttackType::TrafficAnalysis,
    AttackType::SignalStrengthMapping,
    // 2. WEP
    AttackType::WepFms,
    AttackType::WepKorek,
    AttackType::WepPtw,
    AttackType::WepArpReplay,
    AttackType::WepInteractiveReplay,
    AttackType::WepChopchop,
    AttackType::WepFragmentation,
    AttackType::WepCaffeLatte,
    AttackType::WepHirte,
    AttackType::WepFakeAuth,
    // 3. WPA/WPA2-PSK
    AttackType::WpaHandshakeCapture,
    AttackType::WpaDictionary,
    AttackType::WpaBruteforce,
    AttackType::WpaRainbowTable,
    AttackType::WpaPmkid,
    // 4. Enterprise
    AttackType::EnterpriseEvilTwin,
    AttackType::EnterpriseEapDowngrade,
    AttackType::EnterpriseCredentialHarvest,
    AttackType::EnterprisePeapRelay,
    AttackType::EnterpriseCertBypass,
    AttackType::EnterpriseIdentityTheft,
    // 5. WPA3/SAE
    AttackType::Wpa3TimingSideChannel,
    AttackType::Wpa3CacheSideChannel,
    AttackType::Wpa3GroupDowngrade,
    AttackType::Wpa3SaeDos,
    AttackType::Wpa3InvalidCurve,
    AttackType::Wpa3PasswordPartition,
    AttackType::Wpa3TransitionDowngrade,
    // 6. WPS
    AttackType::WpsPinBruteforce,
    AttackType::WpsPixieDust,
    AttackType::WpsNullPin,
    AttackType::WpsPinLockoutBypass,
    // 7. Protocol
    AttackType::Krack4wayHandshake,
    AttackType::KrackGroupKey,
    AttackType::KrackFtReassociation,
    AttackType::KrackTdls,
    AttackType::KrackWnmSleep,
    AttackType::FragAggregationDesign,
    AttackType::FragMixedKey,
    AttackType::FragFragmentCache,
    AttackType::FragPlaintextInjection,
    AttackType::FragAmsduInjection,
    AttackType::SsidConfusion,
    AttackType::MacStealer,
    AttackType::Airsnitch,
    AttackType::Hole196,
    // 8. TKIP
    AttackType::TkipBeckTews,
    AttackType::TkipOhigashiMorii,
    AttackType::TkipMichaelShutdown,
    AttackType::TkipSideChannel,
    // 9. DoS
    AttackType::DeauthFlood,
    AttackType::DeauthTargeted,
    AttackType::DisassocFlood,
    AttackType::AuthFlood,
    AttackType::AssocFlood,
    AttackType::BeaconFlood,
    AttackType::ProbeFlood,
    AttackType::RfJamming,
    AttackType::SelectiveJamming,
    AttackType::CtsFlood,
    AttackType::RtsFlood,
    AttackType::NavManipulation,
    AttackType::FtReassocDos,
    AttackType::BssTransitionDos,
    AttackType::PowerSaveDos,
    // 10. Rogue AP
    AttackType::EvilTwinOpen,
    AttackType::EvilTwinCaptivePortal,
    AttackType::Karma,
    AttackType::ManaLoud,
    AttackType::KnownBeacons,
    AttackType::HostilePortal,
    // 11. MitM
    AttackType::ArpSpoofing,
    AttackType::DnsSpoofing,
    AttackType::DhcpSpoofing,
    AttackType::Dhcpv6Spoofing,
    AttackType::NdpSpoofing,
    AttackType::SslStrip,
    AttackType::HstsBypass,
    AttackType::WpadInjection,
    AttackType::CredentialSniffing,
    // 12. Captive Portal
    AttackType::CaptivePortalMacClone,
    AttackType::CaptivePortalDnsTunnel,
    AttackType::CaptivePortalIcmpTunnel,
    AttackType::CaptivePortalSessionHijack,
    AttackType::CaptivePortalHttpTunnel,
    // 13. MAC/Identity
    AttackType::MacSpoofing,
    AttackType::MacFilterBypass,
    AttackType::MacRandomizationDefeat,
    // 14. WiFi Direct
    AttackType::WifiDirectDeauth,
    AttackType::WifiDirectEvilTwin,
    AttackType::WifiDirectPinBruteforce,
    // 15. Frame-Level
    AttackType::AmsduInjection,
    AttackType::AmpduInjection,
    AttackType::OfdmaResourceExhaust,
    AttackType::BssColoringConfusion,
    AttackType::TwtManipulation,
    // 16. Fuzzing
    AttackType::ManagementFrameFuzz,
    AttackType::EapFuzz,
    AttackType::IeOverflow,
    AttackType::FirmwareOtaExploit,
    AttackType::WifiCoexistenceEscalation,
    // 17. PMF Bypass
    AttackType::PmfDowngrade,
    AttackType::PmfSaQueryFlood,
    AttackType::PmfCsaAbuse,
    AttackType::PmfTimingAttack,
    // 18. Network Infra
    AttackType::RogueRadius,
    AttackType::VlanHopping,
    AttackType::ApFirmwareExploit,
    AttackType::UpnpExploit,
    // 19. Advanced
    AttackType::ChannelBasedMitm,
    AttackType::TimingBasedTracking,
    AttackType::CsiBasedSensing,
    AttackType::RfFingerprinting,
    AttackType::SsidStripping,
    AttackType::BeaconStuffing,
    AttackType::DeauthRaceCondition,
    // 20. WiFi 6/6E/7
    AttackType::Wifi6MuMimoAbuse,
    AttackType::Wifi6e6ghzDiscovery,
    AttackType::Wifi7MloConfusion,
    AttackType::Wifi7_4096qamAmplification,
    AttackType::WifiSensingPrivacy,
    // 21. Social Engineering
    AttackType::CredentialPhishingPortal,
    AttackType::FirmwareUpdatePhishing,
    AttackType::OauthPhishing,
    // 22. Post-Exploitation
    AttackType::WirelessPivot,
    AttackType::CredentialRelayNtlm,
    AttackType::WifiCovertChannel,
];

// ============================================================================
// Summary helpers — for CLI "wifikit taxonomy" command
// ============================================================================

pub fn count_by_status() -> [(Status, usize); 5] {
    use Status::*;
    let mut counts = [(PortFromC, 0), (Done, 0), (Stub, 0), (NotImplemented, 0), (NeedsInfra, 0)];
    for attack in ALL_ATTACKS {
        let status = attack.meta().status;
        for (s, c) in &mut counts {
            if *s == status { *c += 1; break; }
        }
    }
    counts
}

pub fn count_by_category() -> Vec<(Category, usize, usize)> {
    let mut cats: Vec<(Category, usize, usize)> = Vec::new(); // (cat, total, implemented)
    for attack in ALL_ATTACKS {
        let meta = attack.meta();
        let implemented = matches!(meta.status, Status::PortFromC | Status::Done);
        if let Some(entry) = cats.iter_mut().find(|(c, _, _)| *c == meta.category) {
            entry.1 += 1;
            if implemented { entry.2 += 1; }
        } else {
            cats.push((meta.category, 1, if implemented { 1 } else { 0 }));
        }
    }
    cats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_attacks_count() {
        // All 135 attack types from taxonomy (C had 138 but some were merged/reorganized)
        assert_eq!(ALL_ATTACKS.len(), 135, "Expected 135 attack types in taxonomy");
    }

    #[test]
    fn test_every_attack_has_meta() {
        for attack in ALL_ATTACKS {
            let meta = attack.meta();
            assert!(!meta.name.is_empty(), "{:?} missing name", attack);
            assert!(!meta.description.is_empty(), "{:?} missing description", attack);
            assert!(!meta.rust_module.is_empty(), "{:?} missing rust_module", attack);
        }
    }

    #[test]
    fn test_port_from_c_count() {
        let port_count = ALL_ATTACKS.iter()
            .filter(|a| a.meta().status == Status::PortFromC)
            .count();
        // We have ~58 real implementations in C
        assert!(port_count >= 50, "Expected at least 50 PortFromC, got {}", port_count);
    }

    #[test]
    fn test_categories_cover_all() {
        let cats = count_by_category();
        let total: usize = cats.iter().map(|(_, t, _)| t).sum();
        assert_eq!(total, 135);
    }
}
