//! Help, version, and stub commands.

use super::Ctx;

/// /help [command]
pub fn run(ctx: &mut Ctx, args: &str) {
    let output = if args.trim().is_empty() { help_all() } else { help_one(args.trim()) };
    for line in output.lines() {
        ctx.layout.print(line);
    }
}

/// /version
pub fn version(ctx: &mut Ctx) {
    for line in version_string().lines() {
        ctx.layout.print(line);
    }
}

/// /mac (stub — not yet implemented)
pub fn mac_stub(ctx: &mut Ctx) {
    ctx.layout.print(&format!("\n  {} MAC control requires an adapter.\n",
        prism::s().red().paint("!")));
}

fn help_all() -> String {
    let s = prism::s;
    let h = |name: &str, desc: &str| format!("    {}  {}",
        s().cyan().bold().paint(&format!("/{name:<12}")),
        s().dim().paint(desc));
    [
        "", &format!("  {}", s().bold().paint("Shell")),
        &h("help", "Show this help (or /help <command>)"), &h("quit", "Exit wifikit"),
        &h("clear", "Clear terminal screen"), &h("version", "Show version"),
        "", &format!("  {}", s().bold().paint("Adapter")),
        &h("adapter", "List/select/switch adapters (/adapter <N>)"), &h("mac", "Set/randomize MAC address"),
        "", &format!("  {}", s().bold().paint("Scanner")),
        &h("scan", "Start WiFi scanner"), &h("view", "Switch view (aps, clients, probes, channels, events, handshakes)"),
        &h("export", "Export data (pcap, hccapx, hc22000, csv)"),
        "", &format!("  {}", s().bold().paint("Attacks")),
        &h("attack", "Attack control (stop running attack)"),
        &h("pmkid", "PMKID extraction"), &h("wps", "WPS Pixie Dust + brute force"),
        &h("deauth", "Deauthentication"), &h("dos", "Denial of service (14 types)"),
        &h("ap", "Rogue AP / Evil Twin / KARMA"), &h("eap", "Enterprise credential capture"),
        &h("krack", "KRACK key reinstallation (11 variants)"), &h("frag", "FragAttacks (12 CVEs)"),
        &h("fuzz", "WiFi protocol fuzzer"), &h("wpa3", "WPA3/Dragonblood attacks"),
        "", &format!("  {}", s().dim().paint("/ or : enters command mode. Esc returns to Normal. Tab completes.")), "",
    ].join("\n")
}

fn help_one(name: &str) -> String {
    let name = name.strip_prefix('/').unwrap_or(name);
    let info: Option<(&str, &str, &[&str])> = match name {
        "help" | "h" | "?" => Some(("help", "Show available commands.", &["/help", "/help scan"][..])),
        "quit" | "q" | "exit" => Some(("quit", "Exit wifikit.", &["/quit"])),
        "clear" => Some(("clear", "Clear the terminal screen.", &["/clear"])),
        "version" | "v" => Some(("version", "Show version information.", &["/version"])),
        "adapters" | "adapter" => Some(("adapter", "List, select, and switch WiFi adapters.", &["/adapter", "/adapter list", "/adapter <N>", "/adapter rescan"])),
        "mac" => Some(("mac", "Set or randomize MAC address.", &["/mac", "/mac random", "/mac AA:BB:CC:DD:EE:FF"])),
        "scan" => Some(("scan", "Start WiFi scanner.", &["/scan", "/scan --passive", "/scan --channels 1,6,11", "/scan stop"])),
        "view" => Some(("view", "Switch scanner view.", &["/view aps", "/view clients", "/view probes", "/view channels", "/view events", "/view handshakes"])),
        "export" => Some(("export", "Export captured data.", &["/export pcap", "/export hccapx", "/export hc22000", "/export csv", "/export pcap capture.pcap"])),
        "attack" => Some(("attack", "Control running attacks.", &["/attack", "/attack stop", "/attack stop all"])),
        "pmkid" => Some(("pmkid", "Extract PMKID from target AP(s).", &["/pmkid", "/pmkid RL-WiFi", "/pmkid --all"])),
        "wps" => Some(("wps", "WPS Pixie Dust + brute force.", &["/wps", "/wps RL-WiFi"])),
        "deauth" => Some(("deauth", "Deauthentication attack.", &["/deauth", "/deauth RL-WiFi"])),
        "dos" => Some(("dos", "Denial of service (14 types).", &["/dos beacon", "/dos auth RL-WiFi"])),
        "ap" => Some(("ap", "Rogue AP / Evil Twin / KARMA.", &["/ap --evil-twin RL-WiFi", "/ap --karma"])),
        "eap" => Some(("eap", "Enterprise credential capture.", &["/eap CorpWiFi"])),
        "krack" => Some(("krack", "KRACK key reinstallation \u{2014} 11 variants.", &["/krack", "/krack RL-WiFi", "/krack --variant ptk", "/krack --variant ft", "/krack --variant zeroed-tk"])),
        "frag" => Some(("frag", "FragAttacks \u{2014} 12 WiFi CVEs.", &["/frag", "/frag RL-WiFi", "/frag --variant plaintext", "/frag --variant 26144", "/frag --stop-first"])),
        "fuzz" => Some(("fuzz", "WiFi protocol fuzzer.", &["/fuzz", "/fuzz --domain management"])),
        "wpa3" => Some(("wpa3", "WPA3/Dragonblood \u{2014} 8 attack modes.", &["/wpa3", "/wpa3 RL-WiFi", "/wpa3 --mode timing", "/wpa3 --mode invalid-curve", "/wpa3 --mode flood"])),
        _ => None,
    };
    match info {
        Some((cmd_name, desc, examples)) => {
            let s = prism::s;
            let mut l = vec![String::new(), format!("  {}", s().cyan().bold().paint(&format!("/{cmd_name}"))),
                String::new(), format!("  {desc}"), String::new(), format!("  {}", s().bold().paint("Examples:"))];
            for ex in examples { l.push(format!("    {}", s().dim().paint(ex))); }
            l.push(String::new()); l.join("\n")
        }
        None => format!("\n  {} Unknown command: /{name}\n", prism::s().red().paint("!")),
    }
}

fn version_string() -> String {
    format!("\n  {} {}\n  {}\n",
        prism::s().cyan().bold().paint("wifikit"),
        prism::s().dim().paint(&format!("v{}", crate::cli::banner::VERSION)),
        prism::s().dim().paint("WiFi Pentesting Research Lab"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_all_contains_commands() {
        let h = help_all();
        assert!(h.contains("scan") && h.contains("pmkid") && h.contains("wpa3") && h.contains("attack"));
    }

    #[test]
    fn test_help_one_attack_shows_examples() {
        let h = help_one("attack");
        assert!(h.contains("/attack stop"));
    }

    #[test]
    fn test_help_one_export_shows_examples() {
        let h = help_one("export");
        assert!(h.contains("/export pcap"));
    }

    #[test]
    fn test_help_one_unknown_shows_error() {
        let h = help_one("nonexistent");
        assert!(h.contains("Unknown command"));
    }

    #[test]
    fn test_version_contains_version() {
        let v = version_string();
        assert!(v.contains(crate::cli::banner::VERSION));
    }
}
