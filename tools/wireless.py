"""
RedTeam Harness — Wireless Attack Tools Module
WiFi cracking, WPS attacks, deauth, monitor mode.
"""
from tools.base import BaseTool


class WirelessTools(BaseTool):
    """Wireless network attack tools."""

    def get_tools(self):
        return ["aircrack_crack", "airodump_capture", "aireplay_attack",
                "reaver_attack", "wifite_auto", "kismet_scan", "bettercap_mitm"]

    def get_quick_commands(self):
        return [
            {"name": "WPA Handshake Capture", "description": "Capture WPA handshake with airodump-ng",
             "tool": "airodump_capture",
             "args_template": {"interface": "wlan0mon", "channel": "6"}},
            {"name": "Deauth Attack", "description": "Deauth clients to capture handshake",
             "tool": "aireplay_attack",
             "args_template": {"interface": "wlan0mon", "bssid": "TARGET_BSSID", "attack": "0"}},
            {"name": "WPA/WPA2 Crack", "description": "Crack WPA handshake with wordlist",
             "tool": "aircrack_crack",
             "args_template": {"cap_file": "capture.cap", "wordlist": "/usr/share/wordlists/rockyou.txt"}},
            {"name": "WPS PIN Attack", "description": "Brute-force WPS PIN with Reaver",
             "tool": "reaver_attack",
             "args_template": {"interface": "wlan0mon", "bssid": "TARGET_BSSID"}},
            {"name": "Automated WiFi Attack", "description": "Wifite automated wireless attacks",
             "tool": "wifite_auto",
             "args_template": {"interface": "wlan0"}},
            {"name": "WiFi Network Scan", "description": "Passive wireless network discovery with Kismet",
             "tool": "kismet_scan",
             "args_template": {"interface": "wlan0", "time": 60}},
            {"name": "Bettercap MITM", "description": "Bettercap WiFi/Ethernet MITM attack",
             "tool": "bettercap_mitm",
             "args_template": {"target": "TARGET", "module": "wifi"}},
        ]

    def get_preset_attack_chains(self):
        return [
            {"name": "WiFi Cracking Pipeline",
             "description": "Scan → capture handshake → deauth → crack WPA",
             "steps": [
                 {"tool": "kismet_scan", "args": {"interface": "wlan0"}, "description": "Scan for WiFi networks"},
                 {"tool": "airodump_capture", "args": {"interface": "wlan0mon", "channel": "6"}, "description": "Capture WPA handshake"},
                 {"tool": "aireplay_attack", "args": {"interface": "wlan0mon", "bssid": "TARGET_BSSID", "attack": "0"}, "description": "Deauth clients to force handshake"},
                 {"tool": "aircrack_crack", "args": {"cap_file": "capture.cap", "wordlist": "/usr/share/wordlists/rockyou.txt"}, "description": "Crack the WPA key"},
             ]},
        ]