"""
RedTeam Harness — OSINT Tools Module
Domain/email recon, social media hunting, whois, DNS OSINT.
"""
from tools.base import BaseTool


class OSINTTools(BaseTool):
    """Open-source intelligence gathering tools."""

    def get_tools(self):
        return ["whois_lookup", "dig_dns", "dns_enum", "theharvester_gather",
                "recon_ng_gather", "wget_download", "exiftool_osint",
                "sherlock_search", "holehe_check"]

    def get_quick_commands(self):
        return [
            {"name": "WHOIS Lookup", "description": "Domain/IP WHOIS registration info",
             "tool": "whois_lookup", "args_template": {"target": "TARGET"}},
            {"name": "DNS A Records", "description": "Query A records",
             "tool": "dig_dns", "args_template": {"domain": "TARGET", "record_type": "A"}},
            {"name": "DNS MX Records", "description": "Query mail exchange records",
             "tool": "dig_dns", "args_template": {"domain": "TARGET", "record_type": "MX"}},
            {"name": "DNS TXT Records", "description": "TXT records (SPF, DKIM, DMARC)",
             "tool": "dig_dns", "args_template": {"domain": "TARGET", "record_type": "TXT"}},
            {"name": "DNS NS Records", "description": "Query nameserver records",
             "tool": "dig_dns", "args_template": {"domain": "TARGET", "record_type": "NS"}},
            {"name": "Zone Transfer Test", "description": "Test DNS zone transfer",
             "tool": "dig_dns", "args_template": {"domain": "TARGET", "record_type": "AXFR"}},
            {"name": "DNS Enumeration", "description": "Full DNS enumeration + subdomain brute",
             "tool": "dns_enum", "args_template": {"domain": "TARGET", "brute": True}},
            {"name": "theHarvester", "description": "Email/subdomain OSINT gathering",
             "tool": "theharvester_gather", "args_template": {"domain": "TARGET"}},
            {"name": "Recon-ng", "description": "Web reconnaissance framework",
             "tool": "recon_ng_gather", "args_template": {"workspace": "TARGET"}},
            {"name": "Sherlock Search", "description": "Find social media accounts by username",
             "tool": "sherlock_search", "args_template": {"username": "TARGET"}},
            {"name": "Holehe Check", "description": "Check email registration on sites",
             "tool": "holehe_check", "args_template": {"email": "TARGET"}},
            {"name": "Metadata OSINT", "description": "Extract author/GPS/software from files",
             "tool": "exiftool_osint", "args_template": {"file": "TARGET"}},
        ]

    def get_preset_attack_chains(self):
        return [
            {"name": "Domain Intelligence Pipeline",
             "description": "WHOIS → DNS → theHarvester → Sherlock → metadata",
             "steps": [
                 {"tool": "whois_lookup", "args": {"target": "TARGET"}, "description": "Registration info"},
                 {"tool": "dig_dns", "args": {"domain": "TARGET", "record_type": "A"}, "description": "A records"},
                 {"tool": "dig_dns", "args": {"domain": "TARGET", "record_type": "MX"}, "description": "Mail servers"},
                 {"tool": "dig_dns", "args": {"domain": "TARGET", "record_type": "TXT"}, "description": "SPF/DKIM/DMARC"},
                 {"tool": "theharvester_gather", "args": {"domain": "TARGET"}, "description": "Email/subdomain harvesting"},
                 {"tool": "dns_enum", "args": {"domain": "TARGET", "brute": True}, "description": "Subdomain brute-force"},
             ]},
            {"name": "Person OSINT Pipeline",
             "description": "Sherlock → Holehe → theHarvester → metadata",
             "steps": [
                 {"tool": "sherlock_search", "args": {"username": "TARGET_USERNAME"}, "description": "Social media hunting"},
                 {"tool": "holehe_check", "args": {"email": "TARGET_EMAIL"}, "description": "Registration check"},
                 {"tool": "exiftool_osint", "args": {"file": "TARGET_FILE"}, "description": "Extract metadata"},
             ]},
        ]