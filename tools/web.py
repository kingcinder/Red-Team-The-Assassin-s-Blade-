"""
RedTeam Harness — Web Application Tools Module
Web scanning, SQL injection, directory brute-force, crawling, fuzzing.
"""
from tools.base import BaseTool


class WebTools(BaseTool):
    """Web application security testing tools."""

    def get_tools(self):
        return ["nikto_scan", "sqlmap_scan", "gobuster_dir", "whatweb_scan",
                "waf_detect", "curl_request", "dirb_scan", "wfuzz_fuzz",
                "feroxbuster_scan", "ffuf_fuzz", "burpsuite_proxy", "zap_scan",
                "katana_crawl", "gospider_crawl", "hakrawler_crawl",
                "gau_fetch", "waybackurls_fetch"]

    def get_quick_commands(self):
        return [
            {"name": "Web Server Scan", "description": "Nikto comprehensive web server scan",
             "tool": "nikto_scan", "args_template": {"target": "TARGET"}},
            {"name": "SQL Injection Test", "description": "SQLi detection (level 1, risk 1)",
             "tool": "sqlmap_scan",
             "args_template": {"url": "TARGET", "batch": True, "level": 1, "risk": 1}},
            {"name": "SQLi Deep Scan", "description": "Deep SQLi + DB enumeration",
             "tool": "sqlmap_scan",
             "args_template": {"url": "TARGET", "batch": True, "level": 5, "risk": 2, "dbs": True}},
            {"name": "Directory Brute (Go)", "description": "Gobuster directory brute-force",
             "tool": "gobuster_dir",
             "args_template": {"url": "TARGET", "wordlist": "/usr/share/wordlists/dirb/common.txt", "extensions": "php,html,js,txt"}},
            {"name": "Directory Brute (Classic)", "description": "Dirb classic directory scanner",
             "tool": "dirb_scan",
             "args_template": {"url": "TARGET"}},
            {"name": "Fast Fuzz (ffuf)", "description": "High-speed web fuzzer",
             "tool": "ffuf_fuzz",
             "args_template": {"url": "TARGET/FUZZ", "wordlist": "/usr/share/wordlists/dirb/common.txt"}},
            {"name": "Feroxbuster Recursive", "description": "Fast recursive content discovery",
             "tool": "feroxbuster_scan",
             "args_template": {"url": "TARGET"}},
            {"name": "Web Fuzzer (wfuzz)", "description": "Parameter/directory fuzzing",
             "tool": "wfuzz_fuzz",
             "args_template": {"url": "TARGET/FUZZ", "wordlist": "/usr/share/wordlists/dirb/common.txt"}},
            {"name": "Tech Fingerprint", "description": "WhatWeb technology identification",
             "tool": "whatweb_scan",
             "args_template": {"target": "TARGET", "aggression": 3}},
            {"name": "WAF Detection", "description": "Check if target uses a WAF",
             "tool": "waf_detect", "args_template": {"target": "TARGET"}},
            {"name": "Katana Crawl", "description": "Next-gen web crawler/spider",
             "tool": "katana_crawl", "args_template": {"url": "TARGET"}},
            {"name": "Hakrawler Crawl", "description": "Fast web crawler for bug bounty",
             "tool": "hakrawler_crawl", "args_template": {"url": "TARGET"}},
            {"name": "Wayback URLs", "description": "Fetch historical URLs from Wayback Machine",
             "tool": "waybackurls_fetch", "args_template": {"domain": "TARGET"}},
            {"name": "ZAP Automated Scan", "description": "OWASP ZAP web app vulnerability scanner",
             "tool": "zap_scan", "args_template": {"target": "TARGET"}},
        ]

    def get_preset_attack_chains(self):
        return [
            {"name": "Web App Assessment",
             "description": "Fingerprint → WAF check → crawl → dir brute → vuln scan → SQLi",
             "steps": [
                 {"tool": "whatweb_scan", "args": {"target": "TARGET"}, "description": "Technology fingerprint"},
                 {"tool": "waf_detect", "args": {"target": "TARGET"}, "description": "WAF detection"},
                 {"tool": "katana_crawl", "args": {"url": "TARGET"}, "description": "Crawl site structure"},
                 {"tool": "gobuster_dir", "args": {"url": "TARGET", "wordlist": "/usr/share/wordlists/dirb/common.txt"}, "description": "Directory enumeration"},
                 {"tool": "nikto_scan", "args": {"target": "TARGET"}, "description": "Vulnerability scan"},
             ]},
            {"name": "Full URL Discovery Pipeline",
             "description": "Crawl → Wayback → GAU → ffuf fuzz",
             "steps": [
                 {"tool": "katana_crawl", "args": {"url": "TARGET"}, "description": "Live crawl"},
                 {"tool": "waybackurls_fetch", "args": {"domain": "TARGET"}, "description": "Historical URLs"},
                 {"tool": "gau_fetch", "args": {"domain": "TARGET"}, "description": "AlienVault + Wayback"},
                 {"tool": "ffuf_fuzz", "args": {"url": "TARGET/FUZZ", "wordlist": "/usr/share/wordlists/dirb/common.txt"}, "description": "Fuzz parameters"},
             ]},
        ]