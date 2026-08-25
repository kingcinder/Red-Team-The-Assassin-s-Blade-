"""
RedTeam Harness — Forensics Tools Module
Digital forensics, file carving, memory analysis, data recovery.
"""
from tools.base import BaseTool


class ForensicsTools(BaseTool):
    """Digital forensics and data recovery tools."""

    def get_tools(self):
        return ["binwalk_analyze", "foremost_carve", "testdisk_recover",
                "photorec_recover", "volatility_analyze", "dcfldd_image",
                "ddrescue_image", "exiftool_read", "strings_extract",
                "steghide_extract", "stegseek_crack", "bulk_extractor"]

    def get_quick_commands(self):
        return [
            {"name": "Firmware Analysis", "description": "Analyze firmware image for embedded filesystems",
             "tool": "binwalk_analyze",
             "args_template": {"file": "TARGET", "extract": True}},
            {"name": "File Carving", "description": "Recover deleted files from disk image via headers",
             "tool": "foremost_carve",
             "args_template": {"image": "TARGET", "output_dir": "./foremost_out"}},
            {"name": "Recover Partition", "description": "Recover lost partitions with TestDisk",
             "tool": "testdisk_recover",
             "args_template": {"device": "/dev/sdb"}},
            {"name": "Photo Recovery", "description": "Recover deleted photos with PhotoRec",
             "tool": "photorec_recover",
             "args_template": {"device": "/dev/sdb"}},
            {"name": "Memory Forensics", "description": "Analyze RAM dump with Volatility",
             "tool": "volatility_analyze",
             "args_template": {"image": "memory.dmp", "plugin": "pslist"}},
            {"name": "Forensic Disk Image", "description": "Create forensic image with hash verification",
             "tool": "dcfldd_image",
             "args_template": {"input": "/dev/sda", "output": "evidence.dd"}},
            {"name": "Metadata Extraction", "description": "Extract EXIF/metadata from files",
             "tool": "exiftool_read",
             "args_template": {"file": "TARGET"}},
            {"name": "String Extraction", "description": "Extract readable strings from binaries",
             "tool": "strings_extract",
             "args_template": {"file": "TARGET", "min_length": 8}},
            {"name": "Stego Data Extract", "description": "Extract hidden data from stego files",
             "tool": "steghide_extract",
             "args_template": {"file": "TARGET", "extract": True}},
            {"name": "Stego Brute Force", "description": "Brute-force steghide passphrases",
             "tool": "stegseek_crack",
             "args_template": {"file": "TARGET", "wordlist": "/usr/share/wordlists/rockyou.txt"}},
            {"name": "Bulk PII Extraction", "description": "Extract emails/URLs/CCNs from disk images",
             "tool": "bulk_extractor",
             "args_template": {"input": "TARGET", "output_dir": "./bulk_out"}},
        ]

    def get_preset_attack_chains(self):
        return [
            {"name": "Firmware Extraction Pipeline",
             "description": "Analyze → extract → carve files from firmware",
             "steps": [
                 {"tool": "binwalk_analyze", "args": {"file": "firmware.bin"}, "description": "Analyze firmware structure"},
                 {"tool": "binwalk_analyze", "args": {"file": "firmware.bin", "extract": True}, "description": "Extract filesystems"},
                 {"tool": "strings_extract", "args": {"file": "firmware.bin", "min_length": 10}, "description": "Extract hardcoded strings (passwords, URLs)"},
             ]},
            {"name": "Incident Response Pipeline",
             "description": "Memory dump → process list → network connections → malware scan",
             "steps": [
                 {"tool": "volatility_analyze", "args": {"image": "memory.dmp", "plugin": "pslist"}, "description": "List running processes"},
                 {"tool": "volatility_analyze", "args": {"image": "memory.dmp", "plugin": "netscan"}, "description": "Network connections"},
                 {"tool": "yara_scan", "args": {"rules": "malware_rules.yar", "target": "memory.dmp"}, "description": "Scan for malware signatures"},
             ]},
        ]