"""
RedTeam Harness — Reverse Engineering Tools Module
Binary analysis, debugging, disassembly, decompilation.
"""
from tools.base import BaseTool


class ReversingTools(BaseTool):
    """Reverse engineering and binary analysis tools."""

    def get_tools(self):
        return ["radare2_analyze", "gdb_debug", "objdump_disasm",
                "readelf_analyze", "strace_trace", "ltrace_trace",
                "apktool_decompile", "jadx_decompile", "dex2jar_convert",
                "ghidra_headless", "yara_scan"]

    def get_quick_commands(self):
        return [
            {"name": "Binary Analysis (r2)", "description": "Analyze binary with radare2 auto-analysis",
             "tool": "radare2_analyze",
             "args_template": {"file": "TARGET", "command": "aaa; afl"}},
            {"name": "GDB Debug", "description": "Debug binary with GDB",
             "tool": "gdb_debug",
             "args_template": {"binary": "TARGET"}},
            {"name": "Disassemble Binary", "description": "Disassemble binary with objdump",
             "tool": "objdump_disasm",
             "args_template": {"file": "TARGET", "section": ".text"}},
            {"name": "ELF Analysis", "description": "Full ELF header/section analysis",
             "tool": "readelf_analyze",
             "args_template": {"file": "TARGET", "flags": "-a"}},
            {"name": "System Call Trace", "description": "Trace syscalls of running binary",
             "tool": "strace_trace",
             "args_template": {"binary": "TARGET"}},
            {"name": "Library Call Trace", "description": "Trace dynamic library calls",
             "tool": "ltrace_trace",
             "args_template": {"binary": "TARGET"}},
            {"name": "APK Decompile", "description": "Decompile Android APK to smali",
             "tool": "apktool_decompile",
             "args_template": {"apk": "TARGET", "operation": "d"}},
            {"name": "DEX to Java", "description": "Decompile Android DEX to Java source",
             "tool": "jadx_decompile",
             "args_template": {"file": "TARGET", "output_dir": "./jadx_out"}},
            {"name": "DEX to JAR", "description": "Convert DEX to JAR for JD-GUI analysis",
             "tool": "dex2jar_convert",
             "args_template": {"dex": "TARGET"}},
            {"name": "Ghidra Headless", "description": "Automated Ghidra binary analysis",
             "tool": "ghidra_headless",
             "args_template": {"project_dir": "/tmp/ghidra_proj", "binary": "TARGET"}},
            {"name": "YARA Malware Scan", "description": "Scan files/memory with YARA rules",
             "tool": "yara_scan",
             "args_template": {"rules": "rules.yar", "target": "TARGET"}},
        ]

    def get_preset_attack_chains(self):
        return [
            {"name": "Malware Analysis Pipeline",
             "description": "Strings → disassemble → trace → YARA scan",
             "steps": [
                 {"tool": "strings_extract", "args": {"file": "malware.bin", "min_length": 10}, "description": "Extract embedded strings"},
                 {"tool": "readelf_analyze", "args": {"file": "malware.bin", "flags": "-a"}, "description": "ELF header analysis"},
                 {"tool": "strace_trace", "args": {"binary": "malware.bin"}, "description": "Trace syscalls"},
                 {"tool": "yara_scan", "args": {"rules": "malware_rules.yar", "target": "malware.bin"}, "description": "YARA signature match"},
             ]},
            {"name": "Android APK Analysis",
             "description": "Decompile → convert → analyze Android apps",
             "steps": [
                 {"tool": "apktool_decompile", "args": {"apk": "app.apk", "operation": "d"}, "description": "Decompile to smali"},
                 {"tool": "jadx_decompile", "args": {"file": "app.apk", "output_dir": "./source"}, "description": "Decompile to Java"},
                 {"tool": "strings_extract", "args": {"file": "app.apk", "min_length": 8}, "description": "Find hardcoded secrets"},
             ]},
        ]