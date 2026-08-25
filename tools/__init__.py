"""
RedTeam Harness — Tool Modules
===============================

Extensible tool wrappers and exploit modules, one per Kali tool category.

Modules:
    base      — BaseTool ABC every tool module inherits
    recon     — ReconTools (nmap, masscan, amass, ...)
    vuln      — VulnTools (nuclei, wpscan, searchsploit, ...)
    web       — WebTools (nikto, sqlmap, gobuster, ...)
    password  — PasswordTools (hydra, john, hashcat, ...)
    wireless  — WirelessTools (aircrack-ng, reaver, ...)
    sniffing  — SniffingTools (tcpdump, tshark, responder, ...)
    exploit   — ExploitTools (msfconsole, crackmapexec, ...)
    forensics — ForensicsTools (binwalk, volatility, ...)
    reversing — ReversingTools (radare2, gdb, apktool, ...)
    social    — SocialTools (SEToolkit, BeEF, GoPhish)
    postex    — PostExTools (mimikatz, bloodhound, chisel, ...)
    osint     — OSINTTools (whois, dig, theHarvester, ...)
    stress    — StressTools (hping3, slowhttptest, ...)
    hardware  — HardwareTools (minicom, flashrom, ...)
"""
from tools.base import BaseTool
from tools.recon import ReconTools
from tools.vuln import VulnTools
from tools.web import WebTools
from tools.password import PasswordTools
from tools.wireless import WirelessTools
from tools.sniffing import SniffingTools
from tools.exploit import ExploitTools
from tools.forensics import ForensicsTools
from tools.reversing import ReversingTools
from tools.social import SocialTools
from tools.postex import PostExTools
from tools.osint import OSINTTools
from tools.stress import StressTools
from tools.hardware import HardwareTools

ALL_TOOL_MODULES = [
    ReconTools, VulnTools, WebTools, PasswordTools, WirelessTools,
    SniffingTools, ExploitTools, ForensicsTools, ReversingTools,
    SocialTools, PostExTools, OSINTTools, StressTools, HardwareTools,
]

# Explicit public API — BaseTool is re-exported so `from tools import BaseTool`
# works for consumers who only need the ABC, mirroring the module docstring.
__all__ = ["BaseTool", "ALL_TOOL_MODULES"]
