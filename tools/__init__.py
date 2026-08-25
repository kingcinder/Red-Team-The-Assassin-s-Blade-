# RedTeam Harness — ALL Kali Tool Modules (14 categories)
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