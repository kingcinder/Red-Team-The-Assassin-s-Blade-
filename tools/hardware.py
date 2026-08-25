"""
RedTeam Harness — Hardware Hacking Tools Module
Serial communication, firmware flashing, JTAG debugging.
"""
from tools.base import BaseTool


class HardwareTools(BaseTool):
    """Hardware hacking and embedded device tools."""

    def get_tools(self):
        return ["minicom_serial", "flashrom_flash", "screen_serial"]

    def get_quick_commands(self):
        return [
            {"name": "Serial Console", "description": "Connect to UART serial console via minicom",
             "tool": "minicom_serial",
             "args_template": {"device": "/dev/ttyUSB0"}},
            {"name": "Serial Terminal (screen)", "description": "Serial console access via screen",
             "tool": "screen_serial",
             "args_template": {"device": "/dev/ttyUSB0", "baud": 115200}},
            {"name": "Read Flash Chip", "description": "Read firmware from SPI flash chip",
             "tool": "flashrom_flash",
             "args_template": {"read": "firmware.bin"}},
            {"name": "Write Flash Chip", "description": "Write firmware image to flash chip",
             "tool": "flashrom_flash",
             "args_template": {"write": "patched.bin"}},
        ]

    def get_preset_attack_chains(self):
        return [
            {"name": "Firmware Extraction Pipeline (HW)",
             "description": "Read flash → analyze firmware → find vulnerabilities",
             "steps": [
                 {"tool": "flashrom_flash", "args": {"read": "flash_dump.bin"}, "description": "Read chip to file"},
                 {"tool": "binwalk_analyze", "args": {"file": "flash_dump.bin", "extract": True}, "description": "Analyze and extract filesystems"},
                 {"tool": "strings_extract", "args": {"file": "flash_dump.bin", "min_length": 8}, "description": "Find passwords/keys"},
                 {"note": "4. Modify firmware → flashrom write patched.bin"},
             ]},
        ]