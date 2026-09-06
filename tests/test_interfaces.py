import json
import os
import subprocess
import sys
from unittest.mock import patch
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.tool_registry import ToolRegistry
from tools.sniffing import SniffingTools
from tools.wireless import WirelessTools


def test_interface_inventory_preserves_kernel_order_and_fields():
    payload = [
        {"ifname": "wlan9", "link_type": "ether", "flags": ["UP"]},
        {"ifname": "eth7", "link_type": "ether", "flags": []},
        {"ifname": "lo", "link_type": "loopback", "flags": ["UP"]},
    ]
    with patch("core.tool_registry.subprocess.run") as run, patch(
        "core.tool_registry.os.path.isdir", side_effect=lambda p: p == "/sys/class/net/wlan9/wireless"
    ):
        run.return_value = subprocess.CompletedProcess(
            ["ip"], 0, json.dumps(payload), ""
        )
        result = ToolRegistry({"output_dir": os.path.join(tempfile.mkdtemp(), "out")}).get_interface_inventory()
    assert [item["name"] for item in result] == ["wlan9", "eth7"]
    assert result[0]["wireless"] is True and result[0]["up"] is True
    assert result[1]["wireless"] is False and result[1]["up"] is False


def test_interface_inventory_falls_back_on_non_list_ip_json():
    with patch("core.tool_registry.subprocess.run") as run, patch(
        "core.tool_registry.os.listdir", return_value=["lo", "eth0"]
    ), patch("core.tool_registry.os.path.isdir", return_value=False):
        run.return_value = subprocess.CompletedProcess(["ip"], 0, "{}", "")
        result = ToolRegistry({"output_dir": os.path.join(tempfile.mkdtemp(), "out")}).get_interface_inventory()
    assert [item["name"] for item in result] == ["eth0"]


def test_interface_inventory_falls_back_on_malformed_ip_json():
    with patch("core.tool_registry.subprocess.run", side_effect=ValueError), patch(
        "core.tool_registry.os.listdir", return_value=["lo", "wlan0"]
    ), patch("core.tool_registry.os.path.isdir", return_value=False):
        result = ToolRegistry({"output_dir": os.path.join(tempfile.mkdtemp(), "out")}).get_interface_inventory()
    assert [item["name"] for item in result] == ["wlan0"]


def test_capture_presets_require_operator_interface_selection():
    for command in SniffingTools(None).get_quick_commands() + WirelessTools(None).get_quick_commands():
        for value in command.get("args_template", {}).values():
            if isinstance(value, str) and "interface" in command.get("args_template", {}):
                assert value != "eth0"
                assert value != "wlan0"
                assert value != "wlan0mon"


def test_interface_endpoint_is_registered():
    from dashboard.blueprints import core
    assert hasattr(core, "register")
