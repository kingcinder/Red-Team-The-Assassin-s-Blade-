import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from tools.recon import ReconTools
from tools.web import WebTools
from tools.wireless import WirelessTools


@pytest.mark.parametrize("toolset", [ReconTools(None), WebTools(None), WirelessTools(None)])
def test_quick_command_templates_require_operator_targets(toolset):
    commands = toolset.get_quick_commands()
    assert commands
    assert all("192.168.1.1" not in str(command) for command in commands)
