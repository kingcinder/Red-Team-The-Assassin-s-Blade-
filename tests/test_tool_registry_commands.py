import os
import sys
from types import SimpleNamespace

# CI runs `python3 tests/test_*.py` (plain-script runner) from the repo root;
# without this insert the `core` package isn't importable when the script dir
# (tests/) is sys.path[0]. Matches the sibling test files.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.command_builder import _build_command


def tool(name, binary, parameters):
    return SimpleNamespace(name=name, binary=binary, path=binary,
                           subcommand=None, parameters=parameters)


def test_tcpdump_preserves_selected_interface_and_filter():
    cmd = _build_command('/tmp/out', tool('tcpdump_capture', 'tcpdump', {}), {
        'interface': 'wlp5s0', 'count': 3, 'filter': 'tcp port 80',
    })
    # tcpdump needs raw socket access → sudo prepended
    assert cmd == ['sudo', 'tcpdump', '-i', 'wlp5s0', '-c', '3', 'tcp port 80']


def test_nmap_unprivileged_rewrite_only_rewrites_standalone_flag(monkeypatch):
    monkeypatch.setattr(os, 'geteuid', lambda: 1000)
    t = tool('nmap_scan', 'nmap', {})
    assert '-sT' in _build_command('/tmp/out', t, {'target': '127.0.0.1', 'scan_type': '-sS'})
    assert '-sT --script vuln' in _build_command('/tmp/out', t, {'target': '127.0.0.1', 'scan_type': '-sS --script vuln'})


def test_generic_builder_keeps_parameter_order_and_omits_missing_values():
    t = tool('probe', 'probe', {
        'target': {'type': 'string', 'flag': '--target'},
        'verbose': {'type': 'boolean', 'flag': '--verbose'},
    })
    assert _build_command('/tmp/out', t, {'target': 'host', 'verbose': True}) == [
        'probe', '--target', 'host', '--verbose'
    ]
