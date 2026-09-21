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


def test_ligolo_tunnel_builds_daemon_invocation_not_positional():
    """ligolo_tunnel must emit a headless daemon proxy, not a positional arg.

    The old single-param generic path built `ligolo 127.0.0.1:11601` —
    ligolo takes no positional args, so it blocked on its first-run
    "Enable Ligolo-ng WebUI?" prompt until the step timeout killed it
    (verified live, exit 124). The daemon invocation is what the smoke
    test proved works end to end (agent joins, session established).
    """
    t = tool('ligolo_tunnel', 'ligolo', {'server': {'type': 'string'}})
    cmd = _build_command('/tmp/out', t, {'server': '10.0.0.5:11601'})
    assert cmd == ['ligolo', '-selfcert', '-laddr', '10.0.0.5:11601',
                   '-daemon', '-api-laddr', '127.0.0.1:11602']


def test_amass_enum_uses_enum_subcommand_and_domain_flag():
    cmd = _build_command('/tmp/out', tool('amass_enum', 'amass', {
        'domain': {'type': 'string'},
    }), {'domain': 'localhost'})
    assert cmd == ['amass', 'enum', '-d', 'localhost']


def test_trivy_scan_uses_image_subcommand():
    cmd = _build_command('/tmp/out', tool('trivy_scan', 'trivy', {
        'image': {'type': 'string'},
    }), {'image': 'localhost/nonexistent:image'})
    assert cmd == ['trivy', 'image', 'localhost/nonexistent:image']


def test_recon_ng_gather_uses_workspace_flag():
    cmd = _build_command('/tmp/out', tool('recon_ng_gather', 'recon-ng', {
        'workspace': {'type': 'string'},
    }), {'workspace': 'smoketest'})
    assert cmd == ['recon-ng', '-w', 'smoketest']


def test_linux_exploit_suggester_uses_kernel_flag():
    cmd = _build_command('/tmp/out', tool('linux_exploit_suggester', 'linux-exploit-suggester', {
        'kernel': {'type': 'string'},
    }), {'kernel': '5.15.0'})
    assert cmd == ['linux-exploit-suggester', '-k', '5.15.0']


def test_gospider_crawl_uses_url_flag():
    cmd = _build_command('/tmp/out', tool('gospider_crawl', 'gospider', {
        'url': {'type': 'string'},
    }), {'url': 'http://127.0.0.1:9/'})
    assert cmd == ['gospider', '-u', 'http://127.0.0.1:9/']


def test_gophish_setup_uses_config_flag():
    cmd = _build_command('/tmp/out', tool('gophish_setup', 'gophish', {
        'config': {'type': 'string'},
    }), {'config': '/dev/null'})
    assert cmd == ['gophish', '--config', '/dev/null']


def test_ophcrack_crack_uses_list_flag():
    cmd = _build_command('/tmp/out', tool('ophcrack_crack', 'ophcrack', {
        'hash_file': {'type': 'string'},
    }), {'hash_file': '/dev/null'})
    assert cmd == ['ophcrack', '-l', '/dev/null']


def test_rsmangler_uses_file_flag():
    cmd = _build_command('/tmp/out', tool('rsmangler_mangle', 'rsmangler', {
        'wordlist': {'type': 'string'},
    }), {'wordlist': '/tmp/words.txt'})
    assert cmd == ['rsmangler', '--file', '/tmp/words.txt']


def test_bloodhound_rejects_legacy_neo4j_positional_contract():
    t = tool('bloodhound_analyze', 'bloodhound-python', {
        'neo4j_url': {'type': 'string'},
    })
    try:
        _build_command('/tmp/out', t, {'neo4j_url': 'bolt://127.0.0.1:7687'})
    except ValueError as exc:
        assert 'collector' in str(exc).lower()
    else:
        raise AssertionError('legacy Neo4j URL must not become a positional argv')


def test_nmap_unprivileged_rewrite_only_rewrites_standalone_flag(monkeypatch):
    monkeypatch.setattr(os, 'geteuid', lambda: 1000)
    t = tool('nmap_scan', 'nmap', {})
    assert '-sT' in _build_command('/tmp/out', t, {'target': '127.0.0.1', 'scan_type': '-sS'})
    # scan_type carrying multiple flags must land as separate argv tokens
    # (a single token with embedded spaces makes nmap exit 255 "Scantype
    # not supported"); the -sS rewrite still applies per-flag.
    argv = _build_command('/tmp/out', t, {'target': '127.0.0.1', 'scan_type': '-sS --script vuln'})
    assert argv[1:4] == ['-sT', '--script', 'vuln']


def test_nmap_multi_flag_scan_type_becomes_separate_argv_tokens(monkeypatch):
    # Workflow templates pass scan_type as a multi-flag string (e.g.
    # recon_scan.yaml: "-sS -Pn -T4"). Appending it as ONE argv token made
    # nmap reject the whole scan ("Scantype   not supported"), failing every
    # GUI-driven recon workflow at its first gate step.
    monkeypatch.setattr(os, 'geteuid', lambda: 1000)
    t = tool('nmap_scan', 'nmap', {})
    argv = _build_command('/tmp/out', t, {
        'target': '127.0.0.1', 'ports': '1-1000', 'scan_type': '-sS -Pn -T4'})
    assert '-Pn' in argv and '-T4' in argv, 'each flag must be its own argv token'
    assert argv[1] == '-sT', 'unprivileged rewrite still applies per-flag'
    assert not any(' ' in a for a in argv), 'no argv token may contain a space'


def test_generic_builder_keeps_parameter_order_and_omits_missing_values():
    t = tool('probe', 'probe', {
        'target': {'type': 'string', 'flag': '--target'},
        'verbose': {'type': 'boolean', 'flag': '--verbose'},
    })
    assert _build_command('/tmp/out', t, {'target': 'host', 'verbose': True}) == [
        'probe', '--target', 'host', '--verbose'
    ]
