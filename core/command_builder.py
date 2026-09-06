"""
RedTeam Harness — Command Builder (architecture candidate #3)
Pure, dependency-free command-construction for every registered tool.

Extracted from core/tool_registry.py: all hand-written and positional
command builders live here as stateless functions keyed by (output_dir, args, binary).
The ToolRegistry delegates its command building to these functions, keeping that
class focused on data (tool registry) + execution (subprocess).
"""
import os
import re


def _resolve_capture_path(output_dir: str, value) -> str:
    """Resolve a (possibly relative) capture file/path to an absolute path
    anchored under ``output_dir``.

    Both airdump's ``-w <prefix>`` and aircrack's ``cap_file`` are relative
    to the *process cwd*, which is the per-task sandbox root
    (``sandbox_output_dir``). If a tool were ever run from a different cwd,
    a relative ``-w handshake`` / ``cap_file=handshake-01.cap`` would point
    at *different* locations and the crack step would silently read a
    non-existent file. Anchoring both to an absolute path under the shared
    output_dir makes the chained capture deterministic regardless of cwd.
    """
    if value is None:
        return value
    value = str(value)
    if not value or os.path.isabs(value):
        # Empty values stay empty (don't anchor a missing cap_file to the
        # output_dir as if it were a real file); absolute paths pass through.
        return value
    base = output_dir or os.getcwd()
    return os.path.normpath(os.path.join(base, value))


def _unprivileged_scan_type(scan_type: str) -> str:
    """Downgrade root-only nmap scan flags when the harness is unprivileged.

    nmap -sS (SYN scan) requires root/CAP_NET_RAW and fails with "You
    requested a scan type which requires root privileges." when run as a
    regular user. -sT (TCP connect) is the unprivileged equivalent and
    reports the same port states, so silently substitute it — this keeps
    an engagement moving instead of burning iterations on a scan that can
    never succeed.
    """
    try:
        if os.geteuid() != 0:
            return re.sub(r'(^|\s)-sS(?=\s|$)', r'\1-sT', scan_type)
    except AttributeError:
        pass  # non-POSIX: leave flags untouched
    return scan_type


def _clean_interface(value) -> str:
    """Normalize a user/LLM-supplied interface name into a safe argv token.

    The LLM frequently appends trailing sentence punctuation to interface
    args (e.g. `"interface": "wlan0mon."`), which makes airmon-ng/ip fail
    with a nonexistent-interface error. Strip surrounding whitespace and
    any trailing/non-ledger punctuation (. , ; : " ' ! ?) so `wlan0mon.`
    becomes `wlan0mon`. Returns '' for blank input.
    """
    if not value or not isinstance(value, str):
        return ""
    cleaned = value.strip()
    # Trim one or more trailing punctuation chars (not part of a real iface
    # name, which is [A-Za-z0-9_.-]); never strip a leading dot (hidden devs).
    cleaned = re.sub(r'[.,;:\"\'!?]+$', '', cleaned).strip()
    return cleaned


def _resolve_wordlist(value) -> str:
    """Return an ABSOLUTE wordlist path that actually exists, falling back.

    A typical failure is the LLM guessing `/usr/share/wordlists/dictionary.txt`
    which doesn't exist, stalling aircrack/wifite. If the requested path is
    missing, substitute an existing candidate (repo `wordlists/`, then common
    Kali paths). Returns the candidate as an absolute path because the runner
    executes tools with `cwd=sandbox_output_dir`, so a repo-root-relative
    `./wordlists/rockyou.txt` would otherwise miss the file for the same
    reason the original path did.

    Returns '' when the value is blank (preserves the 'no -w wordlist flag'
    behavior) and gives back the stripped original when no fallback exists so
    the tool surfaces a clear missing-file error.
    """
    if not value or not isinstance(value, str):
        return ""
    requested = value.strip()
    if not requested:
        return ""
    if os.path.exists(requested):
        return os.path.abspath(requested)
    candidates = [
        "./wordlists/rockyou.txt",
        "wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
    ]
    for cand in candidates:
        if os.path.exists(cand):
            return os.path.abspath(cand)
    # Give back the original so the tool surfaces a clear missing-file error.
    return requested


# Tools that must use a MONITOR-mode interface (airmon-ng renames <base> to
# <base>mon). When the operator/LLM passes a base iface that no longer exists
# because it was renamed, adapt to the live monitor variant. This mirrors
# WorkflowStateMachine._adapt_monitor_interface but lives at the pure builder
# chokepoint so it also covers the DIRECT + AUTONOMOUS paths (workflows were
# already covered).
_ADAPT_MONITOR_TOOLS = frozenset({
    "airodump_capture", "aireplay_attack", "reaver_attack",
    "hcxdumptool_capture", "kismet_scan", "wifite_auto",
})

# Tools that legitimately manipulate interfaces themselves and must keep the
# exact user-supplied name (never redirect).
_DONT_ADAPT_TOOLS = frozenset({
    "monitor_mode_enable", "monitor_mode_disable", "iface_up", "iface_down",
    "iface_addr", "route_config", "interface_discovery", "macchanger",
    "ifconfig", "rfkill_status", "airmon_check",
})


def _adapt_monitor_interface(tool_name: str, iface: str) -> str:
    """Map a base wireless iface to a live monitor iface when it needs one.

    airmon-ng renames the real adapter: `airmon-ng start wlan0` creates
    `wlan0mon`. An LLM that passes `wlan0` to airodump/aireplay/reaver/wifite
    would hit a nonexistent-interface error. If the requested iface is for a
    monitor-required tool, doesn't exist on disk, but a `<base>mon`/
    `<base>-mon`/`<base>_mon` variant is live on the system, substitute the
    live monitor iface. Returns the original iface when it needs no adaptation
    (exists already, not a monitor-required tool, or no monitor variant).
    """
    if not iface or not isinstance(iface, str):
        return iface
    if tool_name in _DONT_ADAPT_TOOLS:
        return iface
    if tool_name not in _ADAPT_MONITOR_TOOLS:
        return iface
    if os.path.isdir(f"/sys/class/net/{iface}"):
        return iface  # already exists (base present) — leave it
    variants = (iface + "mon", iface + "-mon", iface + "_mon")
    for v in variants:
        if os.path.isdir(f"/sys/class/net/{v}"):
            return v
    # Loose fallback: any live iface that starts with the base and ends mon.
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name.startswith(iface) and name.endswith("mon"):
                return name
    except OSError:
        pass
    return iface


def _adapt_args_interfaces(tool_name: str, args: dict) -> dict:
    """Apply monitor-rename adaptation to any `interface` arg in-place.

    Returns args unchanged if it has no usable `interface` key.
    """
    if not isinstance(args, dict):
        return args
    iface = args.get("interface")
    if not iface or not isinstance(iface, str):
        return args
    args["interface"] = _adapt_monitor_interface(tool_name, _clean_interface(iface))
    return args


def _build_command(output_dir, tool, args) -> list:
    binary = tool.path or tool.binary
    name = tool.name
    subcmd = tool.subcommand

    # Central monitor-rename + trailing-punctuation adaptation. Runs BEFORE any
    # builder dispatch so the DIRECT, AUTONOMOUS, and WORKFLOW paths all get the
    # same interface normalization (workflows also adapt downstream, which is
    # now redundant-but-idempotent). Cleaned twice is harmless — both helpers
    # are idempotent.
    #
    # Operate on a shallow COPY: _adapt_args_interfaces mutates args in place,
    # and we must not leak the cleaned/adapted interface back into the caller's
    # dict (the runner may reuse or log the original LLM args).
    args = _adapt_args_interfaces(name, dict(args))

    # ── tools needing fully custom builders ──
    _nmap = ("nmap_scan","nmap_vuln_scan","host_discovery","service_enum","banner_grab","subdomain_enum")
    if name in _nmap:  return _build_nmap(output_dir, name, args, binary)
    if name == "masscan_scan":     return _build_masscan(output_dir, args, binary)
    if name == "nikto_scan":       return _build_nikto(output_dir, args, binary)
    if name == "sqlmap_scan":      return _build_sqlmap(output_dir, args, binary)
    if name == "gobuster_dir":     return _build_gobuster(output_dir, args, binary)
    if name == "hydra_brute":      return _build_hydra(output_dir, args, binary)
    if name == "john_crack":       return _build_john(output_dir, args, binary)
    if name == "hashcat_crack":    return _build_hashcat(output_dir, args, binary)
    if name == "curl_request":     return _build_curl(output_dir, args, binary)
    if name == "msfvenom_payload": return _build_msfvenom(output_dir, args, binary)
    if name == "msf_resource":     return _build_msfresource(output_dir, args, binary)
    # msf_auto_exploit is intercepted by the orchestrator before reaching here
    if name == "aircrack_crack":   return _build_aircrack(output_dir, args, binary)
    if name == "netcat_listener":  return _build_nc_listener(output_dir, args, binary)
    if name == "netcat_connect":   return _build_nc_connect(output_dir, args, binary)
    if name == "tcpdump_capture":  return _build_tcpdump(output_dir, args, binary)
    if name == "airodump_capture":  return _build_airodump(output_dir, args, binary)

    if name == "aireplay_attack":  return _build_aireplay(output_dir, args, binary)
    if name == "reaver_attack":    return _build_reaver(output_dir, args, binary)
    if name == "hcxdumptool_capture": return _build_hcxdumptool(output_dir, args, binary)
    if name == "hcxpcapngtool_convert": return _build_hcxpcapngtool(output_dir, args, binary)
    if name == "wifite_auto":        return _build_wifite(output_dir, args, binary)
    if name == "tshark_capture":   return _build_tshark(output_dir, args, binary)
    if name == "bettercap_mitm":   return _build_bettercap(output_dir, args, binary)
    if name == "ettercap_mitm":    return _build_ettercap(output_dir, args, binary)
    if name == "responder_poison": return _build_responder(output_dir, args, binary)
    if name == "dsniff_suite":     return _build_dsniff(output_dir, args, binary)
    if name == "monitor_mode_enable":  return ["sudo", "airmon-ng", "start", _clean_interface(args.get("interface", ""))]
    if name == "monitor_mode_disable": return ["sudo", "airmon-ng", "stop", _clean_interface(args.get("interface", ""))]
    # ── wireless-stack diagnostics (Interface Doctor) ──
    if name == "rfkill_status":   return ["rfkill", "list"]
    if name == "airmon_check":    return ["sudo", "airmon-ng", "check"]
    if name == "socat_relay":      return _build_socat(output_dir, args, binary)
    if name == "interface_discovery": return ["ip", "-j", "link", "show"]
    if name == "hashid_identify":  return [binary, args.get("hash","")]
    # ── tools taking positional args (no --flags needed) ──
    if name in ("whois_lookup", "waf_detect", "exiftool_read", "exiftool_osint"):
        return _simple_positional(output_dir, binary, args, ["target", "file"])
    if name in ("searchsploit_search", "searchsploit_exploit"):
        return _simple_positional(output_dir, binary, args, ["query"])
    if name in ("enum4linux_enum", "nbtscan_scan", "smbmap_enum", "snmpwalk_enum", "onesixtyone_scan"):
        return _simple_positional(output_dir, binary, args, ["target"])
    if name in ("theharvester_gather", "amass_enum", "subfinder_enum", "dnsx_probe",
                 "dnswalk_enum", "naabu_scan", "gau_fetch", "waybackurls_fetch",
                 "katana_crawl", "gospider_crawl", "hakrawler_crawl"):
        return _simple_positional(output_dir, binary, args, ["domain","url","target"])
    if name == "whatweb_scan":
        return _build_whatweb(output_dir, args, binary)
    if name == "dns_enum":
        return _build_dnsenum(output_dir, args, binary)
    if name == "wget_download":
        return _build_wget(output_dir, args, binary)
    if name == "dig_dns":
        return _build_dig(output_dir, args, binary)
    if name == "snmpwalk_enum":
        return _build_snmpwalk(output_dir, args, binary)
    if name == "crunch_gen":
        return _build_crunch(output_dir, args, binary)
    if name == "binwalk_analyze":
        return _build_binwalk(output_dir, args, binary)
    if name == "foremost_carve":
        return _build_foremost(output_dir, args, binary)
    if name == "strings_extract":
        return _build_strings(output_dir, args, binary)
    if name == "cewl_gen":
        return _build_cewl(output_dir, args, binary)
    if name == "httpx_probe":
        return _build_httpx(output_dir, args, binary)
    if name == "objdump_disasm":
        return _build_objdump(output_dir, args, binary)
    if name == "readelf_analyze":
        return _build_readelf(output_dir, args, binary)
    if name in ("strace_trace", "ltrace_trace"):
        return _build_trace(output_dir, name, args, binary)
    if name == "gdb_debug":
        return _build_gdb(output_dir, args, binary)
    if name == "apktool_decompile":
        return _build_apktool(output_dir, args, binary)

    # ── system / backend-manipulation builders (v6.x) ──
    if name == "process_list":    return _build_process_list(output_dir, args, binary)
    if name == "process_kill":    return _build_process_kill(output_dir, args, binary)
    if name == "service_control": return _build_service_control(output_dir, args, binary)
    if name == "iface_up":        return ["sudo", "ip", "link", "set", _clean_interface(args.get("interface","")), "up"]
    if name == "iface_down":      return ["sudo", "ip", "link", "set", _clean_interface(args.get("interface","")), "down"]
    if name == "iface_addr":      return _build_iface_addr(output_dir, args, binary)
    if name == "route_config":    return _build_route_config(output_dir, args, binary)
    if name == "kernel_sysctl":   return _build_kernel_sysctl(output_dir, args, binary)
    if name == "firewall_rule":   return _build_firewall_rule(output_dir, args, binary)
    if name == "hostname_set":    return ["sudo", "hostnamectl", "set-hostname", args.get("name","")]
    if name == "file_chmod":      return ["chmod", args.get("mode",""), args.get("path","")]
    if name == "file_chown":      return ["sudo", "chown", args.get("owner",""), args.get("path","")]
    if name == "package_manager": return _build_package_manager(output_dir, args, binary)
    if name == "system_info":     return _build_system_info(output_dir, args, binary)

    # ── smart generic builder ──
    # Single-param tools: treat as positional (binary value)
    if len(tool.parameters) == 1:
        pname = list(tool.parameters.keys())[0]
        return [binary] + ([args[pname]] if args.get(pname) is not None else [])

    # Multi-param: auto-infer --param-name for each param
    cmd = [binary]
    if subcmd:
        cmd.append(subcmd)

    for pname, pinfo in tool.parameters.items():
        val = args.get(pname)
        if val is None:
            continue

        flag = pinfo.get("flag")
        positional = pinfo.get("positional", False)
        flag_only = pinfo.get("flag_only", False)

        if flag_only:
            if val:
                cmd.append(flag or f"--{pname.replace('_','-')}")
            continue
        if positional:
            cmd.append(str(val))
            continue

        inferred_flag = flag or f"--{pname.replace('_','-')}"
        if isinstance(val, bool):
            if val:
                cmd.append(inferred_flag)
        else:
            cmd.extend([inferred_flag, str(val)])
    return cmd

# ──────────────── SPECIFIC BUILDERS ────────────────

def _build_nmap(output_dir, name, args, binary):
    cmd = [binary]
    target = args.get("target","")
    if name == "nmap_vuln_scan":
        cmd.extend(["--script", args.get("script","vuln")])
    elif name == "host_discovery":
        cmd.append("-sn")
        if args.get("method") == "arp": cmd.append("-PR")
    elif name == "service_enum":
        cmd.extend(["-sV","-sC"])
    elif name == "banner_grab":
        cmd.extend(["-sV","--version-intensity","0"])
    elif name == "subdomain_enum":
        cmd.extend(["--script","dns-brute"])
    else:
        st = _unprivileged_scan_type(args.get("scan_type","-sV"))
        if st: cmd.append(st)
        cmd.extend(["-oN", f"{output_dir}/nmap_{target.replace('/','_').replace('.','_')}.txt"])
    ports = args.get("ports","")
    if ports and ports != "-": cmd.extend(["-p",ports])
    flags = args.get("flags","")
    if flags: cmd.extend(flags.split())
    cmd.append(target)
    return cmd

def _build_masscan(output_dir, args, binary):
    cmd = [binary, "-p", args.get("ports","1-65535"),
           "--rate", str(args.get("rate",1000)),
           "-oJ", f"{output_dir}/masscan_{args.get('target','').replace('/','_')}.json",
           args.get("target","")]
    return cmd

def _build_nikto(output_dir, args, binary):
    cmd = [binary, "-h", args.get("target","")]
    if args.get("port"): cmd.extend(["-p",str(args["port"])])
    if args.get("tuning"): cmd.extend(["-Tuning",args["tuning"]])
    return cmd

def _build_sqlmap(output_dir, args, binary):
    cmd = [binary, "-u", args.get("url","")]
    if args.get("method"): cmd.extend(["--method",args["method"]])
    if args.get("data"): cmd.extend(["--data",args["data"]])
    if args.get("level"): cmd.extend(["--level",str(args["level"])])
    if args.get("risk"): cmd.extend(["--risk",str(args["risk"])])
    if args.get("dbs"): cmd.append("--dbs")
    if args.get("batch", True): cmd.append("--batch")
    cmd.extend(["--output-dir", output_dir])
    return cmd

def _build_gobuster(output_dir, args, binary):
    return [binary, "dir", "-u", args.get("url",""),
            "-w", args.get("wordlist","/usr/share/wordlists/dirb/common.txt")] + \
           (["-x", args["extensions"]] if args.get("extensions") else []) + \
           (["-t", str(args["threads"])] if args.get("threads") else []) + \
           (["--status-codes", args["status_codes"]] if args.get("status_codes") else [])

def _build_hydra(output_dir, args, binary):
    return [binary, "-l", args.get("username",""),
            "-P", args.get("password_list",""),
            "-o", f"{output_dir}/hydra_results.txt"] + \
           (["-s", str(args["port"])] if args.get("port") else []) + \
           (["-t", str(args["threads"])] if args.get("threads") else []) + \
           [args.get("target",""), args.get("service","ssh")]

def _build_john(output_dir, args, binary):
    return [binary] + \
           (["--wordlist", args["wordlist"]] if args.get("wordlist") else []) + \
           (["--format", args["format"]] if args.get("format") else []) + \
           (["--rules", args["rules"]] if args.get("rules") else []) + \
           [args.get("hash_file","")]

def _build_hashcat(output_dir, args, binary):
    return [binary, "-a", str(args.get("attack_mode",0)),
            "-m", str(args.get("mode",0)),
            args.get("hash_file",""), args.get("wordlist","")] + \
           (["-r", args["rules"]] if args.get("rules") else [])

def _build_curl(output_dir, args, binary):
    cmd = [binary, "-s", "-i"]
    m = args.get("method","GET")
    if m != "GET": cmd.extend(["-X", m])
    if args.get("headers"):
        for h in args["headers"].split(";"):
            if ":" in h: cmd.extend(["-H", h.strip()])
    if args.get("data"): cmd.extend(["-d", args["data"]])
    if args.get("cookies"): cmd.extend(["-b", args["cookies"]])
    if args.get("follow_redirects"): cmd.append("-L")
    if args.get("insecure"): cmd.append("-k")
    cmd.append(args.get("url",""))
    return cmd

def _build_msfvenom(output_dir, args, binary):
    return [binary, "-p", args.get("payload",""),
            f"LHOST={args.get('lhost','')}", f"LPORT={args.get('lport',4444)}"] + \
           (["-f", args["format"]] if args.get("format") else []) + \
           (["-o", args["output"]] if args.get("output") else [])

def _build_msfresource(output_dir, args, binary):
    return [binary, "-r", args.get("resource",""), "-q"]

def _build_aircrack(output_dir, args, binary):
    cap = _resolve_capture_path(output_dir, args.get("cap_file", ""))
    wl = _resolve_wordlist(args.get("wordlist", ""))
    return [binary, cap] + (["-w", wl] if wl else [])

def _build_nc_listener(output_dir, args, binary):
    return [binary, "-lvnp", str(args.get("port",4444))]

def _build_nc_connect(output_dir, args, binary):
    return [binary, args.get("target",""), str(args.get("port",80))]

def _build_tcpdump(output_dir, args, binary):
    """tcpdump capture."""
    cmd = ["sudo", binary]
    iface = args.get("interface", "")
    if iface: cmd.extend(["-i", iface])
    if args.get("count"): cmd.extend(["-c", str(args["count"])])
    if args.get("output_file"): cmd.extend(["-w", args["output_file"]])
    if args.get("filter"): cmd.append(args["filter"])
    return cmd

def _build_airodump(output_dir, args, binary):
    """airodump-ng takes flags then the interface as a trailing positional arg.

    Adaptability (v6.2): supports `-w capture_file` (chained from an earlier
    step so aircrack/hashcat can consume the real .cap path) and `--bssid`
    target filter, in addition to channel.
    """
    cmd = ["sudo", binary]
    if args.get("channel"): cmd.extend(["--channel", str(args["channel"])])
    if args.get("bssid"): cmd.extend(["--bssid", str(args["bssid"])])
    cap = args.get("capture_file") or args.get("write") or args.get("output")
    if cap:
        # Anchor the -w prefix to an absolute path under output_dir so the
        # .cap file (written as <prefix>-01.cap) always lands in the same
        # place aircrack will read it, independent of process cwd.
        cmd.extend(["-w", _resolve_capture_path(output_dir, cap)])
    iface = _clean_interface(args.get("interface", ""))
    if iface: cmd.append(iface)
    return cmd

def _build_aireplay(output_dir, args, binary):
    """aireplay-ng: attack flags first, interface last as positional arg."""
    cmd = ["sudo", binary]
    attack = str(args.get("attack", "0"))
    # Deauth: -0 <count>, fakeauth: -1, etc.
    cmd.extend(["-" + attack])
    if args.get("bssid"): cmd.extend(["-a", args["bssid"]])
    iface = _clean_interface(args.get("interface", ""))
    if iface: cmd.append(iface)
    return cmd

def _build_reaver(output_dir, args, binary):
    """reaver: -i <interface> -b <bssid> are the required flags."""
    cmd = ["sudo", binary]
    iface = _clean_interface(args.get("interface", ""))
    if iface: cmd.extend(["-i", iface])
    bssid = args.get("bssid", "")
    if bssid: cmd.extend(["-b", bssid])
    if args.get("channel"): cmd.extend(["-c", str(args["channel"])])
    if args.get("verbose"): cmd.append("-vv")
    return cmd


def _build_hcxdumptool(output_dir, args, binary):
    """hcxdumptool: passive PMKID/EAPOL capture.

    `-o <output>` is anchored to an absolute path under output_dir so the
    resulting .pcapng has a stable path for hcxpcapngtool to convert.
    Captures run continuously; `capture_duration` (default 60s) drives the
    timeout the harness enforces so passive capture is bounded.
    """
    cmd = ["sudo", binary]
    iface = args.get("interface", "")
    if iface: cmd.extend(["-i", iface])
    out = args.get("output_file", "")
    if out: cmd.extend(["-o", _resolve_capture_path(output_dir, out)])
    if args.get("channel"): cmd.extend(["-c", str(args["channel"])])
    if args.get("bssid"): cmd.extend(["--filterlist_ap=", str(args["bssid"])])
    # --rds=1 records the raw handshakes/PMKIDs needed by hcxpcapngtool
    cmd.append("--rds=1")
    # With default run behaviour the tool captures forever; cap via a status
    # flag the harness aligns to (it enforces the step timeout regardless).
    return cmd


def _build_hcxpcapngtool(output_dir, args, binary):
    """hcxpcapngtool: convert capture to hashcat-ready .hc22000 PMKID file."""
    cmd = [binary]
    if args.get("output_file"):
        cmd.extend(["-o", _resolve_capture_path(output_dir, args["output_file"])])
    inp = _resolve_capture_path(output_dir, args.get("input", ""))
    if inp: cmd.append(inp)
    return cmd


def _build_wifite(output_dir, args, binary):
    """wifite_auto: one-shot automated wireless attack (WiFi Auto-Crack Engine).

    wifite takes the interface via `-i <iface>`, never positionally — the
    old single-param generic path emitted `wifite wlan0mon`, which wifite
    rejects with "unrecognized arguments". Needs root for monitor/airmon ops,
    so it is prefixed with sudo like the rest of the wireless suite. Fails
    fast when no interface is given instead of launching wifite's interactive
    scan-and-attack mode for the full step timeout.
    """
    iface = _clean_interface(args.get("interface", ""))
    if not iface:
        raise ValueError("wifite_auto requires an 'interface' arg")
    cmd = ["sudo", binary, "-i", iface]
    # Optional: point wifite at the engagement wordlist instead of its default
    wl = _resolve_wordlist(args.get("wordlist", "")) if args.get("wordlist") else ""
    if wl:
        cmd.extend(["--dict", wl])
    return cmd


def _build_tshark(output_dir, args, binary):
    """tshark: capture with interface and optional filter."""
    cmd = ["sudo", binary]
    iface = _clean_interface(args.get("interface", ""))
    if iface: cmd.extend(["-i", iface])
    if args.get("filter"): cmd.extend(["-f", args["filter"]])
    if args.get("duration"): cmd.extend(["-a", f"duration:{args['duration']}"])
    if args.get("output_file"): cmd.extend(["-w", args["output_file"]])
    else:
        # Write to sandbox output file to avoid hanging on stdout
        cmd.extend(["-w", f"{output_dir}/tshark_capture.pcap"])
    return cmd

def _build_bettercap(output_dir, args, binary):
    """bettercap: run with a caplet or inline script."""
    cmd = ["sudo", binary]
    module = args.get("module", "")
    target = args.get("target", "")
    if module and target:
        cmd.extend(["-autostart", module])
    elif module:
        cmd.extend(["-autostart", module])
    if not module:
        cmd.extend(["-autostart", "events.stream"])
    return cmd

def _build_ettercap(output_dir, args, binary):
    """ettercap: -T (text mode) -i <interface> -M arp //target1 //target2"""
    cmd = ["sudo", binary, "-T", "-q"]
    iface = _clean_interface(args.get("interface", ""))
    if iface: cmd.extend(["-i", iface])
    t1 = args.get("target1", "")
    t2 = args.get("target2", "")
    if t1 and t2:
        cmd.extend(["-M", "arp", f"//{t1}//{t2}//"])
    elif t1:
        cmd.extend(["-M", "arp", f"//{t1}//"])
    return cmd

def _build_responder(output_dir, args, binary):
    """responder: -I <interface> -w (WPAD) -v (verbose)."""
    # NOTE: responder is Python 2 only in this install — command will fail
    # but we build the correct args so the error is clear.
    cmd = [binary]
    iface = _clean_interface(args.get("interface", ""))
    if iface: cmd.extend(["-I", iface])
    if args.get("verbose"): cmd.append("-v")
    cmd.extend(["-w", "-f"])
    return cmd

def _build_dsniff(output_dir, args, binary):
    """dsniff suite: arpspoof, dnsspoof, urlsnarf are separate binaries."""
    tool = args.get("tool", "arpspoof")
    # Map tool names to their actual binary paths
    tool_map = {
        "arpspoof": "arpspoof",
        "dnsspoof": "dnsspoof",
        "urlsnarf": "urlsnarf",
        "filesnarf": "filesnarf",
        "msgsnarf": "msgsnarf",
        "sshmitm": "sshmitm",
        "webmitm": "webmitm",
    }
    real_binary = tool_map.get(tool, tool)
    import shutil
    resolved = shutil.which(real_binary) or binary
    cmd = [resolved]
    target = args.get("target", "")
    if target: cmd.extend(["-t", target])
    return cmd

def _build_socat(output_dir, args, binary):
    cmd = [binary]
    if args.get("listen_addr"): cmd.append(args["listen_addr"])
    if args.get("connect_addr"): cmd.append(args["connect_addr"])
    if args.get("exec_cmd"): cmd.extend(["EXEC:", args["exec_cmd"]])
    return cmd

# ── simple positional helpers for tools that take bare args (no --flags) ──
def _simple_positional(output_dir, binary, args, key_order):
    """Build [binary, val1, val2, ...] trying keys in order."""
    cmd = [binary]
    for key in key_order:
        val = args.get(key)
        if val is not None:
            cmd.append(str(val))
            break
    return cmd

def _build_whatweb(output_dir, args, binary):
    cmd = [binary, args.get("target","")]
    if args.get("aggression"): cmd.extend(["-a", str(args["aggression"])])
    return cmd

def _build_dnsenum(output_dir, args, binary):
    cmd = [binary, args.get("domain","")]
    if args.get("brute"): cmd.append("--enum")
    if args.get("wordlist"): cmd.extend(["-f", args["wordlist"]])
    return cmd

def _build_wget(output_dir, args, binary):
    cmd = [binary, args.get("url","")]
    if args.get("output"): cmd.extend(["-O", args["output"]])
    if args.get("recursive"): cmd.append("-r")
    return cmd

def _build_dig(output_dir, args, binary):
    cmd = [binary]
    if args.get("server"): cmd.append("@" + args["server"])
    cmd.append(args.get("domain",""))
    if args.get("record_type"): cmd.append(args["record_type"])
    return cmd

def _build_snmpwalk(output_dir, args, binary):
    return [binary, "-v", "2c", "-c", args.get("community","public"), args.get("target","")]

def _build_crunch(output_dir, args, binary):
    cmd = [binary, str(args.get("min_len","")), str(args.get("max_len",""))]
    if args.get("charset"): cmd.append(args["charset"])
    if args.get("output"): cmd.extend(["-o", args["output"]])
    return cmd

def _build_binwalk(output_dir, args, binary):
    cmd = [binary]
    if args.get("extract"): cmd.append("-e")
    cmd.append(args.get("file",""))
    return cmd

def _build_foremost(output_dir, args, binary):
    return [binary, "-i", args.get("image",""), "-o", args.get("output_dir","./foremost_out")]

def _build_strings(output_dir, args, binary):
    cmd = [binary]
    if args.get("min_length"): cmd.extend(["-n", str(args["min_length"])])
    cmd.append(args.get("file",""))
    return cmd

def _build_cewl(output_dir, args, binary):
    cmd = [binary, args.get("url","")]
    if args.get("depth"): cmd.extend(["-d", str(args["depth"])])
    return cmd

def _build_httpx(output_dir, args, binary):
    """Build httpx command. Handles both ProjectDiscovery httpx and Python httpx."""
    cmd = [binary]
    targets = args.get("targets", "")
    if isinstance(targets, list):
        targets = ",".join(targets)
    # Check if this is Python httpx (HTTP client) or ProjectDiscovery httpx (probe)
    # ProjectDiscovery: httpx -l <targets> -ports 80,443 -tech-detect
    # Python httpx: httpx <URL> [OPTIONS]
    import shutil
    try:
        import subprocess
        result = subprocess.run([binary, "--help"], capture_output=True, text=True, timeout=3)
        is_pd = "-l" in result.stdout or "-tech-detect" in result.stdout
    except Exception:
        is_pd = False
    if is_pd:
        # ProjectDiscovery httpx
        if targets: cmd.extend(["-l", targets])
        if args.get("ports"): cmd.extend(["-ports", args["ports"]])
        if args.get("tech_detect"): cmd.append("-tech-detect")
    else:
        # Python httpx — just probe a single URL
        url = targets.split(",")[0] if targets else ""
        if url and not url.startswith("http"):
            url = f"http://{url}"
        if url: cmd.append(url)
        if args.get("method"): cmd.extend(["-m", args["method"]])
        if args.get("headers"): cmd.extend(["-h", args["headers"]])
    return cmd

def _build_objdump(output_dir, args, binary):
    cmd = [binary, "-d"]
    if args.get("section"): cmd.extend(["-j", args["section"]])
    cmd.append(args.get("file",""))
    return cmd

def _build_readelf(output_dir, args, binary):
    flags = args.get("flags", "-a")
    return [binary, flags, args.get("file","")]

def _build_trace(output_dir, name, args, binary):
    cmd = [binary, args.get("binary","")]
    if args.get("args"): cmd.append(args["args"])
    return cmd

def _build_gdb(output_dir, args, binary):
    cmd = [binary, "--args", args.get("binary","")]
    if args.get("args"): cmd.append(args["args"])
    return cmd

def _build_apktool(output_dir, args, binary):
    return [binary, args.get("operation","d"), args.get("apk","")]


# ──────────────── SYSTEM / BACKEND-MANIPULATION BUILDERS (v6.x) ────────────────

def _build_process_list(output_dir, args, binary):
    """List processes. No shell, so a pattern can't drive a grep pipe here;
    use -ef (full command lines) by default, -e when a narrow list is wanted.
    The harness reads stdout and can post-filter by pattern itself."""
    return ["ps", "-ef"] if args.get("full", True) else ["ps", "-e"]


def _build_process_kill(output_dir, args, binary):
    """Kill a process by PID (kill) or name (pkill). Requires root for others."""
    sig = 9 if args.get("force") else (args.get("signal") or 15)
    if args.get("name"):
        return ["sudo", "pkill", "-%d" % int(sig), str(args["name"])]
    return ["sudo", "kill", "-%d" % int(sig), str(args.get("pid", ""))]


def _build_service_control(output_dir, args, binary):
    """systemctl <action> <unit>. action limited to a safe allowlist."""
    action = str(args.get("action", "status"))
    allowed = {"start", "stop", "restart", "reload", "enable", "disable", "status"}
    if action not in allowed:
        action = "status"
    return ["sudo", "systemctl", action, str(args.get("unit", ""))]


def _build_iface_addr(output_dir, args, binary):
    """ip addr add|del <address> dev <interface>."""
    action = "add" if args.get("action", "add") == "add" else "del"
    return ["sudo", "ip", "addr", action,
            str(args.get("address", "")), "dev", str(args.get("interface", ""))]


def _build_route_config(output_dir, args, binary):
    """ip route add|del <network> via <gateway>."""
    action = "add" if args.get("action", "add") == "add" else "del"
    return ["sudo", "ip", "route", action,
            str(args.get("network", "")), "via", str(args.get("gateway", ""))]


def _build_kernel_sysctl(output_dir, args, binary):
    """sysctl write (sudo, -w key=value) or read (plain key)."""
    key = str(args.get("key", ""))
    value = args.get("value")
    if value:
        return ["sudo", "sysctl", "-w", "%s=%s" % (key, value)]
    return ["sysctl", key]


def _build_firewall_rule(output_dir, args, binary):
    """iptables -A|-D <chain> <raw spec tokens>.

    spec is a free-form rule string split on whitespace (no shell), e.g.
    "-p tcp --dport 8080 -j REDIRECT --to-port 80".
    """
    flag = "-D" if args.get("action", "add") == "delete" else "-A"
    spec = str(args.get("spec", "")).split()
    return ["sudo", "iptables", flag, str(args.get("chain", "INPUT"))] + spec


def _build_package_manager(output_dir, args, binary):
    """apt-get <action> -y <packages>. action allowlisted; pkgs split on space."""
    action = str(args.get("action", "update"))
    allowed = {"update", "upgrade", "install", "remove", "autoremove", "purge"}
    if action not in allowed:
        action = "update"
    cmd = ["sudo", "apt-get", action, "-y"]
    pkgs = str(args.get("packages", "")).split()
    if pkgs:
        cmd.extend(pkgs)
    return cmd


def _build_system_info(output_dir, args, binary):
    """Gather host facts. No sudo; safe read-only commands."""
    section = args.get("section", "all")
    if section == "kernel":
        return ["uname", "-a"]
    if section == "distro":
        return ["cat", "/etc/os-release"]
    if section == "hostname":
        return ["hostnamectl", "status"]
    if section == "memory":
        return ["free", "-h"]
    if section == "disk":
        return ["df", "-h"]
    # all / default: batched facts via uname + os-release
    return ["uname", "-a"]

