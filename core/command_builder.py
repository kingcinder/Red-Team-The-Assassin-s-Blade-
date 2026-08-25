"""
RedTeam Harness — Command Builder (architecture candidate #3)
Pure, dependency-free command-construction for every registered tool.

Extracted from core/tool_registry.py: all hand-written and positional
command builders live here as stateless functions keyed by (output_dir, args, binary).
The ToolRegistry delegates its command building to these functions, keeping that
class focused on data (tool registry) + execution (subprocess).
"""


def _build_command(output_dir, tool, args) -> list:
    binary = tool.path or tool.binary
    name = tool.name
    subcmd = tool.subcommand

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
    if name == "socat_relay":      return _build_socat(output_dir, args, binary)
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
        st = args.get("scan_type","-sV")
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
    return [binary, args.get("cap_file","")] + \
           (["-w", args["wordlist"]] if args.get("wordlist") else [])

def _build_nc_listener(output_dir, args, binary):
    return [binary, "-lvnp", str(args.get("port",4444))]

def _build_nc_connect(output_dir, args, binary):
    return [binary, args.get("target",""), str(args.get("port",80))]

def _build_tcpdump(output_dir, args, binary):
    return [binary] + \
           (["-i", args["interface"]] if args.get("interface") else []) + \
           (["-c", str(args["count"])] if args.get("count") else []) + \
           (["-w", args["output_file"]] if args.get("output_file") else []) + \
           ([args["filter"]] if args.get("filter") else [])

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
    cmd = [binary]
    if args.get("ports"): cmd.extend(["-ports", args["ports"]])
    if args.get("tech_detect"): cmd.append("-tech-detect")
    cmd.append(args.get("targets",""))
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

