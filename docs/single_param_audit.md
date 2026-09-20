# Single-Param Builder Audit — exact argv

This report executes the exact argv produced by `ToolRegistry._build_command`; it does not reconstruct `[binary, sample]`.

## Counts

Registry counts: `{'0': 3, '1': 60, 'multi': 97}`

| Tool | Param | Exact argv | Verdict | Evidence |
|---|---|---|---|---|
| `amass_enum` | `domain` | `/home/cody/redteam-tools/bin/amass enum -d localhost` | **OK** | Configuration error: No root domain names were provided |
| `beef_hook` | `target` | `/home/cody/.local/bin/beef-xss 127.0.0.1` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `burpsuite_proxy` | `mode` | `/home/cody/.local/bin/burpsuite help` | **OK** | Error: Unable to access jarfile /tmp/audit-single-param-8xcl45rq/.local/opt/burpsuite/burpsuite.jar |
| `check_tool_status` | `tool_name` | ` smoketest-arg` | **INTERNAL-INTERCEPTED** | Python interceptor owns execution; no shell binary probe |
| `chntpw_dump` | `sam_file` | `/usr/sbin/chntpw smoketest-arg` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `dex2jar_convert` | `dex` | `/home/cody/.local/bin/dex2jar smoketest-arg` | **OK** | dex2jar smoketest-arg -> ./smoketest-arg-dex2jar.jar ; java.nio.file.NoSuchFileException: smoketest-arg ; 	at java.base/sun.nio.fs.UnixException.translateToIOException(UnixException.java:92) ; 	at java.base/sun.nio.fs.UnixException.rethrowAsIOException(UnixException.java:106) ; 	at java.base/sun.nio |
| `dnswalk_enum` | `domain` | `/usr/bin/dnswalk localhost` | **OK** | Old package separator "'" deprecated at /usr/bin/dnswalk line 242. ; Old package separator "'" deprecated at /usr/bin/dnswalk line 257. ; Usage: dnswalk domain ; domain MUST end with a '.' |
| `dnsx_probe` | `domain` | `/home/cody/redteam-tools/bin/dnsx localhost` | **OK** |  ;       _             __  __ ;    __\| \| _ __   ___ \ \/ / ;   / _' \|\| '_ \ / __\| \  /  ;  \| (_\| \|\| \| \| \|\__ \ /  \  ;   \__,_\|\|_\| \|_\|\|___//_/\_\ ;  ; 		projectdiscovery.io ;  ; [[34mINF[0m] Current dnsx version 1.2.3 ([91moutdated[0m) [probe wrote 1 scratch file(s)] |
| `enum4linux_enum` | `target` | `/home/cody/.local/bin/enum4linux 127.0.0.1` | **HANG-REVIEW** | no exit within 8s |
| `exiftool_osint` | `file` | `/usr/bin/exiftool /dev/null` | **OK** | ExifTool Version Number         : 12.76 ; File Name                       : null ; Directory                       : /dev ; File Size                       : 0 bytes ; File Modification Date/Time     : 2026:09:20 03:26:05-07:00 ; File Access Date/Time           : 2026:09:20 03:26:05-07:00 ; File Ino |
| `exiftool_read` | `file` | `/usr/bin/exiftool /dev/null` | **OK** | ExifTool Version Number         : 12.76 ; File Name                       : null ; Directory                       : /dev ; File Size                       : 0 bytes ; File Modification Date/Time     : 2026:09:20 03:26:05-07:00 ; File Access Date/Time           : 2026:09:20 03:26:05-07:00 ; File Ino |
| `gau_fetch` | `domain` | `/home/cody/redteam-tools/bin/gau localhost` | **HANG-REVIEW** | no exit within 8s |
| `gophish_setup` | `config` | `/home/cody/.local/bin/gophish --config smoketest-arg` | **BROKEN-WRAPPER** | /home/cody/.local/bin/gophish: line 2: cd: /tmp/audit-single-param-6qvdj8w1/.local/opt/gophish: No such file or directory |
| `gospider_crawl` | `url` | `/home/cody/redteam-tools/bin/gospider -u http://127.0.0.1:9/` | **REVIEW-AMBIGUOUS** | rc=1, no output |
| `grype_scan` | `image` | `/home/cody/.local/bin/grype localhost/nonexistent:image` | **HANG-REVIEW** | no exit within 8s |
| `hakrawler_crawl` | `url` | `/home/cody/redteam-tools/bin/hakrawler http://127.0.0.1:9/` | **OK** | No urls detected. Hint: cat urls.txt \| hakrawler |
| `hashid_identify` | `hash` | `/usr/bin/hashid 5d41402abc4b2a76b9719d911017c592` | **OK** | Analyzing '5d41402abc4b2a76b9719d911017c592' ; [+] MD2  ; [+] MD5  ; [+] MD4  ; [+] Double MD5  ; [+] LM  ; [+] RIPEMD-128  ; [+] Haval-128  ; [+] Tiger-128  ; [+] Skein-256(128)  ; [+] Skein-512(128)  ; [+] Lotus Notes/Domino 5  ; [+] Skype  ; [+] Snefru-128  ; [+] NTLM  ; [+] Domain Cached Credent |
| `hexeditor_edit` | `file` | `/usr/bin/hexedit /dev/null` | **HANG-REVIEW** | no exit within 8s |
| `holehe_check` | `email` | `/home/cody/.local/bin/holehe probe@localhost` | **BROKEN-WRAPPER** | Traceback (most recent call last): ;   File "/home/cody/.local/bin/holehe", line 5, in <module> ;     from holehe.core import main ; ModuleNotFoundError: No module named 'holehe' |
| `hostname_set` | `name` | `sudo hostnamectl set-hostname smoketest-arg` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `iface_down` | `interface` | `sudo ip link set lo down` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `iface_up` | `interface` | `sudo ip link set lo up` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `install_all_missing` | `max_tools` | ` smoketest-arg` | **INTERNAL-INTERCEPTED** | Python interceptor owns execution; no shell binary probe |
| `install_tool` | `tool_name` | ` smoketest-arg` | **INTERNAL-INTERCEPTED** | Python interceptor owns execution; no shell binary probe |
| `interface_discovery` | `show` | `ip -j link show` | **OK** | [{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"qdisc":"noqueue","operstate":"UNKNOWN","linkmode":"DEFAULT","group":"default","txqlen":1000,"link_type":"loopback","address":"00:00:00:00:00:00","broadcast":"00:00:00:00:00:00"},{"ifindex":2,"ifname":"enp4s0","flags":["NO- |
| `katana_crawl` | `url` | `/home/cody/redteam-tools/bin/katana http://127.0.0.1:9/` | **OK** |  ;    __        __                 ;   / /_____ _/ /____ ____  ___ _ ;  /  '_/ _  / __/ _  / _ \/ _  / ; /_/\_\\_,_/\__/\_,_/_//_/\_,_/							  ;  ; 		projectdiscovery.io ;  ; [[34mINF[0m] Current katana version v1.7.0 ([92mlatest[0m) ; [[31mERR[0m] could not create runner: cause="no inputs sp [probe wrote 2 scratch file(s)] |
| `ldd_analyze` | `binary` | `/usr/bin/ldd /bin/true` | **OK** | 	linux-vdso.so.1 (0x00007ffe6f7c6000) ; 	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x000073ee9c400000) ; 	/lib64/ld-linux-x86-64.so.2 (0x000073ee9c7d1000) |
| `ligolo_tunnel` | `server` | `/home/cody/redteam-tools/bin/ligolo -selfcert -laddr 127.0.0.1:11601 -daemon -api-laddr 127.0.0.1:11602` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `linpeas_run` | `output` | `/home/cody/.local/bin/linpeas smoketest-arg` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `linux_exploit_suggester` | `kernel` | `/home/cody/.local/bin/linux-exploit-suggester -k 5.15.0` | **OK** |  ; [1;37mAvailable information:[0m ;  ; Kernel version: [1;32m5.15.0[0m ; Architecture: [91;1mN/A[0m ; Distribution: [91;1mN/A[0m ; Distribution version: [91;1mN/A[0m ; Additional checks (CONFIG_*, sysctl entries, custom Bash commands): [91;1mN/A[0m ; Package listing: [91;1mN/A[0m ;  ; |
| `linux_smart_enum` | `level` | `/home/cody/.local/bin/lse smoketest-arg` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `lynis_audit` | `audit_type` | `/usr/sbin/lynis smoketest-arg` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `mimikatz_dump` | `command` | `/home/cody/.local/bin/mimikatz id` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `minicom_serial` | `device` | `/usr/bin/minicom smoketest-arg` | **OK** | minicom: cannot open /dev/modem: No such file or directory |
| `mitm6_attack` | `domain` | `/home/cody/.local/bin/mitm6 localhost` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `monitor_mode_disable` | `interface` | `sudo airmon-ng stop lo` | **SKIP-PRIVILEGED** | exact argv requires sudo; no privileged probe |
| `monitor_mode_enable` | `interface` | `sudo airmon-ng start lo` | **SKIP-PRIVILEGED** | exact argv requires sudo; no privileged probe |
| `msf_resource` | `resource` | `/usr/bin/msfconsole -r smoketest-arg -q` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `nbtscan_scan` | `target` | `/usr/bin/nbtscan 127.0.0.1` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `onesixtyone_scan` | `target` | `/usr/bin/onesixtyone 127.0.0.1` | **OK** | Scanning 1 hosts, 2 communities |
| `ophcrack_crack` | `hash_file` | `/usr/bin/ophcrack -l smoketest-arg` | **HANG-REVIEW** | no exit within 8s |
| `photorec_recover` | `device` | `/usr/bin/photorec smoketest-arg` | **OK** | PhotoRec 7.1, Data Recovery Utility, July 2019 ; Christophe GRENIER <grenier@cgsecurity.org> ; https://www.cgsecurity.org ;  ; Unable to open file or device smoketest-arg: No such file or directory |
| `process_list` | `full` | `ps -ef` | **OK** | UID          PID    PPID  C STIME TTY          TIME CMD ; root           1       0  0 03:25 ?        00:00:08 /sbin/init splash ; root           2       0  0 03:25 ?        00:00:00 [kthreadd] ; root           3       2  0 03:25 ?        00:00:00 [pool_workqueue_release] ; root           4       2   |
| `recon_ng_gather` | `workspace` | `/home/cody/.local/bin/recon-ng -w smoketest-arg` | **OK** | /home/cody/.local/bin/recon-ng: line 2: /tmp/audit-single-param-4xo_qb49/.local/opt/recon-ng-venv/bin/python: No such file or directory |
| `rsmangler_mangle` | `wordlist` | `/home/cody/.local/bin/rsmangler --file smoketest-arg` | **OK** | The specified file does not exist |
| `searchsploit_exploit` | `query` | `/usr/local/bin/searchsploit smoketest` | **OK** | Exploits: No Results ; Shellcodes: No Results ; Papers: No Results |
| `searchsploit_search` | `query` | `/usr/local/bin/searchsploit smoketest` | **OK** | Exploits: No Results ; Shellcodes: No Results ; Papers: No Results |
| `setoolkit_attack` | `attack` | `/home/cody/.local/bin/setoolkit smoketest-arg` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `sherlock_search` | `username` | `/home/cody/.local/bin/sherlock smoketest` | **BROKEN-WRAPPER** | Traceback (most recent call last): ;   File "/home/cody/.local/bin/sherlock", line 5, in <module> ;     from sherlock_project.sherlock import main ; ModuleNotFoundError: No module named 'sherlock_project' |
| `smbmap_enum` | `target` | `/usr/bin/smbmap 127.0.0.1` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
| `subfinder_enum` | `domain` | `/home/cody/redteam-tools/bin/subfinder localhost` | **OK** |  ;                __    _____           __          ;    _______  __/ /_  / __(_)___  ____/ /__  _____ ;   / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/ ;  (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /     ; /____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/ ;  ; 		projectdiscovery.io ;  ; [[34mINF[0m] Cu [probe wrote 2 scratch file(s)] |
| `system_info` | `section` | `uname -a` | **OK** | Linux codypc 6.8.0-138-generic #138-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 31 22:41:49 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux |
| `testdisk_recover` | `device` | `/usr/bin/testdisk smoketest-arg` | **OK** | TestDisk 7.1, Data Recovery Utility, July 2019 ; Christophe GRENIER <grenier@cgsecurity.org> ; https://www.cgsecurity.org ;  ; Unable to open file or device smoketest-arg: No such file or directory |
| `torify_tunnel` | `binary` | `/usr/bin/torify /bin/true` | **OK** | (exit 0, silent) |
| `trivy_scan` | `image` | `/home/cody/.local/bin/trivy image localhost/nonexistent:image` | **HANG-REVIEW** | no exit within 8s |
| `waf_detect` | `target` | `/usr/bin/wafw00f 127.0.0.1` | **OK** |  ;                 [1;97m______ ;                [1;97m/      \ ;               [1;97m(  W00f! ) ;                [1;97m\  ____/ ;                [1;97m,,    [1;92m__            [1;93m404 Hack Not Found ;            [1;96m\|`-.__   [1;92m/ /                     [1;91m __     __ ;            |
| `waybackurls_fetch` | `domain` | `/home/cody/redteam-tools/bin/waybackurls localhost` | **OK** | (exit 0, silent) |
| `whois_lookup` | `target` | `/usr/bin/whois 127.0.0.1` | **OK** |  ; # ; # ARIN WHOIS data and services are subject to the Terms of Use ; # available at: https://www.arin.net/resources/registry/whois/tou/ ; # ; # If you see inaccuracies in the results, please report at ; # https://www.arin.net/resources/registry/whois/inaccuracy_reporting/ ; # ; # Copyright 1997-2 |
| `wireshark_gui` | `file` | `/usr/bin/wireshark /dev/null` | **HANG-REVIEW** | no exit within 8s |
| `zap_scan` | `target` | `/snap/bin/zaproxy 127.0.0.1` | **SKIP-DESTRUCTIVE** | destructive-flagged; no exec probe |
