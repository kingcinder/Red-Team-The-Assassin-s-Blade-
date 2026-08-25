#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# RedTeam Harness — Kali Tool Installer
# Installs 85+ missing security tools via apt, Go, pip, and manual
# Run as root or with sudo for apt packages
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
GOBIN="${HOME}/go/bin"
export PATH="$GOBIN:$PATH"

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }

# ── Detect if we can use sudo ──
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        warn "Not running as root and sudo not available — apt installs may fail"
    fi
fi

# ═══════════════════════════════════════════════════════════════
# PHASE 1: APT PACKAGES
# ═══════════════════════════════════════════════════════════════
install_apt_packages() {
    log "Phase 1: Installing apt packages..."

    # Update package lists first
    $SUDO apt-get update -qq 2>/dev/null || true

    # ── Recon ──
    APT_RECON=(
        gobuster dirb wfuzz whatweb wafw00f
        enum4linux nbtscan smbmap
        zmap dnswalk
        dnsenum fierce
        onesixtyone
        hping3
    )

    # ── Vulnerability ──
    APT_VULN=(
        searchsploit snmp-common snmp-mibs-downloader
        lynis
        onesixtyone
    )

    # ── Web ──
    APT_WEB=(
        wafw00f
    )

    # ── Password ──
    APT_PASS=(
        hashid cewl crunch rsmangler
        chntpw ophcrack fcrackzip pdfcrack
    )

    # ── Wireless ──
    APT_WIRELESS=(
        aircrack-ng
        reaver
        kismet
    )

    # ── Sniffing ──
    APT_SNIFF=(
        ettercap-text-only
        responder
        dsniff
        mitm6
        tcpdump tshark
    )

    # ── Exploitation ──
    APT_EXPLOIT=(
        netexec
        proxychains4
        sshuttle
    )

    # ── Forensics ──
    APT_FOREN=(
        binwalk foremost testdisk photorec
        dcfldd ddrescue
        exiftool
        steghide stegseek
        bulk-extractor
    )

    # ── Reversing ──
    APT_REV=(
        radare2
        gdb
        apktool
        jadx
        dex2jar
        yara
    )

    # ── Social ──
    APT_SOCIAL=(
    )

    # ── Stress ──
    APT_STRESS=(
        slowhttptest
        apache2-utils
        siege
    )

    # ── Hardware ──
    APT_HW=(
        minicom flashrom
    )

    # ── Utility ──
    APT_UTIL=(
        wireshark-common
        hexedit
        proxychains4
        ncat
        socat
    )

    # ── General dependencies ──
    APT_DEPS=(
        python3-dev python3-pip python3-venv
        libssl-dev libffi-dev
        ruby ruby-dev
        golang-go
        wordlists
        seclists
        wordlists-common
    )

    ALL_APT=(
        "${APT_RECON[@]}" "${APT_VULN[@]}" "${APT_WEB[@]}" "${APT_PASS[@]}"
        "${APT_WIRELESS[@]}" "${APT_SNIFF[@]}" "${APT_EXPLOIT[@]}"
        "${APT_FOREN[@]}" "${APT_REV[@]}" "${APT_SOCIAL[@]}"
        "${APT_STRESS[@]}" "${APT_HW[@]}" "${APT_UTIL[@]}" "${APT_DEPS[@]}"
    )

    # Deduplicate
    UNIQUE_APT=($(echo "${ALL_APT[@]}" | tr ' ' '\n' | sort -u))

    log "Installing ${#UNIQUE_APT[@]} apt packages..."
    for pkg in "${UNIQUE_APT[@]}"; do
        if dpkg -s "$pkg" &>/dev/null 2>&1; then
            ok "$pkg (already installed)"
        else
            if $SUDO apt-get install -y -qq "$pkg" 2>/dev/null; then
                ok "$pkg"
            else
                warn "$pkg (not in repos — may need manual install)"
            fi
        fi
    done

    # ── Kali-specific packages (may need Kali repo) ──
    log "Attempting Kali-specific packages..."
    KALI_PKGS=(wpscan zaproxy beef-xss setoolkit mimicatz)
    for pkg in "${KALI_PKGS[@]}"; do
        if command -v "$pkg" &>/dev/null || dpkg -s "$pkg" &>/dev/null 2>&1; then
            ok "$pkg (already installed)"
        else
            if $SUDO apt-get install -y -qq "$pkg" 2>/dev/null; then
                ok "$pkg"
            else
                warn "$pkg (Kali repo required — install from Kali apt source)"
            fi
        fi
    done
}

# ═══════════════════════════════════════════════════════════════
# PHASE 2: GO TOOLS (via go install or GitHub releases)
# ═══════════════════════════════════════════════════════════════
install_go_tools() {
    log "Phase 2: Installing Go-based security tools..."

    mkdir -p "$GOBIN"

    # Ensure Go is available
    if ! command -v go &>/dev/null; then
        warn "Go not found — attempting to install..."
        $SUDO apt-get install -y -qq golang-go 2>/dev/null || {
            fail "Cannot install Go — skipping Go tools"
            return
        }
    fi

    local GO_VERSION=$(go version 2>/dev/null | awk '{print $3}' || echo "unknown")
    log "Go version: $GO_VERSION"

    # ── ProjectDiscovery tools (GitHub releases — faster & more reliable) ──
    install_github_binary() {
        local name="$1" repo="$2" asset_pattern="$3"
        if command -v "$name" &>/dev/null; then
            ok "$name (already installed)"
            return
        fi
        log "Installing $name from $repo..."
        local tmpdir=$(mktemp -d)
        # Get latest release URL
        local url=$(curl -sL "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
            | grep -o "https://[^\"]*${asset_pattern}[^\"]*linux.*amd64[^\"]*\.zip" | head -1)
        if [ -z "$url" ]; then
            # Try .tar.gz
            url=$(curl -sL "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
                | grep -o "https://[^\"]*${asset_pattern}[^\"]*linux.*amd64[^\"]*\.tar\.gz" | head -1)
        fi
        if [ -z "$url" ]; then
            # Fallback: go install
            local gopkg=$(echo "$repo" | sed 's|^[^/]*/||')
            if go install "github.com/$repo@latest" 2>/dev/null; then
                ok "$name (via go install)"
                return
            fi
            fail "$name (could not find release binary)"
            return
        fi
        local ext="${url##*.}"
        curl -sL "$url" -o "$tmpdir/$name.$ext" 2>/dev/null
        if [ "$ext" = "zip" ]; then
            unzip -qo "$tmpdir/$name.$ext" -d "$tmpdir" 2>/dev/null
        elif [ "$ext" = "gz" ]; then
            tar xzf "$tmpdir/$name.$ext" -C "$tmpdir" 2>/dev/null
        fi
        # Find the binary
        local bin=$(find "$tmpdir" -maxdepth 2 -type f -executable -name "$name" 2>/dev/null | head -1)
        if [ -z "$bin" ]; then
            bin=$(find "$tmpdir" -maxdepth 2 -type f -name "$name" 2>/dev/null | head -1)
        fi
        if [ -n "$bin" ]; then
            $SUDO cp "$bin" "$GOBIN/$name" 2>/dev/null || cp "$bin" "$GOBIN/$name" 2>/dev/null
            chmod +x "$GOBIN/$name" 2>/dev/null
            ok "$name"
        else
            # Fallback: go install
            local gopkg=$(echo "$repo" | sed 's|^[^/]*/||')
            if go install "github.com/$repo@latest" 2>/dev/null; then
                ok "$name (via go install)"
            else
                fail "$name (extraction failed)"
            fi
        fi
        rm -rf "$tmpdir"
    }

    # ProjectDiscovery suite
    install_github_binary "subfinder" "projectdiscovery/subfinder" "subfinder"
    install_github_binary "httpx" "projectdiscovery/httpx" "httpx"
    install_github_binary "nuclei" "projectdiscovery/nuclei" "nuclei"
    install_github_binary "naabu" "projectdiscovery/naabu" "naabu"
    install_github_binary "dnsx" "projectdiscovery/dnsx" "dnsx"
    install_github_binary "katana" "projectdiscovery/katana" "katana"
    install_github_binary "gau" "lc/gau" "gau"
    install_github_binary "waybackurls" "tomnomnom/waybackurls" "waybackurls"
    install_github_binary "ffuf" "ffuf/ffuf" "ffuf"
    install_github_binary "hakrawler" "hakluke/hakrawler" "hakrawler"
    install_github_binary "gospider" "jaeles-project/gospider" "gospider"
    install_github_binary "chisel" "jpillora/chisel" "chisel"

    # Additional Go tools via go install
    log "Installing additional Go tools via go install..."
    local GO_TOOLS=(
        "github.com/projectdiscovery/httpx/cmd/httpx"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu"
        "github.com/projectdiscovery/dnsx/cmd/dnsx"
        "github.com/projectdiscovery/katana/cmd/katana"
        "github.com/lc/gau/v2/cmd/gau"
        "github.com/tomnomnom/waybackurls"
        "github.com/ffuf/ffuf/v2"
        "github.com/hakluke/hakrawler"
        "github.com/jaeles-project/gospider"
        "github.com/jpillora/chisel"
        "github.com/projectdiscovery/uncover/cmd/uncover"
        "github.com/projectdiscovery/mapcidr/cmd/mapcidr"
        "github.com/projectdiscovery/cmd/httpx"
    )

    for tool in "${GO_TOOLS[@]}"; do
        local name=$(basename "$tool" | sed 's|/.*||')
        if command -v "$name" &>/dev/null; then
            ok "$name (already installed)"
            continue
        fi
        if go install "$tool@latest" 2>/dev/null; then
            ok "$name"
        else
            warn "$name (go install failed — may need manual install)"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════
# PHASE 3: PYTHON/PIP TOOLS
# ═══════════════════════════════════════════════════════════════
install_pip_tools() {
    log "Phase 3: Installing Python/pip security tools..."

    # ── Core pentest Python packages ──
    PIP_PKGS=(
        impacket
        bloodhound
        certipy-ad
        crackmapexec
        netexec
        wafw00f
        sherlock-project
        holehe
        recon-ng
        theHarvester
        linerpicker
        dnspython
        pwntools
        paramiko
        scapy
        python-nmap
        requests
        beautifulsoup4
        selenium
        websocket-client
        pyyaml
        colorama
        tabulate
        tqdm
        python-whois
        shodan
        censys
        spyse
    )

    log "Installing ${#PIP_PKGS[@]} pip packages..."
    for pkg in "${PIP_PKGS[@]}"; do
        local import_name=$(echo "$pkg" | tr '-' '_' | tr '[:upper:]' '[:lower:]')
        if python3 -c "import $import_name" 2>/dev/null || python3 -c "import ${pkg//-/}" 2>/dev/null; then
            ok "$pkg (already installed)"
        else
            if pip3 install --break-system-packages "$pkg" 2>/dev/null || pip3 install "$pkg" 2>/dev/null; then
                ok "$pkg"
            else
                warn "$pkg (pip install failed)"
            fi
        fi
    done

    # ── Special pip installs ──
    log "Installing special pip tools..."

    # LinPEAS
    if ! command -v linpeas &>/dev/null; then
        local TMPDIR=$(mktemp -d)
        curl -sL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" -o "$TMPDIR/linpeas.sh" 2>/dev/null
        if [ -f "$TMPDIR/linpeas.sh" ]; then
            chmod +x "$TMPDIR/linpeas.sh"
            $SUDO cp "$TMPDIR/linpeas.sh" /usr/local/bin/linpeas 2>/dev/null || cp "$TMPDIR/linpeas.sh" "$HOME/.local/bin/linpeas" 2>/dev/null
            ok "linpeas"
        else
            warn "linpeas (download failed)"
        fi
        rm -rf "$TMPDIR"
    else
        ok "linpeas (already installed)"
    fi

    # Linux Exploit Suggester
    if ! command -v linux-exploit-suggester &>/dev/null; then
        local TMPDIR=$(mktemp -d)
        curl -sL "https://github.com/The-Z-Labs/linux-exploit-suggester/raw/master/linux-exploit-suggester.sh" -o "$TMPDIR/les.sh" 2>/dev/null
        if [ -f "$TMPDIR/les.sh" ]; then
            chmod +x "$TMPDIR/les.sh"
            $SUDO cp "$TMPDIR/les.sh" /usr/local/bin/linux-exploit-suggester 2>/dev/null || cp "$TMPDIR/les.sh" "$HOME/.local/bin/linux-exploit-suggester" 2>/dev/null
            ok "linux-exploit-suggester"
        else
            warn "linux-exploit-suggester (download failed)"
        fi
        rm -rf "$TMPDIR"
    else
        ok "linux-exploit-suggester (already installed)"
    fi

    # LSE (Linux Smart Enumeration)
    if ! command -v lse &>/dev/null; then
        local TMPDIR=$(mktemp -d)
        curl -sL "https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh" -o "$TMPDIR/lse.sh" 2>/dev/null
        if [ -f "$TMPDIR/lse.sh" ]; then
            chmod +x "$TMPDIR/lse.sh"
            $SUDO cp "$TMPDIR/lse.sh" /usr/local/bin/lse 2>/dev/null || cp "$TMPDIR/lse.sh" "$HOME/.local/bin/lse" 2>/dev/null
            ok "lse"
        else
            warn "lse (download failed)"
        fi
        rm -rf "$TMPDIR"
    else
        ok "lse (already installed)"
    fi

    # Grype
    if ! command -v grype &>/dev/null; then
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | $SUDO sh -s -- -b /usr/local/bin 2>/dev/null || \
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "$HOME/.local/bin" 2>/dev/null
        if command -v grype &>/dev/null; then ok "grype"; else warn "grype (install failed)"; fi
    else
        ok "grype (already installed)"
    fi

    # Trivy
    if ! command -v trivy &>/dev/null; then
        $SUDO apt-get install -y -qq trivy 2>/dev/null || \
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | $SUDO sh -s -- -b /usr/local/bin 2>/dev/null
        if command -v trivy &>/dev/null; then ok "trivy"; else warn "trivy (install failed)"; fi
    else
        ok "trivy (already installed)"
    fi
}

# ═══════════════════════════════════════════════════════════════
# PHASE 4: RUBY GEMS
# ═══════════════════════════════════════════════════════════════
install_ruby_tools() {
    log "Phase 4: Installing Ruby security tools..."

    if ! command -v gem &>/dev/null; then
        warn "Ruby gem not found — installing ruby..."
        $SUDO apt-get install -y -qq ruby ruby-dev 2>/dev/null || {
            warn "Cannot install Ruby — skipping"
            return
        }
    fi

    # WPScan
    if ! command -v wpscan &>/dev/null; then
        gem install wpscan 2>/dev/null || $SUDO gem install wpscan 2>/dev/null
        if command -v wpscan &>/dev/null; then ok "wpscan"; else warn "wpscan (gem install failed)"; fi
    else
        ok "wpscan (already installed)"
    fi

    # Bundler for dependency management
    gem install bundler 2>/dev/null || true
}

# ═══════════════════════════════════════════════════════════════
# PHASE 5: MANUAL/SPECIAL INSTALLS
# ═══════════════════════════════════════════════════════════════
install_manual_tools() {
    log "Phase 5: Manual/special installs..."

    local GOBIN="${HOME}/go/bin"

    # ── Feroxbuster (Rust — cargo install) ──
    if ! command -v feroxbuster &>/dev/null; then
        if command -v cargo &>/dev/null; then
            if cargo install feroxbuster 2>/dev/null; then
                ok "feroxbuster"
            else
                warn "feroxbuster (cargo install failed)"
            fi
        else
            # Download binary release
            local tmpdir=$(mktemp -d)
            curl -sL "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz" -o "$tmpdir/ferox.tar.gz" 2>/dev/null
            if [ -f "$tmpdir/ferox.tar.gz" ]; then
                tar xzf "$tmpdir/ferox.tar.gz" -C "$tmpdir" 2>/dev/null
                local bin=$(find "$tmpdir" -name "feroxbuster" -type f | head -1)
                if [ -n "$bin" ]; then
                    chmod +x "$bin"
                    $SUDO cp "$bin" /usr/local/bin/feroxbuster 2>/dev/null || cp "$bin" "$GOBIN/feroxbuster" 2>/dev/null
                    ok "feroxbuster"
                else
                    warn "feroxbuster (extraction failed)"
                fi
            else
                warn "feroxbuster (download failed)"
            fi
            rm -rf "$tmpdir"
        fi
    else
        ok "feroxbuster (already installed)"
    fi

    # ── Bettercap ──
    if ! command -v bettercap &>/dev/null; then
        if command -v snap &>/dev/null; then
            $SUDO snap install bettercap 2>/dev/null || true
        fi
        if ! command -v bettercap &>/dev/null; then
            local tmpdir=$(mktemp -d)
            curl -sL "https://github.com/bettercap/bettercap/releases/latest/download/bettercap_linux_amd64.zip" -o "$tmpdir/bc.zip" 2>/dev/null
            if [ -f "$tmpdir/bc.zip" ]; then
                unzip -qo "$tmpdir/bc.zip" -d "$tmpdir" 2>/dev/null
                local bin=$(find "$tmpdir" -name "bettercap" -type f | head -1)
                if [ -n "$bin" ]; then
                    chmod +x "$bin"
                    $SUDO cp "$bin" /usr/local/bin/bettercap 2>/dev/null || cp "$bin" "$GOBIN/bettercap" 2>/dev/null
                    ok "bettercap"
                else
                    warn "bettercap (extraction failed)"
                fi
            else
                warn "bettercap (download failed)"
            fi
            rm -rf "$tmpdir"
        fi
    else
        ok "bettercap (already installed)"
    fi

    # ── Ligolo ──
    if ! command -v ligolo &>/dev/null && ! command -v ligolo-proxy &>/dev/null; then
        local tmpdir=$(mktemp -d)
        curl -sL "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_linux_amd64.tar.gz" -o "$tmpdir/ligolo.tar.gz" 2>/dev/null
        if [ -f "$tmpdir/ligolo.tar.gz" ]; then
            tar xzf "$tmpdir/ligolo.tar.gz" -C "$tmpdir" 2>/dev/null
            local bin=$(find "$tmpdir" -name "ligolo*" -type f | head -1)
            if [ -n "$bin" ]; then
                chmod +x "$bin"
                $SUDO cp "$bin" /usr/local/bin/ligolo 2>/dev/null || cp "$bin" "$GOBIN/ligolo" 2>/dev/null
                ok "ligolo"
            else
                warn "ligolo (extraction failed)"
            fi
        else
            warn "ligolo (download failed)"
        fi
        rm -rf "$tmpdir"
    else
        ok "ligolo (already installed)"
    fi

    # ── SecLists wordlists ──
    if [ ! -d "/usr/share/seclists" ] && [ ! -d "/usr/share/wordlists/seclists" ]; then
        log "Downloading SecLists wordlists..."
        local tmpdir=$(mktemp -d)
        curl -sL "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.tar.gz" -o "$tmpdir/seclists.tar.gz" 2>/dev/null
        if [ -f "$tmpdir/seclists.tar.gz" ]; then
            $SUDO tar xzf "$tmpdir/seclists.tar.gz" -C /usr/share/ 2>/dev/null
            $SUDO mv /usr/share/SecLists-master /usr/share/seclists 2>/dev/null || true
            ok "seclists"
        else
            warn "seclists (download failed)"
        fi
        rm -rf "$tmpdir"
    else
        ok "seclists (already installed)"
    fi

    # ── RockYou wordlist ──
    if [ ! -f "/usr/share/wordlists/rockyou.txt" ] && [ ! -f "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz" ]; then
        if [ -f "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz" ]; then
            $SUDO tar xzf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /usr/share/wordlists/ 2>/dev/null || true
            ok "rockyou.txt (from seclists)"
        fi
    fi

    # ── Ensure ~/.local/bin is in PATH ──
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc" 2>/dev/null || true
        export PATH="$HOME/.local/bin:$PATH"
    fi
}

# ═══════════════════════════════════════════════════════════════
# PHASE 6: VERIFICATION
# ═══════════════════════════════════════════════════════════════
verify_tools() {
    log "Phase 6: Verifying installation..."

    local TOTAL=0
    local FOUND=0
    local MISSING=0

    # All binaries the harness expects
    local BINARIES=(
        nmap masscan nikto sqlmap hydra john hashcat
        gobuster dirb wfuzz whatweb wafw00f
        enum4linux nbtscan smbmap
        zmap dnswalk fierce dnsenum
        nuclei wpscan searchsploit
        linux-exploit-suggester lse linpeas
        snmpwalk onesixtyone
        grype trivy lynis
        curl wget socat netcat ncat
        hping3 slowhttptest ab siege
        tcpdump tshark ettercap responder dsniff mitm6
        msfconsole msfvenom netexec crackmapexec
        proxychains4 sshuttle chisel bettercap ligolo
        binwalk foremost testdisk photorec dcfldd ddrescue
        exiftool strings steghide stegseek bulk_extractor
        radare2 gdb strace ltrace apktool jadx yara
        minicom flashrom screen hexedit
        wireshark ldd whois dig
        httpx subfinder amass naabu dnsx katana gau waybackurls ffuf
        gospider hakrawler feroxbuster
        impacket bloodhound certipy sherlock holehe
        hashid cewl crunch rsmangler chntpw ophcrack fcrackzip pdfcrack
        python3 pip3 jq
    )

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  TOOL VERIFICATION REPORT${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

    for bin in "${BINARIES[@]}"; do
        TOTAL=$((TOTAL + 1))
        local path=$(command -v "$bin" 2>/dev/null || echo "")
        if [ -n "$path" ]; then
            FOUND=$((FOUND + 1))
            echo -e "  ${GREEN}✓${NC} $bin → $path"
        else
            MISSING=$((MISSING + 1))
            echo -e "  ${RED}✗${NC} $bin"
        fi
    done

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}Found: $FOUND${NC} / $TOTAL tools"
    echo -e "  ${RED}Missing: $MISSING${NC}"
    local PCT=$(( (FOUND * 100) / TOTAL ))
    echo -e "  Coverage: ${PCT}%"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
main() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  RedTeam Harness — Kali Tool Installer v2.0                  ║${NC}"
    echo -e "${CYAN}║  Installing 85+ security tools for the Swiss-Army Knife      ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    install_apt_packages
    echo ""
    install_go_tools
    echo ""
    install_pip_tools
    echo ""
    install_ruby_tools
    echo ""
    install_manual_tools
    echo ""
    verify_tools

    echo -e "${GREEN}═══ Installation complete! ═══${NC}"
    echo ""
    echo "Note: Some tools may require a Kali Linux apt source."
    echo "Add Kali repo: echo 'deb http://http.kali.org/kali kali-rolling main' | sudo tee /etc/apt/sources.list.d/kali.list"
    echo "Then: sudo apt-key adv --keyserver hkps://keyserver.ubuntu.com --recv-keys ED444FF07D8D0BF6"
    echo "And: sudo apt-get update && sudo apt-get install -y <tool-name>"
    echo ""
}

main "$@"
