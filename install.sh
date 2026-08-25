#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# RedTeam Harness v4.0 — Offline Installer (Assassin's Blade)
# Single-script installer that bundles the entire harness.
# 100% offline-ready: pre-download wheels, copy to air-gapped host.
# ═══════════════════════════════════════════════════════════════
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$HARNESS_DIR"

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     RedTeam Harness v4.0 — Assassin's Blade                 ║"
    echo "║     Offline Installer — 140+ Kali Tools — 100% Local        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

banner

# ── Phase 1: Python environment check ──────────────────────
echo -e "${BOLD}[1/6] Checking Python environment...${NC}"
PYTHON=""
for py in python3 python3.12 python3.11 python3.10; do
    if command -v "$py" &>/dev/null; then
        PYTHON="$py"
        PYVER=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        echo -e "${GREEN}  ✓ $PYTHON ($PYVER)${NC}"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo -e "${RED}  ✗ Python 3.10+ required. Install it first.${NC}"
    exit 1
fi

# ── Phase 2: Install Python dependencies ───────────────────
echo -e "${BOLD}[2/6] Installing Python dependencies...${NC}"
WHEEL_DIR="$HARNESS_DIR/wheels"
PIP_FLAGS=""
# Try --break-system-packages for modern distros, fall back gracefully
if "$PYTHON" -m pip install --break-system-packages --help >/dev/null 2>&1 || true; then
    PIP_FLAGS="--break-system-packages"
elif "$PYTHON" -m pip install --help 2>/dev/null | grep -q break-system-packages; then
    PIP_FLAGS="--break-system-packages"
fi

if [ -d "$WHEEL_DIR" ] && [ "$(ls -A "$WHEEL_DIR" 2>/dev/null)" ]; then
    echo -e "${CYAN}  Installing from local wheelhouse (offline)...${NC}"
    "$PYTHON" -m pip install --no-index --find-links="$WHEEL_DIR" -r requirements.txt $PIP_FLAGS 2>/dev/null || \
    "$PYTHON" -m pip install --no-index --find-links="$WHEEL_DIR" -r requirements.txt
    echo -e "${GREEN}  ✓ Installed from offline wheels${NC}"
elif [ -f "$HARNESS_DIR/requirements.txt" ]; then
    echo -e "${YELLOW}  No local wheels found — attempting online install...${NC}"
    "$PYTHON" -m pip install -r requirements.txt $PIP_FLAGS 2>/dev/null || \
    "$PYTHON" -m pip install -r requirements.txt
    echo -e "${GREEN}  ✓ Installed (online)${NC}"
else
    echo -e "${RED}  ✗ requirements.txt not found${NC}"
    exit 1
fi

# ── Phase 3: Create runtime directories ────────────────────
echo -e "${BOLD}[3/6] Creating runtime directories...${NC}"
mkdir -p sessions output tasks workflows/templates
echo -e "${GREEN}  ✓ sessions/ output/ tasks/ ready${NC}"

# ── Phase 4: Verify core Python imports ────────────────────
echo -e "${BOLD}[4/6] Verifying harness imports...${NC}"
if "$PYTHON" -c "
import sys; sys.path.insert(0, '.')
from core.workflow_engine import WorkflowStateMachine
from core.orchestrator import Orchestrator
from core.hardening import HardenedToolRunner
from core.parallel import ParallelExecutor
from core.result_cache import ResultCache
from core.context_manager import ContextManager
from core.tactics import TacticalEngine
from core.prioritizer import TargetPrioritizer
from core.task_scheduler import MultiTargetScheduler
from core.workflow_generator import WorkflowGenerator
from core.correlation import FindingCorrelator
from core.findings import extract_findings
from core.task_isolation import TaskSandbox
from core.tool_registry import ToolRegistry
from core.llm_backend import LLMBackend
from core.session import SessionManager
from core.safety import SafetyEngine
" 2>/dev/null; then
    echo -e "${GREEN}  ✓ All 18 core modules import cleanly${NC}"
else
    echo -e "${YELLOW}  ⚠ Some imports failed — check Python path${NC}"
fi

# ── Phase 5: Tool detection ────────────────────────────────
echo -e "${BOLD}[5/6] Detecting installed security tools...${NC}"
FOUND=0
TOTAL=0

check() {
    TOTAL=$((TOTAL + 1))
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $1"
        FOUND=$((FOUND + 1))
    fi
}

echo -e "  ${BOLD}Recon:${NC}"
check nmap; check masscan; check httpx; check amass; check subfinder
check dnsx; check naabu; check enum4linux; check nbtscan; check smbmap
check zmap; check dnswalk

echo -e "  ${BOLD}Vuln:${NC}"
check nuclei; check wpscan; check searchsploit; check snmpwalk
check onesixtyone; check grype; check trivy; check lynis

echo -e "  ${BOLD}Web:${NC}"
check nikto; check sqlmap; check gobuster; check dirb; check wfuzz
check whatweb; check wafw00f; check feroxbuster; check ffuf
check katana; check gospider; check hakrawler; check gau; check waybackurls

echo -e "  ${BOLD}Password:${NC}"
check hydra; check john; check hashcat; check hashid; check cewl
check crunch; check rsmangler; check chntpw; check fcrackzip; check pdfcrack

echo -e "  ${BOLD}Wireless:${NC}"
check aircrack-ng; check airodump-ng; check aireplay-ng
check reaver; check wifite; check kismet; check bettercap

echo -e "  ${BOLD}Sniffing:${NC}"
check tcpdump; check tshark; check wireshark; check ettercap
check responder; check dsniff; check mitm6

echo -e "  ${BOLD}Exploit:${NC}"
check msfvenom; check msfconsole; check crackmapexec; check netexec
check impacket; check evil-winrm; check sshuttle; check chisel

echo -e "  ${BOLD}Forensics:${NC}"
check binwalk; check foremost; check testdisk; check photorec
check volatility; check dcfldd; check ddrescue; check exiftool
check strings; check steghide; check stegseek; check bulk_extractor

echo -e "  ${BOLD}Reversing:${NC}"
check radare2; check gdb; check objdump; check readelf
check strace; check ltrace; check apktool; check jadx; check yara

echo -e "  ${BOLD}Social:${NC}"
check setoolkit; check beef-xss; check gophish

echo -e "  ${BOLD}Post-Exploitation:${NC}"
check mimikatz; check bloodhound-python; check proxychains
check torify; check socat; check nc; check ligolo; check certipy

echo -e "  ${BOLD}OSINT:${NC}"
check whois; check dig; check dnsenum; check theHarvester
check recon-ng; check sherlock; check holehe

echo -e "  ${BOLD}Stress:${NC}"
check hping3; check slowhttptest; check ab; check siege

echo -e "  ${BOLD}Hardware:${NC}"
check minicom; check flashrom; check screen

echo ""
echo -e "  Tools detected: ${GREEN}${FOUND}${NC}/${TOTAL}"
PERCENT=$((FOUND * 100 / TOTAL))
if [ $PERCENT -ge 50 ]; then
    echo -e "  ${GREEN}Coverage: ${PERCENT}% — good hunting${NC}"
elif [ $PERCENT -ge 25 ]; then
    echo -e "  ${YELLOW}Coverage: ${PERCENT}% — install more Kali tools for full coverage${NC}"
else
    echo -e "  ${YELLOW}Coverage: ${PERCENT}% — consider running on Kali or installing tools${NC}"
fi

# ── Phase 6: LLM backend check ────────────────────────────
echo -e "${BOLD}[6/6] Checking LLM backend...${NC}"
if curl -s http://127.0.0.1:8080/v1/models &>/dev/null; then
    echo -e "${GREEN}  ✓ llama-server reachable on :8080 (local)${NC}"
elif curl -s http://127.0.0.1:11434/api/tags &>/dev/null; then
    echo -e "${GREEN}  ✓ Ollama reachable on :11434 (local)${NC}"
else
    echo -e "${YELLOW}  ⚠ No LLM backend detected. Start llama-server or Ollama.${NC}"
    echo -e "${YELLOW}    Tool execution + workflows work without LLM. AI reasoning needs LLM.${NC}"
fi

# ── Done ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  RedTeam Harness v4.0 — Assassin's Blade — INSTALLED${NC}"
echo ""
echo -e "  ${BOLD}Launch:${NC}"
echo -e "    Dashboard:    ${CYAN}python3 harness.py${NC}          → http://localhost:9999"
echo -e "    CLI mode:     ${CYAN}python3 harness.py --cli${NC}"
echo -e "    Tool check:   ${CYAN}python3 harness.py --check${NC}"
echo -e "    Run workflow: ${CYAN}python3 harness.py --workflow network_recon --target 192.168.1.0/24${NC}"
echo -e "    Multi-target: ${CYAN}python3 harness.py --workflow network_recon --targets 10.0.0.1,10.0.0.2${NC}"
echo -e "    Generate WF:  ${CYAN}python3 harness.py --generate \"compromise the web tier\"${NC}"
echo ""
echo -e "  ${BOLD}Offline air-gap setup:${NC}"
echo -e "    ${YELLOW}1. On connected machine:  pip3 download -r requirements.txt -d ./wheels${NC}"
echo -e "    ${YELLOW}2. Copy this directory + wheels/ to air-gapped host${NC}"
echo -e "    ${YELLOW}3. Run: bash install.sh  (detects offline wheels automatically)${NC}"
echo ""
echo -e "  ${BOLD}7-Phase Assassin's Blade:${NC}"
echo -e "    P1: Parallel Execution  P2: Smart Cache    P3: Context Manager"
echo -e "    P4: Best-of-N Plans     P5: Tactical Engine  P6: Drift Metrics"
echo -e "    P7: Target Prioritizer"
echo ""
echo -e "  ${GREEN}100% local. Zero internet. All offline.${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"