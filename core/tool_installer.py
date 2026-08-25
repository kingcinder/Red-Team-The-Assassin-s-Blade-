"""
RedTeam Harness — Tool Installer (v4.0)
Offline-capable installer that allows the LLM to fetch and install missing
Kali tools mid-engagement. All downloads are cached locally for air-gapped
redeployment.

Supports: apt (.deb), Go binaries (GitHub releases), pip packages,
Ruby gems, and manual script/binary downloads.
"""
import os
import json
import shutil
import logging
import subprocess
import tempfile
import urllib.request
import urllib.error
from typing import Dict, Any, List

logger = logging.getLogger("redteam.installer")

# ── Cache directories ──
CACHE_DIR = os.path.expanduser("~/.cache/redteam-harness")
APT_CACHE_DIR = os.path.join(CACHE_DIR, "apt")
GO_CACHE_DIR = os.path.join(CACHE_DIR, "go-binaries")
PIP_CACHE_DIR = os.path.join(CACHE_DIR, "pip-wheels")
MANUAL_CACHE_DIR = os.path.join(CACHE_DIR, "manual")
LOCAL_BIN = os.path.expanduser("~/.local/bin")

# ── Tool install recipes: binary name → install method + params ──
# Each recipe tells the installer HOW to get a tool if it's missing.
INSTALL_RECIPES: Dict[str, Dict[str, Any]] = {
    # ═══════════ RECON ═══════════
    "amass": {"method": "go", "repo": "owasp-amass/amass/v4", "cmd": "amass"},
    "subfinder": {"method": "go", "repo": "projectdiscovery/subfinder/v2/cmd/subfinder", "cmd": "subfinder"},
    "httpx": {"method": "go", "repo": "projectdiscovery/httpx/cmd/httpx", "cmd": "httpx"},
    "dnsx": {"method": "go", "repo": "projectdiscovery/dnsx/cmd/dnsx", "cmd": "dnsx"},
    "naabu": {"method": "go", "repo": "projectdiscovery/naabu/v2/cmd/naabu", "cmd": "naabu"},
    "katana": {"method": "go", "repo": "projectdiscovery/katana/cmd/katana", "cmd": "katana"},
    "gau": {"method": "go", "repo": "lc/gau/v2/cmd/gau", "cmd": "gau"},
    "waybackurls": {"method": "go", "repo": "tomnomnom/waybackurls", "cmd": "waybackurls"},
    "ffuf": {"method": "go", "repo": "ffuf/ffuf/v2", "cmd": "ffuf"},
    "feroxbuster": {"method": "github_release", "repo": "epi052/feroxbuster",
                     "asset_pattern": "feroxbuster", "ext": "tar.gz"},
    "enum4linux": {"method": "apt", "package": "enum4linux"},
    "nbtscan": {"method": "apt", "package": "nbtscan"},
    "smbmap": {"method": "apt", "package": "smbmap"},
    "zmap": {"method": "apt", "package": "zmap"},
    "dnswalk": {"method": "apt", "package": "dnswalk"},
    "masscan": {"method": "apt", "package": "masscan"},

    # ═══════════ VULN ═══════════
    "nuclei": {"method": "go", "repo": "projectdiscovery/nuclei/v3/cmd/nuclei", "cmd": "nuclei"},
    "grype": {"method": "shell_script", "url": "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
              "args": "-b {bindir}"},
    "trivy": {"method": "shell_script", "url": "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh",
              "args": "-b {bindir}"},
    "searchsploit": {"method": "apt", "package": "exploitdb"},
    "snmpwalk": {"method": "apt", "package": "snmp"},
    "onesixtyone": {"method": "apt", "package": "onesixtyone"},
    "lynis": {"method": "apt", "package": "lynis"},
    "linux-exploit-suggester": {"method": "script",
                                 "url": "https://github.com/The-Z-Labs/linux-exploit-suggester/raw/master/linux-exploit-suggester.sh",
                                 "name": "linux-exploit-suggester"},
    "lse": {"method": "script",
             "url": "https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh",
             "name": "lse"},
    "linpeas": {"method": "script",
                 "url": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh",
                 "name": "linpeas"},

    # ═══════════ WEB ═══════════
    "nikto": {"method": "apt", "package": "nikto"},
    "gobuster": {"method": "apt", "package": "gobuster"},
    "dirb": {"method": "apt", "package": "dirb"},
    "wfuzz": {"method": "apt", "package": "wfuzz"},
    "whatweb": {"method": "apt", "package": "whatweb"},
    "wafw00f": {"method": "pip", "package": "wafw00f"},
    "hakrawler": {"method": "go", "repo": "hakluke/hakrawler", "cmd": "hakrawler"},
    "gospider": {"method": "go", "repo": "jaeles-project/gospider", "cmd": "gospider"},

    # ═══════════ PASSWORD ═══════════
    "hydra": {"method": "apt", "package": "hydra"},
    "john": {"method": "apt", "package": "john"},
    "hashcat": {"method": "apt", "package": "hashcat"},
    "hashid": {"method": "pip", "package": "hashid"},
    "cewl": {"method": "apt", "package": "cewl"},
    "crunch": {"method": "apt", "package": "crunch"},
    "chntpw": {"method": "apt", "package": "chntpw"},
    "fcrackzip": {"method": "apt", "package": "fcrackzip"},
    "pdfcrack": {"method": "apt", "package": "pdfcrack"},

    # ═══════════ WIRELESS ═══════════
    "aircrack-ng": {"method": "apt", "package": "aircrack-ng"},
    "reaver": {"method": "apt", "package": "reaver"},
    "bettercap": {"method": "github_release", "repo": "bettercap/bettercap",
                   "asset_pattern": "bettercap", "ext": "zip"},

    # ═══════════ SNIFFING ═══════════
    "tcpdump": {"method": "apt", "package": "tcpdump"},
    "tshark": {"method": "apt", "package": "tshark"},
    "ettercap": {"method": "apt", "package": "ettercap-text-only"},
    "dsniff": {"method": "apt", "package": "dsniff"},
    "mitm6": {"method": "pip", "package": "mitm6"},
    "responder": {"method": "git", "repo": "SpiderLabs/Responder", "name": "responder"},

    # ═══════════ EXPLOIT ═══════════
    "crackmapexec": {"method": "pip", "package": "crackmapexec"},
    "netexec": {"method": "pip", "package": "netexec"},
    "impacket": {"method": "pip", "package": "impacket"},
    "chisel": {"method": "go", "repo": "jpillora/chisel", "cmd": "chisel"},
    "sshuttle": {"method": "apt", "package": "sshuttle"},
    "evil-winrm": {"method": "pip", "package": "evil-winrm"},
    "certipy": {"method": "pip", "package": "certipy-ad"},

    # ═══════════ FORENSICS ═══════════
    "binwalk": {"method": "apt", "package": "binwalk"},
    "foremost": {"method": "apt", "package": "foremost"},
    "exiftool": {"method": "apt", "package": "libimage-exiftool-perl"},
    "steghide": {"method": "apt", "package": "steghide"},
    "stegseek": {"method": "github_release", "repo": "RoliXor/Stegseek",
                  "asset_pattern": "stegseek", "ext": "zip"},
    "bulk_extractor": {"method": "apt", "package": "bulk-extractor"},
    "dcfldd": {"method": "apt", "package": "dcfldd"},

    # ═══════════ REVERSING ═══════════
    "radare2": {"method": "apt", "package": "radare2"},
    "gdb": {"method": "apt", "package": "gdb"},
    "yara": {"method": "apt", "package": "yara"},
    "apktool": {"method": "apt", "package": "apktool"},
    "jadx": {"method": "github_release", "repo": "skylot/jadx",
              "asset_pattern": "jadx", "ext": "zip"},

    # ═══════════ OSINT ═══════════
    "sherlock": {"method": "pip", "package": "sherlock-project"},
    "holehe": {"method": "pip", "package": "holehe"},
    "theHarvester": {"method": "pip", "package": "theHarvester"},

    # ═══════════ STRESS ═══════════
    "hping3": {"method": "apt", "package": "hping3"},
    "slowhttptest": {"method": "apt", "package": "slowhttptest"},
    "siege": {"method": "apt", "package": "siege"},

    # ═══════════ UTILITY ═══════════
    "ltrace": {"method": "apt", "package": "ltrace"},
    "proxychains4": {"method": "apt", "package": "proxychains4"},

    # ═══════════ SOCIAL ═══════════
    "setoolkit": {"method": "git", "repo": "trustedsec/social-engineer-toolkit", "name": "setoolkit"},
}


class ToolInstaller:
    """
    Installs missing tools on-demand. The LLM can call install_tool()
    mid-engagement to fetch what it needs. Downloads are cached locally
    for offline/air-gapped reuse.
    """

    def __init__(self, tool_registry):
        self.registry = tool_registry
        self._ensure_dirs()

    def _ensure_dirs(self):
        """Create cache and bin directories."""
        for d in [CACHE_DIR, APT_CACHE_DIR, GO_CACHE_DIR, PIP_CACHE_DIR,
                  MANUAL_CACHE_DIR, LOCAL_BIN]:
            os.makedirs(d, exist_ok=True)

        # Ensure ~/.local/bin is in PATH
        path = os.environ.get("PATH", "")
        if LOCAL_BIN not in path:
            os.environ["PATH"] = f"{LOCAL_BIN}:{path}"

    # ═══════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════

    def install_tool(self, tool_name: str) -> Dict[str, Any]:
        """
        Install a missing tool by its binary name or tool definition name.
        Returns a result dict with status, method used, and output.
        """
        logger.info(f"Installing tool: {tool_name}")

        # Resolve tool_name to binary name if it's a harness tool name
        binary_name = self._resolve_binary(tool_name)
        recipe = INSTALL_RECIPES.get(binary_name)

        if not recipe:
            return {
                "status": "error",
                "message": f"No install recipe found for '{tool_name}' (binary: '{binary_name}'). "
                           f"Known tools: {', '.join(sorted(INSTALL_RECIPES.keys())[:30])}...",
                "method": None,
            }

        # Check if already installed
        if shutil.which(binary_name):
            return {
                "status": "already_installed",
                "message": f"{binary_name} is already installed at {shutil.which(binary_name)}",
                "method": None,
            }

        # Dispatch to the right installer
        method = recipe["method"]
        try:
            if method == "apt":
                return self._install_apt(recipe, binary_name)
            elif method == "pip":
                return self._install_pip(recipe, binary_name)
            elif method == "go":
                return self._install_go(recipe, binary_name)
            elif method == "github_release":
                return self._install_github_release(recipe, binary_name)
            elif method == "script":
                return self._install_script(recipe, binary_name)
            elif method == "shell_script":
                return self._install_shell_script(recipe, binary_name)
            elif method == "git":
                return self._install_git(recipe, binary_name)
            else:
                return {"status": "error", "message": f"Unknown install method: {method}",
                        "method": method}
        except Exception as e:
            logger.error(f"Install failed for {tool_name}: {e}", exc_info=True)
            return {"status": "error", "message": str(e), "method": method}

    def list_missing_tools(self) -> List[Dict[str, Any]]:
        """List all tools in the registry that are not currently installed."""
        missing = []
        for name, tool in self.registry.get_all_tools().items():
            if not tool.installed:
                binary = tool.binary
                recipe = INSTALL_RECIPES.get(binary, {})
                missing.append({
                    "tool_name": name,
                    "binary": binary,
                    "category": tool.category,
                    "description": tool.description,
                    "installable": bool(recipe),
                    "install_method": recipe.get("method", "unknown"),
                })
        return missing

    def check_tool_status(self, tool_name: str) -> Dict[str, Any]:
        """Check if a specific tool is installed and get details."""
        binary = self._resolve_binary(tool_name)
        path = shutil.which(binary)
        recipe = INSTALL_RECIPES.get(binary, {})
        tool_def = None
        for name, t in self.registry.get_all_tools().items():
            if t.binary == binary or name == tool_name:
                tool_def = t
                break

        return {
            "tool_name": tool_name,
            "binary": binary,
            "installed": path is not None,
            "path": path,
            "installable": bool(recipe),
            "install_method": recipe.get("method"),
            "category": tool_def.category if tool_def else "unknown",
            "description": tool_def.description if tool_def else "",
        }

    def get_installable_count(self) -> int:
        """Count how many missing tools have install recipes."""
        count = 0
        for name, tool in self.registry.get_all_tools().items():
            if not tool.installed and tool.binary in INSTALL_RECIPES:
                count += 1
        return count

    # ═══════════════════════════════════════════════════════════════
    # INSTALLER METHODS
    # ═══════════════════════════════════════════════════════════════

    def _install_apt(self, recipe: dict, binary: str) -> Dict[str, Any]:
        """Install via apt-get. Caches .deb packages locally."""
        package = recipe["package"]
        logger.info(f"Installing {package} via apt")

        # Check if already installed via dpkg
        ret = subprocess.run(["dpkg", "-s", package], capture_output=True, text=True)
        if ret.returncode == 0:
            return {"status": "already_installed", "message": f"{package} already installed",
                    "method": "apt"}

        # Try apt install
        result = subprocess.run(
            ["sudo", "apt-get", "install", "-y", "-qq", package],
            capture_output=True, text=True, timeout=300
        )

        if result.returncode == 0:
            # Cache the .deb for offline use
            self._cache_apt_package(package)
            # Re-detect in registry
            self.registry._detect_installed()
            return {
                "status": "installed",
                "message": f"{package} installed successfully via apt",
                "method": "apt",
                "output": result.stdout[-500:] if result.stdout else "",
            }
        else:
            return {
                "status": "error",
                "message": f"apt install failed for {package}: {result.stderr[-500:]}",
                "method": "apt",
            }

    def _install_pip(self, recipe: dict, binary: str) -> Dict[str, Any]:
        """Install via pip3. Downloads wheels for offline caching."""
        package = recipe["package"]
        logger.info(f"Installing {package} via pip")

        # Check if already importable
        import_name = package.replace("-", "_").replace(" ", "_")
        ret = subprocess.run(
            ["python3", "-c", f"import {import_name}"],
            capture_output=True, text=True
        )
        if ret.returncode == 0:
            return {"status": "already_installed", "message": f"{package} already installed",
                    "method": "pip"}

        # Download wheel for caching, then install
        wheel_dir = os.path.join(PIP_CACHE_DIR, package)
        os.makedirs(wheel_dir, exist_ok=True)

        result = subprocess.run(
            ["pip3", "install", "--break-system-packages", "--cache-dir", wheel_dir, package],
            capture_output=True, text=True, timeout=300
        )

        if result.returncode == 0:
            self.registry._detect_installed()
            return {
                "status": "installed",
                "message": f"{package} installed successfully via pip",
                "method": "pip",
                "output": result.stdout[-500:] if result.stdout else "",
            }
        else:
            # Fallback: try without --break-system-packages
            result2 = subprocess.run(
                ["pip3", "install", package],
                capture_output=True, text=True, timeout=300
            )
            if result2.returncode == 0:
                self.registry._detect_installed()
                return {
                    "status": "installed",
                    "message": f"{package} installed via pip (fallback)",
                    "method": "pip",
                }
            return {
                "status": "error",
                "message": f"pip install failed for {package}: {result.stderr[-500:]}",
                "method": "pip",
            }

    def _install_go(self, recipe: dict, binary: str) -> Dict[str, Any]:
        """Install via go install. Caches the binary locally."""
        repo = recipe["repo"]
        cmd_name = recipe.get("cmd", binary)
        logger.info(f"Installing {binary} from {repo} via go install")

        # Check if already in GOBIN or PATH
        gobin = os.path.expanduser("~/go/bin")
        cached = os.path.join(GO_CACHE_DIR, cmd_name)

        result = subprocess.run(
            ["go", "install", f"github.com/{repo}@latest"],
            capture_output=True, text=True, timeout=600,
            env={**os.environ, "GOBIN": gobin}
        )

        if result.returncode == 0 and os.path.exists(os.path.join(gobin, cmd_name)):
            # Cache binary for offline use
            src = os.path.join(gobin, cmd_name)
            shutil.copy2(src, cached)
            os.chmod(cached, 0o755)
            # Also install to ~/.local/bin
            shutil.copy2(cached, os.path.join(LOCAL_BIN, cmd_name))
            self.registry._detect_installed()
            return {
                "status": "installed",
                "message": f"{binary} installed from {repo}",
                "method": "go",
                "path": os.path.join(LOCAL_BIN, cmd_name),
            }
        else:
            return {
                "status": "error",
                "message": f"go install failed for {repo}: {result.stderr[-500:]}",
                "method": "go",
            }

    def _install_github_release(self, recipe: dict, binary: str) -> Dict[str, Any]:
        """Download a binary from GitHub releases."""
        repo = recipe["repo"]
        asset_pattern = recipe.get("asset_pattern", binary)
        ext = recipe.get("ext", "tar.gz")
        logger.info(f"Installing {binary} from GitHub release: {repo}")

        cached = os.path.join(GO_CACHE_DIR, binary)
        if os.path.exists(cached) and os.access(cached, os.X_OK):
            shutil.copy2(cached, os.path.join(LOCAL_BIN, binary))
            self.registry._detect_installed()
            return {"status": "installed", "message": f"{binary} restored from cache",
                    "method": "github_release"}

        # Get latest release URL
        try:
            api_url = f"https://api.github.com/repos/{repo}/releases/latest"
            req = urllib.request.Request(api_url, headers={"Accept": "application/vnd.github.v3+json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())

            # Find matching asset
            download_url = None
            for asset in data.get("assets", []):
                name = asset.get("name", "")
                if asset_pattern.lower() in name.lower() and "linux" in name.lower() and "amd64" in name.lower():
                    download_url = asset.get("browser_download_url")
                    break
                if asset_pattern.lower() in name.lower() and ext in name:
                    download_url = asset.get("browser_download_url")
                    break

            if not download_url:
                return {"status": "error", "message": f"No matching release asset found for {binary}",
                        "method": "github_release"}

            # Download to temp
            with tempfile.TemporaryDirectory() as tmpdir:
                dl_path = os.path.join(tmpdir, f"download.{ext}")
                urllib.request.urlretrieve(download_url, dl_path)

                # Extract
                if ext == "zip":
                    import zipfile
                    with zipfile.ZipFile(dl_path) as zf:
                        zf.extractall(tmpdir)
                elif ext in ("tar.gz", "tgz"):
                    import tarfile
                    with tarfile.open(dl_path) as tf:
                        tf.extractall(tmpdir)
                elif ext == "deb":
                    subprocess.run(["sudo", "dpkg", "-i", dl_path], capture_output=True)
                    self.registry._detect_installed()
                    return {"status": "installed", "message": f"{binary} installed from .deb",
                            "method": "github_release"}

                # Find the binary
                found = None
                for root, dirs, files in os.walk(tmpdir):
                    for f in files:
                        if f == binary or (f.startswith(binary) and os.access(os.path.join(root, f), os.X_OK)):
                            found = os.path.join(root, f)
                            break
                    if found:
                        break

                if found:
                    shutil.copy2(found, cached)
                    os.chmod(cached, 0o755)
                    shutil.copy2(cached, os.path.join(LOCAL_BIN, binary))
                    self.registry._detect_installed()
                    return {"status": "installed", "message": f"{binary} installed from GitHub release",
                            "method": "github_release", "path": os.path.join(LOCAL_BIN, binary)}
                else:
                    return {"status": "error", "message": f"Binary not found in release archive",
                            "method": "github_release"}

        except Exception as e:
            return {"status": "error", "message": f"GitHub release install failed: {e}",
                    "method": "github_release"}

    def _install_script(self, recipe: dict, binary: str) -> Dict[str, Any]:
        """Download a script and make it executable."""
        url = recipe["url"]
        name = recipe.get("name", binary)
        logger.info(f"Installing {binary} script from {url}")

        cached = os.path.join(MANUAL_CACHE_DIR, name)
        target = os.path.join(LOCAL_BIN, name)

        try:
            urllib.request.urlretrieve(url, cached)
            os.chmod(cached, 0o755)
            shutil.copy2(cached, target)
            self.registry._detect_installed()
            return {"status": "installed", "message": f"{binary} script installed from {url}",
                    "method": "script", "path": target}
        except Exception as e:
            return {"status": "error", "message": f"Script download failed: {e}",
                    "method": "script"}

    def _install_shell_script(self, recipe: dict, binary: str) -> Dict[str, Any]:
        """Run an install shell script (e.g., grype, trivy)."""
        url = recipe["url"]
        args = recipe.get("args", "")
        logger.info(f"Installing {binary} via shell script from {url}")

        try:
            with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as f:
                urllib.request.urlretrieve(url, f.name)
                script_path = f.name

            os.chmod(script_path, 0o755)
            install_args = args.format(bindir=LOCAL_BIN) if "{bindir}" in args else args
            cmd = f"sh {script_path} {install_args}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            os.unlink(script_path)

            if result.returncode == 0 and shutil.which(binary):
                self.registry._detect_installed()
                return {"status": "installed", "message": f"{binary} installed via shell script",
                        "method": "shell_script", "path": shutil.which(binary)}
            else:
                return {"status": "error",
                        "message": f"Shell script install failed: {result.stderr[-500:]}",
                        "method": "shell_script"}
        except Exception as e:
            return {"status": "error", "message": f"Shell script install failed: {e}",
                    "method": "shell_script"}

    def _install_git(self, recipe: dict, binary: str) -> Dict[str, Any]:
        """Clone a git repo and set up the tool."""
        repo = recipe["repo"]
        name = recipe.get("name", binary)
        logger.info(f"Installing {binary} from git: {repo}")

        target_dir = os.path.join(MANUAL_CACHE_DIR, name)
        try:
            if os.path.exists(target_dir):
                # Pull latest
                subprocess.run(["git", "-C", target_dir, "pull"], capture_output=True, timeout=60)
            else:
                subprocess.run(["git", "clone", "--depth", "1", f"https://github.com/{repo}.git",
                                target_dir], capture_output=True, timeout=120)

            # Create a wrapper script
            wrapper = os.path.join(LOCAL_BIN, name)
            with open(wrapper, "w") as f:
                f.write(f"#!/bin/bash\ncd {target_dir} && python3 {name}.py \"$@\"\n")
            os.chmod(wrapper, 0o755)

            self.registry._detect_installed()
            return {"status": "installed", "message": f"{binary} installed from git: {repo}",
                    "method": "git", "path": wrapper}
        except Exception as e:
            return {"status": "error", "message": f"Git install failed: {e}",
                    "method": "git"}

    # ═══════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════

    def _resolve_binary(self, tool_name: str) -> str:
        """Resolve a harness tool name to its binary name."""
        # Check if it's a tool registry name first
        tool_def = self.registry.get_tool(tool_name)
        if tool_def:
            return tool_def.binary
        # Check all tools for matching name
        for name, t in self.registry.get_all_tools().items():
            if name == tool_name or t.binary == tool_name:
                return t.binary
        # Fallback: use as-is (might be a raw binary name)
        return tool_name

    def _cache_apt_package(self, package: str):
        """Note: apt's own cache (/var/cache/apt/archives/) handles offline .deb caching.
        This method just logs that the package was installed for tracking purposes."""
        logger.info(f"Apt package installed (cached by apt): {package}")

    def install_all_missing(self, max_tools: int = 20) -> Dict[str, Any]:
        """
        Install up to max_tools missing tools that have install recipes.
        Returns summary of what was installed.
        """
        results = {"installed": [], "failed": [], "skipped": []}
        count = 0

        for name, tool in self.registry.get_all_tools().items():
            if count >= max_tools:
                break
            if tool.installed:
                continue
            if tool.binary not in INSTALL_RECIPES:
                results["skipped"].append(name)
                continue

            result = self.install_tool(tool.binary)
            if result["status"] in ("installed", "already_installed"):
                results["installed"].append({"tool": name, "method": result.get("method")})
                count += 1
            else:
                results["failed"].append({"tool": name, "error": result.get("message", "")})

        return {
            "total_installed": len(results["installed"]),
            "total_failed": len(results["failed"]),
            "total_skipped": len(results["skipped"]),
            "details": results,
        }
