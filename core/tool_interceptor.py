"""
RedTeam Harness - Deep ToolInterceptor module.

Owns ALL Python-level tool execution that bypasses the shell command builder:
the tool installer (install / list-missing / install-all / check-status) and the
Metasploit auto-exploit pipeline. Each interceptor normalizes its result into
the harness's standard tool-result dict so the engagement loop treats it like
any other tool.

Extracted from core/orchestrator.py (candidate #2, architecture review): the
orchestrator's `_run_iteration` / `execute_direct` now call into this module
instead of holding five bespoke private methods inline.
"""
import logging
from typing import Dict, Any

logger = logging.getLogger("redteam.tool_interceptor")

# Tools that must execute sequentially because they modify shared state or need
# special Python-level handling; kept here so the orchestrator can route them
# before parallel dispatch.
INTERCEPTED_TOOLS = frozenset({
    "msf_auto_exploit", "install_tool", "list_missing_tools",
    "install_all_missing", "check_tool_status",
})


class ToolInterceptor:
    """Routes orchestrator-side tool execution that has no shell equivalent."""

    def __init__(self, tools, installer, config: Dict[str, Any], llm=None):
        self._tools = tools
        self._installer = installer
        self._config = config
        self._llm = llm

    # ── Dispatch ──
    def dispatch(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run the interceptor matching *tool_name*."""
        if tool_name == "msf_auto_exploit":
            return self.msf_auto_exploit(args)
        if tool_name == "install_tool":
            return self.install_tool(args)
        if tool_name == "list_missing_tools":
            return self.list_missing()
        if tool_name == "install_all_missing":
            return self.install_all(args)
        if tool_name == "check_tool_status":
            return self.check_status(args)
        raise ValueError(f"{tool_name} is not an intercepted tool")

    # ── Tool installer interceptors ──
    def install_tool(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Route install_tool calls to the ToolInstaller."""
        tool_name = args.get("tool_name", "")
        if not tool_name:
            return _shell_result("", stderr="No tool_name specified", exit_code=1,
                                 command="install_tool(?)")
        result = self._installer.install_tool(tool_name)
        status = result.get("status", "error")
        msg = result.get("message", "")
        method = result.get("method", "")
        path = result.get("path", "")
        stdout = f"Status: {status}\nMethod: {method}\nMessage: {msg}"
        if path:
            stdout += f"\nPath: {path}"
        self._tools._detect_installed()
        return _shell_result(stdout, exit_code=0 if status in ("installed", "already_installed") else 1,
                             command=f"install_tool({tool_name})")

    def list_missing(self) -> Dict[str, Any]:
        """Route list_missing_tools - return all tools not yet installed."""
        missing = self._installer.list_missing_tools()
        installable = [m for m in missing if m["installable"]]
        lines = [f"Missing tools: {len(missing)} total, {len(installable)} installable\n"]
        for m in missing[:30]:
            flag = "OK" if m["installable"] else "-"
            lines.append(f"  {flag} {m['binary']} [{m['category']}] - {m['install_method']}")
        if len(missing) > 30:
            lines.append(f"  ... and {len(missing) - 30} more")
        return _shell_result("\n".join(lines), exit_code=0, command="list_missing_tools()")

    def install_all(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Route install_all_missing - batch install up to N tools (capped at 50)."""
        max_tools = min(int(args.get("max_tools", 20)), 50)
        result = self._installer.install_all_missing(max_tools=max_tools)
        lines = [
            f"Batch install complete (max {max_tools}):",
            f"  Installed: {result['total_installed']}",
            f"  Failed: {result['total_failed']}",
            f"  Skipped: {result['total_skipped']}",
        ]
        for item in result["details"]["installed"]:
            lines.append(f"  OK {item['tool']} ({item.get('method', '?')})")
        for item in result["details"]["failed"][:10]:
            lines.append(f"  - {item['tool']}: {item.get('error', '')[:80]}")
        self._tools._detect_installed()
        return _shell_result("\n".join(lines), exit_code=0,
                             command=f"install_all_missing(max={max_tools})")

    def check_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Route check_tool_status - return install status for a tool."""
        tool_name = args.get("tool_name", "")
        if not tool_name:
            return _shell_result("", stderr="No tool_name specified", exit_code=1,
                                 command="check_tool_status(?)")
        status = self._installer.check_tool_status(tool_name)
        lines = [
            f"Tool: {status['tool_name']}",
            f"Binary: {status['binary']}",
            f"Installed: {status['installed']}",
            f"Path: {status['path'] or 'N/A'}",
            f"Installable: {status['installable']}",
            f"Install method: {status['install_method'] or 'N/A'}",
            f"Category: {status['category']}",
            f"Description: {status['description']}",
        ]
        return _shell_result("\n".join(lines), exit_code=0,
                             command=f"check_tool_status({tool_name})")

    # ── Metasploit auto-exploit ──
    def msf_auto_exploit(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run the full MSF auto-exploit pipeline (Python-level, not shell).
        Returns a normalized tool-result dict compatible with the engagement loop."""
        from core.msf_generator import MetasploitScriptGenerator  # local import to avoid circular
        msf = MetasploitScriptGenerator(llm=self._llm, tools=self._tools, config=self._config)
        result = msf.auto_exploit(
            nmap_output=args.get("nmap_output", ""),
            lhost=args.get("lhost", "0.0.0.0"),
            lport=int(args.get("lport", 4444)),
            payload=args.get("payload", ""),
            objective=args.get("objective", ""),
            execute=bool(args.get("execute", False)),
        )
        stdout_lines = []
        if result.get("services"):
            stdout_lines.append(f"Parsed {len(result['services'])} services")
        if result.get("exploits_found"):
            stdout_lines.append(f"Found {result['exploits_found']} matching exploits")
        if result.get("validation"):
            v = result["validation"]
            stdout_lines.append(f"Validation: {'PASS' if v.get('valid') else 'WARN'} - {v.get('warnings', [])}")
        if result.get("rc_path"):
            stdout_lines.append(f"RC script saved: {result['rc_path']}")
        if result.get("execution"):
            ex = result["execution"]
            stdout_lines.append(f"Execution: exit_code={ex.get('exit_code')}, duration={ex.get('duration')}s")
            if ex.get("stdout"):
                stdout_lines.append(f"MSF Output (first 2000 chars):\n{ex['stdout'][:2000]}")
        if result.get("error"):
            return _shell_result("", stderr=result["error"], exit_code=-1)
        rc_content = result.get("rc_content", "")
        if rc_content:
            stdout_lines.extend(["", "RC Content:", rc_content[:3000]])
        return _shell_result("\n".join(stdout_lines), exit_code=0, command="msf_auto_exploit")


def _shell_result(stdout: str, stderr: str = "", exit_code: int = 0,
                  command: str = "") -> Dict[str, Any]:
    """Build a standard normalized tool-result dict."""
    return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code,
            "duration": 0, "command": command}