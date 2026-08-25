#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          RedTeam Harness — AI-Powered Pentest Cockpit       ║
║  Assassin's Blade v4.0 — 140+ Kali Tools — 100% Offline     ║
╚══════════════════════════════════════════════════════════════╝

Main entry point. Launches the web dashboard and orchestration engine.

Usage:
    python3 harness.py                  # Launch dashboard on port 9999
    python3 harness.py --port 8888      # Custom port
    python3 harness.py --cli            # CLI-only mode
    python3 harness.py --check          # Check tool availability
"""

import os
import sys
import json
import yaml
import logging
import argparse
import shutil
from datetime import datetime

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from core.orchestrator import Orchestrator
from core.tool_registry import ToolRegistry
from core.workflow_generator import WorkflowGenerator

# ═══════════════════════════════════════════════════════════════
# Setup Logging
# ═══════════════════════════════════════════════════════════════
def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    fmt = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")
    # Quiet noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

logger = logging.getLogger("redteam")

# ═══════════════════════════════════════════════════════════════
# Load Configuration
# ═══════════════════════════════════════════════════════════════
def load_config(config_path=None):
    if config_path is None:
        config_path = os.path.join(PROJECT_ROOT, "config.yaml")
    if os.path.exists(config_path):
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {}

# ═══════════════════════════════════════════════════════════════
# CLI Mode
# ═══════════════════════════════════════════════════════════════
def run_workflow_cli(config, workflow_name, variables, resume=False):
    """Run a workflow template from the CLI with full hardening + isolation."""
    orchestrator = Orchestrator(config)
    print(f"\n{'='*60}")
    print(f"  🚀 Running Workflow: {workflow_name}")
    print(f"{'='*60}\n")

    # Show available workflows if name not given
    if not workflow_name:
        print("  Available workflows:\n")
        for wf in orchestrator.list_workflows():
            print(f"  • {wf['name']}  [{wf['category']}] — {wf['description'][:60]}")
        print(f"\n  Usage: python3 harness.py --workflow <name> --target <target> [--var key=value]")
        return

    result = orchestrator.run_workflow(workflow_name, variables, resume=resume)

    if "error" in result:
        print(f"  ✗ ERROR: {result['error']}")
        if "available" in result:
            print(f"  Available: {', '.join(result['available'])}")
        return

    print(f"\n  Workflow: {result.get('workflow')}")
    print(f"  Status:   {result.get('status', 'unknown').upper()}")
    print(f"  Steps:    {result.get('completed_steps', 0)}/{result.get('total_steps', 0)} completed")
    print(f"  Task dir: {result.get('root', '')}")
    print(f"  Output:   {result.get('output_size_mb', 0)} MB")

    if result.get("chain_values"):
        print(f"\n  🔗 Exploit chain values:")
        for k, v in result["chain_values"].items():
            print(f"    {k} = {str(v)[:60]}")

    if result.get("warnings"):
        print(f"\n  ⚠️  Warnings:")
        for w in result["warnings"]:
            print(f"    - Step '{w.get('step')}': {w.get('reason', 'failed')}")

    if result.get("steps"):
        print(f"\n  Step results:")
        for s in result["steps"]:
            icon = "✅" if s.get("status") == "success" else ("⛔" if s.get("gate_failed") else "⚠️")
            print(f"    {icon} {s.get('step', '?'):35s} {s.get('status', '?'):10s} "
                  f"(attempts={s.get('attempts', 0)}, {s.get('duration', '?')}s)")
            if s.get("reason"):
                print(f"       ↳ {s['reason'][:100]}")


def run_generate_cli(config, objective):
    """LLM-generate a workflow from a natural-language objective."""
    orchestrator = Orchestrator(config)
    print(f"\n{'='*60}")
    print(f"  🤖 Generating workflow from objective")
    print(f"  {objective}")
    print(f"{'='*60}\n")

    result = orchestrator.generate_workflow(objective)
    if "error" in result:
        print(f"  ✗ {result['error']}")
        if result.get("validation_errors"):
            for e in result["validation_errors"]:
                print(f"    - {e}")
        return

    print(WorkflowGenerator.summarize_generated(result))
    print(f"\n  Run it with: python3 harness.py --workflow \"{result['name']}\" "
          f"--target <target>")


def run_multi_workflow_cli(config, workflow_name, targets, variables,
                           max_concurrent=None):
    """Run a workflow concurrently against multiple targets."""
    orchestrator = Orchestrator(config)
    print(f"\n{'='*60}")
    print(f"  🚀 Multi-Target Workflow: {workflow_name}")
    print(f"  Targets: {', '.join(targets)}")
    print(f"{'='*60}\n")

    result = orchestrator.run_multi_workflow(
        workflow_name, targets, variables, max_concurrent=max_concurrent)

    if "error" in result:
        print(f"  ✗ ERROR: {result['error']}")
        return

    print(f"  Status: {result.get('status', 'unknown').upper()}")
    print(f"  Combined report: {result.get('report_path', '')}\n")
    print("  Per-target results:")
    for target, r in result.get("per_target", {}).items():
        icon = "✅" if r.get("status") in ("complete", "partial") else "❌"
        print(f"    {icon} {target:20s} {r.get('status', '?'):10s} "
              f"({r.get('steps_count', 0)}/{r.get('total_steps', 0)} steps)")
        if r.get("error"):
            print(f"       ↳ {r['error'][:120]}")

    counts = result.get("findings_summary", {})
    print(f"\n  Pooled findings: {len(result.get('pooled_findings', []))} "
          f"(critical={counts.get('critical', 0)}, "
          f"high={counts.get('high', 0)})")


def run_cli(config):
    """Run the harness in interactive CLI mode."""
    orchestrator = Orchestrator(config)
    session_id = orchestrator.new_session("CLI Engagement")

    print("\n" + "="*60)
    print("  RedTeam Harness — CLI Mode")
    print("  Type 'help' for commands, 'quit' to exit")
    print("="*60)

    # Check LLM connection
    if orchestrator.llm.is_connected():
        print(f"  ✓ LLM connected ({config.get('llm', {}).get('backend', 'unknown')})")
    else:
        print("  ✗ LLM not connected — tool execution will work, but no AI reasoning")

    print(f"  ✓ {orchestrator.tools.get_available_count()}/{orchestrator.tools.get_total_count()} tools available")
    print(f"  Session: {session_id}")
    print("="*60 + "\n")

    while True:
        try:
            user_input = input("\033[96mredteam>\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            break
        if user_input.lower() == "help":
            print_help()
            continue
        if user_input.lower() == "status":
            status = orchestrator.get_status()
            print(json.dumps(status, indent=2))
            continue
        if user_input.lower().startswith("tool "):
            # Direct tool execution: tool nmap_scan target=192.168.1.1
            handle_direct_tool(orchestrator, user_input[5:])
            continue

        # Send through LLM
        result = orchestrator.process_prompt(user_input, session_id)
        final = result.get("final_response", {})
        if final and final.get("llm_response"):
            print(f"\n\033[93m[LLM]\033[0m {final['llm_response']}")
            if final.get("results"):
                for r in final["results"]:
                    status_color = "\033[92m" if r.get("status") == "success" else "\033[91m"
                    print(f"  {status_color}[{r.get('tool', 'unknown')}]\033[0m {r.get('status', 'unknown')} ({r.get('duration_seconds', 0)}s)")

def print_help():
    print("""
  Available commands:
    help              Show this help
    status            Show harness status
    tool <name> <args> Execute a tool directly
    quit / exit       Exit the harness

  Direct tool execution examples:
    tool nmap_scan target=192.168.1.1 ports=1-1000
    tool nikto_scan target=http://192.168.1.1
    tool hydra_brute target=192.168.1.1 service=ssh username=root password_list=/usr/share/wordlists/rockyou.txt
    tool whois_lookup target=example.com
    tool dig_dns domain=example.com record_type=A

  Or just type a natural language prompt and the AI will handle it:
    > Scan 192.168.1.0/24 for open ports and identify web servers
    > Find SQL injection vulnerabilities on http://target.com/page?id=1
    > Brute force SSH on 10.0.0.5 with common passwords
""")

def handle_direct_tool(orchestrator, raw_args):
    """Parse and execute a direct tool command."""
    parts = raw_args.split()
    if len(parts) < 1:
        print("Usage: tool <tool_name> key=value key=value ...")
        return

    tool_name = parts[0]
    args = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            # Type coercion
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False
            else:
                try:
                    value = int(value)
                except ValueError:
                    pass
            args[key] = value

    result = orchestrator.execute_direct(tool_name, args)
    if isinstance(result, dict) and "stdout" in result:
        print(f"\n\033[92m[Result]\033[0m Exit code: {result.get('exit_code')}")
        if result.get("stdout"):
            print(result["stdout"][:5000])
        if result.get("stderr"):
            print(f"\033[91m[stderr]\033[0m {result['stderr'][:1000]}")
    else:
        print(json.dumps(result, indent=2))

# ═══════════════════════════════════════════════════════════════
# Dashboard Mode
# ═══════════════════════════════════════════════════════════════
def run_dashboard(config):
    """Launch the web dashboard."""
    from dashboard.server import create_app
    app = create_app(config)
    port = config.get("harness", {}).get("port", 9999)
    host = config.get("harness", {}).get("host", "0.0.0.0")
    debug = config.get("harness", {}).get("debug", False)

    print(f"\n{'='*60}")
    print(f"  🎯 RedTeam Harness — Dashboard")
    print(f"  http://localhost:{port}")
    print(f"{'='*60}\n")

    app.run(host=host, port=port, debug=debug)

# ═══════════════════════════════════════════════════════════════
# Check Mode
# ═══════════════════════════════════════════════════════════════
def run_check(config):
    """Check tool availability and system status."""
    print(f"\n{'='*60}")
    print(f"  RedTeam Harness — System Check")
    print(f"{'='*60}\n")

    tools = ToolRegistry(config.get("tools", {}))
    status = tools.get_status()

    print(f"  Tools: {status['installed_tools']}/{status['total_tools']} installed\n")

    for cat, info in status["categories"].items():
        icon = {"recon": "🔍", "web": "🌐", "password": "🔓", "exploit": "💥", "osint": "🕵️", "postex": "🔧"}.get(cat, "📦")
        print(f"  {icon} {cat.upper()}: {info['installed']}/{info['total']}")

    print(f"\n  {'─'*50}")
    print(f"  Installed tools:")
    for tool in tools.get_installed_tools():
        print(f"    ✓ {tool.name:25s} [{tool.category}]")

    missing = [t for t in tools.get_all_tools().values() if not t.installed]
    if missing:
        print(f"\n  Missing tools:")
        for tool in missing:
            print(f"    ✗ {tool.name:25s} ({tool.binary})")

    # Check LLM
    from core.llm_backend import LLMBackend
    llm = LLMBackend(config.get("llm", {}))
    print(f"\n  {'─'*50}")
    print(f"  LLM Backend: {config.get('llm', {}).get('backend', 'unknown')}")
    if llm.is_connected():
        print(f"    ✓ Connected at {llm.base_url}")
    else:
        print(f"    ✗ Not connected at {llm.base_url}")

    print()

# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="RedTeam Harness — AI-Powered Penetration Testing Cockpit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 harness.py                  Launch web dashboard
  python3 harness.py --port 8888      Custom port
  python3 harness.py --cli            Interactive CLI mode
  python3 harness.py --check          Check tool availability
  python3 harness.py --config my.yaml Custom config
        """,
    )
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--check", action="store_true", help="Check tool availability")
    parser.add_argument("--port", type=int, default=None, help="Dashboard port")
    parser.add_argument("--host", type=str, default=None, help="Dashboard host")
    parser.add_argument("--config", type=str, default=None, help="Config file path")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--workflow", type=str, nargs="?", const="", default=None,
                        help="Run a workflow template by name (omit name to list available)")
    parser.add_argument("--target", type=str, default=None,
                        help="Target for the workflow (sets the {{target}} variable)")
    parser.add_argument("--var", action="append", default=[],
                        help="Extra workflow variables: --var key=value (repeatable)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume the most recent run of the workflow")
    parser.add_argument("--targets", type=str, default=None,
                        help="Comma-separated targets for concurrent multi-target execution")
    parser.add_argument("--max-concurrent", type=int, default=None,
                        help="Max concurrent targets for multi-target runs")
    parser.add_argument("--generate", type=str, default=None,
                        help="LLM-generate a workflow from a natural-language objective")

    args = parser.parse_args()
    setup_logging(debug=args.debug)

    config = load_config(args.config)
    if args.port:
        config.setdefault("harness", {})["port"] = args.port
    if args.host:
        config.setdefault("harness", {})["host"] = args.host
    if args.debug:
        config.setdefault("harness", {})["debug"] = True

    # Ensure output dirs exist
    os.makedirs(config.get("harness", {}).get("session_dir", "./sessions"), exist_ok=True)
    os.makedirs(config.get("harness", {}).get("output_dir", "./output"), exist_ok=True)
    os.makedirs(config.get("workflow", {}).get("tasks_dir", "./tasks"), exist_ok=True)

    if args.check:
        run_check(config)
    elif args.generate:
        run_generate_cli(config, args.generate)
    elif args.workflow is not None:
        # Build variables from CLI args
        variables = {}
        if args.target:
            variables["target"] = args.target
        for v in args.var:
            if "=" in v:
                key, _, val = v.partition("=")
                variables[key.strip()] = val.strip()

        # Concurrent multi-target mode
        if args.targets:
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
            run_multi_workflow_cli(config, args.workflow, targets, variables,
                                   args.max_concurrent)
        else:
            run_workflow_cli(config, args.workflow, variables, resume=args.resume)
    elif args.cli:
        run_cli(config)
    else:
        run_dashboard(config)


if __name__ == "__main__":
    main()
