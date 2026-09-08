"""
RedTeam Harness — Mech-Unit CLI (v7.0 P2.6)

`harness.py --mech <command> ...` — the terminal operator's Mech-Unit
entry point. List intents with probe status, compile, run, resume, inspect,
and read VULN-GRAPH next moves. Zero LLM involvement anywhere.
"""
import json
import logging

logger = logging.getLogger("redteam.mech.cli")

MECH_HELP = """\
Mech-Unit commands (deterministic attack runtime — no LLM):
  list                          Show all attack intents + probe status
  probe <intent_id>             Show precondition probe detail for one intent
  run <intent_id> --target K=V  Compile + execute an intent against a target
  compile <intent_id> [--target K=V]   Compile only (preview + plan.json)
  resume <plan_id>              Resume a persisted plan from its last step
  status <plan_id>              Show plan run state summary
  plans                         List every persisted plan run (recoverable)
  next-moves <plan_id>          VULN-GRAPH capitalization suggestions
"""


def _parse_kv(pairs):
    """Parse k=v pairs. A bare value (no '=') is stored under the generic
    key 'target' — manifests may reference {{ target.target }} for it;
    structured k=v pairs are preferred."""
    out = {}
    for item in pairs or []:
        if "=" in item:
            key, _, val = item.partition("=")
            out[key.strip()] = val.strip()
        elif item.strip():
            out["target"] = item.strip()
    return out


def _print(obj):
    print(json.dumps(obj, indent=2, default=str))


def run_mech_cli(config, mech_args) -> int:
    """Dispatch `--mech` subcommands. Returns a process exit code."""
    from core.mech import MechUnit

    if not mech_args:
        print(MECH_HELP)
        return 0

    unit = MechUnit(config=config)
    command, rest = mech_args[0], mech_args[1:]

    if command == "list":
        _print(_list_intents(unit))
        return 0

    if command == "probe":
        if not rest:
            print("usage: --mech probe <intent_id>")
            return 2
        _print(unit.probe(rest[0]))
        return 0

    if command == "run":
        intent_id, target, extra = _split_run_args(rest)
        return _cmd_run(unit, intent_id, target, extra, execute=True)

    if command == "compile":
        intent_id, target, extra = _split_run_args(rest)
        return _cmd_run(unit, intent_id, target, extra, execute=False)

    if command == "resume":
        if not rest:
            print("usage: --mech resume <plan_id>")
            return 2
        result = unit.resume(rest[0])
        _print(result.summary())
        return 0 if result.state in ("done", "failed", "aborted") else 0

    if command == "status":
        if not rest:
            print("usage: --mech status <plan_id>")
            return 2
        _print(unit.status(rest[0]))
        return 0

    if command == "plans":
        _print({"plans": unit.list_plans()})
        return 0

    if command == "next-moves":
        if not rest:
            print("usage: --mech next-moves <plan_id>")
            return 2
        _print(unit.next_moves(rest[0]))
        return 0

    print(f"unknown mech command '{command}'\n\n{MECH_HELP}")
    return 2


def _split_run_args(rest):
    """Split ['wifi_pmkid', '--target', 'bssid=AA:BB', '--facts', 'x=1']
    into (intent_id, target_dict, facts_dict)."""
    intent_id = rest[0] if rest else ""
    target, facts = {}, {}
    i = 1
    while i < len(rest):
        arg = rest[i]
        if arg == "--target":
            target.update(_parse_kv([rest[i + 1]]))
            i += 2
        elif arg == "--facts":
            facts.update(_parse_kv([rest[i + 1]]))
            i += 2
        else:
            i += 1
    return intent_id, target, facts


def _list_intents(unit) -> dict:
    """Intent cards annotated with a one-line probe status summary."""
    out = []
    for card in unit.list_intents():
        probes = unit.probe(card["id"])
        ok_count = sum(1 for p in probes if p.get("ok"))
        missing = [m for p in probes if not p.get("ok") for m in p.get("missing", [])]
        out.append({
            "id": card["id"],
            "name": card["name"],
            "category": card["category"],
            "operator_label": card["operator_label"],
            "outcome": card["outcome"],
            "noise": card["noise"],
            "time_to_impact": card["time_to_impact"],
            "steps": card["steps"],
            "probe_status": f"{ok_count}/{len(probes)} ok",
            "ready": ok_count == len(probes) and len(probes) > 0,
            "missing": missing,
        })
    return {"intents": out, "count": len(out)}


def _cmd_run(unit, intent_id, target, facts, execute: bool) -> int:
    try:
        plan = unit.compile(intent_id, target=target, facts=facts)
    except PermissionError as exc:
        print(f"COMPILE BLOCKED — preconditions failed:\n  {exc}")
        return 3
    except KeyError as exc:
        print(f"unknown intent: {exc}")
        return 2
    except ValueError as exc:
        print(f"manifest error: {exc}")
        return 2

    _print({
        "plan_id": plan.plan_id,
        "plan_dir": plan.plan_dir,
        "runnable": plan.runnable,
        "steps": [{"step": s.step, "tool": s.tool, "args": s.args,
                   "when": s.when, "gate": s.gate} for s in plan.steps],
        "unresolved": [u.to_dict() for u in plan.unresolved],
        "resolution_log": plan.resolution_log,
    })

    if not execute:
        print(f"plan compiled (preview only): {plan.plan_id}")
        return 0
    if not plan.runnable:
        print("plan has unresolved parameters — not executing. "
              "Provide them via --target/--facts or set them in the cockpit.")
        return 3

    result = unit.run(plan)
    summary = result.summary()
    _print(summary)
    if summary.get("findings_count"):
        _print(unit.next_moves(plan.plan_id))
    return 0 if result.state == "done" else 1
