"""
RedTeam Harness — Mech-Unit (v7.0)

Deterministic-first attack runtime: attack intent manifests → compiled plan
DAG → hardened execution. The LLM is an optional advisor, never a dependency.

Module map (v7.0):
    intents.py    — attack intent manifest loader + fail-fast schema validation
    probes.py     — capability probes (adapters, tools, wordlists, privileges)
    resolver.py   — deterministic parameter resolution (param ← source log)
    compiler.py   — intent + live state → validated plan DAG
    executor.py   — DAG walker: gates, retries, fallbacks (via tool_registry)
    state.py      — plan state machine + atomic persistence + resume
    events.py     — typed event bus (SocketIO relay mapping)
    advisors.py   — optional bounded LLM advisor (compile/preview-time only)
    vuln_graph.py — VULN-GRAPH capitalization engine (findings → next moves)

Design contract (docs/MECH_UNIT_REFACTOR_MANIFEST.md):
    - Every step in every manifest carries llm_required: false (enforced by
      the schema validator — an LLM is never needed to run a plan).
    - The executor calls tools ONLY through tool_registry + hardening
      (list-mode subprocess, kill cascade). No raw subprocess in this package.
    - Plan state persists atomically via core.state_store.atomic_write_json.
"""
import os
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("redteam.mech")

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_MANIFEST_DIR = os.path.join(_REPO_ROOT, "attacks")
DEFAULT_GRAPH_PATH = os.path.join(DEFAULT_MANIFEST_DIR, "vuln_graph.yaml")
DEFAULT_SANDBOX_ROOT = os.path.join(_REPO_ROOT, "tasks", "mech")


class MechUnit:
    """Facade over the Mech-Unit runtime — the only class the dashboard,
    CLI, and orchestrator bridge need to know.

    Public API (plan P2.5):
        list_intents()        → cockpit card payloads
        probe(intent_id)      → precondition probe results for one intent
        compile(...)          → CompiledPlan (blocked by failed probes)
        run(plan)             → execute via HardenedToolRunner
        resume(plan_id)       → continue from the last persisted step
        abort(plan_id)        → cooperative stop
        status(plan_id)       → run summary
        next_moves(plan_id)   → VULN-GRAPH capitalization suggestions
    """

    def __init__(self, config: Optional[dict] = None,
                 manifest_dir: Optional[str] = None,
                 sandbox_root: Optional[str] = None,
                 graph_path: Optional[str] = None):
        cfg = config or {}
        mech_cfg = cfg.get("mech", {}) if isinstance(cfg, dict) else {}
        self.manifest_dir = manifest_dir or mech_cfg.get(
            "manifest_dir", DEFAULT_MANIFEST_DIR)
        self.sandbox_root = sandbox_root or mech_cfg.get(
            "sandbox_root", DEFAULT_SANDBOX_ROOT)
        self.graph_path = graph_path or mech_cfg.get(
            "vuln_graph", DEFAULT_GRAPH_PATH)
        self._intents: Dict[str, Any] = {}
        self._loaded_dir: Optional[str] = None
        self._plans: Dict[str, Any] = {}
        self._run_states: Dict[str, Any] = {}
        self._executors: Dict[str, Any] = {}
        self._abort_requested: set = set()
        self._graph = None
        self._graph_loaded = False

    # ── intents ──────────────────────────────────────────────────────

    def _load_intents(self) -> Dict[str, Any]:
        if self._loaded_dir == self.manifest_dir and self._intents:
            return self._intents
        from core.mech.intents import load_manifest_dir
        self._intents = load_manifest_dir(self.manifest_dir)
        self._loaded_dir = self.manifest_dir
        return self._intents

    def list_intents(self) -> List[Dict[str, Any]]:
        """Cockpit card payloads for every loaded intent."""
        return [m.to_dict() for m in self._load_intents().values()]

    def get_intent(self, intent_id: str):
        manifest = self._load_intents().get(intent_id)
        if manifest is None:
            raise KeyError(f"unknown intent '{intent_id}'")
        return manifest

    # ── probing ──────────────────────────────────────────────────────

    def probe(self, intent_id: str) -> List[Dict[str, Any]]:
        """Run (not block on) an intent's precondition probes — intent-wall
        greying + 'what's missing' surfacing."""
        from core.mech.probes import run_probe
        manifest = self.get_intent(intent_id)
        results = []
        for spec in manifest.preconditions:
            results.append(run_probe(spec.probe, spec.params).to_dict())
        return results

    # ── compiling ────────────────────────────────────────────────────

    def _resolve_context(self, target: Optional[Dict[str, Any]],
                         facts: Optional[Dict[str, Any]],
                         capture_state=None):
        from core.mech.resolver import ResolveContext
        iface = None
        scan: Dict[str, Any] = {}
        if capture_state is not None:
            try:
                iface = capture_state.get()
                scan = capture_state.get_scan() or {}
            except Exception:
                iface, scan = None, {}
        return ResolveContext(
            target=dict(target or {}), facts=dict(facts or {}),
            capture_interface=iface, scan=scan)

    def compile(self, intent_id: str,
                target: Optional[Dict[str, Any]] = None,
                facts: Optional[Dict[str, Any]] = None,
                plan_id: Optional[str] = None,
                capture_state=None):
        """Compile an intent into a runnable plan.

        Raises PermissionError with the probe reason + fix on hard
        precondition failure; KeyError on unknown intent.
        """
        from core.mech.compiler import compile_intent
        manifest = self.get_intent(intent_id)
        ctx = self._resolve_context(target, facts, capture_state)
        plan = compile_intent(manifest, ctx, sandbox_root=self.sandbox_root,
                              plan_id=plan_id)
        self._plans[plan.plan_id] = plan
        from core.mech.state import PlanRunState
        self._run_states[plan.plan_id] = PlanRunState(
            plan_id=plan.plan_id, intent_id=manifest.id,
            plan_dir=plan.plan_dir)
        self._run_states[plan.plan_id].save()
        return plan

    # ── execution ────────────────────────────────────────────────────

    def _executor_for(self, plan) -> "Any":
        from core.mech.executor import PlanExecutor
        if plan.plan_id not in self._executors:
            runner = self._make_runner()
            self._executors[plan.plan_id] = PlanExecutor(runner)
        return self._executors[plan.plan_id]

    def _make_runner(self):
        """Build the hardened runner. HardenedToolRunner is imported lazily
        so the mech package (and its tests) never require a full registry."""
        from core.hardening import HardenedToolRunner
        from core.tool_registry import ToolRegistry
        registry = ToolRegistry({})
        return HardenedToolRunner(registry)

    def run(self, plan):
        """Execute a compiled plan; returns the final PlanRunState."""
        from core.mech.state import PlanState
        run_state = self._run_states[plan.plan_id]
        if run_state.state == PlanState.ABORTED.value:
            raise ValueError(f"plan {plan.plan_id} is aborted")
        executor = self._executor_for(plan)
        result = executor.run(plan, run_state)
        return result

    def resume(self, plan_id: str):
        """Resume a persisted plan from its last step boundary.

        Works across process restarts (v7.1): when the plan was compiled by
        a dead process, it is rebuilt from its persisted plan.json report.
        Terminal-state plans return unchanged (idempotent).
        """
        from core.mech.state import PlanRunState, PlanState
        if plan_id in self._run_states:
            run_state = self._run_states[plan_id]
        else:
            plan_dir = os.path.join(self.sandbox_root, plan_id)
            run_state = PlanRunState.load(plan_dir)
            if run_state is None:
                raise KeyError(f"no persisted plan state for '{plan_id}'")
            self._run_states[plan_id] = run_state
        if run_state.state in (PlanState.DONE.value, PlanState.FAILED.value,
                               PlanState.ABORTED.value):
            return run_state  # idempotent — nothing to resume
        if plan_id not in self._plans:
            # Crash recovery: rebuild from the persisted compile report.
            intent_id = run_state.intent_id
            try:
                intent = self.get_intent(intent_id)
            except KeyError:
                raise KeyError(
                    f"plan '{plan_id}' references intent '{intent_id}', "
                    f"which is not present in {self.manifest_dir}")
            from core.mech.compiler import CompiledPlan
            self._plans[plan_id] = CompiledPlan.from_report(
                run_state.plan_dir, intent)
        return self.run(self._plans[plan_id])

    def list_plans(self) -> List[Dict[str, Any]]:
        """Every persisted plan run in the sandbox, newest first (v7.1).

        Powers cockpit reattach after a browser refresh and the CLI
        `plans` verb — a running plan must always be findable."""
        from core.mech.state import PlanRunState
        out: List[Dict[str, Any]] = []
        if not os.path.isdir(self.sandbox_root):
            return out
        for name in sorted(os.listdir(self.sandbox_root), reverse=True):
            plan_dir = os.path.join(self.sandbox_root, name)
            if not os.path.isfile(os.path.join(plan_dir, "state.json")):
                continue
            st = PlanRunState.load(plan_dir)
            if st is not None:
                out.append(st.summary())
        return out

    def get_plan_report(self, plan_id: str) -> Dict[str, Any]:
        """The persisted compile report (plan.json) for one plan (v7.1)."""
        from core.state_store import read_json
        data = read_json(os.path.join(self.sandbox_root, plan_id, "plan.json"))
        if not data:
            raise KeyError(f"no persisted plan report for '{plan_id}'")
        return data

    def abort(self, plan_id: str) -> Dict[str, Any]:
        """Cooperative abort — takes effect at the next step boundary."""
        run_state = self._run_states.get(plan_id)
        if run_state is None:
            return {"status": "unknown_plan", "plan_id": plan_id}
        try:
            run_state.abort()
        except ValueError:
            return {"status": "not_abortable",
                    "state": run_state.state, "plan_id": plan_id}
        run_state.save()
        return {"status": "aborting", "plan_id": plan_id}

    def pause(self, plan_id: str) -> Dict[str, Any]:
        run_state = self._run_states.get(plan_id)
        if run_state is None:
            return {"status": "unknown_plan", "plan_id": plan_id}
        try:
            run_state.pause()
        except ValueError:
            return {"status": "not_pausable", "state": run_state.state}
        run_state.save()
        return {"status": "pausing", "plan_id": plan_id}

    def status(self, plan_id: str) -> Dict[str, Any]:
        run_state = self._run_states.get(plan_id)
        if run_state is None:
            from core.mech.state import PlanRunState
            run_state = PlanRunState.load(os.path.join(self.sandbox_root, plan_id))
        if run_state is None:
            return {"plan_id": plan_id, "state": "unknown"}
        return run_state.summary()

    # ── VULN-GRAPH ───────────────────────────────────────────────────

    def _load_graph(self):
        if not self._graph_loaded:
            from core.mech.vuln_graph import VulnGraph
            self._graph = VulnGraph.from_file(self.graph_path)
            self._graph_loaded = True
        return self._graph

    def next_moves(self, plan_id: str,
                   extra_findings: Optional[List[Dict[str, Any]]] = None
                   ) -> List[Dict[str, Any]]:
        """Scored next moves from the plan's findings (+ any extras)."""
        from core.mech.probes import run_probe

        def probe_checker(name: str) -> bool:
            return run_probe(name, []).ok

        findings = []
        run_state = self._run_states.get(plan_id)
        if run_state is None:
            from core.mech.state import PlanRunState
            run_state = PlanRunState.load(os.path.join(self.sandbox_root, plan_id))
        if run_state is not None:
            findings.extend(run_state.findings)
        findings.extend(extra_findings or [])
        return [m.to_dict() for m in self._load_graph().next_moves(
            findings, probe_checker=probe_checker)]

    def suggest_moves(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """VULN-GRAPH next moves for arbitrary findings (no plan needed)."""
        from core.mech.probes import run_probe
        return [m.to_dict() for m in self._load_graph().next_moves(
            findings, probe_checker=lambda n: run_probe(n, []).ok)]

    # ── events (cockpit relay) ──────────────────────────────────────

    def on_event(self, event: str, callback: Callable) -> None:
        """Subscribe to the MechUnit-level bus (see core.mech.events)."""
        from core.mech.events import EventBus
        if not hasattr(self, "_bus"):
            self._bus = EventBus()
        self._bus.subscribe(event, callback)
