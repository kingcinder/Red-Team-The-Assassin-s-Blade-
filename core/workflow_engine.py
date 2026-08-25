"""
RedTeam Harness — Workflow Engine (v4.0 Assassin's Blade)
State machine that loads YAML workflow templates, interpolates variables,
chains exploit outputs between steps, validates results, checkpoints progress,
and prevents drift through gate enforcement and expected-output matching.

v4.0: auto-findings extraction, LLM-guided retries, auto pentest reports,
chain-graph visualization, static template validation, drift scoring +
confidence tagging, finding correlation + remediation.
"""
import os
import re
import json
import time
import logging
import yaml
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from core.task_isolation import TaskSandbox
from core.hardening import HardenedToolRunner
from core.findings import extract_findings, SEVERITY_ORDER, get_extractor as _get_findings_extractor
from core.correlation import FindingCorrelator
from core.injection_defense import sanitize_for_llm, sanitize_tool_output

logger = logging.getLogger("redteam.workflow")
MAX_STEPS_PER_WORKFLOW = 50
MAX_RETRIES_PER_STEP = 3
WORKFLOW_OVERALL_TIMEOUT = 3600  # 1 hour safety cap

# ── Drift scoring weights (Phase 6) ──
DRIFT_WEIGHTS = {
    "retries": 0.3,       # penalty per retry
    "output_match": 0.4,  # expected_output regex match
    "confidence": 0.3,    # match confidence from regex specificity
}


class WorkflowError(Exception):
    """Raised for workflow-level failures."""
    pass


class WorkflowStateMachine:
    """
    Executes a YAML-defined pentest workflow with hardened tool running,
    output validation, exploit chaining, and drift prevention.
    """

    def __init__(self, template_path: str, sandbox: TaskSandbox,
                 runner: HardenedToolRunner, variables: Dict[str, Any],
                 llm=None, retry_multiplier: float = 1.0):
        self.template_path = template_path
        self.sandbox = sandbox
        self.runner = runner
        self.variables = variables or {}
        self.llm = llm  # optional LLM backend for smart retry suggestions
        # v5.2: per-target aggressiveness — high-value targets get a higher
        # retry budget (scaled against each step's `retries`). Clamped so a
        # hostile config can't exceed MAX_RETRIES_PER_STEP.
        try:
            self.retry_multiplier = max(0.5, min(3.0, float(retry_multiplier or 1.0)))
        except (TypeError, ValueError):
            self.retry_multiplier = 1.0
        self.template: Dict[str, Any] = {}
        self.steps: List[Dict[str, Any]] = []
        self.state: Dict[str, Any] = {}
        self._chain_values: Dict[str, str] = {}  # extracted → shared across steps
        self._start_time: Optional[float] = None
        self._correlator = FindingCorrelator()

    # ═══════════════════════════════════════════════════════════════
    # LOADING
    # ═══════════════════════════════════════════════════════════════

    def load(self) -> "WorkflowStateMachine":
        """Load and validate the YAML template."""
        if not os.path.exists(self.template_path):
            raise WorkflowError(f"Template not found: {self.template_path}")

        with open(self.template_path) as f:
            self.template = yaml.safe_load(f) or {}

        required = ["name", "steps"]
        for key in required:
            if key not in self.template:
                raise WorkflowError(f"Template missing required key: '{key}'")

        self.steps = self.template["steps"]
        if not isinstance(self.steps, list) or len(self.steps) == 0:
            raise WorkflowError("Template 'steps' must be a non-empty list")
        if len(self.steps) > MAX_STEPS_PER_WORKFLOW:
            raise WorkflowError(f"Too many steps ({len(self.steps)} > {MAX_STEPS_PER_WORKFLOW})")

        # Fill defaults + validate each step
        for step in self.steps:
            if not step.get("tool"):
                raise WorkflowError(f"Step missing required key 'tool': {step.get('name', 'unnamed')}")
            step.setdefault("name", f"step_{self.steps.index(step)+1}")
            step.setdefault("timeout", 300)
            step.setdefault("gate", False)
            step.setdefault("retries", 2)
            step.setdefault("args", {})
            step.setdefault("expected_output", None)
            step.setdefault("extracts", [])
            step.setdefault("on_fail", "retry")  # retry | warn | abort

        return self

    def get_summary(self) -> Dict[str, Any]:
        """Return template summary for the dashboard/CLI."""
        return {
            "name": self.template.get("name", ""),
            "description": self.template.get("description", ""),
            "category": self.template.get("category", "general"),
            "steps_count": len(self.steps),
            "steps": [s.get("name") for s in self.steps],
            "variables": list(self.template.get("variables", {}).keys()),
            "cutting_edge": self.template.get("cutting_edge", False),
            "attack_vector": self.template.get("attack_vector", ""),
            "references": self.template.get("references", []),
        }

    # ═══════════════════════════════════════════════════════════════
    # VARIABLE INTERPOLATION
    # ═══════════════════════════════════════════════════════════════

    def _resolve(self, value: Any) -> Any:
        """Replace {{var}} placeholders in strings/dicts/lists recursively."""
        if isinstance(value, str):
            # Support {{var}} and {var} syntax
            for var, val in {**self.variables, **self._chain_values}.items():
                value = value.replace("{{" + var + "}}", str(val))
                value = value.replace("{" + var + "}", str(val))
            return value
        if isinstance(value, dict):
            return {k: self._resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._resolve(v) for v in value]
        return value

    def _check_unresolved(self, value: str) -> List[str]:
        """Find any remaining {{...}} placeholders (would indicate missing vars)."""
        return re.findall(r"\{\{([^}]+)\}\}", str(value))

    # ═══════════════════════════════════════════════════════════════
    # OUTPUT VALIDATION (drift prevention core)
    # ═══════════════════════════════════════════════════════════════

    def _validate_output(self, step: Dict[str, Any], stdout: str) -> Tuple[bool, str]:
        """
        Validate a step's output against its expected_output regex.
        Returns (passed, message).
        """
        expected = step.get("expected_output")
        if not expected:
            return True, "no validation pattern"

        try:
            # Support multiple patterns (any match passes) and {var} references
            patterns = expected if isinstance(expected, list) else [expected]
            combined = stdout + "\n" + self.sandbox.read_output(step.get("name", ""))
            for pattern in patterns:
                pattern = self._resolve(pattern)
                if re.search(pattern, combined, re.IGNORECASE | re.MULTILINE):
                    return True, f"output matched: {pattern[:60]}"
            return False, f"output did not match expected pattern: {patterns[0][:60]}"
        except re.error as e:
            logger.warning(f"Invalid regex in step {step['name']}: {e}")
            return True, "invalid regex (skipped validation)"

    def _extract_values(self, step: Dict[str, Any], stdout: str):
        """Extract tokens from output for exploit chaining to later steps."""
        for extract in step.get("extracts", []):
            var_name = extract.get("var")
            regex = extract.get("regex")
            if not var_name or not regex:
                continue
            try:
                m = re.search(regex, stdout, re.IGNORECASE | re.MULTILINE)
                if m:
                    # Support capture groups (group 1 preferred)
                    value = m.group(1) if m.groups() else m.group(0)
                    self._chain_values[var_name] = value
                    logger.info(f"Extracted {var_name} = {value[:40]}...")
            except re.error as e:
                logger.warning(f"Bad extract regex in {step['name']}: {e}")

    # ═══════════════════════════════════════════════════════════════
    # STEP EXECUTION
    # ═══════════════════════════════════════════════════════════════

    def _run_step(self, index: int) -> Dict[str, Any]:
        """Run a single workflow step with retries and validation."""
        step = self.steps[index]
        step_name = step["name"]
        tool_name = step["tool"]

        # Interpolate args
        raw_args = step.get("args", {})
        resolved_args = self._resolve(raw_args)

        # Detect unresolved placeholders
        flat_args = json.dumps(resolved_args)
        unresolved = self._check_unresolved(flat_args)
        if unresolved:
            msg = (f"Step '{step_name}': missing variable(s) {unresolved}. "
                   f"Provide via --var key=value or fix the template.")
            logger.error(msg)
            return {"step": step_name, "status": "blocked", "reason": msg,
                    "tool": tool_name, "attempts": 0}

        result = {
            "step": step_name,
            "tool": tool_name,
            "args": resolved_args,
            "status": "pending",
            "attempts": 0,
            "started": datetime.now().isoformat(),
        }

        # v5.2: scale retries by the per-target aggressiveness multiplier
        base_retries = step.get("retries", 2)
        scaled = max(0, int(base_retries * self.retry_multiplier))
        max_retries = min(scaled, MAX_RETRIES_PER_STEP)
        attempt = 0
        last_error = ""
        # Phase 2: LLM-guided alternatives are attempted AFTER normal retries
        llm_alt_tried = False
        current_args = resolved_args
        current_tool = tool_name

        while attempt <= max_retries + (1 if self.llm else 0):
            attempt += 1
            result["attempts"] = attempt
            result["status"] = "running"

            # Phase 2: if normal retries exhausted and LLM available,
            # ask the LLM for an alternative tool+args approach
            if (self.llm and not llm_alt_tried
                    and attempt > max_retries
                    and last_error):
                alt = self._llm_suggest_alternative(step, last_error, current_tool, current_args)
                if alt:
                    current_tool = alt.get("tool", tool_name)
                    current_args = alt.get("args", resolved_args)
                    llm_alt_tried = True
                    result["llm_alt"] = {"tool": current_tool, "args": current_args}
                    self.sandbox.write_log(
                        "workflow",
                        f"Step {step_name}: LLM suggested alternative "
                        f"{current_tool} with {len(current_args)} args")
                    logger.info(f"Step {step_name}: LLM alternative → {current_tool}")
                else:
                    # LLM couldn't propose a valid alternative — fail cleanly
                    result["status"] = "failed"
                    result["reason"] = (f"retries exhausted and LLM suggested no "
                                          f"valid alternative (last: {last_error[:120]})")
                    self.sandbox.write_log(
                        "workflow",
                        f"Step {step_name} FAILED: {result['reason']}")
                    break

            try:
                exec_result = self.runner.execute(
                    current_tool,
                    current_args,
                    timeout=step.get("timeout", 300),
                    sandbox_output_dir=self.sandbox.root,
                )
            except Exception as e:
                exec_result = {"stdout": "", "stderr": str(e), "exit_code": -1,
                               "blocked": True, "block_reason": str(e)}

            result["exec_result"] = {
                "exit_code": exec_result.get("exit_code"),
                "duration": exec_result.get("duration"),
                "blocked": exec_result.get("blocked", False),
            }

            # Save output to sandbox
            self.sandbox.write_output(step_name,
                                      exec_result.get("stdout", ""),
                                      exec_result.get("stderr", ""))

            # Blocked by safety/hardening → record and stop
            if exec_result.get("blocked"):
                result["status"] = "blocked"
                result["reason"] = exec_result.get("block_reason", "blocked by hardening")
                self.sandbox.write_log("workflow", f"Step {step_name} BLOCKED: {result['reason']}")
                break

            # Exit code check
            exit_code = exec_result.get("exit_code", -1)
            if exit_code != 0 and exit_code is not None:
                last_error = (exec_result.get("stderr") or "")[:200]
                self.sandbox.write_log("workflow",
                                       f"Step {step_name} exit={exit_code}: {last_error}")
                if attempt > max_retries:
                    result["status"] = "failed"
                    result["reason"] = f"exit code {exit_code}: {last_error}"
                continue  # retry

            # Expected output validation (drift check)
            stdout = exec_result.get("stdout", "")

            # When running an LLM-suggested ALTERNATIVE tool, the original
            # step's expected_output regex (written for the original tool) can
            # never match the alternative's output format. Relax validation:
            # exit code 0 + non-empty output is sufficient for an alternative.
            if llm_alt_tried:
                passed = (exit_code == 0 and stdout.strip())
                msg = "LLM alternative accepted (exit 0 + non-empty output)" if passed \
                    else "LLM alternative produced no usable output"
                if not passed:
                    last_error = msg
                    self.sandbox.write_log("workflow",
                                           f"Step {step_name} ALT-DRIFT: {msg}")
                    result["status"] = "failed"
                    result["reason"] = msg
                    break
            else:
                passed, msg = self._validate_output(step, stdout)
                if not passed:
                    last_error = msg
                    self.sandbox.write_log("workflow", f"Step {step_name} DRIFT: {msg}")
                    if attempt > max_retries:
                        result["status"] = "failed"
                        result["reason"] = f"validation failed: {msg}"
                    continue  # retry with same args (or we could mutate)

            # Success — extract chain values
            self._extract_values(step, stdout)

            # ── Phase 1: Auto-findings extraction ──
            new_findings = extract_findings(
                step_name, tool_name, stdout,
                exec_result.get("stderr", ""))
            added = 0
            for finding in new_findings:
                # Dedupe against existing findings by source_step+dedupe_key
                existing_keys = {
                    (f.get("source_step"), f.get("dedupe_key"))
                    for f in self.state.get("findings", [])
                }
                if (finding["source_step"], finding["dedupe_key"]) not in existing_keys:
                    self.add_finding(finding)
                    added += 1
            if added:
                logger.info(f"Step {step_name}: +{added} auto-findings "
                            f"(total {len(self.state.get('findings', []))})")

            result["status"] = "success"
            result["duration"] = exec_result.get("duration")
            result["stdout_preview"] = stdout[:300]
            result["findings_added"] = added
            # Phase 6: Drift scoring
            result["drift_score"] = self._compute_drift_score(
                step, result["attempts"], passed if not llm_alt_tried else True)
            result["confidence"] = self._confidence_tag(result["drift_score"])
            break

        # Gate enforcement: gate steps that failed abort the workflow
        if result["status"] in ("failed", "blocked") and step.get("gate"):
            result["gate_failed"] = True
            self.sandbox.write_log("workflow",
                                   f"GATE '{step_name}' failed — workflow aborting")

        return result

    # ═══════════════════════════════════════════════════════════════
    # MAIN EXECUTION LOOP
    # ═══════════════════════════════════════════════════════════════

    def start(self, resume: bool = False) -> Dict[str, Any]:
        """
        Run the full workflow. Returns a summary dict.
        If resume=True, finds the most recent task state and continues from
        the last completed step.
        """
        self._start_time = time.time()

        # ── Resume: locate latest prior state from ANY prior task run ──
        if resume:
            saved = TaskSandbox.find_latest_state(
                self.sandbox.workflow_name, self.sandbox.base_dir)
            if saved and saved.get("current_step", 0) > 0:
                completed = saved.get("steps_completed", [])
                self.state["steps_completed"] = completed
                self.state["resumed_from"] = saved.get("_task_id")
                # Restore exploit-chain values so later steps still resolve
                self._chain_values = saved.get("chain_values", {}) or {}
                logger.info(f"Resuming workflow at step {len(completed)} "
                            f"(from {saved.get('_task_id')})")
                self.sandbox.write_log("workflow",
                                       f"RESUME at step {len(completed)} "
                                       f"from {saved.get('_task_id')}")
            else:
                logger.info("Resume requested but no prior state found — starting fresh")

        self.sandbox.setup()

        completed = self.state.get("steps_completed", [])
        self.state.update({
            "workflow": self.template.get("name", ""),
            "status": "running",
            "current_step": len(completed),
            "total_steps": len(self.steps),
            "started": datetime.now().isoformat(),
        })
        self.sandbox.save_state(self.state)

        # Validate all variables upfront (drift prevention)
        self._validate_variables()

        # ── Execute steps ──
        for index in range(len(completed), len(self.steps)):
            step = self.steps[index]

            # Overall timeout check
            if self._start_time and (time.time() - self._start_time) > WORKFLOW_OVERALL_TIMEOUT:
                self.state["status"] = "timeout"
                self.state["error"] = f"Workflow exceeded {WORKFLOW_OVERALL_TIMEOUT}s overall budget"
                self.sandbox.save_state(self.state)
                break

            self.sandbox.write_log("workflow", f"--- Step {index+1}/{len(self.steps)}: {step['name']} ---")
            result = self._run_step(index)

            if result["status"] == "success":
                completed.append(result)
                self.state["steps_completed"] = completed
                self.state["current_step"] = len(completed)
                self.sandbox.save_state(self.state)
            else:
                if result.get("gate_failed"):
                    self.state["status"] = "failed"
                    self.state["error"] = f"Gate step failed: {result['step']}"
                    self.state["steps_completed"] = completed
                    self.state["current_step"] = len(completed)
                    self.state["chain_values"] = self._chain_values
                    self.sandbox.save_state(self.state)
                    self.sandbox.write_log("workflow", f"WORKFLOW ABORTED at gate: {result['step']}")
                    # Aborted runs still get a report of what was found
                    try:
                        self.generate_report()
                    except Exception as e:
                        logger.error(f"Auto-report on abort failed: {e}")
                    return self._build_summary()
                # Non-gate failure → try to continue but record
                self.state.setdefault("warnings", []).append({
                    "step": result["step"], "reason": result.get("reason", "failed")
                })
                # Don't mark as completed — will retry on resume
                self.sandbox.save_state(self.state)

        # ── Finalize ──
        failed_count = len([s for s in completed if s.get("status") != "success"])
        self.state["status"] = "complete" if len(completed) == len(self.steps) else "partial"
        self.state["completed_steps"] = len(completed)
        self.state["failed_steps"] = failed_count
        self.state["finished"] = datetime.now().isoformat()
        self.state["chain_values"] = self._chain_values
        self.sandbox.save_state(self.state)

        # ── Phase 2: Auto pentest report ──
        try:
            self.generate_report()
        except Exception as e:
            logger.error(f"Auto-report generation failed: {e}")

        self.sandbox.write_log("workflow", f"WORKFLOW {self.state['status'].upper()}: "
                                           f"{len(completed)}/{len(self.steps)} steps")
        return self._build_summary()

    def _validate_variables(self):
        """Check all template-declared variables are provided. Fill defaults."""
        declared = self.template.get("variables", {})
        missing = []
        for var_name, var_spec in declared.items():
            if var_name not in self.variables:
                default = var_spec.get("default") if isinstance(var_spec, dict) else None
                if default is not None:
                    self.variables[var_name] = default
                elif var_spec.get("required", True) if isinstance(var_spec, dict) else True:
                    missing.append(var_name)

        if missing:
            logger.warning(f"Workflow missing variables: {missing}")
            # Don't abort — let step-level validation catch unresolved placeholders

    def _build_summary(self) -> Dict[str, Any]:
        """Build the final workflow summary."""
        completed = self.state.get("steps_completed", [])
        return {
            "workflow": self.template.get("name", ""),
            "description": self.template.get("description", ""),
            "task_id": self.sandbox.task_id,
            "root": self.sandbox.root,
            "status": self.state.get("status", "unknown"),
            "completed_steps": len(completed),
            "total_steps": len(self.steps),
            "error": self.state.get("error"),
            "warnings": self.state.get("warnings", []),
            "chain_values": self._chain_values,
            "output_size_mb": round(self.sandbox.get_total_size_mb(), 2),
            "findings": self.state.get("findings", []),
            "steps": completed,
        }

    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: CHAIN GRAPH (visualizer)
    # ═══════════════════════════════════════════════════════════════

    def build_graph(self, state: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Build a dependency graph of the workflow for visualization.
        Nodes = steps; edges = sequential + exploit-chain (extracts → later steps).
        Each node carries status (from state) so the dashboard can color it.
        """
        state = state or {}
        completed = state.get("steps_completed", [])
        status_map = {}
        for s in completed:
            if isinstance(s, dict):
                status_map[s.get("step")] = s.get("status", "success")
        # Steps not in completed are pending (or the failed current one)
        pending = {}
        for w in state.get("warnings", []):
            pending[w.get("step")] = "failed"

        nodes = []
        edges = []
        for i, step in enumerate(self.steps):
            name = step.get("name", f"step_{i+1}")
            tool = step.get("tool", "")
            status = status_map.get(name) or pending.get(name, "pending")

            # Find chain deps: which extract vars does this step consume?
            deps = []
            args_json = json.dumps(step.get("args", {}))
            for j, prev in enumerate(self.steps[:i]):
                for ex in prev.get("extracts", []):
                    var = ex.get("var")
                    if var and ("{{" + var + "}}" in args_json or "{" + var + "}" in args_json):
                        deps.append(prev.get("name", f"step_{j+1}"))
                        break

            nodes.append({
                "id": name,
                "index": i + 1,
                "tool": tool,
                "description": step.get("description", ""),
                "gate": bool(step.get("gate")),
                "timeout": step.get("timeout", 300),
                "status": status,
                "deps": deps,
            })

            # Sequential edge (unless it's the last step)
            if i < len(self.steps) - 1:
                edges.append({"from": name,
                              "to": self.steps[i + 1].get("name", f"step_{i+2}"),
                              "kind": "sequential"})
            # Chain edges from extract deps
            for dep in deps:
                edges.append({"from": dep, "to": name, "kind": "chain"})

        # Findings summary to overlay
        findings = state.get("findings", [])
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in findings:
            counts[f.get("severity", "info")] = \
                counts.get(f.get("severity", "info"), 0) + 1

        return {
            "workflow": self.template.get("name", ""),
            "category": self.template.get("category", "general"),
            "nodes": nodes,
            "edges": edges,
            "status": state.get("status", "not_started"),
            "findings_summary": counts,
        }

    # ═══════════════════════════════════════════════════════════════
    # STATIC HELPERS
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def discover_templates(templates_dir: str = "workflows/templates") -> List[str]:
        """List all .yaml/.yml workflow template files."""
        if not os.path.isdir(templates_dir):
            return []
        return sorted(
            os.path.join(templates_dir, f)
            for f in os.listdir(templates_dir)
            if f.endswith((".yaml", ".yml"))
        )

    @staticmethod
    def load_all_summaries(templates_dir: str = "workflows/templates") -> List[Dict]:
        """Load summaries for all templates (for dashboard)."""
        summaries = []
        for path in WorkflowStateMachine.discover_templates(templates_dir):
            try:
                wf = WorkflowStateMachine(path, None, None, {})
                wf.load()
                summaries.append(wf.get_summary())
            except Exception as e:
                logger.warning(f"Failed to load template {path}: {e}")
        return summaries

    @staticmethod
    def validate_template(path: str) -> Dict[str, Any]:
        """Phase 6: Validate a template's structure, regexes, and tools without running."""
        errors = []
        warnings = []
        try:
            with open(path) as f:
                template = yaml.safe_load(f) or {}
        except Exception as e:
            return {"valid": False, "errors": [f"Cannot parse: {e}"], "warnings": []}

        for key in ("name", "steps"):
            if key not in template:
                errors.append(f"Missing required key: '{key}'")
        if errors:
            return {"valid": False, "errors": errors, "warnings": warnings}

        steps = template.get("steps", [])
        if not isinstance(steps, list) or len(steps) == 0:
            return {"valid": False, "errors": ["'steps' must be non-empty list"], "warnings": warnings}

        seen_names = set()
        for i, step in enumerate(steps):
            name = step.get("name", f"step_{i+1}")
            tool = step.get("tool", "")

            if name in seen_names:
                warnings.append(f"Step {i+1}: duplicate name '{name}'")
            seen_names.add(name)

            if not tool:
                errors.append(f"Step {i+1} ('{name}'): missing 'tool'")

            # Validate expected_output regexes
            expected = step.get("expected_output")
            if expected:
                patterns = expected if isinstance(expected, list) else [expected]
                for p in patterns:
                    try:
                        re.compile(p)
                    except re.error as e:
                        errors.append(f"Step {i+1} ('{name}'): invalid regex '{p[:60]}': {e}")

            # Validate extract regexes
            for ex in step.get("extracts", []):
                var = ex.get("var", "")
                regex = ex.get("regex", "")
                if not var or not regex:
                    warnings.append(f"Step {i+1} ('{name}'): extract missing 'var' or 'regex'")
                    continue
                try:
                    re.compile(regex)
                except re.error as e:
                    errors.append(f"Step {i+1} ('{name}'): invalid extract regex '{regex[:60]}': {e}")

            # Validate retries range
            retries = step.get("retries", 2)
            if not isinstance(retries, int) or retries < 0 or retries > MAX_RETRIES_PER_STEP:
                warnings.append(f"Step {i+1} ('{name}'): retries={retries} (recommend 0-{MAX_RETRIES_PER_STEP})")

            # Validate timeout range
            timeout = step.get("timeout", 300)
            if not isinstance(timeout, (int, float)) or timeout < 1 or timeout > 7200:
                warnings.append(f"Step {i+1} ('{name}'): timeout={timeout}s (recommend 1-7200)")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "steps_count": len(steps),
            "name": template.get("name", ""),
        }

    # ═══════════════════════════════════════════════════════════════
    # PHASE 6: DRIFT METRICS & CONFIDENCE
    # ═══════════════════════════════════════════════════════════════

    def _compute_drift_score(self, step: Dict, attempts: int,
                             output_matched: bool) -> float:
        """Compute a drift score (0.0 = perfect, 1.0 = total drift)."""
        # Retry penalty: 0 retries = 0 penalty, 3+ retries = 1.0
        retry_score = min(1.0, (attempts - 1) / MAX_RETRIES_PER_STEP)
        # Output match: matched = 0, unmatched = 1.0
        match_score = 0.0 if output_matched else 1.0
        # Confidence: based on whether step has an expected_output pattern
        has_expected = bool(step.get("expected_output"))
        confidence_score = 0.0 if has_expected else 0.3  # no pattern = slightly less certain

        drift = (retry_score * DRIFT_WEIGHTS["retries"] +
                match_score * DRIFT_WEIGHTS["output_match"] +
                confidence_score * DRIFT_WEIGHTS["confidence"])
        return round(min(1.0, drift), 2)

    def _confidence_tag(self, drift_score: float) -> str:
        """Tag step result with a confidence level based on drift."""
        if drift_score <= 0.15:
            return "high"
        elif drift_score <= 0.40:
            return "medium"
        elif drift_score <= 0.70:
            return "low"
        return "uncertain"

    def get_drift_summary(self) -> Dict[str, Any]:
        """Return drift metrics for the entire workflow run."""
        return self.drift_from_state(self.state)

    @staticmethod
    def drift_from_state(state: Dict) -> Dict[str, Any]:
        """Phase 6: Extract drift metrics from a saved state.json (static)."""
        completed = state.get("steps_completed", [])
        if not completed:
            return {"avg_drift": 0.0, "confidence": "N/A", "steps": []}
        scores = []
        steps = []
        for s in completed:
            ds = s.get("drift_score", 0.0)
            scores.append(ds)
            steps.append({
                "step": s.get("step", ""),
                "drift_score": ds,
                "confidence": s.get("confidence", "N/A"),
                "attempts": s.get("attempts", 0),
            })
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        if avg <= 0.15:
            confidence = "high"
        elif avg <= 0.40:
            confidence = "medium"
        elif avg <= 0.70:
            confidence = "low"
        else:
            confidence = "uncertain"
        return {"avg_drift": avg, "confidence": confidence, "steps": steps}

    def add_finding(self, finding: Dict):

        """Record a structured finding (severity, title, evidence...)."""
        findings = self.state.setdefault("findings", [])
        finding["timestamp"] = datetime.now().isoformat()
        findings.append(finding)
        self.sandbox.save_state(self.state)

    @staticmethod
    def _sanitize_prompt(text: str) -> str:
        """Strip control chars and newlines from text before LLM prompt interpolation."""
        from core.injection_defense import sanitize_for_llm
        return sanitize_for_llm(str(text), max_len=500)

    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: LLM-GUIDED RETRY
    # ═══════════════════════════════════════════════════════════════

    def _llm_suggest_alternative(self, step: Dict[str, Any], last_error: str,
                                 current_tool: str, current_args: Dict) -> Optional[Dict]:
        """
        Ask the local LLM to suggest an alternative tool + args for a failed step.
        Returns {"tool": ..., "args": {...}} or None on any failure.
        Never raises — workflow continues on LLM failure.
        """
        if not self.llm:
            return None
        try:
            step_desc = step.get("description", step.get("name", ""))
            prompt = (
                "A penetration testing step failed. Suggest ONE alternative approach.\n\n"
                f"Objective: {sanitize_for_llm(step_desc, max_len=500)}\n"
                f"Original tool: {current_tool}\n"
                f"Original args: {sanitize_tool_output(json.dumps(current_args, default=str)[:500])}\n"
                f"Error: {sanitize_tool_output(last_error[:300])}\n\n"
                'Respond with ONLY valid JSON: '
                '{"tool": "<alternative_tool>", '
                '"args": {<params>}}\n'
                "Pick a real alternative pentest tool (nmap_scan, curl_request, "
                "gobuster_dir, hydra_brute, ffuf_fuzz, sqlmap_scan, dig_dns, "
                "enum4linux_enum, smbmap_enum, netcat_connect, etc.) "
                "with appropriate args for the objective."
            )
            response = self.llm.chat(
                [{"role": "system", "content": "You are an expert pentest operator."},
                 {"role": "user", "content": prompt}],
                max_tokens=512, temperature=0.2)

            # Parse JSON — use brace-matching (handles nested args objects)
            data = None
            m = re.search(r'\{.*\}', response, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(0))
                except json.JSONDecodeError:
                    data = None
            if not data:
                try:
                    data = json.loads(response)
                except json.JSONDecodeError:
                    return None

            tool = data.get("tool", "")
            args = data.get("args", {})
            if not tool or not isinstance(args, dict):
                return None
            # Resolve any {{var}} placeholders the LLM may have echoed back
            try:
                args = self._resolve(args)
            except Exception:
                pass
            return {"tool": tool, "args": args}
        except Exception as e:
            logger.warning(f"LLM alternative suggestion failed: {e}")
            return None

    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: AUTO PENTEST REPORT
    # ═══════════════════════════════════════════════════════════════

    def generate_report(self) -> str:
        """
        Generate a markdown pentest report from findings, steps, and chain
        values. Writes to the sandbox as report.md and stores in state.
        Formatting is delegated to core.report (single report writer).
        """
        from core.report import workflow_report

        findings = self.state.get("findings", [])
        completed = self.state.get("steps_completed", [])
        warnings = self.state.get("warnings", [])

        # Phase 7: Correlated attack paths + summary (data, not formatting)
        paths = self._correlator.correlate(findings)
        paths_md = self._correlator.paths_to_markdown(paths) if paths else ""
        summary_md = self._correlator.summary_to_markdown(paths, findings) if paths else ""

        # ── Phase 2: LLM-powered narrative summary & conclusions ──
        narrative = ""
        if self.llm and findings:
            # Cache: reuse if already generated (e.g. abort + completion both call)
            narrative = self.state.get("llm_narrative", "")
            if not narrative:
                try:
                    narrative = self._llm_generate_narrative(findings, completed, warnings)
                    if narrative:
                        self.state["llm_narrative"] = narrative
                except Exception as e:
                    logger.warning(f"LLM narrative generation failed (non-fatal): {e}")

        # ── Phase 2b: LLM-powered technical deep dive ──
        deep_dive = ""
        if self.llm and findings:
            deep_dive = self.state.get("llm_deep_dive", "")
            if not deep_dive:
                try:
                    deep_dive = self._llm_generate_technical_deep_dive(findings)
                    if deep_dive:
                        self.state["llm_deep_dive"] = deep_dive
                except Exception as e:
                    logger.warning(f"LLM deep dive generation failed (non-fatal): {e}")

        report = workflow_report(
            workflow=self.template.get("name", "Unknown workflow"),
            category=self.template.get("category", "general"),
            attack_vector=self.template.get("attack_vector", "N/A"),
            task_id=self.sandbox.task_id,
            status=self.state.get("status", "unknown"),
            started=self.state.get("started", "N/A"),
            finished=self.state.get("finished", "N/A"),
            steps_completed=len(completed),
            total_steps=len(self.steps),
            findings=findings,
            completed=completed,
            warnings=warnings,
            chain_values=self._chain_values,
            paths=paths,
            paths_markdown=paths_md,
            summary_markdown=summary_md,
            narrative=narrative,
            deep_dive=deep_dive,
        )

        # Save to sandbox + state
        try:
            report_path = os.path.join(self.sandbox.root, "report.md")
            with open(report_path, "w") as f:
                f.write(report)
            self.state["report_path"] = report_path
            self.state["report"] = report[:20000]
            self.sandbox.save_state(self.state)
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

        return report

    def _llm_generate_narrative(self, findings: List[Dict], completed: List[Dict],
                                 warnings: List[Dict]) -> str:
        """
        Ask the LLM to write a professional executive summary and conclusions
        based on the structured findings and step results.
        Returns the narrative text, or empty string on any failure.
        """
        if not self.llm:
            return ""

        _ext = _get_findings_extractor()
        counts = _ext.summarize(findings)
        risk = _ext.compute_risk_score(findings)
        worst = _ext.worst_severity(findings)

        # Build a concise summary of findings for the LLM prompt
        findings_brief = []
        for f in findings[:15]:  # Limit to top 15 to keep prompt short
            findings_brief.append(
                f"- [{sanitize_for_llm(f.get('severity', 'info').upper(), max_len=10)}] {self._sanitize_prompt(f.get('title', ''))} "
                f"({self._sanitize_prompt(f.get('category', ''))}) — evidence: {self._sanitize_prompt(f.get('evidence', ''))}")

        steps_brief = []
        for s in completed:
            alt = f" (used LLM alternative: {s['llm_alt']['tool']})" if s.get('llm_alt') else ""
            steps_brief.append(f"- {s.get('step', '?')}: {s.get('tool', '?')} [{s.get('status', '?')}]{alt}")

        attack_vec = self.template.get('attack_vector', 'N/A')
        category = self.template.get('category', 'general')

        prompt = (
            f"You are a senior penetration tester writing a professional report.\n\n"
            f"## Workflow: {sanitize_for_llm(self.template.get('name', 'Unknown'), max_len=200)}\n"
            f"## Category: {sanitize_for_llm(category, max_len=100)}\n"
            f"## Attack Vector: {sanitize_for_llm(attack_vec, max_len=200)}\n"
            f"## Risk Score: {risk['score']}/100 (Grade: {sanitize_for_llm(risk['grade'], max_len=10)})\n"
            f"## Severity Breakdown: critical={counts.get('critical', 0)}, "
            f"high={counts.get('high', 0)}, medium={counts.get('medium', 0)}, "
            f"low={counts.get('low', 0)}, info={counts.get('info', 0)}\n"
            f"## Highest Severity: {sanitize_for_llm(worst.upper(), max_len=10)}\n\n"
            f"## Key Findings\n" + "\n".join(findings_brief) + "\n\n"
            f"## Steps Executed\n" + "\n".join(steps_brief) + "\n\n"
            f"Write TWO sections:\n"
            f"1. **Executive Summary** (3-4 paragraphs): Professional narrative summarizing "
            f"the engagement scope, methodology, key discoveries, and overall risk posture. "
            f"Written for a non-technical audience (CISO/executive level).\n"
            f"2. **Conclusions & Recommendations** (2-3 paragraphs): Strategic recommendations "
            f"prioritized by risk, with specific remediation guidance.\n\n"
            f"Output ONLY the markdown sections — no preamble, no meta-commentary."
        )

        logger.info(f"Generating LLM narrative for report ({len(findings)} findings, {len(completed)} steps)")
        self._emit("on_llm_thinking", {"session_id": self.sandbox.task_id, "step": "executive-summary"})
        response = self.llm.chat(
            [{"role": "system", "content": "You are a senior penetration tester and report writer."},
             {"role": "user", "content": prompt}],
            max_tokens=2000, temperature=0.3)

        if not response or response.startswith("[ERROR]"):
            logger.warning("LLM narrative generation returned empty/error")
            return ""

        if len(response.strip()) < 50:
            logger.warning("LLM narrative too short, discarding")
            return ""

        logger.info(f"LLM narrative generated ({len(response)} chars)")
        return response.strip()

    def _llm_generate_technical_deep_dive(self, findings: List[Dict]) -> str:
        """
        Ask the LLM to write a Technical Deep Dive section: detailed walkthrough
        of each critical/high finding with exploitation steps, evidence analysis,
        and specific remediation commands.
        Returns the section text, or empty string on any failure.
        """
        if not self.llm:
            return ""

        # Filter to critical/high findings only
        critical_high = [f for f in findings
                         if f.get("severity") in ("critical", "high")]
        if not critical_high:
            return ""

        findings_detail = []
        for i, f in enumerate(critical_high[:10], 1):  # Cap at 10 to stay within context
            findings_detail.append(
                f"### Finding {i}: {self._sanitize_prompt(f.get('title', ''))}\n"
                f"- Severity: {f.get('severity', 'info').upper()}\n"
                f"- Category: {f.get('category', '')}\n"
                f"- Source tool: {f.get('source_tool', '')} (step: {f.get('source_step', '')})\n"
                f"- Evidence: `{self._sanitize_prompt(f.get('evidence', ''))}`\n"
                f"- Context: {self._sanitize_prompt(f.get('context', ''))}\n")

        prompt = (
            f"You are a senior penetration tester writing a technical deep-dive section.\n\n"
            f"For EACH of the following critical/high-severity findings, write:\n"
            f"1. **Technical Analysis**: What this finding means, how it was detected, "
            f"what the evidence shows\n"
            f"2. **Exploitation Path**: Step-by-step how an attacker could exploit this, "
            f"including specific commands/payloads\n"
            f"3. **Impact Assessment**: What an attacker gains (access level, data, pivot)\n"
            f"4. **Remediation**: Specific actionable steps — exact patch versions, "
            f"configuration changes, firewall rules, code fixes\n\n"
            f"## Findings to Analyze\n\n"
            + "\n".join(findings_detail) + "\n\n"
            f"Write each finding as a ### subsection. Use code blocks for commands. "
            f"Be specific and actionable — no vague advice. Output ONLY the markdown."
        )

        logger.info(f"Generating LLM technical deep dive ({len(critical_high)} findings)")
        self._emit("on_llm_thinking", {"session_id": self.sandbox.task_id, "step": "technical-deep-dive"})
        response = self.llm.chat(
            [{"role": "system", "content": "You are a senior penetration tester and technical report writer."},
             {"role": "user", "content": prompt}],
            max_tokens=4000, temperature=0.3)

        if not response or response.startswith("[ERROR]"):
            logger.warning("LLM technical deep dive returned empty/error")
            return ""

        if len(response.strip()) < 50:
            logger.warning("LLM technical deep dive too short, discarding")
            return ""

        logger.info(f"LLM technical deep dive generated ({len(response)} chars)")
        return response.strip()