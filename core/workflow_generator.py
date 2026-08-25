"""
RedTeam Harness — LLM-Driven Dynamic Workflow Generator (v4.0)
Turns a natural-language objective into a validated, runnable YAML workflow
template. The local LLM proposes a step list; we validate every step against
the real tool registry, reject unsafe input, and save a template that
round-trips through WorkflowStateMachine.load().

Design decisions:
  - REJECT the whole generation on any unknown tool / missing required arg /
    injection-looking value. Partial workflows fail unpredictably.
  - Strict filename sanitization + collision handling for the saved template.
  - Offline: only the local LLM is consulted, everything else is local rules.
"""
import os
import re
import json
import yaml
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from core.injection_defense import sanitize_for_llm

logger = logging.getLogger("redteam.gen")

# ── Limits ──
MAX_GENERATED_STEPS = 20
MAX_ARG_STR_LEN = 500
SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9_-]+")

# ── Injection patterns for arg validation (used by _validate) ──
INJECTION_PATTERNS = [
    r";\s*rm\s",
    r"&&\s*rm\s",
    r"\|\|\s*rm\s",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r">\s*/dev/",
    r"curl\s.*\|\s*(ba)?sh",
    r"wget\s.*\|\s*(ba)?sh",
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__",
    r"subprocess",
    r"os\.system",
]

# ── JSON schema for post-execution template improvement ──
IMPROVE_SCHEMA = {
    "type": "object",
    "properties": {
        "assessment": {"type": "string"},
        "step_verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "step": {"type": "string"},
                    "verdict": {"type": "string"},
                    "rationale": {"type": "string"},
                    "replacement_tool": {"type": "string"},
                    "replacement_args": {"type": "object"},
                    "new_gate": {"type": "boolean"},
                    "new_retries": {"type": "integer"},
                    "new_timeout": {"type": "integer"},
                },
                "required": ["step", "verdict", "rationale"],
            },
        },
        "new_steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "tool": {"type": "string"},
                    "args": {"type": "object"},
                    "description": {"type": "string"},
                    "expected_output": {"type": "string"},
                    "gate": {"type": "boolean"},
                    "retries": {"type": "integer"},
                    "timeout": {"type": "integer"},
                },
                "required": ["name", "tool", "args"],
            },
        },
    },
    "required": ["assessment", "step_verdicts"],
}


# ── JSON schema handed to the LLM via GBNF json_schema enforcement ──
GENERATOR_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "description": {"type": "string"},
        "category": {"type": "string"},
        "variables": {"type": "object"},
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "tool": {"type": "string"},
                    "args": {"type": "object"},
                    "description": {"type": "string"},
                    "expected_output": {"type": "string"},
                    "gate": {"type": "boolean"},
                    "retries": {"type": "integer"},
                    "timeout": {"type": "integer"},
                },
                "required": ["name", "tool", "args"],
            },
        },
    },
    "required": ["name", "description", "category", "steps"],
}


class WorkflowGenerator:
    """Generates, validates, and persists LLM-proposed workflow templates."""

    # Single denylist of injection phrases — each is stripped from the objective.
    # No sentence splitting, no prefix stripping — just sub() each pattern.
    _INJECTION_DENYLIST = [
        re.compile(r'ignore\s+(all\s+)?previous\s+instructions?', re.I),
        re.compile(r'disregard\s+(all\s+)?previous', re.I),
        re.compile(r'forget\s+(all\s+)?previous', re.I),
        re.compile(r'override\s+\w*\s*prompt', re.I),
        re.compile(r'pretend\s+(you\s+are|to\s+be)\s+(a|an|the)?\s*\w+', re.I),
        re.compile(r'you\s+are\s+(a|an|the)\s+\w+', re.I),
        re.compile(r'act\s+as\s+(a|an|the)\s+\w+', re.I),
        re.compile(r'role\s*play', re.I),
        re.compile(r'output\s+your\s+(system|initial|full|original)', re.I),
        re.compile(r'reveal\s+your\s+(system|prompt)', re.I),
        re.compile(r'jailbreak', re.I),
        re.compile(r'system\s*prompt', re.I),
        re.compile(r'\[INST\].*?\[/INST\]', re.I | re.DOTALL),
        re.compile(r'<<SYS>>.*?<</SYS>>', re.I | re.DOTALL),
        re.compile(r'<\|im_start\|>.*?<\|im_end\|>', re.I | re.DOTALL),
        re.compile(r'\{\{.*?\}\}'),
        re.compile(r'<script[^>]*>.*?</script>', re.I | re.DOTALL),
        re.compile(r'javascript:', re.I),
        re.compile(r'data:text/html', re.I),
    ]

    # Minimum objective length after sanitization (chars)
    MIN_OBJECTIVE_LEN = 10

    def __init__(self, llm, registry, templates_dir: str = "workflows/templates"):
        self.llm = llm
        self.registry = registry
        self.templates_dir = templates_dir

    # ═══════════════════════════════════════════════════════════════
    # Main entry points
    # ═══════════════════════════════════════════════════════════════

    def sanitize_objective(self, objective: str) -> str:
        """Strip prompt injection attempts from the objective text.
        Returns the cleaned text, or empty string if the input is pure injection.
        """
        if not objective or not objective.strip():
            return ""
        cleaned = objective
        for pattern in self._INJECTION_DENYLIST:
            cleaned = pattern.sub('', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned

    def generate(self, objective: str) -> Dict[str, Any]:
        """
        Ask the LLM to design a workflow for `objective`, validate it,
        save it as a YAML template, and return {name, path, summary, errors}.
        Never raises — errors are returned in the dict.
        """
        # Sanitize the objective to prevent prompt injection
        cleaned = self.sanitize_objective(objective)
        if not cleaned:
            return {"error": "Objective text rejected (empty after sanitization)"}
        if len(cleaned) < self.MIN_OBJECTIVE_LEN:
            return {"error": f"Objective too short ({len(cleaned)} < {self.MIN_OBJECTIVE_LEN} chars) — provide a more detailed description"}

        definition = self._ask_llm(cleaned)
        if "error" in definition:
            return definition

        errors = self._validate(definition)
        if errors:
            return {"error": "Generated workflow failed validation",
                    "validation_errors": errors,
                    "definition": definition}

        path = self._save(definition)
        return {
            "name": definition.get("name", ""),
            "description": definition.get("description", ""),
            "category": definition.get("category", "general"),
            "path": path,
            "steps_count": len(definition.get("steps", [])),
            "steps": [s.get("name") for s in definition.get("steps", [])],
            "variables": list(definition.get("variables", {}).keys()),
            "objective": cleaned,
            "created": datetime.now().isoformat(),
        }

    # ═══════════════════════════════════════════════════════════════
    # Post-execution template self-improvement (v4.2)
    # ═══════════════════════════════════════════════════════════════

    def improve_template(self, template_path: str, exec_result: Dict[str, Any],
                         apply: bool = False,
                         max_new_steps: int = 3) -> Dict[str, Any]:
        """
        Analyze a workflow run's per-step outcomes with the LLM and propose
        concrete improvements to the saved template: keep/modify/remove
        verdicts per step, replacement tool choices, and new steps to add.

        Every proposed tool/arg change is validated against the tool registry
        before being returned; if ``apply`` is True, validated changes are
        written back to ``template_path`` (a backup .bak file is kept).

        Never raises — failures are returned in the dict.

        Returns:
            {
              "assessment": str,
              "verdicts": [{step, verdict, rationale, changes}...],
              "new_steps": [...validated...],
              "rejected": [{step, reason}...],
              "applied": bool,
              "applied_changes": {removed, modified, added},
              "path": str,
              "error": str (only on hard failure),
            }
        """
        if not os.path.exists(template_path):
            return {"error": f"Template not found: {template_path}"}
        if not self.llm:
            return {"error": "No LLM backend configured — cannot analyze template"}

        # ── Load current template ──
        try:
            with open(template_path) as f:
                template = yaml.safe_load(f) or {}
        except Exception as e:
            return {"error": f"Cannot load template: {e}"}
        steps = template.get("steps", [])
        if not isinstance(steps, list) or not steps:
            return {"error": "Template has no steps to analyze"}

        # ── Build per-step outcome brief (sanitized) ──
        outcome_by_step = {}
        for s in exec_result.get("steps", []) or []:
            if not isinstance(s, dict):
                continue
            name = s.get("step", "")
            outcome_by_step[name] = {
                "status": str(s.get("status", "?")),
                "attempts": int(s.get("attempts", 1)),
                "duration": s.get("duration"),
                "drift": s.get("drift_score"),
                "confidence": s.get("confidence", "N/A"),
                "findings": int(s.get("findings_added", 0)),
                "llm_alt": (s.get("llm_alt") or {}).get("tool", "") if s.get("llm_alt") else "",
            }
        warn_by_step = {}
        for w in exec_result.get("warnings", []) or []:
            if isinstance(w, dict):
                warn_by_step[w.get("step", "")] = sanitize_for_llm(
                    str(w.get("reason", ""))[:200], max_len=200)

        brief_lines = []
        for i, step in enumerate(steps, 1):
            name = step.get("name", f"step_{i}")
            o = outcome_by_step.get(name, {})
            warn = warn_by_step.get(name, "")
            parts = [f"{i}. {name} (tool={step.get('tool', '')})"]
            if o:
                parts.append(f"status={o['status']} attempts={o['attempts']} "
                             f"drift={o.get('drift')} conf={o.get('confidence')} "
                             f"findings_added={o['findings']}")
                if o.get("llm_alt"):
                    parts.append(f"llm_alt={o['llm_alt']}")
            else:
                parts.append("status=not_run")
            if warn:
                parts.append(f"warn={warn}")
            brief_lines.append(" | ".join(parts))

        tool_names = sorted(self.registry.get_all_tools().keys())
        tool_hint = ", ".join(tool_names[:80])

        prompt = (
            "A penetration-testing workflow template just finished executing. "
            "Analyze the run and recommend improvements to the template.\n\n"
            f"Workflow: {sanitize_for_llm(str(template.get('name', '')), max_len=200)}\n"
            f"Run status: {sanitize_for_llm(str(exec_result.get('status', '?')), max_len=50)}\n\n"
            "## Per-step outcomes\n" + "\n".join(brief_lines) + "\n\n"
            f"Available tools (use ONLY these exact names): {tool_hint}\n\n"
            "For EACH step return a verdict:\n"
            "  - keep: step works well, leave unchanged\n"
            "  - modify: step is weak (failed, high drift, retried, no findings) — "
            "provide a better replacement_tool and/or replacement_args, "
            "or adjust gate/retries/timeout\n"
            "  - remove: step is ineffective or redundant — drop it\n"
            f"Optionally propose up to {max_new_steps} NEW steps that would "
            "strengthen the workflow (each with name, tool, args, description, "
            "expected_output, gate, retries, timeout).\n"
            "Also write a 2-3 sentence assessment of the run.\n"
            "Rules: only reference exact tool names from the list; args values "
            "must be safe strings/IPs/paths (no shell metacharacters); "
            "variables must use {{var}} placeholders. Strict JSON only."
        )

        try:
            raw = self.llm.chat_structured(
                [{"role": "system",
                  "content": "You are an expert penetration-testing workflow optimizer. "
                             "Output strict JSON only."},
                 {"role": "user", "content": prompt}],
                IMPROVE_SCHEMA,
                max_tokens=2048,
                temperature=0.2,
            )
        except Exception as e:
            logger.error(f"LLM template improvement failed: {e}")
            return {"error": f"LLM template improvement failed: {e}"}

        if raw.startswith("[ERROR]"):
            return {"error": raw}

        data = self._parse_json(raw)
        if not data:
            return {"error": "LLM returned unparseable JSON for template improvement",
                    "raw": raw[:500]}

        # ── Normalize + validate verdicts ──
        step_names = [s.get("name") for s in steps]
        all_tools = self.registry.get_all_tools()
        verdicts, rejected = [], []
        for v in data.get("step_verdicts", []) or []:
            if not isinstance(v, dict):
                continue
            v_step = v.get("step", "")
            verdict = str(v.get("verdict", "keep")).lower()
            if v_step not in step_names:
                rejected.append({"step": v_step,
                                 "reason": "not a step in this template"})
                continue
            if verdict not in ("keep", "modify", "remove"):
                verdict = "keep"
            entry = {
                "step": v_step,
                "verdict": verdict,
                "rationale": sanitize_for_llm(str(v.get("rationale", ""))[:300], max_len=300),
                "changes": {},
            }
            if verdict == "modify":
                repl_tool = str(v.get("replacement_tool", "") or "").strip()
                if repl_tool and repl_tool not in all_tools:
                    rejected.append({"step": v_step,
                                     "reason": f"unknown tool '{repl_tool}'"})
                    # Fall back to keep — don't apply an unknown tool
                    entry["verdict"] = "keep"
                else:
                    if repl_tool:
                        entry["changes"]["tool"] = repl_tool
                    repl_args = v.get("replacement_args")
                    if isinstance(repl_args, dict) and repl_args:
                        entry["changes"]["args"] = repl_args
                    for field, key in (("new_gate", "gate"),
                                       ("new_retries", "retries"),
                                       ("new_timeout", "timeout")):
                        val = v.get(field)
                        if val is not None:
                            try:
                                entry["changes"][key] = (
                                    bool(val) if field == "new_gate" else int(val))
                            except (ValueError, TypeError):
                                pass
            verdicts.append(entry)

        # ── Validate proposed new steps ──
        new_steps = []
        for ns in (data.get("new_steps", []) or [])[:max_new_steps]:
            if not isinstance(ns, dict) or not ns.get("name") or not ns.get("tool"):
                continue
            ns_name = str(ns["name"])
            # Reject name collisions with existing steps or other new steps
            if ns_name in step_names or any(
                    ns_name == (s.get("name") or "") for s in new_steps):
                rejected.append({"step": ns_name,
                                 "reason": "new step name collides with an existing step"})
                continue
            if ns["tool"] not in all_tools:
                rejected.append({"step": ns_name,
                                 "reason": f"new step uses unknown tool '{ns['tool']}'"})
                continue
            # Validate through the same strict pipeline used for generation
            errors = self._validate({
                "name": template.get("name", "improved"),
                "description": template.get("description", ""),
                "category": template.get("category", "general"),
                "variables": template.get("variables", {}) or {},
                "steps": [ns],
            })
            if errors:
                rejected.append({"step": ns.get("name", "?"),
                                 "reason": "; ".join(errors[:2])})
            else:
                new_steps.append(ns)

        # ── Apply validated changes if requested ──
        applied = False
        applied_changes = {"removed": [], "modified": [], "added": []}
        if apply:
            modified_steps = []
            remove_names = {v["step"] for v in verdicts if v["verdict"] == "remove"}
            for step in steps:
                name = step.get("name", "")
                if name in remove_names:
                    applied_changes["removed"].append(name)
                    continue
                entry = next((v for v in verdicts
                              if v["step"] == name and v["verdict"] == "modify"), None)
                if entry and entry["changes"]:
                    new_step = dict(step)
                    new_step.update(entry["changes"])
                    # Resolve variable refs in args before arg-safety check
                    modified_steps.append(new_step)
                    applied_changes["modified"].append(name)
                else:
                    modified_steps.append(step)
            for ns in new_steps:
                modified_steps.append(ns)
                applied_changes["added"].append(ns.get("name", "?"))

            # Full re-validation of the modified template before writing
            full_def = {
                "name": template.get("name", "improved"),
                "description": template.get("description", ""),
                "category": template.get("category", "general"),
                "variables": template.get("variables", {}) or {},
                "steps": modified_steps,
            }
            errors = self._validate(full_def)
            if errors:
                rejected.append({"step": "(template)",
                                 "reason": "full re-validation failed: "
                                            "; ".join(errors[:3])})
                # Nothing was written — do not report phantom changes
                applied_changes = {"removed": [], "modified": [], "added": []}
            elif modified_steps != steps or new_steps:
                # Only write if something actually changed
                try:
                    backup = template_path + \
                        f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    with open(backup, "w") as bf:
                        yaml.safe_dump(template, bf, sort_keys=False, default_flow_style=False)
                    template["steps"] = modified_steps
                    template["description"] = (template.get("description", "") or "") \
                        .split(" [auto-improved")[0] \
                        + f" [auto-improved {datetime.now().strftime('%Y-%m-%d')}]"
                    with open(template_path, "w") as f:
                        yaml.safe_dump(template, f, sort_keys=False, default_flow_style=False)
                    applied = True
                    logger.info(f"Template improved and saved: {template_path} "
                                f"({len(applied_changes['removed'])} removed, "
                                f"{len(applied_changes['modified'])} modified, "
                                f"{len(applied_changes['added'])} added)")
                except Exception as e:
                    return {"error": f"Failed to write improved template: {e}",
                            "assessment": data.get("assessment", ""),
                            "verdicts": verdicts, "new_steps": new_steps,
                            "rejected": rejected, "applied": False}

        return {
            "assessment": sanitize_for_llm(
                str(data.get("assessment", ""))[:600], max_len=600),
            "verdicts": verdicts,
            "new_steps": new_steps,
            "rejected": rejected,
            "applied": applied,
            "applied_changes": applied_changes,
            "path": template_path,
        }

    # ═══════════════════════════════════════════════════════════════
    # LLM interaction
    # ═══════════════════════════════════════════════════════════════

    def _ask_llm(self, objective: str) -> Dict[str, Any]:
        """Query the LLM for a workflow definition with GBNF JSON enforcement."""
        if not self.llm:
            return {"error": "No LLM backend configured — cannot generate workflows"}

        tool_names = sorted(self.registry.get_all_tools().keys())
        tool_hint = ", ".join(tool_names[:60])

        prompt = (
            f"Design a penetration-testing workflow for this objective: \"{objective}\"\n\n"
            f"Available tools (use ONLY these exact names): {tool_hint}\n\n"
            f"Return a JSON object with:\n"
            f"- name: short descriptive title\n"
            f"- description: 1-2 sentences\n"
            f"- category: recon|web|network|ad|cloud|container|wireless|osint|password|exploit|postex\n"
            f"- variables: object of {{name: description}} the operator must supply "
            f"(e.g. target, url, domain)\n"
            f"- steps: array of 3-10 steps, each with:\n"
            f"  - name: unique lowercase_with_underscores\n"
            f"  - tool: exact tool name from the list above\n"
            f"  - args: object of tool arguments; reference variables as "
            f"{{{{variable}}}} (double braces)\n"
            f"  - description: what this step does\n"
            f"  - expected_output: optional regex the output must match to pass\n"
            f"  - gate: true if a failure here must abort the whole workflow\n"
            f"  - retries: 0-2\n"
            f"  - timeout: seconds (60-900)\n\n"
            f"Chain outputs between steps: later steps should consume earlier "
            f"discoveries via {{{{variable}}}} placeholders extracted from output. "
            f"Be specific and realistic. No markdown, JSON only."
        )

        try:
            raw = self.llm.chat_structured(
                [{"role": "system",
                  "content": "You are an expert penetration-testing workflow designer. "
                             "Output strict JSON only."},
                 {"role": "user", "content": prompt}],
                GENERATOR_SCHEMA,
                max_tokens=2048,
                temperature=0.2,
            )
        except Exception as e:
            logger.error(f"LLM workflow generation failed: {e}")
            return {"error": f"LLM workflow generation failed: {e}"}

        if raw.startswith("[ERROR]"):
            return {"error": raw}

        data = self._parse_json(raw)
        if not data:
            return {"error": "LLM returned unparseable JSON for the workflow definition",
                    "raw": raw[:500]}
        return data

    @staticmethod
    def _parse_json(text: str) -> Optional[Dict]:
        """Robust JSON extraction (direct → brace-matched → fenced)."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
        return None

    # ═══════════════════════════════════════════════════════════════
    # Validation (reject-on-any-invalid)
    # ═══════════════════════════════════════════════════════════════

    def _validate(self, definition: Dict[str, Any]) -> List[str]:
        """Validate a generated definition. Returns a list of errors (empty = OK)."""
        errors: List[str] = []
        all_tools = self.registry.get_all_tools()

        if not definition.get("name"):
            errors.append("Missing 'name'")
        steps = definition.get("steps")
        if not isinstance(steps, list) or not steps:
            return errors + ["Missing or empty 'steps' array"]
        if len(steps) > MAX_GENERATED_STEPS:
            errors.append(f"Too many steps ({len(steps)} > {MAX_GENERATED_STEPS})")

        seen_names = set()
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(f"Step {i}: not an object")
                continue
            name = step.get("name", "")
            tool = step.get("tool", "")
            if not name:
                errors.append(f"Step {i}: missing 'name'")
            if name in seen_names:
                errors.append(f"Step {i}: duplicate name '{name}'")
            seen_names.add(name)

            # Tool must exist in the registry
            tool_def = all_tools.get(tool)
            if not tool_def:
                errors.append(f"Step '{name}': unknown tool '{tool}'")
                continue

            # Required args must be present
            args = step.get("args")
            if not isinstance(args, dict):
                errors.append(f"Step '{name}': 'args' must be an object")
                continue
            for pname, pinfo in tool_def.parameters.items():
                if pinfo.get("required") and pname not in args:
                    errors.append(f"Step '{name}': missing required arg '{pname}' "
                                  f"for {tool}")

            # Arg value safety: length + injection patterns
            for pname, val in args.items():
                s = str(val)
                if len(s) > MAX_ARG_STR_LEN:
                    errors.append(f"Step '{name}': arg '{pname}' too long")
                    continue
                for pattern in INJECTION_PATTERNS:
                    if re.search(pattern, s):
                        errors.append(f"Step '{name}': arg '{pname}' rejected "
                                      f"(dangerous characters)")
                        break

            # Coerce scalar fields
            for field, cast in (("timeout", int), ("retries", int), ("gate", bool)):
                if field in step:
                    try:
                        step[field] = cast(step[field])
                    except (ValueError, TypeError):
                        errors.append(f"Step '{name}': '{field}' must be "
                                      f"{cast.__name__}")

        # ── Placeholder validation: every {{var}} referenced in args must be
        # declared in the template's variables (or it'd block at runtime) ──
        declared = set(definition.get("variables", {}) or {})
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            name = step.get("name", f"step_{i}")
            args = step.get("args")
            if not isinstance(args, dict):
                continue
            # Only validate {{var}} double-brace refs. Single-brace {var} is
            # ambiguous inside JSON-serialized args (JSON object braces match
            # the same pattern), and the engine's own _check_unresolved only
            # tracks {{...}} — so we match those semantics exactly.
            args_json = json.dumps(args)
            refs = set(re.findall(r"\{\{([^}]+)\}\}", args_json))
            dangling = sorted(refs - declared)
            if dangling:
                errors.append(f"Step '{name}': references undeclared "
                              f"variable(s) {dangling} — add them to "
                              f"'variables' or remove the reference")

        return errors

    # ═══════════════════════════════════════════════════════════════
    # Persistence
    # ═══════════════════════════════════════════════════════════════

    def _save(self, definition: Dict[str, Any]) -> str:
        """Save the validated definition as a YAML template. Returns the path."""
        os.makedirs(self.templates_dir, exist_ok=True)

        # Sanitize + unique filename
        base = SAFE_FILENAME_RE.sub("_", definition.get("name", "generated").lower())
        base = base.strip("_") or "generated"
        candidate = os.path.join(self.templates_dir, f"{base}.yaml")
        n = 2
        while os.path.exists(candidate):
            candidate = os.path.join(self.templates_dir, f"{base}_{n}.yaml")
            n += 1

        # Build a template dict that round-trips through load()
        template = {
            "name": definition.get("name", ""),
            "description": definition.get("description", ""),
            "category": definition.get("category", "general"),
            "variables": definition.get("variables", {}) or {},
            "cutting_edge": True,
            "references": ["LLM-generated workflow"],
            "steps": definition.get("steps", []),
        }
        with open(candidate, "w") as f:
            yaml.safe_dump(template, f, sort_keys=False, default_flow_style=False)

        logger.info(f"Generated workflow saved: {candidate}")
        return candidate

    # ═══════════════════════════════════════════════════════════════
    # Static helpers
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def summarize_generated(result: Dict[str, Any]) -> str:
        """Human-readable summary of a generation result (for CLI/dashboard)."""
        if result.get("error"):
            return f"✗ Generation failed: {result['error']}"
        steps = result.get("steps", [])
        return (f"✓ Generated '{result['name']}' ({len(steps)} steps)\n"
                f"  Saved: {result.get('path', '')}\n"
                f"  Steps: {', '.join(steps)}\n"
                f"  Variables: {', '.join(result.get('variables', [])) or '(none)'}")
