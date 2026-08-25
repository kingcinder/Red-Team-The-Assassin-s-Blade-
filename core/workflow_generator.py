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
