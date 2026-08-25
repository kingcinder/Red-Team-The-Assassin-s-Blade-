# 🔐 Security Policy — RedTeam Harness (Assassin's Blade)

> **RedTeam Harness is an authorized-security-testing tool.** It automates
> offensive techniques against *your own* systems and networks, or systems you
> have explicit written permission to test. You are responsible for compliance
> with all applicable laws and for the authorization of every target.

---

## Supported Versions

Security fixes are backported to the **latest stable release only**.

| Version | Supported |
|---------|-----------|
| Latest tag (e.g. `v5.8.x`) | ✅ Fully supported |
| Previous minor | ⚠️ Best-effort, security-only |
| Older | ❌ Upgrade to the latest release |

---

## Reporting a Vulnerability

We take security seriously — including vulnerabilities **in this tool itself**.
If you find one, please report it **privately** so we can fix it before it is
exploited:

- **Preferred**: GitHub **Private Security Advisory** — repo → *Security* →
  *Advisories* → *New draft advisory*. Private by default, only maintainers
  see it, and it stays hidden until you choose to publish.
- **Fallback**: email the repository owner directly — find the address via the
  GitHub profile of the `kingcinder` account (the repo owner).
- **Do not** open a public issue, PR, or discussion describing the exploit
  before it is fixed. If a vulnerability report was already made public
  elsewhere, mention that in the advisory so we can prioritize.
- **Include**:
  1. Affected module + version (from the git tag / `git describe`)
  2. A minimal, reproducible trigger (config, prompt, workflow YAML, tool output)
  3. Impact assessment (what an attacker could achieve, and under what
     preconditions)
  4. Suggested fix, if you have one

### What we fix

- **Indirect prompt injection** bypasses in `core/injection_defense.py` or any
  path where tool output / findings reach the LLM unsanitized
- **Command injection / argument-injection** in `core/hardening.py`,
  `core/tool_registry.py`, or `core/tool_installer.py`
- **Path traversal** in dashboard routes, workflow names, or task sandboxes
- **Privilege escalation** or sandbox escape via crafted workflows
- **CVE in dependencies** that affects the offline wheel bundle

### Disclosure timeline

1. **T-0** — Report received; maintainers acknowledge within 72h.
2. **T+7d** — Triage and reproduction; fix targeted for the next release.
3. **T+30d** — Coordinated disclosure (sooner if a public exploit appears).

---

## Threat Model

The harness runs a **locally-hosted LLM that drives real security tools**.
We treat every boundary below as attacker-controlled input.

| Boundary | Input source | Risk | Defense |
|----------|--------------|------|---------|
| **User prompt** | Operator text | Prompt injection / jailbreak | `sanitize_for_llm()`, anchored denylist, `wrap_untrusted()` |
| **Tool output** | Arbitrary remote hosts (nmap banners, nikto pages) | Indirect prompt injection, context stuffing | `sanitize_tool_output()` — control-char strip, homoglyph transliteration, multilingual denylist, truncation |
| **Workflow YAML** | Repo templates, LLM-generated, user-authored | Command injection via tool args | `hardening.validate_template()`, argument allow-lists, no shell string interpolation |
| **Tool args** | LLM planner | Argument injection | Subprocess **list-mode** execution (no `shell=True`), injection-pattern rejection, timeouts |
| **Dashboard HTTP** | Localhost operator | Path traversal, CSRF | `realpath` validation on workflow names, localhost bind, confirmation gates |
| **LLM output** | Local model | Malformed/unsafe tool plans | GBNF grammar enforcement, JSON-schema validation, reflection gates |

### Assumed trust

- The **operator** is authorized and trusted.
- The **LLM is untrusted** — its every plan is validated before execution.
- The **network is hostile** — anything a remote host can echo back is
  treated as an injection attempt.

---

## Hardening Inventory

Implemented and test-covered:

- **Prompt-injection defense** — `core/injection_defense.py`:
  control characters, ANSI/bidi, Unicode homoglyphs, multilingual "ignore
  previous instructions", role-spoofing, special tokens, template injection.
  50+ adversarial vectors covered by `tests/test_injection_defense.py` +
  `tests/test_llm_summarize_injection.py`.
- **Subprocess hardening** — `core/hardening.py`: list-mode exec, timeout
  SIGTERM→SIGKILL, output size caps, injection rejection.
- **Scope enforcement** — `core/safety.py`: CIDR allow-lists, blocked targets
  (`8.8.8.8`, `1.1.1.1`, `0.0.0.0`), confirmation gates on destructive tools
  (`hydra`, `sqlmap`, `msfvenom`).
- **Task isolation** — `core/task_isolation.py`: per-workflow sandboxes under
  `tasks/<name>/<timestamp>/` with size limits and per-step `state.json`.
- **Full audit trail** — every tool invocation logged (args, exit code,
  duration, target).
- **Offline knowledge base** — `core/knowledge_base.py`: all CVE/ATT&CK data
  embedded; every retrieval path passes through `sanitize_for_llm()`.
- **Secrets hygiene** — `.gitignore` blocks `*.pem`, `*.key`, `.env`; the repo
  is scanned for leaked tokens before release (see `RELEASING.md`).

---

## Safe Usage Requirements

- Only test assets you **own** or have **written authorization** to test.
- Keep the dashboard bound to **localhost** — it is not a network service.
- Review every workflow template before execution.
- The LLM is a pilot, not an authority: validate its tool plans (the harness
  does this automatically, but operator awareness is the last line of defense).
