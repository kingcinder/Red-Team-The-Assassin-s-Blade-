"""
RedTeam Harness — Unified Report Writer (architecture candidate #4)

ONE deep module that owns every markdown report format in the harness.
Previously eight shallow writers hand-rolled markdown from the same
finding/campaign data across six modules (findings, workflow_engine,
orchestrator ×2, task_scheduler ×2, campaign, autonomous) — a format
change meant touching all eight. Callers now pass structured data and
receive markdown; formatting lives here and only here.

Writers:
  - findings_section()           — per-severity findings detail + risk table
  - workflow_report()            — single-workflow pentest report
  - chain_report()               — chained workflow report
  - parallel_report()            — parallel multi-workflow campaign report
  - combined_report()            — multi-target combined engagement report
  - campaign_report()            — persisted campaign post-engagement report
  - autonomous_report()          — autonomous engagement fallback report
  - report_prompt()              — LLM narrative prompt builder (data→prompt)

All functions are pure: structured data in, markdown string out.
"""
from typing import Dict, Any, List

from core.findings import get_extractor as _get_findings_extractor

SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                  "low": "🔵", "info": "⚪"}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
STATUS_EMOJI = {"complete": "✅", "partial": "⚠️", "failed": "❌",
                "error": "💀"}


def _sev_emoji(sev: str) -> str:
    return SEVERITY_EMOJI.get(str(sev).lower(), "⚪")


def _risk_line(risk: Dict[str, Any]) -> str:
    total = risk.get("total", risk.get("score", 0))
    rating = risk.get("rating", risk.get("grade", "N/A"))
    return f"- **Risk Score**: {total}/100 ({rating})"


def findings_section(findings: List[Dict[str, Any]]) -> str:
    """Structured markdown findings section (risk table + per-severity detail)."""
    ext = _get_findings_extractor()
    if not findings:
        return "No findings extracted during this run.\n"

    lines = []
    severity_groups = ext.group_by_severity(findings)
    risk = ext.compute_risk_score(findings)

    lines.append(f"**Overall Risk Score: {risk['score']}/100 (Grade: {risk['grade']})**")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in SEVERITY_ORDER:
        count = risk["breakdown"].get(sev, 0)
        if count > 0:
            lines.append(f"| {sev.upper()} | {count} |")
    lines.append("")

    for sev in SEVERITY_ORDER:
        sev_findings = severity_groups.get(sev, [])
        if not sev_findings:
            continue
        lines.append(f"### {_sev_emoji(sev)} {sev.upper()} Findings ({len(sev_findings)})")
        lines.append("")
        for i, f in enumerate(sev_findings, 1):
            lines.append(f"**{i}. {f.get('title', 'Finding')}**")
            lines.append(f"- **Category**: {f.get('category', 'n/a')}")
            lines.append(f"- **Source**: `{f.get('source_tool', '')}` "
                         f"(step: {f.get('source_step', '')})")
            lines.append(f"- **Evidence**: `{f.get('evidence', '')[:300]}`")
            if f.get("context"):
                lines.append("- **Context**:")
                lines.append("  ```")
                lines.append(f"  {f['context'][:300]}")
                lines.append("  ```")
            remediation = ext.get_remediation(f.get("category", ""))
            if remediation:
                lines.append("- **Remediation**:")
                for r in remediation[:3]:
                    lines.append(f"  - {r}")
            lines.append("")

    return "\n".join(lines)


def workflow_report(*, workflow: str, category: str = "general",
                    attack_vector: str = "N/A", task_id: str = "",
                    status: str = "unknown", started: str = "N/A",
                    finished: str = "N/A", steps_completed: int = 0,
                    total_steps: int = 0, findings: List[Dict[str, Any]],
                    completed: List[Dict[str, Any]],
                    warnings: List[Dict[str, Any]] = None,
                    chain_values: Dict[str, str] = None,
                    paths: List[Dict[str, Any]] = None,
                    paths_markdown: str = "", summary_markdown: str = "",
                    narrative: str = "", deep_dive: str = "") -> str:
    """Single-workflow pentest report (previously workflow_engine.generate_report)."""
    warnings = warnings or []
    chain_values = chain_values or {}
    lines = []
    lines.append(f"# Penetration Test Report — {workflow}")
    lines.append("")
    lines.append(f"- **Workflow**: {workflow}")
    lines.append(f"- **Category**: {category}")
    lines.append(f"- **Attack vector**: {attack_vector}")
    if task_id:
        lines.append(f"- **Task ID**: {task_id}")
    lines.append(f"- **Status**: {status}")
    lines.append(f"- **Started**: {started}")
    lines.append(f"- **Finished**: {finished}")
    lines.append(f"- **Steps completed**: {steps_completed}/{total_steps}")
    lines.append("")

    ext = _get_findings_extractor()
    lines.append("## 1. Executive Summary")
    lines.append("")
    if findings:
        counts = ext.summarize(findings)
        risk = ext.compute_risk_score(findings)
        worst = ext.worst_severity(findings)
        lines.append(f"**Risk Score: {risk['score']}/100 (Grade: {risk['grade']})**")
        lines.append("")
        lines.append(f"The assessment identified **{len(findings)} finding(s)** "
                     f"across the target, with the highest severity being "
                     f"**{worst.upper()}**.")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in SEVERITY_ORDER:
            c = counts.get(sev, 0)
            if c > 0:
                lines.append(f"| {sev.upper()} | {c} |")
    else:
        lines.append("No automated findings were extracted during this run.")
    lines.append("")

    lines.append("## 2. Methodology / Steps Executed")
    lines.append("")
    for i, s in enumerate(completed, 1):
        status_s = s.get("status", "?")
        tool = s.get("tool", "?")
        alt = ""
        if s.get("llm_alt"):
            alt = f" *(LLM alternative: {s['llm_alt'].get('tool', '')})*"
        lines.append(f"{i}. **{s.get('step', 'step')}** — `{tool}` "
                     f"[{status_s}]{alt}")
    lines.append("")

    if paths:
        lines.append("## 3. Correlated Attack Paths")
        lines.append("")
        if paths_markdown:
            lines.append(paths_markdown)
            lines.append("")
        if summary_markdown:
            lines.append(summary_markdown)

    findings_heading = "## 4. Findings" if paths else "## 3. Findings"
    lines.append(findings_heading)
    lines.append("")
    if findings:
        lines.append(findings_section(findings))
    else:
        lines.append("No findings recorded.")
        lines.append("")

    if chain_values:
        chain_heading = "## 5. Extracted Chain Values" if paths else "## 4. Extracted Chain Values"
        lines.append(chain_heading)
        lines.append("")
        lines.append("```")
        for k, v in chain_values.items():
            lines.append(f"{k} = {v}")
        lines.append("```")
        lines.append("")

    if warnings:
        warn_heading = "## 6. Warnings & Failed Steps" if paths else "## 5. Warnings & Failed Steps"
        lines.append(warn_heading)
        lines.append("")
        for w in warnings:
            lines.append(f"- **{w.get('step', '?')}**: {w.get('reason', '')}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated automatically by RedTeam Harness. "
                 "Review all evidence before acting on findings.*")

    # Insert narrative + deep dive after the title line
    _NARRATIVE_MARKER = "__NARRATIVE_INSERT__"
    _DEEPDIVE_MARKER = "__DEEPDIVE_INSERT__"
    if lines and lines[0].startswith("# "):
        lines.insert(1, _NARRATIVE_MARKER)
        lines.insert(2, _DEEPDIVE_MARKER)
    else:
        lines.insert(0, _NARRATIVE_MARKER)
        lines.insert(1, _DEEPDIVE_MARKER)
    report = "\n".join(lines)
    if narrative:
        report = report.replace(_NARRATIVE_MARKER, narrative + "\n")
    else:
        report = report.replace(_NARRATIVE_MARKER, "")
    if deep_dive:
        report = report.replace(_DEEPDIVE_MARKER, deep_dive + "\n")
    else:
        report = report.replace(_DEEPDIVE_MARKER, "")
    return report


def chain_report(*, chain_id: str, status: str, links: List[Dict[str, Any]],
                 links_count: int = None, findings: List[Dict[str, Any]] = None,
                 findings_count: int = None, loop_guard: str = "",
                 correlation_paths: List[Dict[str, Any]] = None,
                 paths_markdown: str = "") -> str:
    """Chained-workflow report (previously orchestrator._build_chain_report)."""
    findings = findings or []
    links_count = links_count if links_count is not None else len(links)
    findings_count = findings_count if findings_count is not None else len(findings)
    lines = [
        f"# Chained Workflow Report — {chain_id}",
        "",
        f"- **Status**: {status}",
        f"- **Links executed**: {links_count}",
        f"- **Total findings**: {findings_count}",
        "",
        "## Chain Objectives",
        "",
    ]
    for i, link in enumerate(links, 1):
        ex = link.get("execution") or {}
        lines.append(f"{i}. **{link.get('objective', '?')}** → "
                     f"`{ex.get('workflow', '?')}` "
                     f"[{ex.get('status', link.get('status', '?'))}] "
                     f"({ex.get('completed_steps', 0)}/{ex.get('total_steps', 0)} steps)")
        if link.get("template_improvement"):
            ti = link["template_improvement"]
            if not ti.get("error") and ti.get("applied"):
                ac = ti.get("applied_changes", {})
                lines.append(f"    ↳ template improved: "
                             f"{len(ac.get('removed', []))} removed, "
                             f"{len(ac.get('modified', []))} modified, "
                             f"{len(ac.get('added', []))} added")
    if loop_guard:
        lines.append(f"\n*Chain stopped by loop guard: '{loop_guard}' "
                     f"was already executed.*")

    if findings:
        counts = {}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            counts[sev] = counts.get(sev, 0) + 1
        lines.append("")
        lines.append("## Findings Summary")
        lines.append("")
        for sev in SEVERITY_ORDER:
            if counts.get(sev):
                lines.append(f"- **{sev.upper()}**: {counts[sev]}")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            lines.append(f"- [{str(f.get('severity', 'info')).upper()}] "
                         f"{f.get('title', '?')} — {f.get('description', '')}")
    if correlation_paths and paths_markdown:
        lines.append("")
        lines.append("## Correlated Attack Paths")
        lines.append("")
        lines.append(paths_markdown)
    lines.append("")
    lines.append("---")
    lines.append("*Generated automatically by RedTeam Harness.*")
    return "\n".join(lines)


def parallel_report(summary: Dict[str, Any]) -> str:
    """Parallel multi-workflow campaign report (task_scheduler._write_parallel_report)."""
    workflow = summary["workflow"]
    risk = summary.get("risk_score", {})
    paths = summary.get("correlated_paths", [])
    counts = summary.get("findings_summary", {})
    lines = []
    lines.append(f"# Parallel Campaign Report — {workflow}")
    lines.append("")
    lines.append(f"- **Workflows**: {workflow}")
    lines.append(f"- **Targets**: {', '.join(summary['targets'])}")
    lines.append(f"- **Started**: {summary.get('started', '')}")
    lines.append(f"- **Status**: {summary.get('status', 'unknown')}")
    if risk:
        lines.append(f"- **Risk Score**: {risk.get('total', 0)}/100 "
                     f"({risk.get('rating', 'N/A')})")
    if summary.get("campaign_id"):
        lines.append(f"- **Campaign**: {summary['campaign_id']}")
    lines.append("")

    jobs = summary.get("jobs", {})
    if jobs:
        lines.append("## 1. Workflow Jobs")
        lines.append("")
        lines.append("| Job | Workflow | Targets | Status | Findings |")
        lines.append("|-----|----------|---------|--------|----------|")
        for name, j in jobs.items():
            emoji = STATUS_EMOJI.get(j.get("status"), "❓")
            lines.append(
                f"| {name} | {j.get('workflow', '')} | "
                f"{', '.join(j.get('targets', []))} | "
                f"{emoji} {j.get('status', 'unknown')} | "
                f"{j.get('findings_count', 0)} |")
        lines.append("")

    lines.append("## 2. Executive Summary")
    lines.append("")
    lines.append(
        f"Ran **{len(jobs)} workflow(s)** in parallel against "
        f"**{len(summary['targets'])} target(s)**. Merged "
        f"**{len(summary.get('pooled_findings', []))} unique finding(s)** "
        f"across workflows and correlated them into "
        f"**{len(paths)} cross-workflow attack path(s)**.")
    lines.append("")
    if risk:
        lines.append(f"**Risk Assessment: {risk.get('total', 0)}/100 "
                     f"({risk.get('rating', 'N/A')})**")
        lines.append("")

    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in SEVERITY_ORDER:
        c = counts.get(sev, 0)
        if c > 0:
            lines.append(f"| {_sev_emoji(sev)} {sev.upper()} | {c} |")
    lines.append("")

    lines.append("## 3. Cross-Workflow Attack Paths")
    lines.append("")
    if paths:
        lines.append(f"**{len(paths)} path(s)** chaining findings across "
                     f"the parallel workflows:")
        lines.append("")
        lines.append("| # | Severity | Path | Score | Confidence | Kill Chain | ATT&CK |")
        lines.append("|---|----------|------|-------|------------|------------|--------|")
        for i, p in enumerate(paths[:15], 1):
            techs = ", ".join(t["id"] for t in p.get("attack_techniques", [])[:3])
            lines.append(
                f"| {i} | {_sev_emoji(p['severity'])} {p['severity'].upper()} | "
                f"{p['title']} | {p['score']} | "
                f"{p.get('confidence', 0) * 100:.0f}% | "
                f"{p.get('kill_chain_progress', 0) * 100:.0f}% | {techs} |")
        lines.append("")
        for i, p in enumerate(paths[:10], 1):
            lines.append(f"### {i}. {_sev_emoji(p['severity'])} {p['title']}")
            lines.append(f"- **Score**: {p['score']} | **Confidence**: "
                         f"{p.get('confidence', 0) * 100:.0f}%")
            lines.append(f"- **Kill Chain**: "
                         f"{p.get('kill_chain_progress', 0) * 100:.0f}% "
                         f"(phases: {', '.join(p.get('kill_chain_phases', []))})")
            if p.get("attack_techniques"):
                lines.append("- **ATT&CK**: " + ", ".join(
                    f"`{t['id']}` {t.get('name', '')}" for t in p["attack_techniques"][:5]))
            if p.get("finding_details"):
                lines.append("- **Linked Findings**:")
                for fd in p["finding_details"][:5]:
                    src = f" ({fd.get('source_workflow', '')})" if fd.get("source_workflow") else ""
                    lines.append(
                        f"  - [{fd['severity'].upper()}] {fd['title']} "
                        f"(`{fd.get('source_tool', '')}`){src}")
            lines.append("- **Remediation**:")
            for r in p["remediation"]:
                lines.append(f"  - {r}")
            lines.append("")
    else:
        lines.append("No cross-workflow attack paths identified.")
        lines.append("")

    lines.append("## 4. Merged Findings")
    lines.append("")
    merged = summary.get("pooled_findings", [])
    if merged:
        lines.append(f"**{len(merged)} unique finding(s)** across all "
                     f"workflows:")
        lines.append("")
        for f in merged:
            wf = f.get("_source_workflow", "")
            wf_tag = f" · workflow={wf}" if wf else ""
            lines.append(
                f"- [{f.get('severity', 'info').upper()}] **{f.get('title', '')}** "
                f"(`{f.get('target', '')}`){wf_tag} — "
                f"{f.get('evidence', '')[:120]}")
    else:
        lines.append("No findings merged.")
    lines.append("")

    if risk:
        lines.append("## 5. Risk Score Breakdown")
        lines.append("")
        lines.append(f"- **Total**: {risk['total']}/100 ({risk['rating']})")
        for k, v in risk.get("breakdown", {}).items():
            lines.append(f"  - {k}: {v}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by RedTeam Harness v5.3 parallel multi-workflow "
                 "scheduler with cross-workflow correlation.*")
    return "\n".join(lines)


def combined_report(summary: Dict[str, Any]) -> str:
    """Multi-target combined engagement report (task_scheduler._write_combined_report)."""
    workflow = summary["workflow"]
    risk = summary.get("risk_score", {})
    paths = summary.get("correlated_paths", [])
    counts = summary.get("findings_summary", {})
    findings = summary.get("pooled_findings", [])
    lines = []
    lines.append(f"# Combined Engagement Report — {workflow}")
    lines.append("")
    lines.append(f"- **Targets**: {', '.join(summary['targets'])}")
    lines.append(f"- **Started**: {summary.get('started', '')}")
    lines.append(f"- **Status**: {summary.get('status', 'unknown')}")
    if risk:
        lines.append(f"- **Risk Score**: {risk.get('total', 0)}/100 "
                     f"({risk.get('rating', 'N/A')})")
    if summary.get("campaign_id"):
        lines.append(f"- **Campaign**: {summary['campaign_id']}")
    lines.append("")

    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"Assessed **{len(summary['targets'])} target(s)** using workflow "
                 f"`{workflow}`. Identified **{len(findings)} unique finding(s)** "
                 f"across all targets, correlated into **{len(paths)} attack path(s)**.")
    lines.append("")
    if risk:
        lines.append(f"**Risk Assessment: {risk.get('total', 0)}/100 "
                     f"({risk.get('rating', 'N/A')})**")
        lines.append("")

    prio = summary.get("priority_plan", [])
    if prio:
        lines.append("## 0. Target Priority Plan")
        lines.append("")
        lines.append("Targets were ranked by exploitability before execution "
                     "(high-value first, processed with more retries):")
        lines.append("")
        lines.append("| Rank | Target | Score | Tier | Aggression | Rationale |")
        lines.append("|------|--------|-------|------|------------|-----------|")
        for e in prio[:20]:
            lines.append(
                f"| {e.get('rank', '?')} | {e.get('target', '')} | "
                f"{e.get('score', 0)} | {e.get('tier', '')} | "
                f"{e.get('aggressiveness', 1.0)}x | "
                f"{str(e.get('rationale', ''))[:80]} |")
        lines.append("")

    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in SEVERITY_ORDER:
        c = counts.get(sev, 0)
        if c > 0:
            lines.append(f"| {_sev_emoji(sev)} {sev.upper()} | {c} |")
    lines.append("")

    lines.append("## 2. Per-Target Results")
    lines.append("")
    lines.append("| Target | Status | Steps | Findings | Drift |")
    lines.append("|--------|--------|-------|----------|-------|")
    for t, r in summary["per_target"].items():
        status = r.get("status", "unknown")
        emoji = STATUS_EMOJI.get(status, "❓")
        lines.append(
            f"| {t} | {emoji} {status} | "
            f"{r.get('steps_count', 0)}/{r.get('total_steps', 0)} | "
            f"{r.get('findings_count', 0)} | "
            f"{r.get('drift_score', 0):.2f} |")
    lines.append("")

    if paths:
        lines.append("## 3. Correlated Attack Paths")
        lines.append("")
        lines.append(f"{len(paths)} attack path(s) identified across all targets:")
        lines.append("")
        lines.append("| # | Severity | Path | Score | Confidence "
                     "| Kill Chain | ATT&CK |")
        lines.append("|---|----------|------|-------|------------"
                     "|------------|--------|")
        for i, p in enumerate(paths[:15], 1):
            kill_pct = f"{p.get('kill_chain_progress', 0)*100:.0f}%"
            techs = ", ".join(t["id"] for t in p.get("attack_techniques", [])[:3])
            lines.append(
                f"| {i} | {_sev_emoji(p['severity'])} {p['severity'].upper()} | "
                f"{p['title']} | {p['score']} | "
                f"{p.get('confidence', 0)*100:.0f}% | {kill_pct} | {techs} |")
        lines.append("")
        for i, p in enumerate(paths[:10], 1):
            lines.append(f"### {i}. {_sev_emoji(p['severity'])} {p['title']}")
            lines.append(f"- **Score**: {p['score']} | **Confidence**: "
                         f"{p.get('confidence', 0)*100:.0f}%")
            lines.append(f"- **Kill Chain**: "
                         f"{p.get('kill_chain_progress', 0)*100:.0f}% "
                         f"(phases: {', '.join(p.get('kill_chain_phases', []))})")
            if p.get("attack_techniques"):
                tech_str = ", ".join(
                    f"`{t['id']}` {t.get('name', '')}"
                    for t in p["attack_techniques"][:5])
                lines.append(f"- **ATT&CK**: {tech_str}")
            if p.get("finding_details"):
                lines.append("- **Linked Findings**:")
                for fd in p["finding_details"][:5]:
                    lines.append(
                        f"  - [{fd['severity'].upper()}] {fd['title']} "
                        f"(`{fd.get('source_tool', '')}`)")
            lines.append("- **Remediation**:")
            for r in p["remediation"]:
                lines.append(f"  - {r}")
            lines.append("")

        all_techs = summary.get("attack_techniques", [])
        if all_techs:
            lines.append("### MITRE ATT&CK Coverage")
            lines.append("")
            lines.append(f"**{len(all_techs)} technique(s)** mapped:")
            lines.append("")
            lines.append(", ".join(f"`{t}`" for t in all_techs))
            lines.append("")
        all_phases = summary.get("kill_chain_phases", [])
        if all_phases:
            lines.append("### Kill Chain Coverage")
            lines.append("")
            lines.append(", ".join(f"`{p}`" for p in all_phases))
            lines.append("")
    else:
        lines.append("## 3. Correlated Attack Paths")
        lines.append("")
        lines.append("No correlated attack paths identified.")
        lines.append("")

    lines.append("## 4. Pooled Findings")
    lines.append("")
    if findings:
        lines.append(f"**{len(findings)} unique finding(s)**:")
        lines.append("")
        for f in findings:
            target = f.get("target", "")
            sev = f.get("severity", "info").upper()
            lines.append(
                f"- [{sev}] **{f.get('title', '')}** "
                f"(`{target}`) — "
                f"{f.get('evidence', '')[:120]}")
    else:
        lines.append("No findings extracted.")
    lines.append("")

    if summary.get("chain_values"):
        lines.append("## 5. Extracted Chain Values")
        lines.append("")
        lines.append("```")
        for k, v in summary["chain_values"].items():
            lines.append(f"{k} = {v}")
        lines.append("```")
        lines.append("")

    if risk:
        lines.append("## 6. Risk Score Breakdown")
        lines.append("")
        lines.append(f"- **Total**: {risk['total']}/100 ({risk['rating']})")
        for k, v in risk.get("breakdown", {}).items():
            lines.append(f"  - {k}: {v}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by RedTeam Harness v5.0 multi-target scheduler "
                 "with finding correlation.*")
    return "\n".join(lines)


def campaign_report(data: Dict[str, Any], risk_rating) -> str:
    """Persisted campaign post-engagement report (campaign._write_campaign_report)."""
    lines = [f"# Campaign Report — {data.get('name', data.get('id', ''))}", ""]
    lines.append(f"- **Campaign**: {data.get('id', '')}")
    lines.append(f"- **Workflow**: {data.get('workflow', '')}")
    lines.append(f"- **Status**: {data.get('status', '')}")
    lines.append(f"- **Created**: {data.get('created', '')}")
    lines.append(f"- **Risk Score**: {data.get('risk_score', 0)}/100 "
                 f"({risk_rating(data.get('risk_score', 0))})")
    lines.append(f"- **Drift Avg**: {data.get('drift_avg', 0)}")
    lines.append("")
    lines.append("## Targets")
    lines.append("")
    lines.append("| Target | Status | Progress | Findings | Drift |")
    lines.append("|--------|--------|----------|----------|-------|")
    for t, pt in (data.get("per_target") or {}).items():
        lines.append(f"| {t} | {pt.get('status', '')} | "
                     f"{pt.get('progress', 0)}% | "
                     f"{pt.get('findings_count', 0)} | "
                     f"{pt.get('drift_score', 0)} |")
    lines.append("")
    lines.append("## Findings by Severity")
    lines.append("")
    totals = {sev: 0 for sev in SEVERITY_ORDER}
    for pt in (data.get("per_target") or {}).values():
        for sev, n in (pt.get("findings_by_severity") or {}).items():
            totals[sev] = totals.get(sev, 0) + n
    for sev, n in totals.items():
        if n:
            lines.append(f"- {sev.upper()}: {n}")
    lines.append("")
    lines.append("## Retained Findings")
    lines.append("")
    for t, pt in (data.get("per_target") or {}).items():
        for f in (pt.get("findings") or []):
            lines.append(f"- [{f.get('severity', 'info').upper()}] "
                         f"{f.get('title', '')} (`{t}`) — "
                         f"{str(f.get('evidence', ''))[:120]}")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by RedTeam Harness v5.5 campaign persistence.*")
    return "\n".join(lines)


def autonomous_report(*, objective: str, generated_at: str, duration: str,
                      state: str, targets_count: int, total_steps: int,
                      findings: List[Dict[str, Any]],
                      target_summaries: List[str],
                      kill_chain_counts: Dict[str, Dict[str, int]]) -> str:
    """Autonomous engagement fallback report (autonomous._generate_fallback_report)."""
    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines = [
        "# Autonomous Engagement Report",
        "",
        f"**Generated**: {generated_at}",
        f"**Objective**: {objective}",
        f"**Duration**: {duration}",
        f"**State**: {state}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Targets | {targets_count} |",
        f"| Total Steps | {total_steps} |",
        f"| Total Findings | {len(findings)} |",
        f"| Critical | {severity_counts.get('critical', 0)} |",
        f"| High | {severity_counts.get('high', 0)} |",
        f"| Medium | {severity_counts.get('medium', 0)} |",
        f"| Info | {severity_counts.get('info', 0)} |",
        "",
        "## Targets",
        "",
    ] + [s for s in target_summaries] + [
        "",
        "## Findings",
        "",
    ]

    by_target = {}
    for f in findings:
        t = f.get("target", "unknown")
        by_target.setdefault(t, []).append(f)

    for target, t_findings in by_target.items():
        lines.append(f"### {target}")
        lines.append("")
        for f in t_findings:
            sev = f.get("severity", "info").upper()
            tool = f.get("tool", "unknown")
            phase = f.get("phase", "unknown")
            summary = f.get("summary", "No summary")[:200]
            lines.append(f"- **[{sev}]** `{tool}` ({phase}): {summary}")
        lines.append("")

    lines.extend(["## Kill Chain Coverage", ""])
    for target, phase_counts in kill_chain_counts.items():
        for phase, count in phase_counts.items():
            if count > 0:
                lines.append(f"- **{target}** → {phase.upper()}: {count} findings")

    return "\n".join(lines)


def report_prompt(findings: List[Dict[str, Any]],
                  tool_log: List[Dict[str, Any]], max_len: int = 4000) -> str:
    """Build the LLM pentest-report prompt from structured session data."""
    findings_text = ""
    for f in findings[-20:]:  # Last 20 findings
        findings_text += (f"- [{f.get('severity', 'Info')}] "
                          f"{f.get('title', '')}: {f.get('description', '')}\n")

    from core.injection_defense import sanitize_tool_output
    return (
        f"You conducted a penetration test. Generate a structured markdown report.\n\n"
        f"## Tools Executed\n{', '.join(set(t['tool'] for t in tool_log[-50:]))}\n\n"
        f"## Findings\n{sanitize_tool_output(findings_text or 'No findings recorded.', max_len=max_len)}\n\n"
        f"Draft a professional penetration test report with sections: "
        f"Executive Summary, Methodology, Findings, Remediation, Conclusion."
    )


def autonomous_report_prompt(*, objective: str, duration: str,
                             targets: List[str],
                             target_summaries: List[str],
                             total_steps: int,
                             findings: List[Dict[str, Any]]) -> str:
    """Build the LLM report prompt for an autonomous engagement.

    Richer than report_prompt(): includes objective, duration, per-target
    kill-chain summaries, and capped key-findings list.
    """
    findings_text = ""
    for f in findings[:50]:  # Cap at 50 findings for report
        sev = f.get("severity", "info").upper()
        tool = f.get("tool", "unknown")
        target = f.get("target", "unknown")
        summary = f.get("summary", "")[:120]
        findings_text += f"- [{sev}] {target}: {tool} — {summary}\n"

    from core.injection_defense import sanitize_tool_output
    return (
        f"Generate a comprehensive penetration test report for an autonomous engagement.\n\n"
        f"## Objective\n{sanitize_tool_output(objective, max_len=1000)}\n\n"
        f"## Duration\n{duration}\n\n"
        f"## Targets ({len(targets)})\n"
        + "\n".join(target_summaries) + "\n\n"
        f"## Total Steps: {total_steps}\n"
        f"## Total Findings: {len(findings)}\n\n"
        f"## Key Findings\n{sanitize_tool_output(findings_text or 'No findings recorded.', max_len=6000)}\n\n"
        f"Write a professional penetration test report with:\n"
        f"1. Executive Summary\n"
        f"2. Methodology\n"
        f"3. Findings by Target\n"
        f"4. Kill Chain Coverage\n"
        f"5. Remediation Recommendations\n"
        f"6. Conclusion"
    )
