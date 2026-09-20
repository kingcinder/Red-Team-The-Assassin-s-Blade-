# System-Wide Tool Builder Correction and Discovery Design

**Date:** 2026-09-20

## Goal

Correct the known single-parameter command-builder failures and related external wrapper failures, verify the corrected execution paths locally, then perform a separate read-only whole-system discovery pass and publish a detailed report of all additional issues without fixing any discovery-pass findings.

## Scope

The work covers the RedTeam Harness repository and the reachable local tool environment: registered tools, command builders, hardened/direct/workflow/autonomous/Mech execution paths, interceptors, scripts, manifests, dashboards, CLI routes, installed dependencies, PATH and fallback tool directories, external wrappers, virtual environments, and local services.

Phase 1 may fix known defects directly related to the supplied audit. Phase 2 is discovery-only: findings discovered during Phase 2 are documented but not modified.

## Safety and authority boundary

- Exact command construction and safe local capability probes are mandatory.
- No external-network scans, credential attacks, traffic poisoning, exploitation, persistence, host mutation, interface mutation, package installation, or destructive operations will be executed merely as verification.
- Commands that could alter the host or external state require an explicit per-command elevation approval, even though the session confirmed that root execution is available.
- External wrapper files may be repaired in place when the exact change and command are approved.
- Existing unrelated working-tree changes must remain untouched.

## Architecture

The correction uses explicit command builders at the existing `core/command_builder.py` dispatch boundary. The generic one-parameter positional fallback remains available only for tools whose metadata and binary contract genuinely accept a positional argument.

The audit script becomes a faithful harness verifier: it obtains the exact argv from the registry builder, probes that argv rather than reconstructing `[binary, sample]`, and separates builder/schema errors, wrapper failures, binary argument errors, runtime failures, hangs, and intentionally skipped operations.

The whole-system scan is a read-only inventory pipeline. It emits machine-readable evidence and a human report, but it does not apply repairs during the discovery phase.

## Phase 1: correction targets

### Repository command builders

Add explicit builders and tests for:

- `amass_enum`: `amass enum -d <domain>`.
- `trivy_scan`: `trivy image <image>`.
- `recon_ng_gather`: `recon-ng -w <workspace>`.
- `linux_exploit_suggester`: `linux-exploit-suggester -k <kernel>`.
- `gospider_crawl`: `gospider -u <url>`.
- `gophish_setup`: `gophish --config <config>`.
- `ophcrack_crack`: `ophcrack -l <hash_file>`.
- `bloodhound_analyze`: resolve the current schema mismatch explicitly. The existing `neo4j_url` parameter cannot produce a valid BloodHound Python collector command, so the implementation must either preserve it as a compatibility parameter with a clear unsupported-mode result or introduce the collector parameters required by the registered operation and test that contract. It must not silently emit a misleading positional URL.

`burpsuite_proxy` remains an interactive/GUI limitation unless a safe, installed headless/API invocation is demonstrated. It is not declared fixed by removing its positional argument.

### Interceptor and registry correctness

Ensure the meta-tools `install_tool`, `list_missing_tools`, `install_all_missing`, and `check_tool_status` are routed through `ToolInterceptor` before command construction. They must never produce an empty-binary argv.

### External wrapper repairs

Repair known wrapper defects in place, without relocating installations:

- `~/.local/bin/rsmangler` must invoke the existing `/home/cody/tools/rsmangler/rsmangler.rb` with its actual Ruby CLI contract, or another already-installed valid entry point if one is verified.
- `~/.local/bin/enum4linux` must use a durable, verified enum4linux-ng installation or entry point rather than `/tmp/enum4linux-ng`.

The repair must preserve existing registry paths and update related inventory/ledger evidence only as appropriate.

### Audit correctness

Update `scripts/audit_single_param_builders.py` to:

1. enumerate every registered tool by parameter cardinality;
2. build the exact command with the registry builder;
3. resolve the actual executable behind wrappers and prefixes without discarding argv;
4. run only safe probes according to tool metadata and probe policy;
5. classify wrapper failures separately from argument-shape failures;
6. record the exact command, resolved path, return code, timeout, stdout/stderr evidence, and verdict;
7. write consistent JSON and Markdown reports.

## Phase 1 verification

Run, using repository conventions:

- focused command-builder and registry tests;
- affected hardening/interceptor/workflow/Mech tests;
- the full standalone Python test suite;
- Python compilation and import smoke checks;
- JavaScript syntax checks;
- manifest validation;
- local application/dashboard boot checks;
- corrected single-parameter audit;
- bounded safe probes for repaired wrappers and affected binaries.

Any failed pre-existing gate remains visible and is not hidden by narrowing later verification.

## Phase 2: whole-system discovery-only scan

After Phase 1 verification, freeze implementation changes and inspect:

- all repository Python, shell, JavaScript, YAML, JSON, and manifest files;
- all registered tools and all external inventory entries;
- PATH and fallback directories: `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/snap/bin`, `~/.local/bin`, `~/go/bin`, and relevant local tool directories;
- symlink targets, executable permissions, shebang interpreters, wrapper cwd assumptions, environment variables, virtual-environment launchers, and companion tools;
- shared Python user-site dependencies and every discovered virtual environment;
- ELF shared-library dependencies and dynamic-loader resolution;
- command-builder coverage and registry metadata/schema mismatches;
- direct, hardened, workflow, autonomous, Mech, CLI, dashboard, interceptor, timeout, cache, and resume paths;
- local-only service boot and route behavior;
- generated manifests, verification logs, ledgers, and documentation consistency.

Discovery probes must be bounded, offline/local where possible, stdin-safe, and non-mutating. Destructive or offensive entries receive static contract checks and safe help/version probes rather than normal operation.

## Reporting

Produce a dated machine-readable dataset and detailed Markdown report. Each issue must include:

- identifier;
- severity and confidence;
- what is broken or suspicious;
- when and how it was detected;
- exact location/path/tool;
- why it occurs;
- reproduction command or probe method;
- observed evidence;
- affected execution paths;
- recommended correction;
- whether it was fixed in Phase 1, intentionally deferred, pre-existing, or newly discovered in Phase 2.

The report must clearly separate:

1. Phase 1 fixed findings;
2. known intentional limitations;
3. Phase 1 verification gaps or inconclusive probes;
4. Phase 2 newly discovered findings, which remain unfixed.

## Files expected to change

- `core/command_builder.py`
- `core/tool_registry.py` only if schema or interception integration requires it
- `core/tool_interceptor.py` only if routing gaps are found
- `scripts/audit_single_param_builders.py`
- `tests/test_tool_registry_commands.py`
- focused related tests as needed
- new Phase 2 discovery scanner/report artifacts under `scripts/` and `docs/`
- external wrapper files only when an approved exact repair is applied

No unrelated refactoring or cleanup is included.

## Design self-review

- **Spec coverage:** known eight builder failures, Burp limitation, three meta-tools, two external wrappers, exact-argv audit defect, direct and indirect execution paths, whole-system scan, safe verification, and discovery-only reporting are all covered.
- **Placeholder scan:** no TODO/TBD implementation placeholders are used.
- **Consistency:** Phase 1 permits targeted repairs; Phase 2 explicitly forbids repairs to newly discovered findings.
- **Scope:** the work is broad but decomposed into a correction/verification pass followed by a frozen discovery pass, each with independent evidence.
