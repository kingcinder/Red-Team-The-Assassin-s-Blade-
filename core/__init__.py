"""
RedTeam Harness — Core Engine
=============================

The central orchestration layer for the AI-powered penetration testing harness.

Modules:
    orchestrator        — Main controller: routes prompts → plans → tool execution → results
    llm_backend         — LLM adapter (llama-server / Ollama) with retry and fallback
    tool_registry       — Registry of 140+ Kali Linux tools with auto-detection
    workflow_engine     — YAML workflow state machine with variable interpolation and chaining
    workflow_generator  — LLM-driven workflow YAML generator from natural-language objectives
    task_isolation      — Per-task sandboxed execution with cgroup/namespace isolation
    hardening           — Drift detection, integrity checks, and output sanitization
    safety              — Scope enforcement, target allowlisting, and confirmation gates
    session             — Session persistence and history management
    findings            — Severity-classified finding extraction from tool output
    correlation         — Cross-finding correlation engine with attack-path scoring
    parallel            — ThreadPool-based parallel tool execution with result pooling
    result_cache        — LRU result cache with TTL for deduplication
    context_manager     — Context-window trimming for LLM prompts
    tactics             — Tactical suggestion engine (next-action recommendations)
    prioritizer         — Target prioritization by risk score
    auto_prioritizer    — LLM-driven target ranking by exploitability (v5.2)
    task_scheduler      — Multi-target concurrent workflow scheduler
    autonomous          — Fire-and-forget autonomous agent (recon→vuln→exploit→postex)
    campaign            — Multi-target campaign manager with risk scoring
    vector_memory       — ChromaDB/FAISS-backed session memory for cross-engagement recall
    injection_defense   — Prompt-injection sanitizer for LLM-facing inputs
    msf_generator       — Metasploit .rc script auto-generator from nmap results
    tool_installer      — Runtime tool installer (apt/pip) for missing Kali tools
"""
