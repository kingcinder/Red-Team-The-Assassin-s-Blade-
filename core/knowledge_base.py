"""
RedTeam Harness — Offline Cybersecurity Knowledge Base (v5.6)
=============================================================

A curated, air-gap-safe knowledge base the LLM can reference during
engagements — CVE database, MITRE ATT&CK technique mappings, exploit
signatures, and remediation playbooks — all embedded in this module (no
network access required) and indexed for fast retrieval alongside the
vector memory system.

Components:
  - CVE_DATABASE: curated list of high-value CVEs with severity, affected
    software, exploit signatures (regex patterns), ATT&CK technique links,
    and concrete remediation playbooks (steps + shell commands).
  - ATTACK_TECHNIQUES: MITRE ATT&CK technique catalogue (id, name, tactic,
    detection, mitigation) mirroring the correlation engine's table plus
    detection/mitigation guidance.
  - EXPLOIT_SIGNATURES: regex patterns that match tool output / banners to
    known CVEs (e.g. "MS17-010", "Log4Shell") for automatic grounding.
  - KnowledgeBase class: TF-IDF vector index (mirrors VectorMemory's
    scikit-learn approach) for fast similarity search, plus
    signature-based exact grounding.

Usage:
    kb = KnowledgeBase()
    kb.lookup_cve("CVE-2021-44228")
    kb.search("log4j remote code execution", top_k=5)
    kb.signature_match("445/tcp MS17-010 vulnerable")  # -> [CVE-2017-0144]
    kb.ground_findings(findings)   # attach cves/techniques/remediation
    kb.get_context_block("log4shell")  # sanitized, LLM-ready
"""

import os
import re
import json
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("redteam.knowledge")

# ── Optional scikit-learn for TF-IDF search (lazy — 900ms+ import cost) ──
_HAS_SKLEARN: Optional[bool] = None  # None = not checked yet
_TfidfVectorizer = None
cosine_similarity = None


def _ensure_sklearn():
    """Lazy-import sklearn on first use (~900ms cost deferred from module load)."""
    global _HAS_SKLEARN, _TfidfVectorizer, cosine_similarity
    if _HAS_SKLEARN is not None:
        return
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer as _TV
        from sklearn.metrics.pairwise import cosine_similarity as _CS
        _TfidfVectorizer = _TV
        cosine_similarity = _CS
        _HAS_SKLEARN = True
    except Exception:
        _HAS_SKLEARN = False

from core.injection_defense import sanitize_for_llm
# Embedded dataset (architecture re-review R1) lives in core/kb_data.py so the
# retrieval/behaviour class is separate from the data records. The tables are
# re-exported here so `from core.knowledge_base import ATTACK_TECHNIQUES` and
# the derived-name identity semantics in core/correlation.py keep working.
from core.kb_data import ATTACK_TECHNIQUES, CVE_DATABASE

SIMILARITY_THRESHOLD = 0.12
CONTEXT_MAX_CHARS = 4000
CONTEXT_MAX_ENTRIES = 8

# ═══════════════════════════════════════════════════════════════════
# EMBEDDED DATASET — sourced from core/kb_data.py (architecture re-review R1)
# ATTACK_TECHNIQUES + CVE_DATABASE live there as plain data, imported above.
# ═══════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════
# LAZY DERIVED EXPORTS — deferred to first access for fast import
# correlation.py imports TECHNIQUE_NAMES/ATTACK_TACTICS/ATTACK_TACTIC_ORDER
# at module level; building them eagerly added ~1s to every import chain.
# ═══════════════════════════════════════════════════════════════════
_TECHNIQUE_NAMES: Optional[Dict[str, str]] = None
_ATTACK_TACTICS: Optional[Dict[str, str]] = None
_ATTACK_TACTIC_ORDER: List[str] = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]
_SIGNATURE_INDEX: Optional[Dict[str, List[str]]] = None
_SIGNATURE_PATTERNS: Optional[List[Tuple[re.Pattern, List[str]]]] = None


def _build_signature_index() -> Dict[str, List[str]]:
    index: Dict[str, List[str]] = {}
    for cve in CVE_DATABASE:
        for sig in cve.get("signatures", []):
            try:
                re.compile(sig, re.IGNORECASE)
            except re.error:
                logger.warning(f"Invalid signature regex in {cve['id']}: {sig!r}")
                continue
            index.setdefault(sig, []).append(cve["id"])
    return index


def _ensure_derived():
    """Build TECHNIQUE_NAMES, ATTACK_TACTICS, SIGNATURE_INDEX lazily on first use.
    Caches results on the module dict so __getattr__ is bypassed on subsequent lookups.
    """
    global _TECHNIQUE_NAMES, _ATTACK_TACTICS, _SIGNATURE_INDEX, _SIGNATURE_PATTERNS
    if _TECHNIQUE_NAMES is None:
        _TECHNIQUE_NAMES = {tid: meta["name"] for tid, meta in ATTACK_TECHNIQUES.items()}
    if _ATTACK_TACTICS is None:
        _ATTACK_TACTICS = {tid: meta["tactic"] for tid, meta in ATTACK_TECHNIQUES.items()}
    if _SIGNATURE_INDEX is None:
        _SIGNATURE_INDEX = _build_signature_index()
    if _SIGNATURE_PATTERNS is None:
        _SIGNATURE_PATTERNS = [
            (re.compile(sig, re.IGNORECASE), ids)
            for sig, ids in _SIGNATURE_INDEX.items()
        ]
    # Cache on module dict so __getattr__ is bypassed on subsequent lookups
    g = globals()
    g["TECHNIQUE_NAMES"] = _TECHNIQUE_NAMES
    g["ATTACK_TACTICS"] = _ATTACK_TACTICS
    g["ATTACK_TACTIC_ORDER"] = _ATTACK_TACTIC_ORDER
    g["SIGNATURE_INDEX"] = _SIGNATURE_INDEX
    g["SIGNATURE_PATTERNS"] = _SIGNATURE_PATTERNS


# Module-level __getattr__ enables lazy access: TECHNIQUE_NAMES, ATTACK_TACTICS,
# SIGNATURE_INDEX, SIGNATURE_PATTERNS are computed on first attribute lookup.
def __getattr__(name: str):
    if name in ("TECHNIQUE_NAMES", "ATTACK_TACTICS", "ATTACK_TACTIC_ORDER",
                "SIGNATURE_INDEX", "SIGNATURE_PATTERNS"):
        _ensure_derived()
        return {
            "TECHNIQUE_NAMES": _TECHNIQUE_NAMES,
            "ATTACK_TACTICS": _ATTACK_TACTICS,
            "ATTACK_TACTIC_ORDER": _ATTACK_TACTIC_ORDER,
            "SIGNATURE_INDEX": _SIGNATURE_INDEX,
            "SIGNATURE_PATTERNS": _SIGNATURE_PATTERNS,
        }[name]
    raise AttributeError(f"module 'core.knowledge_base' has no attribute {name!r}")


class KnowledgeBase:
    """
    Offline cybersecurity knowledge base with fast retrieval.

    - Exact lookup: lookup_cve / lookup_technique (O(1) dict).
    - Similarity search: TF-IDF cosine (mirrors VectorMemory) when
      scikit-learn is available; keyword fallback otherwise.
    - Signature grounding: signature_match() maps raw tool output / banners
      to CVEs via compiled regexes.
    - ground_findings(): attaches cves/techniques/remediation to findings so
      the LLM can ground exploit suggestions and remediation steps.
    - get_context_block(): sanitized, LLM-ready text block.

    NOTE: _load_external() only runs at init time (external data_path is
    merged once). A future runtime reload must re-run _build_index() and
    refresh the _external_loaded/_external_error flags under self._lock.
    """

    def __init__(self, data_path: Optional[str] = None):
        self._lock = threading.Lock()
        self._cves: Dict[str, Dict[str, Any]] = {c["id"]: dict(c)
                                                 for c in CVE_DATABASE}
        self._techniques: Dict[str, Dict[str, str]] = {
            tid: dict(t) for tid, t in ATTACK_TECHNIQUES.items()}
        self._vectorizer = None
        self._vectors = None
        self._corpus_keys: List[str] = []  # parallel to vector rows
        self._corpus_meta: Dict[str, Dict[str, Any]] = {}  # key -> {type,id}
        self._external_loaded = False
        self._external_error: Optional[str] = None
        # Optional external JSON extension (user-curated, air-gapped):
        # {"cves": [...], "techniques": {...}} merged over embedded data.
        if data_path and os.path.isfile(data_path):
            self._load_external(data_path)
        self._build_index()  # ALWAYS build — even if the external load failed
        if not self._external_loaded:
            self._external_error = (self._external_error or
                                    ("data_path not found: " + data_path
                                     if data_path else "no data_path configured"))

    # ── Indexing ──
    def _load_external(self, data_path: str) -> None:
        try:
            with open(data_path) as f:
                data = json.load(f)
            with self._lock:  # guard index-writer state against readers
                for cve in data.get("cves", []) or []:
                    if cve.get("id"):
                        self._cves[cve["id"]] = cve
                for tid, meta in (data.get("techniques", {}) or {}).items():
                    if isinstance(meta, dict):
                        self._techniques[tid] = meta
            self._external_loaded = True
            self._external_error = None
            logger.info(f"KnowledgeBase extended from {data_path}: "
                        f"{len(data.get('cves', []))} cves, "
                        f"{len(data.get('techniques', {}))} techniques")
        except Exception as e:
            self._external_loaded = False
            self._external_error = str(e)
            logger.error(f"Failed to load knowledge base extension {data_path}: {e}")

    def _build_index(self) -> None:
        """Build the TF-IDF retrieval index over CVE + technique text.
        Entire rebuild runs under the lock so readers never observe a
        half-populated index (corpus_meta/vectors updated atomically).
        """
        with self._lock:
            self._corpus_keys = []
            self._corpus_meta = {}
            texts = []
            for cve_id, cve in self._cves.items():
                text = " ".join([
                    cve_id, cve.get("title", ""), cve.get("description", ""),
                    cve.get("affected", ""), " ".join(cve.get("signatures", [])),
                ])
                key = f"cve:{cve_id}"
                texts.append(text)
                self._corpus_keys.append(key)
                self._corpus_meta[key] = {"type": "cve", "id": cve_id}
            for tid, tech in self._techniques.items():
                text = " ".join([
                    tid, tech.get("name", ""), tech.get("tactic", ""),
                    tech.get("detection", ""), tech.get("mitigation", ""),
                ])
                key = f"tech:{tid}"
                texts.append(text)
                self._corpus_keys.append(key)
                self._corpus_meta[key] = {"type": "technique", "id": tid}
            _ensure_sklearn()
            if _HAS_SKLEARN and texts:
                try:
                    self._vectorizer = _TfidfVectorizer(
                        lowercase=True, stop_words="english", max_features=5000,
                        ngram_range=(1, 2))
                    self._vectors = self._vectorizer.fit_transform(texts)
                except Exception as e:
                    logger.warning(f"TF-IDF index build failed (keyword fallback): {e}")
                    self._vectorizer = None
                    self._vectors = None
            else:
                self._vectorizer = None
                self._vectors = None

    # ── Lookups ──
    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Exact CVE lookup by ID (case-insensitive)."""
        if not cve_id:
            return None
        cve_id = cve_id.strip().upper()
        cve = self._cves.get(cve_id)
        if not cve:
            # Try alternate formats (CVE-2017-0144 vs 2017-0144)
            for cid, c in self._cves.items():
                if cid.endswith(cve_id) or cve_id.endswith(cid):
                    return dict(c)
            return None
        return dict(cve)

    def lookup_technique(self, tech_id: str) -> Optional[Dict[str, str]]:
        """Exact ATT&CK technique lookup by ID (e.g. T1190)."""
        if not tech_id:
            return None
        tech_id = tech_id.strip().upper()
        tech = self._techniques.get(tech_id)
        return dict(tech) if tech else None

    _CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
    _TECH_RE = re.compile(r"T\d{4}(\.\d{3})?", re.I)

    def search(self, query: str, top_k: int = 5,
               category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Semantic search over CVEs + techniques. Returns entries ranked by
        similarity: [{type, id, title, score, ...}]. Falls back to keyword
        scoring when scikit-learn is unavailable.

        Exact CVE/ATT&CK identifiers embedded in the query are boosted to the
        top of the ranking (an exact ID is always the right answer).
        """
        query = (query or "").strip()
        if not query:
            return []
        top_k = max(1, min(int(top_k), 25))
        results = []
        # Exact-ID boost: "CVE-2021-44228" / "T1059.001" in the query must
        # surface the exact record first, regardless of TF-IDF noise.
        exact_seen = set()
        for m in self._CVE_RE.findall(query):
            entry = self._entry_dict("cve", m.upper())
            if entry and (not category or category == "cve") and entry["id"] not in exact_seen:
                entry["score"] = 1.0
                exact_seen.add(entry["id"])
                results.append(entry)
        for m in self._TECH_RE.findall(query):
            entry = self._entry_dict("technique", m.upper())
            if entry and (not category or category == "technique") and entry["id"] not in exact_seen:
                entry["score"] = 1.0
                exact_seen.add(entry["id"])
                results.append(entry)
        _ensure_sklearn()
        if _HAS_SKLEARN and self._vectorizer is not None and self._vectors is not None:
            try:
                qvec = self._vectorizer.transform([query])
                sims = cosine_similarity(qvec, self._vectors).flatten()
                order = sims.argsort()[::-1]
                for i in order:
                    if sims[i] < SIMILARITY_THRESHOLD:
                        break
                    key = self._corpus_keys[i]
                    meta = self._corpus_meta[key]
                    if category and meta["type"] != category:
                        continue
                    entry = self._entry_dict(meta["type"], meta["id"])
                    if not entry or entry["id"] in exact_seen:
                        continue
                    entry["score"] = round(float(sims[i]), 4)
                    results.append(entry)
                    if len(results) >= top_k:
                        break
            except Exception as e:
                logger.warning(f"KB similarity search failed: {e}")
        if not results:
            results = self._keyword_search(query, top_k, category)
        return results[:top_k]

    def _keyword_search(self, query: str, top_k: int,
                        category: Optional[str]) -> List[Dict[str, Any]]:
        """Simple token-overlap keyword scoring fallback (offline, no deps)."""
        q_tokens = set(re.findall(r"[a-z0-9]+", query.lower()))
        if not q_tokens:
            return []
        scored = []
        for key, meta in self._corpus_meta.items():
            if category and meta["type"] != category:
                continue
            entry = self._entry_dict(meta["type"], meta["id"])
            if not entry:
                continue
            hay = " ".join([
                entry.get("title", ""), entry.get("description", ""),
                entry.get("affected", ""),
                " ".join(str(s) for s in entry.get("signatures", [])),
            ]).lower()
            hits = sum(1 for t in q_tokens if t in hay)
            if hits:
                scored.append((hits / max(1, len(q_tokens)), entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for s, e in scored[:top_k]]

    def _entry_dict(self, etype: str, eid: str) -> Optional[Dict[str, Any]]:
        if etype == "cve":
            cve = self.lookup_cve(eid)
            if cve:
                return {"type": "cve", "id": cve["id"], "title": cve["title"],
                        "cvss": cve.get("cvss", 0), "severity": cve.get("severity", ""),
                        "description": cve.get("description", ""),
                        "affected": cve.get("affected", ""),
                        "techniques": cve.get("techniques", []),
                        "signatures": cve.get("signatures", []),
                        "remediation": cve.get("remediation", []),
                        "commands": cve.get("commands", [])}
        tech = self.lookup_technique(eid)
        if tech:
            return {"type": "technique", "id": eid, "title": tech.get("name", ""),
                    "tactic": tech.get("tactic", ""),
                    "detection": tech.get("detection", ""),
                    "mitigation": tech.get("mitigation", "")}
        return None

    # ── Signature grounding ──
    def signature_match(self, text: str,
                        top_k: int = 8) -> List[Dict[str, Any]]:
        """
        Scan raw tool output / banners / finding evidence for known exploit
        signatures and return matching CVEs (severity-sorted).
        """
        if not text:
            return []
        matches = []
        for pattern, cve_ids in SIGNATURE_PATTERNS:
            if pattern.search(str(text)):
                for cve_id in cve_ids:
                    cve = self.lookup_cve(cve_id)
                    if cve and cve not in matches:
                        matches.append(cve)
        sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        matches.sort(key=lambda c: sev.get(c.get("severity", "info"), 9))
        return matches[:top_k]

    # ── Finding grounding ──
    def ground_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Attach knowledge-base context to each finding:
          - kb_cves: matched CVEs (via signature_match on title/evidence)
          - kb_techniques: ATT&CK techniques referenced by the finding or
            its matched CVEs
          - kb_remediation: deduped remediation steps + commands
        Returns a NEW list; input findings are not mutated.
        """
        grounded = []
        for f in findings or []:
            f2 = dict(f)
            blob = " ".join(str(f2.get(k, "")) for k in
                            ("title", "description", "evidence", "raw_output",
                             "stdout_preview"))
            cves = self.signature_match(blob, top_k=5)
            f2["kb_cves"] = [{"id": c["id"], "title": c["title"],
                              "severity": c.get("severity", ""),
                              "cvss": c.get("cvss", 0)} for c in cves]
            # Techniques: from finding + matched CVEs
            tech_ids = set()
            for t in (f2.get("attack_techniques") or []):
                if isinstance(t, dict) and t.get("id"):
                    tech_ids.add(t["id"])
            for c in cves:
                tech_ids.update(c.get("techniques", []))
            f2["kb_techniques"] = [
                {"id": tid, "name": self._techniques.get(tid, {}).get("name", ""),
                 "tactic": self._techniques.get(tid, {}).get("tactic", "")}
                for tid in sorted(tech_ids)]
            # Remediation (deduped)
            seen = set()
            remediation, commands = [], []
            for c in cves:
                for step in c.get("remediation", []):
                    if step not in seen:
                        seen.add(step)
                        remediation.append(step)
                for cmd in c.get("commands", []):
                    if cmd not in commands:
                        commands.append(cmd)
            f2["kb_remediation"] = {"steps": remediation, "commands": commands}
            f2["kb_grounded"] = bool(cves or tech_ids)
            grounded.append(f2)
        return grounded

    def remediation_for(self, cve_id: str) -> Dict[str, Any]:
        """Full remediation playbook for a CVE: steps + commands + severity."""
        cve = self.lookup_cve(cve_id)
        if not cve:
            return {"cve_id": cve_id, "found": False, "steps": [], "commands": []}
        return {"cve_id": cve["id"], "title": cve["title"], "found": True,
                "severity": cve.get("severity", ""), "cvss": cve.get("cvss", 0),
                "steps": cve.get("remediation", []),
                "commands": cve.get("commands", []),
                "techniques": cve.get("techniques", [])}

    # ── LLM context ──
    def get_context_block(self, query: str = "", findings: Optional[List[dict]] = None,
                          max_chars: int = CONTEXT_MAX_CHARS,
                          max_entries: int = CONTEXT_MAX_ENTRIES) -> str:
        """
        Build a sanitized, LLM-ready grounding block. Pulls the most relevant
        CVE + technique entries for the query/findings and renders them as a
        compact knowledge block. All content is passed through
        sanitize_for_llm (defense-in-depth against injection via findings).
        """
        parts = []
        # 1. Signature-grounded CVEs from findings
        cve_ids = set()
        for f in (findings or []):
            blob = " ".join(str(f.get(k, "")) for k in
                            ("title", "description", "evidence", "raw_output"))
            for c in self.signature_match(blob, top_k=3):
                cve_ids.add(c["id"])
        # 2. Semantic matches for the query
        if query:
            for e in self.search(query, top_k=max_entries, category="cve"):
                cve_ids.add(e["id"])
        for cve_id in sorted(cve_ids):
            cve = self.lookup_cve(cve_id)
            if not cve:
                continue
            parts.append(
                f"[CVE] {cve['id']} ({cve.get('severity', '').upper()}, "
                f"CVSS {cve.get('cvss', 0)}): {cve.get('title', '')} — "
                f"{cve.get('description', '')[:200]} "
                f"Remediation: {'; '.join(cve.get('remediation', [])[:3])}")
            if len(parts) >= max_entries:
                break
        # 3. Techniques (from matched CVEs + explicit finding techniques)
        tech_ids = set()
        for cve_id in list(cve_ids):
            cve = self.lookup_cve(cve_id)
            if cve:
                tech_ids.update(cve.get("techniques", []))
        for f in (findings or []):
            for t in (f.get("attack_techniques") or []):
                if isinstance(t, dict) and t.get("id"):
                    tech_ids.add(t["id"])
        for tid in sorted(tech_ids):
            tech = self.lookup_technique(tid)
            if tech:
                parts.append(
                    f"[ATT&CK] {tid} {tech.get('name', '')} "
                    f"({tech.get('tactic', '')}) — detection: "
                    f"{tech.get('detection', '')[:160]} | mitigation: "
                    f"{tech.get('mitigation', '')[:160]}")
        if not parts:
            return ""
        block = "\n".join(parts)
        if len(block) > max_chars:
            block = block[:max_chars] + "\n…(truncated)"
        return sanitize_for_llm(block, max_len=len(block) + 8)

    # ── Stats ──
    def get_stats(self) -> Dict[str, Any]:
        """Knowledge base statistics for the dashboard / status endpoint."""
        _ensure_derived()
        return {
            "cves": len(self._cves),
            "techniques": len(self._techniques),
            "signatures": len(_SIGNATURE_INDEX),
            "index_ready": self._vectorizer is not None,
            "corpus_entries": len(self._corpus_keys),
            "severity_counts": self._severity_counts(),
            "external_loaded": self._external_loaded,
            "external_error": self._external_error,
        }

    def _severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for cve in self._cves.values():
            sev = (cve.get("severity") or "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts
