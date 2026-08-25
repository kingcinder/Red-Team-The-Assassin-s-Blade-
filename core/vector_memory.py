"""
RedTeam Harness — Vector Memory / RAG (v4.1)
Persists findings across sessions so the LLM remembers what it found before.

When you come back to a target, the LLM automatically retrieves relevant
past findings and injects them into context — no re-scanning needed.

Architecture:
  - TF-IDF vectorization via scikit-learn (already installed)
  - Cosine similarity for retrieval
  - numpy arrays for vector storage (already installed)
  - JSON index for metadata (finding ID, target, session, severity, etc.)
  - Fully offline — no external vector DB required

Usage:
    memory = VectorMemory("./sessions")
    memory.ingest(finding, session_id="engage_20260825_120000_abc123")
    results = memory.query("192.168.1.10", top_k=10)
    context = memory.get_context_block("192.168.1.10")  # for LLM injection
"""
import json
import os
import logging
import threading
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger("redteam.memory")

# ── Constants ──
MAX_VECTORS = 10000       # Max findings to keep in memory
SIMILARITY_THRESHOLD = 0.15  # Minimum cosine similarity for retrieval
CONTEXT_MAX_FINDINGS = 15  # Max findings to inject into LLM context
CONTEXT_MAX_CHARS = 4000   # Max characters for context block


class VectorMemory:
    """
    RAG-style vector memory for cross-session finding persistence.

    Stores findings as TF-IDF vectors and retrieves them by similarity
    to a query (target IP, finding text, etc.).
    """

    def __init__(self, data_dir: str = "./sessions"):
        self._data_dir = data_dir
        self._memory_dir = os.path.join(data_dir, "vector_memory")
        os.makedirs(self._memory_dir, exist_ok=True)

        self._index_file = os.path.join(self._memory_dir, "index.json")
        self._vectors_file = os.path.join(self._memory_dir, "vectors.npy")

        self._lock = threading.Lock()
        self._findings: List[Dict[str, Any]] = []   # metadata index
        self._vectors: Optional[np.ndarray] = None   # TF-IDF matrix (n_findings × vocab)
        self._vectorizer: Optional[TfidfVectorizer] = None
        self._fitted = False

        self._load()

    # ═══════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════

    def ingest(self, finding: Dict[str, Any], session_id: str = "") -> str:
        """
        Add a finding to the vector memory.

        Args:
            finding: Finding dict with at least 'title', 'evidence', 'severity'
            session_id: Session this finding came from

        Returns:
            Finding ID (dedupe key)
        """
        # Build searchable text
        text = self._finding_to_text(finding)

        # Generate deterministic ID
        finding_id = self._generate_id(finding, session_id)

        metadata = {
            "id": finding_id,
            "title": finding.get("title", "Unknown"),
            "severity": finding.get("severity", "info"),
            "category": finding.get("category", "unknown"),
            "evidence": finding.get("evidence", "")[:300],
            "dedupe_key": finding.get("dedupe_key", ""),
            "source_tool": finding.get("source_tool", ""),
            "source_step": finding.get("source_step", ""),
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "targets": self._extract_targets(finding),
            "text": text,
        }

        with self._lock:
            # Dedupe: if same finding ID exists, update timestamp
            existing_idx = None
            for i, f in enumerate(self._findings):
                if f["id"] == finding_id:
                    existing_idx = i
                    break

            if existing_idx is not None:
                self._findings[existing_idx]["timestamp"] = metadata["timestamp"]
                self._findings[existing_idx]["session_id"] = session_id
                logger.debug(f"Updated existing finding: {finding_id}")
                self._rebuild_vectors()
                return finding_id

            self._findings.append(metadata)
            logger.debug(f"Ingested finding: {finding_id} ({metadata['severity']})")

            # Cap at MAX_VECTORS
            if len(self._findings) > MAX_VECTORS:
                self._findings = self._findings[-MAX_VECTORS:]
                self._rebuild_vectors()
            else:
                self._append_vector(text)

            # Persist periodically
            if len(self._findings) % 10 == 0:
                self._save()

        return finding_id

    def ingest_batch(self, findings: List[Dict[str, Any]], session_id: str = "") -> int:
        """Ingest multiple findings at once. Returns count ingested."""
        count = 0
        for f in findings:
            self.ingest(f, session_id)
            count += 1
        return count

    def query(self, query_text: str, top_k: int = 10,
              min_similarity: float = SIMILARITY_THRESHOLD,
              target_filter: str = "",
              severity_filter: str = "") -> List[Dict[str, Any]]:
        """
        Retrieve findings most similar to the query text.

        Args:
            query_text: Search query (target IP, finding description, etc.)
            top_k: Max results
            min_similarity: Minimum cosine similarity threshold
            target_filter: Only return findings with this target
            severity_filter: Only return findings with this severity

        Returns:
            List of finding dicts with added 'similarity' score
        """
        with self._lock:
            if not self._fitted or self._vectors is None or len(self._findings) == 0:
                return []

            # Vectorize the query
            try:
                query_vec = self._vectorizer.transform([query_text])
            except Exception as e:
                logger.warning(f"Query vectorization failed: {e}")
                return []

            # Compute cosine similarity
            sims = cosine_similarity(query_vec, self._vectors).flatten()

            # Build result list
            results = []
            for i, sim in enumerate(sims):
                if sim < min_similarity:
                    continue
                if i >= len(self._findings):
                    break

                finding = self._findings[i]

                # Apply filters
                if target_filter and target_filter not in finding.get("targets", []):
                    # Also check evidence for IP/domain matches
                    if target_filter not in finding.get("evidence", ""):
                        continue
                if severity_filter and finding.get("severity") != severity_filter:
                    continue

                result = dict(finding)
                result["similarity"] = round(float(sim), 4)
                results.append(result)

            # Sort by similarity descending
            results.sort(key=lambda x: x["similarity"], reverse=True)
            return results[:top_k]

    def query_by_target(self, target: str, top_k: int = 15) -> List[Dict[str, Any]]:
        """
        Retrieve all past findings for a specific target.
        Combines direct target matching with semantic similarity.
        """
        # First: direct text match (target IP in evidence/targets)
        direct_matches = []
        with self._lock:
            for f in self._findings:
                if target in f.get("targets", []) or target in f.get("evidence", ""):
                    direct_matches.append(dict(f))

        # Second: semantic similarity query
        sim_results = self.query(target, top_k=top_k)

        # Merge, dedup by finding ID
        seen_ids = set()
        merged = []
        for f in direct_matches:
            fid = f.get("id", "")
            if fid not in seen_ids:
                seen_ids.add(fid)
                f["match_type"] = "direct"
                merged.append(f)

        for f in sim_results:
            fid = f.get("id", "")
            if fid not in seen_ids:
                seen_ids.add(fid)
                f["match_type"] = "semantic"
                merged.append(f)

        return merged[:top_k]

    def get_context_block(self, target: str = "", max_findings: int = CONTEXT_MAX_FINDINGS) -> str:
        """
        Build a context block for injection into the LLM system prompt.
        Shows relevant past findings for the current target.

        Returns a formatted string ready to append to the system prompt.
        """
        if not target:
            return ""

        findings = self.query_by_target(target, top_k=max_findings * 2)

        if not findings:
            return ""

        # Dedupe and take top findings
        seen_keys = set()
        unique = []
        for f in findings:
            dk = f.get("dedupe_key") or f.get("title", "")
            if dk not in seen_keys:
                seen_keys.add(dk)
                unique.append(f)
        unique = unique[:max_findings]

        if not unique:
            return ""

        # Build context block
        parts = [
            f"\n## Prior Findings for {target} (from previous sessions)",
            f"_{len(unique)} findings retrieved from vector memory:_\n",
        ]

        severity_emoji = {
            "critical": "🔴", "high": "🟠",
            "medium": "🟡", "low": "🔵", "info": "⚪"
        }

        for i, f in enumerate(unique, 1):
            sev = f.get("severity", "info")
            emoji = severity_emoji.get(sev, "⚪")
            tool = f.get("source_tool", "?")
            sim = f.get("similarity", 0)
            match_type = f.get("match_type", "semantic")

            line = f"{i}. {emoji} **[{sev.upper()}]** {f.get('title', 'Unknown')}"
            line += f" — tool: `{tool}`"
            if sim > 0:
                line += f" (similarity: {sim:.2f})"
            parts.append(line)

            # Add evidence snippet (truncated)
            evidence = f.get("evidence", "")
            if evidence:
                parts.append(f"   Evidence: `{evidence[:120]}`")

        # Truncate to avoid bloat
        block = "\n".join(parts)
        if len(block) > CONTEXT_MAX_CHARS:
            block = block[:CONTEXT_MAX_CHARS] + "\n   [... truncated]"

        return block

    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        with self._lock:
            severity_counts = {}
            tool_counts = {}
            session_set = set()
            for f in self._findings:
                sev = f.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                tool = f.get("source_tool", "unknown")
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
                session_set.add(f.get("session_id", ""))

            return {
                "total_findings": len(self._findings),
                "unique_sessions": len(session_set),
                "severity_counts": severity_counts,
                "top_tools": sorted(tool_counts.items(), key=lambda x: -x[1])[:10],
                "fitted": self._fitted,
                "vocab_size": len(self._vectorizer.vocabulary_) if self._fitted and hasattr(self._vectorizer, 'vocabulary_') else 0,
            }

    def list_targets(self) -> List[Dict[str, Any]]:
        """List all targets with finding counts."""
        with self._lock:
            target_map: Dict[str, Dict] = {}
            for f in self._findings:
                for t in f.get("targets", []):
                    if t not in target_map:
                        target_map[t] = {"target": t, "count": 0, "severities": {}}
                    target_map[t]["count"] += 1
                    sev = f.get("severity", "info")
                    target_map[t]["severities"][sev] = target_map[t]["severities"].get(sev, 0) + 1
            return sorted(target_map.values(), key=lambda x: -x["count"])

    def reset(self) -> None:
        """Clear all stored findings."""
        with self._lock:
            self._findings = []
            self._vectors = None
            self._vectorizer = None
            self._fitted = False
            self._save()
            logger.info("Vector memory reset")

    def save(self) -> None:
        """Public save — call on shutdown."""
        with self._lock:
            self._save()

    # ═══════════════════════════════════════════════════════════════
    # INTERNALS
    # ═══════════════════════════════════════════════════════════════

    def _finding_to_text(self, finding: Dict[str, Any]) -> str:
        """Convert a finding to searchable text for TF-IDF."""
        parts = [
            str(finding.get("title", "")),
            str(finding.get("evidence", "")),
            str(finding.get("dedupe_key", "")),
            str(finding.get("category", "")),
            str(finding.get("source_tool", "")),
            " ".join(finding.get("targets", [])),
        ]
        return " ".join(p for p in parts if p)

    def _generate_id(self, finding: Dict[str, Any], session_id: str) -> str:
        """Generate a deterministic ID for deduplication."""
        # Use dedupe_key if available, otherwise hash the finding content
        dk = finding.get("dedupe_key", "")
        if dk:
            key_source = f"{dk}:{session_id}"
        else:
            key_source = f"{finding.get('title', '')}:{finding.get('evidence', '')[:100]}:{session_id}"
        return hashlib.sha256(key_source.encode()).hexdigest()[:16]

    def _extract_targets(self, finding: Dict[str, Any]) -> List[str]:
        """Extract target IPs/domains from a finding."""
        import re
        text = f"{finding.get('evidence', '')} {finding.get('dedupe_key', '')}"
        targets = set()
        # IPv4 addresses
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
            # Skip common non-target IPs
            if not ip.startswith(('0.', '127.', '255.')):
                targets.add(ip)
        # Domains
        for domain in re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text):
            # Skip common non-target domains
            if not any(x in domain for x in ['example.com', 'localhost', 'google.com']):
                targets.add(domain)
        return sorted(targets)

    def _rebuild_vectors(self) -> None:
        """Rebuild the TF-IDF index from scratch. Caller must hold self._lock."""
        texts = [self._finding_to_text(f) for f in self._findings]
        if not texts:
            self._vectors = None
            self._fitted = False
            return

        # max_df must be 1.0 when there's only 1 document (0.95 * 1 < min_df=1 crashes)
        n = len(texts)
        self._vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=1,
            max_df=1.0 if n <= 2 else 0.95,
            sublinear_tf=True,
        )
        try:
            self._vectors = self._vectorizer.fit_transform(texts).toarray()
            self._fitted = True
            vocab_size = len(self._vectorizer.vocabulary_) if hasattr(self._vectorizer, 'vocabulary_') else 0
            logger.debug(f"Rebuilt TF-IDF index: {n} documents, {vocab_size} features")
        except Exception as e:
            logger.error(f"Failed to rebuild TF-IDF index: {e}")
            self._fitted = False

    def _append_vector(self, text: str) -> None:
        """Append a single document to the TF-IDF index. Caller must hold self._lock."""
        if self._vectorizer is None:
            # First document — fit from scratch
            self._vectorizer = TfidfVectorizer(
                max_features=5000,
                stop_words='english',
                ngram_range=(1, 2),
                min_df=1,
                max_df=1.0,
                sublinear_tf=True,
            )
            try:
                self._vectors = self._vectorizer.fit_transform([text]).toarray()
                self._fitted = True
            except Exception as e:
                logger.error(f"Failed to fit TF-IDF: {e}")
                self._fitted = False
            return

        # Transform new document using existing vocabulary
        try:
            new_vec = self._vectorizer.transform([text]).toarray()
            if self._vectors is not None:
                self._vectors = np.vstack([self._vectors, new_vec])
            else:
                self._vectors = new_vec
        except Exception as e:
            # Vocabulary mismatch — rebuild from scratch
            logger.warning(f"TF-IDF append failed, rebuilding: {e}")
            self._rebuild_vectors()

    # ═══════════════════════════════════════════════════════════════
    # PERSISTENCE
    # ═══════════════════════════════════════════════════════════════

    def _save(self) -> None:
        """Persist index + vectors to disk. Caller must hold self._lock."""
        try:
            # Save metadata index
            with open(self._index_file, "w") as f:
                json.dump({
                    "version": "4.1",
                    "saved_at": datetime.now().isoformat(),
                    "count": len(self._findings),
                    "findings": self._findings,
                }, f, indent=2)

            # Save vectors
            if self._vectors is not None and self._fitted:
                np.save(self._vectors_file, self._vectors)
                # Also save the vectorizer vocabulary
                vocab_file = os.path.join(self._memory_dir, "vocab.json")
                with open(vocab_file, "w") as f:
                    json.dump({
                        "vocabulary": self._vectorizer.vocabulary_,
                        "max_features": self._vectorizer.max_features,
                        "ngram_range": list(self._vectorizer.ngram_range),
                        "sublinear_tf": self._vectorizer.sublinear_tf,
                    }, f)

            logger.debug(f"Saved vector memory: {len(self._findings)} findings")
        except Exception as e:
            logger.error(f"Failed to save vector memory: {e}")

    def _load(self) -> None:
        """Load index + vectors from disk. Caller must hold self._lock."""
        try:
            if not os.path.exists(self._index_file):
                logger.info("No existing vector memory found — starting fresh")
                return

            # Load metadata index
            with open(self._index_file) as f:
                data = json.load(f)

            if data.get("version") != "4.1":
                logger.warning(f"Vector memory version mismatch ({data.get('version')}), resetting")
                return

            self._findings = data.get("findings", [])
            logger.info(f"Loaded {len(self._findings)} findings from vector memory")

            # Load vectors if they exist
            if os.path.exists(self._vectors_file) and self._findings:
                self._vectors = np.load(self._vectors_file)

                # Load vocabulary
                vocab_file = os.path.join(self._memory_dir, "vocab.json")
                if os.path.exists(vocab_file):
                    with open(vocab_file) as f:
                        vocab_data = json.load(f)

                    self._vectorizer = TfidfVectorizer(
                        max_features=vocab_data.get("max_features", 5000),
                        ngram_range=tuple(vocab_data.get("ngram_range", [1, 2])),
                        sublinear_tf=vocab_data.get("sublinear_tf", True),
                    )
                    # Reconstruct vocabulary
                    self._vectorizer.vocabulary_ = vocab_data["vocabulary"]
                    self._vectorizer._validate_vocabulary()
                    self._fitted = True
                    logger.info(f"Loaded TF-IDF index: {self._vectors.shape[0]} vectors, "
                                f"{self._vectors.shape[1]} features")
                else:
                    # No vocab file — rebuild from scratch
                    logger.info("No vocab file — will rebuild TF-IDF index")
                    self._rebuild_vectors()
            else:
                # No vectors on disk — rebuild from loaded findings
                if self._findings:
                    logger.info("No vectors on disk — rebuilding from findings")
                    self._rebuild_vectors()

        except Exception as e:
            logger.warning(f"Failed to load vector memory: {e}")
            self._findings = []
            self._vectors = None
            self._fitted = False

    def __del__(self):
        """Safety net — persist on shutdown without lock (avoids deadlock)."""
        try:
            if hasattr(self, '_findings') and self._findings:
                # Raw write without acquiring lock during interpreter shutdown
                with open(self._index_file, "w") as f:
                    json.dump({
                        "version": "4.1",
                        "saved_at": datetime.now().isoformat(),
                        "count": len(self._findings),
                        "findings": self._findings,
                    }, f)
        except Exception:
            pass
