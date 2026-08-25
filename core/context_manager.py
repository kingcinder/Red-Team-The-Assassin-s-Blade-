"""
RedTeam Harness — Context Window Manager (v4.0 Phase 3)
Token-aware sliding window that prevents context bloat on long engagements.

Strategy:
  1. Keep a persistent FACTS section (findings, recon data, credentials found)
     that always stays in context — never trimmed.
  2. Full message history is retained on disk; only the LLM-facing window slides.
  3. Old tool outputs are compressed to one-line summaries via regex extraction.
  4. System prompt + few-shots are always prefix-locked.
  5. Configurable budget in tokens, estimated via char/4 heuristic.
"""
import re
import logging
from typing import Dict, List, Any

logger = logging.getLogger("redteam.context")

# Conservative estimate: 1 token ≈ 4 characters (works for English text).
CHARS_PER_TOKEN = 4
# Reserve this many tokens for the LLM's response.
RESPONSE_BUDGET_TOKENS = 2048
# Minimum messages to keep (system prompt + first user + few-shots).
MIN_PREFIX_MESSAGES = 5


class ContextManager:
    """Manages the LLM context window to stay within budget."""

    def __init__(self, max_tokens: int = 32768):
        self.max_tokens = max_tokens
        self.facts: Dict[str, str] = {}   # persistent fact store
        self._trim_count = 0
        self._total_trimmed = 0

    def add_fact(self, key: str, value: str):
        """Store a persistent fact (overwrites if key exists)."""
        self.facts[key] = value

    def add_facts(self, items: Dict[str, str]):
        """Bulk-add facts."""
        self.facts.update(items)

    def get_facts_block(self) -> str:
        """Render the persistent facts block for system injection."""
        if not self.facts:
            return ""
        lines = ["## Persistent Facts (discovered so far)"]
        for k, v in self.facts.items():
            lines.append(f"- **{k}**: {v[:200]}")
        return "\n".join(lines)

    def trim(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Trim messages to fit within the token budget.
        Preserves: prefix (system + few-shots), most recent messages,
        and injects the facts block into the system message.

        Returns a NEW list (does not mutate input).
        """
        if not messages:
            return messages

        available = self.max_tokens - RESPONSE_BUDGET_TOKENS
        prefix_count = min(MIN_PREFIX_MESSAGES, len(messages))

        # ══ Always keep prefix (system + few-shots) + last N messages ══
        prefix = list(messages[:prefix_count])
        suffix = list(messages[prefix_count:])

        # Inject facts block into the first system message
        facts_block = self.get_facts_block()
        if facts_block and prefix:
            for i, msg in enumerate(prefix):
                if msg["role"] == "system":
                    content = msg["content"]
                    if "## Persistent Facts" not in content:
                        prefix[i] = {
                            "role": "system",
                            "content": content + "\n\n" + facts_block,
                        }
                    break

        # Estimate tokens for prefix
        prefix_tokens = sum(len(m.get("content", "")) // CHARS_PER_TOKEN for m in prefix)

        # ══ Build suffix from newest → oldest, compressing old tool outputs ══
        kept_suffix = []
        suffix_tokens = 0
        budget = available - prefix_tokens

        for msg in reversed(suffix):
            content = msg.get("content", "")
            original_tokens = len(content) // CHARS_PER_TOKEN

            if msg["role"] == "tool_result" and original_tokens > 200:
                # Compress old tool outputs
                compressed = self._compress_tool_output(content)
                msg = {"role": "tool_result", "content": compressed}
                content = compressed

            est_tokens = len(content) // CHARS_PER_TOKEN
            if suffix_tokens + est_tokens > budget:
                # We're over budget — keep trying with more compression
                if len(kept_suffix) < 3:
                    # We must keep at least some recent messages
                    msg_short = {"role": msg["role"],
                                 "content": content[:budget // CHARS_PER_TOKEN]}
                    kept_suffix.append(msg_short)
                self._total_trimmed += 1
                break

            kept_suffix.append(msg)
            suffix_tokens += est_tokens

        kept_suffix.reverse()
        result = prefix + kept_suffix
        self._trim_count += 1

        total_tokens = sum(len(m.get("content", "")) // CHARS_PER_TOKEN for m in result)
        logger.info(f"Context trim: {len(messages)} → {len(result)} messages "
                    f"(~{total_tokens} tokens / {self.max_tokens} budget)")

        return result

    def _compress_tool_output(self, content: str) -> str:
        """
        Compress a tool output to key facts: hosts, ports, versions, vulns.
        Returns a short summary string.
        """
        if len(content) <= 500:
            return content

        parts = []
        # Hosts/IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
        if ips:
            parts.append(f"Hosts: {', '.join(sorted(set(ips))[:10])}")

        # Open ports
        ports = re.findall(r'(?:port\s*)?(\d{1,5})/(?:tcp|udp)\s+open', content)
        if ports:
            parts.append(f"Open: {', '.join(sorted(set(ports))[:20])}")

        # Service versions
        versions = re.findall(r'(?:Apache|nginx|OpenSSH|vsftpd|ProFTPD|Postfix|'
                              r'Exim|Sendmail|MySQL|MariaDB|PostgreSQL|MongoDB|'
                              r'Redis|Elasticsearch|Tomcat|Jetty|IIS|Node\.js|'
                              r'Express|Django|Flask|Rails|Laravel|WordPress|'
                              r'Drupal|Joomla)[/\s]*[\d.]+', content, re.IGNORECASE)
        if versions:
            parts.append(f"Services: {', '.join(sorted(set(versions))[:10])}")

        # Vulnerabilities (CVE, findings)
        cves = re.findall(r'CVE-\d{4}-\d{4,}', content)
        if cves:
            parts.append(f"CVEs: {', '.join(sorted(set(cves))[:8])}")

        # Credentials
        creds = re.findall(r'(?:password|passwd|pwd|secret|token|key|credential)s?\s*[:=]\s*\S+',
                           content, re.IGNORECASE)
        if creds:
            parts.append(f"Credentials found: {len(creds)}")

        summary = "; ".join(parts) if parts else content[:500]
        return f"[Compressed] {summary}"

    def get_stats(self) -> Dict[str, Any]:
        """Return context window statistics."""
        return {
            "max_tokens": self.max_tokens,
            "facts_count": len(self.facts),
            "trim_count": self._trim_count,
            "total_messages_trimmed": self._total_trimmed,
        }