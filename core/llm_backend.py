"""
RedTeam Harness — LLM Backend Adapter
Communicates with llama-server (OpenAI-compatible) or Ollama API.

v2.0 Improvements:
  - GBNF/JSON Schema enforcement for structured output
  - Streaming responses (SSE chunks via generator)
  - Tool output summarization (compress bloat before context)
  - Token usage tracking
  - Prompt caching stabilization (KV-cache friendly prefixes)
"""
import json
import logging
import time
from typing import Dict, Any, List, Generator, Optional

import requests

from core.injection_defense import sanitize_tool_output

logger = logging.getLogger("redteam.llm")

# ── Maximum chars per tool output before summarization kicks in ──
MAX_TOOL_OUTPUT_CHARS = 3000
SUMMARY_MAX_TOKENS = 256


class LLMBackend:
    """Adapts LLM API calls to different backends (llama-server, Ollama)."""

    def __init__(self, config: dict):
        self.config = config
        self.backend = config.get("backend", "llama-server")

        if self.backend == "llama-server":
            self.host = config.get("llama-server", {}).get("host", "127.0.0.1")
            self.port = config.get("llama-server", {}).get("port", 8080)
            self.base_url = f"http://{self.host}:{self.port}"
        elif self.backend == "ollama":
            self.host = config.get("ollama", {}).get("host", "127.0.0.1")
            self.port = config.get("ollama", {}).get("port", 11434)
            self.base_url = f"http://{self.host}:{self.port}"
        else:
            raise ValueError(f"Unknown LLM backend: {self.backend}")

        self.model = config.get(self.backend, {}).get("model", "")
        # Generation / I/O knobs. All three are read from the backend's config
        # section (llm.llama-server.* / llm.ollama.*) so the whole backend can
        # be tuned from config.yaml; per-call kwargs still win at each site.
        self.max_tokens = config.get(self.backend, {}).get("max_tokens", 4096)
        self.temperature = config.get(self.backend, {}).get("temperature", 0.3)
        self.timeout = config.get(self.backend, {}).get("timeout", 120)
        # Reasoning effort for llama-server (OpenAI "reasoning_effort" param).
        # "none" disables <think> blocks — critical for agentic tool loops
        # where thinking models otherwise return empty content. Configurable
        # via llm.llama-server.reasoning_effort; per-call kwargs still win.
        self.reasoning_effort = config.get(self.backend, {}).get(
            "reasoning_effort", "none")
        self._connected = False
        self._loaded_model: Optional[str] = None
        self._token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        # JSON Schema for tool_call enforcement via GBNF grammar
        self._tool_call_schema = {
            "type": "object",
            "properties": {
                "tool_call": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "args": {"type": "object"},
                    },
                    "required": ["tool", "args"],
                }
            },
            "required": ["tool_call"],
        }

    # ═══════════════════════════════════════════════════════════════
    # Public API
    # ═══════════════════════════════════════════════════════════════

    def is_connected(self) -> bool:
        """Check if the LLM backend is reachable."""
        try:
            if self.backend == "llama-server":
                r = requests.get(f"{self.base_url}/v1/models", timeout=5)
                self._connected = r.status_code == 200
                # Cache the actually-loaded model on success so the cockpit can
                # show it without an extra round-trip.
                if self._connected:
                    self._detect_loaded_model(r)
            elif self.backend == "ollama":
                r = requests.get(f"{self.base_url}/api/tags", timeout=5)
                self._connected = r.status_code == 200
            return self._connected
        except Exception:
            self._connected = False
            return False

    def _detect_loaded_model(self, response: Any = None) -> None:
        """
        Resolve the model that is actually loaded in llama-server.

        Prefers the model advertised by /v1/models (the real loaded snapshot), then
        falls back to the configured model name, then to a generic label. This lets
        the cockpit auto-place "whatever LLM is loaded in llama-server" on startup.
        """
        advertised = None
        try:
            if response is not None and hasattr(response, "json"):
                data = response.json()
            else:
                data = requests.get(f"{self.base_url}/v1/models", timeout=5).json()
            ids = (data.get("data") or [])
            if ids:
                advertised = ids[0].get("id") or ids[0].get("model") or None
        except Exception:
            advertised = None
        self._loaded_model = advertised or (self.model or "llama-server")

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Send a chat completion request. Returns the full response as a string."""
        if self.backend == "llama-server":
            return self._chat_openai_compatible(messages, **kwargs)
        elif self.backend == "ollama":
            return self._chat_ollama(messages, **kwargs)
        else:
            raise ValueError(f"Unknown backend: {self.backend}")

    def chat_stream(self, messages: List[Dict[str, str]], **kwargs) -> Generator[str, None, None]:
        """
        Stream a chat completion. Yields content chunks as they arrive.
        Consumers should accumulate chunks themselves — the generator yields text, not a final value.
        """
        if self.backend == "llama-server":
            yield from self._chat_openai_stream(messages, **kwargs)
        else:
            # Ollama: fallback to non-streaming
            full = self._chat_ollama(messages, **kwargs)
            yield full

    def chat_structured(self, messages: List[Dict[str, str]], schema: dict = None,
                        **kwargs) -> str:
        """
        Chat with JSON schema enforcement (GBNF grammar on llama-server).
        Guarantees valid JSON output matching the provided schema.
        """
        if self.backend == "llama-server":
            return self._chat_openai_compatible(messages, response_format={
                "type": "json_schema",
                "json_schema": {"name": "response", "schema": schema or self._tool_call_schema},
            }, **kwargs)
        # Ollama fallback: use format=json
        return self._chat_ollama(messages, format="json", **kwargs)

    def summarize(self, text: str, context: str = "") -> str:
        """
        Summarize tool output to fit within context budget.
        Uses a lightweight prompt to extract: hosts, ports, vulnerabilities, credentials.

        NOTE: `text` is attacker-controlled tool output (a malicious service can
        plant prompt-injection payloads in its banner). It is sanitized via
        sanitize_tool_output() BEFORE being returned or embedded in the LLM
        prompt — on BOTH the short path (≤MAX_TOOL_OUTPUT_CHARS, returned raw)
        and the long path (embedded in the summarization prompt).

        Side effect of the sanitizer: newlines/whitespace are collapsed, so
        multi-line tool output (e.g. nmap) comes back as single-line text.
        Readability for the LLM is unaffected; the raw stdout remains available
        in tool_result['stdout'] for dashboards/transcripts.
        """
        # Sanitize attacker-controlled tool output first, capping at the same
        # 8000-char budget the summarization prompt used to slice to. This also
        # means the returned short-path text is injection-free.
        text = sanitize_tool_output(str(text), max_len=8000)

        if len(text) <= MAX_TOOL_OUTPUT_CHARS:
            return text

        prompt = (
            f"Summarize this {context} tool output concisely. "
            f"Extract: discovered hosts/IPs, open ports, service names & versions, "
            f"vulnerabilities found, credentials leaked, and any actionable findings. "
            f"Be brief — keep each bullet under 80 chars.\n\n"
            f"Output:\n{text}"
        )
        try:
            summary = self.chat([{"role": "user", "content": prompt}],
                                max_tokens=SUMMARY_MAX_TOKENS, temperature=0.1)
            return f"[Summarized {context} output]\n{summary.strip()}"
        except Exception:
            logger.warning("Summarization failed, returning truncated output")
            return text[:MAX_TOOL_OUTPUT_CHARS] + "\n[... truncated]"

    def get_usage(self) -> Dict[str, int]:
        """Get cumulative token usage."""
        return dict(self._token_usage)

    def get_loaded_model(self) -> str:
        """Return the model currently loaded in the backend (resolving on demand)."""
        if not getattr(self, "_loaded_model", None):
            self.is_connected()
        return getattr(self, "_loaded_model", self.model or self.backend)

    def get_status(self) -> Dict[str, Any]:
        """Get backend status info, including the model actually loaded."""
        connected = self.is_connected()
        return {
            "backend": self.backend,
            "host": self.host,
            "port": self.port,
            "connected": connected,
            "model": self.model,
            "loaded_model": getattr(self, "_loaded_model", None),
            "machine_url": self.base_url,
            "token_usage": dict(self._token_usage),
        }

    # ═══════════════════════════════════════════════════════════════
    # Internal: OpenAI-compatible (llama-server)
    # ═══════════════════════════════════════════════════════════════

    # ── llama-server (OpenAI-compat) message-shape rules ──
    #
    # llama-server is started with prefill_assistant enabled (the default),
    # which changes how it treats a request whose LAST message is an assistant
    # message:
    #   * TWO OR MORE trailing assistant messages → HTTP 400
    #     ("Cannot have 2 or more assistant messages at the end of the list.")
    #   * ONE trailing assistant message → the server AUTO-CONTINUES the
    #     assistant's previous text instead of issuing a fresh generation
    #     prompt (so a stored tool_call JSON would get garbage appended to it).
    #
    # The harness's engagement loop legitimately ends most turns with an
    # assistant message (the previous LLM response), and a single backend
    # error string stored as an assistant message can poison the whole
    # session into a permanent 400 loop. Normalize the outgoing list so
    # every request is well-formed for llama-server (and any OpenAI server):
    #   * collapse runs of consecutive assistant messages into one,
    #   * demote harness `[ERROR] ...` sentinel strings to system messages
    #     (they are engine status, not model speech),
    #   * ensure the list ends with a user message so the server always
    #     issues a fresh generation prompt rather than continuing a previous
    #     assistant message.
    def _format_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Map internal roles to OpenAI-compatible roles.
        Also strips <think>...</think> tags from stored messages to prevent
        token-budget waste on re-sent thinking blocks.
        """
        import re as _re
        formatted = []
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            # Strip thinking tags from any message to reclaim context budget
            if "<think>" in content:
                content = _re.sub(r'<think>.*?</think>', '', content, flags=_re.DOTALL).strip()
            if role == "tool_result":
                formatted.append({"role": "user", "content": content})
            elif role == "assistant" and isinstance(content, str) and content.startswith("[ERROR]"):
                # Backend error strings must never look like model speech —
                # consecutive assistant messages wedge llama-server (see above).
                formatted.append({"role": "system", "content": content})
            else:
                formatted.append({"role": role, "content": content})

        # Collapse consecutive assistant messages into a single message.
        collapsed = []
        for msg in formatted:
            if collapsed and collapsed[-1]["role"] == "assistant" and msg["role"] == "assistant":
                collapsed[-1]["content"] = collapsed[-1]["content"] + "\n" + msg["content"]
            else:
                collapsed.append(dict(msg))
        formatted = collapsed

        # Ensure the request does not END on a non-user message (llama-server
        # auto-continues a trailing assistant message; demoted error strings
        # leave a trailing system message). Always close with a user message so
        # the server issues a fresh generation prompt.
        if formatted and formatted[-1]["role"] != "user":
            formatted.append({
                "role": "user",
                "content": "[HARNESS] Continue the engagement. Analyze the latest results "
                            "and either output your next tool_call JSON or your findings.",
            })
        return formatted

    def _track_usage(self, data: dict):
        """Extract and accumulate token usage from API response."""
        usage = data.get("usage", {})
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            if key in usage:
                self._token_usage[key] = self._token_usage.get(key, 0) + usage[key]

    def _chat_openai_compatible(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Chat via llama-server's OpenAI-compatible /v1/chat/completions endpoint."""
        formatted_messages = self._format_messages(messages)

        payload = {
            "model": self.model,
            "messages": formatted_messages,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "temperature": kwargs.get("temperature", self.temperature),
            "stream": False,
            # Prompt caching: llama-server automatically caches KV for identical prefixes.
            # We hint via cache_prompt, though llama-server may ignore this.
            "cache_prompt": kwargs.get("cache_prompt", True),
            # Thinking models (e.g. Qwen3.x with a reasoning chat template) will
            # happily burn the whole token budget on <think> blocks and return
            # an EMPTY content field — which the harness reads as a failure.
            # This is an agentic tool-use loop: reasoning is disabled by default
            # (config llm.llama-server.reasoning_effort); per-call kwargs win.
            "reasoning_effort": kwargs.get("reasoning_effort", self.reasoning_effort),
            # Repetition penalty prevents CJK/multilingual repetition loops
            # that Qwen 3.x models can fall into under long agentic contexts.
            "repeat_penalty": kwargs.get("repeat_penalty", 1.15),
        }

        # JSON Schema enforcement (GBNF grammar)
        if "response_format" in kwargs:
            payload["response_format"] = kwargs["response_format"]

        try:
            logger.info(f"Sending {len(formatted_messages)} messages to llama-server")
            start = time.time()
            r = requests.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                timeout=kwargs.get("timeout", self.timeout),
            )
            elapsed = time.time() - start
            logger.info(f"LLM response in {elapsed:.1f}s (status={r.status_code})")

            if r.status_code != 200:
                logger.error(f"LLM API error {r.status_code}: {r.text[:500]}")
                return f"[ERROR] LLM returned status {r.status_code}: {r.text[:200]}"

            data = r.json()
            self._track_usage(data)

            message = data.get("choices", [{}])[0].get("message", {})
            content = message.get("content") or ""
            # Fallback: some templates/models still emit only reasoning tokens;
            # surface them rather than reporting an empty response.
            if not content and message.get("reasoning_content"):
                content = message["reasoning_content"]
            if not content:
                logger.warning("LLM returned empty content")
                return "[ERROR] LLM returned empty response"
            # Strip Qwen <think>...</think> tags if reasoning_effort=none
            # but the model still emitted them via the chat template.
            import re as _re
            content = _re.sub(r'<think>.*?</think>', '', content, flags=_re.DOTALL).strip()
            return content

        except requests.Timeout:
            logger.error(f"LLM request timed out after {self.timeout}s")
            return f"[ERROR] LLM request timed out after {self.timeout}s"
        except requests.ConnectionError:
            logger.error(f"Cannot connect to LLM at {self.base_url}")
            return f"[ERROR] Cannot connect to LLM at {self.base_url}. Is llama-server running?"
        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            return f"[ERROR] LLM request failed: {e}"

    def _chat_openai_stream(self, messages: List[Dict[str, str]], **kwargs) -> Generator[str, None, None]:
        """
        Stream chat completions via SSE. Yields content chunks as they arrive.
        Error messages are yielded as "[ERROR] ..." strings — check for these in consumers.
        """
        formatted_messages = self._format_messages(messages)

        payload = {
            "model": self.model,
            "messages": formatted_messages,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "temperature": kwargs.get("temperature", self.temperature),
            "stream": True,
            "cache_prompt": kwargs.get("cache_prompt", True),
            "reasoning_effort": kwargs.get("reasoning_effort", self.reasoning_effort),
        }
        if "response_format" in kwargs:
            payload["response_format"] = kwargs["response_format"]

        try:
            logger.info(f"Streaming {len(formatted_messages)} messages from llama-server")
            r = requests.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                timeout=kwargs.get("timeout", self.timeout),
                stream=True,
            )
            if r.status_code != 200:
                err = f"[ERROR] LLM stream HTTP {r.status_code}"
                logger.error(err)
                yield err
                return

            # NOTE: llama-server's SSE responses use content-type
            # "text/event-stream" WITHOUT a charset, so requests falls back to
            # its apparent encoding (often ISO-8859-1) and mangles any non-ASCII
            # output (observed: the model's UTF-8 Chinese came back as "åª"-
            # style mojibake). Always decode the raw bytes as UTF-8 ourselves.
            for raw_line in r.iter_lines(decode_unicode=False):
                if not raw_line:
                    continue
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    line = raw_line.decode("utf-8", errors="replace")
                if line.startswith(":"):
                    continue
                if line == "data: [DONE]":
                    break
                if line.startswith("data: "):
                    try:
                        chunk = json.loads(line[6:])
                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            yield content  # push chunk to consumer
                        if "usage" in chunk:
                            self._track_usage(chunk)
                    except json.JSONDecodeError:
                        continue

        except requests.Timeout:
            err = f"[ERROR] Stream timed out after {self.timeout}s"
            logger.error(err)
            yield err
        except requests.ConnectionError:
            err = f"[ERROR] Cannot stream to {self.base_url}"
            logger.error(err)
            yield err
        except Exception as e:
            err = f"[ERROR] Stream failed: {e}"
            logger.error(err)
            yield err

    # ═══════════════════════════════════════════════════════════════
    # Internal: Ollama
    # ═══════════════════════════════════════════════════════════════

    def _chat_ollama(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Chat via Ollama's /api/chat endpoint."""
        formatted_messages = self._format_messages(messages)

        payload = {
            "model": self.model or "llama3",
            "messages": formatted_messages,
            "stream": False,
            "options": {
                "num_predict": kwargs.get("max_tokens", self.max_tokens),
                "temperature": kwargs.get("temperature", self.temperature),
            },
        }
        if kwargs.get("format"):
            payload["format"] = kwargs["format"]

        try:
            logger.info(f"Sending {len(formatted_messages)} messages to Ollama")
            start = time.time()
            r = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=kwargs.get("timeout", self.timeout),
            )
            elapsed = time.time() - start
            logger.info(f"Ollama response in {elapsed:.1f}s")

            if r.status_code != 200:
                return f"[ERROR] Ollama returned status {r.status_code}"

            data = r.json()
            return data.get("message", {}).get("content", "[ERROR] Empty response")

        except requests.Timeout:
            return f"[ERROR] Ollama request timed out after {self.timeout}s"
        except requests.ConnectionError:
            return f"[ERROR] Cannot connect to Ollama at {self.base_url}"
        except Exception as e:
            return f"[ERROR] Ollama request failed: {e}"