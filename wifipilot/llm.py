# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""LLM providers: a local Ollama server, or a remote OpenAI-compatible gateway.

wifipilot's advisor does not care where the tokens come from.  This module
implements the two transports it can speak:

* :class:`OllamaClient` — a local ``ollama serve`` (``/api/chat``, NDJSON stream,
  ``/api/tags`` for the model list, ``/api/pull`` to install models).  This is
  the default: nothing about the engagement leaves the machine.
* :class:`OpenRouterClient` — OpenRouter's OpenAI-compatible gateway
  (``POST /api/v1/chat/completions``, SSE stream, ``GET /api/v1/models``, and
  ``GET /api/v1/key`` for credential/quota checks).  Cloud models, so it is
  *off by default* and engagement identifiers are pseudonymised before they are
  sent unless the operator turns that off.

Both share :class:`LLMClient`: one HTTP plumbing, one error vocabulary
(:class:`LLMError` and friends), one ``(text, stats)`` contract for ``chat()``,
and one model-metadata shape (:class:`ModelInfo`) so the CLI, the web UI and the
advisor stay provider-agnostic.

Everything here is stdlib only (``urllib``, ``json``, ``ssl``) — wifipilot's core
must keep working on a freshly installed Linux box with no site-packages.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from .config import CortexConfig, OllamaConfig, OpenRouterConfig

#: attribution sent to OpenRouter (their docs ask for both headers)
OPENROUTER_REFERER = "https://github.com/codero-sus/Pentest-toolkit"

# --------------------------------------------------------------------------- #
# errors
# --------------------------------------------------------------------------- #


class LLMError(RuntimeError):
    """Any failure while talking to a model provider."""


class LLMPolicyError(LLMError):
    """Refused by *our* policy: no consent, no key, plaintext remote URL, cost cap.

    Deliberately distinct from "the provider is down": a policy refusal must never
    be reported as "offline" and must never be silently retried.
    """


class LLMAuthError(LLMError):
    """The provider rejected our credentials (bad/expired API key)."""


class LLMCreditError(LLMError):
    """Payment required: the account is out of credits or the model is paid-only."""


class LLMRateLimitError(LLMError):
    """Rate limited or quota exhausted — retry later, not immediately."""


# --------------------------------------------------------------------------- #
# model metadata
# --------------------------------------------------------------------------- #


@dataclass
class ModelInfo:
    """One selectable model, normalised across providers."""

    name: str
    provider: str = "ollama"
    size: int = 0                      # bytes on disk (Ollama); 0 when unknown
    parameters: str = ""
    family: str = ""
    modified: str = ""
    context: int = 0                   # context window in tokens
    prompt_price: float = 0.0          # USD per 1M prompt tokens
    completion_price: float = 0.0      # USD per 1M completion tokens
    description: str = ""

    @property
    def size_gb(self) -> float:
        return round(self.size / 1e9, 2)

    @property
    def free(self) -> bool:
        return self.prompt_price == 0.0 and self.completion_price == 0.0

    def price_label(self) -> str:
        if self.free:
            return "free"
        if not self.prompt_price and not self.completion_price:
            return "unknown"
        return f"${self.prompt_price:g}/${self.completion_price:g} per 1M tokens in/out"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "provider": self.provider, "size": self.size,
            "size_gb": self.size_gb, "params": self.parameters, "family": self.family,
            "context": self.context, "prompt_price": self.prompt_price,
            "completion_price": self.completion_price, "free": self.free,
            "price": self.price_label(), "description": self.description,
        }


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# shared client
# --------------------------------------------------------------------------- #


class LLMClient:
    """Common HTTP plumbing, counters and model-cache behaviour."""

    provider = "llm"
    label = "LLM"

    def __init__(self, config: Any, bus=None) -> None:
        self.config = config
        self.bus = bus
        self.last_error = ""
        self.last_latency = 0.0
        self.calls = 0
        self.errors = 0
        self.cost_usd = 0.0
        self.tokens_total = 0
        self.models_error = ""
        self._models: List[ModelInfo] = []
        self._models_at = 0.0

    # -- identity ---------------------------------------------------------- #
    @property
    def host(self) -> str:
        raise NotImplementedError

    def describe(self) -> str:
        return f"{self.label} at {self.host}"

    def _warn(self, message: str) -> None:
        if self.bus is not None:
            try:
                self.bus.warn(message)
            except Exception:  # pragma: no cover - bus is best effort
                pass

    # -- transport --------------------------------------------------------- #
    def _guard(self) -> None:
        """Raise :class:`LLMPolicyError` when we must not make the request."""

    def _classify_http_error(self, code: int, body: str, reason: str) -> LLMError:
        return LLMError(f"HTTP {code}: {body or reason}")

    #: historical name, kept for callers/tests written against the Ollama-only API
    def _guard_host(self) -> None:
        self._guard()

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "wifipilot"}
        headers.update(extra or {})
        return headers

    def _request(self, path: str, payload: Optional[dict] = None, *,
                 stream: bool = False, timeout: float = 0.0,
                 headers: Optional[Dict[str, str]] = None, method: str = ""):
        """Perform one HTTP request.  Returns a file-like response object."""
        self._guard()
        url = path if path.startswith("http") else f"{self.host}{path}"
        data = json.dumps(payload, default=str).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url, data=data, headers=self._headers(headers),
            method=method or ("POST" if data is not None else "GET"),
        )
        timeout = timeout or float(getattr(self.config, "timeout", 120.0))
        started = time.time()
        try:
            response = urllib.request.urlopen(request, timeout=timeout)  # noqa: S310
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:500]
            except Exception:  # pragma: no cover - body may be unreadable
                pass
            self.errors += 1
            error = self._classify_http_error(int(exc.code), body, str(exc.reason))
            self.last_error = str(error)
            raise error from exc
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            self.errors += 1
            message = f"cannot reach {self.label} at {self.host}: {exc}"
            if self.provider != "ollama":
                # the usual causes on an audit box: no route, a proxy, or a filter
                hint = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
                message += (
                    " — check outbound HTTPS access"
                    + (f" (urllib is using proxy {hint})" if hint
                       else " (behind a corporate proxy set HTTPS_PROXY)")
                    + ", or use the local provider instead: wifipilot --provider ollama"
                )
            self.last_error = message
            raise LLMError(message) from exc
        self.last_latency = time.time() - started
        if stream:
            return response
        with response:
            return response.read().decode("utf-8", "replace")

    @staticmethod
    def _iter_sse(response: Iterable[bytes]) -> Iterator[dict]:
        """Yield decoded JSON objects out of an SSE (``text/event-stream``) body."""
        for raw in response:
            line = raw.decode("utf-8", "replace").strip()
            if not line or line.startswith(":"):
                continue
            if line.startswith("data:"):
                line = line[5:].strip()
            if not line or line == "[DONE]":
                continue
            try:
                chunk = json.loads(line)
            except ValueError:
                continue
            if isinstance(chunk, dict):
                yield chunk

    @staticmethod
    def _iter_ndjson(response: Iterable[bytes]) -> Iterator[dict]:
        for raw in response:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                chunk = json.loads(line)
            except ValueError:
                continue
            if isinstance(chunk, dict):
                yield chunk

    # -- availability ------------------------------------------------------ #
    def ping(self) -> bool:
        raise NotImplementedError

    def version(self) -> str:
        return ""

    # -- models ------------------------------------------------------------ #
    def list_models(self, force: bool = False, **kwargs: Any) -> List[ModelInfo]:
        raise NotImplementedError

    def resolve_model(self, preferred: str = "") -> str:
        raise NotImplementedError

    def _cached_models(self, cache_seconds: float, force: bool) -> bool:
        return bool(self._models) and not force and time.time() - self._models_at < cache_seconds

    def _pick_fallback(self, wanted: str, names: List[str]) -> Optional[str]:
        """Match a wanted name against a catalogue (exact, then prefix/partial)."""
        if not wanted:
            return None
        if wanted in names:
            return wanted
        lowered = wanted.lower()
        for name in names:
            if name.lower() == lowered:
                return name
        base = wanted.split(":")[0].lower()
        for name in names:
            if name.lower() == base:
                return name
        for name in names:
            if name.lower().split(":")[0] == base:
                return name
        for name in names:
            if lowered in name.lower():
                return name
        return None

    # -- chat -------------------------------------------------------------- #
    def chat(self, messages: List[Dict[str, str]], model: str = "",
             json_mode: bool = False, on_token: Optional[Callable[[str], None]] = None,
             timeout: float = 0.0,
             options: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError

    def pull(self, model: str, on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
             timeout: float = 3600.0) -> bool:
        self.last_error = f"{self.label} models cannot be installed from here"
        return False

    # -- accounting -------------------------------------------------------- #
    def _account(self, stats: Dict[str, Any], model: str, pricing: Optional[ModelInfo]) -> None:
        tokens = int(stats.get("tokens") or 0)
        self.tokens_total += tokens
        cost = _as_float(stats.get("cost"), 0.0)
        if not cost and pricing is not None:
            prompt_tokens = int(stats.get("prompt_tokens") or 0)
            completion_tokens = int(stats.get("completion_tokens") or 0)
            cost = (prompt_tokens * pricing.prompt_price
                    + completion_tokens * pricing.completion_price) / 1_000_000
        if cost:
            self.cost_usd += cost
            stats["cost"] = round(cost, 6)
        stats["tokens_total"] = self.tokens_total
        stats["cost_total"] = round(self.cost_usd, 6)


# --------------------------------------------------------------------------- #
# Ollama (local)
# --------------------------------------------------------------------------- #


class OllamaClient(LLMClient):
    """Minimal, dependency-free Ollama HTTP client."""

    provider = "ollama"
    label = "Ollama"

    @property
    def host(self) -> str:
        return str(getattr(self.config, "host", "") or getattr(self.config, "base_url", "")
                   ).rstrip("/")

    def describe(self) -> str:
        return f"local Ollama at {self.host}"

    def _guard(self) -> None:
        parsed = urllib.parse.urlparse(self.host)
        host = (parsed.hostname or "").lower()
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return
        if not getattr(self.config, "allow_remote_host", False):
            raise LLMPolicyError(
                f"refusing to contact non-loopback Ollama host {self.host!r} — "
                f"set ollama.allow_remote_host=true to allow sending engagement "
                f"data to a remote model"
            )

    # -- api --------------------------------------------------------------- #
    def ping(self) -> bool:
        try:
            self._request("/api/tags", timeout=4.0)
            return True
        except LLMPolicyError:
            raise                      # a policy refusal must never look like "offline"
        except LLMError:
            return False

    def version(self) -> str:
        try:
            body = self._request("/api/version", timeout=5.0)
            return json.loads(body).get("version", "")
        except (LLMError, ValueError):
            return ""

    def list_models(self, force: bool = False, **kwargs: Any) -> List[ModelInfo]:
        if self._cached_models(30, force):
            return self._models
        try:
            body = self._request("/api/tags", timeout=8.0)
            data = json.loads(body)
        except (LLMError, ValueError) as exc:
            self.models_error = str(exc)
            return self._models
        models: List[ModelInfo] = []
        for entry in data.get("models", []):
            details = entry.get("details") or {}
            models.append(ModelInfo(
                name=entry.get("name") or entry.get("model", ""),
                provider="ollama",
                size=int(entry.get("size") or 0),
                parameters=str(details.get("parameter_size") or ""),
                family=str(details.get("family") or ""),
                modified=str(entry.get("modified_at") or ""),
            ))
        self._models = models
        self._models_at = time.time()
        self.models_error = ""
        return models

    # -- model choice ------------------------------------------------------ #
    def resolve_model(self, preferred: str = "") -> str:
        """Pick the model to use: explicit -> configured -> best installed."""
        wanted = (preferred or self.config.model or "auto").strip()
        models = self.list_models()
        names = [m.name for m in models]
        if wanted and wanted != "auto":
            match = self._pick_fallback(wanted, names)
            if match:
                return match
            self._warn(
                f"Ollama model {wanted!r} is not installed; falling back "
                f"(available: {', '.join(names[:5]) or 'none'})")
        for candidate in self.config.fallback_models:
            match = self._pick_fallback(candidate, names)
            if match:
                return match
        if not names:
            return wanted if wanted != "auto" else ""
        # prefer a mid-sized instruct model: good JSON, sane latency on a laptop
        def score(model: ModelInfo) -> float:
            value = 0.0
            lowered = model.name.lower()
            size = model.size / 1e9
            if 3.0 <= size <= 12.0:
                value += 10
            elif size < 1.5:
                value -= 6
            elif size > 20:
                value -= 3
            for good in ("qwen2.5", "llama3.1", "llama3", "mistral", "gemma2", "phi3",
                         "deepseek", "granite", "smollm"):
                if good in lowered:
                    value += 6
                    break
            if "coder" in lowered or "vision" in lowered or "embed" in lowered:
                value -= 8
            if "instruct" in lowered or "chat" in lowered:
                value += 2
            return value + size

        return max(models, key=score).name

    # -- chat -------------------------------------------------------------- #
    def chat(self, messages: List[Dict[str, str]], model: str = "",
             json_mode: bool = False, on_token: Optional[Callable[[str], None]] = None,
             timeout: float = 0.0,
             options: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
        """Stream a chat completion.  Returns (text, stats)."""
        model = model or self.resolve_model()
        if not model:
            raise LLMError("no Ollama model available (try: ollama pull llama3.1:8b)")
        config = self.config
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": bool(config.stream),
            "keep_alive": config.keep_alive,
            "options": {
                "temperature": config.temperature,
                "num_ctx": config.num_ctx,
                "num_predict": config.max_tokens,
                **(options or {}),
            },
        }
        if json_mode and config.json_mode:
            payload["format"] = "json"
        self.calls += 1
        started = time.time()
        text_parts: List[str] = []
        stats: Dict[str, Any] = {"model": model, "tokens": 0, "eval_count": 0}

        if config.stream:
            response = self._request("/api/chat", payload, stream=True, timeout=timeout)
            with response:
                for chunk in self._iter_ndjson(response):
                    if chunk.get("error"):
                        raise LLMError(str(chunk["error"]))
                    piece = ((chunk.get("message") or {}).get("content") or "")
                    if piece:
                        text_parts.append(piece)
                        if on_token:
                            on_token(piece)
                    if chunk.get("done"):
                        stats.update({
                            "eval_count": chunk.get("eval_count", 0),
                            "prompt_eval_count": chunk.get("prompt_eval_count", 0),
                            "total_duration": chunk.get("total_duration", 0),
                        })
                        break
        else:
            data = json.loads(self._request("/api/chat", payload, timeout=timeout))
            if data.get("error"):
                raise LLMError(str(data["error"]))
            text = ((data.get("message") or {}).get("content") or "")
            text_parts.append(text)
            if on_token and text:
                on_token(text)
            stats.update({
                "eval_count": data.get("eval_count", 0),
                "prompt_eval_count": data.get("prompt_eval_count", 0),
                "total_duration": data.get("total_duration", 0),
            })
        stats["tokens"] = int(stats.get("eval_count") or 0) + int(stats.get("prompt_eval_count") or 0)
        stats["prompt_tokens"] = int(stats.get("prompt_eval_count") or 0)
        stats["completion_tokens"] = int(stats.get("eval_count") or 0)
        stats["seconds"] = round(time.time() - started, 2)
        self.last_latency = stats["seconds"]
        self._account(stats, model, None)
        return "".join(text_parts), stats

    def pull(self, model: str, on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
             timeout: float = 3600.0) -> bool:
        """``ollama pull`` — used by the web UI to install a model on demand."""
        try:
            response = self._request("/api/pull", {"model": model, "stream": True},
                                     stream=True, timeout=timeout)
        except LLMError:
            return False
        with response:
            for chunk in self._iter_ndjson(response):
                if on_progress:
                    on_progress(chunk)
                if chunk.get("error"):
                    self.last_error = str(chunk["error"])
                    return False
                if chunk.get("status") == "success":
                    self._models_at = 0.0
                    return True
        return False


# --------------------------------------------------------------------------- #
# OpenRouter (cloud gateway)
# --------------------------------------------------------------------------- #


class CortexClient(LLMClient):
    """`Cortex LLMHoster <https://github.com/codero-sus/Cortex_LLMHoster>`_: a local
    OpenAI-compatible model host, driven over HTTP on the loopback interface.

    It is the third provider and the second *local* one.  Ollama is the easy path when it
    is already installed; Cortex is for the operator who wants ``llama.cpp`` started for
    them (GGUF paths, GPU layers, context size) behind an OpenAI-shaped API, with a
    dashboard and per-model commands.  From wifipilot's side the differences are:

    1. **It is a local service that must be running.** Nothing is probed unless
       ``cortex.enabled`` is true — wifipilot never knocks on a port it was not asked to.
    2. **Loopback only** unless ``cortex.allow_remote_host`` is set: this API has no
       transport security of its own and the models behind it are the operator's machine.
    3. **The key is optional.** Cortex can run keyless on a trusted listener; when a key
       is configured (``CORTEX_API_KEY``) it is sent as a bearer token and never logged.
    """

    provider = "cortex"
    label = "Cortex LLMHoster"

    @property
    def host(self) -> str:
        return str(getattr(self.config, "base_url", "") or getattr(self.config, "host", "")
                   ).rstrip("/")

    def describe(self) -> str:
        return f"Cortex LLMHoster ({self.host})"

    # -- policy ------------------------------------------------------------- #
    def api_key(self) -> str:
        getter = getattr(self.config, "api_key_value", None)
        return getter() if callable(getter) else str(getattr(self.config, "api_key", "") or "")

    def is_loopback(self) -> bool:
        parsed = urllib.parse.urlparse(self.host)
        return (parsed.hostname or "").lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0")

    def _guard(self) -> None:
        if not getattr(self.config, "enabled", False):
            raise LLMPolicyError(
                "Cortex LLMHoster is disabled — enable it with cortex.enabled=true (or "
                "`wifipilot --provider cortex`) once the hoster is running")
        if not self.is_loopback() and not getattr(self.config, "allow_remote_host", False):
            raise LLMPolicyError(
                f"refusing to send engagement data to {self.host}: Cortex LLMHoster is a "
                "local service — set cortex.allow_remote_host=true only for a listener you "
                "control")

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = super()._headers()
        key = self.api_key()
        if key:
            headers["Authorization"] = f"Bearer {key}"
        if extra:
            headers.update(extra)
        return headers

    def _classify_http_error(self, code: int, body: str, reason: str) -> LLMError:
        detail = body[:300] or reason
        if code in (401, 403):
            return LLMAuthError(
                f"Cortex LLMHoster rejected the request (HTTP {code}): {detail} — check "
                f"CORTEX_API_KEY, or run the hoster with CORTEX_API_AUTH_ENABLED=false on "
                f"a trusted listener")
        if code == 404:
            return LLMError(f"Cortex LLMHoster has no such model or route (HTTP 404): {detail}")
        if code == 429:
            return LLMRateLimitError(f"Cortex LLMHoster is at its inference limit: {detail}")
        if code >= 500:
            return LLMError(f"Cortex LLMHoster runtime error (HTTP {code}): {detail}")
        return LLMError(f"Cortex LLMHoster HTTP {code}: {detail}")

    # -- api ---------------------------------------------------------------- #
    def ping(self) -> bool:
        """``GET /health``: the hoster is up.  Policy refusals raise, they never read offline."""
        self._guard()
        try:
            body = self._request("/health", timeout=min(5.0, float(
                getattr(self.config, "timeout", 5.0))))
        except LLMPolicyError:
            raise
        except LLMError as exc:
            self.last_error = str(exc)
            return False
        self.last_error = ""
        try:
            payload = json.loads(body)
        except ValueError:
            payload = {}
        if isinstance(payload, dict):
            self._health = payload
        return True

    def version(self) -> str:
        health = getattr(self, "_health", None) or {}
        for key in ("version", "api_version", "build"):
            if isinstance(health, dict) and health.get(key):
                return str(health[key])
        return ""

    def list_models(self, force: bool = False, **kwargs: Any) -> List[ModelInfo]:
        """``GET /v1/models``: the models the hoster has configured (cached for a minute)."""
        if not self._cached_models(60, force):
            try:
                body = self._request("/v1/models", timeout=15.0)
                data = json.loads(body)
                entries = data.get("data") if isinstance(data, dict) else None
                if not isinstance(entries, list):
                    raise LLMError(f"unexpected /v1/models payload from {self.host}")
                models: List[ModelInfo] = []
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    identifier = str(entry.get("id") or entry.get("name") or "")
                    if not identifier:
                        continue
                    models.append(ModelInfo(
                        name=identifier, provider=self.provider,
                        context=int(entry.get("context_length") or 0),
                        family=str(entry.get("owned_by") or entry.get("family") or ""),
                        modified=str(entry.get("created") or ""),
                        description=str(entry.get("description") or "")[:400],
                    ))
                self._models = models
                self._models_at = time.time()
                self.models_error = ""
            except (LLMError, ValueError) as exc:
                self.models_error = str(exc)
                return self._models
        return self._models

    def _filter_models(self, query: str = "", limit: int = 0,
                       free_only: bool = False) -> List[ModelInfo]:
        models = self._models
        if query:
            needle = query.lower()
            models = [m for m in models if needle in m.name.lower()]
        return models[:limit] if limit > 0 else models

    def resolve_model(self, preferred: str = "") -> str:
        wanted = (preferred or getattr(self.config, "model", "") or "").strip()
        names = [m.name for m in self.list_models()]
        if wanted and wanted not in ("auto", ""):
            match = self._pick_fallback(wanted, names)
            return match or wanted
        for candidate in list(getattr(self.config, "fallback_models", []) or []):
            match = self._pick_fallback(candidate, names)
            if match:
                return match
        return names[0] if names else ""

    # -- chat --------------------------------------------------------------- #
    def _payload(self, model: str, messages: List[Dict[str, str]], json_mode: bool,
                 options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        config = self.config
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": config.temperature,
            "max_tokens": int((options or {}).get("max_tokens")
                              or (options or {}).get("num_predict") or config.max_tokens),
            "stream": bool(config.stream),
        }
        if json_mode and getattr(config, "json_mode", False):
            payload["response_format"] = {"type": "json_object"}
        return payload

    def chat(self, messages: List[Dict[str, str]], model: str = "",
             json_mode: bool = False, on_token: Optional[Callable[[str], None]] = None,
             timeout: float = 0.0,
             options: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
        model = model or self.resolve_model()
        if not model:
            raise LLMError(
                "no model on the Cortex LLMHoster — add one in cortex.toml (or its "
                "dashboard) and start it")
        payload = self._payload(model, messages, json_mode, options)
        self.calls += 1
        started = time.time()
        text_parts: List[str] = []
        stats: Dict[str, Any] = {"model": model, "provider": self.provider,
                                 "tokens": 0, "cost": 0.0}
        stream = bool(getattr(self.config, "stream", True))
        if stream:
            response = self._request("/v1/chat/completions", payload, stream=True,
                                     timeout=timeout)
            with response:
                for chunk in self._iter_sse(response):
                    if chunk.get("error"):
                        raise LLMError(str(chunk["error"]))
                    usage = chunk.get("usage") or {}
                    if usage:
                        stats["tokens"] = int(usage.get("total_tokens") or 0)
                    for choice in chunk.get("choices") or []:
                        delta = choice.get("delta") or {}
                        piece = delta.get("content")
                        if not piece and isinstance(choice.get("text"), str):
                            piece = choice["text"]
                        if piece:
                            text_parts.append(piece)
                            if on_token:
                                on_token(piece)
                        if choice.get("finish_reason"):
                            stats["finish_reason"] = str(choice["finish_reason"])
        else:
            data = json.loads(self._request("/v1/chat/completions", payload, timeout=timeout))
            if data.get("error"):
                error = data["error"]
                raise LLMError(str(error.get("message") if isinstance(error, dict) else error))
            usage = data.get("usage") or {}
            stats["prompt_tokens"] = int(usage.get("prompt_tokens") or 0)
            stats["completion_tokens"] = int(usage.get("completion_tokens") or 0)
            stats["tokens"] = int(usage.get("total_tokens") or 0) or (
                stats["prompt_tokens"] + stats["completion_tokens"])
            for choice in data.get("choices") or []:
                message = choice.get("message") or {}
                piece = message.get("content") or choice.get("text") or ""
                if piece:
                    text_parts.append(piece)
                    if on_token:
                        on_token(piece)
                if choice.get("finish_reason"):
                    stats["finish_reason"] = str(choice["finish_reason"])
        text = "".join(text_parts)
        stats["seconds"] = round(time.time() - started, 2)
        stats.setdefault("tokens", 0)
        self.last_latency = stats["seconds"]
        self.tokens_total += int(stats.get("tokens") or 0)
        if not text and stats.get("finish_reason") == "error":
            raise LLMError("Cortex LLMHoster returned an empty completion")
        return text, stats

    def pull(self, model: str, on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
             timeout: float = 3600.0) -> bool:
        self.last_error = ("Cortex LLMHoster serves the models you point it at (llama.cpp "
                           "GGUF paths, or a per-model command) — start or add the model in "
                           "cortex.toml or its dashboard, then pick it here")
        return False


class OpenRouterClient(LLMClient):
    """OpenRouter: OpenAI-compatible chat completions over HTTPS.

    Three things make this different from Ollama and they are all enforced here:

    1. **Consent** — ``openrouter.enabled`` must be true.  Contacting a cloud
       provider with client data is an explicit operator decision.
    2. **Credentials** — an API key is required (``OPENROUTER_API_KEY``, a key
       file, or ``openrouter.api_key``).  It is never logged and never returned
       over the API (see :meth:`Config.to_dict(redact_secrets=True)`).
    3. **Transport** — HTTPS only, unless the base URL is loopback (a local
       proxy) or ``allow_insecure_base_url`` is set.
    """

    provider = "openrouter"
    label = "OpenRouter"

    @property
    def host(self) -> str:
        return str(getattr(self.config, "base_url", "") or getattr(self.config, "host", "")
                   ).rstrip("/")

    def describe(self) -> str:
        return f"OpenRouter ({self.host})"

    # -- credentials & policy ---------------------------------------------- #
    def api_key(self) -> str:
        return self.config.api_key_value()

    def has_key(self) -> bool:
        return bool(self.api_key())

    def _guard(self) -> None:
        config = self.config
        if not getattr(config, "enabled", False):
            raise LLMPolicyError(
                "OpenRouter is disabled — enable it explicitly before sending "
                "engagement data to a cloud model (--provider openrouter, or "
                "openrouter.enabled=true)"
            )
        if not self.api_key():
            raise LLMPolicyError(
                "no OpenRouter API key — set OPENROUTER_API_KEY in the environment, "
                "or openrouter.api_key / openrouter.key_file in the config "
                "(create a key at https://openrouter.ai/keys)"
            )
        parsed = urllib.parse.urlparse(self.host)
        host = (parsed.hostname or "").lower()
        loopback = host in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme != "https" and not loopback and not getattr(
                config, "allow_insecure_base_url", False):
            raise LLMPolicyError(
                f"refusing to send an API key over plaintext {parsed.scheme or 'http'}://"
                f"{host} — use https, or set openrouter.allow_insecure_base_url=true "
                f"for a trusted local proxy"
            )

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = super()._headers()
        headers["Authorization"] = f"Bearer {self.api_key()}"
        site = str(getattr(self.config, "site_url", "") or OPENROUTER_REFERER)
        title = str(getattr(self.config, "app_title", "") or "wifipilot")
        headers["HTTP-Referer"] = site
        headers["X-Title"] = title
        headers["X-OpenRouter-Title"] = title
        if extra:
            headers.update(extra)
        return headers

    def _classify_http_error(self, code: int, body: str, reason: str) -> LLMError:
        detail = ""
        try:
            parsed = json.loads(body)
            error = parsed.get("error") if isinstance(parsed, dict) else None
            if isinstance(error, dict):
                detail = str(error.get("message") or "")
            elif error:
                detail = str(error)
        except ValueError:
            detail = body[:300]
        detail = detail or body[:300] or reason
        if code in (401, 403):
            return LLMAuthError(f"OpenRouter rejected the API key (HTTP {code}): {detail}")
        if code == 402:
            return LLMCreditError(f"OpenRouter: payment required — {detail}")
        if code == 429:
            return LLMRateLimitError(f"OpenRouter rate limit: {detail}")
        if code == 404:
            return LLMError(f"OpenRouter model not found (HTTP 404): {detail}")
        if code >= 500:
            return LLMError(f"OpenRouter upstream error (HTTP {code}): {detail}")
        return LLMError(f"OpenRouter HTTP {code}: {detail}")

    # -- api --------------------------------------------------------------- #
    def key_info(self) -> Dict[str, Any]:
        """``GET /key``: quota, usage and rate limits for the configured key."""
        try:
            body = self._request("/key", timeout=10.0)
        except LLMPolicyError:
            raise
        except LLMError:
            return {}
        try:
            return json.loads(body).get("data") or {}
        except ValueError:
            return {}

    def ping(self) -> bool:
        """True when the key is usable.  Policy refusals raise, they never read as offline."""
        if not getattr(self.config, "enabled", False):
            raise LLMPolicyError(
                "OpenRouter is disabled — enable it before contacting a cloud model"
            )
        if not self.api_key():
            raise LLMPolicyError(
                "no OpenRouter API key configured (set OPENROUTER_API_KEY)"
            )
        self._guard()          # https/consent checks raise, they never read as "offline"
        info = self.key_info()
        if info:
            self.last_error = ""
            return True
        if isinstance(self.last_error, str) and "rejected the API key" in self.last_error:
            return False
        # listing models is public; if the key check failed for a transport reason,
        # remember it but do not claim the key is bad.
        return False

    def list_models(self, force: bool = False, query: str = "",
                    limit: int = 0, free_only: bool = False,
                    include_variants: bool = False) -> List[ModelInfo]:
        """The live catalogue (public endpoint, cached for 10 minutes)."""
        if not self._cached_models(600, force):
            try:
                # /models is public: no key, no consent needed
                body = self._request("/models", timeout=20.0, headers={
                    "Authorization": f"Bearer {self.api_key()}" if self.api_key() else "",
                })
                data = json.loads(body)
                entries = data.get("data") if isinstance(data, dict) else None
                if not isinstance(entries, list):
                    raise LLMError(
                        f"unexpected /models payload from {self.host} "
                        f"(expected a data list, got {type(entries).__name__})")
                models: List[ModelInfo] = []
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    identifier = str(entry.get("id") or "")
                    if not identifier:
                        continue
                    if not include_variants and identifier.startswith("~"):
                        continue          # "latest family" aliases are noisy in a picker
                    pricing = entry.get("pricing") or {}
                    architecture = entry.get("architecture") or {}
                    if architecture.get("output_modalities") and \
                            "text" not in architecture["output_modalities"]:
                        continue          # image/audio-only models cannot plan
                    models.append(ModelInfo(
                        name=identifier,
                        provider="openrouter",
                        context=int(entry.get("context_length") or 0),
                        family=str(entry.get("name") or ""),
                        modified=str(entry.get("created") or ""),
                        prompt_price=round(_as_float(pricing.get("prompt")) * 1e6, 4),
                        completion_price=round(_as_float(pricing.get("completion")) * 1e6, 4),
                        description=str(entry.get("description") or "")[:400],
                    ))
                self._models = models
                self._models_at = time.time()
                self.models_error = ""
            except (LLMError, ValueError) as exc:
                self.models_error = str(exc)
                return self._models
        return self._filter_models(query=query, limit=limit, free_only=free_only)

    def _filter_models(self, query: str = "", limit: int = 0,
                       free_only: bool = False) -> List[ModelInfo]:
        models = self._models
        if free_only:
            models = [m for m in models if m.free]
        if query:
            needle = query.lower()
            models = [m for m in models
                      if needle in m.name.lower() or needle in m.family.lower()]
        models = sorted(models, key=lambda m: (m.prompt_price + m.completion_price, m.name))
        return models[:limit] if limit > 0 else models

    def resolve_model(self, preferred: str = "") -> str:
        """Configured model, else the first available preferred, else the auto router."""
        wanted = (preferred or self.config.model or "auto").strip()
        models = self.list_models()
        names = [m.name for m in models]
        if wanted and wanted not in ("auto", ""):
            match = self._pick_fallback(wanted, names)
            if match:
                return match
            if not names:                        # catalogue unavailable: trust the operator
                return wanted
            self._warn(
                f"OpenRouter model {wanted!r} is not in the catalogue; trying it anyway "
                f"(popular: {', '.join(m.name for m in models[:5])})")
            return wanted
        for candidate in self.config.fallback_models:
            match = self._pick_fallback(candidate, names)
            if match:
                return match
        if not names:
            return "openrouter/auto"
        affordable = [m for m in models if not m.free]
        if affordable:
            return sorted(affordable, key=lambda m: m.prompt_price + m.completion_price)[0].name
        return models[0].name

    def pricing_for(self, model: str) -> Optional[ModelInfo]:
        for candidate in self._models:
            if candidate.name == model:
                return candidate
        return None

    # -- chat -------------------------------------------------------------- #
    def _payload(self, model: str, messages: List[Dict[str, str]], json_mode: bool,
                 options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        config = self.config
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": bool(config.stream),
            "temperature": config.temperature,
            "max_tokens": int((options or {}).get("max_tokens")
                              or (options or {}).get("num_predict") or config.max_tokens),
            "usage": {"include": True},          # ask for cost in the response
        }
        if json_mode and config.json_mode:
            payload["response_format"] = {"type": "json_object"}
        routing = dict(getattr(config, "provider_routing", {}) or {})
        if routing:
            payload["provider"] = routing
        return payload

    def chat(self, messages: List[Dict[str, str]], model: str = "",
             json_mode: bool = False, on_token: Optional[Callable[[str], None]] = None,
             timeout: float = 0.0,
             options: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
        model = model or self.resolve_model()
        if not model:
            raise LLMError("no OpenRouter model selected")
        config = self.config
        payload = self._payload(model, messages, json_mode, options)
        self.calls += 1
        started = time.time()
        text_parts: List[str] = []
        stats: Dict[str, Any] = {"model": model, "provider": self.provider, "tokens": 0}

        def absorb(usage: Dict[str, Any], used_model: str = "") -> None:
            if used_model:
                stats["model"] = used_model
            if not usage:
                return
            stats["prompt_tokens"] = int(usage.get("prompt_tokens") or 0)
            stats["completion_tokens"] = int(usage.get("completion_tokens") or 0)
            stats["tokens"] = int(usage.get("total_tokens")
                                  or stats["prompt_tokens"] + stats["completion_tokens"])
            cost = usage.get("cost")
            if cost is None and isinstance(usage.get("cost_details"), dict):
                cost = None                     # upstream-only breakdown, not our bill
            if cost is not None:
                stats["cost"] = _as_float(cost, 0.0)

        if config.stream:
            response = self._request("/chat/completions", payload, stream=True, timeout=timeout)
            with response:
                for chunk in self._iter_sse(response):
                    if chunk.get("error"):
                        message = chunk["error"]
                        if isinstance(message, dict):
                            message = message.get("message") or json.dumps(message)
                        raise LLMError(str(message))
                    usage = chunk.get("usage") or {}
                    if usage:
                        absorb(usage, str(chunk.get("model") or ""))
                    for choice in chunk.get("choices") or []:
                        delta = choice.get("delta") or {}
                        piece = delta.get("content")
                        if not piece and isinstance(choice.get("text"), str):
                            piece = choice["text"]
                        if piece:
                            text_parts.append(piece)
                            if on_token:
                                on_token(piece)
                        if choice.get("finish_reason"):
                            stats["finish_reason"] = str(choice["finish_reason"])
                        if choice.get("message") and choice["message"].get("content"):
                            piece = choice["message"]["content"]
                            if piece and not text_parts:
                                text_parts.append(piece)
                                if on_token:
                                    on_token(piece)
        else:
            data = json.loads(self._request("/chat/completions", payload, timeout=timeout))
            if data.get("error"):
                error = data["error"]
                raise LLMError(str(error.get("message") if isinstance(error, dict) else error))
            absorb(data.get("usage") or {}, str(data.get("model") or ""))
            for choice in data.get("choices") or []:
                message = choice.get("message") or {}
                piece = message.get("content") or choice.get("text") or ""
                if piece:
                    text_parts.append(piece)
                    if on_token:
                        on_token(piece)
                if choice.get("finish_reason"):
                    stats["finish_reason"] = str(choice["finish_reason"])

        text = "".join(text_parts)
        stats.setdefault("prompt_tokens", 0)
        stats.setdefault("completion_tokens", 0)
        stats.setdefault("tokens", stats["prompt_tokens"] + stats["completion_tokens"])
        stats["seconds"] = round(time.time() - started, 2)
        self.last_latency = stats["seconds"]
        if not text and stats.get("finish_reason") == "error":
            raise LLMError("OpenRouter returned an empty completion")
        self._account(stats, stats["model"], self.pricing_for(str(stats["model"])))
        return text, stats

    def pull(self, model: str, on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
             timeout: float = 3600.0) -> bool:
        self.last_error = ("OpenRouter models are hosted remotely and cannot be pulled — "
                           "pick a model name instead (wifipilot ai models)")
        return False


# --------------------------------------------------------------------------- #
# provider selection
# --------------------------------------------------------------------------- #


PROVIDERS = ("auto", "ollama", "cortex", "openrouter", "none")

PROVIDER_LABELS = {
    "auto": "automatic (prefer a local model)",
    "ollama": "Ollama (local, private)",
    "cortex": "Cortex LLMHoster (local, OpenAI-compatible)",
    "openrouter": "OpenRouter (cloud, paid, explicit consent)",
    "none": "disabled (deterministic planner only)",
}

#: local providers, in the order ``auto`` prefers them
LOCAL_PROVIDERS = ("ollama", "cortex")


def build_client(provider: str, ollama: OllamaConfig, openrouter: OpenRouterConfig,
                 bus=None, cortex: Optional[CortexConfig] = None) -> Optional[LLMClient]:
    """Instantiate the client for a concrete provider name."""
    if provider == "ollama":
        return OllamaClient(ollama, bus)
    if provider == "cortex":
        if cortex is None:
            raise LLMPolicyError(
                "no Cortex LLMHoster configuration — add a [cortex] section to "
                "wifipilot.json (host, model) or pass cortex=CortexConfig(...)")
        return CortexClient(cortex, bus)
    if provider == "openrouter":
        return OpenRouterClient(openrouter, bus)
    return None


def ollama_reachable(config: OllamaConfig, timeout: float = 2.0) -> bool:
    if not config.enabled:
        return False
    client = OllamaClient(config)
    try:
        return client.ping()
    except LLMPolicyError:
        return False


def cortex_reachable(config: Optional[CortexConfig], timeout: float = 2.0) -> bool:
    if config is None or not config.enabled:
        return False
    try:
        return CortexClient(config).ping()
    except LLMPolicyError:
        return False


def select_provider(ai_provider: str, ollama: OllamaConfig, openrouter: OpenRouterConfig,
                    probe: bool = True,
                    cortex: Optional[CortexConfig] = None) -> Tuple[str, str]:
    """Resolve ``ai_provider`` to a concrete provider plus a human-readable reason.

    ``auto`` prefers the local model (private, free, no data leaves the box) and
    only falls back to OpenRouter when it is explicitly enabled *and* has a key.
    """
    ai_provider = (ai_provider or "auto").strip().lower()
    if ai_provider in ("none", "off", "disabled"):
        return "none", "AI advisor disabled"
    if ai_provider == "ollama":
        return ("ollama", "explicitly selected local Ollama"
                if not ollama.enabled else "Ollama selected")
    if ai_provider == "cortex":
        if cortex is None or not cortex.enabled:
            return "none", ("Cortex LLMHoster selected but not enabled "
                            "(cortex.enabled=false)")
        return "cortex", "explicitly selected Cortex LLMHoster"
    if ai_provider == "openrouter":
        if not openrouter.enabled:
            return "none", "OpenRouter selected but not enabled (openrouter.enabled=false)"
        if not openrouter.api_key_value():
            return "none", "OpenRouter selected but no API key is configured"
        return "openrouter", "explicitly selected OpenRouter"
    # auto: a local model first (private, free), then the cloud if it was enabled
    if ollama.enabled and (ollama_reachable(ollama) if probe else True):
        return "ollama", ("local Ollama is reachable" if probe
                          else "Ollama configured (reachability not tested)")
    if cortex is not None and cortex.enabled and (cortex_reachable(cortex) if probe else True):
        return "cortex", ("local Cortex LLMHoster is reachable" if probe
                          else "Cortex LLMHoster configured (reachability not tested)")
    if openrouter.enabled and openrouter.api_key_value():
        reason = ("local Ollama is not reachable; using the explicitly enabled "
                  "OpenRouter fallback")
        if not ollama.enabled:
            reason = "Ollama is disabled; using the enabled OpenRouter provider"
        return "openrouter", reason
    if ollama.enabled:
        if probe:
            return "none", "Ollama is configured but not reachable (start it: ollama serve)"
        return "ollama", "Ollama configured (reachability not tested)"
    if cortex is not None and cortex.enabled:
        if probe:
            return "none", ("Cortex LLMHoster is configured but not reachable (start it: "
                            "cortex-llmhoster --config cortex.toml)")
        return "cortex", "Cortex LLMHoster configured (reachability not tested)"
    return "none", ("no provider available (start Ollama or Cortex LLMHoster, or configure "
                    "OpenRouter)")


def provider_status(ollama: OllamaConfig, openrouter: OpenRouterConfig,
                    probe: bool = False,
                    cortex: Optional[CortexConfig] = None) -> List[Dict[str, Any]]:
    """Summary of every provider for the dashboard and the web UI."""
    rows: List[Dict[str, Any]] = [{
        "name": "ollama", "label": PROVIDER_LABELS["ollama"],
        "enabled": bool(ollama.enabled),
        "configured": bool(ollama.host),
        "host": ollama.host,
        "model": ollama.model,
        "reachable": ollama_reachable(ollama) if (probe and ollama.enabled) else None,
    }, {
        "name": "cortex", "label": PROVIDER_LABELS["cortex"],
        "enabled": bool(cortex.enabled) if cortex is not None else False,
        "configured": bool(cortex is not None and cortex.host),
        "host": cortex.base() if cortex is not None else "",
        "model": (cortex.model if cortex is not None else "") or "host default",
        "key_hint": cortex.key_hint() if cortex is not None else "",
        "reachable": (cortex_reachable(cortex) if (probe and cortex is not None
                                                   and cortex.enabled) else None),
    }, {
        "name": "openrouter", "label": PROVIDER_LABELS["openrouter"],
        "enabled": bool(openrouter.enabled),
        "configured": bool(openrouter.api_key_value()),
        "host": openrouter.base(),
        "model": openrouter.model,
        "key_hint": openrouter.key_hint(),
        "redact": bool(openrouter.redact_identifiers),
        "reachable": None,
    }]
    return rows
