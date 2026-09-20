"""The AI co-pilot: a local LLM (through Ollama) that plans and explains.

wifipilot stays useful without a model — the deterministic planner in
:mod:`wifipilot.planner` takes over automatically.  When Ollama *is* reachable
this module adds three things:

* **auto-think**: periodically re-reads a compact situation report and decides
  what to attack next (and *why*), including when to give up on a target.
* **failure triage**: turns a failed attempt plus the target's state into a
  concrete next step in plain language.
* **chat**: the operator can ask questions about the running engagement
  ("which target is most promising and why?") and get an answer grounded in the
  live state rather than in the model's imagination.

Only loopback Ollama hosts are accepted unless the operator explicitly allows a
remote one.  Nothing about the engagement leaves the machine by default.
"""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from .config import OllamaConfig
from .deps import registry
from .events import EK
from .planner import (MAX_ACTIONS, PLANNER_ACTIONS, Plan, heuristic_plan,
                      validate_plan)
from .session import Session

JSON_RETRY_SUFFIX = (
    "\n\nReturn ONLY a single JSON object. No markdown fences, no commentary."
)

SYSTEM_PLANNER = """You are wifipilot's tactical planner: an experienced wireless \
penetration tester running an AUTHORISED internal assessment.

You receive a JSON situation report and must choose the next actions. Think like \
a professional: prefer the least disruptive attack that recovers a PSK, respect \
budgets, and stop attacking a target that has clearly failed.

Attack vocabulary (the ONLY allowed values for "attack"):
- "crack": run the offline cracker against a capture we already hold
- "pmkid": request the RSN PMKID; works without clients, non-disruptive; best first choice when the AP has no clients
- "handshake": deauth clients and capture a 4-way handshake; needs at least one client, fails against WPA3-SAE and PMF
- "wps_pixie": offline Pixie-Dust against WPS; only when WPS is enabled and not locked; usually < 60s
- "wps_pin": online WPS PIN recovery; slow and disruptive, only when Pixie-Dust failed
- "wep_ivs": harvest IVs from a WEP network
- "passive": listen only, never transmit

Decision rules you MUST follow:
1. If a target has "handshake": true or "pmkid": true and no PSK yet, choose "crack" first.
2. WPA3-only targets (sec == "WPA3") cannot be attacked: skip them.
3. Prefer "pmkid" over "handshake" when clients == 0.
4. Do not choose an attack that already appears twice in the target's "attacks_tried" with failures.
5. "wps_pin" only after "wps_pixie" failed on that target.
6. If every target is exhausted, return {"actions": [], "stop": true, "reasoning": "..."}.
7. Only use BSSIDs that appear in the report. Maximum %d actions.
8. Order actions by expected value: fastest loot first.

Output schema (JSON only):
{"reasoning": "<2-4 sentences, concrete, mentions the deciding facts>",
 "actions": [{"attack": "<one of the vocabulary>", "bssid": "<from the report>",
              "priority": <int, 1 = next>, "reason": "<short justification>"}],
 "stop": <bool>, "notes": "<optional operator note>"}
""" % MAX_ACTIONS

SYSTEM_CHAT = """You are wifipilot's assistant for an AUTHORISED wireless \
assessment. Answer the operator's question about the CURRENT engagement using \
only the JSON situation report provided. Be concrete and brief (max 6 sentences). \
If the report does not contain the answer, say what data would be needed. \
Never invent SSIDs, BSSIDs, passwords or tool output."""


# --------------------------------------------------------------------------- #
# tiny JSON helper (kept local so the core needs no third-party deps)
# --------------------------------------------------------------------------- #


def dumps(data: Any) -> str:
    return json.dumps(data, default=str, ensure_ascii=False)


def extract_json(text: str) -> Optional[dict]:
    """Pull the first JSON object out of a model response (fences and all)."""
    if not text:
        return None
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        loaded = json.loads(text)
        return loaded if isinstance(loaded, dict) else None
    except ValueError:
        pass
    depth, start = 0, -1
    for index, char in enumerate(text):
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    loaded = json.loads(text[start:index + 1])
                    if isinstance(loaded, dict):
                        return loaded
                except ValueError:
                    start = -1
    return None


# --------------------------------------------------------------------------- #
# Ollama client
# --------------------------------------------------------------------------- #


@dataclass
class OllamaModel:
    name: str
    size: int = 0
    parameters: str = ""
    family: str = ""
    modified: str = ""

    @property
    def size_gb(self) -> float:
        return round(self.size / 1e9, 2)


class OllamaError(RuntimeError):
    pass


class OllamaHostError(OllamaError):
    """The configured host is refused by policy (non-loopback without opt-in)."""


class OllamaClient:
    """Minimal, dependency-free Ollama HTTP client (stdlib urllib only)."""

    def __init__(self, config: OllamaConfig, bus=None):
        self.config = config
        self.bus = bus
        self.last_error = ""
        self.last_latency = 0.0
        self.calls = 0
        self.errors = 0
        self._models: List[OllamaModel] = []
        self._models_at = 0.0

    # -- transport ---------------------------------------------------------
    @property
    def host(self) -> str:
        return self.config.host.rstrip("/")

    def _guard_host(self) -> None:
        parsed = urllib.parse.urlparse(self.host)
        host = (parsed.hostname or "").lower()
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return
        if not self.config.allow_remote_host:
            raise OllamaHostError(
                f"refusing to contact non-loopback Ollama host {self.host!r} — "
                f"set ollama.allow_remote_host=true to allow sending engagement "
                f"data to a remote model"
            )

    def _request(self, path: str, payload: Optional[dict] = None,
                 stream: bool = False, timeout: float = 0.0):
        self._guard_host()
        url = f"{self.host}{path}"
        data = dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST" if data is not None else "GET",
        )
        timeout = timeout or self.config.timeout
        started = time.time()
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:400]
            except Exception:
                pass
            self.errors += 1
            self.last_error = f"HTTP {exc.code}: {body or exc.reason}"
            raise OllamaError(self.last_error) from exc
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            self.errors += 1
            self.last_error = f"cannot reach Ollama at {self.host}: {exc}"
            raise OllamaError(self.last_error) from exc
        self.last_latency = time.time() - started
        if stream:
            return response
        with response:
            body = response.read().decode("utf-8", "replace")
        return body

    # -- api ---------------------------------------------------------------
    def ping(self) -> bool:
        try:
            self._request("/api/tags", timeout=4.0)
            return True
        except OllamaHostError:
            raise                      # a policy refusal must never look like "offline"
        except OllamaError:
            return False

    def version(self) -> str:
        try:
            body = self._request("/api/version", timeout=5.0)
            return json.loads(body).get("version", "")
        except (OllamaError, ValueError):
            return ""

    def list_models(self, force: bool = False) -> List[OllamaModel]:
        if not force and self._models and time.time() - self._models_at < 30:
            return self._models
        try:
            body = self._request("/api/tags", timeout=8.0)
            data = json.loads(body)
        except (OllamaError, ValueError):
            return self._models
        models: List[OllamaModel] = []
        for entry in data.get("models", []):
            details = entry.get("details") or {}
            models.append(OllamaModel(
                name=entry.get("name") or entry.get("model", ""),
                size=int(entry.get("size") or 0),
                parameters=str(details.get("parameter_size") or ""),
                family=str(details.get("family") or ""),
                modified=str(entry.get("modified_at") or ""),
            ))
        self._models = models
        self._models_at = time.time()
        return models

    # -- model choice ------------------------------------------------------
    def resolve_model(self, preferred: Optional[str] = None) -> str:
        """Pick the model to use: explicit -> configured -> best installed."""
        wanted = (preferred or self.config.model or "auto").strip()
        models = self.list_models()
        names = [m.name for m in models]
        if wanted and wanted != "auto":
            if wanted in names:
                return wanted
            base = wanted.split(":")[0]
            for name in names:
                if name.split(":")[0] == base:
                    return name
            self.bus and self.bus.warn(
                f"Ollama model {wanted!r} is not installed; falling back "
                f"(available: {', '.join(names[:5]) or 'none'})")
        for candidate in self.config.fallback_models:
            for name in names:
                if name == candidate or name.split(":")[0] == candidate.split(":")[0]:
                    return name
        if not names:
            return wanted if wanted != "auto" else ""
        # prefer a mid-sized instruct model: good JSON, sane latency on a laptop
        def score(model: OllamaModel) -> float:
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

    # -- chat --------------------------------------------------------------
    def chat(self, messages: List[Dict[str, str]], model: str = "",
             json_mode: bool = False, on_token: Optional[Callable[[str], None]] = None,
             timeout: float = 0.0, options: Optional[Dict[str, Any]] = None) -> Tuple[str, Dict[str, Any]]:
        """Stream a chat completion.  Returns (text, stats)."""
        model = model or self.resolve_model()
        if not model:
            raise OllamaError("no Ollama model available (try: ollama pull llama3.1:8b)")
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": bool(self.config.stream),
            "keep_alive": self.config.keep_alive,
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": self.config.num_ctx,
                "num_predict": self.config.max_tokens,
                **(options or {}),
            },
        }
        if json_mode and self.config.json_mode:
            payload["format"] = "json"
        self.calls += 1
        started = time.time()
        text_parts: List[str] = []
        stats: Dict[str, Any] = {"model": model, "tokens": 0, "eval_count": 0}

        if self.config.stream:
            response = self._request("/api/chat", payload, stream=True, timeout=timeout)
            for raw in response:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except ValueError:
                    continue
                if chunk.get("error"):
                    raise OllamaError(str(chunk["error"]))
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
            body = self._request("/api/chat", payload, timeout=timeout)
            data = json.loads(body)
            if data.get("error"):
                raise OllamaError(str(data["error"]))
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
        stats["seconds"] = round(time.time() - started, 2)
        self.last_latency = stats["seconds"]
        return "".join(text_parts), stats

    def pull(self, model: str, on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
             timeout: float = 3600.0) -> bool:
        """``ollama pull`` — used by the web UI to install a model on demand."""
        try:
            response = self._request("/api/pull", {"model": model, "stream": True},
                                     stream=True, timeout=timeout)
        except OllamaError:
            return False
        with response:
            for raw in response:
                try:
                    chunk = json.loads(raw.decode("utf-8", "replace").strip() or "{}")
                except ValueError:
                    continue
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
# advisor
# --------------------------------------------------------------------------- #


class Advisor:
    """Planning + explanation layer.  Never blocks the attack loop for long."""

    def __init__(self, session: Session, config: Optional[OllamaConfig] = None,
                 bus=None, demo: bool = False):
        self.session = session
        self.config = config or session.config.ollama
        self.bus = bus or session.bus
        self.demo = demo
        self.client = OllamaClient(self.config, self.bus)
        self.available = False
        self.model = ""
        self.last_plan: Optional[Plan] = None
        self.last_error = ""
        self.last_check = 0.0
        self.latency: List[float] = []
        self.history: List[Dict[str, str]] = []
        self.plan_count = 0
        self.fallback_count = 0

    # -- availability ------------------------------------------------------
    def check(self, force: bool = False, announce: bool = True) -> bool:
        if not self.config.enabled:
            self.available = False
            return False
        if not force and time.time() - self.last_check < 20:
            return self.available
        self.last_check = time.time()
        was = self.available
        try:
            self.available = self.client.ping()
        except OllamaHostError as exc:
            self.available = False
            self.last_error = str(exc)
            self.bus.publish(EK.ADVISOR_ERROR, {"stage": "policy", "error": str(exc)})
            self.bus.error(str(exc))
            self.bus.publish(EK.ADVISOR_STATUS, {"available": False, "error": str(exc),
                                                 "model": "", "host": self.client.host})
            return False
        if self.available:
            self.model = self.client.resolve_model()
            version = self.client.version()
            self.last_error = ""
            if announce and not was:
                models = ", ".join(m.name for m in self.client.list_models()[:4])
                self.bus.publish(EK.ADVISOR_STATUS, {
                    "available": True, "model": self.model, "host": self.client.host,
                    "version": version, "models": models,
                })
                self.bus.log(f"Ollama online ({self.client.host}, v{version or '?'}) — "
                             f"advisor using {self.model or 'no model'}", level="success")
        else:
            self.last_error = self.client.last_error or "Ollama not reachable"
            if announce and was:
                self.bus.warn(f"Ollama went away: {self.last_error}; "
                              f"falling back to the deterministic planner")
            self.bus.publish(EK.ADVISOR_STATUS, {
                "available": False, "error": self.last_error, "model": "",
                "host": self.client.host,
            })
        return self.available

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "available": self.available,
            "host": self.client.host,
            "model": self.model,
            "models": [{"name": m.name, "size_gb": m.size_gb,
                        "params": m.parameters, "family": m.family}
                       for m in self.client.list_models()],
            "auto_think": self.session.auto_think,
            "plan_count": self.plan_count,
            "fallback_count": self.fallback_count,
            "calls": self.client.calls,
            "errors": self.client.errors,
            "last_error": self.last_error or self.client.last_error,
            "avg_latency": round(sum(self.latency) / len(self.latency), 2) if self.latency else 0.0,
            "last_plan": self.last_plan.to_dict() if self.last_plan else None,
            "policy": {
                "allow_remote_host": self.config.allow_remote_host,
                "temperature": self.config.temperature,
                "num_ctx": self.config.num_ctx,
                "think_interval": self.config.think_interval,
            },
            "actions": list(PLANNER_ACTIONS),
        }

    # -- planning ----------------------------------------------------------
    def plan(self, force_model: str = "") -> Plan:
        """Ask the model what to do next; fall back to heuristics on any problem."""
        situation = self.session.situation()
        started = time.time()
        if not self.check():
            self.fallback_count += 1
            plan = heuristic_plan(self.session)
            plan.reasoning = ("deterministic planner (Ollama unavailable: "
                              f"{self.last_error or 'not configured'}): " + plan.reasoning)
            self.last_plan = plan
            self.bus.publish(EK.ADVISOR_PLAN, plan.to_dict())
            return plan

        self.bus.publish(EK.ADVISOR_THINKING, {
            "stage": "plan", "model": force_model or self.model,
            "targets": len(self.session.aps),
        })
        messages = [
            {"role": "system", "content": SYSTEM_PLANNER},
            {"role": "user", "content": "Situation report:\n" + dumps(situation)
             + JSON_RETRY_SUFFIX},
        ]
        raw, stats = self._call(messages, json_mode=True, model=force_model,
                                stage="plan")
        data = extract_json(raw) if raw else None
        if data is None:
            self.bus.warn("the model returned unparseable JSON; using the deterministic planner")
            self.fallback_count += 1
            plan = heuristic_plan(self.session)
            plan.reasoning = ("deterministic planner (model output was not valid JSON): "
                              + plan.reasoning)
            plan.latency = time.time() - started
            self.last_plan = plan
            self.bus.publish(EK.ADVISOR_PLAN, plan.to_dict())
            return plan

        plan = validate_plan(data, self.session, source="llm", model=stats.get("model", self.model))
        plan.latency = time.time() - started
        self.plan_count += 1
        self.session.stats.llm_calls += 1
        self.session.stats.llm_tokens += int(stats.get("tokens") or 0)
        if plan.dropped:
            self.bus.publish(EK.ADVISOR_PLAN, {**plan.to_dict(), "dropped": plan.dropped})
            self.bus.warn("planner proposed actions that were rejected: "
                          + "; ".join(plan.dropped[:4]))
        if not plan.actions and not plan.stop:
            # model said nothing useful: keep the engagement moving
            heuristic = heuristic_plan(self.session)
            plan.actions = heuristic.actions
            plan.reasoning += (" | model proposed no valid action; filled in by the "
                               "deterministic planner")
        self.last_plan = plan
        self.bus.publish(EK.ADVISOR_PLAN, plan.to_dict())
        if plan.reasoning:
            self.bus.publish(EK.ADVISOR_CHAT, {
                "role": "assistant", "kind": "plan",
                "message": plan.reasoning, "model": plan.model,
                "actions": [a.to_dict() for a in plan.actions],
            })
        self.latency.append(plan.latency)
        del self.latency[:-20]
        return plan

    # -- failure triage ----------------------------------------------------
    def triage(self, attempt: Dict[str, Any], ap_summary: Dict[str, Any]) -> str:
        """Short natural-language diagnosis of a failed attempt (best effort)."""
        if not self.check():
            return ""
        prompt = (
            "An attack just failed. Attempt:\n" + dumps(attempt)
            + "\nTarget state:\n" + dumps(ap_summary)
            + "\n\nIn at most 2 sentences: what most likely went wrong and what should "
              "be tried next? Return JSON: {\"diagnosis\": \"...\", \"next\": \"<attack or none>\"}"
        )
        messages = [
            {"role": "system", "content": SYSTEM_CHAT},
            {"role": "user", "content": prompt + JSON_RETRY_SUFFIX},
        ]
        raw, _ = self._call(messages, json_mode=True, stage="triage", max_tokens=220)
        data = extract_json(raw) if raw else None
        if not data:
            return ""
        text = str(data.get("diagnosis") or "").strip()
        if text:
            self.bus.publish(EK.ADVISOR_CHAT, {
                "role": "assistant", "kind": "triage", "message": text,
                "next": data.get("next", ""), "bssid": attempt.get("bssid", ""),
                "model": self.model,
            })
        return text

    # -- chat --------------------------------------------------------------
    def ask(self, question: str, model: str = "") -> str:
        """Answer an operator question grounded in the live situation report."""
        if not question.strip():
            return ""
        self.history.append({"role": "user", "content": question})
        del self.history[:-12]
        if not self.check(announce=True):
            message = (f"Ollama is not reachable at {self.client.host} "
                       f"({self.last_error or 'connection refused'}). Start it with "
                       f"`ollama serve` and pull a model, e.g. "
                       f"`ollama pull {self.config.fallback_models[0]}`.")
            self.bus.publish(EK.ADVISOR_CHAT, {
                "role": "assistant", "kind": "chat", "message": message, "error": True,
            })
            self.history.append({"role": "assistant", "content": message})
            return message

        situation = self.session.situation(max_aps=20)
        messages = [
            {"role": "system", "content": SYSTEM_CHAT},
            *self.history[:-1][-6:],
            {"role": "user", "content": (
                "Live situation report:\n" + dumps(situation)
                + "\n\nOperator question: " + question
            )},
        ]
        tokens: List[str] = []

        def on_token(piece: str) -> None:
            tokens.append(piece)
            self.bus.publish(EK.ADVISOR_TOKEN, {"piece": piece, "kind": "chat"})

        self.bus.publish(EK.ADVISOR_THINKING, {"stage": "chat", "model": model or self.model,
                                               "question": question[:200]})
        raw, stats = self._call(messages, model=model, on_token=on_token, stage="chat",
                                json_mode=False)
        answer = raw or "".join(tokens)
        if not answer:
            answer = (f"The local model did not answer ({self.last_error or 'unknown error'}). "
                      f"Check that Ollama is running and the model is pulled:\n"
                      f"  ollama serve\n  ollama pull {self.config.fallback_models[0]}\n"
                      f"  wifipilot ai status")
            self.bus.publish(EK.ADVISOR_CHAT, {"role": "assistant", "kind": "chat",
                                               "message": answer, "error": True})
            self.history.append({"role": "assistant", "content": answer})
            return answer
        self.history.append({"role": "assistant", "content": answer})
        self.session.stats.llm_calls += 1
        self.session.stats.llm_tokens += int(stats.get("tokens") or 0)
        self.bus.publish(EK.ADVISOR_CHAT, {
            "role": "assistant", "kind": "chat", "message": answer,
            "model": stats.get("model", self.model), "question": question,
        })
        return answer

    # -- internals ---------------------------------------------------------
    def _call(self, messages: List[Dict[str, str]], json_mode: bool = True, model: str = "",
              on_token: Optional[Callable[[str], None]] = None, stage: str = "",
              max_tokens: int = 0) -> Tuple[str, Dict[str, Any]]:
        options = {"num_predict": max_tokens} if max_tokens else None
        try:
            text, stats = self.client.chat(messages, model=model or self.model,
                                           json_mode=json_mode, on_token=on_token,
                                           options=options)
            self.available = True
            return text, stats
        except OllamaError as exc:
            self.last_error = str(exc)
            self.available = False
            self.session.stats.llm_errors += 1
            self.bus.publish(EK.ADVISOR_ERROR, {"stage": stage, "error": str(exc)})
            self.bus.warn(f"advisor call failed ({stage}): {exc}")
            return "", {}
        except Exception as exc:  # pragma: no cover - defensive
            self.last_error = str(exc)
            self.available = False
            self.bus.publish(EK.ADVISOR_ERROR, {"stage": stage, "error": str(exc)})
            return "", {}

    # -- model management (used by the web UI) -----------------------------
    def pull_model(self, name: str) -> bool:
        self.bus.publish(EK.ADVISOR_STATUS, {"action": "pull-start", "model": name})

        def on_progress(chunk: Dict[str, Any]) -> None:
            self.bus.publish("advisor.pull", {
                "model": name, "status": chunk.get("status", ""),
                "completed": chunk.get("completed", 0), "total": chunk.get("total", 0),
                "percent": round(100 * (chunk.get("completed", 0) /
                                        chunk.get("total", 1) or 0), 1),
            })

        ok = self.client.pull(name, on_progress=on_progress)
        self.bus.publish(EK.ADVISOR_STATUS, {"action": "pull-done", "model": name, "ok": ok})
        if ok:
            self.model = self.client.resolve_model(name)
            self.check(force=True)
        return ok
