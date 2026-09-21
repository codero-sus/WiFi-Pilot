"""The AI co-pilot: an LLM (local Ollama, or OpenRouter) that plans and explains.

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

Two providers are supported, through the transports in :mod:`wifipilot.llm`:

* **Ollama** (default) — a local model on ``127.0.0.1``.  Nothing about the
  engagement leaves the machine; only loopback hosts are accepted unless the
  operator explicitly allows a remote one.
* **OpenRouter** — cloud models, used only when explicitly enabled *and* an API
  key is configured.  SSIDs, BSSIDs, client MACs and recovered PSKs are replaced
  with stable pseudonyms before the report is sent (``redact_identifiers``), and
  the plan is mapped back to the real identifiers before it is validated, so the
  provider never sees the client's network names.

The rules that matter for both: the model is an *advisor*, every plan it proposes
is re-validated against the live session, and the deterministic planner takes
over the moment the model is unavailable, over budget or incoherent.
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

from .config import OllamaConfig, OpenRouterConfig
from .deps import registry
from .events import EK
from .llm import (LLMAuthError, LLMClient, LLMCreditError, LLMError, LLMPolicyError,
                  LLMRateLimitError, ModelInfo, OllamaClient, OpenRouterClient,
                  build_client, provider_status, select_provider)
from .planner import (MAX_ACTIONS, PLANNER_ACTIONS, Plan, heuristic_plan,
                      validate_plan)
from .session import Session

#: kept so existing imports (and third-party callers) keep working
OllamaError = LLMError
OllamaHostError = LLMPolicyError
OllamaModel = ModelInfo

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
# provider compatibility shims
# --------------------------------------------------------------------------- #
# The transports themselves live in :mod:`wifipilot.llm`.  These names are the
# historical public surface of this module and are kept importable.


# --------------------------------------------------------------------------- #
# identifier redaction (used for cloud providers)
# --------------------------------------------------------------------------- #


class IdentifierRedactor:
    """Replaces SSIDs, BSSIDs, MACs and recovered PSKs with stable pseudonyms.

    The model still gets everything it needs to reason ("ssid-2 is WPA2, WPS is
    unlocked, one client, a PSK is already recovered") without receiving the
    client's network names or credentials.  Aliases are stable for the life of
    the redactor, so plans stay consistent across re-planning cycles.
    """

    KINDS = ("bssid", "ssid", "psk", "mac")

    def __init__(self) -> None:
        self.alias_to_real: Dict[str, str] = {}
        self.real_to_alias: Dict[str, str] = {}
        self._counters: Dict[str, int] = {kind: 0 for kind in self.KINDS}

    def alias(self, real: str, kind: str = "bssid") -> str:
        real = (real or "").strip()
        if not real:
            return real
        if real in self.real_to_alias:
            return self.real_to_alias[real]
        kind = kind if kind in self._counters else "mac"
        self._counters[kind] += 1
        alias = f"{kind}-{self._counters[kind]}"
        self.real_to_alias[real] = alias
        self.alias_to_real[alias] = real
        return alias

    def redact_text(self, text: str) -> str:
        """Replace every known identifier in a JSON/text blob (longest first)."""
        for real in sorted(self.real_to_alias, key=len, reverse=True):
            escaped = json.dumps(real)[1:-1]     # the form that appears inside JSON
            text = text.replace(escaped, self.real_to_alias[real])
        return text

    def restore(self, value: Any) -> Any:
        return self.alias_to_real.get(str(value), value)

    def restore_plan(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map pseudonyms in a model plan back to the real BSSIDs."""
        actions = data.get("actions")
        if isinstance(actions, list):
            for action in actions:
                if isinstance(action, dict) and action.get("bssid"):
                    action["bssid"] = self.restore(action["bssid"])
        return data

    def mapping(self) -> Dict[str, str]:
        return dict(self.alias_to_real)

    def __len__(self) -> int:
        return len(self.alias_to_real)


def build_redactor(aps: Iterable[Any]) -> IdentifierRedactor:
    """Collect every engagement identifier we should not send to a cloud model."""
    redactor = IdentifierRedactor()
    for ap in aps:
        redactor.alias(str(getattr(ap, "bssid", "") or ""), "bssid")
        redactor.alias(str(getattr(ap, "essid", "") or ""), "ssid")
        redactor.alias(str(getattr(ap, "password", "") or ""), "psk")
        for client in (getattr(ap, "clients", {}) or {}).values():
            redactor.alias(str(getattr(client, "mac", "") or ""), "mac")
    return redactor


# --------------------------------------------------------------------------- #
# advisor
# --------------------------------------------------------------------------- #


class Advisor:
    """Planning + explanation layer over a local (Ollama) or cloud (OpenRouter) model."""

    def __init__(self, session: Session, config: Optional[Any] = None,
                 bus=None, demo: bool = False, provider: str = ""):
        self.session = session
        self.bus = bus or session.bus
        self.demo = demo
        self.provider_explicit = provider
        #: config object of the *active* provider (OllamaConfig/OpenRouterConfig)
        self._config: Any = None
        self.provider_reason = ""
        self.provider = self._infer_provider(config)
        self.config = (config if config is not None
                       else session.config.llm_config(
                           self.provider if self.provider in ("ollama", "openrouter") else ""))
        self.client = self._make_client()
        self._sync_client_config()
        self.provider_reason = ""
        self.available = False
        self.model = ""
        self.last_plan: Optional[Plan] = None
        self.last_error = ""
        self.last_check = 0.0
        self.latency: List[float] = []
        self.history: List[Dict[str, str]] = []
        self.plan_count = 0
        self.fallback_count = 0
        self.redactor: Optional[IdentifierRedactor] = None
        self.cost_usd = 0.0
        self.tokens = 0
        self._key_info: Dict[str, Any] = {}
        self._key_info_at = 0.0

    # -- configuration ----------------------------------------------------- #
    #: aliases accepted from the CLI/UI mapped onto real providers
    PROVIDER_ALIASES = {"": "auto", "off": "none", "disabled": "none", "no": "none",
                        "false": "none", "local": "ollama", "cloud": "openrouter"}

    def _concrete_provider(self, candidate: str = "") -> str:
        """Resolve 'auto'/aliases/config defaults into ollama | openrouter | none.

        The advisor must never hold an "auto" provider: it owns one transport, and
        the client's config object must belong to that same transport.
        """
        name = self.PROVIDER_ALIASES.get((candidate or "").strip().lower(),
                                         (candidate or "").strip().lower())
        if name in ("ollama", "openrouter", "none"):
            return name
        resolved, self.provider_reason = select_provider(
            self.session.config.ai_provider, self.session.config.ollama,
            self.session.config.openrouter, probe=False)
        return resolved if resolved in ("ollama", "openrouter", "none") else "none"

    def _infer_provider(self, config: Optional[Any]) -> str:
        """A provider can be named explicitly, or inferred from the config object."""
        if isinstance(config, OpenRouterConfig):
            return "openrouter"
        if isinstance(config, OllamaConfig):
            return "ollama"
        return self._concrete_provider(self.provider_explicit)

    @property
    def config(self) -> Any:
        return self._config

    @config.setter
    def config(self, value: Any) -> None:
        self._config = value
        client = getattr(self, "client", None)
        if client is not None and value is not None:
            client.config = value

    @property
    def redact(self) -> bool:
        return bool(getattr(self._config, "redact_identifiers", False))

    @property
    def cost_cap(self) -> float:
        return float(getattr(self._config, "max_cost_usd", 0.0) or 0.0)

    def configure(self, provider: str = "", config: Optional[Any] = None,
                  announce: bool = True) -> "Advisor":
        """Point the advisor at another provider (used by the CLI and the web UI)."""
        explicit = bool((provider or "").strip())
        requested = (provider or "").strip().lower()
        if not requested:
            # no choice expressed: (re)resolve from the session configuration
            requested = (self.provider_explicit or "").strip().lower() or "auto"
        concrete = self._concrete_provider(requested)
        # remember what the operator asked for ("auto" is a valid *setting*), but
        # run the concrete provider we resolved it to.
        self.provider_explicit = requested
        self.provider = concrete
        if explicit and requested != "auto" and self.session.config.ai_provider != requested:
            self.session.config.ai_provider = requested
        chosen = (config if config is not None
                  else self.session.config.llm_config(
                      concrete if concrete in ("ollama", "openrouter") else ""))
        if config is not None:
            self._config = chosen
        else:
            self.config = chosen
        self.client = self._make_client()
        self._sync_client_config()
        self.model = ""
        self.last_check = 0.0
        self.last_error = ""
        self._key_info = {}
        self._key_info_at = 0.0
        self.check(force=True, announce=announce)
        return self

    def _make_client(self) -> LLMClient:
        """A transport that matches :attr:`provider`, never a mismatched leftover."""
        client = build_client(self.provider, self.session.config.ollama,
                              self.session.config.openrouter, self.bus)
        if client is None:
            # provider "none": nothing is ever called, but the object must still be
            # coherent (its config is the one the dashboard reads for policy).
            client = build_client("ollama", self.session.config.ollama,
                                  self.session.config.openrouter, self.bus)
        return client

    def _sync_client_config(self) -> None:
        """The client must read the config object of *its own* provider."""
        if self.client is None:
            return
        expected = "openrouter" if isinstance(self.client, OpenRouterClient) else "ollama"
        if self.provider not in ("none", expected):
            self.provider = expected
        self.client.config = (self.session.config.openrouter if expected == "openrouter"
                              else self.session.config.ollama)
        self._config = self.client.config

    def is_cloud(self) -> bool:
        return self.provider == "openrouter"

    def key_info(self, force: bool = False) -> Dict[str, Any]:
        """OpenRouter quota/usage for the configured key (empty for other providers).

        Reporting must never explode: a refused request (no key, provider
        disabled, insecure base URL) is answered with an empty dict plus the
        reason in :attr:`last_error`, which is what the dashboards show.  The
        transport itself still raises — see ``LLMClient.key_info()``.
        """
        if not isinstance(self.client, OpenRouterClient):
            return {}
        if not force and self._key_info and time.time() - self._key_info_at < 60:
            return self._key_info
        try:
            info = self.client.key_info()
        except LLMPolicyError as exc:
            self.last_error = str(exc)
            return {}
        except LLMError as exc:
            self.last_error = str(exc)
            return {}
        if info:
            self._key_info = info
            self._key_info_at = time.time()
        return self._key_info

    def models(self, force: bool = False, query: str = "", limit: int = 0,
               free_only: bool = False) -> List[Dict[str, Any]]:
        """The model catalogue of the active provider (for pickers and `ai models`)."""
        client = self.client
        if isinstance(client, OpenRouterClient):
            models = client.list_models(force=force, query=query, limit=limit,
                                        free_only=free_only)
        else:
            models = client.list_models(force=force)
            if query:
                needle = query.lower()
                models = [m for m in models if needle in m.name.lower()]
            if limit > 0:
                models = models[:limit]
        return [m.to_dict() for m in models]

    # -- availability ------------------------------------------------------
    def _refused(self, message: str, stage: str = "policy", loud: bool = True) -> bool:
        """A policy refusal (no key, no consent, over budget) is not "offline"."""
        self.available = False
        self.last_error = message
        self.bus.publish(EK.ADVISOR_ERROR, {"stage": stage, "error": message,
                                            "provider": self.provider})
        self.bus.publish(EK.ADVISOR_STATUS, {
            "available": False, "error": message, "model": "", "host": self.client.host,
            "provider": self.provider,
        })
        if loud:
            self.bus.error(message)
        return False

    def check(self, force: bool = False, announce: bool = True) -> bool:
        if self.provider == "none":
            self.available = False
            return False
        if not getattr(self.config, "enabled", False):
            self.available = False
            return False
        if not force and time.time() - self.last_check < 20:
            return self.available
        self.last_check = time.time()
        was = self.available

        # a paid provider stops planning once the operator's budget is spent
        cap = self.cost_cap
        if cap and self.cost_usd >= cap:
            return self._refused(
                f"OpenRouter budget reached (${self.cost_usd:.4f} of ${cap:.2f}) — "
                f"no further planning calls will be made "
                f"(raise openrouter.max_cost_usd or set it to 0 for unlimited)")

        try:
            self.available = self.client.ping()
        except LLMPolicyError as exc:
            return self._refused(str(exc))
        except (LLMAuthError, LLMCreditError, LLMRateLimitError) as exc:
            return self._refused(str(exc))
        except LLMError as exc:                     # pragma: no cover - transport
            self.available = False
            self.last_error = str(exc)

        if self.available:
            self.model = self.client.resolve_model()
            version = self.client.version()
            self.last_error = ""
            if announce and not was:
                if self.is_cloud():
                    models = ", ".join(m.name for m in self.client.list_models()[:4])
                    allowance = self._allowance_text()
                    self.bus.publish(EK.ADVISOR_STATUS, {
                        "available": True, "model": self.model, "host": self.client.host,
                        "provider": self.provider, "models": models,
                        "allowance": allowance,
                    })
                    self.bus.log(
                        f"OpenRouter online ({self.client.host}) — advisor using "
                        f"{self.model or 'no model'}; "
                        + ("engagement identifiers are pseudonymised"
                           if self.redact else
                           "WARNING: identifier redaction is disabled"), level="success")
                    if allowance:
                        self.bus.log(f"OpenRouter allowance: {allowance}", level="info")
                else:
                    models = ", ".join(m.name for m in self.client.list_models()[:4])
                    self.bus.publish(EK.ADVISOR_STATUS, {
                        "available": True, "model": self.model, "host": self.client.host,
                        "version": version, "models": models, "provider": self.provider,
                    })
                    self.bus.log(f"Ollama online ({self.client.host}, v{version or '?'}) — "
                                 f"advisor using {self.model or 'no model'}", level="success")
        else:
            self.last_error = self.client.last_error or f"{self.client.label} not reachable"
            if announce and was:
                self.bus.warn(f"{self.client.label} went away: {self.last_error}; "
                              f"falling back to the deterministic planner")
            self.bus.publish(EK.ADVISOR_STATUS, {
                "available": False, "error": self.last_error, "model": "",
                "host": self.client.host, "provider": self.provider,
            })
        return self.available

    def _allowance_text(self) -> str:
        """Human summary of OpenRouter credits/limits, when the key endpoint answers."""
        info = self.key_info()
        if not info:
            return ""
        pieces: List[str] = []
        limit = info.get("limit")
        usage = info.get("usage")
        if limit:
            remaining = float(limit) - float(usage or 0)
            pieces.append(f"${remaining:.2f} of ${float(limit):.2f} credit left")
        elif info.get("limit_remaining") is not None:
            pieces.append(f"${float(info['limit_remaining']):.2f} credit left")
        elif usage is not None:
            pieces.append(f"${float(usage):.4f} spent on this key")
        if info.get("is_free_tier"):
            pieces.append("free tier")
        rate = info.get("rate_limit") or {}
        if rate.get("requests"):
            pieces.append(f"{rate['requests']} req/{rate.get('interval', 'min')}")
        return " · ".join(pieces)

    def status(self) -> Dict[str, Any]:
        policy: Dict[str, Any] = {
            "temperature": getattr(self.config, "temperature", 0.0),
            "think_interval": getattr(self.config, "think_interval", 0.0),
            "redact_identifiers": self.redact,
            "max_cost_usd": self.cost_cap,
        }
        if self.provider != "openrouter":
            policy["allow_remote_host"] = bool(
                getattr(self.config, "allow_remote_host", False))
            policy["num_ctx"] = getattr(self.config, "num_ctx", 0)
        else:
            policy["allow_insecure_base_url"] = getattr(
                self.config, "allow_insecure_base_url", False)
            policy["provider_routing"] = dict(getattr(self.config, "provider_routing", {}) or {})
        info = self.key_info() if self.is_cloud() else {}
        return {
            "provider": self.provider,
            "provider_reason": self.provider_reason,
            "provider_label": {
                "ollama": "Ollama (local)", "openrouter": "OpenRouter (cloud)",
                "none": "disabled",
            }.get(self.provider, self.provider),
            "cloud": self.is_cloud(),
            "enabled": bool(getattr(self.config, "enabled", False)),
            "available": self.available,
            "host": self.client.host,
            "model": self.model,
            "models": [m.to_dict() for m in self.client.list_models()],
            "models_error": getattr(self.client, "models_error", ""),
            "auto_think": self.session.auto_think,
            "plan_count": self.plan_count,
            "fallback_count": self.fallback_count,
            "calls": self.client.calls,
            "errors": self.client.errors,
            "last_error": self.last_error or self.client.last_error,
            "avg_latency": round(sum(self.latency) / len(self.latency), 2) if self.latency else 0.0,
            "last_plan": self.last_plan.to_dict() if self.last_plan else None,
            "cost_usd": round(self.cost_usd or self.client.cost_usd, 6),
            "tokens": int(self.tokens or self.client.tokens_total),
            "allowance": self._allowance_text() if self.is_cloud() else "",
            "key": {
                "configured": bool(self.client.has_key()) if self.is_cloud() else False,
                "hint": getattr(self.config, "key_hint", lambda: "")() if self.is_cloud() else "",
                "source": getattr(self.config, "key_source", lambda: "")() if self.is_cloud() else "",
            } if self.is_cloud() else {},
            "key_info": {
                "is_free_tier": info.get("is_free_tier"),
                "limit": info.get("limit"),
                "usage": info.get("usage"),
                "limit_remaining": info.get("limit_remaining"),
                "rate_limit": info.get("rate_limit") or {},
                "label": info.get("label", ""),
            } if info else {},
            "providers": provider_status(self.session.config.ollama,
                                         self.session.config.openrouter),
            "policy": policy,
            "actions": list(PLANNER_ACTIONS),
        }

    # -- situation report -------------------------------------------------- #
    def _situation_text(self, max_aps: int = 20) -> str:
        """The JSON report sent to the model, pseudonymised for cloud providers."""
        situation = self.session.situation(max_aps=max_aps)
        text = dumps(situation)
        if not self.redact:
            self.redactor = None
            return text
        redactor = build_redactor(self.session.sorted_aps())
        self.redactor = redactor
        return redactor.redact_text(text)

    def _restore_plan(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map pseudonyms back to real BSSIDs before the plan is validated."""
        if self.redactor is not None:
            data = self.redactor.restore_plan(data)
        return data

    # -- planning ----------------------------------------------------------
    def plan(self, force_model: str = "") -> Plan:
        """Ask the model what to do next; fall back to heuristics on any problem."""
        situation = self._situation_text()
        started = time.time()
        if not self.check():
            self.fallback_count += 1
            plan = heuristic_plan(self.session)
            plan.reasoning = (f"deterministic planner ({self.client.label} unavailable: "
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
            {"role": "user", "content": "Situation report:\n" + situation
             + JSON_RETRY_SUFFIX},
        ]
        raw, stats = self._call(messages, json_mode=True, model=force_model,
                                stage="plan")
        data = self._restore_plan(extract_json(raw)) if raw else None
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
        plan.provider = self.provider
        plan.latency = time.time() - started
        self.plan_count += 1
        self.session.stats.llm_calls += 1
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
        def safe(payload: Any) -> str:
            text = dumps(payload)
            return self.redactor.redact_text(text) if self.redactor is not None else text

        prompt = (
            "An attack just failed. Attempt:\n" + safe(attempt)
            + "\nTarget state:\n" + safe(ap_summary)
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
            message = self._offline_message()
            self.bus.publish(EK.ADVISOR_CHAT, {
                "role": "assistant", "kind": "chat", "message": message, "error": True,
            })
            self.history.append({"role": "assistant", "content": message})
            return message

        messages = [
            {"role": "system", "content": SYSTEM_CHAT},
            *self.history[:-1][-6:],
            {"role": "user", "content": (
                "Live situation report:\n" + self._situation_text(max_aps=20)
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
            answer = (f"The model did not answer ({self.last_error or 'unknown error'}).\n"
                      + self._offline_message())
            self.bus.publish(EK.ADVISOR_CHAT, {"role": "assistant", "kind": "chat",
                                               "message": answer, "error": True})
            self.history.append({"role": "assistant", "content": answer})
            return answer
        self.history.append({"role": "assistant", "content": answer})
        self.session.stats.llm_calls += 1
        self.bus.publish(EK.ADVISOR_CHAT, {
            "role": "assistant", "kind": "chat", "message": answer,
            "model": stats.get("model", self.model), "question": question,
        })
        return answer

    # -- internals ---------------------------------------------------------
    def _offline_message(self) -> str:
        """Operator-facing help text when the active provider cannot answer."""
        if self.provider == "openrouter":
            key = getattr(self.config, "api_key_env", "OPENROUTER_API_KEY")
            return (f"OpenRouter is not usable ({self.last_error or 'unavailable'}).\n"
                    f"  export {key}=sk-or-...   # create a key: https://openrouter.ai/keys\n"
                    f"  wifipilot ai providers                      # check what is configured\n"
                    f"  wifipilot ai models --provider openrouter   # pick a model\n"
                    f"Prefer to keep the data local? Use the Ollama provider instead "
                    f"(wifipilot --provider ollama ...).")
        model = (self.config.fallback_models or ["llama3.1:8b"])[0]
        return (f"Ollama is not reachable at {self.client.host} "
                f"({self.last_error or 'connection refused'}). Start it with\n"
                f"  ollama serve\n  ollama pull {model}\n  wifipilot ai status\n"
                f"Or switch to a cloud model: wifipilot --provider openrouter ...")

    def _call(self, messages: List[Dict[str, str]], json_mode: bool = True, model: str = "",
              on_token: Optional[Callable[[str], None]] = None, stage: str = "",
              max_tokens: int = 0) -> Tuple[str, Dict[str, Any]]:
        # provider-neutral option names; each client maps them to its own API
        options = {"num_predict": max_tokens, "max_tokens": max_tokens} if max_tokens else None
        try:
            text, stats = self.client.chat(messages, model=model or self.model,
                                           json_mode=json_mode, on_token=on_token,
                                           options=options)
            self.available = True
            self._record_usage(stats, stage)
            return text, stats
        except LLMPolicyError as exc:
            self.last_error = str(exc)
            self.available = False
            self.session.stats.llm_errors += 1
            self.bus.publish(EK.ADVISOR_ERROR, {"stage": stage, "error": str(exc),
                                                "provider": self.provider})
            self.bus.error(f"advisor refused ({stage}): {exc}")
            return "", {}
        except LLMAuthError as exc:
            self.last_error = str(exc)
            self.available = False
            self.session.stats.llm_errors += 1
            self.bus.publish(EK.ADVISOR_ERROR, {"stage": stage, "error": str(exc),
                                                "provider": self.provider, "auth": True})
            self.bus.error(f"OpenRouter authentication failed: {exc} — check the API key "
                           f"(`wifipilot ai providers`)")
            return "", {}
        except LLMCreditError as exc:
            self.last_error = str(exc)
            self.available = False
            self.session.stats.llm_errors += 1
            self.bus.publish(EK.ADVISOR_ERROR, {"stage": stage, "error": str(exc),
                                                "provider": self.provider, "credits": True})
            self.bus.warn(f"OpenRouter has no credit left: {exc} — add credits at "
                          f"https://openrouter.ai/credits, or switch to a local model "
                          f"(--provider ollama)")
            return "", {}
        except LLMRateLimitError as exc:
            self.last_error = str(exc)
            self.session.stats.llm_errors += 1
            self.bus.warn(f"OpenRouter rate limited ({stage}): {exc}")
            return "", {}
        except LLMError as exc:
            self.last_error = str(exc)
            self.available = False
            self.session.stats.llm_errors += 1
            self.bus.publish(EK.ADVISOR_ERROR, {"stage": stage, "error": str(exc),
                                                "provider": self.provider})
            self.bus.warn(f"advisor call failed ({stage}): {exc}")
            return "", {}
        except Exception as exc:  # pragma: no cover - defensive
            self.last_error = str(exc)
            self.available = False
            self.bus.publish(EK.ADVISOR_ERROR, {"stage": stage, "error": str(exc)})
            return "", {}

    def _record_usage(self, stats: Dict[str, Any], stage: str = "") -> None:
        """Token/cost accounting, shared by planning, triage and chat."""
        tokens = int(stats.get("tokens") or 0)
        self.tokens += tokens
        self.session.stats.llm_tokens += tokens
        cost = float(stats.get("cost") or 0.0)
        if cost:
            self.cost_usd += cost
            self.session.stats.llm_cost += cost
            self.session.stats.llm_calls += 1
            self.bus.publish(EK.ADVISOR_COST, {
                "provider": self.provider, "model": stats.get("model", self.model),
                "cost": round(cost, 6), "cost_total": round(self.cost_usd, 6),
                "tokens": tokens, "stage": stage,
            })
            cap = self.cost_cap
            if cap and self.cost_usd >= cap * 0.8:
                self.bus.warn(f"OpenRouter spend ${self.cost_usd:.4f} is close to the "
                              f"${cap:.2f} budget (openrouter.max_cost_usd)")

    # -- model management (used by the web UI) -----------------------------
    def use_model(self, name: str, provider: str = "") -> bool:
        """Select a model (and optionally a provider) for this session."""
        target_provider = (provider or self.provider).strip().lower()
        if target_provider != self.provider:
            if target_provider == "openrouter":
                self.session.config.openrouter.model = name or "auto"
            elif target_provider == "ollama":
                self.session.config.ollama.model = name or "auto"
            self.session.config.ai_provider = target_provider
            self.configure(target_provider)
            return self.available
        if self.provider == "openrouter":
            self.session.config.openrouter.model = name or "auto"
        else:
            self.session.config.ollama.model = name or "auto"
        self.model = name or "auto"
        self.check(force=True)
        self.bus.publish(EK.ADVISOR_STATUS, {"action": "model", "model": self.model,
                                             "provider": self.provider})
        return True

    def pull_model(self, name: str) -> bool:
        if not isinstance(self.client, OllamaClient):
            self.bus.error(f"{self.client.label} models cannot be pulled — pick a model "
                           f"name instead (wifipilot ai models)")
            return False
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
