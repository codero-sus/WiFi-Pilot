"""The AI advisor: JSON handling, model selection, host policy and fallbacks."""

from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from wifipilot.advisor import Advisor, OllamaClient, OllamaError, extract_json
from wifipilot.config import OllamaConfig
from wifipilot.llm import ModelInfo
from tests.conftest import AP_MAC


class FakeClient(OllamaClient):
    """OllamaClient with the network replaced by canned answers."""

    def __init__(self, config, bus=None, models=None, reply="", fail=False):
        super().__init__(config, bus)
        self._fake_models = models or []
        self.reply = reply
        self.fail = fail
        self.sent: List[Dict[str, Any]] = []

    def ping(self) -> bool:
        return not self.fail

    def list_models(self, force: bool = False, **kwargs):
        if self.fail:
            return []
        return [ModelInfo(name=n, provider="ollama", size=4_000_000_000,
                          parameters="8B", family="llama")
                for n in self._fake_models]

    def chat(self, messages, model="", json_mode=False, on_token=None, timeout=0.0, options=None):
        self.sent.append({"model": model or self.resolve_model(), "messages": messages})
        if self.fail:
            raise OllamaError("connection refused")
        text = self.reply
        if on_token:
            for piece in text.split(" "):
                on_token(piece + " ")
        return text, {"model": model or self.resolve_model(), "tokens": 42, "seconds": 0.5}


# ---------------------------------------------------------------- parsing
@pytest.mark.parametrize("text,expected", [
    ('{"a": 1}', {"a": 1}),
    ('```json\n{"a": 1}\n```', {"a": 1}),
    ('Here you go: {"actions": [], "stop": true} — done.', {"actions": [], "stop": True}),
    ('no json here', None),
    ('', None),
    ('{broken', None),
])
def test_extract_json(text, expected):
    assert extract_json(text) == expected


# ------------------------------------------------------------ model choice
def test_resolve_model_prefers_configured_then_auto():
    config = OllamaConfig()
    client = FakeClient(config, models=["llama3.2:3b", "qwen2.5:7b", "llava:13b"])
    assert client.resolve_model("qwen2.5:7b") == "qwen2.5:7b"
    assert client.resolve_model("qwen2.5") == "qwen2.5:7b"          # partial match
    auto = client.resolve_model("auto")
    assert auto in ("llama3.2:3b", "qwen2.5:7b")                    # llava is penalised


def test_resolve_model_without_models_returns_requested():
    client = FakeClient(OllamaConfig(), models=[])
    assert client.resolve_model("auto") == ""
    assert client.resolve_model("mistral:7b") == "mistral:7b"


def test_remote_host_is_refused_by_default():
    from wifipilot.advisor import OllamaHostError
    client = OllamaClient(OllamaConfig(host="http://10.0.0.5:11434"))
    with pytest.raises(OllamaHostError) as excinfo:
        client.ping()
    assert "non-loopback" in str(excinfo.value)
    client = OllamaClient(OllamaConfig(host="http://10.0.0.5:11434", allow_remote_host=True))
    assert client._guard_host() is None      # explicitly allowed


def test_loopback_hosts_are_allowed():
    for host in ("http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434"):
        OllamaClient(OllamaConfig(host=host))._guard_host()


# ----------------------------------------------------------------- advisor
@pytest.fixture()
def advisor(session):
    session.config.ollama.enabled = True      # the fake client will answer instead
    session.config.ollama.model = "auto"
    return Advisor(session, session.config.ollama, session.bus, demo=True)


def test_plan_uses_llm_output_when_available(session, advisor):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet", publish=False)
    ap.encryption = "WPA2"
    ap.signal = -50
    advisor.client = FakeClient(
        session.config.ollama, session.bus, models=["qwen2.5:7b"],
        reply=json.dumps({
            "reasoning": "client-less AP: PMKID is the least disruptive option",
            "actions": [{"attack": "pmkid", "bssid": AP_MAC, "priority": 1,
                         "reason": "no clients seen"}],
            "stop": False,
        }))
    plan = advisor.plan()
    assert plan.source == "llm"
    assert plan.actions and plan.actions[0].attack == "pmkid"
    assert plan.model
    assert advisor.last_plan is plan
    assert session.stats.llm_tokens >= 0


def test_plan_drops_unsafe_llm_actions(session, advisor):
    ap, _ = session.upsert_ap(AP_MAC, "sae-net", publish=False)
    ap.encryption = "WPA3"
    advisor.client = FakeClient(
        session.config.ollama, session.bus, models=["qwen2.5:7b"],
        reply=json.dumps({"reasoning": "deauth it",
                          "actions": [{"attack": "handshake", "bssid": AP_MAC}]}))
    plan = advisor.plan()
    assert plan.actions == []
    assert plan.dropped


def test_plan_falls_back_to_heuristics_when_ollama_is_down(session, advisor):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet", publish=False)
    ap.encryption = "WEP"
    ap.signal = -50
    advisor.client = FakeClient(session.config.ollama, session.bus, fail=True)
    plan = advisor.plan()
    assert plan.source == "heuristic"
    assert any(action.attack == "wep_ivs" for action in plan.actions)
    assert "unavailable" in plan.reasoning.lower() or "deterministic" in plan.reasoning.lower()
    assert advisor.fallback_count == 1


def test_plan_falls_back_when_model_returns_garbage(session, advisor):
    ap, _ = session.upsert_ap(AP_MAC, "TestNet", publish=False)
    ap.encryption = "WPA2"
    advisor.client = FakeClient(session.config.ollama, session.bus,
                                models=["qwen2.5:7b"], reply="I think you should attack it")
    plan = advisor.plan()
    assert plan.source == "heuristic"
    assert "not valid JSON" in plan.reasoning


def test_ask_streams_and_reports_offline(session, advisor):
    tokens: List[str] = []
    session.bus.subscribe(["advisor.token"])
    advisor.client = FakeClient(session.config.ollama, session.bus, models=["qwen2.5:7b"],
                                reply="Attack the WPS target first.")
    answer = advisor.ask("what next?")
    assert "WPS" in answer
    assert advisor.history and advisor.history[0]["role"] == "user"

    advisor.client = FakeClient(session.config.ollama, session.bus, fail=True)
    offline = advisor.ask("still there?")
    assert "did not answer" in offline or "not reachable" in offline
    del tokens


def test_status_reports_policy_and_models(session, advisor):
    advisor.client = FakeClient(session.config.ollama, session.bus,
                                models=["qwen2.5:7b:latest"])
    advisor.check(force=True)
    status = advisor.status()
    assert status["host"].startswith("http")
    assert status["auto_think"] in (True, False)
    assert status["policy"]["allow_remote_host"] is False
    assert "pmkid" in status["actions"]
    assert isinstance(status["models"], list)


def test_triage_without_ollama_returns_empty(session, advisor):
    advisor.client = FakeClient(session.config.ollama, session.bus, fail=True)
    assert advisor.triage({"attack": "handshake"}, {}) == ""
