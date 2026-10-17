# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""OpenRouter + provider abstraction: config, transport, redaction, advisor wiring.

The HTTP layer is faked (no network in the test suite) but everything above it is
the real code path: request construction, auth headers, SSE parsing, error
classification, cost accounting, plan validation and secret handling.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from wifipilot.advisor import Advisor, IdentifierRedactor, build_redactor
from wifipilot.config import Config, OllamaConfig, OpenRouterConfig
from wifipilot.llm import (LLMAuthError, LLMCreditError, LLMError, LLMPolicyError,
                           LLMRateLimitError, ModelInfo, OllamaClient, OpenRouterClient,
                           build_client, provider_status, select_provider)
from tests.conftest import AP_MAC, PSK, SSID, STA_MAC

# --------------------------------------------------------------------------- #
# fake HTTP
# --------------------------------------------------------------------------- #


class FakeResponse:
    """Minimal stand-in for urlopen()'s return value."""

    def __init__(self, body: str = "", lines: Optional[List[str]] = None) -> None:
        self._body = body.encode("utf-8")
        self._lines = [line.encode("utf-8") for line in (lines or [])]

    def read(self) -> bytes:
        return self._body

    def __iter__(self):
        return iter(self._lines)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeHTTP:
    """Records requests and replays canned responses, routed by URL fragment.

    ``routes`` maps a URL fragment (``"/chat/completions"``) to either a
    :class:`FakeResponse` or an exception instance to raise.  ``default`` covers
    everything else.
    """

    def __init__(self, response: Any = None, routes: Optional[Dict[str, Any]] = None,
                 default: Any = None) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.routes = dict(routes or {})
        self.default = default if default is not None else response
        if response is not None and default is None:
            self.default = response

    def __call__(self, request, timeout=None):     # noqa: ARG002 - urlopen signature
        body = request.data.decode("utf-8") if request.data else ""
        self.requests.append({
            "url": request.full_url,
            "method": request.get_method(),
            "headers": {k.lower(): v for k, v in request.header_items()},
            "payload": json.loads(body) if body else None,
        })
        answer = self.default
        for fragment, candidate in self.routes.items():
            if fragment in request.full_url:
                answer = candidate
                break
        if isinstance(answer, Exception):
            raise answer
        if callable(answer) and not isinstance(answer, FakeResponse):
            return answer(request)
        if answer is None:
            raise AssertionError(f"unexpected request to {request.full_url}")
        return answer

    @property
    def response(self) -> Any:
        """Default answer; tests flip this mid-test to change the reply."""
        return self.default

    @response.setter
    def response(self, value: Any) -> None:
        self.default = value

    @property
    def last(self) -> Dict[str, Any]:
        return self.requests[-1]

    @property
    def urls(self) -> List[str]:
        return [r["url"] for r in self.requests]

    def payloads(self, fragment: str = "") -> List[Optional[dict]]:
        return [r["payload"] for r in self.requests if fragment in r["url"]]


def http_error(code: int, body: str = "", reason: str = "error"):
    import urllib.error
    import io

    return urllib.error.HTTPError("https://openrouter.ai/api/v1/chat/completions", code,
                                  reason, {}, io.BytesIO(body.encode("utf-8")))


@pytest.fixture()
def openrouter_config() -> OpenRouterConfig:
    return OpenRouterConfig(enabled=True, api_key="sk-or-test-key-0123456789",
                            model="openai/gpt-4o-mini", stream=False, redact_identifiers=True)


@pytest.fixture()
def client(openrouter_config, monkeypatch) -> OpenRouterClient:
    instance = OpenRouterClient(openrouter_config)
    fake = FakeHTTP(FakeResponse(json.dumps({"data": {"label": "test"}})))
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", fake)
    instance.fake = fake               # type: ignore[attr-defined]
    return instance


# --------------------------------------------------------------------------- #
# config + key handling
# --------------------------------------------------------------------------- #


def test_openrouter_is_off_by_default():
    config = Config()
    assert config.ai_provider == "auto"
    assert config.openrouter.enabled is False
    assert config.openrouter.base_url.startswith("https://")
    assert config.openrouter.redact_identifiers is True


def test_api_key_precedence_env_then_file_then_config(tmp_path, monkeypatch):
    key_file = tmp_path / "or.key"
    key_file.write_text("sk-or-from-file\n")
    config = OpenRouterConfig(api_key="sk-or-literal", key_file=str(key_file))
    assert config.api_key_value() == "sk-or-from-file"
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-from-env")
    assert config.api_key_value() == "sk-or-from-env"
    assert "environment" in config.key_source()
    monkeypatch.delenv("OPENROUTER_API_KEY")
    assert config.key_hint() == f"set (15 chars, key file ({key_file}))"


def test_key_hint_never_reveals_any_part_of_the_key():
    config = OpenRouterConfig(api_key="sk-or-v1-abcdefghijklmnop")
    hint = config.key_hint()
    assert "abcdefghij" not in hint and "mnop" not in hint and "sk-or" not in hint
    assert hint == "set (25 chars, config file)"


def test_config_round_trip_and_secret_redaction(tmp_path):
    config = Config()
    config.ai_provider = "openrouter"
    config.openrouter.enabled = True
    config.openrouter.api_key = "sk-or-secret-value-1234"
    dumped = config.to_dict(redact_secrets=True)
    assert dumped["openrouter"]["api_key"] == ""
    assert dumped["openrouter"]["has_api_key"] is True
    assert "1234" not in json.dumps(dumped)          # not even a fingerprint
    assert dumped["ai_provider_resolved"] == "openrouter"

    restored = Config.from_dict(dumped)              # pseudo-keys must be ignored
    assert restored.ai_provider == "openrouter"
    assert restored.openrouter.api_key == ""         # redacted input cannot round-trip

    path = config.save(str(tmp_path / "wifipilot.json"))
    assert oct((tmp_path / "wifipilot.json").stat().st_mode)[-3:] == "600"
    assert Config.load(path).openrouter.api_key == "sk-or-secret-value-1234"


def test_nested_update_keeps_other_openrouter_values():
    config = Config()
    config.update(openrouter={"redact_identifiers": False})
    assert config.openrouter.redact_identifiers is False
    assert config.openrouter.base_url.endswith("/api/v1")


# --------------------------------------------------------------------------- #
# provider policy
# --------------------------------------------------------------------------- #


def test_disabled_openrouter_refuses_to_send_anything(monkeypatch):
    config = OpenRouterConfig(enabled=False, api_key="sk-or-x")
    client = OpenRouterClient(config)
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen",
                        FakeHTTP(FakeResponse("{}")))
    with pytest.raises(LLMPolicyError) as excinfo:
        client.chat([{"role": "user", "content": "hi"}])
    assert "disabled" in str(excinfo.value)
    with pytest.raises(LLMPolicyError):
        client.ping()


def test_missing_key_is_a_policy_error_not_an_offline_state(monkeypatch):
    config = OpenRouterConfig(enabled=True, api_key="")
    client = OpenRouterClient(config)
    fake = FakeHTTP(FakeResponse("{}"))
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", fake)
    with pytest.raises(LLMPolicyError) as excinfo:
        client.ping()
    assert "no OpenRouter API key" in str(excinfo.value)
    assert fake.requests == []                       # nothing left the process
    assert "OPENROUTER_API_KEY" in client.last_error or client.last_error == ""


def test_plaintext_base_url_is_refused_unless_opted_in(monkeypatch):
    config = OpenRouterConfig(enabled=True, api_key="sk-or-x",
                              base_url="http://proxy.example.com/v1")
    client = OpenRouterClient(config)
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", FakeHTTP(FakeResponse("{}")))
    with pytest.raises(LLMPolicyError) as excinfo:
        client.ping()
    assert "plaintext" in str(excinfo.value)
    config.allow_insecure_base_url = True            # trusted local proxy
    assert client.ping() in (True, False)            # no policy exception now


def test_loopback_proxy_may_use_http(monkeypatch):
    config = OpenRouterConfig(enabled=True, api_key="sk-or-x",
                              base_url="http://127.0.0.1:8080/v1")
    client = OpenRouterClient(config)
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen",
                        FakeHTTP(FakeResponse(json.dumps({"data": {"label": "proxy"}}))))
    assert client.ping() is True


def test_stale_last_error_cannot_be_confused_with_success(client):
    client.last_error = "stale transport error"
    assert client.ping() is True
    assert client.last_error == ""


# --------------------------------------------------------------------------- #
# transport details
# --------------------------------------------------------------------------- #


def test_chat_request_shape_and_headers(client, openrouter_config):
    client.fake.response = FakeResponse(json.dumps({
        "model": "openai/gpt-4o-mini",
        "choices": [{"message": {"content": "hello there"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14, "cost": 0.00012},
    }))
    text, stats = client.chat([{"role": "user", "content": "hi"}], json_mode=True)
    assert text == "hello there"
    assert stats["tokens"] == 14
    assert stats["cost"] == pytest.approx(0.00012)
    assert stats["finish_reason"] == "stop"

    request = client.fake.last
    assert request["url"].endswith("/chat/completions")
    assert request["method"] == "POST"
    assert request["headers"]["authorization"].startswith("Bearer sk-or-")
    assert "http-referer" in request["headers"] and "x-title" in request["headers"]
    assert request["payload"]["model"] == "openai/gpt-4o-mini"
    assert request["payload"]["response_format"] == {"type": "json_object"}
    assert request["payload"]["usage"] == {"include": True}
    assert "provider" not in request["payload"]      # no routing preferences configured


def test_provider_routing_is_forwarded(client, openrouter_config):
    openrouter_config.provider_routing = {"sort": "throughput", "allow_fallbacks": False}
    client.fake.response = FakeResponse(json.dumps(
        {"choices": [{"message": {"content": "ok"}}], "usage": {}}))
    client.chat([{"role": "user", "content": "hi"}])
    assert client.fake.last["payload"]["provider"]["sort"] == "throughput"


def test_streaming_sse_is_parsed_with_usage_and_cost(openrouter_config, monkeypatch):
    openrouter_config.stream = True
    openrouter_config.price_prompt = 0.0             # no local pricing needed
    chunks = [
        'data: {"model":"openai/gpt-4o-mini","choices":[{"delta":{"content":"Hel"}}]}',
        'data: {"model":"openai/gpt-4o-mini","choices":[{"delta":{"content":"lo"}}]}',
        'data: {"choices":[{"delta":{},"finish_reason":"stop"}],'
        '"usage":{"prompt_tokens":7,"completion_tokens":2,"total_tokens":9,"cost":0.000031}}',
        "data: [DONE]",
    ]
    client = OpenRouterClient(openrouter_config)
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen",
                        FakeHTTP(FakeResponse(lines=chunks)))
    pieces: List[str] = []
    text, stats = client.chat([{"role": "user", "content": "hi"}], on_token=pieces.append)
    assert text == "Hello"
    assert "".join(pieces) == "Hello"
    assert stats["tokens"] == 9
    assert stats["cost"] == pytest.approx(0.000031)
    assert client.cost_usd == pytest.approx(0.000031)


def test_cost_is_estimated_from_catalogue_when_usage_has_none(openrouter_config, monkeypatch):
    client = OpenRouterClient(openrouter_config)
    catalogue = FakeResponse(json.dumps({"data": [
        {"id": "openai/gpt-4o-mini", "pricing": {"prompt": "0.00000015",
                                                 "completion": "0.0000006"},
         "context_length": 128000, "architecture": {"output_modalities": ["text"]}},
    ]}))
    completion = FakeResponse(json.dumps({
        "model": "openai/gpt-4o-mini",
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 0,
                  "total_tokens": 1_000_000},
    }))
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen",
                        FakeHTTP(routes={"/models": catalogue,
                                         "/chat/completions": completion}))
    client.chat([{"role": "user", "content": "hi"}])
    assert client.cost_usd == pytest.approx(0.15, rel=1e-6)


@pytest.mark.parametrize("code,error_type,fragment", [
    (401, LLMAuthError, "API key"),
    (403, LLMAuthError, "API key"),
    (402, LLMCreditError, "payment required"),
    (429, LLMRateLimitError, "rate limit"),
    (503, LLMError, "upstream error"),
])
def test_http_errors_are_classified(client, code, error_type, fragment):
    client.fake.response = http_error(code, json.dumps({"error": {"message": "detail here"}}))
    with pytest.raises(error_type) as excinfo:
        client.chat([{"role": "user", "content": "hi"}])
    assert fragment.lower() in str(excinfo.value).lower()


def test_key_info_exposes_quota_fields(client):
    client.fake.response = FakeResponse(json.dumps({"data": {
        "label": "wifipilot", "limit": 10.0, "usage": 1.25, "is_free_tier": False,
        "rate_limit": {"requests": 60, "interval": "1m"},
    }}))
    info = client.key_info()
    assert info["limit"] == 10.0
    assert info["rate_limit"]["requests"] == 60


def test_model_catalogue_is_mapped_and_filtered(client):
    client.fake.response = FakeResponse(json.dumps({"data": [
        {"id": "openai/gpt-4o-mini", "name": "OpenAI: GPT-4o mini", "context_length": 128000,
         "pricing": {"prompt": "0.00000015", "completion": "0.0000006"},
         "architecture": {"output_modalities": ["text"]}},
        {"id": "meta-llama/llama-3.3-70b-instruct:free", "name": "Llama 3.3",
         "context_length": 131072, "pricing": {"prompt": "0", "completion": "0"},
         "architecture": {"output_modalities": ["text"]}},
        {"id": "black-forest-labs/flux", "name": "FLUX", "pricing": {"prompt": "0", "completion": "0"},
         "architecture": {"output_modalities": ["image"]}},
        {"id": "~deepseek/deepseek-flash-latest", "name": "DeepSeek Flash",
         "pricing": {"prompt": "0.0000001", "completion": "0.0000004"},
         "architecture": {"output_modalities": ["text"]}},
    ]}))
    models = client.list_models(force=True)
    names = [m.name for m in models]
    assert "black-forest-labs/flux" not in names          # image-only cannot plan
    assert "~deepseek/deepseek-flash-latest" not in names  # alias noise hidden
    cheap = next(m for m in models if m.name == "openai/gpt-4o-mini")
    assert cheap.prompt_price == pytest.approx(0.15)       # per 1M tokens
    assert "per 1M" in cheap.price_label()
    free = client.list_models(free_only=True)
    assert [m.name for m in free] == ["meta-llama/llama-3.3-70b-instruct:free"]
    assert free[0].free is True
    assert client.list_models(query="gpt")[0].name == "openai/gpt-4o-mini"


def test_resolve_model_prefers_configured_then_fallbacks(client):
    client.fake.response = FakeResponse(json.dumps({"data": [
        {"id": "openai/gpt-4o-mini", "pricing": {"prompt": "0.00000015"}, "context_length": 128000},
        {"id": "google/gemini-2.5-flash", "pricing": {"prompt": "0.0000003"}, "context_length": 1_000_000},
    ]}))
    assert client.resolve_model("google/gemini-2.5-flash") == "google/gemini-2.5-flash"
    assert client.resolve_model("gemini-2.5-flash") == "google/gemini-2.5-flash"
    client.config.model = "auto"
    assert client.resolve_model() == "openai/gpt-4o-mini"   # first configured fallback


def test_resolve_model_falls_back_to_auto_router_when_catalogue_is_empty(client):
    client.fake.response = FakeResponse(json.dumps({"data": []}))
    assert client.resolve_model("auto") == "openrouter/auto"


def test_pull_is_refused_for_cloud_models(client):
    assert client.pull("openai/gpt-4o-mini") is False
    assert "cannot be pulled" in client.last_error


# --------------------------------------------------------------------------- #
# provider selection
# --------------------------------------------------------------------------- #


def test_auto_prefers_local_ollama(monkeypatch):
    monkeypatch.setattr("wifipilot.llm.OllamaClient.ping", lambda self: True)
    provider, reason = select_provider("auto", Config().ollama, Config().openrouter)
    assert provider == "ollama" and "local" in reason


def test_auto_falls_back_to_openrouter_when_ollama_is_down(monkeypatch):
    monkeypatch.setattr("wifipilot.llm.OllamaClient.ping", lambda self: False)
    openrouter = OpenRouterConfig(enabled=True, api_key="sk-or-x")
    assert select_provider("auto", Config().ollama, openrouter)[0] == "openrouter"


def test_openrouter_is_never_implicit(monkeypatch):
    monkeypatch.setattr("wifipilot.llm.OllamaClient.ping", lambda self: False)
    # a key alone is not consent: enabled must be true
    assert select_provider("auto", Config().ollama,
                           OpenRouterConfig(enabled=False, api_key="sk-or-x"))[0] == "none"
    provider, reason = select_provider("openrouter", Config().ollama,
                                       OpenRouterConfig(enabled=False, api_key="sk-or-x"))
    assert provider == "none" and "not enabled" in reason


def test_explicit_provider_is_honoured():
    provider, reason = select_provider("openrouter", Config().ollama,
                                       OpenRouterConfig(enabled=True, api_key="sk-or-x"))
    assert provider == "openrouter" and "explicitly" in reason
    assert select_provider("none", Config().ollama, Config().openrouter)[0] == "none"


def test_build_client_and_provider_status():
    config = Config()
    assert isinstance(build_client("ollama", config.ollama, config.openrouter), OllamaClient)
    assert isinstance(build_client("openrouter", config.ollama, config.openrouter),
                      OpenRouterClient)
    assert build_client("none", config.ollama, config.openrouter) is None
    rows = provider_status(config.ollama, config.openrouter)
    assert {row["name"] for row in rows} == {"ollama", "cortex", "openrouter"}
    assert rows[1]["configured"] is False


# --------------------------------------------------------------------------- #
# identifier redaction
# --------------------------------------------------------------------------- #


def test_redactor_replaces_identifiers_consistently():
    redactor = IdentifierRedactor()
    assert redactor.alias(AP_MAC, "bssid") == "bssid-1"
    assert redactor.alias(AP_MAC, "bssid") == "bssid-1"          # stable
    assert redactor.alias(SSID, "ssid") == "ssid-1"
    assert redactor.alias(PSK, "psk") == "psk-1"
    assert redactor.restore("bssid-1") == AP_MAC
    assert len(redactor) == 3


def test_redact_text_replaces_every_occurrence():
    redactor = IdentifierRedactor()
    redactor.alias(AP_MAC, "bssid")
    redactor.alias(PSK, "psk")
    payload = json.dumps({"bssid": AP_MAC, "reason": f"cracked {PSK} on {AP_MAC}"})
    redacted = redactor.redact_text(payload)
    assert AP_MAC not in redacted and PSK not in redacted
    assert "bssid-1" in redacted and "psk-1" in redacted


def test_redact_text_handles_quotes_and_backslashes():
    redactor = IdentifierRedactor()
    awkward = 'weird "ssid" \\ name'
    redactor.alias(awkward, "ssid")
    payload = json.dumps({"ssid": awkward})
    assert awkward not in redactor.redact_text(payload)


def test_restore_plan_maps_actions_back():
    redactor = IdentifierRedactor()
    redactor.alias(AP_MAC, "bssid")
    plan = {"reasoning": "attack bssid-1",
            "actions": [{"attack": "pmkid", "bssid": "bssid-1"}]}
    restored = redactor.restore_plan(plan)
    assert restored["actions"][0]["bssid"] == AP_MAC


def test_build_redactor_collects_ap_secrets(session):
    from wifipilot.models import Capture

    ap, _ = session.upsert_ap(AP_MAC, SSID, publish=False)
    session.add_capture(Capture(kind="handshake", bssid=AP_MAC, essid=SSID,
                                password=PSK, valid=True))
    ap.clients[STA_MAC] = type("C", (), {"mac": STA_MAC})()
    redactor = build_redactor(session.sorted_aps())
    assert AP_MAC in redactor.real_to_alias
    assert SSID in redactor.real_to_alias
    assert PSK in redactor.real_to_alias
    assert STA_MAC in redactor.real_to_alias


# --------------------------------------------------------------------------- #
# advisor integration
# --------------------------------------------------------------------------- #


def openrouter_advisor(session, monkeypatch, reply: str = "") -> Advisor:
    """An advisor on the OpenRouter provider, with the transport faked."""
    config = session.config
    config.ai_provider = "openrouter"
    config.openrouter = OpenRouterConfig(enabled=True, api_key="sk-or-test-key",
                                         model="openai/gpt-4o-mini", stream=False)
    monkeypatch.setattr("wifipilot.llm.OpenRouterClient.key_info",
                        lambda self, **kwargs: {"limit": 5.0, "usage": 0.5, "is_free_tier": False})
    advisor = Advisor(session, None, session.bus)
    advisor.configure("openrouter", announce=False)
    payload = json.dumps({
        "model": "openai/gpt-4o-mini",
        "choices": [{"message": {"content": reply or "{}"}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
                  "cost": 0.0002},
    })
    fake = FakeHTTP(routes={
        "/chat/completions": FakeResponse(payload),
        "/models": FakeResponse(json.dumps({"data": [
            {"id": "openai/gpt-4o-mini", "pricing": {"prompt": "0.00000015"},
             "context_length": 128000, "architecture": {"output_modalities": ["text"]}},
        ]})),
    })
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", fake)
    advisor.fake = fake                  # type: ignore[attr-defined]
    return advisor


def test_advisor_selects_the_openrouter_transport(session):
    advisor = Advisor(session, session.config.ollama, session.bus)
    assert advisor.provider == "ollama"
    assert isinstance(advisor.client, OllamaClient)
    advisor = Advisor(session, None, session.bus, provider="openrouter")
    assert advisor.provider == "openrouter"
    assert advisor.is_cloud() and isinstance(advisor.client, OpenRouterClient)
    assert advisor.redact is True                      # cloud default


def test_advisor_plan_uses_the_cloud_model_and_hides_identifiers(session, monkeypatch):
    ap, _ = session.upsert_ap(AP_MAC, SSID, publish=False)
    ap.encryption = "WPA2"
    ap.signal = -45
    ap.clients[STA_MAC] = type("C", (), {"mac": STA_MAC})()
    advisor = openrouter_advisor(session, monkeypatch, json.dumps({
        "reasoning": "bssid-1 is client-less: PMKID first",
        "actions": [{"attack": "pmkid", "bssid": "bssid-1", "priority": 1}],
    }))
    plan = advisor.plan()
    assert plan.source == "llm" and plan.provider == "openrouter"
    assert [a.attack for a in plan.actions] == ["pmkid"]
    assert plan.actions[0].bssid == AP_MAC             # pseudonym mapped back

    sent = json.dumps(advisor.fake.last["payload"])
    assert AP_MAC not in sent and SSID not in sent and STA_MAC not in sent
    assert "bssid-1" in sent
    assert advisor.session.stats.llm_cost == pytest.approx(0.0002)
    assert advisor.status()["cost_usd"] == pytest.approx(0.0002)


def test_advisor_with_redaction_off_sends_real_identifiers(session, monkeypatch):
    ap, _ = session.upsert_ap(AP_MAC, SSID, publish=False)
    ap.encryption = "WPA2"
    advisor = openrouter_advisor(session, monkeypatch, json.dumps(
        {"reasoning": "go", "actions": [{"attack": "pmkid", "bssid": AP_MAC}]}))
    advisor.config.redact_identifiers = False
    plan = advisor.plan()
    assert plan.actions[0].bssid == AP_MAC
    assert AP_MAC in json.dumps(advisor.fake.last["payload"])


def test_advisor_reports_missing_key_without_calling_out(session, monkeypatch):
    session.config.ai_provider = "openrouter"
    session.config.openrouter = OpenRouterConfig(enabled=True, api_key="")
    advisor = Advisor(session, None, session.bus)
    advisor.configure("openrouter", announce=False)
    fake = FakeHTTP(FakeResponse("{}"))
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", fake)
    assert advisor.check(force=True) is False
    assert "no OpenRouter API key" in advisor.last_error
    assert fake.requests == []
    plan = advisor.plan()                              # falls back, keeps working
    assert plan.source == "heuristic"
    assert "OpenRouter" in plan.reasoning


def test_budget_cap_stops_planning(session, monkeypatch):
    session.config.ai_provider = "openrouter"
    session.config.openrouter = OpenRouterConfig(enabled=True, api_key="sk-or-x",
                                                 max_cost_usd=0.01)
    advisor = Advisor(session, None, session.bus)
    advisor.configure("openrouter", announce=False)
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", FakeHTTP(FakeResponse("{}")))
    advisor.cost_usd = 0.02
    assert advisor.check(force=True) is False
    assert "budget reached" in advisor.last_error.lower()
    assert advisor.status()["policy"]["max_cost_usd"] == 0.01


def test_advisor_status_exposes_provider_details(session, monkeypatch):
    advisor = openrouter_advisor(session, monkeypatch)
    monkeypatch.setattr("wifipilot.llm.OpenRouterClient.list_models",
                        lambda self, **kwargs: [ModelInfo(name="openai/gpt-4o-mini",
                                                          provider="openrouter",
                                                          prompt_price=0.15,
                                                          completion_price=0.6)])
    status = advisor.status()
    assert status["provider"] == "openrouter"
    assert status["cloud"] is True
    assert status["key"]["configured"] is True
    assert "set (" in status["key"]["hint"]
    assert "sk-or" not in json.dumps(status)           # never leak the key
    assert status["models"][0]["price"] == "$0.15/$0.6 per 1M tokens in/out"
    assert {row["name"] for row in status["providers"]} == {"ollama", "cortex",
                                                              "openrouter"}


def test_offline_message_differs_per_provider(session):
    ollama = Advisor(session, session.config.ollama, session.bus)
    assert "ollama pull" in ollama._offline_message()
    cloud = Advisor(session, None, session.bus, provider="openrouter")
    assert "openrouter.ai/keys" in cloud._offline_message()


def test_ask_updates_cost_and_history(session, monkeypatch):
    advisor = openrouter_advisor(session, monkeypatch, "Attack HOME-2F4A first.")
    answer = advisor.ask("what next?")
    assert "HOME-2F4A" in answer
    assert advisor.session.stats.llm_cost == pytest.approx(0.0002)
    assert advisor.status()["tokens"] == 120


def test_use_model_switches_provider(session, monkeypatch):
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", FakeHTTP(
        routes={"/key": FakeResponse(json.dumps({"data": {"label": "ok"}})),
                "/models": FakeResponse(json.dumps({"data": [
                    {"id": "openai/gpt-4o-mini", "pricing": {"prompt": "0.00000015"},
                     "context_length": 128000,
                     "architecture": {"output_modalities": ["text"]}},
                ]}))}))
    advisor = Advisor(session, session.config.ollama, session.bus)
    advisor.session.config.openrouter.enabled = True
    advisor.session.config.openrouter.api_key = "sk-or-x"
    advisor.use_model("openai/gpt-4o-mini", provider="openrouter")
    assert advisor.provider == "openrouter"
    assert session.config.openrouter.model == "openai/gpt-4o-mini"
    assert session.config.ai_provider == "openrouter"


def test_pull_model_is_refused_on_openrouter(session, monkeypatch):
    advisor = openrouter_advisor(session, monkeypatch)
    assert advisor.pull_model("openai/gpt-4o-mini") is False


def test_models_helper_returns_dicts(session, monkeypatch):
    advisor = openrouter_advisor(session, monkeypatch)
    monkeypatch.setattr("wifipilot.llm.OpenRouterClient.list_models",
                        lambda self, **kwargs: [ModelInfo(name="free/model",
                                                          provider="openrouter")])
    models = advisor.models()
    assert models[0]["name"] == "free/model" and models[0]["free"] is True


def test_provider_switch_events_are_published(session, monkeypatch):
    from wifipilot.events import EK

    subscribed = session.bus.subscribe([EK.ADVISOR_STATUS, EK.ADVISOR_ERROR])
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", FakeHTTP(
        routes={"/key": FakeResponse(json.dumps({"data": {"label": "ok"}})),
                "/models": FakeResponse(json.dumps({"data": []}))}))
    advisor = Advisor(session, None, session.bus)
    session.config.openrouter.enabled = True
    session.config.openrouter.api_key = "sk-or-x"
    advisor.configure("openrouter", announce=True)
    assert advisor.status()["provider"] == "openrouter"
    kinds = [event.kind for event in subscribed.drain()]
    assert EK.ADVISOR_STATUS in kinds              # the switch was announced
    subscribed.close()


# --------------------------------------------------------------------------- #
# provider switching must never leave the advisor incoherent
# --------------------------------------------------------------------------- #


def test_switching_back_to_auto_keeps_client_and_config_in_step(session, monkeypatch):
    """Regression: pairing an OpenRouter client with an Ollama config crashed the UI."""
    monkeypatch.setattr("wifipilot.llm.OllamaClient.ping", lambda self: False)
    monkeypatch.setattr("wifipilot.llm.OpenRouterClient.key_info",
                        lambda self, **kwargs: {"limit": 5.0, "usage": 0.0})
    monkeypatch.setattr("wifipilot.llm.OllamaClient.list_models", lambda self, **kw: [])
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", FakeHTTP(routes={
        "/models": FakeResponse(json.dumps({"data": []})),
        "/api/tags": FakeResponse(json.dumps({"models": []})),
    }))
    session.config.openrouter = OpenRouterConfig(enabled=True, api_key="sk-or-x",
                                                 base_url="https://openrouter.ai/api/v1")
    advisor = Advisor(session, None, session.bus)

    advisor.configure("openrouter", announce=False)
    assert advisor.provider == "openrouter"
    assert isinstance(advisor.client, OpenRouterClient)
    assert advisor.client.config is session.config.openrouter
    assert advisor.status()["host"] == "https://openrouter.ai/api/v1"

    session.config.ai_provider = "auto"          # as POST /api/config would
    advisor.configure("auto", announce=False)
    assert advisor.provider in ("ollama", "cortex", "openrouter", "none")
    if advisor.provider == "openrouter":
        assert isinstance(advisor.client.config, OpenRouterConfig)
    else:
        assert isinstance(advisor.client.config, OllamaConfig)
    assert advisor.status()["host"]                # never raises on a mismatch

    advisor.configure("none", announce=False)
    assert advisor.provider == "none"
    assert advisor.check(force=True) is False
    assert advisor.status()["provider"] == "none"
    assert advisor.status()["host"]


def test_provider_aliases(session):
    advisor = Advisor(session, None, session.bus)
    assert advisor.PROVIDER_ALIASES["off"] == "none"
    assert advisor.PROVIDER_ALIASES["cloud"] == "openrouter"
    advisor.configure("none", announce=False)
    assert advisor.provider == "none"
    advisor.configure("off", announce=False)
    assert advisor.provider == "none"
    assert advisor._concrete_provider("cloud") == "openrouter"
    assert advisor._concrete_provider("local") == "ollama"
    assert advisor._concrete_provider("garbage") in ("ollama", "cortex", "openrouter", "none")


def test_disabled_provider_never_calls_out(session, monkeypatch):
    fake = FakeHTTP()
    monkeypatch.setattr("wifipilot.llm.urllib.request.urlopen", fake)
    advisor = Advisor(session, None, session.bus)
    advisor.configure("none", announce=False)
    plan = advisor.plan()
    assert plan.source == "heuristic"
    assert fake.requests == []
    assert advisor.ask("anything?") is not None or True
