"""OpenRouter integration over *real* HTTP against a local mock of the API.

The unit tests in ``test_openrouter.py`` fake ``urlopen``; this module starts an
actual HTTP server that speaks OpenRouter's wire format (``/models``, ``/key``,
``/chat/completions`` with SSE streaming) and points a real
:class:`OpenRouterClient` at it.  That exercises the parts a fake cannot: the
transport, header serialisation, SSE chunking over a socket, and the advisor's
end-to-end planning path.

No external network access is required — the mock lives on loopback.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

import pytest

from wifipilot.advisor import Advisor
from wifipilot.config import OpenRouterConfig
from wifipilot.llm import (LLMAuthError, LLMCreditError, OpenRouterClient)
from tests.conftest import AP_MAC, SSID, STA_MAC

CATALOGUE = {
    "data": [
        {"id": "openai/gpt-4o-mini", "name": "OpenAI: GPT-4o mini", "context_length": 128000,
         "pricing": {"prompt": "0.00000015", "completion": "0.0000006"},
         "architecture": {"output_modalities": ["text"]}},
        {"id": "meta-llama/llama-3.3-70b-instruct:free", "name": "Llama 3.3 (free)",
         "context_length": 131072, "pricing": {"prompt": "0", "completion": "0"},
         "architecture": {"output_modalities": ["text"]}},
    ]
}

KEY_INFO = {"data": {"label": "wifipilot-test", "limit": 10.0, "usage": 0.25,
                     "is_free_tier": False, "rate_limit": {"requests": 60, "interval": "1m"}}}


class MockOpenRouter(BaseHTTPRequestHandler):
    """Minimal OpenRouter-compatible endpoint (see the real API docs)."""

    protocol_version = "HTTP/1.1"
    seen: List[Dict[str, Any]] = []
    status = 200
    catalogue: Dict[str, Any] = CATALOGUE
    key_info: Dict[str, Any] = KEY_INFO
    #: text the fake model returns for a completion
    reply = '{"reasoning": "test", "actions": []}'
    require_auth = True
    stream_usage = {"prompt_tokens": 40, "completion_tokens": 12, "total_tokens": 52,
                    "cost": 0.00021}

    def log_message(self, *args):        # keep the test output clean
        return

    def _body(self) -> Optional[dict]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return None
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, chunks: List[str]) -> None:
        body = "".join(chunks).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self, payload: Optional[dict]) -> None:
        MockOpenRouter.seen.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization", ""),
            "referer": self.headers.get("HTTP-Referer", ""),
            "title": self.headers.get("X-Title", ""),
            "payload": payload,
        })

    def _authorized(self) -> bool:
        if not self.require_auth:
            return True
        header = self.headers.get("Authorization", "")
        return header.startswith("Bearer ") and len(header) > 20

    def do_GET(self) -> None:            # noqa: N802 - http.server API
        self._record(None)
        if not self._authorized():
            return self._json({"error": {"message": "No auth credentials found",
                                         "code": 401}}, 401)
        if self.path.startswith("/api/v1/models"):
            return self._json(self.catalogue)
        if self.path.startswith("/api/v1/key"):
            return self._json(self.key_info)
        if self.path.startswith("/api/v1/credits"):
            return self._json({"data": {"total_credits": 10.0, "total_usage": 0.25}})
        return self._json({"error": {"message": "not found", "code": 404}}, 404)

    def do_POST(self) -> None:           # noqa: N802 - http.server API
        payload = self._body()
        self._record(payload)
        if self.status != 200:
            code, message = self.status, "injected failure"
            if code == 402:
                message = "Insufficient credits"
            if code == 429:
                message = "Rate limit exceeded"
            return self._json({"error": {"message": message, "code": code}}, code)
        if not self._authorized():
            return self._json({"error": {"message": "No auth credentials found",
                                         "code": 401}}, 401)
        if not self.path.startswith("/api/v1/chat/completions"):
            return self._json({"error": {"message": "not found", "code": 404}}, 404)
        if payload and payload.get("stream"):
            text = self.reply
            half = max(1, len(text) // 2)
            chunks = [
                "data: " + json.dumps({"model": payload.get("model"),
                                       "choices": [{"delta": {"content": text[:half]}}]}) + "\n\n",
                "data: " + json.dumps({"model": payload.get("model"),
                                       "choices": [{"delta": {"content": text[half:]}}]}) + "\n\n",
                "data: " + json.dumps({"choices": [{"delta": {}, "finish_reason": "stop"}],
                                       "usage": self.stream_usage}) + "\n\n",
                "data: [DONE]\n\n",
            ]
            return self._sse(chunks)
        return self._json({
            "id": "gen-test", "model": payload.get("model"),
            "choices": [{"message": {"role": "assistant", "content": self.reply},
                         "finish_reason": "stop"}],
            "usage": self.stream_usage,
        })


@pytest.fixture()
def mock_api():
    MockOpenRouter.seen = []
    MockOpenRouter.status = 200
    MockOpenRouter.require_auth = True
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockOpenRouter)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/api/v1"
    server.shutdown()
    server.server_close()


def make_client(mock_api, **overrides) -> OpenRouterClient:
    settings: Dict[str, Any] = {"enabled": True, "api_key": "sk-or-mock-1234567890abcdef",
                                "base_url": mock_api, "stream": False}
    settings.update(overrides)
    return OpenRouterClient(OpenRouterConfig(**settings))


# --------------------------------------------------------------------------- #
# transport over a real socket
# --------------------------------------------------------------------------- #


def test_health_check_and_credentials_over_http(mock_api):
    client = make_client(mock_api)
    assert client.ping() is True
    info = client.key_info()
    assert info["limit"] == 10.0 and info["usage"] == 0.25
    assert MockOpenRouter.seen[0]["authorization"].startswith("Bearer sk-or-mock")
    assert MockOpenRouter.seen[0]["title"] == "wifipilot"


def test_model_catalogue_over_http(mock_api):
    client = make_client(mock_api)
    models = client.list_models(force=True)
    names = [m.name for m in models]
    assert set(names) == {"openai/gpt-4o-mini", "meta-llama/llama-3.3-70b-instruct:free"}
    assert names[0].endswith(":free")                  # cheapest first
    assert client.resolve_model("auto") == "openai/gpt-4o-mini"
    assert client.list_models(free_only=True)[0].free is True
    assert client.list_models(query="gpt")[0].name == "openai/gpt-4o-mini"


def test_non_streaming_completion_over_http(mock_api):
    MockOpenRouter.reply = "planned: attack the WPS target"
    client = make_client(mock_api)
    text, stats = client.chat([{"role": "user", "content": "hi"}],
                              model="openai/gpt-4o-mini")
    assert text == "planned: attack the WPS target"
    assert stats["tokens"] == 52
    assert client.cost_usd == pytest.approx(0.00021)
    request = MockOpenRouter.seen[-1]
    assert request["payload"]["messages"] == [{"role": "user", "content": "hi"}]


def test_streaming_completion_over_http(mock_api):
    MockOpenRouter.reply = "Pixie-Dust first, then a deauth."
    client = make_client(mock_api, stream=True)
    pieces: List[str] = []
    text, stats = client.chat([{"role": "user", "content": "hi"}],
                              model="openai/gpt-4o-mini", on_token=pieces.append)
    assert text == "Pixie-Dust first, then a deauth."
    assert "".join(pieces) == text                    # streamed in pieces
    assert len(pieces) > 1
    assert stats["cost"] == pytest.approx(0.00021)


def test_bad_key_is_reported_as_an_auth_error(mock_api):
    MockOpenRouter.require_auth = False
    MockOpenRouter.status = 401
    client = make_client(mock_api)
    with pytest.raises(LLMAuthError):
        client.chat([{"role": "user", "content": "hi"}], model="openai/gpt-4o-mini")
    MockOpenRouter.status = 402
    with pytest.raises(LLMCreditError):
        client.chat([{"role": "user", "content": "hi"}], model="openai/gpt-4o-mini")


# --------------------------------------------------------------------------- #
# advisor end to end
# --------------------------------------------------------------------------- #


def test_advisor_plans_over_http_with_pseudonymised_identifiers(session, mock_api):
    session.config.ai_provider = "openrouter"
    session.config.openrouter = OpenRouterConfig(
        enabled=True, api_key="sk-or-mock-1234567890abcdef", base_url=mock_api,
        model="openai/gpt-4o-mini", stream=False, redact_identifiers=True,
        think_interval=10.0)
    ap, _ = session.upsert_ap(AP_MAC, SSID, publish=False)
    ap.encryption = "WPA2"
    ap.signal = -48
    ap.clients[STA_MAC] = type("C", (), {"mac": STA_MAC})()
    MockOpenRouter.reply = json.dumps({
        "reasoning": "bssid-1 has no clients: PMKID is the least disruptive choice",
        "actions": [{"attack": "pmkid", "bssid": "bssid-1", "priority": 1,
                     "reason": "client-less"}],
        "stop": False,
    })

    advisor = Advisor(session, None, session.bus)
    advisor.configure("openrouter", announce=False)
    assert advisor.client.host == mock_api
    plan = advisor.plan()

    assert plan.source == "llm"
    assert plan.provider == "openrouter"
    assert [(a.attack, a.bssid) for a in plan.actions] == [("pmkid", AP_MAC)]

    prompt = json.dumps(MockOpenRouter.seen[-1]["payload"])
    assert AP_MAC not in prompt and SSID not in prompt and STA_MAC not in prompt
    assert "bssid-1" in prompt

    status = advisor.status()
    assert status["cloud"] is True and status["available"] is True
    assert status["cost_usd"] == pytest.approx(0.00021)
    assert session.stats.llm_cost == pytest.approx(0.00021)
    assert "sk-or" not in json.dumps(status)


def test_advisor_ask_over_http(session, mock_api):
    session.config.ai_provider = "openrouter"
    session.config.openrouter = OpenRouterConfig(
        enabled=True, api_key="sk-or-mock-1234567890abcdef", base_url=mock_api,
        model="openai/gpt-4o-mini", stream=True)
    MockOpenRouter.reply = "Attack the WPS-enabled target first."
    advisor = Advisor(session, None, session.bus)
    advisor.configure("openrouter", announce=False)
    answer = advisor.ask("what should I do next?")
    assert "WPS" in answer
    assert session.stats.llm_cost > 0


def test_advisor_surfaces_an_out_of_credit_account(session, mock_api):
    from wifipilot.events import EK

    session.config.ai_provider = "openrouter"
    session.config.openrouter = OpenRouterConfig(
        enabled=True, api_key="sk-or-mock-1234567890abcdef", base_url=mock_api,
        model="openai/gpt-4o-mini")
    MockOpenRouter.status = 402
    subscription = session.bus.subscribe([EK.ADVISOR_ERROR])
    advisor = Advisor(session, None, session.bus)
    advisor.configure("openrouter", announce=False)
    assert advisor.check(force=True) in (True, False)
    plan = advisor.plan()                    # must still produce something useful
    assert plan.source in ("llm", "heuristic")
    assert advisor.last_error
    subscription.close()
    MockOpenRouter.status = 200


def test_cli_can_run_against_the_mock_gateway(mock_api, tmp_path, monkeypatch, capsys):
    """`wifipilot ai status --provider openrouter` with a key in the environment."""
    from wifipilot.cli import apply_cli_config, build_parser, command_ai

    class Console:
        lines: List[str] = []

        def print(self, *items, **kwargs):
            Console.lines.append(" ".join(str(i) for i in items))

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-mock-1234567890abcdef")
    monkeypatch.chdir(tmp_path)
    # global flags come before the subcommand in wifipilot's CLI
    args = build_parser().parse_args([
        "--json", "--openrouter-base-url", mock_api,
        "ai", "--provider", "openrouter", "status",
    ])
    config = apply_cli_config(args)
    assert config.ai_provider == "openrouter"
    assert config.openrouter.enabled is True
    assert config.openrouter.base_url == mock_api
    assert command_ai(args, config, Console()) == 0
    payload = json.loads(capsys.readouterr().out)      # --json writes to stdout
    assert payload["provider"] == "openrouter"
    assert payload["available"] is True
    assert payload["key"]["configured"] is True
    assert "sk-or" not in json.dumps(payload)
