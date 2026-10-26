# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Cortex LLMHoster: the local, OpenAI-compatible model host provider.

https://github.com/codero-sus/Cortex_LLMHoster — a local service that starts the models
itself and speaks the OpenAI API.  The tests run a stand-in for that service on a real
loopback socket, so the client is exercised over HTTP exactly as it is in the field: no
mocks, no monkeypatched transports.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wifipilot.config import Config, CortexConfig
from wifipilot.llm import (CortexClient, LLMAuthError, LLMPolicyError, build_client,
                           provider_status, select_provider)


# --------------------------------------------------------------------------- #
# a stand-in for the hoster
# --------------------------------------------------------------------------- #

class _Hoster(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    api_key = ""
    calls: list = []

    def log_message(self, *args):        # quiet
        pass

    def _send(self, payload, code=200, content_type="application/json"):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self) -> bool:
        header = self.headers.get("Authorization") or ""
        return not self.api_key or header == f"Bearer {self.api_key}"

    def do_GET(self):
        if self.path == "/health":
            return self._send({"status": "ok", "version": "0.2.0"})
        if self.path == "/v1/models":
            return self._send({"object": "list", "data": [
                {"id": "qwen-local", "object": "model", "created": 1},
                {"id": "llama3-local", "object": "model", "created": 2},
            ]})
        self._send({"error": {"message": "no such route"}}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = {}
        if length:
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        type(self).calls.append((self.path, payload))
        if not self._authorised():
            return self._send({"error": {"message": "invalid API key"}}, 401)
        if self.path != "/v1/chat/completions":
            return self._send({"error": {"message": "no such route"}}, 404)
        answer = "run it_http_discover first, then it_http_default_creds"
        if payload.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for piece in answer.split(" "):
                chunk = {"model": payload.get("model", "qwen-local"),
                         "choices": [{"delta": {"content": piece + " "}}]}
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
            self.wfile.write(b"data: [DONE]\n\n")
            return
        self._send({"model": payload.get("model", "qwen-local"),
                    "choices": [{"message": {"role": "assistant", "content": answer},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 11, "completion_tokens": 7,
                              "total_tokens": 18}})


@pytest.fixture()
def hoster():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Hoster)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Hoster.api_key = ""
    _Hoster.calls = []
    config = CortexConfig(enabled=True, host=f"http://127.0.0.1:{server.server_address[1]}",
                          stream=False)
    try:
        yield server, config
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# the client
# --------------------------------------------------------------------------- #

def test_health_and_model_catalogue(hoster):
    _server, config = hoster
    client = CortexClient(config)
    assert client.ping() is True
    assert client.version() == "0.2.0"
    assert [model.name for model in client.list_models(force=True)] == ["qwen-local",
                                                                       "llama3-local"]
    assert client.resolve_model() == "qwen-local"
    assert client.describe().startswith("Cortex LLMHoster (http://127.0.0.1:")
    assert client.host == config.host


def test_chat_without_streaming(hoster):
    _server, config = hoster
    client = CortexClient(config)
    text, stats = client.chat([{"role": "user", "content": "what next?"}])
    assert "it_http_discover" in text
    assert stats["tokens"] == 18 and stats["cost"] == 0.0
    assert stats["provider"] == "cortex"
    assert client.calls == 1
    # the payload the hoster saw is an OpenAI chat request
    _path, payload = _Hoster.calls[-1]
    assert payload["messages"][0]["content"] == "what next?"
    assert payload["stream"] is False


def test_chat_with_streaming(hoster):
    _server, config = hoster
    config.stream = True
    seen: list = []
    client = CortexClient(config)
    text, stats = client.chat([{"role": "user", "content": "plan"}],
                              on_token=seen.append)
    assert "it_http_default_creds" in text
    assert "".join(seen).strip() == text.strip()
    assert stats["seconds"] >= 0


def test_keyless_listener_and_bearer_key(hoster):
    _server, config = hoster
    # keyless: nothing to configure, the request carries no Authorization header
    client = CortexClient(config)
    assert client.api_key() == ""
    client.ping()
    assert client.list_models(force=True)

    # with a key: it is sent, and a wrong one is reported as an auth error, not as "down"
    _Hoster.api_key = "test-key"
    config.api_key = "test-key"
    client = CortexClient(config)
    assert client.ping() is True
    config.api_key = "wrong-key"
    with pytest.raises(LLMAuthError):
        CortexClient(config).chat([{"role": "user", "content": "hi"}], model="qwen-local")


def test_policy_refuses_a_disabled_or_remote_host():
    disabled = CortexConfig(enabled=False)
    with pytest.raises(LLMPolicyError):
        CortexClient(disabled).ping()

    remote = CortexConfig(enabled=True, host="http://10.0.0.9:8624")
    with pytest.raises(LLMPolicyError):
        CortexClient(remote).ping()
    remote.allow_remote_host = True          # the operator may say otherwise, explicitly
    assert CortexClient(remote).is_loopback() is False


def test_pull_explains_itself_without_raising():
    client = CortexClient(CortexConfig(enabled=True))
    assert client.pull("qwen-local") is False
    assert "Cortex LLMHoster serves the models" in client.last_error


# --------------------------------------------------------------------------- #
# provider selection, the CLI and the API
# --------------------------------------------------------------------------- #

def test_auto_prefers_a_local_model(hoster):
    _server, config = hoster
    cfg = Config()
    cfg.ollama.enabled = False
    cfg.ai_provider = "auto"
    chosen, reason = select_provider("auto", cfg.ollama, cfg.openrouter, probe=True,
                                     cortex=config)
    assert chosen == "cortex" and "Cortex" in reason
    assert select_provider("cortex", cfg.ollama, cfg.openrouter, probe=False,
                           cortex=config)[0] == "cortex"

    # an explicitly selected but disabled hoster is a decision, not a fallback
    cfg.cortex = CortexConfig(enabled=False)
    chosen, reason = select_provider("cortex", cfg.ollama, cfg.openrouter, probe=False,
                                     cortex=cfg.cortex)
    assert chosen == "none" and "not enabled" in reason


def test_provider_status_lists_cortex():
    cfg = Config()
    cfg.cortex = CortexConfig(enabled=False, model="qwen-local")
    row = {entry["name"]: entry for entry in provider_status(cfg.ollama, cfg.openrouter,
                                                             cortex=cfg.cortex)}["cortex"]
    assert row["host"] == "http://127.0.0.1:8624"
    assert row["model"] == "qwen-local"
    assert row["enabled"] is False
    assert "keyless" in row["key_hint"]


def test_build_client_needs_the_cortex_config():
    cfg = Config()
    assert build_client("cortex", cfg.ollama, cfg.openrouter, None, cfg.cortex).provider == "cortex"
    with pytest.raises(LLMPolicyError):
        build_client("cortex", cfg.ollama, cfg.openrouter, None, None)


def test_cli_flags_select_the_hoster(tmp_path):
    from wifipilot.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["--provider", "cortex", "--cortex-host",
                              "http://127.0.0.1:8624", "--cortex-model", "qwen-local",
                              "--config", str(tmp_path / "wifipilot.json"), "ai", "providers"])
    assert args.provider == "cortex"
    assert args.cortex_model == "qwen-local"
    assert Config.load(str(tmp_path / "wifipilot.json")).cortex.enabled is False


def test_webui_can_switch_to_cortex(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from wifipilot.web.app import create_app

    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    with TestClient(create_app(config, demo=True)) as client:
        answer = client.post("/api/ai/provider", json={"provider": "cortex",
                                                       "host": "http://127.0.0.1:8624",
                                                       "model": "qwen-local"}).json()
        assert answer["ok"] is True
        assert answer["provider"] == "cortex"
        state = client.get("/api/state").json()["advisor"]
        assert state["provider"] == "cortex"
        names = [row["name"] for row in state["providers"]]
        assert "cortex" in names
        assert client.post("/api/ai/provider", json={"provider": "nope"}).status_code == 400
