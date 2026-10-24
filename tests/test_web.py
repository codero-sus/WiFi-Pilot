# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Web API tests (FastAPI TestClient) — the browser UI's whole control surface."""

from __future__ import annotations

import json
import sys

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient      # noqa: E402

from wifipilot.config import Config             # noqa: E402
from wifipilot.web.app import create_app        # noqa: E402


@pytest.fixture()
def client(tmp_path):
    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    config.scan_time = 1
    app = create_app(config, demo=True, authorized=False)
    with TestClient(app) as test_client:
        yield test_client


def test_index_and_health(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "wifipilot" in page.text and "AI advisor" in page.text
    health = client.get("/healthz").json()
    assert health["ok"] and health["demo"] is True


def test_static_assets_are_served(client):
    js = client.get("/static/app.js")
    css = client.get("/static/style.css")
    assert js.status_code == 200 and "WebSocket" in js.text
    assert css.status_code == 200 and "tabpane" in css.text


def test_state_snapshot_has_everything_the_ui_needs(client):
    state = client.get("/api/state").json()
    for key in ("session", "stats", "access_points", "engine", "advisor", "attacks",
                "config", "loot", "progress", "tools", "wordlists"):
        assert key in state, key
    assert state["session"]["demo"] is True
    assert isinstance(state["access_points"], list)
    assert state["config"]["demo"] is True
    assert state["advisor"]["policy"]["allow_remote_host"] is False


def test_tools_and_interfaces(client):
    tools = client.get("/api/tools").json()
    assert "tools" in tools and "capabilities" in tools
    assert "missing_required" in tools
    interfaces = client.get("/api/interfaces").json()
    assert "interfaces" in interfaces


def test_config_update_and_attacks_toggle(client):
    response = client.post("/api/config", json={"attacks": ["pmkid", "handshake"],
                                                "stealth": True})
    assert response.status_code == 200
    config = response.json()["config"]
    assert config["attacks"] == ["pmkid", "handshake"] and config["stealth"] is True
    state = client.get("/api/state").json()
    assert state["session"]["stealth"] is True
    enabled = {a["name"]: a["enabled"] for a in state["attacks"]}
    assert enabled["pmkid"] and not enabled["wps_pixie"]


def test_scan_control(client):
    assert client.post("/api/scan", json={"action": "start"}).json()["ok"]
    assert client.post("/api/scan", json={"action": "stop"}).json()["scanning"] is False


def test_ai_endpoints_work_without_ollama(client):
    think = client.post("/api/ai/think", json={})
    assert think.status_code == 200
    plan = think.json()["plan"]
    assert plan["source"] in ("llm", "heuristic")
    assert "actions" in plan and "reasoning" in plan
    chat = client.post("/api/ai/chat", json={"message": "what next?"})
    assert chat.status_code == 200
    status = client.get("/api/state").json()["advisor"]
    assert status["enabled"] is False or "model" in status
    toggle = client.post("/api/ai/toggle", json={"autothink": False})
    assert toggle.json()["auto_think"] is False


def test_campaign_start_requires_authorisation_in_live_mode(tmp_path):
    config = Config()
    config.demo = False
    config.authorized = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    app = create_app(config, demo=False, authorized=False)
    with TestClient(app) as live:
        response = live.post("/api/campaign", json={"targets": []})
        assert response.status_code == 403
        assert "authoris" in response.json()["detail"]


def test_attack_endpoint_validates_input(client):
    assert client.post("/api/attack", json={"bssid": "not-a-mac"}).status_code == 400
    assert client.post("/api/attack", json={"bssid": "aa:bb:cc:dd:ee:ff",
                                            "attack": "rm -rf /"}).status_code == 400
    unknown = client.post("/api/attack", json={"bssid": "aa:bb:cc:dd:ee:ff",
                                               "attack": "pmkid"})
    assert unknown.status_code == 200
    assert "unknown target" in unknown.json()["message"]


def test_report_and_export(client):
    export = client.get("/api/export")
    assert export.status_code == 200
    assert "access_points" in export.json()
    report = client.get("/api/report")
    assert report.status_code == 200
    assert "wifipilot engagement" in report.text


def test_file_download_is_restricted(client):
    forbidden = client.get("/api/file", params={"path": "/etc/passwd"})
    assert forbidden.status_code == 403
    missing = client.get("/api/file", params={"path": "/tmp/definitely-not-here.cap"})
    assert missing.status_code in (403, 404)


def test_events_endpoint(client):
    events = client.get("/api/events").json()["events"]
    assert isinstance(events, list)


def test_websocket_streams_state_and_events(client):
    with client.websocket_connect("/ws") as websocket:
        first = json.loads(websocket.receive_text())
        assert first["kind"] == "state"
        assert "access_points" in first["data"]
        client.post("/api/ai/think", json={})
        for _ in range(6):
            message = json.loads(websocket.receive_text())
            assert message["kind"] in ("state", "event")
            if message["kind"] == "event" and message["event"]["kind"] == "advisor.plan":
                break


def _one_real_adaptor():
    """What ``iw dev`` finds on an actual laptop (CI machines have none)."""
    from wifipilot.deps import WirelessInterface
    return [WirelessInterface(
        name="wlan0", phy="phy0", driver="ath9k", mode="managed",
        bands=["2.4GHz", "5GHz"], supports_monitor=True,
        supports_injection=True,
    )]


def test_tools_summary_is_json_serializable_with_a_real_interface():
    # regression: ToolRegistry.summary() embedded raw WirelessInterface
    # dataclasses; the WebSocket's plain json.dumps died with "Object of
    # type WirelessInterface is not JSON serializable" on any machine that
    # actually has a WiFi adaptor (empty list on CI hid it for months).
    from unittest import mock

    from wifipilot.deps import registry

    with mock.patch("wifipilot.deps.list_interfaces", return_value=_one_real_adaptor()):
        payload = json.dumps(registry.summary())           # must not raise
    iface = json.loads(payload)["interfaces"][0]
    # the keys static/app.js renders (name/driver/bands/monitor/injection)
    assert iface["name"] == "wlan0" and iface["driver"] == "ath9k"
    assert iface["bands"] == ["2.4GHz", "5GHz"]
    assert iface["monitor"] is True and iface["injection"] is True


def test_websocket_state_with_a_real_interface(client):
    # the socket's first frame is the full snapshot — the exact frame that
    # crashed uvicorn's ASGI handler in the field.
    from unittest import mock

    with mock.patch("wifipilot.deps.list_interfaces", return_value=_one_real_adaptor()):
        with client.websocket_connect("/ws") as websocket:
            first = json.loads(websocket.receive_text())
    assert first["kind"] == "state"
    assert first["data"]["tools"]["interfaces"][0]["name"] == "wlan0"


def test_ws_json_default_survives_stray_objects():
    # defence in depth: no single leaked object may kill the stream again.
    from datetime import datetime
    from pathlib import Path

    from wifipilot.web.app import _json_default

    text = json.dumps(
        {"iface": _one_real_adaptor()[0], "cap": Path("/loot/a.cap"),
         "at": datetime(2026, 10, 19, 9, 0), "tags": {"b", "a"},
         "blob": b"\xde\xad"},
        default=_json_default,
    )
    data = json.loads(text)
    assert data["iface"]["name"] == "wlan0"               # to_dict() won
    assert data["cap"] == "/loot/a.cap"
    assert data["tags"] == ["a", "b"] and data["blob"] == "dead"


# --------------------------------------------------------------------------- #
# AI provider endpoints
# --------------------------------------------------------------------------- #


def test_provider_endpoints_and_secret_handling(client):
    # switching to the cloud provider requires consent
    refused = client.post("/api/ai/provider", json={"provider": "openrouter", "consent": False})
    assert refused.status_code == 400
    assert "consent" in refused.json()["detail"].lower()

    # a syntactically invalid key is rejected before it is stored
    bad = client.post("/api/ai/key", json={"key": "nope", "save": False})
    assert bad.status_code == 400
    assert "sk-or-" in bad.json()["detail"]

    # an unknown provider is rejected
    assert client.post("/api/ai/provider", json={"provider": "gpt5"}).status_code == 400

    # a valid-looking key is stored and reported, but never echoed back
    key = "sk-or-v1-0000000000000000000000000000000000000000"    # noqa: S105 - test data
    stored = client.post("/api/ai/key", json={"key": key, "save": False})
    assert stored.status_code == 200
    assert stored.json()["key_configured"] is True
    assert key not in json.dumps(stored.json())

    state = client.get("/api/state").json()
    assert state["config"]["openrouter"]["api_key"] == ""
    assert state["config"]["openrouter"]["has_api_key"] is True
    assert "config file" in state["config"]["openrouter"]["key_source"]
    assert key not in json.dumps(state)
    assert state["advisor"]["key"]["configured"] is True
    assert key not in json.dumps(state["advisor"])

    config = client.get("/api/config").json()
    assert config["config"]["openrouter"]["api_key"] == ""
    assert {row["name"] for row in config["providers"]} == {"ollama", "cortex", "openrouter"}


def test_provider_switch_cycle_keeps_the_ui_working(client):
    """Regression: openrouter → auto used to 500 the whole dashboard."""
    client.post("/api/ai/key", json={"key": "sk-or-v1-abcdefghijklmnopqrstuvwxyz",    # noqa: S106
                                     "save": False})
    for provider in ("openrouter", "auto", "none", "ollama", "auto"):
        response = client.post("/api/ai/provider", json={"provider": provider})
        assert response.status_code == 200, (provider, response.text)
        assert response.json()["provider"] in ("ollama", "cortex", "openrouter", "none")
        state = client.get("/api/state")
        assert state.status_code == 200
        assert "advisor" in state.json()
    # the key survived every switch
    assert client.get("/api/state").json()["config"]["openrouter"]["has_api_key"] is True


def test_redacted_config_post_cannot_wipe_the_key(client):
    key = "sk-or-v1-abcdefghijklmnopqrstuvwxyz"      # noqa: S105 - test data
    client.post("/api/ai/key", json={"key": key, "save": False})
    # the UI round-trips what GET /api/config returned (api_key: "")
    echoed = {"openrouter": {"api_key": "", "redact_identifiers": False,
                             "max_cost_usd": 2.5, "model": "openai/gpt-4o-mini"}}
    response = client.post("/api/config", json=echoed)
    assert response.status_code == 200
    state = client.get("/api/state").json()
    assert state["config"]["openrouter"]["has_api_key"] is True       # not wiped
    assert state["config"]["openrouter"]["redact_identifiers"] is False
    assert state["config"]["openrouter"]["max_cost_usd"] == 2.5
    assert state["advisor"]["policy"]["redact_identifiers"] is False


def test_models_endpoint_lists_the_active_provider(client):
    data = client.get("/api/ai/models").json()
    assert data["provider"] in ("ollama", "none", "openrouter")
    assert isinstance(data["models"], list)
    assert "redact" in data and "configured" in data
    # an explicit provider can be queried without switching to it
    openrouter = client.get("/api/ai/models?provider=openrouter&limit=5").json()
    assert openrouter["provider"] == "openrouter"
    assert isinstance(openrouter["models"], list)
    assert "error" in openrouter          # unreachable catalogue is reported, not raised


def test_state_and_health_report_the_platform(client):
    state = client.get("/api/state").json()
    assert state["platform"]["os"] in ("linux", sys.platform)
    assert "supported" in state["platform"]
    health = client.get("/healthz").json()
    assert health["platform"] in ("linux", sys.platform)
    assert "provider" in health


def test_docs_index_lists_the_bundled_documents(client):
    payload = client.get("/api/docs").json()
    names = [doc["name"] for doc in payload["docs"]]
    assert "OPTIMIZATIONS.md" in names
    entry = next(doc for doc in payload["docs"] if doc["name"] == "OPTIMIZATIONS.md")
    assert "419" in entry["title"] and entry["bytes"] > 1000


def test_doc_fetch_serves_markdown(client):
    doc = client.get("/api/docs/OPTIMIZATIONS.md").json()
    assert doc["name"] == "OPTIMIZATIONS.md"
    assert doc["markdown"].startswith("# ")
    assert "419" in doc["markdown"]


def test_docs_reject_bad_names_and_traversal(client):
    for path in ("/api/docs/nope.md", "/api/docs/OPTIMIZATIONS.txt",
                 "/api/docs/.hidden.md", "/api/docs/..%2F..%2FREADME.md",
                 "/api/docs/..%2Fapp.py"):
        assert client.get(path).status_code == 404, path


def test_index_has_sidebar_and_the_new_views(client):
    page = client.get("/").text
    assert 'id="sidebar"' in page and 'class="tab sidenav' in page
    for tab in ("targets", "tasks", "devices", "loot", "ai", "log",
                "setup", "settings", "docs", "about"):
        assert f'data-tab="{tab}"' in page, tab
        assert f'id="tab-{tab}"' in page, tab
