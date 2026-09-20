"""Web API tests (FastAPI TestClient) — the browser UI's whole control surface."""

from __future__ import annotations

import json

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
