"""The advisor is optional: one switch, three spellings, and nothing touches a model.

Covers ``wp.ai()``, ``Config.ai_off()``, the ``WIFIPILOT_NO_AI`` environment variable,
the CLI aliases and the ``wifipilot ai off/on`` verbs, the advisor's promise to stay
offline while disabled, and the web API's disabled-state answers.
"""

from __future__ import annotations

import json
import os

import pytest

from wifipilot import api
from wifipilot.advisor import Advisor, OllamaClient
from wifipilot.api import WifiPilotError
from wifipilot.cli import main
from wifipilot.config import Config
from wifipilot.events import EventBus
from wifipilot.session import Session


@pytest.fixture()
def clean_env(monkeypatch):
    monkeypatch.delenv("WIFIPILOT_NO_AI", raising=False)
    yield monkeypatch


@pytest.fixture()
def session(tmp_path, clean_env):
    config = Config()
    config.demo = True
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    return Session(config, EventBus(), demo=True)


# --------------------------------------------------------------------------- #
# config: the switch itself
# --------------------------------------------------------------------------- #

def test_ai_is_on_by_default(clean_env):
    config = Config()
    assert config.ai_off() is False
    assert config.ai_enabled() is True
    assert config.active_provider(probe=False)[0] in ("ollama", "openrouter")


def test_provider_none_switches_ai_off(clean_env):
    config = Config()
    config.ai_provider = "none"
    assert config.ai_off() is True
    assert config.ai_enabled() is False
    assert config.autothink_enabled() is False          # auto-think follows the switch
    provider, reason = config.active_provider(probe=False)
    assert provider == "none" and "--disable-ai" in reason


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_environment_can_disable_ai(clean_env, value):
    clean_env.setenv("WIFIPILOT_NO_AI", value)
    config = Config()
    assert config.ai_off() is True and config.ai_enabled() is False


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off"])
def test_environment_leaves_ai_enabled_by_default(clean_env, value):
    clean_env.setenv("WIFIPILOT_NO_AI", value)
    assert Config().ai_off() is False


def test_ai_disabled_is_reported_and_not_round_tripped(clean_env):
    config = Config()
    config.ai_provider = "none"
    payload = config.to_dict()
    assert payload["ai_disabled"] is True
    restored = Config.from_dict(payload)
    assert restored.ai_provider == "none"
    assert not hasattr(restored, "ai_disabled")          # derived, never persisted as state


# --------------------------------------------------------------------------- #
# wifipilot.ai()
# --------------------------------------------------------------------------- #

def test_ai_disable_and_restore(clean_env):
    first = api.ai()                                     # report only
    assert first["changed"] is False and first["disabled"] is False

    off = api.ai(disable=True)
    assert off["disabled"] is True and off["enabled"] is False
    assert off["provider"] == "none" and off["changed"] is True
    assert "nothing leaves this machine" in off["note"]

    back = api.ai(disable=False)
    assert back["disabled"] is False and back["enabled"] is True
    assert back["provider"] in ("ollama", "openrouter")


def test_ai_provider_none_is_the_same_as_disable(clean_env):
    a = api.ai(provider="none")
    assert a["disabled"] is True
    b = api.ai(disable=True)
    assert b["disabled"] is True and b["changed"] is False      # already off


def test_ai_provider_selection_and_model(clean_env):
    api.config().ai_provider = "none"
    status = api.ai(provider="ollama")
    assert status["provider"] == "ollama" and status["disabled"] is False
    api.ai(model="qwen2.5:7b")
    assert api.config().ollama.model == "qwen2.5:7b"


def test_ai_rejects_an_unknown_provider(clean_env):
    with pytest.raises(WifiPilotError):
        api.ai(provider="gpt-5")


def test_ai_respects_the_environment(clean_env):
    clean_env.setenv("WIFIPILOT_NO_AI", "1")
    status = api.ai()
    assert status["disabled"] is True and status["env_off"] is True
    status = api.ai(disable=False)
    assert status["disabled"] is True                   # the env still wins
    assert "WIFIPILOT_NO_AI" in status["reason"]


def test_set_provider_none_matches_disable(clean_env):
    api.ai(disable=False)
    api.set_provider("none")
    assert api.config().ai_off() is True
    api.set_provider("auto")
    assert api.config().ai_off() is False


def test_ai_is_exported(clean_env):
    import wifipilot as wp
    assert "ai" in wp.__all__ and callable(wp.ai)


# --------------------------------------------------------------------------- #
# the advisor itself: off means no socket
# --------------------------------------------------------------------------- #

class ExplodingClient(OllamaClient):
    """A real client whose network methods raise — touched at all, and the test fails."""

    def ping(self) -> bool:                                       # pragma: no cover
        raise AssertionError("disabled advisor pinged its client")

    def list_models(self, *args, **kwargs):                       # pragma: no cover
        raise AssertionError("disabled advisor listed models")

    def chat(self, *args, **kwargs):                              # pragma: no cover
        raise AssertionError("disabled advisor sent a prompt")


def test_disabled_advisor_never_calls_out(session):
    session.config.ai_provider = "none"
    session.config.ollama.enabled = False
    advisor = Advisor(session, session.config.ollama, session.bus, demo=True)
    advisor.configure("none")
    advisor.client = ExplodingClient(session.config.ollama, session.bus)
    assert advisor.check(force=True) is False
    assert advisor.models() == []
    status = advisor.status()
    assert status["disabled"] is True and status["provider"] == "none"
    assert status["models"] == []
    answer = advisor.ask("anything, does anyone answer?")     # no model, no crash
    assert "advisor is off" in answer.lower()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_no_ai_and_disable_ai_are_the_same_flag(capsys):
    from wifipilot.cli import build_parser
    parser = build_parser()
    a = parser.parse_args(["--no-ai", "config"])
    b = parser.parse_args(["--disable-ai", "config"])
    c = parser.parse_args(["--offline", "config"])
    assert a.no_ai is True and b.no_ai is True and c.no_ai is True
    assert parser.parse_args(["config"]).no_ai is False


@pytest.fixture()
def cli_env(tmp_path, monkeypatch, clean_env):
    """--save must land in tmp_path, not in the repository."""
    monkeypatch.setenv("WIFIPILOT_CONFIG", str(tmp_path / "wifipilot.json"))
    return tmp_path


def test_ai_off_and_on_verbs(capsys, cli_env):
    code, out, _ = run(capsys, "--json", "ai", "off", "--save")
    assert code == 0 and json.loads(out)["disabled"] is True

    code, out, _ = run(capsys, "--json", "ai", "status")
    assert code == 0 and json.loads(out)["disabled"] is True     # short-circuits quietly

    code, out, _ = run(capsys, "--json", "ai", "on", "--save")
    assert code == 0 and json.loads(out)["disabled"] is False

    code, out, _ = run(capsys, "--json", "ai", "toggle", "--save")
    assert code == 0 and json.loads(out)["disabled"] is True
    code, out, _ = run(capsys, "--json", "ai", "toggle", "--save")
    assert code == 0 and json.loads(out)["disabled"] is False

    code, out, _ = run(capsys, "--json", "ai", "on", "ollama", "--save")
    assert code == 0 and json.loads(out)["ai_provider"] == "ollama"


def test_ai_off_survives_a_save_and_reload(capsys, cli_env):
    code, _, _ = run(capsys, "--json", "ai", "off", "--save")
    assert code == 0
    assert json.loads((cli_env / "wifipilot.json").read_text())["ai_provider"] == "none"
    code, out, _ = run(capsys, "--json", "ai", "status")
    assert json.loads(out)["disabled"] is True


def test_ai_off_says_what_is_deciding_instead(capsys, cli_env):
    code, out, _ = run(capsys, "--no-ai", "ai", "off", "--no-color")
    assert code == 0 and "deterministic planner" in out


def test_disabled_ai_subcommands_do_not_probe(capsys, cli_env):
    for argv in (("ai", "status"), ("ai", "models"), ("ai", "pull", "llama3.1:8b")):
        code, out, _ = run(capsys, "--disable-ai", "--json", *argv)
        payload = json.loads(out)
        assert payload["disabled"] is True and payload["provider"] == "none"
        assert code == (0 if argv[1] == "status" else 1)


def test_help_documents_both_spellings(capsys):
    with pytest.raises(SystemExit) as info:
        main(["--help"])
    assert info.value.code == 0
    out = capsys.readouterr().out
    assert "--no-ai" in out and "--disable-ai" in out and "WIFIPILOT_NO_AI" in out


# --------------------------------------------------------------------------- #
# dashboard + web UI surface the state
# --------------------------------------------------------------------------- #

def test_dashboard_labels_a_disabled_advisor(session):
    pytest.importorskip("rich")
    import io

    from rich.console import Console

    from wifipilot.cli import Dashboard
    from wifipilot.engine import Engine

    config = session.config
    config.ai_provider = "none"
    engine = Engine(config)
    engine.session.upsert_ap("aa:bb:cc:dd:ee:01", "TestNet", publish=False)
    dashboard = Dashboard(engine, console=Console(file=io.StringIO(), width=110))
    buf = io.StringIO()
    Console(file=buf, width=110).print(dashboard.build())
    text = buf.getvalue()
    assert "off" in text and "deterministic" in text
    assert "offline" not in text.split("events")[0]      # not painted as an outage


def test_web_api_reports_and_accepts_disabled(tmp_path, clean_env):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from wifipilot.web.app import create_app

    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    app = create_app(config, demo=True, authorized=True)
    with TestClient(app) as client:
        state = client.get("/api/state").json()
        assert state["advisor"].get("disabled") in (True, False)

        off = client.post("/api/ai/toggle", json={"disabled": True}).json()
        assert off["disabled"] is True and off["provider"] == "none"

        state = client.get("/api/state").json()
        assert state["advisor"]["disabled"] is True
        assert state["config"]["ai_disabled"] is True
        assert state["config"]["ai_provider"] == "none"

        assert client.post("/api/ai/think", json={}).json()["disabled"] is True
        models = client.get("/api/ai/models").json()
        assert models["models"] == [] and models["disabled"] is True
        chat = client.post("/api/ai/chat", json={"message": "what next?"}).json()
        assert chat["ok"] is False and chat["disabled"] is True and chat["streaming"] is False

        on = client.post("/api/ai/toggle", json={"disabled": False}).json()
        assert on["disabled"] is False and on["configured_provider"] == "auto"
        assert on["ollama_enabled"] is True          # "on" turns something on
        state = client.get("/api/state").json()
        assert state["config"]["ai_provider"] == "auto"
        assert state["advisor"]["disabled"] is False

        accepted = client.post("/api/ai/provider", json={"provider": "none"}).json()
        assert accepted["ok"] is True and accepted["disabled"] is True


def test_web_page_ships_the_off_controls(clean_env):
    from pathlib import Path
    static = Path(__file__).resolve().parents[1] / "wifipilot" / "web" / "static"
    html = (static / "index.html").read_text()
    js = (static / "app.js").read_text()
    css = (static / "style.css").read_text()
    assert 'id="ai-off-note"' in html and 'id="btn-ai-toggle"' in html
    assert 'id="btn-ai-off"' in html
    assert "deterministic planner" in js and "badge-off" in js
    assert "badge-off" in css and "card-off" in css
