# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""CLI smoke tests: every subcommand must run, exit cleanly and emit valid JSON."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from wifipilot.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_help_and_version(capsys):
    with pytest.raises(SystemExit) as info:
        main(["--help"])
    assert info.value.code == 0
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0


def test_tools_json(capsys):
    code, out, _ = run(capsys, "--json", "tools")
    payload = json.loads(out)
    assert "tools" in payload and "capabilities" in payload
    assert code in (0, 1)          # 1 when required tools are missing (this container)


def test_config_json_and_write(capsys, tmp_path):
    code, out, _ = run(capsys, "--json", "config")
    config = json.loads(out)
    assert config["attacks"]
    assert "handshake_timeout" in config
    target = tmp_path / "cfg.json"
    code, out, _ = run(capsys, "--json", "config", "--write", str(target))
    assert target.exists()
    assert json.loads(target.read_text())["attacks"] == config["attacks"]


def test_analyze_json(handshake_capture, capsys):
    code, out, _ = run(capsys, "--json", "analyze", handshake_capture)
    payload = json.loads(out)
    assert payload[0]["has_handshake"] is True
    assert code == 0


def test_crack_command_finds_a_psk(handshake_capture, capsys):
    code, out, _ = run(capsys, "crack", handshake_capture, "-e", "TestNet")
    assert code == 0
    assert "TestNet2024" in out
    assert "verified" in out


def test_crack_command_reports_failure(tmp_path, capsys):
    from wifipilot.synth import build_capture
    path = str(tmp_path / "hard.pcap")
    build_capture(path, "TestNet", "aa:bb:cc:11:22:33", "02:00:00:00:00:09",
                  "Q7#veryUnlikelyPassphrase!")
    code, out, _ = run(capsys, "--timeout", "5", "crack", path, "-e", "TestNet")
    assert code == 1
    assert "not cracked" in out


def test_ai_status_without_ollama(capsys):
    code, out, _ = run(capsys, "--json", "ai", "status")
    payload = json.loads(out)
    assert "available" in payload and "model" in payload
    assert code == 0


def test_unknown_attack_is_rejected(capsys):
    code = main(["--attacks", "not-an-attack", "scan"])
    assert code == 2


def test_attack_requires_authorisation_without_demo(capsys):
    code, out, _ = run(capsys, "attack", "--no-scan")
    assert code == 2
    assert "authoris" in out.lower() or "permission" in out.lower()


def test_scan_runs_in_demo_mode(capsys, tmp_path):
    code, out, _ = run(capsys, "--demo", "--json", "-o", str(tmp_path / "loot"),
                       "--session-dir", str(tmp_path / "sessions"),
                       "scan", "-t", "2")
    payload = json.loads(out)
    assert isinstance(payload, list) and payload
    assert any("bssid" in ap for ap in payload)
    assert code == 0


def test_demo_command_completes(capsys, tmp_path):
    code, out, _ = run(capsys, "--demo", "--no-ai", "--json",
                       "-o", str(tmp_path / "loot"),
                       "--session-dir", str(tmp_path / "sessions"),
                       "--timeout", "8s", "demo")
    payload = json.loads(out)
    assert "stats" in payload
    assert payload["stats"]["attacks_run"] >= 1
    assert code == 0
