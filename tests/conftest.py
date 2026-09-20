"""Shared pytest fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("NO_COLOR", "1")

from wifipilot.config import Config            # noqa: E402
from wifipilot.events import EventBus          # noqa: E402
from wifipilot.session import Session          # noqa: E402
from wifipilot.synth import build_capture      # noqa: E402

#: a fixed "engagement" used across the tests
AP_MAC = "aa:bb:cc:11:22:33"
STA_MAC = "02:00:00:00:00:09"
SSID = "TestNet"
PSK = "TestNet2024"


@pytest.fixture()
def bus() -> EventBus:
    return EventBus()


@pytest.fixture()
def config(tmp_path) -> Config:
    cfg = Config()
    cfg.demo = True
    cfg.ollama.enabled = False
    cfg.output_dir = str(tmp_path / "loot")
    cfg.session_dir = str(tmp_path / "sessions")
    cfg.scan_time = 2
    cfg.handshake_timeout = 8
    cfg.pmkid_timeout = 6
    cfg.wps_timeout = 8
    cfg.wep_timeout = 6
    cfg.crack_timeout = 10
    return cfg


@pytest.fixture()
def session(config, bus) -> Session:
    return Session(config, bus, demo=True)


@pytest.fixture()
def handshake_capture(tmp_path) -> str:
    path = tmp_path / "handshake.pcap"
    build_capture(str(path), SSID, AP_MAC, STA_MAC, PSK)
    return str(path)


@pytest.fixture()
def pmkid_capture(tmp_path) -> str:
    path = tmp_path / "pmkid.pcap"
    build_capture(str(path), SSID, AP_MAC, STA_MAC, PSK, include_handshake=False)
    return str(path)
