# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The feature endpoints the browser UI uses: scoping, notes, advice, analytics."""

from __future__ import annotations

from pathlib import Path

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
    app = create_app(config, demo=True, authorized=True)
    with TestClient(app) as test_client:
        yield test_client


def _aps(client):
    return client.get("/api/state").json()["access_points"]


def test_targets_endpoint_filters_like_the_cli(client):
    """The endpoint answers with the same rows the CLI prints, filtered the same way.

    The demo scan keeps discovering in the background, so the assertion is on the
    *shape* and the filtering, not on an exact count.
    """
    listing = client.get("/api/targets").json()
    assert listing["ok"] is True
    assert listing["count"] >= 1
    assert listing["count"] == len(listing["targets"])
    assert all(row["bssid"] for row in listing["targets"])

    guests = client.get("/api/targets", params={"kind": "guest"}).json()
    assert guests["count"] <= listing["count"]
    for row in guests["targets"]:
        assert row["target_kind"] == "guest"

    nothing = client.get("/api/targets", params={"kind": "no-such-kind"}).json()
    assert nothing["count"] == 0


def test_select_scopes_the_campaign(client):
    aps = _aps(client)
    assert aps, "demo mode should have discovered access points"
    chosen = aps[0]["bssid"]
    result = client.post("/api/select", json={"bssids": [chosen], "clear": True}).json()
    assert result["selected"] == [chosen]

    scoped = client.get("/api/state").json()["session"]["selected"]
    assert scoped == [chosen]

    by_filter = client.post("/api/select", json={"kind": "guest", "clear": True}).json()
    assert by_filter["count"] == by_filter["selected"].__len__()


def test_tag_and_delete_tag(client):
    bssid = _aps(client)[0]["bssid"]
    added = client.post("/api/tag", json={"bssid": bssid, "tag": "in-scope"}).json()
    assert added["tags"] == ["in-scope"]

    tags = client.get("/api/tags").json()
    assert tags["tags"]["in-scope"] == [bssid]

    removed = client.post("/api/tag",
                          json={"bssid": bssid, "tag": "in-scope", "remove": True}).json()
    assert removed["tags"] == []

    bad = client.post("/api/tag", json={"bssid": bssid, "tag": ""})
    assert bad.status_code == 400


def test_note_endpoint_persists(client):
    created = client.post("/api/note", json={"text": "engagement started"}).json()
    assert created["note"]["text"] == "engagement started"

    # it is on disk, so it survives the browser tab (and a crash)
    state_dir = client.get("/api/state").json()["session"]["state_dir"]
    assert (Path(state_dir) / "notes.jsonl").exists()

    empty = client.post("/api/note", json={"text": "   "})
    assert empty.status_code == 400


def test_advice_endpoint_returns_actions(client):
    payload = client.get("/api/advice").json()
    assert payload["ok"] is True
    assert payload["advice"]
    first = payload["advice"][0]
    assert first["action"] and first["why"] is not None


def test_vendor_endpoint_by_mac_and_by_name(client):
    by_mac = client.get("/api/vendor", params={"bssid": "d0:9e:12:9d:36:cc"}).json()
    assert by_mac["vendor"] == "AVM"
    assert by_mac["dossier"]["matched"] is True
    assert by_mac["dossier"]["confidence"] == "heuristic"

    by_name = client.get("/api/vendor", params={"query": "tp-link"}).json()
    assert by_name["dossier"]["key"] == "TP-Link"

    assert client.get("/api/vendor").status_code == 400


def test_passwords_endpoint_reports_weakness(client):
    payload = client.get("/api/passwords").json()
    assert payload["ok"] is True
    for row in payload["passwords"]:
        assert row["password"] and 0 <= row["score"] <= 100
        assert row["seconds"]


def test_benchmark_endpoint_stays_short(client):
    result = client.post("/api/benchmark", json={"seconds": 1}).json()
    assert result["ok"] is True
    assert result["benchmark"]["rate"] > 0
    # the endpoint clamps the duration so a browser cannot start a long job
    clamped = client.post("/api/benchmark", json={"seconds": 9999}).json()
    assert clamped["benchmark"]["seconds"] <= 31.0
