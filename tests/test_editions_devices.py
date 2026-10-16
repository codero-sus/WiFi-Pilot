"""The editions (WiFi / Bluetooth / IT), the device shelf and the web UI's new views.

The three editions are one registry cut three ways: this file checks that the cut is
consistent (every attack has an edition and the counts add up), that the device shelf
only offers attacks that exist, and that the endpoints the browser talks to answer with
the same data the Python API returns.
"""

from __future__ import annotations

import json

import pytest

from wifipilot import api
from wifipilot.attacks import attack_catalog
from wifipilot.itdev import DEVICE_TYPES, device_type, edition_catalog
from wifipilot.models import ATTACK_NAMES

#: the shape of the registry this wave ships: 288 radio attacks + 356 service/device ones
#: (+ the Bluetooth waves: wifipilot 3.0 = 762 attacks across wifi, bluetooth and it)
WIFI, BLUETOOTH, IT = 288, 118, 356
TOTAL = WIFI + BLUETOOTH + IT


# --------------------------------------------------------------------------- #
# the registry, cut into editions
# --------------------------------------------------------------------------- #

def test_every_attack_belongs_to_an_edition():
    rows = attack_catalog()
    assert len(rows) == len(ATTACK_NAMES) == TOTAL
    domains = {}
    for row in rows:
        domain = str(row.get("domain", ""))
        assert domain in ("wifi", "bluetooth", "it"), (row["name"], domain)
        domains[domain] = domains.get(domain, 0) + 1
    assert domains == {"wifi": WIFI, "bluetooth": BLUETOOTH, "it": IT}
    assert sum(domains.values()) == len(rows)


def test_bluetooth_attacks_are_not_filed_as_wifi():
    """``bt_``/``ble_`` names come from batches registered before domains existed."""
    bluetooth = [row["name"] for row in attack_catalog() if row.get("domain") == "bluetooth"]
    assert "bt_knob" in bluetooth and "bt_blueborne" in bluetooth
    assert "deauth_flood" not in bluetooth


def test_edition_catalog_counts_match_the_registry():
    counts = {}
    for row in attack_catalog():
        counts[str(row["domain"])] = counts.get(str(row["domain"]), 0) + 1
    shelf = {row["id"]: row for row in edition_catalog()}
    assert set(shelf) == {"wifi", "bluetooth", "it", "all"}
    for domain in ("wifi", "bluetooth", "it"):
        assert shelf[domain]["devices"] == len([d for d in DEVICE_TYPES if d.domain == domain])
    assert shelf["all"]["devices"] == len(DEVICE_TYPES)
    # the attack counts live in the registry, so they come from the API layer
    rows = {row["id"]: row for row in api.editions()}
    assert rows["wifi"]["attacks"] == counts["wifi"]
    assert rows["bluetooth"]["attacks"] == counts["bluetooth"]
    assert rows["it"]["attacks"] == counts["it"]
    assert rows["all"]["attacks"] == sum(counts.values())


# --------------------------------------------------------------------------- #
# the device shelf
# --------------------------------------------------------------------------- #

def test_device_types_carry_ports_protocols_and_attacks():
    for dev in DEVICE_TYPES:
        assert dev.id and dev.label and dev.description
        assert dev.domain in ("wifi", "bluetooth", "it")
        assert dev.protocols, dev.id                   # what it answers
        assert dev.risk, dev.id                        # why it matters
        if dev.domain != "bluetooth":
            # Bluetooth devices are found by their advertisement, not by a TCP port
            assert dev.ports, dev.id


def test_every_device_offers_attacks_that_exist():
    """The roadmap may name attacks this build does not have; the UI may not show them."""
    from wifipilot.itdev import roadmap_attacks, suggested_attacks

    known = set(ATTACK_NAMES)
    for dev in DEVICE_TYPES:
        assert device_type(dev.id) is not None, f"{dev.id} is unreachable by id"
        resolved = suggested_attacks(dev)
        assert resolved, dev.id
        assert all(name in known for name in resolved), dev.id
        # a roadmap name that is literally registered must survive resolution
        for name in roadmap_attacks(dev):
            if name in known:
                assert name in resolved, (dev.id, name)


def test_catalogue_rows_name_devices_that_exist():
    ids = {dev.id for dev in DEVICE_TYPES}
    for row in attack_catalog():
        for device_id in row.get("devices") or []:
            assert device_id in ids, (row["name"], device_id)


def test_api_catalogue_filters_by_edition_and_device():
    everything = api.catalogue()
    wifi = api.catalogue(domain="wifi")
    bluetooth = api.catalogue(domain="bluetooth")
    it = api.catalogue(domain="it")
    assert len(wifi) + len(bluetooth) + len(it) == len(everything)
    assert all(row["domain"] == "it" for row in it)

    camera = api.catalogue(device="ip_camera")
    assert camera and all("ip_camera" in row["devices"] for row in camera)
    assert "it_rtsp_anonymous" in [row["name"] for row in camera]


def test_api_editions_and_device_helpers():
    rows = {row["id"]: row for row in api.editions()}
    assert set(rows) == {"wifi", "bluetooth", "it", "all"}
    assert rows["it"]["attacks"] == IT

    camera = api.device("ip_camera")
    assert camera["label"] and camera["ports"]
    assert camera["attack_names"] == [row["name"] for row in camera["attacks"]]
    assert "it_rtsp_default_creds" in camera["attack_names"]
    assert api.device("not_a_device") == {}

    printers = api.devices(device="printer")
    assert printers and all("printer" in row["id"] for row in printers)
    assert api.devices(edition="bluetooth")
    assert all(row["domain"] == "bluetooth" for row in api.devices(edition="bluetooth"))


def test_device_plan_only_contains_registered_attacks():
    from wifipilot.itdev import plan_for_device

    for dev in DEVICE_TYPES:
        plan = plan_for_device(dev)
        assert plan, dev.id
        assert all(name in ATTACK_NAMES for name in plan)


# --------------------------------------------------------------------------- #
# the planner and the CLI switches
# --------------------------------------------------------------------------- #

def test_planner_edition_attacks_returns_the_named_attacks(config):
    from wifipilot.planner import edition_attacks

    config.attacks = ["it_http_default_creds", "bt_knob", "deauth_flood"]
    assert edition_attacks(config) == ["it_http_default_creds", "bt_knob"]


def test_cli_edition_selects_that_edition(config, capsys):
    from wifipilot.cli import build_parser, main

    parser = build_parser()
    args = parser.parse_args(["--edition", "it", "attacks", "--domain", "it", "--json"])
    assert args.edition == "it" and args.domain == "it"
    main(["--edition", "it", "attacks", "--domain", "it", "--json"])
    payload = capsys.readouterr().out
    assert f'"count": {IT}' in payload
    # the parser keeps the edition on the Config when the command builds one
    args = parser.parse_args(["--edition", "bluetooth", "--it-host", "192.168.1.26",
                              "--it-port", "1883", "demo"])
    assert args.it_host == "192.168.1.26" and args.it_port == 1883


def test_cli_edition_switch_sets_the_enabled_attacks(tmp_path, capsys):
    """``--edition it`` *is* the plan: the IT attacks become the enabled list."""
    from wifipilot.cli import main

    config_path = tmp_path / "wifipilot.json"
    code = main(["--edition", "it", "--config", str(config_path), "--demo", "attacks",
                 "--domain", "it", "--json"])
    assert code == 0
    payload = capsys.readouterr().out
    assert f'"count": {IT}' in payload


# --------------------------------------------------------------------------- #
# the web UI's views
# --------------------------------------------------------------------------- #

@pytest.fixture()
def client(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from wifipilot.config import Config
    from wifipilot.web.app import create_app

    config = Config()
    config.demo = True
    config.ollama.enabled = False
    config.output_dir = str(tmp_path / "loot")
    config.session_dir = str(tmp_path / "sessions")
    app = create_app(config, demo=True, authorized=True)
    with TestClient(app) as test_client:
        yield test_client


def test_state_carries_the_edition_block(client):
    state = client.get("/api/state").json()
    assert state["edition"]["total"] == TOTAL
    assert state["edition"]["attacks"] == {"wifi": WIFI, "bluetooth": BLUETOOTH, "it": IT}
    assert state["edition"]["active"] in ("all", "wifi", "bluetooth", "it")
    assert "selected" in state["devices"]


def test_editions_endpoint_and_switch(client):
    listing = client.get("/api/editions").json()
    assert {row["id"] for row in listing["editions"]} >= {"wifi", "bluetooth", "it"}
    assert listing["total"] == TOTAL

    switched = client.post("/api/edition", json={"edition": "it"}).json()
    assert switched["active"] == "it"
    state = client.get("/api/state").json()
    assert state["edition"]["active"] == "it"
    assert state["config"]["edition"] == "it"
    assert len(state["config"]["attacks"]) == IT

    assert client.post("/api/edition", json={"edition": "nope"}).status_code == 400
    client.post("/api/edition", json={"edition": "all"})
    assert client.get("/api/state").json()["edition"]["active"] == "all"


def test_catalog_endpoint_filters_like_the_api(client):
    everything = client.get("/api/catalog").json()
    assert everything["count"] == TOTAL
    wifi = client.get("/api/catalog", params={"domain": "wifi"}).json()
    bluetooth = client.get("/api/catalog", params={"domain": "bluetooth"}).json()
    assert wifi["count"] == WIFI and bluetooth["count"] == BLUETOOTH
    cameras = client.get("/api/catalog", params={"device": "ip_camera"}).json()
    assert cameras["count"] and all("ip_camera" in row["devices"] for row in cameras["attacks"])
    search = client.get("/api/catalog", params={"q": "rtsp"}).json()
    assert search["count"]
    assert all("rtsp" in (row["name"] + row["label"] + row["description"]).lower()
               for row in search["attacks"])
    # a device query on the catalogue endpoint is the same set the device endpoint plans
    only_printer = client.get("/api/catalog", params={"device": "printer"}).json()
    assert only_printer["count"] and all("printer" in row["devices"]
                                         for row in only_printer["attacks"])


def test_devices_endpoint_lists_the_shelf(client):
    listing = client.get("/api/devices").json()
    assert listing["count"] == len(DEVICE_TYPES)
    assert listing["groups"]
    row = listing["devices"][0]
    for key in ("id", "label", "group", "group_label", "ports", "protocols",
                "attack_names", "attack_count", "plan"):
        assert key in row
    assert row["attack_count"] == len(row["attack_names"])
    assert all(name in ATTACK_NAMES for name in row["attack_names"])
    # the payload carries names, not a copy of the whole catalogue: the rows are one
    # click away (GET /api/device, GET /api/catalog) and the shelf loads on every filter
    assert len(json.dumps(listing)) < 400_000

    cameras = client.get("/api/devices", params={"q": "camera"}).json()
    assert cameras["count"] and all("camera" in row["id"] for row in cameras["devices"])

    printed = client.get("/api/devices", params={"group": "iot"}).json()
    assert printed["count"] and all(row["group"] == "iot" for row in printed["devices"])


def test_device_endpoint_points_the_attacks_and_returns_the_plan(client):
    answer = client.post("/api/device", json={"device": "ip_camera", "host": "192.168.1.26",
                                              "port": 554}).json()
    assert answer["selected"] == {"host": "192.168.1.26", "port": 554, "device": "ip_camera"}
    detail = answer["device"]
    assert detail["label"] == device_type("ip_camera").label
    assert "it_rtsp_anonymous" in detail["attack_names"]
    assert detail["briefing"] and "554" in detail["briefing"]

    state = client.get("/api/state").json()
    assert state["devices"]["selected"]["host"] == "192.168.1.26"
    assert state["config"]["it_host"] == "192.168.1.26"
    assert state["device"]["id"] == "ip_camera"

    assert client.post("/api/device", json={}).status_code == 400


def test_help_and_explain_answer_without_a_model(client):
    """The help panel must work with the advisor off: the catalogue is the source."""
    plain = client.get("/api/help", params={"name": "it_rtsp_anonymous"}).json()
    assert plain["source"] == "catalogue"
    assert "it_rtsp_anonymous" in plain["answer"]
    assert "defender sees" in plain["answer"]

    asked = client.post("/api/help", json={"question": "how loud is this?",
                                           "name": "it_rtsp_anonymous",
                                           "device": "ip_camera"}).json()
    assert asked["source"] == "catalogue"
    assert "IP camera" in asked["answer"]

    explained = client.post("/api/explain", json={"name": "it_http_default_creds",
                                                  "device": "router"}).json()
    assert explained["attack"] == "it_http_default_creds"
    assert explained["heuristic"]
    assert client.post("/api/explain", json={}).status_code == 400


def test_attack_endpoint_accepts_an_it_attack_without_a_bssid(client):
    """An IT attack needs a bridge, not a target AP: the engine picks the best one.

    In simulation the demo scan runs in the background, so the endpoint either queues
    the attack against the best-scoring AP or (before the first scan result) refuses
    with the explanation the operator needs.
    """
    client.get("/api/state")
    answer = client.post("/api/attack", json={"attack": "it_rtsp_anonymous"})
    if answer.status_code == 400:
        assert "no access point" in answer.json()["detail"]
    else:
        assert answer.json()["ok"] is True


def test_demo_hosts_are_offered_to_the_device_picker(client):
    listing = client.get("/api/devices").json()
    assert listing["demo_hosts"]
    host = listing["demo_hosts"][0]
    assert host["ip"] and host["label"]
    assert client.post("/api/device", json={"host": host["ip"]}).json()["ok"] is True
