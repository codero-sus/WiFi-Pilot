# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""``wifipilot tools install``: plan building and the confirmation gate.

Nothing here ever runs a real package manager: the runner is injected,
which is exactly the seam the CLI/web paths use.
"""

from __future__ import annotations

from wifipilot import deps


class _Result:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.returncode = 0 if ok else 1
        self.timed_out = False


def test_plan_covers_every_tool_once():
    plan = deps.install_plan()
    assert plan["missing_tools"] or plan["present_tools"]
    assert len(plan["missing_tools"]) + len(plan["present_tools"]) == len(deps.TOOLS)
    # packages are deduplicated (four aircrack tools share one package)
    assert len(plan["packages"]) == len(set(plan["packages"]))


def test_plan_commands_are_argv_never_shell():
    plan = deps.install_plan()
    for argv in plan["commands"]:
        assert isinstance(argv, list)
        assert all(isinstance(part, str) for part in argv)
        assert not any(part in ("&&", ";", "|") for part in argv)


def test_plan_category_filter():
    plan = deps.install_plan(categories=["wps"])
    names = plan["missing_tools"] + plan["present_tools"]
    assert names and all(deps.TOOLS[n].category == "wps" for n in names)


def test_dry_run_never_runs_anything():
    called = []
    result = deps.install_tools(dry_run=True, yes=True,
                                runner=lambda *a, **k: called.append(a) or _Result())
    assert result["dry_run"] is True
    assert result["results"] == []
    assert called == []


def test_install_requires_confirmation():
    called = []
    result = deps.install_tools(runner=lambda *a, **k: called.append(a) or _Result())
    assert result["needs_confirmation"] is True
    assert called == []


def test_install_runs_every_planned_command(monkeypatch):
    monkeypatch.setattr(deps, "which", lambda name: None)   # everything missing
    monkeypatch.setattr(deps.registry, "probe",
                        lambda name, force=False: type("I", (), {"path": ""})())
    ran = []

    def runner(argv, timeout=None, env=None):
        ran.append(argv)
        return _Result(ok=True)

    result = deps.install_tools(yes=True, runner=runner, manager="apt-get")
    plan = result["plan"]
    assert plan["manager"] == "apt"
    assert len(ran) == len(plan["commands"]) >= 1
    assert result["results"][0]["ok"] is True
    # the probe still says missing, so the result is honestly not-ok
    assert result["after_missing"] == plan["missing_tools"]
    assert result["ok"] is False


def test_install_manager_package_overrides(monkeypatch):
    monkeypatch.setattr(deps, "which", lambda name: None)
    plan = deps.install_plan(manager="pacman", categories=["iface"])
    assert "networkmanager" in plan["packages"]       # arch spelling
    assert "network-manager" not in plan["packages"]
    assert plan["commands"][0][0] in ("pacman", "sudo")


def test_api_install_tools_defaults_to_dry_run():
    import wifipilot as wp
    result = wp.install_tools()
    assert result["dry_run"] is True
    assert result["results"] == []
