"""Linux-only enforcement and platform reporting.

wifipilot drives nl80211/aircrack-ng/sysfs/rfkill: it must refuse to *run* on any
other operating system, while staying importable everywhere (so packaging tools,
linters and this test suite work on any host).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from wifipilot.cli import main
from wifipilot.util import (PLATFORM_OVERRIDE_ENV, distro_name, is_linux, kernel_release,
                            package_manager, platform_info, require_linux)
from wifipilot import deps, util

REPO = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# platform reporting
# --------------------------------------------------------------------------- #


def test_platform_info_reports_linux_here():
    info = platform_info()
    assert info["platform"] == sys.platform
    assert info["os"] in ("linux", sys.platform)
    assert info["supported"] is is_linux()
    for key in ("kernel", "distro", "package_manager", "supported"):
        assert key in info
    assert isinstance(info["supported"], bool)


def test_distro_and_package_manager_are_strings():
    assert isinstance(distro_name(), str) and distro_name()
    assert isinstance(package_manager(), str)
    assert isinstance(kernel_release(), str)


def test_imports_work_on_any_platform():
    """The library must stay importable off Linux (only *running* is refused)."""
    proc = subprocess.run(
        [sys.executable, "-c",
         "import wifipilot, wifipilot.cli, wifipilot.engine, wifipilot.web.app; "
         "from wifipilot.util import platform_info; print('ok')"],
        cwd=str(REPO), capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ok" in proc.stdout


# --------------------------------------------------------------------------- #
# require_linux
# --------------------------------------------------------------------------- #


def test_require_linux_passes_on_linux():
    require_linux()          # must not raise
    require_linux("wifipilot web")


def test_require_linux_refuses_other_platforms(monkeypatch):
    monkeypatch.setattr(util.sys, "platform", "darwin")
    monkeypatch.delenv(PLATFORM_OVERRIDE_ENV, raising=False)
    with pytest.raises(SystemExit) as excinfo:
        require_linux()
    message = str(excinfo.value)
    assert "Linux only" in message
    assert "darwin" in message
    assert "aircrack-ng" in message


def test_require_linux_override_is_explicit(monkeypatch):
    monkeypatch.setattr(util.sys, "platform", "win32")
    monkeypatch.setenv(PLATFORM_OVERRIDE_ENV, "1")
    require_linux()                                     # packaging escape hatch
    monkeypatch.setenv(PLATFORM_OVERRIDE_ENV, "0")       # not a synonym for yes
    with pytest.raises(SystemExit):
        require_linux()


def test_cli_refuses_to_run_on_macos(monkeypatch, capsys):
    monkeypatch.setattr(util.sys, "platform", "darwin")
    monkeypatch.delenv(PLATFORM_OVERRIDE_ENV, raising=False)
    assert main(["tools"]) == 2
    captured = capsys.readouterr()
    assert "Linux only" in captured.err


def test_web_server_refuses_to_start_on_macos(monkeypatch):
    from wifipilot.web import app as web_app

    monkeypatch.setattr(util.sys, "platform", "darwin")
    monkeypatch.delenv(PLATFORM_OVERRIDE_ENV, raising=False)
    with pytest.raises(SystemExit):
        web_app.run_server()


# --------------------------------------------------------------------------- #
# tooling metadata
# --------------------------------------------------------------------------- #


def test_install_hints_are_linux_only():
    for tool, hint in deps.INSTALL_HINTS.items():
        assert "brew" not in hint, f"{tool} suggests a macOS package manager"
        assert "choco" not in hint and "winget" not in hint
        assert any(manager in hint for manager in ("apt", "pacman", "dnf", "zypper", "apk")), tool


def test_install_command_matches_the_distribution():
    command = deps.install_command()
    assert "aircrack-ng" in command
    assert "sudo" in command
    assert "brew" not in command


def test_registry_summary_includes_platform():
    summary = deps.registry.summary()
    assert summary["platform"]["os"] in ("linux", sys.platform)
    assert "install_command" in summary


def test_tools_command_reports_platform(capsys):
    from wifipilot.cli import build_parser, apply_cli_config, command_tools

    class Console:
        def print(self, *items, **kwargs):
            print(*[str(i) for i in items])

    args = build_parser().parse_args(["tools"])
    config = apply_cli_config(args)
    command_tools(args, config, Console())
    out = capsys.readouterr().out
    assert "platform" in out
    assert "linux" in out.lower()


def test_no_macos_specific_code_paths_remain():
    """Guard against reintroducing a macOS branch in the Linux-only tool."""
    offenders = []
    for path in list(REPO.glob("wifipilot/**/*.py")) + list(REPO.glob("scripts/*")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle in ("brew install", "darwin", "sys.platform == \"win32\"", "macOS"):
            if needle in text:
                offenders.append(f"{path.relative_to(REPO)}: {needle}")
    assert not offenders, f"non-Linux references: {offenders}"
