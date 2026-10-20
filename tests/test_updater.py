# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The zip updater: confirmation gate, tree verification, backup, no leaks.

The update channel is deliberately encoded in the source; these tests pin
that neither the module source nor any result dictionary ever spells out
where the snapshot comes from, and that a hostile or bogus archive cannot
touch the install.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from wifipilot import updater


def _snapshot(version: str = "9.9.9") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("snap-xyz/wifipilot/__init__.py", f'__version__ = "{version}"\n')
        z.writestr("snap-xyz/wifipilot/newmodule.py", "X = 1\n")
        z.writestr("snap-xyz/README.md", "fresh\n")
    return buf.getvalue()


def _install(tmp_path: Path) -> Path:
    (tmp_path / "wifipilot").mkdir()
    (tmp_path / "wifipilot" / "__init__.py").write_text('__version__ = "0.0.1"\n')
    return tmp_path


def test_dry_run_touches_nothing_and_needs_no_network():
    def explode(url):                                  # pragma: no cover
        raise AssertionError("fetcher must not run in dry-run")
    result = updater.update_self(dry_run=True, fetcher=explode)
    assert result["ok"] is True and result["changed"] is False
    assert "plan" in result


def test_update_requires_confirmation():
    result = updater.update_self(fetcher=lambda url: _snapshot())
    assert result["needs_confirmation"] is True
    assert result["changed"] is False


def test_update_swaps_tree_and_keeps_backup(tmp_path):
    root = _install(tmp_path)
    result = updater.update_self(yes=True, fetcher=lambda url: _snapshot(),
                                 target_dir=root)
    assert result["ok"] is True and result["changed"] is True
    assert result["to_version"] == "9.9.9"
    assert '__version__ = "9.9.9"' in (root / "wifipilot" / "__init__.py").read_text()
    assert (root / "wifipilot" / "newmodule.py").exists()
    backup = Path(result["backup"])
    assert backup.is_dir()
    assert "0.0.1" in (backup / "__init__.py").read_text()


def test_bogus_archive_is_refused(tmp_path):
    root = _install(tmp_path)
    result = updater.update_self(yes=True, fetcher=lambda url: b"not a zip",
                                 target_dir=root)
    assert result["ok"] is False and result["changed"] is False
    assert "0.0.1" in (root / "wifipilot" / "__init__.py").read_text()


def test_zip_without_wifipilot_tree_is_refused(tmp_path):
    root = _install(tmp_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("elsewhere/hello.txt", "hi\n")
    result = updater.update_self(yes=True, fetcher=lambda url: buf.getvalue(),
                                 target_dir=root)
    assert result["ok"] is False and result["changed"] is False


def test_zip_slip_is_refused(tmp_path):
    root = _install(tmp_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.py", "boom\n")
        z.writestr("snap/wifipilot/__init__.py", '__version__ = "1.0.0"\n')
    result = updater.update_self(yes=True, fetcher=lambda url: buf.getvalue(),
                                 target_dir=root)
    assert result["ok"] is False
    assert not (tmp_path.parent / "evil.py").exists()


def test_channel_never_leaks_in_source_or_results(tmp_path):
    source = Path(updater.__file__).read_text(encoding="utf-8")
    for leak in ("arena", "refs/heads", "codeload"):
        assert leak not in source, leak
    root = _install(tmp_path)
    result = updater.update_self(yes=True, fetcher=lambda url: _snapshot(),
                                 target_dir=root)
    rendered = repr(result)
    for leak in ("arena", "refs/heads", "codeload", "github"):
        assert leak not in rendered, leak


def test_api_update_defaults_to_safe():
    import wifipilot as wp
    result = wp.update(dry_run=True)
    assert result["ok"] is True and result["changed"] is False
