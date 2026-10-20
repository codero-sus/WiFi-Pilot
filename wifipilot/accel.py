# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
# Copyright (c) 2025-2026 codero-sus
"""Opt-in hardware acceleration: CPU, RAM and GPU — only when allowed.

wifipilot never spins up worker processes, preloads dictionaries into RAM or
hands work to the GPU unless the operator says so (``config.accel`` /
``--accel`` / ``wp.attack(accel=...)``).  This module is the single place that
turns that permission into concrete settings:

* **cpu** — the built-in cracker verifies candidates in a process pool, and
  the engine may run several non-radio attacks side by side (``jobs``).
* **ram** — candidates are de-duplicated across every pass in a big in-memory
  cache, and wordlists small enough to fit are read once into RAM.
* **gpu** — hashcat (which drives the GPU) becomes the chosen cracker, with a
  full workload profile.
* **all** — everything above.

Detection is cheap and honest: :func:`detect` reports what the machine
actually has, and nothing here pretends a GPU exists when there is none.
"""

from __future__ import annotations

import glob
import os
from functools import lru_cache
from typing import Any, Dict, FrozenSet, Optional

from .util import which

__all__ = [
    "ACCEL_MODES", "parse_accel", "accel_enabled", "detect", "workers",
    "cache_mb", "cache_entries", "apply_accel", "accel_summary",
]

#: the values ``config.accel`` understands (comma combinations work too)
ACCEL_MODES = ("off", "cpu", "ram", "gpu", "all")

_PARTS = ("cpu", "ram", "gpu")


def parse_accel(value: Any) -> FrozenSet[str]:
    """Normalise an accel setting to the set of allowed resources.

    Accepts ``"all"``, ``"cpu,gpu"``, ``True`` (everything), ``False``/``"off"``
    (nothing) and lists of parts.  Unknown words are ignored rather than
    guessed at, so a typo never silently enables hardware use.
    """
    if value is True:
        return frozenset(_PARTS)
    if not value or value is False:
        return frozenset()
    if isinstance(value, (list, tuple, set, frozenset)):
        parts = {str(v).strip().lower() for v in value}
    else:
        parts = {p.strip().lower() for p in str(value).replace("+", ",").split(",")}
    if "all" in parts or "everything" in parts or "full" in parts:
        return frozenset(_PARTS)
    return frozenset(p for p in parts if p in _PARTS)


def accel_enabled(config: Any, part: str) -> bool:
    """Did the operator allow this resource (``"cpu"`` / ``"ram"`` / ``"gpu"``)?"""
    return part in parse_accel(getattr(config, "accel", "off"))


def _meminfo_mb() -> Dict[str, int]:
    """Total / available RAM in MB from /proc/meminfo (0 when unreadable)."""
    out = {"total_mb": 0, "available_mb": 0}
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    out["total_mb"] = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    out["available_mb"] = int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return out


def _gpu_info() -> Dict[str, Any]:
    """Best-effort GPU presence, without running anything slow.

    A render node under /dev/dri or an nvidia-smi binary means silicon is
    there; whether it can *crack* depends on hashcat, which is reported too.
    """
    via = ""
    if which("nvidia-smi"):
        via = "nvidia-smi"
    elif glob.glob("/dev/dri/renderD*"):
        via = "/dev/dri"
    elif os.path.exists("/dev/kfd"):                      # AMD ROCm
        via = "/dev/kfd"
    hashcat = bool(which("hashcat"))
    return {
        "present": bool(via),
        "via": via,
        "hashcat": hashcat,
        "usable_for_cracking": bool(via and hashcat),
    }


@lru_cache(maxsize=1)
def _detect_cached() -> Dict[str, Any]:
    mem = _meminfo_mb()
    return {
        "cpu": {"count": os.cpu_count() or 1},
        "ram": mem,
        "gpu": _gpu_info(),
    }


def detect(force: bool = False) -> Dict[str, Any]:
    """What hardware this machine has (cached; ``force`` re-probes)."""
    if force:
        _detect_cached.cache_clear()
    found = _detect_cached()
    return {"cpu": dict(found["cpu"]), "ram": dict(found["ram"]),
            "gpu": dict(found["gpu"])}


def workers(config: Any) -> int:
    """How many crack worker processes CPU acceleration may use (1 = serial)."""
    if not accel_enabled(config, "cpu"):
        return 1
    wanted = int(getattr(config, "accel_workers", 0) or 0)
    if wanted > 0:
        return max(1, wanted)
    return max(1, os.cpu_count() or 1)


def cache_mb(config: Any) -> int:
    """MB of RAM the candidate caches may spend (0 when RAM use is not allowed)."""
    if not accel_enabled(config, "ram"):
        return 0
    wanted = int(getattr(config, "accel_ram_mb", 0) or 0)
    if wanted > 0:
        return wanted
    available = _meminfo_mb()["available_mb"]
    if available <= 0:
        return 256
    return max(64, min(available // 4, 2048))


def cache_entries(config: Any) -> int:
    """Roughly how many candidate strings fit in the RAM budget (~64 B each)."""
    return cache_mb(config) * 1024 * 1024 // 64


def apply_accel(config: Any, mode: Optional[Any] = None) -> Dict[str, Any]:
    """Apply an acceleration mode to a config; returns what was switched on.

    Only ever *adds* capability the operator asked for: CPU raises the engine's
    parallel ``jobs`` (capped, one radio still serialises Wi-Fi work), GPU
    points the cracker at hashcat when it exists, RAM just sizes the caches.
    """
    if mode is not None:
        parts = parse_accel(mode)
        config.accel = "all" if parts == frozenset(_PARTS) else (
            ",".join(p for p in _PARTS if p in parts) or "off")
    parts = parse_accel(getattr(config, "accel", "off"))
    report: Dict[str, Any] = {"mode": getattr(config, "accel", "off"),
                              "parts": sorted(parts), "notes": []}
    hardware = detect()
    if "cpu" in parts:
        count = workers(config)
        report["crack_workers"] = count
        jobs = max(int(getattr(config, "jobs", 1) or 1), min(count, 8))
        config.jobs = jobs
        report["jobs"] = jobs
        report["notes"].append(f"CPU: {count} crack worker(s), {jobs} parallel attack lane(s)")
    if "ram" in parts:
        report["cache_mb"] = cache_mb(config)
        report["notes"].append(
            f"RAM: up to {report['cache_mb']} MB of candidate caching")
    if "gpu" in parts:
        gpu = hardware["gpu"]
        report["gpu"] = gpu
        if gpu["usable_for_cracking"]:
            config.cracker = "hashcat"
            config.hashcat_workload = max(int(config.hashcat_workload or 3), 3)
            report["notes"].append(
                f"GPU: hashcat will drive it (seen via {gpu['via']}), "
                f"workload profile {config.hashcat_workload}")
        elif gpu["present"] and not gpu["hashcat"]:
            report["notes"].append(
                "GPU present but hashcat is not installed — run "
                "`wifipilot tools install` to use it; cracking stays on CPU")
        else:
            report["notes"].append(
                "no GPU detected — GPU acceleration requested but unavailable")
    return report


def accel_summary(config: Any) -> Dict[str, Any]:
    """Detected hardware + what the operator has allowed, for UIs and reports."""
    hardware = detect()
    allowed = sorted(parse_accel(getattr(config, "accel", "off")))
    return {
        "allowed": allowed,
        "mode": getattr(config, "accel", "off"),
        "hardware": hardware,
        "crack_workers": workers(config),
        "cache_mb": cache_mb(config),
    }
