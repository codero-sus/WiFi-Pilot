# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
# Copyright (c) 2025-2026 codero-sus
"""Hardware acceleration: multiprocessing CPU, RAM caches and GPU — on by default.

wifipilot uses the machine it is given.  ``config.accel`` defaults to
``"auto"``: CPU worker processes and RAM candidate caches are always on, and
the GPU joins in (via hashcat) when one is actually detected.  This module is
the single place that turns that setting into concrete numbers:

* **cpu** — the built-in cracker verifies candidates in a process pool, and
  the engine runs several non-radio attacks side by side (``jobs`` lanes).
* **ram** — candidates are de-duplicated across every pass in a big in-memory
  cache, so rule expansion never pays for the same PBKDF2 twice.
* **gpu** — hashcat (which drives the GPU) becomes the chosen cracker, with a
  full workload profile.
* **all** — everything above, GPU included whether or not one was detected.
* **off** — the classic single-threaded behaviour, for tiny VMs and shared
  boxes: ``--accel off`` / ``wp.configure(accel="off")``.

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
    "lanes", "cpu_count", "cache_mb", "cache_entries", "apply_accel",
    "accel_summary",
]

#: the values ``config.accel`` understands (comma combinations work too)
ACCEL_MODES = ("auto", "off", "cpu", "ram", "gpu", "all")

_PARTS = ("cpu", "ram", "gpu")


def cpu_count() -> int:
    """Usable CPUs: the affinity mask when the OS gives one (containers, CI)."""
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def _resolve_auto() -> FrozenSet[str]:
    """What ``"auto"`` means on this machine: CPU + RAM, GPU if it can crack."""
    parts = {"cpu", "ram"}
    gpu = detect()["gpu"]
    if gpu.get("usable_for_cracking"):
        parts.add("gpu")
    return frozenset(parts)


def parse_accel(value: Any) -> FrozenSet[str]:
    """Normalise an accel setting to the set of enabled resources.

    Accepts ``"auto"`` (CPU + RAM, plus GPU when detected — the default),
    ``"all"``, ``"cpu,gpu"``, ``True`` (everything), ``False``/``"off"``
    (nothing) and lists of parts.  Unknown words are ignored rather than
    guessed at.
    """
    if value is True:
        return frozenset(_PARTS)
    if not value or value is False:
        return frozenset()
    if isinstance(value, (list, tuple, set, frozenset)):
        parts = {str(v).strip().lower() for v in value}
    else:
        parts = {p.strip().lower() for p in str(value).replace("+", ",").split(",")}
    if parts == {"auto"}:
        return _resolve_auto()
    if "all" in parts or "everything" in parts or "full" in parts:
        return frozenset(_PARTS)
    return frozenset(p for p in parts if p in _PARTS)


def accel_enabled(config: Any, part: str) -> bool:
    """Did the operator allow this resource (``"cpu"`` / ``"ram"`` / ``"gpu"``)?"""
    return part in parse_accel(getattr(config, "accel", "auto"))


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
        "cpu": {"count": cpu_count()},
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
    return cpu_count()


def lanes(config: Any) -> int:
    """Parallel non-radio attack lanes the engine may run.

    An explicit ``config.jobs`` (> 0) wins — presets and ``--jobs`` set one.
    Otherwise the lanes follow the CPU: one per core, capped at 8, while CPU
    acceleration is on; strictly 1 (the classic serial engine) when off.
    """
    explicit = int(getattr(config, "jobs", 0) or 0)
    if explicit > 0:
        return explicit
    if not accel_enabled(config, "cpu"):
        return 1
    return max(1, min(cpu_count(), 8))


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

    CPU sizes the crack process pool and the engine's parallel lanes (one
    radio still serialises Wi-Fi work), GPU points the cracker at hashcat
    when it exists, RAM sizes the candidate caches.
    """
    if mode is not None:
        if isinstance(mode, str) and mode.strip().lower() == "auto":
            config.accel = "auto"
        else:
            parts = parse_accel(mode)
            config.accel = "all" if parts == frozenset(_PARTS) else (
                ",".join(p for p in _PARTS if p in parts) or "off")
    parts = parse_accel(getattr(config, "accel", "auto"))
    report: Dict[str, Any] = {"mode": getattr(config, "accel", "auto"),
                              "parts": sorted(parts),
                              "resolved": sorted(parts), "notes": []}
    hardware = detect()
    if "cpu" in parts:
        count = workers(config)
        report["crack_workers"] = count
        report["lanes"] = lanes(config)
        report["jobs"] = report["lanes"]
        report["notes"].append(
            f"CPU: {count} crack worker(s), {report['lanes']} parallel attack lane(s)")
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
    """Detected hardware + what acceleration resolves to, for UIs and reports."""
    hardware = detect()
    resolved = sorted(parse_accel(getattr(config, "accel", "auto")))
    return {
        "allowed": resolved,
        "resolved": resolved,
        "mode": getattr(config, "accel", "auto"),
        "hardware": hardware,
        "crack_workers": workers(config),
        "lanes": lanes(config),
        "cache_mb": cache_mb(config),
    }
