#!/usr/bin/env python3
"""Render the complete attack catalogue into ``docs/ATTACKS.md``.

The prose in that file is written by hand — what each attack answers, how to read its
result, how it fails.  The *list* must not be: an attack added without a line in the
matrix is an attack nobody can find, so the matrix is generated from the registry and
checked by the test suite.

Usage::

    python3 tools/gen_attack_docs.py            # rewrite the appendix in place
    python3 tools/gen_attack_docs.py --check     # exit 1 if it is out of date
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from wifipilot.attacks import (attack_catalog, category_label)   # noqa: E402
from wifipilot.attacks.meta import NOISE_STYLE, IMPACT_STYLE     # noqa: E402

START = "<!-- catalogue:start -->"
END = "<!-- catalogue:end -->"
RSTART = "<!-- attack-index:start -->"
REND = "<!-- attack-index:end -->"

FAMILIES = [("offline", "Offline analysis (no radio at all)"),
            ("survey", "Surveys the air, transmits nothing"),
            ("capture", "Capture requests (frames on air)"),
            ("wps", "WPS"), ("wep", "WEP"), ("enterprise", "Enterprise (802.1X)"),
            ("rogue", "Rogue infrastructure and lures"),
            ("dos", "Denial-of-service tests (opt-in)")]


def _clean(text: str) -> str:
    """One table cell: single line, pipes escaped."""
    return " ".join(str(text or "").split()).replace("|", "\\|")


def render() -> str:
    catalog = attack_catalog()
    offline = [entry for entry in catalog if entry["offline"]]
    noise = {}
    impact = {}
    for entry in catalog:
        noise[str(entry["noise"])] = noise.get(str(entry["noise"]), 0) + 1
        impact[str(entry["impact"])] = impact.get(str(entry["impact"]), 0) + 1

    lines = [START, "",
             "## 11. The complete catalogue",
             "",
             f"**{len(catalog)} attacks**, of which **{len(offline)}** transmit nothing at "
             "all — no radio, no monitor interface, no frame.  The table is generated from "
             "the registry (`python3 tools/gen_attack_docs.py`), so it cannot drift from the "
             "code: `wifipilot attacks` prints the same list, `--json` returns it, and the "
             "web UI, the planner and the report are all built from it.",
             "",
             "How to read the columns: **noise** is what a defender sees "
             f"({', '.join(f'{key} {value}' for key, value in sorted(noise.items()))}), "
             "**impact** is what the *network* loses when the attack works "
             f"({', '.join(f'{key} {value}' for key, value in sorted(impact.items()))}), and "
             "**detection** is the artefact left behind — the thing to look for in a "
             "capture when asking whether this was run against you.",
             ""]

    for category, label in FAMILIES:
        entries = [entry for entry in catalog if entry["category"] == category]
        if not entries:
            continue
        lines += [f"### {label} — {len(entries)}", "",
                  "| attack | answers | noise | impact | tool | defender sees |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for entry in entries:
            flags = []
            if entry["default_enabled"]:
                flags.append("on by default")
            if entry["needs_injection"]:
                flags.append("injects")
            name = f"`{entry['name']}`" + (f" <br>_{', '.join(flags)}_" if flags else "")
            lines.append(f"| {name} | {_clean(entry['label'])} | "
                         f"{NOISE_STYLE.get(str(entry['noise']), '') or entry['noise']} | "
                         f"{IMPACT_STYLE.get(str(entry['impact']), '') or entry['impact']} | "
                         f"{_clean(entry['tool'])} | {_clean(entry['detection'])} |")
        lines.append("")

    leftovers = [entry for entry in catalog
                 if entry["category"] not in ("offline", "survey", "capture", "wps", "wep",
                                              "enterprise", "rogue", "dos")]
    if leftovers:                                              # pragma: no cover - new family
        lines += [f"### Other — {len(leftovers)}", "",
                  "| attack | answers | category |", "| --- | --- | --- |"]
        for entry in leftovers:
            lines.append(f"| `{entry['name']}` | {_clean(entry['label'])} | "
                         f"{category_label(str(entry['category']))} |")
        lines.append("")

    lines += [f"<!-- {len(catalog)} attacks -->", END, ""]
    return "\n".join(lines)


def render_index() -> str:
    """A one-line-per-family index of every attack name, for the README.

    The README is the first thing anyone reads, so it has to be able to answer "is
    *my* attack in here" without opening another file — and it has to be generated,
    because a hand-written list of a hundred and sixty names is a list that is wrong.
    """
    catalog = attack_catalog()
    lines = [RSTART, "",
             "## Every attack at a glance",
             "",
             f"The full reference for each of the **{len(catalog)} attacks** — what it "
             "answers, what it costs, what goes on the air, how it fails — is in "
             "[docs/ATTACKS.md](docs/ATTACKS.md); this is the index. "
             "`wifipilot attacks` prints it with the metadata, `--json` returns it, and "
             "`--no-radio` filters it to the attacks that transmit nothing.",
             ""]
    for category, label in FAMILIES:
        names = [entry["name"] for entry in catalog if entry["category"] == category]
        if names:
            lines.append(f"* **{label} ({len(names)})** — " +
                         ", ".join(f"`{name}`" for name in names))
    leftovers = [entry["name"] for entry in catalog
                 if entry["category"] not in {name for name, _ in FAMILIES}]
    if leftovers:                                        # pragma: no cover - new family
        lines.append(f"* **Other ({len(leftovers)})** — " +
                     ", ".join(f"`{name}`" for name in leftovers))
    lines += ["", f"<!-- {len(catalog)} attacks -->", REND, ""]
    return "\n".join(lines)


def _target() -> str:
    return os.path.join(ROOT, "docs", "ATTACKS.md")


def main(argv) -> int:
    path = _target()
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    block = render()
    if START in text and END in text:
        head, _, rest = text.partition(START)
        _, _, tail = rest.partition(END)
        updated = head + block.rstrip("\n") + "\n" + tail.lstrip("\n")
    else:                                       # first run: append the appendix
        updated = text.rstrip("\n") + "\n\n" + block
    readme_path = os.path.join(ROOT, "README.md")
    with open(readme_path, encoding="utf-8") as handle:
        readme = handle.read()
    index = render_index()
    if RSTART in readme and REND in readme:
        head, _, rest = readme.partition(RSTART)
        _, _, tail = rest.partition(REND)
        readme_updated = head + index.rstrip("\n") + "\n" + tail.lstrip("\n")
    else:
        readme_updated = readme.rstrip("\n") + "\n\n" + index

    if "--check" in argv:
        if updated.strip() != text.strip() or readme_updated.strip() != readme.strip():
            print("the generated docs are out of date: run tools/gen_attack_docs.py",
                  file=sys.stderr)
            return 1
        return 0
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(updated)
    with open(readme_path, "w", encoding="utf-8") as handle:
        handle.write(readme_updated)
    print(f"catalogue written: {len(attack_catalog())} attacks "
          f"(docs/ATTACKS.md and the README index)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
