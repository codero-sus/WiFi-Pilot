"""File-level tooling: hash files, wordlists, potfiles and loot manifests.

Everything here works on *files*, never on a radio, so it is usable in a
pipeline or a CI job: merge the hashes three colleagues captured, dedupe them,
split them for a cracking farm, check a wordlist's shape before spending a night
on it, import whatever hashcat already cracked, and prove afterwards that the
loot directory has not changed.

Nothing in this module invents data.  A hash line that cannot be verified is
still written — with the reason surfaced — because losing an operator's capture
would be worse than reporting an imperfect one.
"""

from __future__ import annotations

import csv
import hashlib
import io
import os
from pathlib import Path
from typing import Dict, Iterator, List, Sequence, Tuple

from . import hash22000
from .hash22000 import HashLine
from .masks import expand_mask, mask_space
from .rules import apply_rules, parse_file as parse_rule_file, preset as rule_preset

__all__ = [
    "hash_stats", "merge_hash_files", "dedupe_hash_file", "filter_hash_file",
    "split_hash_file", "normalize_hash_file", "rescue_partial_capture",
    "wordlist_stats", "merge_wordlists", "expand_wordlist", "wordlist_from_masks",
    "read_potfile", "potfile_entries", "potfile_export", "potfile_remove",
    "write_manifest", "verify_manifest", "MANIFEST_NAME",
]

MANIFEST_NAME = "manifest.sha256"

#: dedup key: everything that decides whether a line is crackable at all.  The
#: message-pair byte is deliberately *not* part of it (hashcat dedupes the same
#: way): the same handshake seen twice is one handshake.
_DEDUP_FIELDS = ("kind", "bssid", "station")


def _line_key(line: HashLine) -> Tuple[str, ...]:
    return (line.kind, line.bssid, line.station, line.essid_bytes.hex(),
            line.pmkid if line.kind == "pmkid" else line.mic.hex(),
            line.nonce.hex(), line.eapol.hex())


def _read_lines(path: str) -> Tuple[List[HashLine], List[str]]:
    """(lines, problems) — an unreadable file is a problem, not an exception."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return [], [f"{os.path.basename(str(path))}: {error.strerror or 'unreadable'}"]
    return hash22000.parse_text(text)


# --------------------------------------------------------------------------- #
# hash files
# --------------------------------------------------------------------------- #

def hash_stats(path: str) -> Dict[str, object]:
    """What is in a mode 22000 file, including what cannot be verified."""
    lines, problems = _read_lines(path)
    data = hash22000.summary(lines, problems)
    data["path"] = str(path)
    data["readable"] = os.path.isfile(path)
    data["size"] = os.path.getsize(path) if data["readable"] else 0
    data["unverifiable"] = [line.label for line in lines if not line.verifiable]
    data["files"] = 1
    return data


def merge_hash_files(paths: Sequence[str], out: str = "", dedupe: bool = True
                     ) -> Dict[str, object]:
    """Merge hash files into one, optionally dropping duplicates.

    Returns ``{"path", "written", "duplicates", "sources", "problems"}``.
    """
    merged: List[str] = []
    seen: set = set()
    duplicates = 0
    problems: List[str] = []
    for path in paths:
        lines, file_problems = _read_lines(path)
        problems.extend(f"{os.path.basename(path)}: {problem}" for problem in file_problems)
        for line in lines:
            key = _line_key(line)
            if dedupe and key in seen:
                duplicates += 1
                continue
            seen.add(key)
            merged.append(line.raw or "")
    target = out or (os.path.splitext(str(paths[0]))[0] + "-merged.hc22000" if paths else "")
    if not target:
        raise ValueError("nothing to merge")
    hash22000.write_lines(merged, target)
    return {"path": target, "written": len(merged), "duplicates": duplicates,
            "sources": [str(p) for p in paths], "problems": problems}


def dedupe_hash_file(path: str, out: str = "") -> Dict[str, object]:
    """Drop duplicate lines (same hash, different message-pair byte)."""
    result = merge_hash_files([path], out or path, dedupe=True)
    result["duplicates"] = result["duplicates"]
    return result


def filter_hash_file(path: str, out: str = "", essid: str = "", bssid: str = "",
                     kind: str = "", verifiable_only: bool = False) -> Dict[str, object]:
    """Keep only the lines matching the filters; everything else is dropped."""
    lines, problems = _read_lines(path)
    kept: List[str] = []
    dropped = 0
    for line in lines:
        if essid and essid.lower() not in (line.essid or "").lower():
            dropped += 1
            continue
        if bssid and line.bssid.lower() != bssid.lower():
            dropped += 1
            continue
        if kind and line.kind != kind:
            dropped += 1
            continue
        if verifiable_only and not line.verifiable:
            dropped += 1
            continue
        kept.append(line.raw or "")
    target = out or (os.path.splitext(path)[0] + "-filtered.hc22000")
    hash22000.write_lines(kept, target)
    return {"path": target, "written": len(kept), "dropped": dropped,
            "problems": problems}


def split_hash_file(path: str, out_dir: str, per_file: int = 1) -> Dict[str, object]:
    """Split a hash file into chunks of ``per_file`` lines (for a cracking farm)."""
    lines, problems = _read_lines(path)
    per_file = max(1, int(per_file))
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    stem = Path(path).stem or "hashes"
    chunks: List[str] = []
    for index in range(0, len(lines), per_file):
        chunk = lines[index:index + per_file]
        target = str(Path(out_dir) / f"{stem}-{index // per_file + 1:03d}.hc22000")
        hash22000.write_lines([line.raw or "" for line in chunk], target)
        chunks.append(target)
    return {"path": out_dir, "files": len(chunks), "written": len(lines),
            "chunks": chunks, "problems": problems}


def normalize_hash_file(path: str, out: str = "") -> Dict[str, object]:
    """Rewrite a hash file canonically (sorted, lower-case hex, MACs as-is).

    Canonical form makes two files comparable with ``diff`` and makes the
    dedupe deterministic across tools that emit different field orderings.
    """
    lines, problems = _read_lines(path)
    rendered: List[str] = []
    changed = 0
    for line in lines:
        text = line.raw or ""
        canonical = _canonical_line(line)
        if canonical != text:
            changed += 1
        rendered.append(canonical)
    rendered.sort()
    target = out or (os.path.splitext(path)[0] + "-normalized.hc22000")
    hash22000.write_lines(rendered, target)
    return {"path": target, "written": len(rendered), "changed": changed,
            "problems": problems}


def _canonical_line(line: HashLine) -> str:
    """The same hash, written the way hashcat writes it.

    Mode 22000 takes *bare* hex MACs — a canonicaliser that emitted the
    colons we display would produce a file hashcat (and our own parser)
    refuses, so the MACs are stripped back down here.
    """
    essid = line.essid_bytes.hex()
    ap = line.bssid.replace(":", "").lower()
    station = line.station.replace(":", "").lower()
    if line.kind == "pmkid":
        return f"WPA*01*{line.pmkid.lower()}*{ap}*{station}*{essid}***"
    return (f"WPA*02*{line.mic.hex().lower()}*{ap}*{station}*{essid}"
            f"*{line.nonce.hex().lower()}*{line.eapol.hex().lower()}*"
            f"{line.message_pair:02x}")


def rescue_partial_capture(capture: str, out: str = "") -> Dict[str, object]:
    """Recover hashes from a capture the normal converter would skip.

    A PMKID can arrive in the RSN PMKID KDE of *message 1* — before any client
    replies — so a capture with no complete pair can still be crackable.  This
    walks every EAPOL message that carried a PMKID (not just the "crackable"
    handshakes) and writes those lines.
    """
    from .pcap import analyze_file
    analysis = analyze_file(str(capture))
    found: Dict[Tuple[str, str], str] = {}
    for handshake in analysis.handshakes:
        for message in handshake.messages.values():
            if not message.pmkid:
                continue
            key = (handshake.bssid, message.pmkid.lower())
            if key in found:
                continue
            line = hash22000.line_from_pmkid(
                handshake.bssid, message.station or handshake.station,
                analysis.essids.get(handshake.bssid, ""), message.pmkid)
            if line:
                found[key] = line
    partial = [(bssid, pmkid) for (bssid, pmkid) in
               {h.bssid: h.pmkid for h in analysis.handshakes if h.pmkid}.items()
               if (bssid, pmkid.lower()) not in found]
    for bssid, pmkid in partial:
        line = hash22000.line_from_pmkid(bssid, "", analysis.essids.get(bssid, ""), pmkid)
        if line:
            found[(bssid, pmkid.lower())] = line
    target = out or (os.path.splitext(str(capture))[0] + "-rescued.hc22000")
    hash22000.write_lines(list(found.values()), target)
    return {"path": target, "written": len(found),
            "crackable": len(analysis.crackable_handshakes()),
            "messages": analysis.eapol_messages,
            "note": ("PMKID KDEs found in any EAPOL message, including M1"
                     if found else "no PMKID in this capture: nothing to rescue")}


# --------------------------------------------------------------------------- #
# wordlists
# --------------------------------------------------------------------------- #

def _wordlist_files(paths: Sequence[str]) -> List[str]:
    out: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            out.extend(sorted(str(Path(path) / name) for name in os.listdir(path)
                              if not name.startswith(".")))
        else:
            out.append(str(path))
    return out


def iter_words(path: str, min_length: int = 1, max_length: int = 0) -> Iterator[str]:
    """Stream a wordlist (plain or ``.gz``), skipping blanks and comments."""
    import gzip
    opener = gzip.open if str(path).endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                word = line.rstrip("\n").rstrip("\r")
                if not word or word.startswith("#"):
                    continue
                if len(word) < min_length:
                    continue
                if max_length and len(word) > max_length:
                    continue
                yield word
    except (OSError, EOFError, gzip.BadGzipFile):
        return


def wordlist_stats(path: str, sample_limit: int = 200_000) -> Dict[str, object]:
    """Shape of a wordlist: sizes, lengths, character classes, uniqueness.

    Uniqueness is measured exactly for files up to ``sample_limit`` words and
    estimated above it — the estimate is labelled as such rather than passed off
    as a count.
    """
    files = _wordlist_files([path])
    total_path = files[0] if files else str(path)
    size = os.path.getsize(total_path) if os.path.exists(total_path) else 0
    lines = 0
    unique: set = set()
    exact = True
    lengths: List[int] = []
    classes = {"lower": 0, "upper": 0, "digits": 0, "symbols": 0, "mixed": 0}
    for word in iter_words(total_path):
        lines += 1
        lengths.append(len(word))
        if lines <= sample_limit:
            unique.add(word)
        else:
            if exact:
                exact = False
        has_lower = any(c.islower() for c in word)
        has_upper = any(c.isupper() for c in word)
        has_digit = any(c.isdigit() for c in word)
        has_symbol = any(not c.isalnum() for c in word)
        if has_lower and not (has_upper or has_digit or has_symbol):
            classes["lower"] += 1
        elif has_upper and not (has_lower or has_digit or has_symbol):
            classes["upper"] += 1
        elif has_digit and not (has_lower or has_upper or has_symbol):
            classes["digits"] += 1
        elif has_symbol and not (has_lower or has_upper or has_digit):
            classes["symbols"] += 1
        else:
            classes["mixed"] += 1
    wpa = [length for length in lengths if 8 <= length <= 63]
    return {
        "path": total_path, "bytes": size, "lines": lines,
        "unique": len(unique), "unique_exact": exact,
        "duplicates": (lines - len(unique)) if exact else None,
        "min_length": min(lengths) if lengths else 0,
        "max_length": max(lengths) if lengths else 0,
        "average_length": round(sum(lengths) / len(lengths), 2) if lengths else 0.0,
        "wpa_compatible": len(wpa),
        "wpa_rejected": lines - len(wpa),
        "classes": classes,
        "estimated_seconds_builtin": round(len(wpa) / 415.0, 1),
        "estimated_seconds_hashcat_cpu": round(len(wpa) / 100_000.0, 1),
    }


def merge_wordlists(paths: Sequence[str], out: str, dedupe: bool = True,
                    min_length: int = 8, max_length: int = 63,
                    limit: int = 0) -> Dict[str, object]:
    """Merge wordlists into one WPA-shaped list (8-63 characters by default)."""
    seen: set = set()
    written = 0
    duplicates = 0
    rejected = 0
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        for path in _wordlist_files(paths):
            for word in iter_words(path):
                if not (min_length <= len(word) <= max_length):
                    rejected += 1
                    continue
                if dedupe:
                    if word in seen:
                        duplicates += 1
                        continue
                    seen.add(word)
                handle.write(word + "\n")
                written += 1
                if limit and written >= limit:
                    return {"path": out, "written": written, "duplicates": duplicates,
                            "rejected": rejected, "truncated": True}
    return {"path": out, "written": written, "duplicates": duplicates,
            "rejected": rejected, "truncated": False}


def expand_wordlist(path: str, out: str, rule_spec: str = "best64",
                    limit: int = 0, min_length: int = 8, max_length: int = 63
                    ) -> Dict[str, object]:
    """Apply a rule set (a ``.rule`` file, or a preset name) to a wordlist."""
    if os.path.exists(rule_spec):
        rules = parse_rule_file(rule_spec)
    else:
        rules = rule_preset(rule_spec)
    written = 0
    base = 0
    seen: set = set()
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        for word in iter_words(path):
            base += 1
            for candidate in apply_rules(word, rules, dedupe=True):
                if not (min_length <= len(candidate) <= max_length):
                    continue
                if candidate in seen:
                    continue
                seen.add(candidate)
                handle.write(candidate + "\n")
                written += 1
                if limit and written >= limit:
                    return {"path": out, "written": written, "base_words": base,
                            "rules": len(rules), "truncated": True}
    return {"path": out, "written": written, "base_words": base,
            "rules": len(rules), "truncated": False}


def wordlist_from_masks(patterns: Sequence[str], out: str, limit: int = 0
                        ) -> Dict[str, object]:
    """Write the candidates of one or more masks to a wordlist."""
    written = 0
    space = sum(mask_space(pattern) for pattern in patterns)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    seen: set = set()
    with open(out, "w", encoding="utf-8") as handle:
        for pattern in patterns:
            for candidate in expand_mask(pattern):
                if candidate in seen:
                    continue
                seen.add(candidate)
                handle.write(candidate + "\n")
                written += 1
                if limit and written >= limit:
                    return {"path": out, "written": written, "space": space,
                            "patterns": list(patterns), "truncated": True}
    return {"path": out, "written": written, "space": space,
            "patterns": list(patterns), "truncated": False}


# --------------------------------------------------------------------------- #
# potfiles
# --------------------------------------------------------------------------- #

def read_potfile(path: str) -> Dict[str, str]:
    """``{hash: password}`` from a hashcat potfile (last entry wins)."""
    out: Dict[str, str] = {}
    if not path or not os.path.exists(path):
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line or ":" not in line:
                    continue
                digest, _, password = line.rpartition(":")
                out[digest] = password
    except OSError:
        return out
    return out


def potfile_entries(path: str, limit: int = 0) -> List[Dict[str, str]]:
    """Potfile entries with the hash type and the network, when it is a WPA line."""
    entries: List[Dict[str, str]] = []
    for digest, password in read_potfile(path).items():
        entry = {"hash": digest, "password": password, "kind": "", "essid": "",
                 "bssid": ""}
        if digest.upper().startswith("WPA*"):
            line, problem = hash22000.parse_line(digest)
            if line is not None:
                entry.update(kind=line.kind, essid=line.essid, bssid=line.bssid)
        entries.append(entry)
        if limit and len(entries) >= limit:
            break
    return entries


def potfile_export(path: str, out: str = "", fmt: str = "csv") -> Dict[str, object]:
    """Export a potfile as CSV or JSON (never in the clear to stdout by default)."""
    entries = potfile_entries(path)
    if fmt == "json":
        import json
        text = json.dumps({"entries": entries, "count": len(entries)}, indent=2)
    else:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["essid", "bssid", "kind", "password", "hash"])
        for entry in entries:
            writer.writerow([entry["essid"], entry["bssid"], entry["kind"],
                             entry["password"], entry["hash"]])
        text = buffer.getvalue()
    if out:
        Path(out).write_text(text, encoding="utf-8")
    return {"path": out, "count": len(entries), "format": fmt, "text": text}


def potfile_remove(path: str, needle: str) -> Dict[str, object]:
    """Delete every potfile entry whose hash or password contains ``needle``."""
    if not os.path.exists(path):
        return {"path": path, "removed": 0, "kept": 0}
    kept: List[str] = []
    removed = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.rstrip("\n")
            if stripped and needle and needle in stripped:
                removed += 1
                continue
            if stripped:
                kept.append(stripped)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(line + "\n" for line in kept))
    return {"path": path, "removed": removed, "kept": len(kept)}


def potfile_lookup(path: str, lines: Sequence[HashLine]) -> Dict[str, str]:
    """Which of ``lines`` the potfile already knows the password for.

    hashcat stores the *whole* hash line as the digest, so the lookup is exact —
    but tools differ in the message-pair byte, so the dedup key is used as a
    fallback.
    """
    potfile = read_potfile(path)
    if not potfile:
        return {}
    by_key = {}
    for digest, password in potfile.items():
        if not digest.upper().startswith("WPA*"):
            continue
        line, _ = hash22000.parse_line(digest)
        if line is not None:
            by_key[_line_key(line)] = password
    found: Dict[str, str] = {}
    for line in lines:
        password = potfile.get(line.raw or "") or by_key.get(_line_key(line))
        if password:
            found[line.raw or ""] = password
    return found


# --------------------------------------------------------------------------- #
# loot manifests
# --------------------------------------------------------------------------- #

def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(directory: str, path: str = "") -> Dict[str, object]:
    """Write ``manifest.sha256`` for every file in a loot directory."""
    root = Path(directory)
    target = Path(path) if path else root / MANIFEST_NAME
    entries: List[Tuple[str, str, int]] = []
    for item in sorted(root.rglob("*")):
        if not item.is_file() or item.name == MANIFEST_NAME:
            continue
        rel = str(item.relative_to(root))
        entries.append((rel, _sha256(str(item)), item.stat().st_size))
    target.write_text("".join(f"{digest}  {rel}\n" for rel, digest, _ in entries),
                      encoding="utf-8")
    return {"path": str(target), "files": len(entries),
            "bytes": sum(size for _, _, size in entries),
            "directory": str(root)}


def verify_manifest(directory: str, path: str = "") -> Dict[str, object]:
    """Check a loot directory against its manifest (missing/changed/extra)."""
    root = Path(directory)
    target = Path(path) if path else root / MANIFEST_NAME
    if not target.exists():
        return {"path": str(target), "ok": False, "reason": "no manifest",
                "missing": [], "changed": [], "extra": [], "checked": 0}
    recorded: Dict[str, str] = {}
    for line in target.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        if rel:
            recorded[rel] = digest
    missing: List[str] = []
    changed: List[str] = []
    for rel, digest in recorded.items():
        item = root / rel
        if not item.exists():
            missing.append(rel)
        elif _sha256(str(item)) != digest:
            changed.append(rel)
    extra = [str(item.relative_to(root)) for item in sorted(root.rglob("*"))
             if item.is_file() and item.name != MANIFEST_NAME
             and str(item.relative_to(root)) not in recorded]
    return {"path": str(target), "ok": not (missing or changed),
            "checked": len(recorded), "missing": missing, "changed": changed,
            "extra": extra}
