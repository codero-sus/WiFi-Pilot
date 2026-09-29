"""Target scoring, plan validation and the deterministic fallback planner.

The LLM advisor is optional; this module is what runs when it is unavailable,
and it is also the safety net that validates whatever the model proposes.  A
hallucinated BSSID, a disabled attack or an "attack" that does not exist never
reaches the radio — every plan goes through :func:`validate_plan`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .config import Config
from .deps import registry
from .models import ATTACK_NAMES, STATUS_FAILED, STATUS_SUCCESS, AccessPoint
from .session import Session
from .util import clamp, mac_norm

#: actions the planner may emit — attacks plus the two meta actions
PLANNER_ACTIONS = tuple(ATTACK_NAMES) + ("crack", "stop")

MAX_ACTIONS = 6


@dataclass
class Action:
    attack: str
    bssid: str = ""
    reason: str = ""
    priority: int = 5
    params: Dict[str, Any] = field(default_factory=dict)
    source: str = "heuristic"

    def to_dict(self) -> Dict[str, Any]:
        return {"attack": self.attack, "bssid": self.bssid, "reason": self.reason,
                "priority": self.priority, "params": self.params, "source": self.source}


@dataclass
class Plan:
    actions: List[Action] = field(default_factory=list)
    reasoning: str = ""
    source: str = "heuristic"          # heuristic | llm
    model: str = ""
    provider: str = ""                 # ollama | openrouter | heuristic
    notes: str = ""
    stop: bool = False
    created: float = field(default_factory=time.time)
    latency: float = 0.0
    dropped: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actions": [a.to_dict() for a in self.actions],
            "reasoning": self.reasoning, "source": self.source, "model": self.model,
            "provider": self.provider,
            "notes": self.notes, "stop": self.stop, "created": self.created,
            "latency": round(self.latency, 2), "dropped": self.dropped,
            "summary": self.summary(),
        }

    def summary(self) -> str:
        if not self.actions:
            return self.reasoning or "no actions"
        return "; ".join(f"{a.attack} {a.bssid}" + (f" ({a.reason})" if a.reason else "")
                         for a in self.actions[:4])


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #


def score_ap(ap: AccessPoint, config: Config) -> Tuple[float, List[str]]:
    """Rate how attractive/attackable an AP is.  Returns (score, reasons)."""
    score = 0.0
    reasons: List[str] = []

    if ap.cracked:
        return -1000.0, ["already cracked"]

    # signal quality (stronger = less packet loss)
    quality = clamp(2 * (ap.signal + 100), 0, 100)
    score += quality / 5.0
    if ap.signal >= -60:
        reasons.append("strong signal")

    # encryption
    if ap.encryption == "WEP":
        score += 35
        reasons.append("WEP (trivially broken)")
    elif ap.encryption == "WPA2":
        score += 12
    elif ap.encryption == "WPA":
        score += 8
        reasons.append("WPA1/TKIP")
    elif ap.encryption == "WPA2/WPA3":
        score += 6
        reasons.append("transition mode (WPA2 clients still attackable)")
    elif ap.encryption == "WPA3":
        score -= 45
        reasons.append("WPA3-SAE: handshake/PMKID attacks do not apply")
    elif ap.encryption in ("OWE",):
        score -= 30
        reasons.append("OWE: no PSK to recover")
    elif ap.encryption == "OPEN":
        score -= 60
        reasons.append("open network: nothing to crack")

    # WPS
    if ap.wps:
        if ap.wps_locked == "unlocked":
            score += 22
            reasons.append("WPS unlocked (Pixie-Dust candidate)")
        elif ap.wps_locked == "locked":
            score -= 12
            reasons.append("WPS locked/rate-limited")
        else:
            score += 8
            reasons.append("WPS enabled, lock state unknown")
        if ap.wps_model:
            score += 2

    # clients (deauth requires someone to deauth)
    clients = len(ap.clients)
    if clients:
        score += min(14, 4 + clients * 2)
        reasons.append(f"{clients} client(s) to deauth")
    else:
        score -= 2
        reasons.append("no clients: prefer PMKID")

    # progress already made
    if ap.has_pmkid and not ap.cracked:
        score += 25
        reasons.append("PMKID captured, needs cracking")
    if ap.has_handshake and not ap.cracked:
        score += 25
        reasons.append("handshake captured, needs cracking")

    # cost of past failures
    failures = sum(1 for a in ap.attempts if a.status == STATUS_FAILED)
    if failures:
        score -= failures * 9
        reasons.append(f"{failures} failed attempt(s)")

    # vendor intel
    if ap.vendor:
        score += 1
    if ap.hidden:
        score -= 3
        reasons.append("hidden SSID (lock/PMKID still workable)")

    # budget pressure: cheap targets first when time is short
    if ap.encryption == "WPA3" and not ap.sai:
        score -= 10

    return score, reasons


def rank_targets(session: Session, config: Optional[Config] = None,
                 limit: int = 5) -> List[Tuple[AccessPoint, float, List[str]]]:
    config = config or session.config
    ranked: List[Tuple[AccessPoint, float, List[str]]] = []
    for ap in session.aps.values():
        score, reasons = score_ap(ap, config)
        ap.score = score
        if reasons:
            ap.pick_reason = "; ".join(reasons[:4])
        ranked.append((ap, score, reasons))
    ranked.sort(key=lambda item: item[1], reverse=True)
    return ranked[:limit]


def attackable_hidden(ap: AccessPoint) -> bool:
    """Is this AP a hidden network whose name we could still learn?"""
    return not ap.cracked and not (ap.essid or "").strip()


def preferred_attacks(ap: AccessPoint, config: Config) -> List[str]:
    """Which attack should this AP get, best first, given its current state?"""
    enabled = [a for a in config.attacks if a in PLANNER_ACTIONS]
    caps = registry.capabilities() if not config.demo else {k: True for k in (
        "aircrack", "airodump", "deauth", "monitor", "wps", "wash", "pmkid",
        "hcxtools", "hashcat", "john", "iw", "nmcli", "root", "mdk4", "hostapd",
        "twin")}
    out: List[str] = []

    def allow(name: str) -> bool:
        if name not in enabled:
            return False
        if config.demo:
            # simulation mode drives a fake radio: the real toolchain is irrelevant
            return True
        if name in ("wps_pixie", "wps_pin") and not caps.get("wps"):
            return False
        if name == "pmkid" and not (caps.get("pmkid") or caps.get("airodump")):
            return False
        if name == "handshake" and not (caps.get("airodump") and (caps.get("deauth") or config.stealth)):
            return False
        if name == "wep_ivs" and not caps.get("airodump"):
            return False
        if name == "hidden_ssid" and not caps.get("airodump"):
            return False
        if name == "enterprise" and not caps.get("airodump"):
            return False
        if name == "tracker" and not caps.get("airodump"):
            return False
        if name in ("saewolf", "pmf_audit") and not caps.get("airodump"):
            # both are read-only, but they still need the capture stack
            return False
        if name == "pmkid_flood" and not (caps.get("airodump") and caps.get("deauth")):
            return False
        if name.startswith("wep_") and name != "wep_ivs":
            # every additional WEP technique needs injection on top of the capture
            if not (caps.get("airodump") and caps.get("deauth")):
                return False
        if name == "evil_twin":
            if config.stealth or not caps.get("twin"):
                return False
        if name in ("deauth_flood", "beacon_flood"):
            # a flood is a deliberate denial of service: never in stealth mode
            if config.stealth or not caps.get("mdk4"):
                return False
        if name == "rogue_radius":
            # a rogue RADIUS needs one of the impersonation tools; without them the
            # read-only enterprise survey is what is left
            if not any(registry.path(binary) for binary in
                       ("eaphammer", "hostapd-mana", "hostapd-wpe")):
                return False
            if not caps.get("monitor") or not caps.get("airodump"):
                return False
        return True                       # rogue_ap is pure analysis: no radio

    if ap.cracked:
        return []
    # already have loot -> crack it
    if (ap.has_handshake or ap.has_pmkid) and not config.skip_crack:
        out.append("crack")
    # read-only surveys change what we know, so they run before anything noisy
    if allow("pmf_audit") and not ap.pmf_checked:
        # which classic attacks are still possible on this AP?  known before we try
        out.append("pmf_audit")
    if attackable_hidden(ap) and allow("hidden_ssid"):
        out.append("hidden_ssid")
    # following a station is read-only and decides which name is worth impersonating,
    # so it comes before anything that transmits
    if ap.clients and allow("tracker"):
        out.append("tracker")
    enterprise = (ap.encryption in ("WPA-ENTERPRISE", "WPA2-ENTERPRISE", "ENTERPRISE")
                  or (ap.auth or "").upper() in ("MGT", "802.1X", "ENTERPRISE"))
    if enterprise:
        if allow("enterprise") and not ap.has_handshake:
            out.append("enterprise")
        # only after the survey says the certificate is checkable-or-not: impersonating
        # a network whose clients do validate certificates wastes radio time
        if allow("rogue_radius") and not config.stealth:
            out.append("rogue_radius")
        return _prune(out, ap)      # there is no PSK here to grab or crack
    if ap.encryption == "WEP":
        # the harvest first: it is the attack that actually recovers the key
        if allow("wep_ivs"):
            out.append("wep_ivs")
        # then the techniques that get an idle network moving again
        if allow("wep_p0841"):
            out.append("wep_p0841")
        if not ap.clients:
            if allow("wep_chopchop"):
                out.append("wep_chopchop")
            if allow("wep_fragment"):
                out.append("wep_fragment")
        elif allow("wep_hirte"):
            out.append("wep_hirte")
    if ap.wps and ap.wps_open:
        if allow("wps_pixie"):
            out.append("wps_pixie")
        if allow("wps_pin") and not config.stealth:
            out.append("wps_pin")
    if ap.encryption == "WPA3" and ap.sae:
        # a WPA3-only network is not cracked with a deauth: it is captured and audited
        if allow("saewolf") and not ap.sai:
            out.append("saewolf")
        return _prune(out, ap)
    if ap.encryption in ("WPA", "WPA2", "WPA2/WPA3"):
        if allow("saewolf") and ap.sae:
            # transition mode: the SAE half is worth a capture for the report
            out.append("saewolf")
        if not ap.clients and allow("pmkid") and not ap.has_pmkid:
            out.append("pmkid")
        if (ap.clients and allow("pmkid_flood") and not ap.has_pmkid
                and not config.stealth and not ap.sae):
            # a whisper-quiet AP still answers M1 if we make its clients reconnect
            out.append("pmkid_flood")
        if allow("handshake") and not ap.has_handshake and not (ap.sae and not ap.sai):
            out.append("handshake")
        elif not ap.clients and allow("pmkid") and not ap.has_pmkid:
            out.append("pmkid")
    if config.stealth and allow("passive") and not ap.has_handshake and not ap.has_pmkid:
        out.append("passive")
    # the twin is a *lure*, not a capture: it goes last, after everything quiet has
    # been tried, and only when the operator asked for it
    if allow("evil_twin") and not ap.cracked and (ap.essid or "").strip():
        out.append("evil_twin")
    if allow("deauth_flood") and not config.stealth:
        out.append("deauth_flood")
    if allow("beacon_flood") and not config.stealth:
        out.append("beacon_flood")

    return _prune(out, ap)


def _prune(out: List[str], ap: AccessPoint) -> List[str]:
    """Never repeat an attack that succeeded, or failed twice, on one target."""
    failures: Dict[str, int] = {}
    succeeded: set = set()
    for attempt in ap.attempts:
        if attempt.status == STATUS_FAILED:
            failures[attempt.attack] = failures.get(attempt.attack, 0) + 1
        elif attempt.status == STATUS_SUCCESS:
            succeeded.add(attempt.attack)
    result = []
    for name in dict.fromkeys(out):
        if name in succeeded:
            continue
        if failures.get(name, 0) >= 2:
            continue
        result.append(name)
    return result


def heuristic_plan(session: Session, config: Optional[Config] = None,
                   limit: int = 3) -> Plan:
    """Deterministic plan used when no LLM is available (or agreed with it)."""
    config = config or session.config
    ranked = rank_targets(session, config, limit=limit)
    actions: List[Action] = []
    for ap, score, reasons in ranked:
        if score <= -50:
            continue
        for attack in preferred_attacks(ap, config)[:2]:
            actions.append(Action(
                attack=attack, bssid=ap.bssid,
                reason="; ".join(reasons[:3]) or "highest ranked target",
                priority=len(actions) + 1, source="heuristic",
            ))
        if len(actions) >= MAX_ACTIONS:
            break
    reasoning = (f"ranked {len(session.aps)} APs by signal, encryption, WPS state and "
                 f"prior attempts; selected {len(actions)} action(s)")
    if not actions:
        reasoning = ("no attackable target right now — everything is either cracked, "
                     "WPA3-only, open, or has exhausted its attack budget")
    return Plan(actions=actions, reasoning=reasoning, source="heuristic")


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def validate_plan(raw: Any, session: Session, config: Optional[Config] = None,
                  source: str = "llm", model: str = "") -> Plan:
    """Turn untrusted LLM output into a safe, executable plan.

    Anything that is not explicitly allowed is dropped and reported in
    ``plan.dropped`` so the operator can see the model was overruled.
    """
    config = config or session.config
    plan = Plan(source=source, model=model)
    dropped: List[str] = []
    if not isinstance(raw, dict):
        plan.dropped = ["model did not return a JSON object"]
        return plan

    plan.reasoning = str(raw.get("reasoning") or raw.get("think") or "").strip()[:2000]
    plan.notes = str(raw.get("notes") or "").strip()[:600]
    plan.stop = bool(raw.get("stop"))
    actions = raw.get("actions")
    if isinstance(actions, dict):
        actions = [actions]
    if not isinstance(actions, list):
        plan.dropped = ["no 'actions' array in model output"]
        return plan

    seen = set()
    for index, item in enumerate(actions[:MAX_ACTIONS * 2]):
        if not isinstance(item, dict):
            dropped.append(f"action {index}: not an object")
            continue
        attack = str(item.get("attack") or "").strip().lower()
        if attack not in PLANNER_ACTIONS:
            dropped.append(f"action {index}: unknown attack {attack!r}")
            continue
        if attack == "stop":
            plan.stop = True
            continue
        if attack not in config.attacks and attack != "crack":
            dropped.append(f"{attack}: disabled in this engagement")
            continue
        bssid = mac_norm(str(item.get("bssid") or ""))
        if not bssid:
            dropped.append(f"action {index}: missing/invalid BSSID")
            continue
        ap = session.ap(bssid)
        if ap is None:
            dropped.append(f"{bssid}: not a discovered target")
            continue
        if (bssid, attack) in seen:
            dropped.append(f"{bssid}/{attack}: duplicate")
            continue
        # hard safety rules — never overridden by the model
        if attack == "handshake" and ap.encryption == "WPA3":
            dropped.append(f"{bssid}: WPA3-SAE cannot be attacked with deauth")
            continue
        if attack in ("wps_pixie", "wps_pin") and not ap.wps:
            dropped.append(f"{bssid}: no WPS detected")
            continue
        if attack == "wep_ivs" and ap.encryption != "WEP":
            dropped.append(f"{bssid}: not a WEP network")
            continue
        if attack in ("handshake", "pmkid") and ap.encryption in ("OPEN", "OWE", "WEP"):
            dropped.append(f"{bssid}: no PSK handshake for {ap.encryption}")
            continue
        if attack == "pmkid" and ap.encryption == "WPA3" and not ap.sai:
            dropped.append(f"{bssid}: WPA3-SAE does not expose a PSK PMKID")
            continue
        if attack == "crack" and not (ap.has_handshake or ap.has_pmkid):
            dropped.append(f"{bssid}: nothing captured yet, cannot crack")
            continue
        if attack in ("wep_p0841", "wep_chopchop", "wep_fragment", "wep_hirte",
                       "wep_ivs") and ap.encryption != "WEP":
            dropped.append(f"{bssid}: {attack} only applies to WEP")
            continue
        if attack == "saewolf" and not (ap.sae or "WPA3" in (ap.encryption or "")):
            dropped.append(f"{bssid}: not a WPA3 network, there is no SAE exchange")
            continue
        if attack == "pmkid_flood" and ap.encryption in ("OPEN", "OWE", "WEP", "WPA3"):
            dropped.append(f"{bssid}: no PSK PMKID to force on {ap.encryption}")
            continue
        if attack in ("deauth_flood", "beacon_flood"):
            if config.stealth:
                dropped.append(f"{bssid}: {attack} is a denial of service; "
                               f"stealth mode is on")
                continue
            if ap.cracked and attack == "deauth_flood":
                dropped.append(f"{bssid}: already cracked, no reason to disconnect it")
                continue
        if attack == "evil_twin":
            if (ap.auth or "").upper() in ("MGT", "802.1X", "ENTERPRISE"):
                dropped.append(f"{bssid}: 802.1X clients need rogue_radius, not a PSK twin")
                continue
            if not (ap.essid or "").strip():
                dropped.append(f"{bssid}: hidden network, a twin needs a name to serve")
                continue
            if config.stealth:
                dropped.append(f"{bssid}: the twin transmits; stealth mode is on")
                continue
        if attack == "wps_pin" and config.stealth:
            dropped.append(f"{bssid}: online PIN brute force disabled in stealth mode")
            continue
        seen.add((bssid, attack))
        try:
            priority = int(item.get("priority", index + 1))
        except (TypeError, ValueError):
            priority = index + 1
        params = item.get("params") if isinstance(item.get("params"), dict) else {}
        plan.actions.append(Action(
            attack=attack, bssid=bssid,
            reason=str(item.get("reason") or "")[:300],
            priority=priority, params=params, source=source,
        ))
    plan.actions.sort(key=lambda a: a.priority)
    plan.actions = plan.actions[:MAX_ACTIONS]
    plan.dropped = dropped
    return plan


# --------------------------------------------------------------------------- #
# adaptivity
# --------------------------------------------------------------------------- #


def should_replan(session: Session, last_plan: Optional[Plan],
                  new_aps: int = 0, failures: int = 0, interval: float = 45.0) -> Tuple[bool, str]:
    """Cheap, deterministic trigger for the next LLM call."""
    if last_plan is None:
        return True, "no plan yet"
    age = time.time() - last_plan.created
    if not last_plan.actions:
        return age > max(20.0, interval / 2), "previous plan was empty"
    if failures and failures >= 2:
        return True, f"{failures} consecutive failures"
    if new_aps >= 3:
        return True, f"{new_aps} new access points appeared"
    if age > interval:
        return True, f"{int(age)}s since the last plan"
    # every planned action finished -> re-evaluate
    remaining = [a for a in last_plan.actions if a.attack != "stop"]
    done = all(_action_done(session, a) for a in remaining) if remaining else True
    if done and age > 5:
        return True, "planned actions completed"
    return False, ""


def _action_done(session: Session, action: Action) -> bool:
    ap = session.ap(action.bssid)
    if ap is None:
        return True
    for attempt in reversed(ap.attempts):
        if attempt.attack == action.attack:
            return attempt.status != "running"
    return False


def explain_failure(attempt: Dict[str, Any], ap: Optional[AccessPoint]) -> str:
    """Human-readable diagnosis used in logs and by the LLM as context."""
    attack = attempt.get("attack", "")
    result = (attempt.get("result") or "").lower()
    detail = attempt.get("detail") or ""
    if "wps locked" in result or "rate-limit" in detail.lower():
        return "WPS rate limiting/lockout: stop PIN attempts, wait for the lockout to expire"
    if attack == "handshake":
        if ap is not None and not ap.clients:
            return "no clients associated: nothing to deauthenticate — use PMKID instead"
        if ap is not None and ap.pmf:
            return "PMF (802.11w) appears active: deauth is ignored, PMKID is the way in"
        return "clients did not re-handshake within the budget (weak signal or sleeping client)"
    if attack == "pmkid":
        return "AP did not return a PMKID (common with 802.11r/PMF or recent firmware)"
    if attack == "wps_pixie":
        return "chipset is not vulnerable to Pixie-Dust (or WPS is locked)"
    if attack == "crack":
        return "candidate space exhausted: try a bigger wordlist or a mask attack"
    if attack == "wep_ivs":
        return "not enough ARP traffic to harvest IVs (weak injection or idle network)"
    if attack in ("wep_chopchop", "wep_fragment", "wep_hirte"):
        return ("no packet to work with: the technique needs traffic in the air and a "
                "working injection (run `aireplay-ng -9` first)")
    if attack == "wep_p0841":
        return ("the injected ARP was not accepted: the AP may filter broadcast ARP, or "
                "the card cannot inject (try --arpreplay once a real ARP packet exists)")
    if attack == "saewolf":
        return ("no client authenticated during the window: SAE needs a live "
                "commit/confirm exchange to capture (and cannot be cracked offline)")
    if attack == "pmf_audit":
        return "no beacons or captures to read: the RSN elements were not in reach"
    if attack == "pmkid_flood":
        return ("the AP never sent a PMKID KDE, even with a client reconnecting: this "
                "firmware disables it, and the handshake is the way in")
    if attack == "evil_twin":
        return ("no client tried the twin: either nothing was in range, or the client "
                "has the real BSSID cached and stayed with it")
    if attack in ("deauth_flood", "beacon_flood"):
        return ("the flood produced no output: mdk4 did not start, or the monitor "
                "interface is not on the target's channel")
    return attempt.get("detail", "attack did not succeed")
