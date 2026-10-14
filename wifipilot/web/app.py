"""FastAPI application: REST control plane + WebSocket event stream.

The web UI is a *remote control* for the same :class:`wifipilot.engine.Engine`
the CLI uses — identical code path, identical events, no duplicated logic.  The
browser never talks to a radio directly; it just renders the event stream.

Endpoints
---------
``GET  /``                     single page UI
``GET  /api/state``            full snapshot (APs, loot, engine, advisor)
``GET  /api/tools``            dependency/capability report
``GET  /api/interfaces``       wireless interfaces
``GET  /api/config``           effective configuration
``POST /api/config``           update configuration
``POST /api/mode``             switch live/simulation and re-create the engine
``POST /api/scan``             start / stop discovery
``POST /api/campaign``         start / stop a campaign
``POST /api/attack``           run one attack against one BSSID
``POST /api/crack``            run the cracker against a capture
``POST /api/ai/think``         force an advisor planning cycle
``POST /api/ai/chat``          ask the local LLM about the engagement
``POST /api/ai/model``         select the model for the active provider
``POST /api/ai/provider``      switch provider (ollama | cortex | openrouter | auto | none)
``POST /api/ai/key``           set/clear the OpenRouter API key (never echoed back)
``GET  /api/ai/models``        model catalogue of the active provider
``POST /api/ai/pull``          pull a model through Ollama
``GET  /api/report``           markdown engagement report
``GET  /api/export``           JSON export of the whole session
``WS   /ws``                   live events + state
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..config import Config, find_wordlists
from ..deps import list_interfaces, registry
from ..engine import Engine
from ..events import EK, EventBus
from ..llm import build_client, provider_status
from ..models import ATTACK_NAMES
from ..util import mac_norm, now_iso, platform_info, require_linux

try:  # pragma: no cover - import guard
    from fastapi import Body, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
    from fastapi.staticfiles import StaticFiles
    from starlette.middleware.gzip import GZipMiddleware
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "the web UI needs FastAPI: pip install 'wifipilot[web]' "
        "(or: pip install fastapi 'uvicorn[standard]')"
    ) from exc

STATIC_DIR = Path(__file__).parent / "static"


class WebState:
    """Holds the engine that all requests share, and rebuilds it on mode switch."""

    def __init__(self, config: Config, demo: bool = False, authorized: bool = False,
                 bus: Optional[EventBus] = None):
        self.config = config
        self.demo = demo
        self.authorized = authorized
        self.bus = bus or EventBus()
        self.lock = threading.RLock()
        self.engine: Optional[Engine] = None
        self.auto_prepare = True

    def get_engine(self, create: bool = True) -> Optional[Engine]:
        with self.lock:
            if self.engine is None and create:
                self.engine = Engine(self.config, self.bus, demo=self.demo,
                                     authorized=self.authorized)
                self.engine.start_worker()
                # in simulation there is no radio to configure, so prepare eagerly
                if self.demo and self.auto_prepare:
                    with contextlib.suppress(Exception):
                        self.engine.prepare(announce=True)
                        self.engine.start_scan()
            return self.engine

    def reset(self, demo: Optional[bool] = None, authorized: Optional[bool] = None) -> Engine:
        with self.lock:
            if self.engine is not None:
                with contextlib.suppress(Exception):
                    self.engine.shutdown(timeout=5)
            self.demo = self.demo if demo is None else demo
            self.authorized = self.authorized if authorized is None else authorized
            self.config.demo = self.demo
            self.config.authorized = self.authorized
            self.engine = None
            self.bus.clear()
            return self.get_engine()


def create_app(config: Optional[Config] = None, demo: bool = False,
               authorized: bool = False, state: Optional[WebState] = None) -> FastAPI:
    config = config or Config()
    state = state or WebState(config, demo=demo, authorized=authorized)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        state.get_engine()
        try:
            yield
        finally:
            if state.engine is not None:
                with contextlib.suppress(Exception):
                    state.engine.shutdown(timeout=6)

    app = FastAPI(title="wifipilot", version="0.1.0",
                  description="AI-piloted WiFi auditing · wifite alternative · authorised use only",
                  lifespan=lifespan)
    app.state.ctx = state
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_credentials=False,
        allow_methods=["*"], allow_headers=["*"],
    )
    # the catalogue is half a megabyte of JSON and the browser polls /api/state while a
    # campaign runs: gzip makes that a few tens of KB on the wire, and changes no payload
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def engine_or_404() -> Engine:
        engine = state.get_engine()
        if engine is None:
            raise HTTPException(status_code=503, detail="engine unavailable")
        return engine

    def snapshot() -> Dict[str, Any]:
        engine = engine_or_404()
        data = engine.snapshot()
        data["platform"] = platform_info()
        data["config"] = config.to_dict(redact_secrets=True)
        data["tools"] = registry.summary()
        data["wordlists"] = find_wordlists(config)
        data["wordlist"] = find_wordlists(config)[0]["path"] if find_wordlists(config) else ""
        # the edition view: one shape for the first paint of the UI (no second round-trip)
        summary = edition_summary()
        data["edition"] = summary
        data["devices"] = {"selected": {"host": getattr(config, "it_host", ""),
                                        "port": getattr(config, "it_port", 0),
                                        "device": getattr(config, "it_device", ""),
                                        "bt": getattr(config, "bt_target", "")},
                           "counts": summary["attacks"]}
        if getattr(config, "it_device", ""):
            data["device"] = device_payload(str(config.it_device),
                                            str(getattr(config, "it_host", "")))
        return data

    # ------------------------------------------------------------------ #
    # editions, devices and the attack catalogue
    # ------------------------------------------------------------------ #
    def catalogue() -> List[Dict[str, Any]]:
        """Every attack with the metadata the UI's edition and device views read."""
        from ..attacks import attack_catalog
        return attack_catalog()

    def edition_summary() -> Dict[str, Any]:
        from ..itdev import edition_catalog
        counts: Dict[str, int] = {}
        for entry in catalogue():
            domain = str(entry.get("domain", "wifi"))
            counts[domain] = counts.get(domain, 0) + 1
        total = sum(counts.values())
        editions = []
        for edition in edition_catalog():
            row = dict(edition)
            row["attacks"] = counts.get(str(row.get("id")), total)
            editions.append(row)
        return {"active": getattr(config, "edition", "all") or "all",
                "editions": editions, "attacks": counts, "total": total}

    def device_payload(device_id: str = "", host: str = "") -> Dict[str, Any]:
        """One device type, the attacks that apply to it, and the briefing for it."""
        from ..itdev import device_type
        dev = device_type(device_id)
        if dev is None:
            return {}
        rows = [entry for entry in catalogue()
                if device_id in (entry.get("devices") or [])]
        rows.sort(key=lambda row: (str(row.get("category")) != "discovery",
                                   str(row.get("domain")) != "it", str(row.get("name"))))
        names = [str(row["name"]) for row in rows]
        plan = [name for name in names
                if name.endswith(("_discover", "_banner", "_census"))][:6] or names[:6]
        return {**dev.to_dict(),
                "attack_names": names,
                "plan": plan,
                "attacks": rows,
                "host": host,
                "briefing": device_briefing(dev, rows)}

    def device_briefing(dev: Any, rows: Sequence[Dict[str, Any]]) -> str:
        """A short, honest paragraph about testing this kind of device — no model needed.

        The AI advisor can say more, and does when it is switched on, but a tool whose
        explanation of *why* only exists when a model is reachable is a tool that cannot
        be explained during an incident.
        """
        protocols = ", ".join(dev.protocols) or "no protocol of its own"
        ports = ", ".join(str(port) for port in dev.ports) or "unknown"
        categories = sorted({str(row.get("category")) for row in rows})
        loud = [row["name"] for row in rows if str(row.get("noise")) in ("loud", "extreme")]
        return (
            f"{dev.label} ({dev.group_label}). Typical ports: {ports}. "
            f"It answers: {protocols}. Vendors seen in the field: "
            f"{', '.join(dev.vendors) or 'any'}. "
            f"{dev.risk} "
            f"{len(rows)} attacks in the catalogue apply to it"
            + (f", across {', '.join(categories)}" if categories else "")
            + (f"; {len(loud)} of them are loud enough to be noticed "
               f"({', '.join(loud[:3])})" if loud else "; none of them is loud")
            + ". Start with the discovery rows: they cost nothing, they name the model, "
              "and the model decides which of the rest is worth running."
        )

    def demo_hosts() -> List[Dict[str, Any]]:
        """The simulated segment, so a device can be picked by its address in demo mode."""
        try:
            from ..itsim import build_lan, lan_catalog
        except Exception:                                       # pragma: no cover
            return []
        return lan_catalog(build_lan())

    def demo_ble() -> List[Dict[str, Any]]:
        """The simulated Bluetooth floor, so a device can be picked by its address."""
        try:
            from ..blesim import ble_catalog
        except Exception:                                       # pragma: no cover
            return []
        return ble_catalog()
    @app.get("/api/editions")
    async def api_editions() -> Dict[str, Any]:
        return edition_summary()

    @app.post("/api/edition")
    async def api_set_edition(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        """Switch editions: wifi, bluetooth, it — or all three."""
        edition = (payload.get("edition") or "").strip().lower()
        if edition not in {"wifi", "bluetooth", "it", "all"}:
            raise HTTPException(status_code=400,
                                detail="edition must be wifi, bluetooth, it or all")
        config.edition = edition
        if edition != "all":                    # the edition *is* the plan
            from ..attacks import ATTACK_META
            names = [name for name in ATTACK_NAMES
                     if ATTACK_META.get(name, {}).get("domain", "wifi") == edition]
            if names:
                config.attacks = names
        else:
            config.attacks = list(ATTACK_NAMES)
        return {"ok": True, **edition_summary()}

    @app.get("/api/catalog")
    async def api_catalog(domain: str = Query(""), category: str = Query(""),
                          device: str = Query(""), q: str = Query("")) -> Dict[str, Any]:
        """The attack catalogue, filtered — what the UI's lists are drawn from."""
        rows = catalogue()
        if domain:
            rows = [row for row in rows if row.get("domain") == domain]
        if category:
            rows = [row for row in rows if row.get("category") == category]
        if device:
            rows = [row for row in rows if device in (row.get("devices") or [])]
        if q:
            needle = q.lower()
            rows = [row for row in rows
                    if needle in str(row.get("name", "")).lower()
                    or needle in str(row.get("label", "")).lower()
                    or needle in str(row.get("description", "")).lower()]
        return {"count": len(rows), "attacks": rows}

    @app.get("/api/devices")
    async def api_devices(edition: str = Query(""), group: str = Query(""),
                          q: str = Query(""), limit: int = Query(0)) -> Dict[str, Any]:
        """The device shelf: what the tool knows how to test, and with which attacks."""
        from ..itdev import DEVICE_GROUPS, device_catalog
        wanted = (edition or getattr(config, "edition", "") or "").strip().lower()
        needle = q.strip().lower()
        people: List[Dict[str, Any]] = []
        for row in device_catalog():
            if group and row.get("group") != group:
                continue
            if wanted and wanted != "all" and row.get("domain") != wanted:
                continue
            if needle and needle not in (row["id"] + " " + row["label"] + " " +
                                         " ".join(row.get("protocols", []))).lower():
                continue
            # names and counts only: the device shelf is drawn on every filter change and
            # the full metadata is one click away (GET /api/catalog, GET /api/device)
            names = [str(entry["name"]) for entry in catalogue()
                     if row["id"] in (entry.get("devices") or [])]
            row = dict(row)
            row.pop("attacks", None)
            row["attack_names"] = names
            row["attack_count"] = len(names)
            row["plan"] = [name for name in names
                           if name.endswith(("_discover", "_banner", "_census"))][:6] \
                or names[:6]
            people.append(row)
        if limit:
            people = people[:limit]
        return {"count": len(people), "groups": DEVICE_GROUPS, "devices": people,
                "demo_hosts": demo_hosts() if state.demo else [],
                "demo_ble": demo_ble() if state.demo else [],
                "selected": {"host": getattr(config, "it_host", ""),
                             "port": getattr(config, "it_port", 0),
                             "device": getattr(config, "it_device", ""),
                             "bt": getattr(config, "bt_target", "")}}

    @app.get("/api/sim")
    async def api_sim(domain: str = Query(""),
                      limit: int = Query(0, description="rows to include (0 = all)")) -> Dict[str, Any]:
        """What the simulated environments contain — the same data ``wifipilot sim`` prints.

        A demo run is a simulation, not a stub, and this is what the simulation is made of:
        the Bluetooth floor's devices with their profiles and roles, and the IT segment's
        hosts with their ports and the responders behind them.  The UI's simulated-device
        picker, the CLI and ``wp.simulations()`` all read this one answer.
        """
        from ..api import simulations
        from ..itdev import domain_label
        try:
            data = simulations(domain)
        except Exception as exc:                                # unknown edition
            raise HTTPException(status_code=400, detail=str(exc))
        if domain:
            data["edition_label"] = domain_label(domain.strip().lower())
        if limit and limit > 0:
            for key in ("bluetooth", "it"):
                block = data.get(key)
                if block and isinstance(block.get("catalog"), list):
                    block["catalog"] = block["catalog"][:limit]
        return data

    @app.post("/api/sim/target")
    async def api_sim_target(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        """Point the Bluetooth attacks at a simulated device (the floor's own address list)."""
        address = str(payload.get("address") or "").strip().lower()
        if not address:
            raise HTTPException(status_code=400, detail="address required")
        from ..blesim import ble, ble_catalog

        device: Dict[str, Any] = {}
        if address != "auto":
            row = ble().by_address(address)
            if row is None:
                raise HTTPException(status_code=404,
                                    detail=f"no simulated device at {address}")
            device = row.to_dict()
        config.bt_target = "" if address == "auto" else address
        return {"ok": True, "selected": {"bt": getattr(config, "bt_target", ""),
                                         "bt_auto": not address or address == "auto"},
                "device": device,
                "count": len(ble_catalog())}

    @app.post("/api/device")
    async def api_select_device(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        """Pick a device to point the IT attacks at (an address, and/or a type)."""
        device_id = (payload.get("device") or "").strip()
        host = (payload.get("host") or "").strip()
        port = int(payload.get("port") or 0)
        if not device_id and not host:
            raise HTTPException(status_code=400, detail="device or host required")
        if host:
            config.it_host = host
        if port:
            config.it_port = port
        if device_id:
            config.it_device = device_id
        detail = device_payload(device_id, host) if device_id else {}
        if host:
            detail["host"] = host
        return {"ok": True, "selected": {"host": getattr(config, "it_host", ""),
                                         "port": getattr(config, "it_port", 0),
                                         "device": device_id},
                "device": detail}

    @app.get("/api/help")
    async def api_help_get(name: str = Query(""), device: str = Query("")) -> Dict[str, Any]:
        return help_answer("", name, device)

    @app.post("/api/help")
    async def api_help(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        """Explain an attack, a device, or how to test one without breaking it.

        The answer is built from the catalogue whether or not a model is available: the
        advisor only adds to it, and says so when it is off.
        """
        return help_answer((payload.get("question") or "").strip(),
                           (payload.get("name") or "").strip(),
                           (payload.get("device") or "").strip())

    @app.post("/api/explain")
    async def api_explain(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        """The one-click version of /api/help: explain this attack, with its context."""
        name = (payload.get("name") or "").strip()
        device_id = (payload.get("device") or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="name required")
        return help_answer(f"What does {name} do, when should I run it, and what should "
                           "the site's defender see?", name, device_id)

    #: words a question may share with a device label without meaning that device
    HELP_STOPWORDS = {"network", "server", "system", "device", "mobile", "smart",
                      "digital", "station", "controller", "management", "monitoring"}

    def help_devices_for(question: str) -> List[str]:
        """The device types a free-text question is about, from the shelf itself.

        The panel promises it explains a device or an attack *without* a model, so the
        question is resolved against the catalogue: an id the operator typed, a label
        that appears in it, or a distinctive word of a label ("printer", "camera").
        """
        from ..itdev import DEVICE_TYPES, device_type
        lowered = question.lower()
        words = [word.strip("?,.!\'\"()[]:/") for word in lowered.split()]
        words = [word for word in words if len(word) >= 3]
        found: List[str] = []
        for word in words:                                     # an id, typed as an id
            dev = device_type(word)
            if dev is not None and dev.id not in found:
                found.append(dev.id)
        for dev in DEVICE_TYPES:                               # a label, or its main word
            if dev.id.replace("_", " ") in lowered or dev.label.lower() in lowered:
                if dev.id not in found:
                    found.append(dev.id)
                continue
            label_words = {word.strip("(),/") for word in dev.label.lower().split()}
            hits = {word for word in words if word in label_words and len(word) >= 5
                    and word not in HELP_STOPWORDS}
            if hits and dev.id not in found:
                found.append(dev.id)
        return found[:2]

    def help_attacks_for(question: str) -> List[str]:
        """The attacks a free-text question names, by registry name or by its words."""
        lowered = question.lower()
        named = [name for name in ATTACK_NAMES
                 if name in lowered or name.replace("_", " ") in lowered]
        if named:
            return named[:4]
        words = {word.strip("?,.!\'\"()[]:/") for word in lowered.split()}
        # a name is matched on its *distinctive* words: "deauth" is a topic, "flood" and
        # "audit" are not, so one distinctive hit is enough and two generic ones are not
        generic = {"discover", "version", "audit", "flood", "scan", "read", "write",
                   "default", "creds", "unauth", "enum", "dump", "bypass", "probe",
                   "attack", "test", "list", "info", "census", "sweep"}
        found: List[str] = []
        for name in ATTACK_NAMES:
            parts = set(name.split("_"))
            hits = parts & words
            if len(hits) >= 2 or (hits - generic):
                found.append(name)
        return found[:3]

    def help_answer(question: str, name: str = "", device_id: str = "") -> Dict[str, Any]:
        rows = {str(row["name"]): row for row in catalogue()}
        row = rows.get(name, {})
        context: List[str] = []
        if question and not row and not device_id:
            # a plain question: answer it from the catalogue before any model is asked
            for found_device in help_devices_for(question):
                detail = device_payload(found_device)
                if detail:
                    context.append(detail["briefing"])
                    context.append("attacks for " + found_device + ": "
                                   + ", ".join(detail["attack_names"][:12]))
            for found_attack in help_attacks_for(question):
                found_row = rows.get(found_attack, {})
                context.append(f"attack {found_attack}: {found_row.get('label', '')} — "
                               f"{found_row.get('description', '')} "
                               f"[edition {found_row.get('domain')}, noise "
                               f"{found_row.get('noise')}, impact {found_row.get('impact')}]")
        if row:
            context.append(
                f"attack {name}: {row.get('label', '')} — {row.get('description', '')} "
                f"[category {row.get('category')}, noise {row.get('noise')}, "
                f"impact {row.get('impact')}, edition {row.get('domain')}, "
                f"protocol {row.get('protocol', '')} port {row.get('port', 0)}]")
            if row.get("detection"):
                context.append(f"what a defender sees: {row['detection']}")
            devices = row.get("devices") or []
            if devices:
                context.append("applies to devices: " + ", ".join(devices[:12]))
        if device_id:
            detail = device_payload(device_id)
            if detail:
                context.append(detail["briefing"])
        heuristic = "\n".join(context) or (
            "Pick a device (Devices & attacks) or an attack name and this panel explains "
            "it: what it does, what it proves, how loud it is and what the defender sees. "
            "You can also ask in words — \"how do I test a printer?\", \"what does deauth "
            "do?\" — and the answer is built from the catalogue whether or not a model is "
            "reachable.")
        if state.demo:
            heuristic += ("\nIn simulation mode the answers come from the simulated "
                          "segment: no packet leaves this machine.")
        answer = heuristic
        source = "catalogue"
        if question:
            prompt = (question + "\n\nUse only this context, and be concrete about the "
                      "next command to run:\n" + ("\n".join(context) or heuristic))
            engine = state.get_engine()
            advisor = getattr(engine, "advisor", None) if engine else None
            reachable = False
            if advisor is not None and not config.ai_off() and advisor.provider != "none":
                # ask() answers with a friendly "the advisor is off" note when no model
                # is reachable; that is not an answer to the operator's question, so
                # the catalogue's own text stays the answer unless a model replied.
                try:
                    reachable = bool(advisor.check(announce=False))
                except Exception:                              # noqa: BLE001 - never 500 a help page
                    reachable = False
            if reachable:
                try:
                    reply = advisor.ask(prompt)
                    if reply and reply.strip():
                        answer, source = reply.strip(), "advisor"
                except Exception as exc:                       # noqa: BLE001 - never 500 a help page
                    answer = f"{heuristic}\n\n(advisor unavailable: {exc})"
        return {"ok": True, "source": source, "question": question, "attack": name,
                "device": device_id, "heuristic": heuristic, "answer": answer}

    # ------------------------------------------------------------------ #
    # static UI
    # ------------------------------------------------------------------ #
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        index_file = STATIC_DIR / "index.html"
        if not index_file.exists():
            return HTMLResponse("<h1>wifipilot</h1><p>static assets missing</p>", status_code=500)
        return HTMLResponse(index_file.read_text(encoding="utf-8"))

    @app.get("/healthz")
    async def healthz() -> Dict[str, Any]:
        engine = state.get_engine()
        advisor = getattr(engine, "advisor", None)
        return {
            "ok": True, "demo": state.demo, "phase": engine.status.phase if engine else "idle",
            "time": now_iso(), "version": "0.1.0",
            "platform": platform_info()["os"],
            "provider": getattr(advisor, "provider", ""),
            "model": getattr(advisor, "model", ""),
        }

    # ------------------------------------------------------------------ #
    # read APIs
    # ------------------------------------------------------------------ #
    def engine_session():
        """The live session (creating the engine's is fine — it has no radio)."""
        active = engine_or_404()
        return active.session

    @app.get("/api/state")
    async def api_state(detail: str = Query("", description="BSSID to include in detail")):
        data = snapshot()
        if detail:
            ap = state.get_engine().session.ap(detail)
            if ap is not None:
                data["detail"] = ap.to_dict(detail=True)
        return data

    @app.get("/api/tools")
    async def api_tools(force: bool = False):
        return registry.summary()

    @app.get("/api/interfaces")
    async def api_interfaces(force: bool = False):
        return {"interfaces": [i.to_dict() for i in list_interfaces(force=force)]}

    @app.get("/api/wordlists")
    async def api_wordlists():
        return {"wordlists": find_wordlists(config)}

    @app.get("/api/config")
    async def api_config():
        # redact_secrets: the browser must never receive the OpenRouter key
        return {"config": config.to_dict(redact_secrets=True),
                "attacks": list(ATTACK_NAMES),
                "providers": provider_status(config.ollama, config.openrouter,
                                             cortex=config.cortex)}

    @app.get("/api/report", response_class=PlainTextResponse)
    async def api_report():
        engine = engine_or_404()
        path = Path(engine.session.write_markdown_report())
        return PlainTextResponse(path.read_text(encoding="utf-8"))

    @app.get("/api/export")
    async def api_export():
        engine = engine_or_404()
        return JSONResponse(engine.session.export())

    @app.get("/api/file")
    async def api_file(path: str = Query(..., description="absolute path inside the loot/session dirs")):
        """Download a capture. Only files inside this session's dirs are served."""
        engine = engine_or_404()
        session = engine.session
        requested = Path(path).expanduser().resolve()
        allowed_roots = [Path(session.output_dir).resolve(), Path(session.state_dir).resolve()]
        if not any(str(requested).startswith(str(root)) for root in allowed_roots):
            raise HTTPException(status_code=403,
                                detail="only files inside the loot and session directories can be downloaded")
        if not requested.is_file():
            raise HTTPException(status_code=404, detail="file not found")
        return FileResponse(str(requested), filename=requested.name,
                            media_type="application/octet-stream")

    @app.get("/api/events")
    async def api_events(limit: int = 200):
        engine = engine_or_404()
        return {"events": [e.to_dict() for e in engine.bus.recent(limit)]}

    # ------------------------------------------------------------------ #
    # control APIs
    # ------------------------------------------------------------------ #
    @app.post("/api/config")
    async def api_config_update(payload: Dict[str, Any] = Body(...)):
        engine = engine_or_404()
        try:
            payload = dict(payload)
            # a redacted GET /api/config returns api_key="" — never let that wipe the key
            nested = payload.get("openrouter")
            if isinstance(nested, dict) and not nested.get("api_key"):
                payload["openrouter"] = {k: v for k, v in nested.items() if k != "api_key"}
            config.update(**payload)
            if "ai_provider" in payload:
                engine.advisor.configure(config.ai_provider, announce=False)
            else:
                engine.advisor.config = config.llm_config(engine.advisor.provider)
            # keep the live session in step with the new settings
            engine.session.stealth = config.stealth
            engine.session.auto_think = config.autothink_enabled()
            if not state.demo:
                with contextlib.suppress(Exception):
                    engine.session.known_wordlists = find_wordlists(config)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid config: {exc}") from exc
        redacted = config.to_dict(redact_secrets=True)
        engine.bus.publish(EK.SESSION_INFO, {"config": redacted, "action": "config-updated"})
        return {"ok": True, "config": redacted}

    @app.post("/api/config/save")
    async def api_config_save(payload: Dict[str, Any] = Body(default={})):
        path = payload.get("path") or "wifipilot.json"
        config.save(path)
        return {"ok": True, "path": path}

    @app.post("/api/mode")
    async def api_mode(payload: Dict[str, Any] = Body(...)):
        demo = bool(payload.get("demo", state.demo))
        authorized = bool(payload.get("authorized", state.authorized))
        if not demo and not authorized:
            raise HTTPException(
                status_code=400,
                detail="live mode requires an explicit authorisation confirmation",
            )
        try:
            engine = state.reset(demo=demo, authorized=authorized)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"could not start engine: {exc}") from exc
        mode = "simulation" if demo else "live"
        engine.bus.log(f"switched to {mode} mode", level="warning")
        return {"ok": True, "demo": demo, "authorized": authorized}

    @app.post("/api/scan")
    async def api_scan(payload: Dict[str, Any] = Body(default={})):
        engine = engine_or_404()
        action = payload.get("action", "start")
        if action == "stop":
            engine.stop_scan()
            return {"ok": True, "scanning": False}
        try:
            if not engine._prepared:      # noqa: SLF001 - intentional control surface
                engine.prepare()
            engine.start_scan()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"ok": True, "scanning": True}

    @app.post("/api/campaign")
    async def api_campaign(payload: Dict[str, Any] = Body(default={})):
        engine = engine_or_404()
        action = payload.get("action", "start")
        if action == "stop":
            return {"ok": True, "message": engine.request_stop()}
        if not state.authorized and not state.demo:
            raise HTTPException(status_code=403, detail=(
                "authorisation not confirmed: enable 'authorized' for this engagement"))
        targets = payload.get("targets") or []
        if isinstance(targets, str):
            targets = [t for t in targets.replace(",", " ").split() if t]
        duration = float(payload.get("duration") or 0)
        scan_first = bool(payload.get("scan_first", True))
        message = engine.request_start(targets, duration, scan_first)
        return {"ok": True, "message": message}

    @app.post("/api/attack")
    async def api_attack(payload: Dict[str, Any] = Body(...)):
        engine = engine_or_404()
        attack = (payload.get("attack") or "").strip()
        if attack and attack not in ATTACK_NAMES:
            raise HTTPException(status_code=400, detail=f"unknown attack {attack!r}")
        bssid = mac_norm(payload.get("bssid", ""))
        if not bssid:
            # an IT or Bluetooth attack talks to a *service*, not to an access point:
            # the AP is only the bridge the traffic crosses, so the best-scoring target
            # stands in for it when the operator did not name one.
            from ..attacks import ATTACK_META
            edition = str(ATTACK_META.get(attack, {}).get("domain", "wifi"))
            if edition in ("it", "bluetooth"):
                session = engine.session
                scoped = list(getattr(session, "selected_bssids", []) or [])
                pool = [session.aps[mac] for mac in scoped if mac in session.aps]
                if not pool:
                    pool = list(session.aps.values())
                if not pool:
                    raise HTTPException(status_code=400,
                                        detail="no access point discovered yet: run a scan "
                                               "first (the AP is the bridge for IT attacks)")
                bssid = max(pool, key=lambda ap: ap.score).bssid
            else:
                raise HTTPException(status_code=400, detail="bssid required")
        return {"ok": True, "message": engine.request_attack(bssid, attack,
                                                             payload.get("reason", ""))}

    @app.post("/api/cancel")
    async def api_cancel():
        engine = engine_or_404()
        return {"ok": True, "message": engine.request_cancel_attack()}

    @app.post("/api/crack")
    async def api_crack(payload: Dict[str, Any] = Body(...)):
        engine = engine_or_404()
        bssid = mac_norm(payload.get("bssid", ""))
        if not bssid:
            raise HTTPException(status_code=400, detail="bssid required")
        wordlists = payload.get("wordlists") or []
        if isinstance(wordlists, str):
            wordlists = [wordlists]
        masks = payload.get("masks") or []
        if isinstance(masks, str):
            masks = [part.strip() for part in masks.split(",") if part.strip()]
        return {"ok": True, "message": engine.request_crack(bssid, wordlists, masks)}

    @app.get("/api/targets")
    async def api_targets_query(kind: str = "", tag: str = "", vendor: str = "",
                                encryption: str = "", channel: int = 0):
        session = engine_session()
        rows = [ap.to_dict() for ap in session.filter_aps(
            kind=kind, tag=tag, vendor=vendor, encryption=encryption, channel=channel)]
        return {"ok": True, "count": len(rows), "targets": rows}

    @app.post("/api/select")
    async def api_select(payload: Dict[str, Any] = Body(default={})):
        """Scope the campaign: explicit BSSIDs and/or the same filters as /api/targets."""
        session = engine_session()
        clear = bool(payload.get("clear"))
        chosen = [mac_norm(b) for b in (payload.get("bssids") or []) if mac_norm(b)]
        filters = {key: payload.get(key) or "" for key in ("kind", "tag", "vendor",
                                                           "encryption")}
        if any(filters.values()) or payload.get("channel"):
            # only filter when a filter was actually given — otherwise every AP
            # would match and "select these two" would silently scope the world
            chosen += [ap.bssid for ap in session.filter_aps(
                channel=payload.get("channel") or 0, **filters)]
        selected = sorted(set(chosen) if clear else {*session.selected_bssids, *chosen})
        session.selected_bssids = selected
        return {"ok": True, "selected": selected, "count": len(selected)}

    @app.post("/api/tag")
    async def api_tag(payload: Dict[str, Any] = Body(...)):
        session = engine_session()
        bssid = mac_norm(payload.get("bssid", ""))
        name = str(payload.get("tag") or "").strip()
        if not bssid or not name:
            raise HTTPException(status_code=400, detail="bssid and tag are required")
        tags = session.tag_ap(bssid, name, add=not payload.get("remove"))
        return {"ok": True, "bssid": bssid, "tags": tags}

    @app.post("/api/note")
    async def api_note(payload: Dict[str, Any] = Body(...)):
        session = engine_session()
        text = str(payload.get("text") or "").strip()
        if not text:
            raise HTTPException(status_code=400, detail="text is required")
        entry = session.add_note(text, bssid=payload.get("bssid") or "")
        return {"ok": True, "note": entry}

    @app.get("/api/advice")
    async def api_advice():
        """Next steps from the heuristics (no LLM round trip, no cost)."""
        active = engine_or_404()
        return {"ok": True, "advice": active.advice()}

    @app.get("/api/vendor")
    async def api_vendor(bssid: str = "", query: str = ""):
        """Vendor dossier + identification for a BSSID, a MAC or an ESSID."""
        from ..analytics import identify
        from ..util import mac_norm as _norm
        from ..vendors import oui_lookup, vendor_dossier

        target = _norm(bssid) or query
        if not target:
            raise HTTPException(status_code=400, detail="bssid or query is required")
        mac = _norm(target)
        if mac:
            name, match = oui_lookup(mac)
            return {"ok": True, "mac": mac, "vendor": name, "match": match,
                    "dossier": vendor_dossier(name or mac),
                    "identification": identify("", name)}
        return {"ok": True, "vendor": "", "match": "",
                "dossier": vendor_dossier(target), "identification": identify(target)}

    @app.post("/api/benchmark")
    async def api_benchmark(payload: Dict[str, Any] = Body(default={})):
        """How fast this machine verifies candidates — a short, radio-free run."""
        active = engine_or_404()
        seconds = float(payload.get("seconds") or 2.0)
        return {"ok": True, "benchmark": active.benchmark(seconds=min(30.0, max(1.0, seconds)))}

    @app.get("/api/passwords")
    async def api_passwords():
        """Recovered PSKs with the weakness verdict and time-to-crack estimates."""
        from ..analytics import password_report
        session = engine_session()
        rows: List[Dict[str, Any]] = []
        for ap in session.sorted_aps():
            if not ap.password:
                continue
            report = password_report(ap.password).to_dict()
            report.update({"bssid": ap.bssid, "essid": ap.essid})
            rows.append(report)
        rows.sort(key=lambda item: item["score"])
        return {"ok": True, "passwords": rows}

    @app.get("/api/survey")
    async def api_survey(capture: str = "", limit: int = 40):
        """Read-only intelligence: probe requests, deauths, rogue twins."""
        from ..sniff import passive_report
        session = engine_session()
        path = capture or ""
        if not path:
            captures = [item for item in session.all_captures()
                        if item.path and os.path.exists(item.path)]
            path = captures[-1].path if captures else ""
        aps = [ap.to_dict() for ap in session.aps.values()]
        return {"ok": True, "survey": passive_report(path, aps,
                                                     limit=max(1, min(200, limit)))}

    @app.get("/api/eap")
    async def api_eap(capture: str = "", limit: int = 4):
        """Decode an 802.1X exchange: EAP method, outer identity, server certificate."""
        from ..sniff import eap_exchange
        path = capture or ""
        if path and not os.path.exists(path):
            raise HTTPException(status_code=400, detail="no such capture")
        if not path:
            session = engine_session()
            captures = [item for item in session.all_captures()
                        if item.path and os.path.exists(item.path)]
            path = captures[-1].path if captures else ""
        if not path:
            raise HTTPException(status_code=400,
                                detail="pass ?capture=..., or capture something first")
        return {"ok": True, "path": path,
                "eap": eap_exchange(path, limit_certs=max(1, min(8, limit)))}

    @app.get("/api/pins")
    async def api_pins(bssid: str = "", essid: str = "", vendor: str = "",
                       first_half: str = "", limit: int = 24):
        """WPS PIN candidates (with provenance) and the attempt plan — offline."""
        from .. import wps as wps_module
        from ..util import oui_vendor
        mac = mac_norm(bssid) if bssid else ""
        if bssid and not mac:
            raise HTTPException(status_code=400, detail="not a MAC address")
        vendor = vendor or (oui_vendor(mac) if mac else "")
        candidates = wps_module.candidate_pins(bssid=mac, essid=essid, vendor=vendor)
        order = list(wps_module.pin_attempt_order(
            [item.pin for item in candidates if item.pin], first_half=first_half))
        return {"ok": True, "bssid": mac, "essid": essid, "vendor": vendor,
                "candidates": [item.to_dict() for item in candidates],
                "order": order[:max(1, min(200, limit))],
                "plan": wps_module.attempt_plan(bssid=mac, essid=essid, vendor=vendor)}

    @app.get("/api/pmk/cache")
    async def api_pmk_cache():
        """The ESSID-keyed PMK cache: what a second capture of the same network costs."""
        from .. import pmk as pmk_module
        active = engine_or_404()
        cache = active.cracker.pmk_cache() if hasattr(active, "cracker") else None
        if cache is None:
            path = config.pmk_cache_path or os.path.join(
                config.session_dir, pmk_module.PMK_CACHE_NAME)
            cache = pmk_module.PMKCache(path=path).load()
        return {"ok": True, "path": cache.path,
                "entries": [entry.to_dict() for entry in cache.entries()]}

    @app.post("/api/pmk/verify")
    async def api_pmk_verify(payload: Dict[str, Any] = Body(...)):
        """Verify a candidate PSK against a capture (never trust an unverified one)."""
        from .. import pmk as pmk_module
        psk = str(payload.get("psk") or "")
        capture = str(payload.get("capture") or "")
        if not psk or not capture or not os.path.exists(capture):
            raise HTTPException(status_code=400, detail="psk and an existing capture are required")
        return {"ok": True, "result": pmk_module.verify_psk_against(
            psk, capture, str(payload.get("essid") or ""))}

    @app.get("/api/tags")
    async def api_tags():
        session = engine_session()
        return {"ok": True, "tags": session.tags(),
                "selected": session.selected_bssids}

    @app.post("/api/rescan")
    async def api_rescan(payload: Dict[str, Any] = Body(default={})):
        engine = engine_or_404()
        return {"ok": True, "message": engine.request_rescan(float(payload.get("seconds") or 20))}

    @app.post("/api/targets")
    async def api_targets(payload: Dict[str, Any] = Body(...)):
        engine = engine_or_404()
        bssids = payload.get("bssids") or []
        if isinstance(bssids, str):
            bssids = [b for b in bssids.replace(",", " ").split() if b]
        engine.session.selected_bssids = [mac_norm(b) or b for b in bssids]
        engine._targets_filter = list(engine.session.selected_bssids)   # noqa: SLF001
        engine.bus.publish(EK.SESSION_INFO, {"selected": engine.session.selected_bssids})
        return {"ok": True, "selected": engine.session.selected_bssids}

    # ------------------------------------------------------------------ #
    # AI APIs
    # ------------------------------------------------------------------ #
    @app.post("/api/ai/think")
    async def api_think():
        engine = engine_or_404()
        if config.ai_off():
            return {"ok": False, "disabled": True, "plan": None,
                    "note": "the advisor is off — the deterministic planner is already "
                            "deciding; nothing is sent to a model"}
        plan = engine.request_think()
        return {"ok": True, "disabled": False, "plan": plan.to_dict()}

    @app.post("/api/ai/chat")
    async def api_chat(payload: Dict[str, Any] = Body(...)):
        engine = engine_or_404()
        message = (payload.get("message") or "").strip()
        if not message:
            raise HTTPException(status_code=400, detail="message required")
        if config.ai_off():
            return {"ok": False, "disabled": True, "streaming": False,
                    "note": "the advisor is off — no model is called. Re-enable it with "
                            "the provider picker (or `wifipilot ai on`)"}
        engine.bus.publish(EK.ADVISOR_CHAT, {"role": "user", "kind": "chat", "message": message})

        def worker() -> None:
            try:
                engine.advisor.ask(message, model=payload.get("model", ""))
            except Exception as exc:  # pragma: no cover
                engine.bus.error(f"chat failed: {exc}")

        threading.Thread(target=worker, name="advisor-chat", daemon=True).start()
        return {"ok": True, "streaming": True}

    @app.get("/api/ai/models")
    async def ai_models(provider: str = Query(""), q: str = Query(""), free: bool = False,
                        limit: int = Query(60), refresh: bool = False):
        """The model catalogue of the active (or requested) provider."""
        engine = engine_or_404()
        advisor = engine.advisor
        if config.ai_off():
            return {"provider": "none", "models": [], "error": "", "disabled": True,
                    "note": "advisor disabled: no model is in use", "configured": False,
                    "redact": False}
        wanted = (provider or "").strip().lower()
        if wanted in ("ollama", "openrouter") and wanted != advisor.provider:
            client = build_client(wanted, config.ollama, config.openrouter, engine.bus,
                                  config.cortex)
            models = client.list_models(force=refresh, query=q, limit=max(0, limit),
                                        free_only=free)
            provider_config = config.openrouter if wanted == "openrouter" else config.ollama
            return {"provider": wanted, "models": [m.to_dict() for m in models],
                    "error": getattr(client, "models_error", ""),
                    "configured": bool(getattr(provider_config, "enabled", True)),
                    "redact": bool(getattr(provider_config, "redact_identifiers", False))}
        return {"provider": advisor.provider,
                "models": advisor.models(force=refresh, query=q, limit=max(0, limit),
                                         free_only=free),
                "error": getattr(advisor.client, "models_error", ""),
                "configured": bool(getattr(advisor.config, "enabled", True)),
                "redact": bool(advisor.redact)}

    @app.post("/api/ai/model")
    async def api_model(payload: Dict[str, Any] = Body(...)):
        engine = engine_or_404()
        advisor = engine.advisor
        name = str(payload.get("model", ""))
        provider = str(payload.get("provider", "") or "").strip().lower()
        if provider in ("auto", "ollama", "openrouter", "none") and provider != advisor.provider:
            if provider == "openrouter":
                config.openrouter.enabled = True   # switching to it is the consent step
            config.ai_provider = provider
            advisor.configure(provider, announce=False)
        advisor.use_model(name)
        config.ai_provider = advisor.provider
        engine.session.auto_think = config.autothink_enabled()
        engine.bus.publish(EK.SESSION_INFO, {"config": config.to_dict(redact_secrets=True),
                                             "action": "model-changed"})
        return {"ok": True, "model": advisor.model, "provider": advisor.provider,
                "advisor": advisor.status()}

    @app.post("/api/ai/provider")
    async def ai_provider(payload: Dict[str, Any] = Body(...)):
        """Switch providers.  Moving to the cloud requires an explicit consent flag."""
        engine = engine_or_404()
        provider = str(payload.get("provider", "") or "").strip().lower()
        if provider not in ("auto", "ollama", "cortex", "openrouter", "none"):
            raise HTTPException(status_code=400,
                                detail=f"unknown provider {provider!r} "
                                       f"(expected auto|ollama|cortex|openrouter|none)")
        if provider == "openrouter" and payload.get("consent", True) is False:
            raise HTTPException(
                status_code=400,
                detail="switching to OpenRouter sends engagement data (SSIDs, BSSIDs, MACs "
                       "and recovered PSKs unless redaction is on) to a cloud service — "
                       "confirm consent first",
            )
        advisor = engine.advisor
        config.ai_provider = provider
        if provider == "openrouter":
            config.openrouter.enabled = True
        if provider == "cortex":
            # a local hoster: selecting it is the opt-in, exactly like Ollama
            config.cortex.enabled = True
            if payload.get("host"):
                config.cortex.host = str(payload["host"]).strip()
            if payload.get("model"):
                config.cortex.model = str(payload["model"]).strip()
        advisor.configure(provider, announce=True)
        engine.session.auto_think = config.autothink_enabled()
        engine.bus.publish(EK.SESSION_INFO, {"config": config.to_dict(redact_secrets=True),
                                             "action": ("advisor-off" if provider == "none"
                                                        else "provider-changed"),
                                             "provider": advisor.provider})
        return {"ok": True, "provider": advisor.provider, "disabled": config.ai_off(),
                "note": ("advisor off: deterministic planner only" if config.ai_off() else ""),
                "advisor": advisor.status()}

    @app.post("/api/ai/key")
    async def ai_key(payload: Dict[str, Any] = Body(default={})):
        """Store the OpenRouter key in the config file (mode 600).  Never echoed back."""
        engine = engine_or_404()
        key = str(payload.get("key", "") or "").strip()
        if key:
            if not key.startswith("sk-or-"):
                raise HTTPException(
                    status_code=400,
                    detail="that does not look like an OpenRouter key (they start with "
                           "'sk-or-') — create one at https://openrouter.ai/keys",
                )
            config.openrouter.api_key = key
            config.openrouter.enabled = bool(payload.get("enable", True))
            if payload.get("model"):
                config.openrouter.model = str(payload["model"])
            if config.ai_provider in ("", "auto"):
                config.ai_provider = "openrouter"
        else:
            config.openrouter.api_key = ""
        if payload.get("save", True):
            config.save()
        engine.advisor.configure(config.ai_provider, announce=False)
        engine.session.auto_think = config.autothink_enabled()
        status = engine.advisor.status()
        engine.bus.publish(EK.SESSION_INFO, {"config": config.to_dict(redact_secrets=True),
                                             "action": "openrouter-key"})
        return {"ok": True, "key_configured": bool(config.openrouter.api_key_value()),
                "key": status.get("key", {}), "advisor": status}

    @app.post("/api/ai/pull")
    async def api_pull(payload: Dict[str, Any] = Body(...)):
        engine = engine_or_404()
        model = (payload.get("model") or "").strip()
        if not model:
            raise HTTPException(status_code=400, detail="model required")
        threading.Thread(target=engine.advisor.pull_model, args=(model,),
                         name="ollama-pull", daemon=True).start()
        return {"ok": True, "pulling": model}

    @app.post("/api/ai/toggle")
    async def api_ai_toggle(payload: Dict[str, Any] = Body(default={})):
        engine = engine_or_404()
        if "autothink" in payload:
            engine.session.auto_think = bool(payload["autothink"])
            config.ollama.enable_autothink = bool(payload["autothink"])
        if "enabled" in payload:
            config.ollama.enabled = bool(payload["enabled"])
            engine.advisor.config = config.ollama
        if "disabled" in payload:                    # the single switch, web flavoured
            if payload["disabled"]:
                config.ai_provider = "none"
            else:
                config.ai_provider = "auto"
                # "turn the advisor on" has to turn something on: --no-ai switched the
                # local provider off, so switch it back on and let auto resolve it
                config.ollama.enabled = True
            engine.advisor.configure(config.ai_provider, announce=False)
            engine.session.auto_think = config.autothink_enabled()
        engine.bus.publish(EK.SESSION_INFO, {
            "auto_think": engine.session.auto_think, "ollama_enabled": config.ollama.enabled,
        })
        return {"ok": True, "auto_think": engine.session.auto_think,
                "disabled": config.ai_off(), "provider": engine.advisor.provider,
                "configured_provider": config.ai_provider,
                "ollama_enabled": config.ollama.enabled}

    # ------------------------------------------------------------------ #
    # WebSocket
    # ------------------------------------------------------------------ #
    @app.websocket("/ws")
    async def websocket(ws: WebSocket):
        await ws.accept()
        engine = state.get_engine()
        if engine is None:
            await ws.close(code=1011)
            return
        subscription = engine.bus.subscribe(maxsize=4000)
        queue: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=2000)

        def pump() -> None:
            """Bridge the thread-safe bus queue into the asyncio world."""
            while not subscription.closed:
                event = subscription.get(timeout=1.0)
                if event is None:
                    continue
                try:
                    asyncio.run_coroutine_threadsafe(queue.put(event.to_dict()), loop)
                except RuntimeError:
                    return

        loop = asyncio.get_running_loop()
        threading.Thread(target=pump, name="ws-pump", daemon=True).start()
        try:
            await ws.send_text(json.dumps({"kind": "state", "data": snapshot()}))
            last_state = 0.0
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    event = None
                if event is not None:
                    await ws.send_text(json.dumps({"kind": "event", "event": event}))
                now = time.time()
                if now - last_state > 3.0:
                    last_state = now
                    await ws.send_text(json.dumps({"kind": "state", "data": snapshot()}))
        except (WebSocketDisconnect, RuntimeError, ConnectionError):
            pass
        finally:
            subscription.close()

    return app


def run_server(config: Optional[Config] = None, host: str = "", port: int = 0,
               demo: bool = False, authorized: bool = False, open_browser: bool = False) -> None:
    """Start uvicorn (blocking).  Used by ``wifipilot web``."""
    require_linux("wifipilot web")
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise ImportError("the web UI needs uvicorn: pip install 'uvicorn[standard]'") from exc

    config = config or Config()
    host = host or config.web_host
    port = port or config.web_port
    app = create_app(config, demo=demo, authorized=authorized)
    if open_browser:
        import webbrowser

        def opener() -> None:
            time.sleep(1.2)
            with contextlib.suppress(Exception):
                webbrowser.open(f"http://127.0.0.1:{port}/")

        threading.Thread(target=opener, daemon=True).start()
    levels = {"critical", "error", "warning", "info", "debug", "trace"}
    level = config.log_level if config.log_level in levels else "info"
    if level == "info":
        level = "warning"          # the CLI dashboard is our log, not uvicorn's
    uvicorn.run(app, host=host, port=port, log_level=level, access_log=False)
