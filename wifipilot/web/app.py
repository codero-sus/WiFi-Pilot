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
``POST /api/ai/provider``      switch provider (ollama | openrouter | auto | none)
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
from typing import Any, Dict, List, Optional

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
        return data

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
                "providers": provider_status(config.ollama, config.openrouter)}

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
        bssid = mac_norm(payload.get("bssid", ""))
        if not bssid:
            raise HTTPException(status_code=400, detail="bssid required")
        attack = (payload.get("attack") or "").strip()
        if attack and attack not in ATTACK_NAMES:
            raise HTTPException(status_code=400, detail=f"unknown attack {attack!r}")
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
            client = build_client(wanted, config.ollama, config.openrouter, engine.bus)
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
        if provider not in ("auto", "ollama", "openrouter", "none"):
            raise HTTPException(status_code=400,
                                detail=f"unknown provider {provider!r} "
                                       f"(expected auto|ollama|openrouter|none)")
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
