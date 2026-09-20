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
``POST /api/ai/model``         select the Ollama model
``POST /api/ai/pull``          pull a model through Ollama
``GET  /api/report``           markdown engagement report
``GET  /api/export``           JSON export of the whole session
``WS   /ws``                   live events + state
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..config import Config, find_wordlists
from ..deps import list_interfaces, registry
from ..engine import Engine
from ..events import EK, EventBus
from ..models import ATTACK_NAMES
from ..util import human_duration, mac_norm, now_iso, read_json, write_json

try:  # pragma: no cover - import guard
    from fastapi import Body, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
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
                  description="AI-piloted WiFi auditing — authorised use only",
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
        return {
            "ok": True, "demo": state.demo, "phase": engine.status.phase if engine else "idle",
            "time": now_iso(), "version": "0.1.0",
        }

    # ------------------------------------------------------------------ #
    # read APIs
    # ------------------------------------------------------------------ #
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
        return {"config": config.to_dict(), "attacks": list(ATTACK_NAMES)}

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
            config.update(**payload)
            engine.advisor.config = config.ollama
            engine.advisor.client.config = config.ollama
            # keep the live session in step with the new settings
            engine.session.stealth = config.stealth
            engine.session.auto_think = config.ollama.enable_autothink
            if not state.demo:
                with contextlib.suppress(Exception):
                    engine.session.known_wordlists = find_wordlists(config)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid config: {exc}") from exc
        engine.bus.publish(EK.SESSION_INFO, {"config": config.to_dict(), "action": "config-updated"})
        return {"ok": True, "config": config.to_dict()}

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
        return {"ok": True, "message": engine.request_crack(bssid, wordlists)}

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
        plan = engine.request_think()
        return {"ok": True, "plan": plan.to_dict()}

    @app.post("/api/ai/chat")
    async def api_chat(payload: Dict[str, Any] = Body(...)):
        engine = engine_or_404()
        message = (payload.get("message") or "").strip()
        if not message:
            raise HTTPException(status_code=400, detail="message required")
        engine.bus.publish(EK.ADVISOR_CHAT, {"role": "user", "kind": "chat", "message": message})

        def worker() -> None:
            try:
                engine.advisor.ask(message, model=payload.get("model", ""))
            except Exception as exc:  # pragma: no cover
                engine.bus.error(f"chat failed: {exc}")

        threading.Thread(target=worker, name="advisor-chat", daemon=True).start()
        return {"ok": True, "streaming": True}

    @app.post("/api/ai/model")
    async def api_model(payload: Dict[str, Any] = Body(...)):
        engine = engine_or_404()
        name = payload.get("model", "")
        config.ollama.model = name or "auto"
        engine.advisor.config = config.ollama
        engine.advisor.client.config = config.ollama
        engine.advisor.client._models_at = 0  # noqa: SLF001
        engine.advisor.check(force=True)
        return {"ok": True, "model": engine.advisor.model, "advisor": engine.advisor.status()}

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
        engine.bus.publish(EK.SESSION_INFO, {
            "auto_think": engine.session.auto_think, "ollama_enabled": config.ollama.enabled,
        })
        return {"ok": True, "auto_think": engine.session.auto_think,
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
