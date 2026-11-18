"""API FastAPI et service des fichiers statiques de DomainExposure."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from . import __version__, audit
from .compare import compare_reports
from .config import get_settings
from .models import AnalysisStatus, Consents
from .modules import MODULE_LABELS
from .orchestrator import AnalysisChannel, Orchestrator, purge_expired
from .remediation import build_plan, simulate
from .scheduler import Scheduler
from .scoring import CRITICAL_SCORE_CAP, GRADE_SCALE, MODULE_WEIGHTS
from .storage import Store
from .validation import InvalidDomain, normalize_domain
from .watchlist import INTERVALLES, build_portfolio, next_run

STATIC_DIR = Path(__file__).resolve().parent / "static"

#: Nombre d'analyses dont le flux d'événements reste consultable en mémoire.
MAX_LIVE_CHANNELS = 50


class AnalysisRequest(BaseModel):
    """Corps de la demande d'analyse."""

    domain: str = Field(..., max_length=300)
    authorization: bool = False
    passive_only: bool = False
    domain_verified: bool = False


class WatchRequest(BaseModel):
    """Inscription d'un domaine au portefeuille surveillé.

    Les deux attestations obligatoires sont les mêmes que pour une analyse
    ponctuelle : elles valent ici **mandat permanent**, puisque les analyses
    planifiées se déclencheront sans intervention humaine.
    """

    domain: str = Field(..., max_length=300)
    label: str | None = Field(default=None, max_length=200)
    interval_hours: int = Field(default=168, ge=0, le=8760)
    authorization: bool = False
    passive_only: bool = False
    domain_verified: bool = False
    mandate_reference: str | None = Field(default=None, max_length=200)
    notify_webhook: str | None = Field(default=None, max_length=500)
    notify_email: str | None = Field(default=None, max_length=500)


class WatchUpdate(BaseModel):
    """Modification d'un suivi existant. Le mandat, lui, ne se modifie pas."""

    label: str | None = Field(default=None, max_length=200)
    interval_hours: int | None = Field(default=None, ge=0, le=8760)
    active: bool | None = None
    domain_verified: bool | None = None
    notify_webhook: str | None = Field(default=None, max_length=500)
    notify_email: str | None = Field(default=None, max_length=500)


class SimulationRequest(BaseModel):
    """Constats dont on veut simuler la correction."""

    codes: list[str] = Field(default_factory=list, max_length=200)


def create_app(settings=None, store=None) -> FastAPI:
    settings = settings or get_settings()
    store = store or Store(settings.db_path)

    scheduler = Scheduler(settings, store)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await store.init()
        await purge_expired(store, settings)
        await scheduler.start()
        try:
            yield
        finally:
            await scheduler.stop()

    app = FastAPI(
        title="DomainExposure",
        version=__version__,
        description="Évaluation passive de l'exposition cyber d'une organisation",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.store = store
    app.state.scheduler = scheduler
    app.state.channels: OrderedDict[str, AnalysisChannel] = OrderedDict()
    app.state.tasks: dict[str, asyncio.Task] = {}

    def register_channel(analysis_id: str, channel: AnalysisChannel) -> None:
        channels = app.state.channels
        channels[analysis_id] = channel
        while len(channels) > MAX_LIVE_CHANNELS:
            channels.popitem(last=False)

    # ------------------------------------------------------------------ UI --
    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/app.js", include_in_schema=False)
    async def app_js() -> FileResponse:
        return FileResponse(STATIC_DIR / "app.js", media_type="application/javascript")

    # --------------------------------------------------------------- méta ---
    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "horodatage": datetime.now(UTC).isoformat(),
        }

    @app.get("/api/modules")
    async def modules() -> dict[str, Any]:
        return {
            "modules": [
                {"key": key, "label": label, "weight": MODULE_WEIGHTS.get(key, 0)}
                for key, label in MODULE_LABELS.items()
            ],
            "cles_api": settings.api_key_inventory(),
            "bareme": [{"score_minimal": seuil, "note": note} for seuil, note in GRADE_SCALE],
            "plafond_critique": CRITICAL_SCORE_CAP,
            "cache_heures": settings.cache_ttl_hours,
            "audit_jours": settings.audit_retention_days,
        }

    # ----------------------------------------------------------- analyses ---
    @app.post("/api/analyses", status_code=202)
    async def create_analysis(payload: AnalysisRequest, request: Request) -> dict[str, Any]:
        consents = Consents(
            authorization=payload.authorization,
            passive_only=payload.passive_only,
            domain_verified=payload.domain_verified,
        )
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        try:
            domain = normalize_domain(payload.domain)
        except InvalidDomain as exc:
            raise HTTPException(
                status_code=400, detail={"erreur": exc.reason, "aide": exc.hint}
            ) from exc

        if not consents.mandatory_granted:
            await audit.record(
                store,
                action=audit.ACTION_ANALYSE_REFUSEE,
                actor=settings.operator,
                domain=domain.ascii,
                consents=consents,
                client_ip=client_ip,
                user_agent=user_agent,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "erreur": "Les cases obligatoires n'ont pas été cochées : l'analyse est "
                              "refusée et le refus est journalisé.",
                    "manquantes": consents.missing(),
                },
            )

        analysis_id = uuid.uuid4().hex
        await audit.record(
            store,
            action=audit.ACTION_ANALYSE_DEMANDEE,
            actor=settings.operator,
            domain=domain.ascii,
            consents=consents,
            client_ip=client_ip,
            user_agent=user_agent,
            analysis_id=analysis_id,
        )

        channel = AnalysisChannel()
        register_channel(analysis_id, channel)
        orchestrator = Orchestrator(settings, store)

        async def worker() -> None:
            try:
                await orchestrator.run(
                    domain, consents, actor=settings.operator,
                    channel=channel, analysis_id=analysis_id,
                )
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception as exc:
                await channel.publish(
                    "analysis_failed",
                    {"id": analysis_id, "erreur": f"{type(exc).__name__}: {str(exc)[:300]}"},
                )
                await channel.close()
            finally:
                app.state.tasks.pop(analysis_id, None)

        app.state.tasks[analysis_id] = asyncio.create_task(worker())
        return {
            "id": analysis_id,
            "domaine": domain.ascii,
            "domaine_unicode": domain.unicode,
            "flux": f"/api/analyses/{analysis_id}/stream",
        }

    @app.get("/api/analyses/{analysis_id}/stream", include_in_schema=False)
    async def stream(analysis_id: str) -> StreamingResponse:
        channel: AnalysisChannel | None = app.state.channels.get(analysis_id)
        if channel is None:
            raise HTTPException(status_code=404, detail={"erreur": "analyse inconnue ou expirée"})

        async def events():
            async for event in channel.stream():
                payload = json.dumps(event["data"], ensure_ascii=False, default=str)
                yield f"event: {event['event']}\ndata: {payload}\n\n"
            yield "event: end\ndata: {}\n\n"

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"cache-control": "no-cache", "x-accel-buffering": "no"},
        )

    @app.get("/api/analyses")
    async def list_analyses(
        domain: str | None = None, limit: int = Query(default=50, ge=1, le=500)
    ) -> dict[str, Any]:
        normalise = None
        if domain:
            try:
                normalise = normalize_domain(domain).ascii
            except InvalidDomain as exc:
                raise HTTPException(status_code=400, detail={"erreur": exc.reason}) from exc
        return {"analyses": await store.list_analyses(normalise, limit)}

    @app.get("/api/analyses/{analysis_id}")
    async def get_analysis(analysis_id: str) -> JSONResponse:
        report = await store.get_report(analysis_id)
        if report is None:
            if analysis_id in app.state.channels:
                return JSONResponse({"id": analysis_id, "status": AnalysisStatus.RUNNING.value})
            raise HTTPException(status_code=404, detail={"erreur": "analyse inconnue"})
        return JSONResponse(report)

    @app.get("/api/analyses/{analysis_id}/plan")
    async def remediation_plan(
        analysis_id: str, limite: int = Query(default=10, ge=1, le=100)
    ) -> dict[str, Any]:
        """Plan de remédiation : actions triées par gain, effort et score projeté."""
        report = await store.get_report(analysis_id)
        if report is None:
            raise HTTPException(status_code=404, detail={"erreur": "analyse inconnue"})
        return build_plan(report.get("modules") or [], limite=limite)

    @app.post("/api/analyses/{analysis_id}/simulate")
    async def remediation_simulate(
        analysis_id: str, payload: SimulationRequest
    ) -> dict[str, Any]:
        """Score et note obtenus si les constats indiqués étaient corrigés."""
        report = await store.get_report(analysis_id)
        if report is None:
            raise HTTPException(status_code=404, detail={"erreur": "analyse inconnue"})
        return simulate(report.get("modules") or [], payload.codes)

    @app.get("/api/compare")
    async def compare(a: str = Query(...), b: str = Query(...)) -> dict[str, Any]:
        before, after = await asyncio.gather(store.get_report(a), store.get_report(b))
        if before is None or after is None:
            raise HTTPException(
                status_code=404, detail={"erreur": "une des deux analyses est introuvable"}
            )
        if before.get("domain") != after.get("domain"):
            raise HTTPException(
                status_code=400,
                detail={"erreur": "la comparaison n'a de sens qu'entre deux analyses du même "
                                  "domaine"},
            )
        if (before.get("started_at") or "") > (after.get("started_at") or ""):
            before, after = after, before
        return compare_reports(before, after)

    # -------------------------------------------------------- portefeuille --
    @app.get("/api/watchlist")
    async def portefeuille() -> dict[str, Any]:
        """Vue consolidée du portefeuille, du domaine le plus exposé au moins exposé."""
        suivis = await store.watch_list()
        rapports = {
            entree["domain"]: await store.last_two_reports(entree["domain"])
            for entree in suivis
        }
        return {
            "domaines": build_portfolio(suivis, rapports),
            "intervalles": INTERVALLES,
            "ordonnanceur": {
                "actif": settings.scheduler_enabled,
                "periode_secondes": settings.scheduler_tick_seconds,
                "seuil_alerte_points": settings.alert_score_drop,
                "derniere_passe": (
                    scheduler.derniere_passe.isoformat() if scheduler.derniere_passe else None
                ),
                "courriel_configure": bool(settings.smtp_host),
            },
        }

    @app.post("/api/watchlist", status_code=201)
    async def surveiller(payload: WatchRequest, request: Request) -> dict[str, Any]:
        consents = Consents(
            authorization=payload.authorization,
            passive_only=payload.passive_only,
            domain_verified=payload.domain_verified,
        )
        client_ip = request.client.host if request.client else None

        try:
            domaine = normalize_domain(payload.domain)
        except InvalidDomain as exc:
            raise HTTPException(
                status_code=400, detail={"erreur": exc.reason, "aide": exc.hint}
            ) from exc

        if not consents.mandatory_granted:
            await audit.record(
                store, action=audit.ACTION_ANALYSE_REFUSEE, actor=settings.operator,
                domain=domaine.ascii, consents=consents, client_ip=client_ip,
                detail="inscription au portefeuille refusée",
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "erreur": "Les attestations obligatoires valent mandat permanent pour les "
                              "analyses planifiées : elles ne peuvent pas être omises.",
                    "manquantes": consents.missing(),
                },
            )

        existant = await store.watch_get(domaine.ascii)
        maintenant = datetime.now(UTC)
        entree = {
            "id": existant["id"] if existant else uuid.uuid4().hex,
            "domain": domaine.ascii,
            "label": payload.label or domaine.unicode,
            "interval_hours": payload.interval_hours,
            "active": True,
            "domain_verified": payload.domain_verified,
            "mandate_actor": settings.operator,
            "mandate_at": maintenant.isoformat(),
            "mandate_reference": payload.mandate_reference,
            "notify_webhook": payload.notify_webhook,
            "notify_email": payload.notify_email,
            "next_run_at": next_run(payload.interval_hours, maintenant),
            "created_at": (existant or {}).get("created_at") or maintenant.isoformat(),
        }
        await store.watch_upsert(entree)
        await audit.record(
            store, action=audit.ACTION_SURVEILLANCE_AJOUT, actor=settings.operator,
            domain=domaine.ascii, consents=consents, client_ip=client_ip,
            detail=f"mandat permanent, réf. {payload.mandate_reference or 'non précisée'}, "
                   f"périodicité {payload.interval_hours} h",
        )
        return {"id": entree["id"], "domaine": domaine.ascii,
                "prochaine_analyse": entree["next_run_at"]}

    @app.patch("/api/watchlist/{identifiant}")
    async def modifier_surveillance(identifiant: str, payload: WatchUpdate) -> dict[str, Any]:
        entree = await store.watch_get(identifiant)
        if entree is None:
            raise HTTPException(status_code=404, detail={"erreur": "domaine non suivi"})
        modifications = payload.model_dump(exclude_none=True)
        entree.update(modifications)
        if "interval_hours" in modifications:
            entree["next_run_at"] = next_run(int(modifications["interval_hours"]))
        await store.watch_upsert(entree)
        return {"id": entree["id"], "prochaine_analyse": entree.get("next_run_at")}

    @app.delete("/api/watchlist/{identifiant}", status_code=204)
    async def retirer_surveillance(identifiant: str, request: Request) -> Response:
        entree = await store.watch_get(identifiant)
        if entree is None:
            raise HTTPException(status_code=404, detail={"erreur": "domaine non suivi"})
        await store.watch_delete(identifiant)
        await audit.record(
            store, action=audit.ACTION_SURVEILLANCE_RETRAIT, actor=settings.operator,
            domain=entree["domain"],
            client_ip=request.client.host if request.client else None,
            detail="mandat révoqué",
        )
        return Response(status_code=204)

    @app.post("/api/watchlist/{identifiant}/run")
    async def analyser_maintenant(identifiant: str) -> dict[str, Any]:
        """Déclenche immédiatement l'analyse d'un domaine suivi, hors échéance."""
        entree = await store.watch_get(identifiant)
        if entree is None:
            raise HTTPException(status_code=404, detail={"erreur": "domaine non suivi"})
        return await scheduler.run_one(entree, declencheur="manuelle")

    # ----------------------------------------------------------- exports ----
    @app.get("/api/analyses/{analysis_id}/report.html", include_in_schema=False)
    async def export_html(analysis_id: str, request: Request) -> HTMLResponse:
        from .report.html import render_html

        report = await store.get_report(analysis_id)
        if report is None:
            raise HTTPException(status_code=404, detail={"erreur": "analyse inconnue"})
        await audit.record(
            store, action=audit.ACTION_EXPORT, actor=settings.operator,
            domain=report.get("domain"), analysis_id=analysis_id,
            client_ip=request.client.host if request.client else None,
        )
        return HTMLResponse(render_html(report, settings))

    @app.get("/api/analyses/{analysis_id}/report.pdf", include_in_schema=False)
    async def export_pdf(analysis_id: str, request: Request) -> Response:
        from .report.pdf import PdfUnavailable, render_pdf

        report = await store.get_report(analysis_id)
        if report is None:
            raise HTTPException(status_code=404, detail={"erreur": "analyse inconnue"})
        try:
            content = await asyncio.to_thread(render_pdf, report, settings)
        except PdfUnavailable as exc:
            raise HTTPException(status_code=503, detail={"erreur": str(exc)}) from exc
        await audit.record(
            store, action=audit.ACTION_EXPORT, actor=settings.operator,
            domain=report.get("domain"), analysis_id=analysis_id,
            client_ip=request.client.host if request.client else None,
        )
        filename = f"domainexposure-{report.get('domain')}-{analysis_id[:8]}.pdf"
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"content-disposition": f'attachment; filename="{filename}"'},
        )

    # ------------------------------------------------------------- audit ----
    @app.get("/api/audit")
    async def audit_log(limit: int = Query(default=100, ge=1, le=1000)) -> dict[str, Any]:
        return {"journal": await store.list_audit(limit)}

    return app


app = create_app()
