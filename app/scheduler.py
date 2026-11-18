"""Ordonnanceur des analyses planifiées et détection des régressions.

Une tâche de fond réveille périodiquement les domaines dont l'échéance est
atteinte, lance leur analyse, compare le résultat à la précédente et notifie si
la situation s'est dégradée.

L'ordonnanceur s'exécute dans le processus applicatif : avec plusieurs workers
uvicorn, les analyses seraient dupliquées. La configuration livrée n'en utilise
qu'un seul ; pour monter en charge, désactivez SCHEDULER_ENABLED sur les
processus supplémentaires.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import Any

import httpx

from . import audit, notify
from .httpclient import HttpClient
from .models import Consents
from .orchestrator import Orchestrator
from .validation import InvalidDomain, normalize_domain
from .watchlist import build_alert_payload, detect_regression, next_run


class Scheduler:
    """Boucle d'ordonnancement des analyses planifiées."""

    def __init__(self, settings, store) -> None:
        self.settings = settings
        self.store = store
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._semaphore = asyncio.Semaphore(max(1, int(settings.scheduler_concurrency)))
        self.derniere_passe: datetime | None = None

    # -- cycle de vie -------------------------------------------------------
    async def start(self) -> None:
        if not self.settings.scheduler_enabled or self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._loop(), name="domainexposure-scheduler")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _loop(self) -> None:  # pragma: no cover - boucle infinie
        intervalle = max(10, int(self.settings.scheduler_tick_seconds))
        while not self._stop.is_set():
            try:
                await self.run_due()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # une passe en échec ne doit pas tuer l'ordonnanceur
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=intervalle)

    # -- exécution ----------------------------------------------------------
    async def run_due(self) -> list[dict[str, Any]]:
        """Analyse tous les domaines dont l'échéance est atteinte."""
        self.derniere_passe = datetime.now(UTC)
        echus = await self.store.watch_due()
        if not echus:
            return []
        return list(await asyncio.gather(*(self._run_guarded(w) for w in echus)))

    async def _run_guarded(self, watched: dict[str, Any]) -> dict[str, Any]:
        async with self._semaphore:
            try:
                return await self.run_one(watched)
            except Exception as exc:
                return {
                    "domaine": watched.get("domain"),
                    "erreur": f"{type(exc).__name__} : {str(exc)[:200]}",
                }

    async def run_one(
        self, watched: dict[str, Any], declencheur: str = "planifiee"
    ) -> dict[str, Any]:
        """Analyse un domaine suivi, détecte les régressions et notifie."""
        try:
            domaine = normalize_domain(watched["domain"])
        except InvalidDomain as exc:
            return {"domaine": watched.get("domain"), "erreur": exc.reason}

        mandat = (
            f"mandat attesté par {watched.get('mandate_actor')} le "
            f"{(watched.get('mandate_at') or '')[:10]}"
            + (
                f", réf. {watched['mandate_reference']}"
                if watched.get("mandate_reference")
                else ""
            )
        )
        consents = Consents(
            authorization=True,
            passive_only=True,
            domain_verified=bool(watched.get("domain_verified")),
        )

        await audit.record(
            self.store,
            action=audit.ACTION_ANALYSE_PLANIFIEE,
            actor=watched.get("mandate_actor") or self.settings.operator,
            domain=domaine.ascii,
            consents=consents,
            detail=f"{declencheur} — {mandat}",
        )

        precedents = await self.store.last_two_reports(domaine.ascii)
        avant = precedents[0] if precedents else None

        rapport = await Orchestrator(self.settings, self.store).run(
            domaine,
            consents,
            actor=f"{declencheur}:{watched.get('mandate_actor') or self.settings.operator}",
        )
        maintenant = datetime.now(UTC)
        await self.store.watch_mark_run(
            watched["id"],
            rapport.id,
            maintenant.isoformat(),
            next_run(int(watched.get("interval_hours") or 0), maintenant),
        )

        apres = rapport.model_dump(mode="json")
        alertes = detect_regression(avant, apres, self.settings.alert_score_drop)
        envois: list[dict[str, Any]] = []
        if alertes:
            payload = build_alert_payload(watched, avant, apres, alertes)
            async with httpx.AsyncClient(
                headers={"user-agent": self.settings.user_agent},
                timeout=self.settings.http_timeout,
                follow_redirects=True,
            ) as client:
                http = HttpClient(self.settings, None, client=client)
                envois = await notify.dispatch(self.settings, http, watched, payload)
            await audit.record(
                self.store,
                action=audit.ACTION_ALERTE,
                actor=watched.get("mandate_actor") or self.settings.operator,
                domain=domaine.ascii,
                analysis_id=rapport.id,
                detail="; ".join(a.type for a in alertes),
            )

        return {
            "domaine": domaine.ascii,
            "analyse_id": rapport.id,
            "score": rapport.score,
            "note": rapport.grade,
            "alertes": [a.to_dict() for a in alertes],
            "notifications": envois,
        }
