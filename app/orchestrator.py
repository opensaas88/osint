"""Orchestration d'une analyse : reconnaissance DNS, exécution des modules par vagues, scoring.

Les modules sont exécutés en parallèle au sein d'une même vague ; un module qui
déclare `DEPENDS_ON` attend la vague précédente. Chaque étape émet un événement
consommé par le flux SSE de l'interface.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx

from . import audit
from .httpclient import HttpClient
from .models import AnalysisStatus, Consents, ModuleResult, ModuleStatus, Report
from .modules import ModuleContext, ReconData, load_registry
from .resolver import build_resolver
from .sanitize import scrub_module_result
from .scoring import compute_global_score
from .validation import DomainName

#: Délai maximal par défaut accordé à un module, en secondes.
DEFAULT_MODULE_TIMEOUT = 120.0


class AnalysisChannel:
    """Diffusion des événements d'une analyse, avec rejeu pour les abonnés tardifs."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.closed = False
        self._condition = asyncio.Condition()

    async def publish(self, event: str, data: dict[str, Any] | None = None) -> None:
        async with self._condition:
            self.events.append({"event": event, "data": data or {}})
            self._condition.notify_all()

    async def close(self) -> None:
        async with self._condition:
            self.closed = True
            self._condition.notify_all()

    async def stream(self):
        """Rejoue les événements déjà émis puis suit les suivants jusqu'à la clôture."""
        index = 0
        while True:
            async with self._condition:
                while index >= len(self.events) and not self.closed:
                    await self._condition.wait()
                if index >= len(self.events) and self.closed:
                    return
                batch = self.events[index:]
                index = len(self.events)
            for event in batch:
                yield event


async def collect_recon(resolver, domain: DomainName) -> ReconData:
    """Résout une fois pour toutes les enregistrements de l'apex."""
    rrtypes = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "DS")
    answers = await asyncio.gather(*(resolver.query(domain.ascii, rr) for rr in rrtypes))
    recon = ReconData(domain=domain.ascii)
    by_type = dict(zip(rrtypes, answers, strict=True))
    recon.a = list(by_type["A"].records)
    recon.aaaa = list(by_type["AAAA"].records)
    recon.mx = list(by_type["MX"].records)
    recon.ns = list(by_type["NS"].records)
    recon.txt = list(by_type["TXT"].records)
    recon.soa = list(by_type["SOA"].records)
    recon.caa = list(by_type["CAA"].records)
    recon.ds = list(by_type["DS"].records)
    recon.dnssec_authenticated = any(a.authenticated for a in answers if a.ok)
    recon.resolves = bool(recon.a or recon.aaaa or recon.ns or recon.soa)
    for rrtype, answer in by_type.items():
        if answer.error:
            recon.errors.append(f"{rrtype}: {answer.error}")
    return recon


def plan_waves(registry: list[Any]) -> list[list[Any]]:
    """Ordonne les modules en vagues successives selon leurs dépendances."""
    remaining = list(registry)
    satisfied: set[str] = set()
    waves: list[list[Any]] = []
    while remaining:
        wave = [m for m in remaining if set(getattr(m, "DEPENDS_ON", ())) <= satisfied]
        if not wave:  # dépendance manquante ou cycle : on exécute le reste tel quel
            waves.append(remaining)
            break
        waves.append(wave)
        satisfied.update(m.KEY for m in wave)
        remaining = [m for m in remaining if m not in wave]
    return waves


class Orchestrator:
    """Exécute une analyse complète et persiste le rapport."""

    def __init__(self, settings, store) -> None:
        self.settings = settings
        self.store = store

    async def run(
        self,
        domain: DomainName,
        consents: Consents,
        *,
        actor: str,
        channel: AnalysisChannel | None = None,
        analysis_id: str | None = None,
    ) -> Report:
        report = Report(
            id=analysis_id or uuid.uuid4().hex,
            domain=domain.ascii,
            domain_unicode=domain.unicode,
            started_at=datetime.now(UTC),
            consents=consents,
            actor=actor,
        )
        channel = channel or AnalysisChannel()
        registry = load_registry()

        async with httpx.AsyncClient(
            headers={"user-agent": self.settings.user_agent},
            timeout=self.settings.http_timeout,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        ) as raw_client:
            http = HttpClient(self.settings, self.store, client=raw_client)
            resolver = await build_resolver(self.settings, raw_client)
            report.dns_backend = resolver.backend

            await channel.publish(
                "analysis_started",
                {
                    "id": report.id,
                    "domain": domain.ascii,
                    "domain_unicode": domain.unicode,
                    "dns_backend": resolver.backend,
                    "modules": [
                        {"key": m.KEY, "label": m.LABEL, "weight": m.WEIGHT} for m in registry
                    ],
                },
            )

            recon = await collect_recon(resolver, domain)
            if not recon.resolves:
                report.notes.append(
                    "Le domaine ne renvoie aucun enregistrement DNS : il est peut-être "
                    "expiré, non délégué, ou la résolution a échoué."
                )
            await channel.publish(
                "recon",
                {
                    "resolves": recon.resolves,
                    "ips": recon.ips,
                    "mx": recon.mx_hosts,
                    "ns": [n.rstrip(".") for n in recon.ns],
                    "errors": recon.errors,
                },
            )

            ctx = ModuleContext(
                domain=domain,
                settings=self.settings,
                http=http,
                resolver=resolver,
                consents=consents,
                recon=recon,
            )

            for wave in plan_waves(registry):
                await asyncio.gather(
                    *(self._run_module(module, ctx, channel) for module in wave)
                )

        report.modules = [ctx.results[m.KEY] for m in registry if m.KEY in ctx.results]
        report.score, report.grade, report.score_capped_by_critical = compute_global_score(
            report.modules
        )
        report.status = AnalysisStatus.DONE
        report.finished_at = datetime.now(UTC)

        await self.store.save_report(report)
        await audit.record(
            self.store,
            action=audit.ACTION_ANALYSE_TERMINEE,
            actor=actor,
            domain=domain.ascii,
            consents=consents,
            analysis_id=report.id,
        )
        await channel.publish(
            "analysis_done",
            {
                "id": report.id,
                "score": report.score,
                "grade": report.grade,
                "capped": report.score_capped_by_critical,
                "counts": report.counts,
                "notes": report.notes,
            },
        )
        await channel.close()
        return report

    async def _run_module(self, module: Any, ctx: ModuleContext, channel: AnalysisChannel) -> None:
        """Exécute un module en isolant ses erreurs et son dépassement de délai."""
        key = module.KEY
        await channel.publish("module_started", {"key": key, "label": module.LABEL})
        timeout = float(getattr(module, "TIMEOUT", DEFAULT_MODULE_TIMEOUT))
        try:
            result: ModuleResult = await asyncio.wait_for(module.run(ctx), timeout=timeout)
        except TimeoutError:
            result = ModuleResult(
                key=key,
                label=module.LABEL,
                status=ModuleStatus.ERROR,
                score=None,
                weight=module.WEIGHT,
                disabled_reason=f"délai dépassé ({timeout:.0f} s)",
                errors=[f"le module a dépassé son délai maximal de {timeout:.0f} s"],
            )
        except asyncio.CancelledError:  # pragma: no cover - annulation du serveur
            raise
        except Exception as exc:
            result = ModuleResult(
                key=key,
                label=module.LABEL,
                status=ModuleStatus.ERROR,
                score=None,
                weight=module.WEIGHT,
                disabled_reason="erreur interne du module",
                errors=[f"{type(exc).__name__}: {str(exc)[:300]}"],
            )

        scrub_module_result(result)
        ctx.results[key] = result
        await channel.publish(
            "module_done",
            {"key": key, "result": result.model_dump(mode="json")},
        )


async def purge_expired(store, settings) -> dict[str, int]:
    """Purge le cache expiré et le journal d'audit hors période de conservation."""
    purged_cache = await store.cache_purge_expired()
    purged_audit = await store.purge_audit(settings.audit_retention_days)
    with contextlib.suppress(Exception):
        await audit.record(store, action=audit.ACTION_PURGE, actor="systeme")
    return {"cache": purged_cache, "audit": purged_audit}
