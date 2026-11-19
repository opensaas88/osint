"""Point d'entrée en ligne de commande : `python -m app [serve|purge|analyse]`."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from .config import get_settings


def _serve() -> None:
    import uvicorn

    settings = get_settings()
    print(f"DomainExposure écoute sur http://{settings.host}:{settings.port}")
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, log_level="info")


async def _purge() -> None:
    from .orchestrator import purge_expired
    from .storage import Store

    settings = get_settings()
    store = Store(settings.db_path)
    await store.init()
    purged = await purge_expired(store, settings)
    print(
        f"Cache expiré supprimé : {purged['cache']} entrée(s). "
        f"Journal d'audit au-delà de {settings.audit_retention_days} jours : "
        f"{purged['audit']} entrée(s)."
    )


async def _analyse(domain: str) -> int:
    """Analyse en ligne de commande, utile pour les tests et l'intégration continue."""
    from .models import SEVERITY_LABEL, Consents
    from .orchestrator import Orchestrator
    from .storage import Store
    from .validation import InvalidDomain, normalize_domain

    settings = get_settings()
    try:
        target = normalize_domain(domain)
    except InvalidDomain as exc:
        print(f"Domaine refusé : {exc.reason}")
        return 2

    print(
        "En lançant cette analyse, vous attestez disposer d'une autorisation du propriétaire "
        "du domaine ou agir dans un cadre contractuel, et vous limiter à de la collecte passive."
    )
    store = Store(settings.db_path)
    await store.init()
    report = await Orchestrator(settings, store).run(
        target, Consents(authorization=True, passive_only=True), actor=f"cli:{settings.operator}"
    )
    print(f"\n{report.domain} — score {report.score}/100, note {report.grade}")
    for module in report.modules:
        suffix = f" ({module.disabled_reason})" if module.disabled_reason else ""
        score = module.score if module.score is not None else "--"
        print(f"  [{module.status.value:7}] {module.label:24} {score:>4}{suffix}")
        for finding in module.findings:
            print(f"      {SEVERITY_LABEL[finding.severity]:8} {finding.title}")
    print(f"\nIdentifiant de l'analyse : {report.id}")
    return 0


async def _export(cible: str) -> int:
    """Range le rapport d'une analyse dans le répertoire de suivi interne."""
    from .report.html import render_html
    from .report.pdf import PdfUnavailable, render_pdf
    from .storage import Store
    from .validation import InvalidDomain, normalize_domain

    settings = get_settings()
    store = Store(settings.db_path)
    await store.init()

    rapport = await store.get_report(cible)
    if rapport is None:
        # Pas un identifiant : on tente le domaine, et on prend sa dernière analyse.
        try:
            domaine = normalize_domain(cible).ascii
        except InvalidDomain as exc:
            print(f"Ni identifiant d'analyse, ni domaine exploitable : {exc.reason}")
            return 2
        analyses = await store.list_analyses(domaine, limit=1)
        if not analyses:
            print(f"Aucune analyse enregistrée pour {domaine}.")
            return 2
        rapport = await store.get_report(analyses[0]["id"])
    if rapport is None:  # pragma: no cover - incohérence de base
        print("Analyse introuvable.")
        return 2

    domaine = rapport.get("domain", "inconnu")
    horodatage = str(rapport.get("started_at") or "")[:16].replace(":", "").replace("T", "-")
    dossier = Path(settings.reports_dir) / domaine
    dossier.mkdir(parents=True, exist_ok=True)
    base = dossier / f"{horodatage}-rapport"

    historique = await store.score_history(domaine)
    base.with_suffix(".html").write_text(
        render_html(rapport, settings, historique), encoding="utf-8"
    )
    print(f"→ {base.with_suffix('.html')}")

    try:
        base.with_suffix(".pdf").write_bytes(render_pdf(rapport, settings, historique))
        print(f"→ {base.with_suffix('.pdf')}")
    except PdfUnavailable as exc:
        print(f"PDF non généré : {exc}")

    print(
        "\nCe rapport décrit la surface d'attaque de l'organisation : traitez-le comme "
        "un document confidentiel. Le répertoire de suivi est exclu du dépôt."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    command = argv[0] if argv else "serve"

    if command in ("serve", ""):
        _serve()
        return 0
    if command == "purge":
        asyncio.run(_purge())
        return 0
    if command == "export":
        if len(argv) < 2:
            print("Usage : python -m app export <identifiant d'analyse | domaine>")
            return 2
        return asyncio.run(_export(argv[1]))

    if command == "analyse":
        if len(argv) < 2:
            print("Usage : python -m app analyse <domaine>")
            return 2
        return asyncio.run(_analyse(argv[1]))

    print(
        "Commandes disponibles : serve (défaut), purge, analyse <domaine>, "
        "export <identifiant | domaine>"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
