"""Journal d'audit : qui a lance quelle analyse, sur quel domaine, avec quelles cases cochees."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from .models import Consents

ACTION_ANALYSE_DEMANDEE = "analyse_demandee"
ACTION_ANALYSE_REFUSEE = "analyse_refusee_consentement_manquant"
ACTION_ANALYSE_TERMINEE = "analyse_terminee"
ACTION_EXPORT = "export_rapport"
ACTION_PURGE = "purge_journal"


async def record(
    store,
    *,
    action: str,
    actor: str | None = None,
    domain: str | None = None,
    consents: Consents | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    analysis_id: str | None = None,
) -> None:
    """Ecrit une entree d'audit. Ne leve jamais : l'audit ne doit pas casser l'analyse."""
    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "actor": actor,
        "domain": domain,
        "action": action,
        "consents_json": json.dumps(consents.model_dump(), sort_keys=True) if consents else None,
        "client_ip": client_ip,
        "user_agent": (user_agent or "")[:300] or None,
        "analysis_id": analysis_id,
    }
    try:
        await store.log_audit(entry)
    except Exception:  # pragma: no cover - l'audit ne doit jamais interrompre le service
        pass
