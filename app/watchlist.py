"""Surveillance d'un portefeuille de domaines : mandat, régressions, vue consolidée.

Une analyse planifiée pose une question éthique particulière : personne ne coche
de case au moment où elle se déclenche. La réponse retenue est le **mandat
permanent** — l'opérateur atteste une fois, nominativement et avec une référence
contractuelle, que le domaine est sous sa responsabilité ; cette attestation est
journalisée à l'inscription, puis rappelée dans le journal d'audit à chaque
exécution automatique. Elle est révocable en retirant le domaine du portefeuille.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import SEVERITY_ORDER, Severity
from .scoring import GRADE_SCALE

#: Baisse de score, en points, à partir de laquelle une alerte est émise.
DEFAULT_SCORE_DROP = 5

#: Intervalles proposés dans l'interface, en heures.
INTERVALLES = {
    "quotidien": 24,
    "hebdomadaire": 168,
    "mensuel": 720,
    "manuel": 0,
}

_GRADE_RANK = {note: rang for rang, (_, note) in enumerate(GRADE_SCALE)}


@dataclass(slots=True)
class Alerte:
    """Un motif de notification."""

    type: str
    gravite: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "gravite": self.gravite,
            "message": self.message,
            "detail": self.detail,
        }


def _findings_par_code(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        finding["code"]: finding
        for module in report.get("modules") or []
        for finding in module.get("findings") or []
    }


def _grade_rank(note: str | None) -> int | None:
    return _GRADE_RANK.get(note or "")


def detect_regression(
    avant: dict[str, Any] | None,
    apres: dict[str, Any],
    seuil: int = DEFAULT_SCORE_DROP,
) -> list[Alerte]:
    """Compare deux analyses et retourne les motifs d'alerte.

    Sans analyse antérieure, seule l'apparition d'un constat critique justifie une
    notification : il serait absurde d'alerter sur l'état initial d'un domaine qu'on
    vient tout juste d'inscrire.
    """
    alertes: list[Alerte] = []
    findings_apres = _findings_par_code(apres)

    if avant is None:
        critiques = [
            f for f in findings_apres.values() if f["severity"] == Severity.CRITIQUE.value
        ]
        if critiques:
            alertes.append(
                Alerte(
                    type="premiere_analyse_critique",
                    gravite="critique",
                    message=f"Première analyse : {len(critiques)} constat(s) critique(s)",
                    detail={"codes": [f["code"] for f in critiques]},
                )
            )
        return alertes

    findings_avant = _findings_par_code(avant)
    score_avant, score_apres = avant.get("score"), apres.get("score")

    if score_avant is not None and score_apres is not None:
        delta = score_apres - score_avant
        if delta <= -abs(seuil):
            alertes.append(
                Alerte(
                    type="score_baisse",
                    gravite="eleve",
                    message=f"Le score a baissé de {abs(delta)} points "
                            f"({score_avant} → {score_apres})",
                    detail={"avant": score_avant, "apres": score_apres, "delta": delta},
                )
            )

    rang_avant, rang_apres = _grade_rank(avant.get("grade")), _grade_rank(apres.get("grade"))
    if rang_avant is not None and rang_apres is not None and rang_apres > rang_avant:
        alertes.append(
            Alerte(
                type="note_degradee",
                gravite="eleve",
                message=f"La note est passée de {avant.get('grade')} à {apres.get('grade')}",
                detail={"avant": avant.get("grade"), "apres": apres.get("grade")},
            )
        )

    nouveaux = [
        findings_apres[code] for code in findings_apres.keys() - findings_avant.keys()
    ]
    for severite, etiquette in (
        (Severity.CRITIQUE, "critique"),
        (Severity.ELEVE, "élevé"),
    ):
        concernes = [f for f in nouveaux if f["severity"] == severite.value]
        if not concernes:
            continue
        concernes.sort(key=lambda f: f["code"])
        alertes.append(
            Alerte(
                type=f"nouveau_constat_{severite.value}",
                gravite=severite.value,
                message=f"{len(concernes)} nouveau(x) constat(s) de gravité {etiquette} : "
                        + ", ".join(f["title"] for f in concernes[:3]),
                detail={
                    "codes": [f["code"] for f in concernes],
                    "titres": [f["title"] for f in concernes],
                },
            )
        )

    alertes.sort(key=lambda a: SEVERITY_ORDER.get(Severity(a.gravite), 9))
    return alertes


def build_alert_payload(
    watched: dict[str, Any],
    avant: dict[str, Any] | None,
    apres: dict[str, Any],
    alertes: list[Alerte],
) -> dict[str, Any]:
    """Corps de notification, commun au webhook et au courriel."""
    return {
        "evenement": "regression_detectee",
        "domaine": apres.get("domain"),
        "client": watched.get("label") or apres.get("domain"),
        "analyse_id": apres.get("id"),
        "horodatage": apres.get("finished_at") or apres.get("started_at"),
        "score": {
            "avant": avant.get("score") if avant else None,
            "apres": apres.get("score"),
            "note_avant": avant.get("grade") if avant else None,
            "note_apres": apres.get("grade"),
        },
        "alertes": [a.to_dict() for a in alertes],
        "mandat": {
            "atteste_par": watched.get("mandate_actor"),
            "le": watched.get("mandate_at"),
            "reference": watched.get("mandate_reference"),
        },
    }


def format_alert_text(payload: dict[str, Any]) -> str:
    """Rend la notification sous forme de texte, pour le courriel."""
    score = payload["score"]
    lignes = [
        f"DomainExposure — alerte sur {payload['client']} ({payload['domaine']})",
        "",
        f"Score : {score['avant'] if score['avant'] is not None else '—'} "
        f"({score['note_avant'] or '—'}) → {score['apres']} ({score['note_apres']})",
        "",
        "Motifs :",
    ]
    lignes += [f"  - [{a['gravite']}] {a['message']}" for a in payload["alertes"]]
    lignes += [
        "",
        f"Analyse : {payload['analyse_id']}",
        f"Mandat : attesté par {payload['mandat']['atteste_par']} le "
        f"{(payload['mandat']['le'] or '')[:10]}"
        + (f" (réf. {payload['mandat']['reference']})" if payload["mandat"]["reference"] else ""),
        "",
        "Cette analyse est passive : sources ouvertes uniquement.",
    ]
    return "\n".join(lignes)


def next_run(interval_hours: int, depuis: datetime | None = None) -> str | None:
    """Prochaine échéance d'analyse, ou None si le suivi est manuel."""
    if not interval_hours or interval_hours <= 0:
        return None
    base = depuis or datetime.now(UTC)
    return (base + timedelta(hours=interval_hours)).astimezone(UTC).isoformat()


def build_portfolio(
    watched: list[dict[str, Any]], rapports: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    """Vue consolidée du portefeuille, triée du plus exposé au moins exposé.

    `rapports` associe à chaque domaine ses deux dernières analyses, la plus
    récente en premier.
    """
    lignes: list[dict[str, Any]] = []
    for entree in watched:
        historique = rapports.get(entree["domain"]) or []
        dernier = historique[0] if historique else None
        precedent = historique[1] if len(historique) > 1 else None

        comptes = {s.value: 0 for s in Severity}
        if dernier:
            for module in dernier.get("modules") or []:
                for finding in module.get("findings") or []:
                    comptes[finding["severity"]] = comptes.get(finding["severity"], 0) + 1

        score = dernier.get("score") if dernier else None
        score_precedent = precedent.get("score") if precedent else None
        lignes.append(
            {
                "id": entree["id"],
                "domaine": entree["domain"],
                "client": entree.get("label") or entree["domain"],
                "actif": bool(entree.get("active", 1)),
                "intervalle_heures": entree.get("interval_hours"),
                "prochaine_analyse": entree.get("next_run_at"),
                "derniere_analyse": entree.get("last_run_at"),
                "analyse_id": dernier.get("id") if dernier else None,
                "score": score,
                "note": dernier.get("grade") if dernier else None,
                "tendance": (
                    None if score is None or score_precedent is None else score - score_precedent
                ),
                "constats": comptes,
                "mandat": {
                    "atteste_par": entree.get("mandate_actor"),
                    "le": entree.get("mandate_at"),
                    "reference": entree.get("mandate_reference"),
                },
                "notifications": {
                    "webhook": bool(entree.get("notify_webhook")),
                    "courriel": bool(entree.get("notify_email")),
                },
            }
        )

    lignes.sort(key=lambda ligne: (ligne["score"] is None, ligne["score"] or 0, ligne["domaine"]))
    return lignes
