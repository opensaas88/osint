"""Rendu du rapport HTML autonome : aucune ressource externe, aucun script."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import SEVERITY_ORDER, Severity
from ..modules import MODULE_LABELS
from ..remediation import build_plan
from ..scoring import CRITICAL_SCORE_CAP

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

#: Palette de STATUT (réservée aux états), jamais une palette catégorielle.
#: Chaque gravité porte systématiquement un glyphe et un libellé : la couleur ne
#: véhicule jamais seule l'information, ce qui est la contrepartie exigée pour les
#: teintes « warning » et « serious », sous le seuil de 3:1 sur fond clair.
SEVERITY_STYLE: dict[str, dict[str, Any]] = {
    "critique": {"label": "Critique", "color": "#d03b3b", "track": "#f5dfde",
                 "glyph": "◆", "on_light": False},
    "eleve": {"label": "Élevé", "color": "#ec835a", "track": "#faeae3",
              "glyph": "▲", "on_light": True},
    "moyen": {"label": "Moyen", "color": "#fab219", "track": "#fcf1d9",
              "glyph": "●", "on_light": True},
    "faible": {"label": "Faible", "color": "#6b6a64", "track": "#e4e4e0",
               "glyph": "▫", "on_light": False},
    "info": {"label": "Info", "color": "#b4b2ab", "track": "#ececea",
             "glyph": "○", "on_light": True},
}

STATUS_LABELS = {
    "ok": "exploité",
    "partial": "partiellement exploité",
    "skipped": "désactivé",
    "error": "en échec",
}

GRADE_STYLE: dict[str, dict[str, str]] = {
    "A": {"color": "#0ca30c", "track": "#d8efd7", "libelle": "Exposition maîtrisée."},
    "B": {"color": "#0ca30c", "track": "#d8efd7",
          "libelle": "Bonne hygiène d'ensemble, quelques correctifs mineurs."},
    "C": {"color": "#fab219", "track": "#fcf1d9",
          "libelle": "Défauts de configuration à corriger."},
    "D": {"color": "#ec835a", "track": "#faeae3",
          "libelle": "Exposition préoccupante : des actions correctives sont attendues."},
    "E": {"color": "#d03b3b", "track": "#f5dfde",
          "libelle": "Exposition élevée : traitement prioritaire."},
    "F": {"color": "#d03b3b", "track": "#f5dfde",
          "libelle": "Exposition critique : traitement immédiat."},
}


def resume_impact(texte: str, maximum: int = 320) -> str:
    """Accroche d'une explication pour la synthèse destinée à la direction.

    Conserve les premières phrases dans la limite impartie : la première pose le
    fait, la suivante porte généralement la conséquence concrète, qui est ce qui
    parle à un décideur.
    """
    texte = " ".join((texte or "").split())
    if len(texte) <= maximum:
        return texte
    phrases = re.split(r"(?<=[.!?])\s+", texte)
    retenu = ""
    for phrase in phrases:
        if retenu and len(retenu) + len(phrase) + 1 > maximum:
            break
        retenu = f"{retenu} {phrase}".strip()
    if not retenu:
        retenu = texte[: maximum - 1].rstrip()
    return retenu if len(retenu) <= maximum else retenu[: maximum - 1].rstrip() + "…"


def _format_datetime(value: Any) -> str:
    """Formate un horodatage ISO en date lisible, en UTC."""
    if not value:
        return "—"
    if isinstance(value, datetime):
        moment = value
    else:
        try:
            moment = datetime.fromisoformat(str(value))
        except ValueError:
            return str(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%d/%m/%Y %H:%M UTC")


def _format_number(value: Any) -> str:
    """Sépare les milliers par une espace fine insécable."""
    try:
        return f"{int(value):,}".replace(",", " ")
    except (TypeError, ValueError):
        return str(value or "—")


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["dt"] = _format_datetime
    env.filters["nombre"] = _format_number
    return env


def build_context(report: dict[str, Any], settings) -> dict[str, Any]:
    """Prépare toutes les données dérivées dont le gabarit a besoin."""
    modules = report.get("modules") or []

    counts = {severity.value: 0 for severity in Severity}
    for module in modules:
        for finding in module.get("findings") or []:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    total_findings = sum(counts.values())

    # Barre segmentée : une part par gravité présente, largeur proportionnelle.
    segments = []
    for severity in Severity:
        count = counts.get(severity.value, 0)
        if not count:
            continue  # une part à zéro ne dessine rien
        style = SEVERITY_STYLE[severity.value]
        segments.append(
            {
                "label": style["label"],
                "glyph": style["glyph"],
                "color": style["color"],
                "on_light": style["on_light"],
                "count": count,
                "share": round(count / total_findings * 100, 1) if total_findings else 0,
            }
        )

    modules_meter = []
    for module in modules:
        score = module.get("score")
        grade_key = (
            "A" if score is not None and score >= 90
            else "B" if score is not None and score >= 80
            else "C" if score is not None and score >= 70
            else "D" if score is not None and score >= 60
            else "E" if score is not None and score >= 50
            else "F"
        )
        style = GRADE_STYLE[grade_key]
        modules_meter.append(
            {
                "label": module.get("label") or module.get("key"),
                "score": score,
                "weight": module.get("weight") or 0,
                "color": style["color"],
                "track": style["track"],
                "disabled_reason": module.get("disabled_reason"),
            }
        )

    top_findings = sorted(
        (
            finding
            for module in modules
            for finding in module.get("findings") or []
            if finding["severity"] in ("critique", "eleve")
        ),
        key=lambda f: (SEVERITY_ORDER[Severity(f["severity"])], f["module"], f["code"]),
    )

    sources: list[dict[str, Any]] = []
    sources_desactivees: list[dict[str, Any]] = []
    for module in modules:
        label = module.get("label") or module.get("key")
        for source in module.get("sources") or []:
            sources.append({**source, "module": label})
        for item in (module.get("data") or {}).get("sources_desactivees") or []:
            sources_desactivees.append({**item, "module": label})

    by_key = {module.get("key"): module for module in modules}
    breaches_data = (by_key.get("breaches") or {}).get("data") or {}
    exposure_data = (by_key.get("exposure") or {}).get("data") or {}
    subdomains_data = (by_key.get("subdomains") or {}).get("data") or {}

    cve_rows = [
        address
        for address in exposure_data.get("adresses") or []
        if address.get("vulns")
    ]
    subdomain_rows = (subdomains_data.get("records") or [])[:80]

    # Plan de remédiation : ce que coûte la correction et ce qu'elle rapporte.
    plan = build_plan(modules, limite=8)
    plan_prioritaire = plan["etapes"][:3]
    projection_courte = (
        plan_prioritaire[-1]["score_cumule"] if plan_prioritaire else report.get("score")
    )
    projection_courte_note = (
        plan_prioritaire[-1]["grade_cumule"] if plan_prioritaire else report.get("grade")
    )

    # Les trois risques à retenir, dans l'ordre de gravité.
    risques_majeurs = [
        {
            "severity": finding["severity"],
            "title": finding["title"],
            "impact": resume_impact(finding.get("explication", "")),
            "module": MODULE_LABELS.get(finding["module"], finding["module"]),
        }
        for finding in top_findings[:3]
    ]
    if len(risques_majeurs) < 3:
        complement = sorted(
            (
                f
                for m in modules
                for f in m.get("findings") or []
                if f["severity"] in ("moyen", "faible")
            ),
            key=lambda f: (SEVERITY_ORDER[Severity(f["severity"])], f["code"]),
        )
        for finding in complement[: 3 - len(risques_majeurs)]:
            risques_majeurs.append(
                {
                    "severity": finding["severity"],
                    "title": finding["title"],
                    "impact": resume_impact(finding.get("explication", "")),
                    "module": MODULE_LABELS.get(finding["module"], finding["module"]),
                }
            )

    score = report.get("score")
    grade = report.get("grade") or (
        "F" if score is not None and score < 50 else "—"
    )
    score_style = GRADE_STYLE.get(grade, GRADE_STYLE["F"])

    return {
        "report": report,
        "counts": counts,
        "total_findings": total_findings,
        "segments": segments,
        "modules_meter": modules_meter,
        "modules_actifs": sum(
            1 for module in modules if module.get("status") in ("ok", "partial")
        ),
        "top_findings": top_findings,
        "sources": sources,
        "sources_desactivees": sources_desactivees,
        "timeline": breaches_data.get("chronologie") or [],
        "cve_rows": cve_rows,
        "subdomain_rows": subdomain_rows,
        "subdomain_truncated": bool(subdomains_data.get("truncated")),
        "severities": SEVERITY_STYLE,
        "statuts": STATUS_LABELS,
        "module_labels": MODULE_LABELS,
        "plan": plan,
        "plan_prioritaire": plan_prioritaire,
        "projection_courte": projection_courte,
        "projection_courte_note": projection_courte_note,
        "risques_majeurs": risques_majeurs,
        "score_style": score_style,
        "plafond_critique": CRITICAL_SCORE_CAP,
        "cache_heures": settings.cache_ttl_hours,
        "audit_jours": settings.audit_retention_days,
        "cles_api": settings.api_key_inventory(),
        "generated_at": _format_datetime(datetime.now(UTC)),
    }


def render_html(report: dict[str, Any], settings) -> str:
    """Rend le rapport complet dans un fichier HTML autonome."""
    env = _environment()
    css = (TEMPLATE_DIR / "report.css").read_text(encoding="utf-8")
    template = env.get_template("report.html.j2")
    return template.render(css=css, **build_context(report, settings))
