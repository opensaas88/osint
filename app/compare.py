"""Comparaison de deux analyses du même domaine, pour mesurer l'évolution."""

from __future__ import annotations

from typing import Any

from .models import SEVERITY_ORDER, Severity


def _findings_by_code(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for module in report.get("modules") or []:
        for finding in module.get("findings") or []:
            index[finding["code"]] = finding
    return index


def _modules_by_key(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {m["key"]: m for m in report.get("modules") or []}


def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Diff structuré entre deux rapports : score, modules, findings apparus/résolus."""
    before_findings = _findings_by_code(before)
    after_findings = _findings_by_code(after)

    apparus = [after_findings[c] for c in after_findings.keys() - before_findings.keys()]
    resolus = [before_findings[c] for c in before_findings.keys() - after_findings.keys()]
    persistants = [after_findings[c] for c in after_findings.keys() & before_findings.keys()]

    for collection in (apparus, resolus, persistants):
        collection.sort(key=lambda f: (SEVERITY_ORDER[Severity(f["severity"])], f["code"]))

    before_modules = _modules_by_key(before)
    after_modules = _modules_by_key(after)
    modules = []
    for key in sorted(before_modules.keys() | after_modules.keys()):
        avant = before_modules.get(key, {})
        apres = after_modules.get(key, {})
        score_avant, score_apres = avant.get("score"), apres.get("score")
        modules.append(
            {
                "key": key,
                "label": apres.get("label") or avant.get("label") or key,
                "score_avant": score_avant,
                "score_apres": score_apres,
                "delta": (
                    score_apres - score_avant
                    if score_avant is not None and score_apres is not None
                    else None
                ),
                "statut_avant": avant.get("status"),
                "statut_apres": apres.get("status"),
            }
        )

    score_avant, score_apres = before.get("score"), after.get("score")
    return {
        "domaine": after.get("domain") or before.get("domain"),
        "avant": {
            "id": before.get("id"),
            "date": before.get("started_at"),
            "score": score_avant,
            "note": before.get("grade"),
        },
        "apres": {
            "id": after.get("id"),
            "date": after.get("started_at"),
            "score": score_apres,
            "note": after.get("grade"),
        },
        "delta_score": (
            score_apres - score_avant
            if score_avant is not None and score_apres is not None
            else None
        ),
        "modules": modules,
        "findings_apparus": apparus,
        "findings_resolus": resolus,
        "findings_persistants": persistants,
        "resume": {
            "apparus": len(apparus),
            "resolus": len(resolus),
            "persistants": len(persistants),
        },
    }
