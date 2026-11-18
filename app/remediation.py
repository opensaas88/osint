"""Plan de remédiation : effort estimé, gain de score et projection.

Ce module répond à la question qui décide d'un budget : « qu'est-ce que ça change
si on corrige ? ». Il ne détecte rien ; il réordonne ce que les modules ont déjà
constaté, chiffre le gain de chaque correction sur le score global et projette la
note atteignable.

L'effort est un paramètre de planification, pas de détection : il est centralisé
ici pour qu'un prestataire puisse l'ajuster à son contexte sans toucher aux
modules d'analyse.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .models import SEVERITY_ORDER, Severity
from .scoring import compute_global_score, module_score


class Effort(StrEnum):
    """Charge de travail estimée pour corriger un constat."""

    RAPIDE = "rapide"
    MODERE = "modere"
    IMPORTANT = "important"


EFFORT_LABEL: dict[Effort, str] = {
    Effort.RAPIDE: "moins d'une heure",
    Effort.MODERE: "une demi-journée",
    Effort.IMPORTANT: "plusieurs jours",
}

EFFORT_ORDER: dict[Effort, int] = {Effort.RAPIDE: 0, Effort.MODERE: 1, Effort.IMPORTANT: 2}

#: Effort par code de constat. Les corrections « rapides » sont des modifications de
#: configuration (un enregistrement DNS, un en-tête HTTP) ; les « modérées »
#: demandent une coordination avec un prestataire ou un déploiement ; les
#: « importantes » sont des chantiers avec des dépendances.
EFFORT_BY_CODE: dict[str, Effort] = {
    # --- Messagerie : presque tout se joue sur des enregistrements DNS ---
    "EMAIL_SPF_MISSING": Effort.RAPIDE,
    "EMAIL_SPF_MULTIPLE": Effort.RAPIDE,
    "EMAIL_SPF_ALLOW_ALL": Effort.RAPIDE,
    "EMAIL_SPF_NEUTRAL": Effort.RAPIDE,
    "EMAIL_SPF_NO_ALL": Effort.RAPIDE,
    "EMAIL_SPF_PTR": Effort.RAPIDE,
    "EMAIL_SPF_SOFTFAIL": Effort.MODERE,  # exige de valider tous les flux d'envoi
    "EMAIL_SPF_TOO_MANY_LOOKUPS": Effort.MODERE,
    "EMAIL_SPF_LOOKUPS_NEAR_LIMIT": Effort.MODERE,
    "EMAIL_DMARC_MISSING": Effort.RAPIDE,
    "EMAIL_DMARC_MULTIPLE": Effort.RAPIDE,
    "EMAIL_DMARC_NO_RUA": Effort.RAPIDE,
    "EMAIL_DMARC_POLICY_INVALID": Effort.RAPIDE,
    "EMAIL_DMARC_PARTIAL_PCT": Effort.RAPIDE,
    "EMAIL_DMARC_POLICY_NONE": Effort.MODERE,  # durcir demande d'analyser les rapports
    "EMAIL_DMARC_POLICY_QUARANTINE": Effort.MODERE,
    "EMAIL_DKIM_NOT_FOUND": Effort.MODERE,
    "EMAIL_MX_MISSING": Effort.RAPIDE,
    "EMAIL_TLSRPT_MISSING": Effort.RAPIDE,
    "EMAIL_MTA_STS_MISSING": Effort.MODERE,
    "EMAIL_MTA_STS_TESTING": Effort.RAPIDE,
    "EMAIL_MTA_STS_POLICY_UNREACHABLE": Effort.MODERE,
    # --- DNS ---
    "DNS_CAA_MISSING": Effort.RAPIDE,
    "DNS_SUBDOMAIN_TAKEOVER_RISK": Effort.RAPIDE,  # supprimer l'enregistrement orphelin
    "DNS_DOMAIN_EXPIRED": Effort.RAPIDE,
    "DNS_DOMAIN_EXPIRING": Effort.RAPIDE,
    "DNS_DOMAIN_EXPIRING_SOON": Effort.RAPIDE,
    "DNS_DOMAIN_NO_LOCK": Effort.RAPIDE,
    "DNS_DNSSEC_MISSING": Effort.MODERE,
    "DNS_DNSSEC_INCOMPLETE": Effort.MODERE,
    "DNS_DNSSEC_UNVALIDATED": Effort.MODERE,
    "DNS_SINGLE_NS": Effort.MODERE,
    "DNS_NS_SINGLE_PROVIDER": Effort.IMPORTANT,  # second opérateur DNS à contractualiser
    # --- TLS et en-têtes : des lignes de configuration serveur ---
    "HTTP_HSTS_MISSING": Effort.RAPIDE,
    "HTTP_HSTS_SHORT": Effort.RAPIDE,
    "HTTP_HSTS_NO_SUBDOMAINS": Effort.MODERE,
    "HTTP_NOSNIFF_MISSING": Effort.RAPIDE,
    "HTTP_REFERRER_POLICY_MISSING": Effort.RAPIDE,
    "HTTP_PERMISSIONS_POLICY_MISSING": Effort.RAPIDE,
    "HTTP_VERSION_DISCLOSURE": Effort.RAPIDE,
    "HTTP_XFO_MISSING": Effort.RAPIDE,
    "HTTP_NO_REDIRECT": Effort.RAPIDE,
    "HTTP_REDIRECT_TEMPORARY": Effort.RAPIDE,
    "HTTP_COOKIE_NOT_SECURE": Effort.MODERE,
    "HTTP_COOKIE_NOT_HTTPONLY": Effort.MODERE,
    "HTTP_COOKIE_NO_SAMESITE": Effort.MODERE,
    "HTTP_CSP_MISSING": Effort.IMPORTANT,  # inventaire des ressources de chaque page
    "HTTP_CSP_UNSAFE": Effort.IMPORTANT,
    "TLS_CERT_EXPIRED": Effort.RAPIDE,
    "TLS_CERT_EXPIRING_SOON": Effort.RAPIDE,
    "TLS_CERT_EXPIRY_WARNING": Effort.RAPIDE,
    "TLS_CERT_SELF_SIGNED": Effort.RAPIDE,
    "TLS_CERT_NOT_TRUSTED": Effort.MODERE,
    "TLS_CERT_HOSTNAME_MISMATCH": Effort.MODERE,
    "TLS_WEAK_KEY": Effort.MODERE,
    "TLS_WEAK_SIGNATURE": Effort.MODERE,
    "TLS_OBSOLETE_VERSION": Effort.MODERE,
    # --- Surface exposée ---
    "EXPOSURE_CRITICAL_PORTS": Effort.MODERE,  # fermeture au pare-feu, à coordonner
    "EXPOSURE_SENSITIVE_PORTS": Effort.MODERE,
    "EXPOSURE_KNOWN_CVE": Effort.IMPORTANT,
    # --- Sous-domaines ---
    "SUBDOMAIN_DANGLING": Effort.RAPIDE,
    "SUBDOMAIN_CERT_EXPIRING": Effort.RAPIDE,
    "SUBDOMAIN_SENSITIVE_NAMES": Effort.IMPORTANT,
    # --- Fuites, rançongiciel, réputation : réponse à incident ---
    "BREACH_DOMAIN_ACCOUNTS": Effort.MODERE,
    "BREACH_LEAKCHECK": Effort.MODERE,
    "BREACH_INTELX": Effort.MODERE,
    "BREACH_STEALER_LOG_STAFF": Effort.IMPORTANT,
    "BREACH_STEALER_LOG_CUSTOMERS": Effort.IMPORTANT,
    "RANSOMWARE_CLAIMED_VICTIM": Effort.IMPORTANT,
    "RANSOMWARE_POSSIBLE_HOMONYM": Effort.RAPIDE,  # lever le doute, pas corriger
    "REPUTATION_VT_FLAGGED": Effort.IMPORTANT,
    "REPUTATION_URLHAUS_MALWARE": Effort.IMPORTANT,
    "REPUTATION_ABUSEIPDB_FLAGGED": Effort.MODERE,
    # --- Typosquatting : surveillance et signalement ---
    "TYPO_MAIL_CAPABLE": Effort.MODERE,
    "TYPO_REGISTERED_BY_THIRD_PARTY": Effort.MODERE,
}

#: Effort retenu lorsqu'un code n'est pas répertorié ci-dessus.
DEFAULT_EFFORT = Effort.MODERE


def estimate_effort(code: str) -> Effort:
    """Effort estimé pour corriger un constat, à partir de son code."""
    return EFFORT_BY_CODE.get(code, DEFAULT_EFFORT)


@dataclass(slots=True)
class Step:
    """Une action de remédiation et son effet sur le score."""

    code: str
    module: str
    module_label: str
    title: str
    severity: Severity
    recommandation: str
    effort: Effort
    gain: int  # points gagnés si ce constat était le seul corrigé
    gain_marginal: int  # points réellement apportés par cette étape, dans l'ordre du plan
    score_cumule: int  # score atteint en corrigeant cette action et les précédentes
    grade_cumule: str

    @property
    def effort_label(self) -> str:
        return EFFORT_LABEL[self.effort]


def _recompute(modules: list[dict[str, Any]], corriges: set[str]):
    """Recalcule le score global en considérant les constats `corriges` comme résolus."""
    from .models import Finding, ModuleResult

    repliques: list[ModuleResult] = []
    for module in modules:
        findings = [
            Finding.model_validate(f)
            for f in (module.get("findings") or [])
            if f["code"] not in corriges
        ]
        score = module.get("score")
        repliques.append(
            ModuleResult(
                key=module["key"],
                label=module.get("label") or module["key"],
                status=module.get("status", "ok"),
                score=module_score(findings) if score is not None else None,
                weight=module.get("weight") or 0,
                findings=findings,
            )
        )
    return compute_global_score(repliques)


def actionable_findings(modules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Constats sur lesquels une action est possible : tout sauf les informations."""
    return [
        finding
        for module in modules
        for finding in (module.get("findings") or [])
        if finding["severity"] != Severity.INFO.value
    ]


def build_plan(modules: list[dict[str, Any]], limite: int | None = None) -> dict[str, Any]:
    """Construit le plan de remédiation trié par rapport gain / effort.

    Retourne le score actuel, les étapes ordonnées avec leur gain propre et le
    score cumulé atteint à chaque étape, puis le score projeté si tout est corrigé.
    """
    score_actuel, note_actuelle, _ = compute_global_score(
        [_as_result(m) for m in modules]
    )
    labels = {m["key"]: (m.get("label") or m["key"]) for m in modules}
    candidats = actionable_findings(modules)

    if score_actuel is None or not candidats:
        return {
            "score_actuel": score_actuel,
            "note_actuelle": note_actuelle,
            "etapes": [],
            "score_projete": score_actuel,
            "note_projetee": note_actuelle,
            "gain_total": 0,
            "corrections_rapides": [],
        }

    # Gain propre de chaque correction, prise isolément.
    gains: list[tuple[dict[str, Any], int]] = []
    for finding in candidats:
        score_apres, _, _ = _recompute(modules, {finding["code"]})
        gains.append((finding, max(0, (score_apres or 0) - score_actuel)))

    # Tri : gain décroissant, puis effort croissant, puis gravité.
    gains.sort(
        key=lambda item: (
            -item[1],
            EFFORT_ORDER[estimate_effort(item[0]["code"])],
            SEVERITY_ORDER[Severity(item[0]["severity"])],
        )
    )

    etapes: list[Step] = []
    corriges: set[str] = set()
    precedent = score_actuel
    for finding, gain in gains:
        corriges.add(finding["code"])
        cumule, note_cumulee, _ = _recompute(modules, corriges)
        cumule = cumule if cumule is not None else precedent
        etapes.append(
            Step(
                code=finding["code"],
                module=finding["module"],
                module_label=labels.get(finding["module"], finding["module"]),
                title=finding["title"],
                severity=Severity(finding["severity"]),
                recommandation=finding["recommandation"],
                effort=estimate_effort(finding["code"]),
                gain=gain,
                gain_marginal=cumule - precedent,
                score_cumule=cumule,
                grade_cumule=note_cumulee or (note_actuelle or "—"),
            )
        )
        precedent = cumule

    score_projete, note_projetee, _ = _recompute(modules, {e.code for e in etapes})
    retenues = etapes if limite is None else etapes[:limite]

    return {
        "score_actuel": score_actuel,
        "note_actuelle": note_actuelle,
        "etapes": [_step_dict(e) for e in retenues],
        "etapes_totales": len(etapes),
        "score_projete": score_projete,
        "note_projetee": note_projetee,
        "gain_total": (score_projete or score_actuel) - score_actuel,
        "corrections_rapides": [
            _step_dict(e)
            for e in etapes
            if e.effort is Effort.RAPIDE and (e.gain > 0 or e.gain_marginal > 0)
        ][:5],
    }


def simulate(modules: list[dict[str, Any]], codes: list[str]) -> dict[str, Any]:
    """Score et note obtenus si les constats `codes` étaient corrigés."""
    score_actuel, note_actuelle, _ = compute_global_score([_as_result(m) for m in modules])
    score, note, plafonne = _recompute(modules, set(codes))
    return {
        "codes": codes,
        "score_actuel": score_actuel,
        "note_actuelle": note_actuelle,
        "score_projete": score,
        "note_projetee": note,
        "gain": (score or 0) - (score_actuel or 0),
        "plafonne_par_un_critique": plafonne,
    }


def _as_result(module: dict[str, Any]):
    from .models import ModuleResult

    return ModuleResult.model_validate(module)


def _step_dict(step: Step) -> dict[str, Any]:
    return {
        "code": step.code,
        "module": step.module,
        "module_label": step.module_label,
        "title": step.title,
        "severity": step.severity.value,
        "recommandation": step.recommandation,
        "effort": step.effort.value,
        "effort_label": step.effort_label,
        "gain": step.gain,
        "gain_marginal": step.gain_marginal,
        "score_cumule": step.score_cumule,
        "grade_cumule": step.grade_cumule,
    }
