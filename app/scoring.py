"""Calcul des scores : par module, puis score global pondere et note de A a F.

La formule est documentee dans SCORING.md.
"""

from __future__ import annotations

from .models import Finding, ModuleResult, ModuleStatus, Severity

#: Score minimal et maximal d'un module.
MIN_SCORE, MAX_SCORE = 0, 100

#: Un finding critique plafonne la note globale a ce score (soit la note D au mieux).
CRITICAL_SCORE_CAP = 69

#: Bareme de la note finale : (score minimal, note).
GRADE_SCALE: tuple[tuple[int, str], ...] = (
    (90, "A"), (80, "B"), (70, "C"), (60, "D"), (50, "E"), (0, "F")
)

#: Poids de chaque module dans le score global (somme = 100).
MODULE_WEIGHTS: dict[str, int] = {
    "email": 20,
    "exposure": 15,
    "tls": 15,
    "breaches": 15,
    "ransomware": 10,
    "dns": 10,
    "subdomains": 5,
    "typosquatting": 5,
    "reputation": 5,
}


def module_score(findings: list[Finding]) -> int:
    """Score d'un module : 100 moins la somme des penalites, borne a [0, 100]."""
    penalty = sum(f.penalty for f in findings)
    return max(MIN_SCORE, min(MAX_SCORE, MAX_SCORE - penalty))


def grade_for(score: int) -> str:
    """Note de A a F correspondant a un score."""
    for threshold, grade in GRADE_SCALE:
        if score >= threshold:
            return grade
    return "F"


def is_active(module: ModuleResult) -> bool:
    """Un module compte dans le score global s'il a produit un resultat exploitable."""
    return module.status in (ModuleStatus.OK, ModuleStatus.PARTIAL) and module.score is not None


def compute_global_score(modules: list[ModuleResult]) -> tuple[int | None, str | None, bool]:
    """Score global pondere, renormalise sur les seuls modules actifs.

    Retourne `(score, note, plafonne_par_un_critique)`. Un module desactive (cle
    absente) n'est ni penalisant ni avantageux : il quitte le numerateur et le
    denominateur.
    """
    active = [m for m in modules if is_active(m)]
    if not active:
        return None, None, False

    total_weight = sum(m.weight for m in active)
    if total_weight <= 0:
        return None, None, False

    weighted = sum((m.score or 0) * m.weight for m in active)
    score = round(weighted / total_weight)

    has_critical = any(f.severity is Severity.CRITIQUE for m in modules for f in m.findings)
    capped = has_critical and score > CRITICAL_SCORE_CAP
    if capped:
        score = CRITICAL_SCORE_CAP

    return score, grade_for(score), capped
