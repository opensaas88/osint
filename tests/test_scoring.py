"""Calcul des scores par module et du score global pondéré."""

import pytest

from app.models import Finding, ModuleResult, ModuleStatus, Severity
from app.scoring import (
    CRITICAL_SCORE_CAP,
    MODULE_WEIGHTS,
    compute_global_score,
    grade_for,
    module_score,
)


def finding(severity: Severity, code: str = "X") -> Finding:
    return Finding(
        code=code, module="m", severity=severity, title="t",
        constat="c", explication="e", recommandation="r",
    )


def module(key: str, score: int | None, status=ModuleStatus.OK, findings=None) -> ModuleResult:
    return ModuleResult(
        key=key, label=key, status=status, score=score,
        weight=MODULE_WEIGHTS.get(key, 0), findings=findings or [],
    )


def test_les_poids_totalisent_cent():
    assert sum(MODULE_WEIGHTS.values()) == 100


@pytest.mark.parametrize(
    ("severites", "attendu"),
    [
        ([], 100),
        ([Severity.INFO], 100),
        ([Severity.FAIBLE], 96),
        ([Severity.MOYEN], 90),
        ([Severity.ELEVE], 75),
        ([Severity.CRITIQUE], 60),
        ([Severity.CRITIQUE] * 3, 0),  # borné à zéro
    ],
)
def test_score_de_module(severites, attendu):
    assert module_score([finding(s, f"C{i}") for i, s in enumerate(severites)]) == attendu


@pytest.mark.parametrize(
    ("score", "note"),
    [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (70, "C"), (60, "D"), (50, "E"), (49, "F"), (0, "F")],
)
def test_bareme(score, note):
    assert grade_for(score) == note


def test_moyenne_ponderee():
    modules = [module("email", 50), module("dns", 100)]  # poids 20 et 10
    score, note, plafonne = compute_global_score(modules)
    assert score == round((50 * 20 + 100 * 10) / 30)
    assert note == grade_for(score)
    assert plafonne is False


def test_un_module_desactive_est_exclu_du_denominateur():
    actifs = [module("email", 50)]
    avec_desactive = [
        module("email", 50),
        module("reputation", None, status=ModuleStatus.SKIPPED),
        module("tls", None, status=ModuleStatus.ERROR),
    ]
    assert compute_global_score(actifs)[0] == compute_global_score(avec_desactive)[0]


def test_un_constat_critique_plafonne_la_note():
    modules = [
        module("email", 95, findings=[finding(Severity.CRITIQUE)]),
        module("dns", 100),
    ]
    score, note, plafonne = compute_global_score(modules)
    assert score == CRITICAL_SCORE_CAP
    assert note == "D"
    assert plafonne is True


def test_aucun_module_actif_donne_un_score_indetermine():
    assert compute_global_score([module("email", None, status=ModuleStatus.SKIPPED)]) == (
        None, None, False
    )
