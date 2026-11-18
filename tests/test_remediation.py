"""Plan de remédiation : effort, gain et projection de score."""

import pytest

from app.remediation import (
    DEFAULT_EFFORT,
    EFFORT_BY_CODE,
    Effort,
    actionable_findings,
    build_plan,
    estimate_effort,
    simulate,
)


def finding(code, severity, module="email", titre=None):
    return {
        "code": code, "module": module, "severity": severity,
        "title": titre or code, "constat": "c", "explication": "e",
        "recommandation": f"corriger {code}", "references": [], "evidence": {},
    }


def module(key, score, weight, findings, label=None, status="ok"):
    return {
        "key": key, "label": label or key, "status": status, "score": score,
        "weight": weight, "findings": findings, "sources": [], "errors": [],
        "disabled_reason": None, "duration_ms": 0, "data": {},
    }


@pytest.fixture
def modules():
    """Score 57/E : un critique et un élevé sur la messagerie, le DNS est sain.

    (35 × 20 + 100 × 10) / 30 = 56,7 → 57 ; le plafond critique (69) ne mord pas.
    """
    return [
        module("email", 35, 20, [
            finding("EMAIL_SPF_MULTIPLE", "critique", titre="Deux SPF"),
            finding("EMAIL_DMARC_MISSING", "eleve", titre="Pas de DMARC"),
            finding("EMAIL_DKIM_PRESENT", "info", titre="DKIM présent"),
        ]),
        module("dns", 100, 10, [], label="Hygiène DNS", status="ok"),
    ]


def test_effort_connu_et_defaut():
    assert estimate_effort("EMAIL_SPF_MULTIPLE") is Effort.RAPIDE
    assert estimate_effort("HTTP_CSP_MISSING") is Effort.IMPORTANT
    assert estimate_effort("CODE_INEXISTANT") is DEFAULT_EFFORT


def test_la_table_deffort_ne_contient_que_des_codes_plausibles():
    for code, effort in EFFORT_BY_CODE.items():
        assert code.isupper() and "_" in code, code
        assert isinstance(effort, Effort)


def test_les_constats_informatifs_sont_exclus_du_plan(modules):
    codes = {f["code"] for f in actionable_findings(modules)}
    assert codes == {"EMAIL_SPF_MULTIPLE", "EMAIL_DMARC_MISSING"}


def test_le_plan_ordonne_par_gain_puis_effort(modules):
    plan = build_plan(modules)
    assert [e["code"] for e in plan["etapes"]] == ["EMAIL_SPF_MULTIPLE", "EMAIL_DMARC_MISSING"]
    assert plan["score_actuel"] == 57
    assert plan["note_actuelle"] == "E"
    assert plan["score_projete"] == 100
    assert plan["note_projetee"] == "A"
    assert plan["gain_total"] == 43


def test_le_gain_marginal_explique_la_progression(modules):
    """Le gain isolé peut masquer l'effet du plafonnement : le marginal le révèle."""
    plan = build_plan(modules)
    etapes = plan["etapes"]
    assert sum(e["gain_marginal"] for e in etapes) == plan["gain_total"]
    assert etapes[0]["score_cumule"] == plan["score_actuel"] + etapes[0]["gain_marginal"]
    assert etapes[-1]["score_cumule"] == plan["score_projete"]


def test_lever_le_constat_critique_deplafonne_la_note(modules):
    """Corriger le seul critique fait sauter le plafond à 69 : c'est le plus gros gain."""
    avant = build_plan(modules)["score_actuel"]
    apres = simulate(modules, ["EMAIL_SPF_MULTIPLE"])
    assert avant == 57
    assert apres["score_projete"] > 69  # le plafond ne s'applique plus
    assert apres["plafonne_par_un_critique"] is False


def test_simulation_ciblee(modules):
    resultat = simulate(modules, ["EMAIL_DMARC_MISSING"])
    assert resultat["score_actuel"] == 57
    assert resultat["gain"] > 0
    # Le critique subsiste : la note reste plafonnée.
    assert resultat["plafonne_par_un_critique"] is True
    assert resultat["score_projete"] <= 69


def test_corrections_rapides_mises_en_avant(modules):
    rapides = build_plan(modules)["corrections_rapides"]
    assert rapides and all(e["effort"] == "rapide" for e in rapides)
    assert rapides[0]["effort_label"] == "moins d'une heure"


def test_plan_limite(modules):
    plan = build_plan(modules, limite=1)
    assert len(plan["etapes"]) == 1
    assert plan["etapes_totales"] == 2
    # La projection porte sur le plan complet, pas sur les seules étapes affichées.
    assert plan["score_projete"] == 100


def test_aucune_action_possible():
    sains = [module("dns", 100, 10, [finding("DNS_CAA_PRESENT", "info")])]
    plan = build_plan(sains)
    assert plan["etapes"] == []
    assert plan["gain_total"] == 0
    assert plan["score_projete"] == plan["score_actuel"] == 100


def test_module_desactive_ignore():
    modules = [
        module("email", 60, 20, [finding("EMAIL_DMARC_MISSING", "eleve")]),
        module("reputation", None, 5, [], status="skipped"),
    ]
    plan = build_plan(modules)
    assert plan["score_actuel"] == 60
    assert plan["etapes"][0]["code"] == "EMAIL_DMARC_MISSING"
