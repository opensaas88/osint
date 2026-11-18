"""Portefeuille surveillé : détection de régression et vue consolidée."""

import pytest

from app.watchlist import (
    DEFAULT_SCORE_DROP,
    build_alert_payload,
    build_portfolio,
    detect_regression,
    format_alert_text,
    next_run,
)


def rapport(score, note, constats, identifiant="r1", domaine="exemple.fr"):
    return {
        "id": identifiant, "domain": domaine, "score": score, "grade": note,
        "started_at": "2026-02-01T10:00:00+00:00", "finished_at": "2026-02-01T10:01:00+00:00",
        "modules": [{
            "key": "email", "label": "Hygiène email",
            "findings": [
                {"code": c, "severity": s, "title": f"Constat {c}", "module": "email"}
                for c, s in constats
            ],
        }],
    }


def test_premiere_analyse_sans_critique_nalerte_pas():
    assert detect_regression(None, rapport(85, "B", [("A", "moyen")])) == []


def test_premiere_analyse_avec_critique_alerte():
    alertes = detect_regression(None, rapport(40, "F", [("A", "critique")]))
    assert [a.type for a in alertes] == ["premiere_analyse_critique"]
    assert alertes[0].gravite == "critique"


def test_baisse_de_score_detectee():
    avant, apres = rapport(90, "A", []), rapport(80, "B", [])
    types = [a.type for a in detect_regression(avant, apres)]
    assert "score_baisse" in types
    assert "note_degradee" in types


def test_baisse_sous_le_seuil_ignoree():
    avant, apres = rapport(90, "A", []), rapport(88, "A", [])
    assert detect_regression(avant, apres, seuil=DEFAULT_SCORE_DROP) == []


def test_amelioration_nest_pas_une_alerte():
    avant, apres = rapport(60, "D", [("A", "eleve")]), rapport(95, "A", [])
    assert detect_regression(avant, apres) == []


def test_nouveau_constat_grave_detecte_meme_sans_baisse_de_score():
    """Un nouveau constat critique doit alerter même si le score global ne bouge pas."""
    avant = rapport(69, "D", [("VIEUX", "critique")])
    apres = rapport(69, "D", [("VIEUX", "critique"), ("NOUVEAU", "critique")])
    alertes = detect_regression(avant, apres)
    assert [a.type for a in alertes] == ["nouveau_constat_critique"]
    assert alertes[0].detail["codes"] == ["NOUVEAU"]


def test_les_alertes_sont_triees_par_gravite():
    avant = rapport(90, "A", [])
    apres = rapport(50, "E", [("C", "critique"), ("E", "eleve")])
    gravites = [a.gravite for a in detect_regression(avant, apres)]
    assert gravites[0] == "critique"


def test_constat_resolu_nalerte_pas():
    avant = rapport(60, "D", [("A", "critique")])
    apres = rapport(100, "A", [])
    assert detect_regression(avant, apres) == []


def test_corps_de_notification_et_rendu_texte():
    suivi = {
        "label": "Client A", "mandate_actor": "operateur",
        "mandate_at": "2026-01-15T09:00:00+00:00", "mandate_reference": "contrat 42",
    }
    avant, apres = rapport(90, "A", []), rapport(70, "C", [("X", "critique")])
    alertes = detect_regression(avant, apres)
    payload = build_alert_payload(suivi, avant, apres, alertes)

    assert payload["client"] == "Client A"
    assert payload["score"] == {"avant": 90, "apres": 70, "note_avant": "A", "note_apres": "C"}
    assert payload["mandat"]["reference"] == "contrat 42"

    texte = format_alert_text(payload)
    assert "Client A" in texte and "90" in texte and "70" in texte
    assert "contrat 42" in texte
    assert "passive" in texte  # le rappel du périmètre accompagne chaque alerte


@pytest.mark.parametrize(("heures", "attendu"), [(0, None), (-5, None)])
def test_suivi_manuel_na_pas_decheance(heures, attendu):
    assert next_run(heures) is attendu


def test_echeance_calculee():
    assert next_run(24) is not None


def test_portefeuille_trie_du_plus_expose_au_moins_expose():
    suivis = [
        {"id": "1", "domain": "bon.fr", "label": "Bon", "active": 1, "interval_hours": 168},
        {"id": "2", "domain": "mauvais.fr", "label": "Mauvais", "active": 1,
         "interval_hours": 24},
        {"id": "3", "domain": "neuf.fr", "label": "Neuf", "active": 1, "interval_hours": 0},
    ]
    rapports = {
        "bon.fr": [rapport(95, "A", [], domaine="bon.fr")],
        "mauvais.fr": [
            rapport(40, "F", [("X", "critique")], "r2", "mauvais.fr"),
            rapport(60, "D", [], "r1", "mauvais.fr"),
        ],
        "neuf.fr": [],
    }
    lignes = build_portfolio(suivis, rapports)

    assert [ligne["domaine"] for ligne in lignes] == ["mauvais.fr", "bon.fr", "neuf.fr"]
    assert lignes[0]["tendance"] == -20  # 60 → 40
    assert lignes[0]["constats"]["critique"] == 1
    assert lignes[1]["tendance"] is None  # une seule analyse
    assert lignes[2]["score"] is None  # jamais analysé
