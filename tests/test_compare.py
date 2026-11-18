"""Comparaison de deux analyses du même domaine."""

from app.compare import compare_reports


def rapport(identifiant, date, score, note, findings, module_score):
    return {
        "id": identifiant, "domain": "exemple.fr", "started_at": date,
        "score": score, "grade": note,
        "modules": [{
            "key": "email", "label": "Hygiène email", "score": module_score, "status": "ok",
            "findings": [{"code": c, "severity": s, "module": "email", "title": c}
                         for c, s in findings],
        }],
    }


def test_evolution_entre_deux_analyses():
    avant = rapport("a", "2026-01-01", 50, "E",
                    [("SPF_MANQUANT", "eleve"), ("DMARC_NONE", "moyen")], 40)
    apres = rapport("b", "2026-02-01", 80, "B",
                    [("DMARC_NONE", "moyen"), ("CAA_ABSENT", "faible")], 86)

    diff = compare_reports(avant, apres)
    assert diff["delta_score"] == 30
    assert diff["resume"] == {"apparus": 1, "resolus": 1, "persistants": 1}
    assert diff["findings_apparus"][0]["code"] == "CAA_ABSENT"
    assert diff["findings_resolus"][0]["code"] == "SPF_MANQUANT"
    assert diff["modules"][0]["delta"] == 46


def test_tri_par_gravite_des_constats_apparus():
    avant = rapport("a", "2026-01-01", 90, "A", [], 100)
    apres = rapport("b", "2026-02-01", 40, "F",
                    [("B", "faible"), ("A", "critique"), ("C", "moyen")], 20)
    codes = [f["code"] for f in compare_reports(avant, apres)["findings_apparus"]]
    assert codes == ["A", "C", "B"]


def test_module_apparu_ou_disparu():
    avant = rapport("a", "2026-01-01", 50, "E", [], 50)
    apres = rapport("b", "2026-02-01", 50, "E", [], None)
    apres["modules"].append({"key": "tls", "label": "TLS", "score": 70, "status": "ok",
                             "findings": []})
    modules = {m["key"]: m for m in compare_reports(avant, apres)["modules"]}
    assert modules["email"]["delta"] is None  # score devenu indisponible
    assert modules["tls"]["score_avant"] is None and modules["tls"]["score_apres"] == 70
