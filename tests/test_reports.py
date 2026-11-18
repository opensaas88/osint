"""Rendu des rapports : HTML autonome et PDF."""

import pytest

from app.report.html import SEVERITY_STYLE, build_context, render_html
from app.report.pdf import PdfUnavailable, pdf_available, render_pdf


@pytest.fixture
def rapport() -> dict:
    return {
        "id": "abc", "domain": "exemple.fr", "domain_unicode": "exemple.fr",
        "status": "done", "started_at": "2026-02-01T10:00:00+00:00",
        "finished_at": "2026-02-01T10:01:00+00:00", "score": 64, "grade": "D",
        "score_capped_by_critical": True, "actor": "pytest", "app_version": "1.0.0",
        "dns_backend": "doh", "notes": [],
        "consents": {"authorization": True, "passive_only": True, "domain_verified": False},
        "modules": [
            {
                "key": "email", "label": "Hygiène email", "status": "ok", "score": 35,
                "weight": 20, "duration_ms": 120, "errors": [], "disabled_reason": None,
                "sources": [{"name": "HIBP", "url": "https://x", "cached": True,
                             "fetched_at": "2026-02-01T10:00:00+00:00", "status": 200}],
                "findings": [{
                    "code": "EMAIL_SPF_MULTIPLE", "module": "email", "severity": "critique",
                    "title": "Deux enregistrements SPF", "constat": "Constat technique",
                    "explication": "Explication grand public", "recommandation": "Fusionner",
                    "references": [{"framework": "ANSSI", "label": "Messagerie", "url": "https://x"}],
                    "evidence": {},
                }],
                "data": {},
            },
            {
                "key": "reputation", "label": "Réputation", "status": "skipped", "score": None,
                "weight": 5, "duration_ms": 0, "errors": [],
                "disabled_reason": "clé absente", "sources": [], "findings": [],
                "data": {"sources_desactivees": [{"source": "VirusTotal", "raison": "clé absente"}]},
            },
        ],
    }


def test_contexte_calcule(rapport, settings):
    contexte = build_context(rapport, settings)
    assert contexte["counts"]["critique"] == 1
    assert contexte["total_findings"] == 1
    assert contexte["segments"][0]["label"] == "Critique"
    assert contexte["segments"][0]["share"] == 100.0
    assert contexte["modules_actifs"] == 1
    assert [m["score"] for m in contexte["modules_meter"]] == [35, None]
    assert contexte["top_findings"][0]["code"] == "EMAIL_SPF_MULTIPLE"
    assert contexte["sources_desactivees"][0]["module"] == "Réputation"


def test_chaque_gravite_a_un_glyphe_et_un_libelle():
    """La couleur ne doit jamais porter seule l'information."""
    for style in SEVERITY_STYLE.values():
        assert style["glyph"] and style["label"] and style["color"]


def test_rendu_html_autonome(rapport, settings):
    html = render_html(rapport, settings)
    assert "<script" not in html
    assert "http://" not in html.split("</head>")[0]  # aucune ressource externe chargée
    assert "Deux enregistrements SPF" in html
    assert "Explication grand public" in html
    assert "Fusionner" in html
    assert "ANSSI" in html
    assert "plafonné" in html
    assert "clé absente" in html
    assert "Transfert de zone" in html  # annexe de méthode


def test_echappement_du_contenu_externe(rapport, settings):
    rapport["modules"][0]["findings"][0]["title"] = "<script>alert(1)</script>"
    html = render_html(rapport, settings)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_rendu_pdf(rapport, settings):
    disponible, raison = pdf_available()
    if not disponible:
        pytest.skip(f"WeasyPrint indisponible : {raison}")
    contenu = render_pdf(rapport, settings)
    assert contenu.startswith(b"%PDF")
    assert len(contenu) > 5000


def test_message_clair_si_weasyprint_absent(rapport, settings, monkeypatch):
    monkeypatch.setattr("app.report.pdf.pdf_available", lambda: (False, "WeasyPrint absent"))
    with pytest.raises(PdfUnavailable):
        render_pdf(rapport, settings)
