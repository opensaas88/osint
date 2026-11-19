"""Export des rapports vers le répertoire de suivi interne."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.__main__ import _export
from app.config import Settings
from app.models import AnalysisStatus, Consents, ModuleResult, ModuleStatus, Report
from app.storage import Store


@pytest.fixture
def reglages(tmp_path, monkeypatch) -> Settings:
    settings = Settings(
        _env_file=None,
        db_path=tmp_path / "test.db",
        reports_dir=tmp_path / "suivi",
        scheduler_enabled=False,
        rate_limits_enabled=False,
    )
    monkeypatch.setattr("app.__main__.get_settings", lambda: settings)
    return settings


async def _enregistrer(settings, identifiant="a1", domaine="exemple.fr", score=72):
    store = Store(settings.db_path)
    await store.init()
    await store.save_report(Report(
        id=identifiant, domain=domaine, domain_unicode=domaine,
        status=AnalysisStatus.DONE,
        started_at=datetime(2026, 3, 14, 9, 26, tzinfo=UTC),
        finished_at=datetime(2026, 3, 14, 9, 27, tzinfo=UTC),
        score=score, grade="C", actor="pytest",
        consents=Consents(authorization=True, passive_only=True),
        modules=[ModuleResult(key="email", label="Hygiène email", status=ModuleStatus.OK,
                              score=score, weight=20)],
    ))


async def test_export_par_identifiant(reglages, capsys):
    await _enregistrer(reglages)
    assert await _export("a1") == 0

    dossier = Path(reglages.reports_dir) / "exemple.fr"
    fichiers = sorted(f.name for f in dossier.iterdir())
    # Classement par domaine, puis horodatage de l'analyse : tri chronologique naturel.
    assert fichiers == ["2026-03-14-0926-rapport.html", "2026-03-14-0926-rapport.pdf"]
    assert (dossier / "2026-03-14-0926-rapport.pdf").read_bytes().startswith(b"%PDF")

    sortie = capsys.readouterr().out
    assert "document confidentiel" in sortie
    assert "exclu du dépôt" in sortie


async def test_export_par_domaine_prend_la_derniere_analyse(reglages):
    await _enregistrer(reglages, "ancienne", score=40)
    store = Store(reglages.db_path)
    rapport = await store.get_report("ancienne")
    rapport["id"] = "recente"
    rapport["started_at"] = "2026-06-01T15:00:00+00:00"
    rapport["score"] = 90
    store._save_report_sync(rapport, json.dumps(rapport))  # écriture directe, synchrone

    assert await _export("exemple.fr") == 0
    fichiers = sorted(
        f.name for f in (Path(reglages.reports_dir) / "exemple.fr").iterdir()
    )
    assert fichiers == ["2026-06-01-1500-rapport.html", "2026-06-01-1500-rapport.pdf"]


async def test_domaine_sans_analyse(reglages, capsys):
    await _enregistrer(reglages)
    assert await _export("jamais-analyse.fr") == 2
    assert "Aucune analyse enregistrée" in capsys.readouterr().out


async def test_cible_inexploitable(reglages, capsys):
    await _enregistrer(reglages)
    assert await _export("pas un domaine") == 2
    assert "Ni identifiant d'analyse, ni domaine exploitable" in capsys.readouterr().out


async def test_le_rapport_exporte_est_autonome(reglages):
    """Un rapport transmis à un client doit s'ouvrir sans réseau."""
    await _enregistrer(reglages)
    await _export("a1")
    html = (Path(reglages.reports_dir) / "exemple.fr" / "2026-03-14-0926-rapport.html").read_text(
        encoding="utf-8"
    )
    assert "<script" not in html
    assert 'src="http' not in html
