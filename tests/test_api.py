"""API HTTP : garde-fous éthiques, flux d'événements, exports et historique."""

import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models import AnalysisStatus, Consents, ModuleResult, ModuleStatus, Report
from app.storage import Store


class OrchestrateurFactice:
    """Remplace l'orchestrateur réel : aucune requête réseau pendant les tests."""

    def __init__(self, settings, store):
        self.settings = settings
        self.store = store

    async def run(self, domain, consents, *, actor, channel=None, analysis_id=None):
        rapport = Report(
            id=analysis_id or "fixe", domain=domain.ascii, domain_unicode=domain.unicode,
            status=AnalysisStatus.DONE, started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC), score=72, grade="C", actor=actor,
            consents=consents,
            modules=[ModuleResult(key="email", label="Hygiène email", status=ModuleStatus.OK,
                                  score=72, weight=20)],
        )
        if channel is not None:
            await channel.publish("analysis_started", {"id": rapport.id, "modules": []})
            await channel.publish("module_done", {"key": "email", "result": {}})
            await channel.publish("analysis_done", {"id": rapport.id, "score": 72, "grade": "C"})
            await channel.close()
        await self.store.save_report(rapport)
        return rapport


@pytest.fixture
def client(settings, monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, "Orchestrator", OrchestrateurFactice)
    application = create_app(settings, Store(settings.db_path))
    with TestClient(application) as test_client:
        yield test_client


def test_sante(client):
    reponse = client.get("/api/health")
    assert reponse.status_code == 200 and reponse.json()["status"] == "ok"


def test_inventaire_des_modules_et_des_cles(client):
    corps = client.get("/api/modules").json()
    assert len(corps["modules"]) == 9
    assert sum(m["weight"] for m in corps["modules"]) == 100
    assert all(not cle["configured"] for cle in corps["cles_api"])
    assert corps["cache_heures"] == 24


def test_interface_servie(client):
    assert "DomainExposure" in client.get("/").text
    assert client.get("/app.js").status_code == 200


def test_refus_sans_les_cases_obligatoires(client, settings):
    reponse = client.post("/api/analyses", json={"domain": "exemple.fr"})
    assert reponse.status_code == 403
    detail = reponse.json()["detail"]
    assert set(detail["manquantes"]) == {"authorization", "passive_only"}


def test_le_refus_est_journalise(client, settings):
    client.post("/api/analyses", json={"domain": "exemple.fr", "authorization": True})
    journal = client.get("/api/audit").json()["journal"]
    entree = journal[0]
    assert entree["action"] == "analyse_refusee_consentement_manquant"
    assert entree["domain"] == "exemple.fr"
    consentements = json.loads(entree["consents_json"])
    assert consentements == {"authorization": True, "passive_only": False, "domain_verified": False}


@pytest.mark.parametrize(
    "domaine", ["https://exemple.fr/x", "1.1.1.1", "exemple", "localhost", "a_b.fr"]
)
def test_domaines_refuses(client, domaine):
    reponse = client.post(
        "/api/analyses",
        json={"domain": domaine, "authorization": True, "passive_only": True},
    )
    assert reponse.status_code == 400
    assert reponse.json()["detail"]["erreur"]


def test_analyse_complete_et_flux_devenements(client):
    reponse = client.post(
        "/api/analyses",
        json={"domain": "exemple.fr", "authorization": True, "passive_only": True},
    )
    assert reponse.status_code == 202
    identifiant = reponse.json()["id"]

    flux = client.get(f"/api/analyses/{identifiant}/stream").text
    assert "event: analysis_started" in flux
    assert "event: analysis_done" in flux
    assert "event: end" in flux

    rapport = client.get(f"/api/analyses/{identifiant}").json()
    assert rapport["score"] == 72 and rapport["grade"] == "C"

    journal = [e["action"] for e in client.get("/api/audit").json()["journal"]]
    assert "analyse_demandee" in journal


def test_historique_filtre_par_domaine(client):
    client.post("/api/analyses",
                json={"domain": "exemple.fr", "authorization": True, "passive_only": True})
    client.get("/api/analyses")  # laisse le temps à la tâche de fond de persister
    analyses = client.get("/api/analyses?domain=exemple.fr").json()["analyses"]
    assert len(analyses) >= 1
    assert client.get("/api/analyses?domain=autre.fr").json()["analyses"] == []


def test_analyse_inconnue(client):
    assert client.get("/api/analyses/inexistante").status_code == 404
    assert client.get("/api/analyses/inexistante/stream").status_code == 404
    assert client.get("/api/analyses/inexistante/report.html").status_code == 404


def test_comparaison_impossible_entre_domaines_differents(client, settings):
    import asyncio

    async def preparer():
        store = Store(settings.db_path)
        await store.init()
        for identifiant, domaine in (("a1", "exemple.fr"), ("b1", "autre.fr")):
            await store.save_report(Report(
                id=identifiant, domain=domaine, domain_unicode=domaine,
                status=AnalysisStatus.DONE, started_at=datetime.now(UTC),
                score=50, grade="E", actor="pytest",
                consents=Consents(authorization=True, passive_only=True),
            ))

    asyncio.run(preparer())
    assert client.get("/api/compare?a=a1&b=b1").status_code == 400
    assert client.get("/api/compare?a=a1&b=inexistant").status_code == 404


def test_exports_html_et_pdf(client):
    reponse = client.post(
        "/api/analyses",
        json={"domain": "exemple.fr", "authorization": True, "passive_only": True},
    )
    identifiant = reponse.json()["id"]

    html = client.get(f"/api/analyses/{identifiant}/report.html")
    assert html.status_code == 200
    assert "DomainExposure" in html.text
    assert "<script" not in html.text  # rapport autonome, sans script

    pdf = client.get(f"/api/analyses/{identifiant}/report.pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")
    assert "attachment" in pdf.headers["content-disposition"]

    exports = [e["action"] for e in client.get("/api/audit").json()["journal"]]
    assert exports.count("export_rapport") == 2
