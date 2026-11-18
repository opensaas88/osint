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


def test_plan_de_remediation_expose(client, settings):
    """Le plan est calculé à la demande à partir du rapport persisté."""
    import asyncio

    from app.models import Finding, Severity

    rapport = Report(
        id="plan-1", domain="exemple.fr", domain_unicode="exemple.fr",
        status=AnalysisStatus.DONE, started_at=datetime.now(UTC), score=75, grade="C",
        actor="pytest", consents=Consents(authorization=True, passive_only=True),
        modules=[ModuleResult(
            key="email", label="Hygiène email", status=ModuleStatus.OK, score=75, weight=20,
            findings=[Finding(
                code="EMAIL_DMARC_MISSING", module="email", severity=Severity.ELEVE,
                title="Pas de DMARC", constat="c", explication="e",
                recommandation="publier DMARC",
            )],
        )],
    )
    asyncio.run(Store(settings.db_path).save_report(rapport))

    plan = client.get("/api/analyses/plan-1/plan").json()
    assert plan["score_actuel"] == 75
    assert plan["etapes"][0]["code"] == "EMAIL_DMARC_MISSING"
    assert plan["etapes"][0]["effort"] == "rapide"
    assert plan["etapes"][0]["effort_label"] == "moins d'une heure"
    assert plan["score_projete"] == 100
    assert plan["gain_total"] == 25

    simulation = client.post(
        "/api/analyses/plan-1/simulate", json={"codes": ["EMAIL_DMARC_MISSING"]}
    ).json()
    assert simulation["score_projete"] == 100
    assert simulation["gain"] == 25


def test_plan_dune_analyse_inconnue(client):
    assert client.get("/api/analyses/inexistante/plan").status_code == 404
    assert client.post("/api/analyses/inexistante/simulate", json={"codes": []}).status_code == 404


# ---------------------------------------------------------------------------
# Portefeuille surveillé
# ---------------------------------------------------------------------------

def test_inscription_refusee_sans_mandat(client):
    """Les attestations valent mandat permanent : elles ne peuvent pas être omises."""
    reponse = client.post("/api/watchlist", json={"domain": "exemple.fr"})
    assert reponse.status_code == 403
    assert set(reponse.json()["detail"]["manquantes"]) == {"authorization", "passive_only"}
    actions = [e["action"] for e in client.get("/api/audit").json()["journal"]]
    assert "analyse_refusee_consentement_manquant" in actions


def test_inscription_domaine_invalide(client):
    reponse = client.post(
        "/api/watchlist",
        json={"domain": "https://exemple.fr/x", "authorization": True, "passive_only": True},
    )
    assert reponse.status_code == 400


def test_cycle_de_vie_dun_domaine_suivi(client):
    creation = client.post("/api/watchlist", json={
        "domain": "exemple.fr", "label": "Client A", "interval_hours": 168,
        "authorization": True, "passive_only": True,
        "mandate_reference": "contrat 42", "notify_webhook": "https://hook.exemple.fr/x",
    })
    assert creation.status_code == 201
    identifiant = creation.json()["id"]
    assert creation.json()["prochaine_analyse"] is not None

    portefeuille = client.get("/api/watchlist").json()
    ligne = portefeuille["domaines"][0]
    assert ligne["client"] == "Client A"
    assert ligne["domaine"] == "exemple.fr"
    assert ligne["score"] is None  # jamais analysé
    assert ligne["mandat"]["reference"] == "contrat 42"
    assert ligne["notifications"] == {"webhook": True, "courriel": False}
    assert portefeuille["ordonnanceur"]["seuil_alerte_points"] == 5

    # Le mandat est journalisé à l'inscription.
    journal = client.get("/api/audit").json()["journal"]
    inscription = next(e for e in journal if e["action"] == "surveillance_ajout_mandat")
    assert "contrat 42" in inscription["user_agent"]

    modification = client.patch(
        f"/api/watchlist/{identifiant}", json={"interval_hours": 0, "label": "Client B"}
    )
    assert modification.status_code == 200
    assert modification.json()["prochaine_analyse"] is None
    assert client.get("/api/watchlist").json()["domaines"][0]["client"] == "Client B"

    assert client.delete(f"/api/watchlist/{identifiant}").status_code == 204
    assert client.get("/api/watchlist").json()["domaines"] == []
    actions = [e["action"] for e in client.get("/api/audit").json()["journal"]]
    assert "surveillance_retrait" in actions


def test_inscription_idempotente_sur_le_domaine(client):
    for label in ("Premier", "Second"):
        reponse = client.post("/api/watchlist", json={
            "domain": "exemple.fr", "label": label, "interval_hours": 24,
            "authorization": True, "passive_only": True,
        })
        assert reponse.status_code == 201
    domaines = client.get("/api/watchlist").json()["domaines"]
    assert len(domaines) == 1
    assert domaines[0]["client"] == "Second"


def test_actions_sur_un_domaine_inconnu(client):
    assert client.patch("/api/watchlist/inexistant", json={"label": "x"}).status_code == 404
    assert client.delete("/api/watchlist/inexistant").status_code == 404
    assert client.post("/api/watchlist/inexistant/run").status_code == 404


def test_analyse_immediate_dun_domaine_suivi(client, monkeypatch):
    """Le bouton « Analyser » déclenche l'analyse hors échéance."""
    import app.scheduler as scheduler_module

    monkeypatch.setattr(scheduler_module, "Orchestrator", OrchestrateurFactice)
    creation = client.post("/api/watchlist", json={
        "domain": "exemple.fr", "authorization": True, "passive_only": True,
        "interval_hours": 24,
    })
    identifiant = creation.json()["id"]

    resultat = client.post(f"/api/watchlist/{identifiant}/run").json()
    assert resultat["score"] == 72
    assert resultat["domaine"] == "exemple.fr"

    ligne = client.get("/api/watchlist").json()["domaines"][0]
    assert ligne["score"] == 72
    assert ligne["derniere_analyse"] is not None

    actions = [e["action"] for e in client.get("/api/audit").json()["journal"]]
    assert "analyse_planifiee" in actions


def test_historique_des_scores_et_courbe(client, settings):
    """Deux analyses au moins sont nécessaires pour tracer une évolution."""
    import asyncio

    store = Store(settings.db_path)
    for identifiant, score, note, date in (
        ("h1", 45, "F", datetime(2026, 1, 5, tzinfo=UTC)),
        ("h2", 69, "D", datetime(2026, 2, 5, tzinfo=UTC)),
        ("h3", 91, "A", datetime(2026, 3, 5, tzinfo=UTC)),
    ):
        asyncio.run(store.save_report(Report(
            id=identifiant, domain="exemple.fr", domain_unicode="exemple.fr",
            status=AnalysisStatus.DONE, started_at=date, finished_at=date,
            score=score, grade=note, actor="pytest",
            consents=Consents(authorization=True, passive_only=True),
        )))

    payload = client.get("/api/history?domain=exemple.fr").json()
    assert [p["score"] for p in payload["points"]] == [45, 69, 91]  # du plus ancien au récent
    assert payload["svg"].startswith("<svg")
    assert payload["domaine"] == "exemple.fr"


def test_historique_dun_domaine_sans_analyse(client):
    payload = client.get("/api/history?domain=jamais-vu.fr").json()
    assert payload["points"] == []
    assert payload["svg"] == ""  # rien à tracer


def test_historique_domaine_invalide(client):
    assert client.get("/api/history?domain=https://x.fr/y").status_code == 400


def test_identite_visuelle_exposee(client):
    marque = client.get("/api/branding").json()
    assert marque["nom"] and marque["couleur"].startswith("#")


def test_impacts_metier_exposes(client):
    impacts = client.get("/api/impacts").json()["impacts"]
    assert "EMAIL_SPF_MULTIPLE" in impacts
    entree = impacts["EMAIL_SPF_MULTIPLE"]
    assert "facture" in entree["phrase"]
    assert entree["subi_par"]
