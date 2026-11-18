"""Ordonnanceur : mandat permanent, régression et notifications."""

from datetime import UTC, datetime

import httpx
import pytest
import respx

from app import audit
from app.models import AnalysisStatus, Consents, Finding, ModuleResult, ModuleStatus, Report, Severity
from app.scheduler import Scheduler
from app.watchlist import next_run

WEBHOOK = "https://alertes.exemple.fr/hook"


def faux_rapport(domaine, score, constats, identifiant="r-new"):
    return Report(
        id=identifiant, domain=domaine, domain_unicode=domaine,
        status=AnalysisStatus.DONE, started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC), score=score,
        grade="A" if score >= 90 else "D", actor="planifiee",
        consents=Consents(authorization=True, passive_only=True),
        modules=[ModuleResult(
            key="email", label="Hygiène email", status=ModuleStatus.OK, score=score, weight=20,
            findings=[
                Finding(code=c, module="email", severity=Severity(s), title=f"Constat {c}",
                        constat="c", explication="e", recommandation="r")
                for c, s in constats
            ],
        )],
    )


@pytest.fixture
def orchestrateur_factice(monkeypatch):
    """Remplace l'orchestrateur : aucun accès réseau pendant les tests."""
    etat = {"rapport": faux_rapport("exemple.fr", 95, [])}

    class Faux:
        def __init__(self, settings, store):
            self.store = store

        async def run(self, domain, consents, *, actor, channel=None, analysis_id=None):
            rapport = etat["rapport"]
            rapport.consents = consents
            rapport.actor = actor
            await self.store.save_report(rapport)
            return rapport

    monkeypatch.setattr("app.scheduler.Orchestrator", Faux)
    return etat


async def inscrire(store, **extra):
    entree = {
        "id": "w1", "domain": "exemple.fr", "label": "Client A", "interval_hours": 24,
        "active": 1, "domain_verified": 0, "mandate_actor": "operateur",
        "mandate_at": "2026-01-15T09:00:00+00:00", "mandate_reference": "contrat 42",
        "created_at": "2026-01-15T09:00:00+00:00", "next_run_at": None,
    }
    entree.update(extra)
    await store.watch_upsert(entree)
    return entree


async def test_analyse_planifiee_journalise_le_mandat(settings, store, orchestrateur_factice):
    entree = await inscrire(store)
    resultat = await Scheduler(settings, store).run_one(entree)

    assert resultat["score"] == 95
    journal = await store.list_audit()
    planifiee = next(e for e in journal if e["action"] == audit.ACTION_ANALYSE_PLANIFIEE)
    assert planifiee["domain"] == "exemple.fr"
    assert planifiee["actor"] == "operateur"
    # Le mandat invoqué est tracé avec l'analyse.
    assert "contrat 42" in planifiee["user_agent"]
    assert "operateur" in planifiee["user_agent"]


async def test_lecheance_suivante_est_reprogrammee(settings, store, orchestrateur_factice):
    entree = await inscrire(store, interval_hours=24)
    await Scheduler(settings, store).run_one(entree)
    suivi = await store.watch_get("w1")
    assert suivi["last_run_at"] is not None
    assert suivi["next_run_at"] is not None
    assert suivi["last_analysis_id"] == "r-new"


async def test_suivi_manuel_na_pas_de_prochaine_echeance(settings, store, orchestrateur_factice):
    entree = await inscrire(store, interval_hours=0)
    await Scheduler(settings, store).run_one(entree)
    assert (await store.watch_get("w1"))["next_run_at"] is None


async def test_domaine_verifie_propage_le_consentement(settings, store, orchestrateur_factice):
    entree = await inscrire(store, domain_verified=1)
    await Scheduler(settings, store).run_one(entree)
    rapport = await store.get_report("r-new")
    assert rapport["consents"]["domain_verified"] is True


@respx.mock
async def test_regression_declenche_le_webhook(settings, store, orchestrateur_factice):
    route = respx.post(WEBHOOK).mock(return_value=httpx.Response(200, json={"ok": True}))
    await store.save_report(faux_rapport("exemple.fr", 95, [], identifiant="r-old"))
    orchestrateur_factice["rapport"] = faux_rapport(
        "exemple.fr", 60, [("NOUVEAU", "critique")], identifiant="r-new"
    )
    entree = await inscrire(store, notify_webhook=WEBHOOK)

    resultat = await Scheduler(settings, store).run_one(entree)

    assert route.call_count == 1
    envoye = resultat["notifications"][0]
    assert envoye["canal"] == "webhook" and envoye["succes"] is True
    types = {a["type"] for a in resultat["alertes"]}
    assert {"score_baisse", "nouveau_constat_critique"} <= types

    corps = respx.calls.last.request.content.decode()
    assert "Client A" in corps and "contrat 42" in corps

    journal = [e["action"] for e in await store.list_audit()]
    assert audit.ACTION_ALERTE in journal


@respx.mock
async def test_aucune_notification_sans_regression(settings, store, orchestrateur_factice):
    route = respx.post(WEBHOOK).mock(return_value=httpx.Response(200))
    await store.save_report(faux_rapport("exemple.fr", 60, [], identifiant="r-old"))
    orchestrateur_factice["rapport"] = faux_rapport("exemple.fr", 95, [], identifiant="r-new")
    entree = await inscrire(store, notify_webhook=WEBHOOK)

    resultat = await Scheduler(settings, store).run_one(entree)
    assert resultat["alertes"] == []
    assert route.call_count == 0


@respx.mock
async def test_un_webhook_en_panne_ninterrompt_pas_lanalyse(
    settings, store, orchestrateur_factice
):
    respx.post(WEBHOOK).mock(return_value=httpx.Response(500))
    await store.save_report(faux_rapport("exemple.fr", 95, [], identifiant="r-old"))
    orchestrateur_factice["rapport"] = faux_rapport(
        "exemple.fr", 50, [("X", "critique")], identifiant="r-new"
    )
    entree = await inscrire(store, notify_webhook=WEBHOOK)

    resultat = await Scheduler(settings, store).run_one(entree)
    assert resultat["score"] == 50  # l'analyse a bien abouti
    assert resultat["notifications"][0]["succes"] is False


async def test_courriel_sans_serveur_smtp_est_signale(settings, store, orchestrateur_factice):
    await store.save_report(faux_rapport("exemple.fr", 95, [], identifiant="r-old"))
    orchestrateur_factice["rapport"] = faux_rapport(
        "exemple.fr", 40, [("X", "critique")], identifiant="r-new"
    )
    entree = await inscrire(store, notify_email="rssi@exemple.fr")

    resultat = await Scheduler(settings, store).run_one(entree)
    envoi = resultat["notifications"][0]
    assert envoi["canal"] == "courriel" and envoi["succes"] is False
    assert "SMTP_HOST" in envoi["detail"]


async def test_domaine_invalide_ne_fait_pas_tomber_lordonnanceur(
    settings, store, orchestrateur_factice
):
    entree = await inscrire(store, id="w2", domain="pas un domaine")
    resultat = await Scheduler(settings, store).run_one(entree)
    assert "erreur" in resultat


async def test_les_echeances_atteintes_sont_traitees(settings, store, orchestrateur_factice):
    await inscrire(store, id="w1", domain="exemple.fr", next_run_at="2020-01-01T00:00:00+00:00")
    await inscrire(store, id="w2", domain="futur.fr", next_run_at=next_run(240))
    resultats = await Scheduler(settings, store).run_due()
    assert [r["domaine"] for r in resultats] == ["exemple.fr"]


async def test_un_suivi_inactif_est_ignore(settings, store, orchestrateur_factice):
    await inscrire(store, active=0, next_run_at="2020-01-01T00:00:00+00:00")
    assert await Scheduler(settings, store).run_due() == []
