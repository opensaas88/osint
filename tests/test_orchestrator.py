"""Orchestration : vagues de dépendances, isolation des erreurs, nettoyage final."""

import asyncio

from app.models import Consents, ModuleStatus, Severity
from app.modules import ModuleRun
from app.orchestrator import AnalysisChannel, Orchestrator, collect_recon, plan_waves
from app.validation import normalize_domain
from tests.conftest import FakeResolver


class FauxModule:
    def __init__(self, key, depends=(), comportement="ok", timeout=5.0):
        self.KEY = key
        self.LABEL = key
        self.WEIGHT = 10
        self.DEPENDS_ON = depends
        self.TIMEOUT = timeout
        self.comportement = comportement
        self.appele = False

    async def run(self, ctx):
        self.appele = True
        if self.comportement == "exception":
            raise RuntimeError("défaillance interne")
        if self.comportement == "lent":
            await asyncio.sleep(10)
        run_ = ModuleRun("email")
        run_.key = self.KEY
        run_.label = self.KEY
        run_.data = {"password": "secret"}  # doit être nettoyé par l'orchestrateur
        run_.add("CODE", Severity.MOYEN, "t", "c", "e", "r")
        return run_.done()


def test_ordonnancement_en_vagues():
    a, b, c = FauxModule("a"), FauxModule("b", depends=("a",)), FauxModule("c", depends=("b",))
    vagues = plan_waves([c, b, a])
    assert [[m.KEY for m in vague] for vague in vagues] == [["a"], ["b"], ["c"]]


def test_dependance_absente_nempeche_pas_lexecution():
    module = FauxModule("a", depends=("inexistant",))
    assert plan_waves([module]) == [[module]]


async def test_reconnaissance_partagee():
    resolver = FakeResolver(records={
        ("exemple.fr", "A"): ["203.0.113.10"],
        ("exemple.fr", "MX"): ["10 mail.exemple.fr.", "20 secours.exemple.fr."],
    })
    recon = await collect_recon(resolver, normalize_domain("exemple.fr"))
    assert recon.resolves is True
    assert recon.ips == ["203.0.113.10"]
    assert recon.mx_hosts == ["mail.exemple.fr", "secours.exemple.fr"]
    assert recon.has_null_mx is False


async def test_null_mx_detecte():
    resolver = FakeResolver(records={("exemple.fr", "MX"): ["0 ."],
                                     ("exemple.fr", "A"): ["203.0.113.10"]})
    recon = await collect_recon(resolver, normalize_domain("exemple.fr"))
    assert recon.has_null_mx is True


async def test_le_canal_rejoue_les_evenements_pour_un_abonne_tardif():
    canal = AnalysisChannel()
    await canal.publish("un", {"n": 1})
    await canal.publish("deux", {"n": 2})
    await canal.close()
    recus = [event["event"] async for event in canal.stream()]
    assert recus == ["un", "deux"]


async def test_un_module_en_erreur_nempeche_pas_les_autres(settings, store, monkeypatch):
    bon, casse = FauxModule("bon"), FauxModule("casse", comportement="exception")
    monkeypatch.setattr("app.orchestrator.load_registry", lambda: [bon, casse])
    monkeypatch.setattr(
        "app.orchestrator.build_resolver",
        lambda s, c: _resolver_factice(),
    )

    rapport = await Orchestrator(settings, store).run(
        normalize_domain("exemple.fr"), Consents(authorization=True, passive_only=True),
        actor="pytest",
    )
    resultats = {m.key: m for m in rapport.modules}
    assert resultats["bon"].status is ModuleStatus.OK
    assert resultats["casse"].status is ModuleStatus.ERROR
    assert resultats["casse"].score is None
    assert "RuntimeError" in resultats["casse"].errors[0]


async def test_un_module_trop_lent_est_interrompu(settings, store, monkeypatch):
    lent = FauxModule("lent", comportement="lent", timeout=0.2)
    monkeypatch.setattr("app.orchestrator.load_registry", lambda: [lent])
    monkeypatch.setattr("app.orchestrator.build_resolver", lambda s, c: _resolver_factice())

    rapport = await Orchestrator(settings, store).run(
        normalize_domain("exemple.fr"), Consents(authorization=True, passive_only=True),
        actor="pytest",
    )
    assert rapport.modules[0].status is ModuleStatus.ERROR
    assert "délai" in rapport.modules[0].disabled_reason


async def test_les_resultats_sont_nettoyes_et_persistes(settings, store, monkeypatch):
    from app.sanitize import REDACTED

    monkeypatch.setattr("app.orchestrator.load_registry", lambda: [FauxModule("bon")])
    monkeypatch.setattr("app.orchestrator.build_resolver", lambda s, c: _resolver_factice())

    rapport = await Orchestrator(settings, store).run(
        normalize_domain("exemple.fr"), Consents(authorization=True, passive_only=True),
        actor="pytest",
    )
    assert rapport.modules[0].data["password"] == REDACTED
    assert rapport.score is not None and rapport.grade
    assert (await store.get_report(rapport.id))["domain"] == "exemple.fr"
    journal = await store.list_audit()
    assert journal[0]["action"] == "analyse_terminee"


async def _resolver_factice():
    return FakeResolver(records={("exemple.fr", "A"): ["203.0.113.10"]})
