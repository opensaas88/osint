"""Persistance : cache horodaté, analyses, journal d'audit et purge."""

from datetime import UTC, datetime, timedelta

from app import audit
from app.models import AnalysisStatus, Consents, ModuleResult, ModuleStatus, Report


def make_report(domain="exemple.fr", score=72) -> Report:
    return Report(
        id="abc123", domain=domain, domain_unicode=domain,
        status=AnalysisStatus.DONE, started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC), score=score, grade="C", actor="pytest",
        modules=[ModuleResult(key="email", label="Hygiène email", status=ModuleStatus.OK,
                              score=score, weight=20)],
        consents=Consents(authorization=True, passive_only=True),
    )


async def test_cache_relu_puis_expire(store, settings):
    await store.cache_put("k1", "hibp", "https://x", 200, '{"a":1}', 24)
    entree = await store.cache_get("k1")
    assert entree["status"] == 200 and entree["payload"] == '{"a":1}'

    await store.cache_put("k2", "hibp", "https://x", 200, "{}", 0)  # expire immédiatement
    assert await store.cache_get("k2") is None


async def test_purge_du_cache_expire(store):
    await store.cache_put("vieux", "s", "u", 200, "{}", 0)
    await store.cache_put("frais", "s", "u", 200, "{}", 24)
    assert await store.cache_purge_expired() == 1
    assert await store.cache_get("frais") is not None


async def test_enregistrement_et_relecture_dune_analyse(store):
    rapport = make_report()
    await store.save_report(rapport)
    relu = await store.get_report("abc123")
    assert relu["domain"] == "exemple.fr"
    assert relu["modules"][0]["label"] == "Hygiène email"

    listing = await store.list_analyses("exemple.fr")
    assert len(listing) == 1 and listing[0]["score"] == 72
    assert await store.list_analyses("autre.fr") == []


async def test_journal_daudit_consigne_les_cases_cochees(store):
    consents = Consents(authorization=True, passive_only=True, domain_verified=False)
    await audit.record(
        store, action=audit.ACTION_ANALYSE_DEMANDEE, actor="pytest",
        domain="exemple.fr", consents=consents, client_ip="127.0.0.1",
        user_agent="pytest", analysis_id="abc123",
    )
    journal = await store.list_audit()
    assert len(journal) == 1
    entree = journal[0]
    assert entree["domain"] == "exemple.fr"
    assert entree["action"] == audit.ACTION_ANALYSE_DEMANDEE
    assert '"authorization": true' in entree["consents_json"]
    assert entree["ts"]


async def test_purge_du_journal_selon_la_retention(store):
    ancien = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    await store.log_audit({"ts": ancien, "action": "vieux", "actor": "x"})
    await audit.record(store, action="recent", actor="x")
    assert await store.purge_audit(365) == 1
    assert [e["action"] for e in await store.list_audit()] == ["recent"]


async def test_laudit_ne_leve_jamais():
    class StoreCasse:
        async def log_audit(self, entry):
            raise RuntimeError("base indisponible")

    await audit.record(StoreCasse(), action="test")  # ne doit pas lever
