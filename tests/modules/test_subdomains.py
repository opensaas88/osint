"""Module Sous-domaines : transparence des certificats (crt.sh)."""

import httpx
import respx

from app.models import ModuleStatus
from app.modules import subdomains
from app.modules.subdomains import classify_sensitive, parse_crtsh
from tests.conftest import FakeResolver

CRTSH = "https://crt.sh/"


def codes(resultat) -> set[str]:
    return {f.code for f in resultat.findings}


def test_extraction_des_noms():
    payload = [
        {"name_value": "www.exemple.fr\n*.exemple.fr", "common_name": "exemple.fr"},
        {"name_value": "api.exemple.fr"},
    ]
    assert parse_crtsh(payload) == {"www.exemple.fr", "exemple.fr", "api.exemple.fr"}


def test_detection_des_noms_revelateurs():
    assert classify_sensitive("staging.exemple.fr")
    assert classify_sensitive("vpn-paris.exemple.fr")
    assert classify_sensitive("www.exemple.fr") == []


@respx.mock
async def test_inventaire_et_noms_sensibles(settings, http, make_context):
    respx.get(CRTSH).mock(return_value=httpx.Response(200, json=[
        {"name_value": "www.exemple.fr"},
        {"name_value": "staging.exemple.fr"},
        {"name_value": "vieux.exemple.fr"},
    ]))
    resolver = FakeResolver(records={
        ("www.exemple.fr", "A"): ["203.0.113.1"],
        ("staging.exemple.fr", "A"): ["203.0.113.2"],
    })
    ctx = await make_context(settings, http, resolver)
    resultat = await subdomains.run(ctx)

    assert "SUBDOMAIN_INVENTORY" in codes(resultat)
    assert "SUBDOMAIN_SENSITIVE_NAMES" in codes(resultat)
    assert "SUBDOMAIN_DANGLING" in codes(resultat)
    assert resultat.data["ips"] == ["203.0.113.1", "203.0.113.2"]
    assert resultat.data["dead"] == ["vieux.exemple.fr"]


@respx.mock
async def test_repli_quand_lhistorique_complet_echoue(settings, http, make_context):
    """crt.sh renvoie souvent 502 sur l'historique : la variante restreinte prend le relais."""
    route = respx.get(CRTSH)
    route.side_effect = [
        httpx.Response(502, text="Bad Gateway"),
        httpx.Response(200, json=[{"name_value": "www.exemple.fr"}]),
    ]
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await subdomains.run(ctx)
    assert resultat.status is ModuleStatus.PARTIAL
    assert resultat.data["discovered_count"] == 1
    assert any("historique" in erreur for erreur in resultat.errors)


@respx.mock
async def test_echec_complet_de_crtsh(settings, http, make_context):
    respx.get(CRTSH).mock(return_value=httpx.Response(502))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await subdomains.run(ctx)
    assert resultat.status is ModuleStatus.ERROR
    assert resultat.score is None


@respx.mock
async def test_limite_de_resolution(settings, http, make_context):
    settings.subdomain_resolve_limit = 2
    respx.get(CRTSH).mock(return_value=httpx.Response(200, json=[
        {"name_value": f"h{i}.exemple.fr"} for i in range(10)
    ]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await subdomains.run(ctx)
    assert resultat.data["discovered_count"] == 10
    assert len(resultat.data["records"]) == 2
    assert resultat.data["truncated"] is True


# ---------------------------------------------------------------------------
# Expiration des certificats, à partir des données déjà récupérées de crt.sh
# ---------------------------------------------------------------------------

def _cert(nom: str, jours: int) -> dict:
    from datetime import UTC, datetime, timedelta

    fin = datetime.now(UTC) + timedelta(days=jours)
    return {"name_value": nom, "not_after": fin.strftime("%Y-%m-%dT%H:%M:%S")}


def test_extraction_du_certificat_le_plus_recent():
    from app.modules.subdomains import parse_crtsh_expiry

    payload = [
        {"name_value": "a.exemple.fr", "not_after": "2026-01-01T00:00:00"},
        {"name_value": "a.exemple.fr", "not_after": "2027-01-01T00:00:00"},
        {"name_value": "*.exemple.fr", "not_after": "2026-06-01T00:00:00"},
    ]
    expirations = parse_crtsh_expiry(payload)
    assert expirations["a.exemple.fr"] == "2027-01-01T00:00:00"
    assert expirations["exemple.fr"] == "2026-06-01T00:00:00"  # le joker est normalisé


@respx.mock
async def test_certificat_de_sous_domaine_expirant(settings, http, make_context):
    respx.get(CRTSH).mock(return_value=httpx.Response(200, json=[
        _cert("www.exemple.fr", 5), _cert("api.exemple.fr", 18), _cert("old.exemple.fr", 3),
    ]))
    resolver = FakeResolver(records={
        ("www.exemple.fr", "A"): ["203.0.113.1"],
        ("api.exemple.fr", "A"): ["203.0.113.2"],
        # old.exemple.fr ne résout plus : son certificat n'a plus d'importance
    })
    ctx = await make_context(settings, http, resolver)
    resultat = await subdomains.run(ctx)

    assert "SUBDOMAIN_CERT_EXPIRING" in codes(resultat)
    finding = next(f for f in resultat.findings if f.code == "SUBDOMAIN_CERT_EXPIRING")
    assert finding.severity.value == "eleve"  # le plus proche est à 5 jours
    noms = {c["nom"] for c in resultat.data["certificats_proches_expiration"]}
    assert noms == {"www.exemple.fr", "api.exemple.fr"}
    # Le constat dit explicitement sur quoi il se fonde.
    assert "journaux de transparence" in finding.explication


@respx.mock
async def test_certificats_lointains_ne_declenchent_rien(settings, http, make_context):
    respx.get(CRTSH).mock(return_value=httpx.Response(200, json=[_cert("www.exemple.fr", 70)]))
    resolver = FakeResolver(records={("www.exemple.fr", "A"): ["203.0.113.1"]})
    ctx = await make_context(settings, http, resolver)
    resultat = await subdomains.run(ctx)
    assert "SUBDOMAIN_CERT_EXPIRING" not in codes(resultat)
    assert resultat.data["certificats_proches_expiration"] == []


@respx.mock
async def test_lapex_est_laisse_au_module_tls(settings, http, make_context):
    """Le certificat de l'apex est analysé par le module TLS : pas de doublon ici."""
    respx.get(CRTSH).mock(return_value=httpx.Response(200, json=[_cert("exemple.fr", 4)]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await subdomains.run(ctx)
    assert "SUBDOMAIN_CERT_EXPIRING" not in codes(resultat)
