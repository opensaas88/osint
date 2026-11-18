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
