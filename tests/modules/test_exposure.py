"""Module Services exposés : Shodan InternetDB, sans jamais ouvrir de connexion."""

import httpx
import pytest
import respx

from app.models import ModuleResult, ModuleStatus
from app.modules import ReconData, exposure
from app.modules.exposure import is_shared_infrastructure
from tests.conftest import FakeResolver

IDB = "https://internetdb.shodan.io/{}"
RDAP_IP = "https://rdap.org/ip/{}"


@pytest.fixture(autouse=True)
def rdap_muet():
    """Neutralise la localisation RDAP : aucun test ne doit dépendre du réseau.

    Les tests qui portent sur l'hébergement redéfinissent la route pour l'adresse
    qui les intéresse ; une route précise l'emporte sur ce repli générique.
    """
    respx.get(url__startswith="https://rdap.org/ip/", name="rdap_ip").mock(
        return_value=httpx.Response(404)
    )
    yield


def codes(resultat) -> set[str]:
    return {f.code for f in resultat.findings}


def test_detection_dinfrastructure_mutualisee():
    assert is_shared_infrastructure({"cpes": ["cpe:/a:cloudflare:cloudflare"]}, "exemple.fr")[0]
    assert is_shared_infrastructure(
        {"hostnames": ["a.autre.fr", "b.tiers.com", "c.encore.net"]}, "exemple.fr")[0]
    assert not is_shared_infrastructure({"hostnames": ["srv.exemple.fr"]}, "exemple.fr")[0]


@respx.mock
async def test_ports_critiques_sur_infrastructure_dediee(settings, http, make_context):
    respx.get(IDB.format("203.0.113.10")).mock(return_value=httpx.Response(200, json={
        "ip": "203.0.113.10", "ports": [22, 3389, 3306], "vulns": [],
        "hostnames": ["srv.exemple.fr"], "tags": [], "cpes": [],
    }))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await exposure.run(ctx)
    assert "EXPOSURE_CRITICAL_PORTS" in codes(resultat)
    assert "EXPOSURE_SENSITIVE_PORTS" in codes(resultat)
    assert next(f for f in resultat.findings
                if f.code == "EXPOSURE_CRITICAL_PORTS").severity.value == "critique"


@respx.mock
async def test_vulnerabilites_connues(settings, http, make_context):
    respx.get(IDB.format("203.0.113.10")).mock(return_value=httpx.Response(200, json={
        "ip": "203.0.113.10", "ports": [443], "vulns": ["CVE-2024-1234", "CVE-2023-9999"],
        "hostnames": ["srv.exemple.fr"], "tags": [], "cpes": [],
    }))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await exposure.run(ctx)
    assert "EXPOSURE_KNOWN_CVE" in codes(resultat)
    finding = next(f for f in resultat.findings if f.code == "EXPOSURE_KNOWN_CVE")
    assert "faux positif" in finding.explication


@respx.mock
async def test_infrastructure_mutualisee_nest_pas_imputee(settings, http, make_context):
    """Derrière un CDN, les ports observés appartiennent au fournisseur : pas de pénalité."""
    respx.get(IDB.format("198.51.100.1")).mock(return_value=httpx.Response(200, json={
        "ip": "198.51.100.1", "ports": [22, 3389, 3306], "vulns": ["CVE-2024-1111"],
        "hostnames": ["autre.fr", "tiers.com", "encore.net"],
        "tags": [], "cpes": ["cpe:/a:cloudflare:cloudflare"],
    }))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["198.51.100.1"]))
    resultat = await exposure.run(ctx)
    assert "EXPOSURE_SHARED_INFRASTRUCTURE" in codes(resultat)
    assert "EXPOSURE_CRITICAL_PORTS" not in codes(resultat)
    assert "EXPOSURE_KNOWN_CVE" not in codes(resultat)
    assert resultat.score == 100


@respx.mock
async def test_adresses_des_sous_domaines_reutilisees(settings, http, make_context):
    respx.get(IDB.format("203.0.113.10")).mock(
        return_value=httpx.Response(404, json={"detail": "No information available"}))
    respx.get(IDB.format("203.0.113.20")).mock(return_value=httpx.Response(200, json={
        "ip": "203.0.113.20", "ports": [80], "vulns": [], "hostnames": ["s.exemple.fr"],
        "tags": [], "cpes": [],
    }))
    precedent = ModuleResult(key="subdomains", label="Sous-domaines", status=ModuleStatus.OK,
                             score=100, weight=5, data={"ips": ["203.0.113.20"]})
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]),
                             results={"subdomains": precedent})
    resultat = await exposure.run(ctx)
    assert {a["ip"] for a in resultat.data["adresses"]} == {"203.0.113.10", "203.0.113.20"}


async def test_sans_adresse_le_module_echoue_proprement(settings, http, make_context):
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr"))
    resultat = await exposure.run(ctx)
    assert resultat.status is ModuleStatus.ERROR
    assert resultat.score is None


@respx.mock
async def test_cle_shodan_absente_est_documentee(settings, http, make_context):
    respx.get(IDB.format("203.0.113.10")).mock(return_value=httpx.Response(200, json={
        "ip": "203.0.113.10", "ports": [443], "vulns": [], "hostnames": [], "tags": [], "cpes": [],
    }))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await exposure.run(ctx)
    assert resultat.data["cle_shodan"] is False
    assert resultat.data["sources_desactivees"][0]["source"] == "Shodan (API complète)"


# ---------------------------------------------------------------------------
# Localisation de l'hébergement (RDAP du registre régional)
# ---------------------------------------------------------------------------

def rdap_ip(pays: str, reseau: str = "RESEAU-TEST") -> dict:
    """Réponse RDAP contenant volontairement un contact nominatif."""
    return {
        "name": reseau, "handle": "203.0.113.0 - 203.0.113.255", "country": pays,
        "entities": [{
            "roles": ["administrative"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Jean Dupont"],
                                     ["email", {}, "text", "jean.dupont@hebergeur.fr"]]],
        }],
    }


@respx.mock
async def test_hebergement_europeen(settings, http, make_context):
    respx.get(IDB.format("203.0.113.10")).mock(return_value=httpx.Response(200, json={
        "ip": "203.0.113.10", "ports": [443], "vulns": [], "hostnames": ["srv.exemple.fr"],
        "tags": [], "cpes": [],
    }))
    respx.routes["rdap_ip"].mock(return_value=httpx.Response(200, json=rdap_ip("FR", "OVH-CUSTOMERS")))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await exposure.run(ctx)

    assert "EXPOSURE_HOSTING_LOCATION" in codes(resultat)
    assert resultat.data["hebergement"][0]["pays"] == "FR"
    assert resultat.data["hebergement"][0]["dans_eee"] is True


@respx.mock
async def test_aucune_donnee_personnelle_du_registre_nest_conservee(
    settings, http, make_context
):
    """Les fiches RDAP contiennent des contacts nominatifs : ils ne doivent pas ressortir."""
    respx.get(IDB.format("203.0.113.10")).mock(return_value=httpx.Response(404))
    respx.routes["rdap_ip"].mock(return_value=httpx.Response(200, json=rdap_ip("FR")))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    contenu = (await exposure.run(ctx)).model_dump_json()

    assert "Jean Dupont" not in contenu
    assert "jean.dupont@hebergeur.fr" not in contenu
    assert "RESEAU-TEST" in contenu  # le nom du réseau, lui, est conservé


@respx.mock
async def test_hebergement_hors_eee_est_un_point_de_conformite(settings, http, make_context):
    respx.get(IDB.format("203.0.113.10")).mock(return_value=httpx.Response(404))
    respx.routes["rdap_ip"].mock(return_value=httpx.Response(200, json=rdap_ip("US", "US-CLOUD")))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await exposure.run(ctx)

    finding = next(f for f in resultat.findings if f.code == "EXPOSURE_HOSTING_OUTSIDE_EU")
    assert finding.severity.value == "faible"  # conformité, pas vulnérabilité
    assert "registre de traitements" in finding.explication
    # La limite de la donnée est explicitée : le pays du registre n'est pas le lieu réel.
    assert "siège de l'opérateur" in finding.explication


@respx.mock
async def test_valeur_generique_eu_du_ripe_est_traitee_comme_europeenne(
    settings, http, make_context
):
    respx.get(IDB.format("203.0.113.10")).mock(return_value=httpx.Response(404))
    respx.routes["rdap_ip"].mock(return_value=httpx.Response(200, json=rdap_ip("EU")))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await exposure.run(ctx)
    assert "EXPOSURE_HOSTING_OUTSIDE_EU" not in codes(resultat)


@respx.mock
async def test_rdap_injoignable_ne_produit_aucun_constat(settings, http, make_context):
    respx.get(IDB.format("203.0.113.10")).mock(return_value=httpx.Response(404))
    respx.routes["rdap_ip"].mock(return_value=httpx.Response(503))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await exposure.run(ctx)
    assert not any(c.startswith("EXPOSURE_HOSTING") for c in codes(resultat))
    assert any("RDAP" in e for e in resultat.errors)
