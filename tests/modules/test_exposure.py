"""Module Services exposés : Shodan InternetDB, sans jamais ouvrir de connexion."""

import httpx
import respx

from app.models import ModuleResult, ModuleStatus
from app.modules import ReconData, exposure
from app.modules.exposure import is_shared_infrastructure
from tests.conftest import FakeResolver

IDB = "https://internetdb.shodan.io/{}"


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
