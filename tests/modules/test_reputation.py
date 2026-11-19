"""Module Réputation : trois sources optionnelles, désactivation propre sans clé."""

import httpx
import respx

from app.models import ModuleStatus
from app.modules import ReconData, reputation
from tests.conftest import FakeResolver

VT = "https://www.virustotal.com/api/v3/domains/exemple.fr"
URLHAUS = "https://urlhaus-api.abuse.ch/v1/host/"
ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"


def codes(resultat) -> set[str]:
    return {f.code for f in resultat.findings}


async def test_module_desactive_sans_aucune_cle(settings, http, make_context):
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await reputation.run(ctx)
    assert resultat.status is ModuleStatus.SKIPPED
    assert resultat.score is None
    assert "VIRUSTOTAL_API_KEY" in resultat.disabled_reason
    assert "SAFEBROWSING_API_KEY" in resultat.disabled_reason
    assert len(resultat.data["sources_desactivees"]) == 4


@respx.mock
async def test_domaine_signale_par_virustotal(settings, http, make_context):
    settings.virustotal_api_key = "cle"
    respx.get(VT).mock(return_value=httpx.Response(200, json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60},
        "reputation": -40, "categories": {"editeur": "malware"},
    }}}))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await reputation.run(ctx)
    assert "REPUTATION_VT_FLAGGED" in codes(resultat)
    assert next(f for f in resultat.findings
                if f.code == "REPUTATION_VT_FLAGGED").severity.value == "eleve"


@respx.mock
async def test_domaine_propre_chez_virustotal(settings, http, make_context):
    settings.virustotal_api_key = "cle"
    respx.get(VT).mock(return_value=httpx.Response(200, json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70},
    }}}))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await reputation.run(ctx)
    assert "REPUTATION_VT_CLEAN" in codes(resultat)
    assert resultat.score == 100


@respx.mock
async def test_urls_malveillantes_sur_le_domaine(settings, http, make_context):
    settings.urlhaus_auth_key = "cle"
    respx.post(URLHAUS).mock(return_value=httpx.Response(200, json={
        "query_status": "ok",
        "urls": [{"url_status": "online"}, {"url_status": "offline"}],
        "blacklists": {"spamhaus_dbl": "listed"},
    }))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await reputation.run(ctx)
    assert "REPUTATION_URLHAUS_MALWARE" in codes(resultat)


@respx.mock
async def test_adresse_ip_signalee(settings, http, make_context):
    settings.abuseipdb_api_key = "cle"
    respx.get(ABUSEIPDB).mock(return_value=httpx.Response(200, json={"data": {
        "abuseConfidenceScore": 80, "totalReports": 42, "countryCode": "FR", "isp": "Hébergeur",
    }}))
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await reputation.run(ctx)
    assert "REPUTATION_ABUSEIPDB_FLAGGED" in codes(resultat)
    assert next(f for f in resultat.findings
                if f.code == "REPUTATION_ABUSEIPDB_FLAGGED").severity.value == "eleve"


@respx.mock
async def test_cle_refusee_degrade_sans_interrompre(settings, http, make_context):
    settings.virustotal_api_key = "mauvaise-cle"
    respx.get(VT).mock(return_value=httpx.Response(401, json={"error": "WrongCredentialsError"}))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await reputation.run(ctx)
    assert resultat.status is ModuleStatus.PARTIAL
    assert any("authentification refusée" in e for e in resultat.errors)


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

SAFEBROWSING = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


@respx.mock
async def test_domaine_signale_par_safe_browsing(settings, http, make_context):
    settings.safebrowsing_api_key = "cle"
    respx.post(SAFEBROWSING).mock(return_value=httpx.Response(200, json={"matches": [
        {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM",
         "threat": {"url": "https://exemple.fr/connexion"}},
        {"threatType": "MALWARE", "platformType": "ANY_PLATFORM",
         "threat": {"url": "https://exemple.fr/telechargement"}},
    ]}))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await reputation.run(ctx)

    finding = next(f for f in resultat.findings if f.code == "REPUTATION_SAFEBROWSING_FLAGGED")
    assert finding.severity.value == "eleve"
    assert "hameçonnage" in finding.constat
    assert "distribution de logiciel malveillant" in finding.constat
    # L'argument décisif : le client peut le vérifier lui-même en trois secondes.
    assert "Chrome" in finding.explication


@respx.mock
async def test_reponse_vide_signifie_domaine_sain(settings, http, make_context):
    """L'API renvoie un objet vide quand il n'y a rien à signaler."""
    settings.safebrowsing_api_key = "cle"
    respx.post(SAFEBROWSING).mock(return_value=httpx.Response(200, json={}))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await reputation.run(ctx)
    assert "REPUTATION_SAFEBROWSING_CLEAN" in codes(resultat)
    assert resultat.score == 100


@respx.mock
async def test_les_trois_variantes_durl_sont_soumises(settings, http, make_context):
    settings.safebrowsing_api_key = "cle"
    route = respx.post(SAFEBROWSING).mock(return_value=httpx.Response(200, json={}))
    ctx = await make_context(settings, http, FakeResolver())
    await reputation.run(ctx)

    assert route.call_count == 1
    import json as _json
    corps = _json.loads(respx.calls.last.request.content.decode())
    urls = [e["url"] for e in corps["threatInfo"]["threatEntries"]]
    assert urls == ["http://exemple.fr/", "https://exemple.fr/", "https://www.exemple.fr/"]
    assert "MALWARE" in corps["threatInfo"]["threatTypes"]


@respx.mock
async def test_cle_safe_browsing_invalide(settings, http, make_context):
    settings.safebrowsing_api_key = "mauvaise"
    respx.post(SAFEBROWSING).mock(
        return_value=httpx.Response(400, json={"error": {"message": "API key not valid"}}))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await reputation.run(ctx)
    assert any("Safe Browsing" in e for e in resultat.errors)
    assert not any(c.startswith("REPUTATION_SAFEBROWSING") for c in codes(resultat))


async def test_safe_browsing_absent_des_cles_desactivees_si_configure(settings, http, make_context):
    settings.safebrowsing_api_key = "cle"
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await reputation.run(ctx)
    sources = {item["source"] for item in resultat.data["sources_desactivees"]}
    assert "Google Safe Browsing" not in sources
