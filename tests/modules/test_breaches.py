"""Module Fuites de données : métadonnées uniquement, adresses masquées."""

import httpx
import respx

from app.models import Consents
from app.modules import breaches
from app.modules.breaches import breach_severity
from tests.conftest import FakeResolver

HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_DOMAIN = "https://haveibeenpwned.com/api/v3/breacheddomain/exemple.fr"

FUITE = {
    "Name": "FuiteTest", "Title": "Fuite de test", "Domain": "exemple.fr",
    "BreachDate": "2024-03-01", "AddedDate": "2024-04-01T00:00:00Z",
    "PwnCount": 120000, "DataClasses": ["Email addresses", "Passwords"],
    "IsVerified": True, "Description": "Fuite <em>test</em>, contact admin@exemple.fr",
    # Champs hostiles qui ne doivent jamais ressortir :
    "Password": "hunter2", "PasswordHash": "deadbeef",
}


def codes(resultat) -> set[str]:
    return {f.code for f in resultat.findings}


def test_gravite_selon_nature_et_anciennete():
    assert breach_severity({"DataClasses": ["Passwords"], "BreachDate": "2025-01-01"}).value == "critique"
    assert breach_severity({"DataClasses": ["Passwords"], "BreachDate": "2014-01-01"}).value == "eleve"
    assert breach_severity({"DataClasses": ["Email addresses"], "BreachDate": "2024-01-01"}).value == "moyen"
    assert breach_severity({"DataClasses": ["Email addresses"], "BreachDate": "2010-01-01"}).value == "faible"
    assert breach_severity(
        {"DataClasses": ["Passwords"], "BreachDate": "2025-01-01", "IsVerified": False}
    ).value == "eleve"


@respx.mock
async def test_aucun_secret_nest_conserve(settings, http, make_context):
    """Whitelist stricte : mots de passe et empreintes n'entrent jamais dans le rapport."""
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[FUITE]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)

    contenu = resultat.model_dump_json()
    assert "hunter2" not in contenu
    assert "deadbeef" not in contenu
    # Les catégories de données exposées, elles, sont des métadonnées légitimes.
    assert "Passwords" in contenu
    assert "admin@exemple.fr" not in contenu  # adresse masquée dans la description


@respx.mock
async def test_fuite_du_site_remontee(settings, http, make_context):
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[FUITE]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)
    assert "BREACH_SITE_FUITETEST" in codes(resultat)
    assert resultat.data["chronologie"][0]["comptes"] == 120000


@respx.mock
async def test_aucune_fuite(settings, http, make_context):
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    ctx = await make_context(settings, http, FakeResolver())
    assert "BREACH_SITE_NONE" in codes(await breaches.run(ctx))


@respx.mock
async def test_domain_search_desactive_sans_cle(settings, http, make_context):
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)
    raisons = {item["source"]: item["raison"] for item in resultat.data["sources_desactivees"]}
    assert "HIBP Domain Search" in raisons
    assert "HIBP_API_KEY" in raisons["HIBP Domain Search"]


@respx.mock
async def test_domain_search_bloque_sans_verification_du_domaine(settings, http, make_context):
    """Avec une clé mais sans attestation de propriété, la recherche est volontairement bloquée."""
    settings.hibp_api_key = "cle-de-test"
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    route = respx.get(HIBP_DOMAIN).mock(return_value=httpx.Response(200, json={}))

    ctx = await make_context(settings, http, FakeResolver(),
                             consents=Consents(authorization=True, passive_only=True))
    resultat = await breaches.run(ctx)
    assert route.call_count == 0
    raisons = {item["source"]: item["raison"] for item in resultat.data["sources_desactivees"]}
    assert "domaine vérifié" in raisons["HIBP Domain Search"]


@respx.mock
async def test_domain_search_masque_les_adresses(settings, http, make_context):
    settings.hibp_api_key = "cle-de-test"
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    respx.get(HIBP_DOMAIN).mock(return_value=httpx.Response(200, json={
        "jean.dupont": ["FuiteTest"], "contact": ["FuiteTest", "Autre"],
    }))
    ctx = await make_context(
        settings, http, FakeResolver(),
        consents=Consents(authorization=True, passive_only=True, domain_verified=True),
    )
    resultat = await breaches.run(ctx)
    contenu = resultat.model_dump_json()
    assert "jean.dupont@exemple.fr" not in contenu
    assert "j***@exemple.fr" in contenu
    assert resultat.data["comptes_exposes"]["comptes"] == 2
    assert "BREACH_DOMAIN_ACCOUNTS" in codes(resultat)


@respx.mock
async def test_source_en_panne_degrade_sans_interrompre(settings, http, make_context):
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(503))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)
    assert resultat.status.value == "partial"
    assert resultat.errors


@respx.mock
async def test_un_champ_inconnu_de_la_source_nentre_jamais_dans_le_rapport(
    settings, http, make_context
):
    """Deux barrières : la whitelist écarte le champ, puis le filet de l'orchestrateur nettoie."""
    from app.sanitize import REDACTED, scrub, scrub_module_result

    hostile = {**FUITE, "NouveauChampPasswordHash": "0xdead"}
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[hostile]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)
    scrub_module_result(resultat)
    contenu = resultat.model_dump_json()

    # Première barrière : la whitelist n'a pas laissé passer le champ.
    assert "0xdead" not in contenu
    assert "NouveauChampPasswordHash" not in contenu
    # Seconde barrière : si un tel champ atteignait malgré tout un résultat, il serait masqué.
    assert scrub({"NouveauChampPasswordHash": "0xdead"})["NouveauChampPasswordHash"] == REDACTED
