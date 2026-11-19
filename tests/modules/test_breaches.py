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
    respx.get(
        "https://haveibeenpwned.com/api/v3/stealerLogsByEmailDomain/exemple.fr"
    ).mock(return_value=httpx.Response(404))
    respx.get(
        "https://haveibeenpwned.com/api/v3/stealerLogsByWebsiteDomain/exemple.fr"
    ).mock(return_value=httpx.Response(404))
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


# ---------------------------------------------------------------------------
# Journaux d'infostealers : identifiants capturés sur des postes infectés.
# ---------------------------------------------------------------------------

HIBP_STEALER_EMAIL = "https://haveibeenpwned.com/api/v3/stealerLogsByEmailDomain/exemple.fr"
HIBP_STEALER_SITE = "https://haveibeenpwned.com/api/v3/stealerLogsByWebsiteDomain/exemple.fr"


def _active(settings):
    """Clé présente et propriété du domaine attestée."""
    settings.hibp_api_key = "cle-de-test"
    return Consents(authorization=True, passive_only=True, domain_verified=True)


@respx.mock
async def test_infostealer_sur_le_domaine_de_messagerie(settings, http, make_context):
    consents = _active(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    respx.get(HIBP_DOMAIN).mock(return_value=httpx.Response(404))
    respx.get(HIBP_STEALER_EMAIL).mock(return_value=httpx.Response(200, json={
        "jean.dupont": ["netflix.com", "spotify.com"],
        "compta": ["banque-exemple.fr"],
    }))
    respx.get(HIBP_STEALER_SITE).mock(return_value=httpx.Response(404))

    ctx = await make_context(settings, http, FakeResolver(), consents=consents)
    resultat = await breaches.run(ctx)

    assert "BREACH_STEALER_LOG_STAFF" in codes(resultat)
    finding = next(f for f in resultat.findings if f.code == "BREACH_STEALER_LOG_STAFF")
    assert finding.severity.value == "critique"
    # Les services concernés sont conservés : ce sont eux qui disent quoi renouveler.
    assert "netflix.com" in finding.constat and "banque-exemple.fr" in finding.constat
    # Les alias, eux, sont masqués.
    contenu = resultat.model_dump_json()
    assert "jean.dupont@exemple.fr" not in contenu
    assert "j***@exemple.fr" in contenu
    assert resultat.data["stealer_logs"]["domaine_de_messagerie"]["comptes"] == 2


@respx.mock
async def test_infostealer_chez_les_utilisateurs_du_site(settings, http, make_context):
    consents = _active(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    respx.get(HIBP_DOMAIN).mock(return_value=httpx.Response(404))
    respx.get(HIBP_STEALER_EMAIL).mock(return_value=httpx.Response(404))
    respx.get(HIBP_STEALER_SITE).mock(return_value=httpx.Response(200, json=[
        "andy@gmail.com", "jane@gmail.com", "pierre@orange.fr",
    ]))

    ctx = await make_context(settings, http, FakeResolver(), consents=consents)
    resultat = await breaches.run(ctx)

    assert "BREACH_STEALER_LOG_CUSTOMERS" in codes(resultat)
    finding = next(f for f in resultat.findings if f.code == "BREACH_STEALER_LOG_CUSTOMERS")
    assert finding.severity.value == "eleve"
    # Aucune adresse de tiers en clair : volumétrie et fournisseurs seulement.
    contenu = resultat.model_dump_json()
    for adresse in ("andy@gmail.com", "jane@gmail.com", "pierre@orange.fr"):
        assert adresse not in contenu
    assert "a***@gmail.com" in contenu
    site = resultat.data["stealer_logs"]["site_web"]
    assert site["comptes"] == 3
    assert site["par_fournisseur"] == {"gmail.com": 2, "orange.fr": 1}


@respx.mock
async def test_aucune_trace_dinfostealer(settings, http, make_context):
    consents = _active(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    respx.get(HIBP_DOMAIN).mock(return_value=httpx.Response(404))
    respx.get(HIBP_STEALER_EMAIL).mock(return_value=httpx.Response(404))
    respx.get(HIBP_STEALER_SITE).mock(return_value=httpx.Response(404))

    ctx = await make_context(settings, http, FakeResolver(), consents=consents)
    resultat = await breaches.run(ctx)
    assert "BREACH_STEALER_LOG_NONE" in codes(resultat)
    assert resultat.score == 100


@respx.mock
async def test_domaine_non_verifie_chez_hibp_message_explicite(settings, http, make_context):
    """HIBP répond 403 tant que le domaine n'est pas vérifié dans son tableau de bord."""
    consents = _active(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    respx.get(HIBP_DOMAIN).mock(return_value=httpx.Response(404))
    respx.get(HIBP_STEALER_EMAIL).mock(return_value=httpx.Response(403))
    respx.get(HIBP_STEALER_SITE).mock(return_value=httpx.Response(403))

    ctx = await make_context(settings, http, FakeResolver(), consents=consents)
    resultat = await breaches.run(ctx)
    assert resultat.status.value == "partial"
    assert any("tableau de bord" in erreur for erreur in resultat.errors)
    assert "BREACH_STEALER_LOG_NONE" not in codes(resultat)


@respx.mock
async def test_palier_insuffisant_message_explicite(settings, http, make_context):
    consents = _active(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    respx.get(HIBP_DOMAIN).mock(return_value=httpx.Response(404))
    respx.get(HIBP_STEALER_EMAIL).mock(return_value=httpx.Response(401))
    respx.get(HIBP_STEALER_SITE).mock(return_value=httpx.Response(401))

    ctx = await make_context(settings, http, FakeResolver(), consents=consents)
    resultat = await breaches.run(ctx)
    assert any("Pro" in erreur for erreur in resultat.errors)


@respx.mock
async def test_infostealers_bloques_sans_attestation_de_propriete(settings, http, make_context):
    """Sans la case « domaine vérifié », aucune requête n'est émise vers ces endpoints."""
    settings.hibp_api_key = "cle-de-test"
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    route_mail = respx.get(HIBP_STEALER_EMAIL).mock(return_value=httpx.Response(200, json={}))
    route_site = respx.get(HIBP_STEALER_SITE).mock(return_value=httpx.Response(200, json=[]))

    ctx = await make_context(settings, http, FakeResolver(),
                             consents=Consents(authorization=True, passive_only=True))
    resultat = await breaches.run(ctx)

    assert route_mail.call_count == 0 and route_site.call_count == 0
    sources = {item["source"] for item in resultat.data["sources_desactivees"]}
    assert "HIBP — journaux d'infostealers" in sources


# ---------------------------------------------------------------------------
# Recherche de code public (GitHub)
# ---------------------------------------------------------------------------

GITHUB = "https://api.github.com/search/code"


def resultat_github(total: int, chemins: list[str] | None = None) -> dict:
    return {
        "total_count": total,
        "incomplete_results": False,
        "items": [
            {
                "name": chemin.split("/")[-1],
                "path": chemin,
                "html_url": f"https://github.com/acme/depot/blob/main/{chemin}",
                "repository": {"full_name": "acme/depot"},
                # Champ volontairement présent : il ne doit jamais ressortir.
                "text_matches": [{"fragment": "api_key = 'sk-secret-reel'"}],
            }
            for chemin in (chemins or [])
        ],
    }


def _avec_jeton(settings):
    settings.github_search_token = "jeton-de-test"
    return settings


@respx.mock
async def test_piste_de_secret_dans_du_code_public(settings, http, make_context):
    _avec_jeton(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    route = respx.get(GITHUB)
    route.side_effect = [
        httpx.Response(200, json=resultat_github(12, ["README.md"])),            # mentions
        httpx.Response(200, json=resultat_github(2, ["config/prod.yml"])),       # password
        httpx.Response(200, json=resultat_github(0)),                            # api_key
    ]
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)

    assert "BREACH_PUBLIC_CODE_SECRET" in codes(resultat)
    finding = next(f for f in resultat.findings if f.code == "BREACH_PUBLIC_CODE_SECRET")
    assert finding.severity.value == "eleve"
    assert "piste à vérifier, pas une preuve" in finding.explication
    # La révocation prime sur la suppression : l'historique Git conserve le secret.
    assert "l'historique Git le conserve" in finding.recommandation


@respx.mock
async def test_le_contenu_des_fichiers_nest_jamais_conserve(settings, http, make_context):
    """Signaler une fuite d'identifiant ne doit pas conduire l'outil à le détenir."""
    _avec_jeton(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    route = respx.get(GITHUB)
    route.side_effect = [
        httpx.Response(200, json=resultat_github(1, ["a.yml"])),
        httpx.Response(200, json=resultat_github(1, ["config/prod.yml"])),
        httpx.Response(200, json=resultat_github(0)),
    ]
    ctx = await make_context(settings, http, FakeResolver())
    contenu = (await breaches.run(ctx)).model_dump_json()

    assert "sk-secret-reel" not in contenu
    assert "text_matches" not in contenu
    assert "fragment" not in contenu
    # L'emplacement, lui, est conservé : c'est ce qui permet d'aller vérifier.
    assert "config/prod.yml" in contenu


@respx.mock
async def test_un_domaine_trop_repandu_ne_declenche_pas_dalerte(settings, http, make_context):
    """Mesuré en réel : « example.com password » renvoie plus de onze millions de fichiers."""
    _avec_jeton(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    route = respx.get(GITHUB)
    route.side_effect = [
        httpx.Response(200, json=resultat_github(9_000_000)),
        httpx.Response(200, json=resultat_github(11_223_040, ["docs/api.md"])),
        httpx.Response(200, json=resultat_github(500_000, ["readme.md"])),
    ]
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)

    assert "BREACH_PUBLIC_CODE_TOO_COMMON" in codes(resultat)
    assert "BREACH_PUBLIC_CODE_SECRET" not in codes(resultat)
    assert resultat.score == 100  # un constat informatif ne pénalise pas


@respx.mock
async def test_aucune_mention_dans_le_code_public(settings, http, make_context):
    _avec_jeton(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    respx.get(GITHUB).mock(return_value=httpx.Response(200, json=resultat_github(0)))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)
    assert not any(c.startswith("BREACH_PUBLIC_CODE") for c in codes(resultat))


@respx.mock
async def test_quota_github_epuise_est_signale_clairement(settings, http, make_context):
    _avec_jeton(settings)
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    respx.get(GITHUB).mock(return_value=httpx.Response(403, json={"message": "rate limited"}))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)
    assert any("10 requêtes par minute" in e for e in resultat.errors)


@respx.mock
async def test_recherche_de_code_desactivee_sans_jeton(settings, http, make_context):
    """Sans jeton, aucune requête n'est émise vers GitHub."""
    respx.get(HIBP_BREACHES).mock(return_value=httpx.Response(200, json=[]))
    route = respx.get(GITHUB).mock(return_value=httpx.Response(200, json=resultat_github(0)))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await breaches.run(ctx)

    assert route.call_count == 0
    sources = {item["source"] for item in resultat.data["sources_desactivees"]}
    assert "GitHub (recherche de code public)" in sources
