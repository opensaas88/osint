"""Module Ransomware : correspondance exacte contre simple homonymie."""

import httpx
import respx

from app.modules import ransomware
from app.modules.ransomware import classify_match
from tests.conftest import FakeResolver

URL = "https://api.ransomware.live/v2/searchvictims/{}"

VICTIME = {
    "victim": "Exemple SAS", "domain": "exemple.fr", "group": "lockbit",
    "attackdate": "2026-02-10T12:00:00+00:00", "discovered": "2026-02-11T08:00:00+00:00",
    "country": "FR", "activity": "Services",
    "claim_url": "http://leaksite7xyz.onion/posts/abc",
}


def codes(resultat) -> set[str]:
    return {f.code for f in resultat.findings}


def test_qualification_des_correspondances():
    assert classify_match({"domain": "exemple.fr"}, "exemple.fr", "exemple") == "exact"
    assert classify_match({"domain": "www.exemple.fr"}, "exemple.fr", "exemple") == "exact"
    assert classify_match({"victim": "Groupe Exemple"}, "exemple.fr", "exemple") == "apparente"
    assert classify_match({"victim": "Autre société"}, "exemple.fr", "exemple") is None
    # Un nom d'organisation trop court n'autorise pas la correspondance approximative.
    assert classify_match({"victim": "ABC corp"}, "abc.fr", "abc") is None


@respx.mock
async def test_victime_revendiquee_est_critique(settings, http, make_context):
    respx.get(URL.format("exemple.fr")).mock(return_value=httpx.Response(200, json=[VICTIME]))
    respx.get(URL.format("exemple")).mock(return_value=httpx.Response(200, json=[]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await ransomware.run(ctx)

    assert "RANSOMWARE_CLAIMED_VICTIM" in codes(resultat)
    finding = next(f for f in resultat.findings if f.code == "RANSOMWARE_CLAIMED_VICTIM")
    assert finding.severity.value == "critique"


@respx.mock
async def test_ladresse_du_site_de_fuite_nest_jamais_conservee(settings, http, make_context):
    """Choix éthique : on signale l'existence de la revendication, pas son adresse .onion."""
    respx.get(URL.format("exemple.fr")).mock(return_value=httpx.Response(200, json=[VICTIME]))
    respx.get(URL.format("exemple")).mock(return_value=httpx.Response(200, json=[]))
    ctx = await make_context(settings, http, FakeResolver())
    contenu = (await ransomware.run(ctx)).model_dump_json()
    assert "onion" not in contenu
    assert "leaksite7xyz" not in contenu
    assert "revendication_publiee" in contenu


@respx.mock
async def test_homonyme_signale_comme_a_confirmer(settings, http, make_context):
    homonyme = {**VICTIME, "domain": "exemple.com.br", "victim": "Exemple Industria"}
    respx.get(URL.format("exemple.fr")).mock(return_value=httpx.Response(200, json=[]))
    respx.get(URL.format("exemple")).mock(return_value=httpx.Response(200, json=[homonyme]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await ransomware.run(ctx)
    assert "RANSOMWARE_POSSIBLE_HOMONYM" in codes(resultat)
    finding = next(f for f in resultat.findings if f.code == "RANSOMWARE_POSSIBLE_HOMONYM")
    assert finding.severity.value == "moyen"
    assert "vérification humaine" in finding.explication


@respx.mock
async def test_aucune_revendication(settings, http, make_context):
    respx.get(url__regex=r"https://api\.ransomware\.live/.*").mock(
        return_value=httpx.Response(200, json=[]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await ransomware.run(ctx)
    assert "RANSOMWARE_NONE" in codes(resultat)
    assert resultat.score == 100


@respx.mock
async def test_doublons_fusionnes(settings, http, make_context):
    respx.get(URL.format("exemple.fr")).mock(
        return_value=httpx.Response(200, json=[VICTIME, dict(VICTIME)]))
    respx.get(URL.format("exemple")).mock(return_value=httpx.Response(200, json=[VICTIME]))
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await ransomware.run(ctx)
    assert len(resultat.data["correspondances_exactes"]) == 1


# ---------------------------------------------------------------------------
# Deux pièges rencontrés sur des données réelles de ransomware.live
# ---------------------------------------------------------------------------

def test_un_domaine_de_remplissage_ne_vaut_pas_correspondance_exacte():
    """Trois victimes sans rapport portaient « example.com » faute de vraie donnée."""
    for faux in ("example.com", "example.org", "unknown", "n/a", "null", "-"):
        assert classify_match({"domain": faux, "victim": "Meena Health"}, faux, "example") is None


def test_un_domaine_reellement_enregistrable_nest_jamais_ignore():
    """Taire une revendication authentique serait plus grave qu'un faux positif.

    Seuls les noms réservés par la norme sont écartés : « domain.com » ou
    « test.com » appartiennent à quelqu'un et peuvent être victimes.
    """
    for vrai in ("domain.com", "test.com", "exemple.fr", "company.com"):
        assert classify_match({"domain": vrai, "victim": "X"}, vrai, vrai.split(".")[0]) == "exact"


def test_un_suffixe_ne_correspond_pas_a_tous_les_domaines():
    """Une fiche dont le champ domaine vaut « com » matchait tout le .com."""
    assert classify_match({"domain": "com", "victim": "X"}, "exemple.com", "exemple") is None
    assert classify_match({"domain": "fr", "victim": "X"}, "exemple.fr", "exemple") is None


def test_le_domaine_parent_demande_une_confirmation_humaine():
    """Analyser un sous-domaine d'une victime est un indice, pas une certitude."""
    assert classify_match(
        {"domain": "acme.fr", "victim": "Acme"}, "boutique.acme.fr", "boutique"
    ) == "apparente"


def test_sous_domaine_de_la_victime_reste_une_correspondance_exacte():
    assert classify_match(
        {"domain": "www.exemple.fr", "victim": "X"}, "exemple.fr", "exemple"
    ) == "exact"


@respx.mock
async def test_les_fiches_bouche_trou_ne_produisent_aucun_constat(
    settings, http, make_context
):
    """Reproduit le cas réel : trois victimes distinctes, toutes sur « example.com »."""
    fiches = [
        {**VICTIME, "victim": nom, "domain": "example.com"}
        for nom in ("meena health", "NextCapitalTrust", "republica federative do brasil")
    ]
    respx.get(url__regex=r"https://api\.ransomware\.live/.*").mock(
        return_value=httpx.Response(200, json=fiches)
    )
    ctx = await make_context(settings, http, FakeResolver(), domain="example.com")
    resultat = await ransomware.run(ctx)

    assert "RANSOMWARE_CLAIMED_VICTIM" not in codes(resultat)
    assert "RANSOMWARE_NONE" in codes(resultat)
    assert resultat.score == 100
