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
