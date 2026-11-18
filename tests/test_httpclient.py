"""Client HTTP : cache, politesse, retries, gestion des erreurs."""

import httpx
import respx

from app.httpclient import HttpClient

URL = "https://api.exemple.fr/ressource"


@respx.mock
async def test_appel_simple_et_decodage_json(settings, http):
    respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    resultat = await http.request("hibp", URL)
    assert resultat.ok and resultat.payload == {"a": 1} and resultat.cached is False


@respx.mock
async def test_mise_en_cache_evite_un_second_appel(settings, store):
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    client = HttpClient(settings, store)
    premier = await client.request("hibp", URL)
    second = await client.request("hibp", URL)
    await client.aclose()

    assert route.call_count == 1
    assert premier.cached is False and second.cached is True
    assert second.payload == {"a": 1}


@respx.mock
async def test_les_erreurs_ne_sont_pas_mises_en_cache(settings, store):
    route = respx.get(URL).mock(return_value=httpx.Response(500))
    client = HttpClient(settings, store)
    await client.request("hibp", URL)
    await client.request("hibp", URL)
    await client.aclose()
    assert route.call_count == 2


@respx.mock
async def test_nouvelle_tentative_apres_une_erreur_passagere(settings, http):
    settings.http_retries = 3
    route = respx.get(URL)
    route.side_effect = [httpx.Response(503), httpx.Response(200, json={"ok": True})]
    resultat = await http.request("hibp", URL, use_cache=False)
    assert resultat.ok and resultat.attempts == 2


@respx.mock
async def test_respect_de_lentete_retry_after(settings, http):
    settings.http_retries = 2
    route = respx.get(URL)
    route.side_effect = [
        httpx.Response(429, headers={"retry-after": "0"}),
        httpx.Response(200, json={"ok": True}),
    ]
    assert (await http.request("hibp", URL, use_cache=False)).ok


@respx.mock
async def test_message_derreur_lisible_par_statut(settings, http):
    respx.get(URL).mock(return_value=httpx.Response(401))
    resultat = await http.request("hibp", URL, use_cache=False)
    assert not resultat.ok
    assert "authentification refusée" in resultat.describe_error()


@respx.mock
async def test_erreur_reseau_ne_leve_pas(settings, http):
    respx.get(URL).mock(side_effect=httpx.ConnectError("injoignable"))
    resultat = await http.request("hibp", URL, use_cache=False)
    assert resultat.error and resultat.status is None
    assert "réseau" in resultat.describe_error()


@respx.mock
async def test_les_entetes_et_cookies_sont_exposes(settings, http):
    respx.get(URL).mock(return_value=httpx.Response(
        200, headers=[("set-cookie", "a=1; Secure"), ("set-cookie", "b=2"),
                      ("x-test", "valeur")], json={}))
    resultat = await http.request("cible", URL, use_cache=False)
    assert resultat.headers["x-test"] == "valeur"
    assert len(resultat.cookies) == 2
