"""Notifications : mise au format par plateforme et acheminement."""

import json

import httpx
import pytest
import respx

from app.notify import (
    build_webhook_body,
    detect_webhook_format,
    dispatch,
    send_email,
    send_webhook,
)

PAYLOAD = {
    "evenement": "regression_detectee",
    "domaine": "exemple.fr",
    "client": "Client A",
    "analyse_id": "abc123",
    "horodatage": "2026-02-01T10:00:00+00:00",
    "score": {"avant": 90, "apres": 55, "note_avant": "A", "note_apres": "E"},
    "alertes": [
        {"type": "nouveau_constat_critique", "gravite": "critique",
         "message": "1 nouveau constat critique : Deux SPF", "detail": {}},
        {"type": "score_baisse", "gravite": "eleve",
         "message": "Le score a baissé de 35 points (90 → 55)", "detail": {}},
    ],
    "mandat": {"atteste_par": "operateur", "le": "2026-01-15T09:00:00+00:00",
               "reference": "contrat 42"},
}


@pytest.mark.parametrize(
    ("url", "attendu"),
    [
        ("https://hooks.slack.com/services/T0/B0/xxx", "slack"),
        ("https://acme.webhook.office.com/webhookb2/abc", "teams"),
        ("https://prod-3.francecentral.logic.azure.com/workflows/x/triggers/manual", "teams_workflow"),
        ("https://discord.com/api/webhooks/123/abc", "discord"),
        ("https://discordapp.com/api/webhooks/123/abc", "discord"),
        ("https://n8n.exemple.fr/webhook/alertes", "json"),
        ("https://exemple.fr/hook", "json"),
    ],
)
def test_detection_du_format(url, attendu):
    assert detect_webhook_format(url) == attendu


def test_format_slack_respecte_le_schema_block_kit():
    corps = build_webhook_body("slack", PAYLOAD)
    assert corps["text"]  # repli affiché en notification
    types = [bloc["type"] for bloc in corps["blocks"]]
    assert types == ["header", "section", "context"]
    # Le titre d'un bloc header doit être du plain_text et tenir en 150 caractères.
    entete = corps["blocks"][0]["text"]
    assert entete["type"] == "plain_text" and len(entete["text"]) <= 150
    assert "exemple.fr" in corps["blocks"][1]["text"]["text"]
    assert "contrat 42" in corps["blocks"][2]["elements"][0]["text"]


def test_format_teams_est_une_messagecard():
    corps = build_webhook_body("teams", PAYLOAD)
    assert corps["@type"] == "MessageCard"
    assert corps["themeColor"] == "D03B3B"  # gravité la plus élevée
    assert corps["summary"] and corps["title"]
    noms = [fait["name"] for fait in corps["sections"][0]["facts"]]
    assert noms == ["critique", "eleve"]


def test_format_teams_workflow_est_une_carte_adaptative():
    corps = build_webhook_body("teams_workflow", PAYLOAD)
    assert corps["type"] == "message"
    carte = corps["attachments"][0]
    assert carte["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert carte["content"]["type"] == "AdaptiveCard"
    assert any(bloc["type"] == "FactSet" for bloc in carte["content"]["body"])


def test_format_discord_utilise_un_embed_colore():
    corps = build_webhook_body("discord", PAYLOAD)
    assert corps["content"]
    embed = corps["embeds"][0]
    assert embed["title"] == "exemple.fr"
    assert embed["color"] == int("D03B3B", 16)  # entier décimal attendu par Discord
    assert "Deux SPF" in embed["description"]


def test_format_generique_transmet_la_charge_complete():
    assert build_webhook_body("json", PAYLOAD) == PAYLOAD


def test_toutes_les_alertes_apparaissent_dans_chaque_format():
    for format_ in ("slack", "teams", "teams_workflow", "discord", "json"):
        rendu = json.dumps(build_webhook_body(format_, PAYLOAD), ensure_ascii=False)
        assert "Deux SPF" in rendu, format_
        assert "35 points" in rendu, format_


@respx.mock
async def test_envoi_slack_poste_le_bon_corps(settings, http):
    url = "https://hooks.slack.com/services/T0/B0/xxx"
    route = respx.post(url).mock(return_value=httpx.Response(200, text="ok"))
    resultat = await send_webhook(http, url, PAYLOAD)

    assert route.call_count == 1
    assert resultat["succes"] is True
    assert resultat["format"] == "slack"
    envoye = json.loads(respx.calls.last.request.content.decode())
    assert "blocks" in envoye


@respx.mock
async def test_lurl_du_webhook_nentre_pas_dans_le_resultat(settings, http):
    """Une URL de webhook est un secret : seul l'hôte est conservé."""
    url = "https://hooks.slack.com/services/T0/B0/jeton-secret"
    respx.post(url).mock(return_value=httpx.Response(200))
    resultat = await send_webhook(http, url, PAYLOAD)
    assert "jeton-secret" not in json.dumps(resultat)
    assert resultat["cible"] == "hooks.slack.com"


@respx.mock
async def test_echec_webhook_est_rapporte(settings, http):
    url = "https://n8n.exemple.fr/webhook/x"
    respx.post(url).mock(return_value=httpx.Response(404))
    resultat = await send_webhook(http, url, PAYLOAD)
    assert resultat["succes"] is False and resultat["detail"]


async def test_courriel_sans_smtp(settings):
    resultat = await send_email(settings, ["a@exemple.fr"], PAYLOAD)
    assert resultat["succes"] is False and "SMTP_HOST" in resultat["detail"]


@respx.mock
async def test_dispatch_sur_les_deux_canaux(settings, http):
    url = "https://n8n.exemple.fr/webhook/x"
    respx.post(url).mock(return_value=httpx.Response(200))
    envois = await dispatch(
        settings, http,
        {"notify_webhook": url, "notify_email": "a@exemple.fr, b@exemple.fr"},
        PAYLOAD,
    )
    assert [e["canal"] for e in envois] == ["webhook", "courriel"]


async def test_dispatch_sans_canal_configure(settings, http):
    assert await dispatch(settings, http, {}, PAYLOAD) == []
