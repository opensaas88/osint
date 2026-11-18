"""Canaux de notification : webhook HTTP et courriel SMTP.

Les deux sont optionnels et indépendants. Une notification qui échoue n'interrompt
jamais une analyse : l'échec est journalisé et l'exécution se poursuit.
"""

from __future__ import annotations

import asyncio
import json
import smtplib
from email.message import EmailMessage
from typing import Any

from .watchlist import format_alert_text

#: Couleurs de gravité, alignées sur la palette des rapports.
COULEURS = {
    "critique": "D03B3B",
    "eleve": "EC835A",
    "moyen": "FAB219",
    "faible": "6B6A64",
    "info": "B4B2AB",
}


def detect_webhook_format(url: str) -> str:
    """Devine le format attendu à partir de l'hôte du webhook.

    Chaque plateforme impose sa propre structure : poster le JSON brut de
    DomainExposure sur un webhook Slack renvoie « invalid_payload ».
    """
    hote = url.split("://")[-1].split("/")[0].lower()
    if "hooks.slack.com" in hote:
        return "slack"
    if hote.endswith("webhook.office.com"):
        return "teams"
    if "logic.azure.com" in hote or "powerplatform.com" in hote or "powerautomate" in hote:
        return "teams_workflow"
    if "discord.com" in hote or "discordapp.com" in hote:
        return "discord"
    return "json"


def _entete(payload: dict[str, Any]) -> str:
    score = payload["score"]
    avant = (
        f"{score['avant']} ({score['note_avant']}) → "
        if score["avant"] is not None
        else ""
    )
    return (
        f"{payload['client']} — score {avant}{score['apres']} ({score['note_apres']})"
    )


def _lignes_alertes(payload: dict[str, Any]) -> list[str]:
    return [f"[{a['gravite']}] {a['message']}" for a in payload["alertes"]]


def _gravite_max(payload: dict[str, Any]) -> str:
    for gravite in ("critique", "eleve", "moyen", "faible", "info"):
        if any(a["gravite"] == gravite for a in payload["alertes"]):
            return gravite
    return "info"


def _mandat(payload: dict[str, Any]) -> str:
    mandat = payload["mandat"]
    reference = f", réf. {mandat['reference']}" if mandat.get("reference") else ""
    return (
        f"Analyse passive · mandat attesté par {mandat['atteste_par']} le "
        f"{(mandat['le'] or '')[:10]}{reference} · analyse {payload['analyse_id']}"
    )


def build_webhook_body(format_: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Met la notification au format attendu par la plateforme destinataire."""
    entete = _entete(payload)
    lignes = _lignes_alertes(payload)
    gravite = _gravite_max(payload)
    couleur = COULEURS[gravite]
    domaine = payload["domaine"]

    if format_ == "slack":
        return {
            "text": f"DomainExposure — {entete}",
            "blocks": [
                {"type": "header",
                 "text": {"type": "plain_text", "text": entete[:150]}},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f"*{domaine}*\n" + "\n".join(f"• {ligne}" for ligne in lignes)}},
                {"type": "context",
                 "elements": [{"type": "mrkdwn", "text": _mandat(payload)}]},
            ],
        }

    if format_ == "teams":
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": couleur,
            "summary": f"DomainExposure — {entete}",
            "title": entete,
            "text": domaine,
            "sections": [
                {"facts": [
                    {"name": a["gravite"], "value": a["message"]} for a in payload["alertes"]
                ]},
                {"text": _mandat(payload)},
            ],
        }

    if format_ == "teams_workflow":
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "size": "Medium", "weight": "Bolder",
                         "text": entete, "wrap": True},
                        {"type": "TextBlock", "text": domaine, "isSubtle": True, "wrap": True},
                        {"type": "FactSet", "facts": [
                            {"title": a["gravite"], "value": a["message"]}
                            for a in payload["alertes"]
                        ]},
                        {"type": "TextBlock", "text": _mandat(payload), "isSubtle": True,
                         "wrap": True, "size": "Small"},
                    ],
                },
            }],
        }

    if format_ == "discord":
        return {
            "content": f"**DomainExposure** — {entete}",
            "embeds": [{
                "title": domaine,
                "description": "\n".join(f"• {ligne}" for ligne in lignes),
                "color": int(couleur, 16),
                "footer": {"text": _mandat(payload)[:2048]},
            }],
        }

    return payload  # format générique : la charge utile complète


async def send_webhook(http, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Poste la notification, mise au format de la plateforme destinataire."""
    format_ = detect_webhook_format(url)
    corps = build_webhook_body(format_, payload)
    resultat = await http.request(
        "webhook",
        url,
        method="POST",
        headers={"content-type": "application/json"},
        content=json.dumps(corps, ensure_ascii=False).encode("utf-8"),
        use_cache=False,
        retries=2,
    )
    return {
        "canal": "webhook",
        "format": format_,
        # Hôte seul : l'URL d'un webhook est un secret, elle n'entre pas dans les journaux.
        "cible": url.split("://")[-1].split("/")[0],
        "succes": resultat.ok,
        "detail": None if resultat.ok else resultat.describe_error(),
    }


def _send_email_sync(settings, destinataires: list[str], sujet: str, corps: str) -> None:
    message = EmailMessage()
    message["From"] = settings.smtp_from or settings.smtp_user or "domainexposure@localhost"
    message["To"] = ", ".join(destinataires)
    message["Subject"] = sujet
    message.set_content(corps)

    if settings.smtp_starttls:
        serveur = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
        serveur.starttls()
    else:
        serveur = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
    try:
        if settings.smtp_user and settings.key("smtp_password"):
            serveur.login(settings.smtp_user, settings.key("smtp_password"))
        serveur.send_message(message)
    finally:
        serveur.quit()


async def send_email(settings, destinataires: list[str], payload: dict[str, Any]) -> dict[str, Any]:
    """Envoie l'alerte par courriel, si un serveur SMTP est configuré."""
    if not settings.smtp_host:
        return {
            "canal": "courriel",
            "succes": False,
            "detail": "aucun serveur SMTP configuré (SMTP_HOST)",
        }
    sujet = (
        f"[DomainExposure] {payload['client']} — score "
        f"{payload['score']['apres']}/{payload['score']['note_apres']}"
    )
    try:
        await asyncio.to_thread(
            _send_email_sync, settings, destinataires, sujet, format_alert_text(payload)
        )
    except Exception as exc:
        return {
            "canal": "courriel",
            "succes": False,
            "detail": f"{type(exc).__name__} : {str(exc)[:160]}",
        }
    return {"canal": "courriel", "succes": True, "detail": None}


async def dispatch(settings, http, watched: dict[str, Any], payload: dict[str, Any]) -> list[dict]:
    """Envoie la notification sur tous les canaux configurés pour ce domaine."""
    envois: list[dict[str, Any]] = []
    url = (watched.get("notify_webhook") or "").strip()
    if url:
        try:
            envois.append(await send_webhook(http, url, payload))
        except Exception as exc:  # pragma: no cover - le canal ne doit jamais propager
            envois.append(
                {"canal": "webhook", "succes": False, "detail": f"{type(exc).__name__}"}
            )

    adresses = [a.strip() for a in (watched.get("notify_email") or "").split(",") if a.strip()]
    if adresses:
        envois.append(await send_email(settings, adresses, payload))
    return envois
