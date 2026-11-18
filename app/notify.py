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


async def send_webhook(http, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Poste la notification en JSON. Compatible Slack, Teams, n8n et consorts."""
    resultat = await http.request(
        "webhook",
        url,
        method="POST",
        headers={"content-type": "application/json"},
        data=json.dumps(payload, ensure_ascii=False),
        use_cache=False,
        retries=2,
    )
    return {
        "canal": "webhook",
        "cible": url.split("://")[-1].split("/")[0],  # hôte seul : pas de jeton dans les journaux
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
