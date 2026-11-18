"""Module 9 — réputation du domaine et de ses adresses IP.

Trois sources, toutes optionnelles et activées par clé : VirusTotal, URLhaus
(abuse.ch) et AbuseIPDB. Sans aucune clé, le module se désactive proprement et
l'indique dans le rapport.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from .. import refs
from ..models import ModuleResult, ModuleStatus, Severity
from . import MODULE_LABELS, ModuleContext, ModuleRun

KEY = "reputation"
LABEL = MODULE_LABELS[KEY]
WEIGHT = 5
DEPENDS_ON: tuple[str, ...] = ()
TIMEOUT = 120.0

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

MAX_IPS = 5


async def _virustotal(ctx: ModuleContext, run_: ModuleRun) -> dict[str, Any] | None:
    key = ctx.settings.key("virustotal_api_key")
    if not key:
        return None
    result = await ctx.http.request(
        "virustotal", VIRUSTOTAL_URL.format(domain=ctx.name), headers={"x-apikey": key}
    )
    run_.source(result.source_ref(label="VirusTotal"))
    if not result.ok or not isinstance(result.payload, dict):
        run_.error(f"VirusTotal : {result.describe_error()}")
        return None
    attributes = (result.payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    return {
        "malveillant": int(stats.get("malicious") or 0),
        "suspect": int(stats.get("suspicious") or 0),
        "inoffensif": int(stats.get("harmless") or 0),
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories") or {},
    }


async def _urlhaus(ctx: ModuleContext, run_: ModuleRun) -> dict[str, Any] | None:
    key = ctx.settings.key("urlhaus_auth_key")
    if not key:
        return None
    result = await ctx.http.request(
        "urlhaus", URLHAUS_URL, method="POST", data={"host": ctx.name},
        headers={"Auth-Key": key},
    )
    run_.source(result.source_ref(label="URLhaus (abuse.ch)"))
    if not result.ok or not isinstance(result.payload, dict):
        run_.error(f"URLhaus : {result.describe_error()}")
        return None
    payload = result.payload
    if payload.get("query_status") == "no_results":
        return {"urls_malveillantes": 0, "listes_noires": {}}
    urls = payload.get("urls") or []
    return {
        "urls_malveillantes": len(urls),
        "listes_noires": payload.get("blacklists") or {},
        "actives": sum(1 for u in urls if isinstance(u, dict) and u.get("url_status") == "online"),
    }


async def _abuseipdb(ctx: ModuleContext, run_: ModuleRun) -> list[dict[str, Any]] | None:
    key = ctx.settings.key("abuseipdb_api_key")
    if not key:
        return None
    adresses = []
    for candidate in ctx.recon.ips[:MAX_IPS]:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        adresses.append(candidate)
    if not adresses:
        return []

    async def check(ip: str) -> dict[str, Any] | None:
        result = await ctx.http.request(
            "abuseipdb", ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
        )
        run_.source(result.source_ref(label=f"AbuseIPDB — {ip}", url=ABUSEIPDB_URL))
        if not result.ok or not isinstance(result.payload, dict):
            run_.error(f"AbuseIPDB ({ip}) : {result.describe_error()}")
            return None
        data = result.payload.get("data") or {}
        return {
            "ip": ip,
            "score": int(data.get("abuseConfidenceScore") or 0),
            "signalements": int(data.get("totalReports") or 0),
            "pays": data.get("countryCode"),
            "fournisseur": data.get("isp"),
        }

    return [r for r in await asyncio.gather(*(check(ip) for ip in adresses)) if r]


async def run(ctx: ModuleContext) -> ModuleResult:
    """Consulte les bases de réputation pour le domaine et ses adresses IP."""
    run_ = ModuleRun(KEY)

    cles = {
        "VirusTotal": ctx.settings.has_key("virustotal_api_key"),
        "URLhaus (abuse.ch)": ctx.settings.has_key("urlhaus_auth_key"),
        "AbuseIPDB": ctx.settings.has_key("abuseipdb_api_key"),
    }
    manquantes = [nom for nom, presente in cles.items() if not presente]
    run_.data["sources_desactivees"] = [
        {"source": nom, "raison": "clé API absente"} for nom in manquantes
    ]

    if not any(cles.values()):
        return run_.skipped(
            "aucune clé de réputation configurée (VIRUSTOTAL_API_KEY, URLHAUS_AUTH_KEY, "
            "ABUSEIPDB_API_KEY)"
        )

    virustotal, urlhaus, abuseipdb = await asyncio.gather(
        _virustotal(ctx, run_), _urlhaus(ctx, run_), _abuseipdb(ctx, run_)
    )

    # ------------------------------------------------------------ VirusTotal --
    if virustotal is not None:
        run_.data["virustotal"] = virustotal
        malveillant = virustotal["malveillant"]
        suspect = virustotal["suspect"]
        if malveillant >= 3:
            severity = Severity.ELEVE
        elif malveillant >= 1:
            severity = Severity.MOYEN
        elif suspect >= 2:
            severity = Severity.FAIBLE
        else:
            severity = Severity.INFO

        if severity is Severity.INFO:
            run_.add(
                "REPUTATION_VT_CLEAN", Severity.INFO,
                "Aucun moteur antivirus ne signale le domaine",
                f"VirusTotal : {virustotal['inoffensif']} moteurs le considèrent comme "
                f"inoffensif, {malveillant} comme malveillant, {suspect} comme suspect.",
                "Le domaine n'est pas répertorié comme malveillant par les moteurs consultés.",
                "Aucune action nécessaire ; surveiller en cas de compromission du site.",
                [refs.CIS_CONTROLS],
            )
        else:
            run_.add(
                "REPUTATION_VT_FLAGGED", severity,
                f"{malveillant} moteur(s) antivirus signalent le domaine comme malveillant",
                f"VirusTotal : {malveillant} détections malveillantes, {suspect} suspectes, "
                f"{virustotal['inoffensif']} inoffensives. "
                f"Catégories : {virustotal['categories'] or 'non renseignées'}.",
                "Votre domaine est signalé comme dangereux par des éditeurs de sécurité. "
                "Conséquences concrètes : vos emails partent en indésirables, les navigateurs "
                "affichent des avertissements, et certains réseaux d'entreprise bloquent "
                "complètement l'accès à votre site. C'est souvent le signe d'une compromission "
                "ou d'un hébergement partagé avec des sites malveillants.",
                "Identifier et supprimer le contenu malveillant, puis demander une réévaluation "
                "auprès des éditeurs qui signalent le domaine.",
                [refs.CIS_CONTROLS, refs.ANSSI_SITE_WEB],
                {"detections": malveillant, "suspectes": suspect},
            )

    # --------------------------------------------------------------- URLhaus --
    if urlhaus is not None:
        run_.data["urlhaus"] = urlhaus
        nombre = urlhaus["urls_malveillantes"]
        if nombre:
            run_.add(
                "REPUTATION_URLHAUS_MALWARE", Severity.ELEVE,
                f"{nombre} URL malveillante(s) hébergée(s) sur ce domaine",
                f"URLhaus référence {nombre} URL de distribution de logiciels malveillants"
                + (f", dont {urlhaus.get('actives', 0)} encore active(s)" if urlhaus.get("actives") else "")
                + f". Listes noires : {urlhaus['listes_noires'] or 'aucune'}.",
                "Des adresses de votre domaine servent à distribuer des logiciels malveillants. "
                "C'est le signe d'une compromission du site, qui est utilisé comme relais "
                "d'attaque contre d'autres victimes — avec les conséquences juridiques et de "
                "réputation que cela implique.",
                "Traiter la compromission comme un incident : identifier la porte d'entrée, "
                "nettoyer ou réinstaller le site à partir d'une sauvegarde saine, changer tous "
                "les accès, puis demander le retrait des listes noires.",
                [refs.ANSSI_SITE_WEB, refs.CIS_CONTROLS],
                {"urls": nombre, "listes_noires": urlhaus["listes_noires"]},
            )
        else:
            run_.add(
                "REPUTATION_URLHAUS_CLEAN", Severity.INFO,
                "Aucune URL malveillante référencée sur ce domaine",
                "URLhaus ne référence aucune URL de distribution de logiciels malveillants.",
                "Le domaine n'est pas utilisé, à la connaissance d'abuse.ch, pour diffuser des "
                "logiciels malveillants.",
                "Aucune action nécessaire.",
                [refs.CIS_CONTROLS],
            )

    # ------------------------------------------------------------- AbuseIPDB --
    if abuseipdb:
        run_.data["abuseipdb"] = abuseipdb
        signalees = [entry for entry in abuseipdb if entry["score"] >= 25]
        if signalees:
            detail = "; ".join(
                f"{e['ip']} : score {e['score']}/100, {e['signalements']} signalements"
                for e in signalees
            )
            run_.add(
                "REPUTATION_ABUSEIPDB_FLAGGED",
                Severity.ELEVE if any(e["score"] >= 50 for e in signalees) else Severity.MOYEN,
                f"{len(signalees)} adresse(s) IP du domaine sont signalées pour abus",
                detail,
                "Les adresses IP qui hébergent vos services sont signalées pour des activités "
                "malveillantes (envoi de pourriels, tentatives d'intrusion). Si le serveur vous "
                "appartient, il est probablement compromis. Si l'hébergement est mutualisé, la "
                "mauvaise réputation d'un voisin dégrade la délivrabilité de vos emails et "
                "l'accès à votre site.",
                "Vérifier l'absence de compromission, demander le retrait des signalements, et "
                "envisager un changement d'adresse IP si la réputation reste dégradée.",
                [refs.CIS_CONTROLS, refs.ANSSI_SITE_WEB],
                {"adresses": signalees},
            )
        else:
            run_.add(
                "REPUTATION_ABUSEIPDB_CLEAN", Severity.INFO,
                "Les adresses IP du domaine ne sont pas signalées",
                "AbuseIPDB : "
                + ", ".join(f"{e['ip']} (score {e['score']}/100)" for e in abuseipdb),
                "Aucune activité malveillante n'est signalée depuis les adresses IP qui hébergent "
                "vos services.",
                "Aucune action nécessaire.",
                [refs.CIS_CONTROLS],
            )

    return run_.done(status=ModuleStatus.PARTIAL if run_.errors else ModuleStatus.OK)
