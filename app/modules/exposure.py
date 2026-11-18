"""Module 6 — services exposés, observés passivement.

Les données proviennent de Shodan : InternetDB (gratuit, sans authentification) et,
si une clé est configurée, l'API complète. DomainExposure n'ouvre jamais de
connexion vers les ports de la cible : il consulte ce que Shodan a déjà collecté.

Nuance importante : lorsqu'une adresse IP est mutualisée (CDN, hébergement
partagé), les ports et vulnérabilités observés appartiennent au fournisseur et non
à l'organisation analysée. Le module le détecte et ne pénalise pas le score dans
ce cas.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from .. import refs
from ..models import ModuleResult, ModuleStatus, Severity
from . import MODULE_LABELS, ModuleContext, ModuleRun

KEY = "exposure"
LABEL = MODULE_LABELS[KEY]
WEIGHT = 15
DEPENDS_ON: tuple[str, ...] = ("subdomains",)
TIMEOUT = 150.0

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"

MAX_IPS = 30

#: Ports dont l'exposition directe sur Internet est particulièrement grave.
CRITICAL_PORTS: dict[int, str] = {
    23: "Telnet (identifiants en clair)",
    445: "Partage de fichiers Windows (SMB)",
    135: "RPC Windows",
    139: "NetBIOS",
    1433: "Base de données Microsoft SQL Server",
    3306: "Base de données MySQL",
    3389: "Bureau à distance Windows (RDP)",
    5432: "Base de données PostgreSQL",
    5900: "Bureau à distance VNC",
    6379: "Base Redis (souvent sans authentification)",
    9200: "Moteur de recherche Elasticsearch",
    11211: "Cache memcached (souvent sans authentification)",
    27017: "Base de données MongoDB",
    2375: "API Docker sans chiffrement",
    2376: "API Docker",
    5984: "Base de données CouchDB",
}

#: Ports d'administration dont l'exposition mérite un examen.
SENSITIVE_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    161: "SNMP",
    623: "IPMI",
    1521: "Base de données Oracle",
    3000: "Interface d'administration applicative",
    4444: "Service d'administration",
    5000: "Interface d'administration applicative",
    8006: "Interface Proxmox VE",
    8080: "Serveur d'applications",
    8443: "Interface d'administration HTTPS",
    9090: "Console d'administration",
    10000: "Webmin",
}

#: Marqueurs d'infrastructure mutualisée : les ports observés ne sont pas imputables.
SHARED_MARKERS = (
    "cloudflare", "fastly", "akamai", "amazonaws", "cloudfront", "azureedge", "vercel",
    "netlify", "incapsula", "sucuri", "ovh.net", "gandi", "github.io", "google",
)


def is_shared_infrastructure(record: dict[str, Any], domain: str) -> tuple[bool, str | None]:
    """Détermine si l'IP appartient à une infrastructure mutualisée."""
    haystack = " ".join(
        [
            *(str(h) for h in record.get("hostnames") or []),
            *(str(c) for c in record.get("cpes") or []),
            *(str(t) for t in record.get("tags") or []),
        ]
    ).lower()
    for marker in SHARED_MARKERS:
        if marker in haystack:
            return True, marker
    foreign = [
        str(h) for h in record.get("hostnames") or []
        if not str(h).lower().endswith(domain)
    ]
    if len(foreign) >= 3:
        return True, "noms d'hôtes multiples sans rapport avec le domaine"
    return False, None


async def run(ctx: ModuleContext) -> ModuleResult:
    """Interroge Shodan pour chaque adresse IP découverte."""
    run_ = ModuleRun(KEY)

    addresses: list[str] = []
    for candidate in ctx.recon.ips:
        if candidate not in addresses:
            addresses.append(candidate)
    previous = ctx.results.get("subdomains")
    if previous is not None:
        for candidate in previous.data.get("ips", []):
            if candidate not in addresses:
                addresses.append(candidate)

    valid: list[str] = []
    for candidate in addresses:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        valid.append(candidate)

    if not valid:
        return run_.failed("aucune adresse IP à interroger (le domaine ne résout pas)")

    truncated = len(valid) > MAX_IPS
    valid = valid[:MAX_IPS]
    if truncated:
        run_.error(f"plus de {MAX_IPS} adresses IP découvertes : seules les {MAX_IPS} premières "
                   "ont été interrogées")

    shodan_key = ctx.settings.key("shodan_api_key")

    async def lookup(ip: str) -> dict[str, Any]:
        result = await ctx.http.request("internetdb", INTERNETDB_URL.format(ip=ip))
        run_.source(result.source_ref(label=f"Shodan InternetDB — {ip}"))
        record: dict[str, Any] = {"ip": ip, "ports": [], "vulns": [], "tags": [], "hostnames": []}
        if result.status == 404:
            record["connu"] = False
            return record
        if not result.ok or not isinstance(result.payload, dict):
            record["erreur"] = result.describe_error()
            run_.error(f"Shodan InternetDB ({ip}) : {result.describe_error()}")
            return record
        payload = result.payload
        record.update(
            {
                "connu": True,
                "ports": sorted(int(p) for p in payload.get("ports") or []),
                "vulns": sorted(str(v) for v in payload.get("vulns") or []),
                "tags": [str(t) for t in payload.get("tags") or []],
                "hostnames": [str(h) for h in payload.get("hostnames") or []],
                "cpes": [str(c) for c in payload.get("cpes") or []],
            }
        )
        if shodan_key:
            detailed = await ctx.http.request(
                "shodan", SHODAN_HOST_URL.format(ip=ip), params={"key": shodan_key, "minify": "true"}
            )
            run_.source(detailed.source_ref(label=f"Shodan API — {ip}", url=SHODAN_HOST_URL.format(ip=ip)))
            if detailed.ok and isinstance(detailed.payload, dict):
                record["organisation"] = detailed.payload.get("org")
                record["systeme"] = detailed.payload.get("os")
                record["pays"] = detailed.payload.get("country_name")
                record["asn"] = detailed.payload.get("asn")
            elif detailed.status in (401, 403):
                run_.error("Shodan (API complète) : clé refusée")
            elif not detailed.ok:
                run_.error(f"Shodan (API complète, {ip}) : {detailed.describe_error()}")
        return record

    records = await asyncio.gather(*(lookup(ip) for ip in valid))

    for record in records:
        shared, marker = is_shared_infrastructure(record, ctx.name)
        record["mutualisee"] = shared
        record["marqueur_mutualisation"] = marker

    run_.data["adresses"] = records
    run_.data["cle_shodan"] = bool(shodan_key)
    if not shodan_key:
        run_.data["sources_desactivees"] = [
            {
                "source": "Shodan (API complète)",
                "raison": "clé SHODAN_API_KEY absente — InternetDB fournit déjà ports, "
                          "vulnérabilités connues et étiquettes",
            }
        ]

    dedies = [r for r in records if r.get("connu") and not r["mutualisee"]]
    mutualisees = [r for r in records if r.get("connu") and r["mutualisee"]]
    inconnues = [r for r in records if r.get("connu") is False]

    # --- vulnérabilités connues sur une infrastructure dédiée ---
    vulnerables = [r for r in dedies if r["vulns"]]
    if vulnerables:
        total_cve = sorted({cve for r in vulnerables for cve in r["vulns"]})
        detail = "; ".join(f"{r['ip']} : {', '.join(r['vulns'][:8])}" for r in vulnerables[:6])
        run_.add(
            "EXPOSURE_KNOWN_CVE", Severity.ELEVE,
            f"{len(total_cve)} vulnérabilité(s) connue(s) sur {len(vulnerables)} adresse(s) exposée(s)",
            f"{detail}",
            "Shodan a identifié sur ces machines des versions de logiciels affectées par des "
            "vulnérabilités publiées. Les codes d'exploitation de ces failles sont souvent "
            "publics, et des robots balaient Internet en continu pour les utiliser. Ce constat "
            "repose sur la bannière annoncée par le service : il peut s'agir d'un faux positif "
            "si un correctif a été appliqué sans changer le numéro de version.",
            "Vérifier chaque référence CVE sur les machines concernées, appliquer les correctifs "
            "et, à défaut, restreindre l'accès au service depuis Internet.",
            [refs.CIS_VULN, refs.ANSSI_CARTOGRAPHIE],
            {"cve": total_cve[:60], "adresses": [r["ip"] for r in vulnerables]},
        )

    # --- ports critiques ---
    critiques: dict[str, list[str]] = {}
    sensibles: dict[str, list[str]] = {}
    for record in dedies:
        for port in record["ports"]:
            if port in CRITICAL_PORTS:
                critiques.setdefault(record["ip"], []).append(f"{port} — {CRITICAL_PORTS[port]}")
            elif port in SENSITIVE_PORTS:
                sensibles.setdefault(record["ip"], []).append(f"{port} — {SENSITIVE_PORTS[port]}")

    if critiques:
        detail = "; ".join(f"{ip} : {', '.join(ports)}" for ip, ports in list(critiques.items())[:6])
        run_.add(
            "EXPOSURE_CRITICAL_PORTS", Severity.CRITIQUE,
            f"Services sensibles directement accessibles depuis Internet sur "
            f"{len(critiques)} adresse(s)",
            detail,
            "Ces services — bases de données, partages de fichiers, bureaux à distance — ne "
            "devraient jamais être joignables depuis Internet. Ils sont la cible privilégiée des "
            "attaques automatisées : essais de mots de passe en masse, exploitation de failles "
            "connues, et point d'entrée habituel des rançongiciels.",
            "Fermer ces ports au niveau du pare-feu et n'y accéder que par VPN ou passerelle "
            "d'administration dédiée. Vérifier immédiatement les journaux de connexion de ces "
            "services.",
            [refs.CIS_CONTROLS, refs.ANSSI_CARTOGRAPHIE],
            {"ports": critiques},
        )

    if sensibles:
        detail = "; ".join(f"{ip} : {', '.join(ports)}" for ip, ports in list(sensibles.items())[:6])
        run_.add(
            "EXPOSURE_SENSITIVE_PORTS", Severity.MOYEN,
            f"Services d'administration exposés sur {len(sensibles)} adresse(s)",
            detail,
            "Ces services ont une raison d'être exposés dans certaines architectures, mais ils "
            "constituent une surface d'attaque : chaque interface d'administration accessible "
            "publiquement peut subir des tentatives d'authentification automatisées.",
            "Restreindre l'accès par filtrage d'adresses IP ou VPN, imposer "
            "l'authentification multifacteur et surveiller les tentatives échouées.",
            [refs.CIS_CONTROLS, refs.ANSSI_CARTOGRAPHIE],
            {"ports": sensibles},
        )

    # --- synthèse de la surface ---
    if dedies:
        total_ports = sorted({p for r in dedies for p in r["ports"]})
        if total_ports and not critiques and not sensibles:
            run_.add(
                "EXPOSURE_SURFACE", Severity.INFO,
                f"{len(total_ports)} port(s) ouverts observés sur l'infrastructure dédiée",
                "Ports : " + ", ".join(str(p) for p in total_ports[:30]),
                "Ces ports correspondent à des services web standards. La surface exposée reste "
                "limitée.",
                "Maintenir l'inventaire des services exposés et vérifier régulièrement qu'aucun "
                "port n'a été ouvert par inadvertance.",
                [refs.CIS_INVENTAIRE],
            )

    if mutualisees:
        marqueurs = sorted({r["marqueur_mutualisation"] for r in mutualisees if r["marqueur_mutualisation"]})
        ports = sorted({p for r in mutualisees for p in r["ports"]})
        run_.add(
            "EXPOSURE_SHARED_INFRASTRUCTURE", Severity.INFO,
            f"{len(mutualisees)} adresse(s) appartiennent à une infrastructure mutualisée",
            f"Marqueurs détectés : {', '.join(marqueurs) or 'noms d\'hôtes partagés'}. "
            f"Ports observés sur ces adresses : {', '.join(str(p) for p in ports[:20]) or 'aucun'}.",
            "Le domaine est servi par un hébergeur mutualisé ou un réseau de diffusion de "
            "contenu. Les ports et vulnérabilités vus à ces adresses appartiennent au "
            "fournisseur, pas à votre organisation : ils ne sont donc pas comptés dans le score. "
            "L'avantage est que vos serveurs d'origine restent masqués ; l'inconvénient est que "
            "cette analyse ne les voit pas non plus.",
            "Vérifier que les serveurs d'origine n'acceptent que le trafic venant du réseau de "
            "diffusion, sans quoi ils resteraient joignables en contournant la protection.",
            [refs.CIS_INVENTAIRE],
            {"adresses": [r["ip"] for r in mutualisees], "marqueurs": marqueurs},
        )

    if inconnues and not dedies and not mutualisees:
        run_.add(
            "EXPOSURE_NO_DATA", Severity.INFO,
            "Aucune donnée d'exposition pour les adresses du domaine",
            "Adresses sans fiche Shodan : " + ", ".join(r["ip"] for r in inconnues[:10]),
            "Shodan n'a jamais observé de service sur ces adresses. C'est plutôt bon signe, mais "
            "cela peut aussi venir d'un filtrage des robots de balayage.",
            "Confirmer par un audit interne quels ports sont réellement ouverts.",
            [refs.CIS_INVENTAIRE],
        )

    return run_.done(status=ModuleStatus.PARTIAL if run_.errors else ModuleStatus.OK)
