"""Module 4 — hygiène DNS : DNSSEC, serveurs de noms, CAA, IPv6, risque de reprise de sous-domaine.

Le transfert de zone (AXFR) n'est pas tenté : il s'agit d'une sollicitation directe
des serveurs de la cible, hors du périmètre strictement passif de l'outil.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from .. import refs
from ..models import ModuleResult, Severity
from ..resolver import strip_root
from . import MODULE_LABELS, ModuleContext, ModuleRun

KEY = "dns"
LABEL = MODULE_LABELS[KEY]
WEIGHT = 10
DEPENDS_ON: tuple[str, ...] = ("subdomains",)
TIMEOUT = 120.0

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

#: Sous-domaines systématiquement vérifiés pour le risque de reprise.
COMMON_SUBDOMAINS = (
    "www", "mail", "webmail", "autodiscover", "blog", "shop", "cdn", "static", "assets",
    "docs", "status", "support", "help", "app", "api", "portal", "dev", "staging", "test",
    "git", "vpn", "remote", "cloud", "files", "img", "media", "news", "beta",
)


def load_fingerprints() -> list[dict]:
    try:
        payload = json.loads((_DATA_DIR / "takeover_fingerprints.json").read_text(encoding="utf-8"))
        return list(payload.get("fingerprints", []))
    except (OSError, ValueError):  # pragma: no cover
        return []


def match_fingerprint(cname: str, fingerprints: list[dict]) -> str | None:
    """Retourne le nom du service tiers correspondant à un CNAME, le cas échéant."""
    lowered = cname.lower().rstrip(".")
    for entry in fingerprints:
        for pattern in entry.get("patterns", []):
            if lowered.endswith(pattern) or f".{pattern}" in lowered:
                return entry["service"]
    return None


async def run(ctx: ModuleContext) -> ModuleResult:
    """Évalue la robustesse de la configuration DNS du domaine."""
    run_ = ModuleRun(KEY)
    recon = ctx.recon

    run_.data["ns"] = [strip_root(n) for n in recon.ns]
    run_.data["a"] = recon.a
    run_.data["aaaa"] = recon.aaaa
    run_.data["caa"] = recon.caa
    run_.data["ds"] = recon.ds
    run_.data["dnssec_authenticated"] = recon.dnssec_authenticated

    if not recon.resolves:
        return run_.failed(
            "le domaine ne renvoie aucun enregistrement DNS (domaine expiré, non délégué, "
            "ou résolution impossible)"
        )

    # -------------------------------------------------------------- DNSSEC --
    dnskey = await ctx.resolver.query(ctx.name, "DNSKEY")
    has_ds = bool(recon.ds)
    has_dnskey = bool(dnskey.records)
    run_.data["dnskey_count"] = len(dnskey.records)

    if has_ds and recon.dnssec_authenticated:
        run_.add(
            "DNS_DNSSEC_OK", Severity.INFO,
            "DNSSEC est actif et la chaîne de confiance est validée",
            f"{len(recon.ds)} enregistrement(s) DS publié(s) et réponses validées par le résolveur.",
            "DNSSEC signe les réponses DNS de votre domaine : un attaquant ne peut pas faire "
            "croire à vos visiteurs que votre site se trouve sur un autre serveur.",
            "Maintenir la rotation des clés et surveiller l'expiration des signatures.",
            [refs.RFC_DNSSEC, refs.ANSSI_DNS],
        )
    elif has_ds and not recon.dnssec_authenticated:
        run_.add(
            "DNS_DNSSEC_UNVALIDATED", Severity.MOYEN,
            "DNSSEC est déclaré mais les réponses ne sont pas validées",
            f"{len(recon.ds)} enregistrement(s) DS publié(s), mais le résolveur n'a pas marqué "
            "les réponses comme authentifiées.",
            "La chaîne de confiance DNSSEC est peut-être rompue (clé expirée, DS obsolète après "
            "une rotation). Dans ce cas, les résolveurs validants peuvent refuser totalement de "
            "résoudre votre domaine, rendant vos services injoignables. Ce test reste indicatif : "
            "il dépend du résolveur utilisé pour l'analyse.",
            "Vérifier la cohérence entre les enregistrements DS publiés chez le registrar et les "
            "clés DNSKEY de la zone, à l'aide d'un outil de diagnostic DNSSEC.",
            [refs.RFC_DNSSEC, refs.ANSSI_DNS],
            {"ds": recon.ds, "dnskey_count": len(dnskey.records)},
        )
    elif has_dnskey and not has_ds:
        run_.add(
            "DNS_DNSSEC_INCOMPLETE", Severity.MOYEN,
            "La zone est signée mais la délégation DNSSEC n'est pas publiée",
            "Des clés DNSKEY existent, mais aucun enregistrement DS n'est publié par le parent.",
            "La signature de la zone est inutile tant que le registrar ne publie pas "
            "l'enregistrement DS correspondant : aucun résolveur ne peut vérifier la chaîne.",
            "Transmettre l'empreinte de la clé au registrar pour qu'il publie l'enregistrement DS.",
            [refs.RFC_DNSSEC, refs.ANSSI_DNS],
        )
    else:
        run_.add(
            "DNS_DNSSEC_MISSING", Severity.MOYEN,
            "DNSSEC n'est pas déployé",
            "Aucun enregistrement DS ni DNSKEY n'est publié pour le domaine.",
            "Sans DNSSEC, les réponses DNS de votre domaine ne sont pas signées. Un attaquant "
            "capable de s'interposer peut rediriger vos visiteurs ou vos emails vers ses propres "
            "serveurs sans que rien ne l'indique.",
            "Activer DNSSEC chez l'hébergeur DNS puis publier l'enregistrement DS chez le "
            "registrar. La plupart des hébergeurs proposent l'opération en un clic.",
            [refs.RFC_DNSSEC, refs.ANSSI_DNS, refs.CIS_CONTROLS],
        )

    # ------------------------------------------------- serveurs de noms ----
    ns_hosts = [strip_root(n) for n in recon.ns]
    if len(ns_hosts) < 2:
        run_.add(
            "DNS_SINGLE_NS", Severity.MOYEN,
            "Un seul serveur de noms déclaré" if ns_hosts else "Aucun serveur de noms déclaré",
            f"Serveurs de noms : {', '.join(ns_hosts) or 'aucun'}.",
            "Avec un seul serveur de noms, sa panne rend l'ensemble de vos services "
            "injoignables : site web, messagerie, applications. La norme en recommande au moins "
            "deux, sur des infrastructures distinctes.",
            "Déclarer au moins deux serveurs de noms, de préférence chez deux opérateurs "
            "différents ou sur deux réseaux séparés.",
            [refs.ANSSI_DNS, refs.CIS_CONTROLS],
            {"ns": ns_hosts},
        )
    else:
        zones = {".".join(h.split(".")[-2:]) for h in ns_hosts}
        if len(zones) == 1:
            run_.add(
                "DNS_NS_SINGLE_PROVIDER", Severity.FAIBLE,
                "Tous les serveurs de noms appartiennent au même domaine",
                f"Serveurs de noms : {', '.join(ns_hosts)} (domaine commun : {zones.pop()}).",
                "Les serveurs de noms sont redondants mais dépendent du même opérateur. Un "
                "incident majeur chez lui — panne, attaque par déni de service, litige "
                "contractuel — rend votre domaine entièrement injoignable.",
                "Pour un service critique, ajouter un opérateur DNS secondaire indépendant.",
                [refs.ANSSI_DNS],
                {"ns": ns_hosts},
            )

    # ------------------------------------------------------------------ CAA --
    if not recon.caa:
        run_.add(
            "DNS_CAA_MISSING", Severity.FAIBLE,
            "Aucun enregistrement CAA",
            "Le domaine ne publie pas d'enregistrement CAA.",
            "L'enregistrement CAA indique quelles autorités de certification ont le droit "
            "d'émettre un certificat pour votre domaine. Sans lui, n'importe quelle autorité "
            "peut en émettre un, ce qui facilite l'usurpation de votre site.",
            "Publier un enregistrement CAA n'autorisant que les autorités réellement utilisées, "
            "avec une adresse « iodef » pour être alerté des demandes refusées.",
            [refs.RFC_CAA, refs.ANSSI_DNS],
        )
    else:
        run_.add(
            "DNS_CAA_PRESENT", Severity.INFO,
            "Les autorités de certification autorisées sont déclarées (CAA)",
            f"Enregistrements CAA : {', '.join(recon.caa)}",
            "Seules les autorités listées peuvent émettre un certificat pour ce domaine, ce qui "
            "limite les émissions frauduleuses.",
            "Vérifier que la liste reste alignée avec les autorités réellement utilisées.",
            [refs.RFC_CAA],
        )

    # ----------------------------------------------------------------- IPv6 --
    if recon.a and not recon.aaaa:
        run_.add(
            "DNS_NO_IPV6", Severity.INFO,
            "Le domaine n'est pas joignable en IPv6",
            "Enregistrement A présent, aucun enregistrement AAAA.",
            "L'absence d'IPv6 n'est pas une faille de sécurité, mais elle dégrade "
            "l'accessibilité depuis les réseaux mobiles et les opérateurs modernes.",
            "Prévoir le déploiement d'IPv6 sur les services exposés.",
            [refs.ANSSI_DNS],
        )

    # ------------------------------------------ reprise de sous-domaine ----
    fingerprints = load_fingerprints()
    candidates: dict[str, list[str]] = {}

    # CNAME des sous-domaines déjà découverts par le module Certificate Transparency.
    previous = ctx.results.get("subdomains")
    if previous is not None:
        for record in previous.data.get("records", []):
            if record.get("cname"):
                candidates[record["name"]] = record["cname"]

    # Plus une liste fixe de noms usuels, qui peuvent ne pas figurer dans les certificats.
    async def probe(label: str) -> tuple[str, list[str]]:
        name = f"{label}.{ctx.name}"
        answer = await ctx.resolver.query(name, "CNAME")
        return name, [strip_root(c) for c in answer.records]

    probes = await asyncio.gather(*(probe(label) for label in COMMON_SUBDOMAINS))
    for name, cnames in probes:
        if cnames:
            candidates.setdefault(name, cnames)

    third_party: list[dict] = []
    orphaned: list[dict] = []

    async def inspect(name: str, cnames: list[str]) -> None:
        for cname in cnames:
            service = match_fingerprint(cname, fingerprints)
            if not service:
                continue
            target = await ctx.resolver.query(cname, "A")
            entry = {"subdomain": name, "cname": cname, "service": service, "rcode": target.rcode}
            if target.rcode == "NXDOMAIN" or (target.ok and not target.records and not target.cnames):
                orphaned.append(entry)
            else:
                third_party.append(entry)

    await asyncio.gather(*(inspect(name, cnames) for name, cnames in candidates.items()))

    run_.data["cnames"] = {name: cnames for name, cnames in candidates.items()}
    run_.data["third_party_services"] = third_party
    run_.data["takeover_candidates"] = orphaned

    if orphaned:
        detail = "; ".join(f"{e['subdomain']} → {e['cname']} ({e['service']})" for e in orphaned[:8])
        run_.add(
            "DNS_SUBDOMAIN_TAKEOVER_RISK", Severity.ELEVE,
            f"{len(orphaned)} sous-domaine(s) pointent vers un service tiers inexistant",
            f"{detail}. La cible du CNAME ne résout pas.",
            "Un de vos sous-domaines renvoie vers un hébergement externe qui n'existe plus. "
            "N'importe qui peut souvent recréer gratuitement cette ressource chez le même "
            "prestataire et récupérer ainsi le contrôle du sous-domaine : il publierait du "
            "contenu en votre nom, intercepterait des cookies ou obtiendrait un certificat "
            "valide. Ce constat est un faisceau d'indices : l'outil ne tente jamais de "
            "réclamer la ressource, ce qui serait une action intrusive.",
            "Supprimer sans délai l'enregistrement CNAME concerné, ou recréer la ressource chez "
            "le prestataire pour reprendre la main.",
            [refs.ANSSI_NOMS_DE_DOMAINE, refs.CIS_INVENTAIRE, refs.OWASP_HEADERS],
            {"candidats": orphaned},
        )

    if third_party:
        services = sorted({e["service"] for e in third_party})
        run_.add(
            "DNS_THIRD_PARTY_DEPENDENCIES", Severity.INFO,
            f"{len(third_party)} sous-domaine(s) délégués à {len(services)} service(s) tiers",
            "Services identifiés : " + ", ".join(services),
            "Ces sous-domaines sont hébergés chez des prestataires externes. C'est courant, "
            "mais cela élargit votre surface d'attaque : la sécurité de ces noms dépend de "
            "comptes chez des tiers, et un compte abandonné devient un risque de récupération.",
            "Tenir l'inventaire de ces dépendances, et supprimer l'enregistrement DNS dès qu'un "
            "service est résilié.",
            [refs.CIS_INVENTAIRE, refs.ANSSI_CARTOGRAPHIE],
            {"services": services},
        )

    # ------------------------------------------------- transfert de zone ----
    run_.add(
        "DNS_AXFR_NOT_TESTED", Severity.INFO,
        "Transfert de zone (AXFR) non testé, par choix méthodologique",
        "Aucune requête AXFR n'a été envoyée aux serveurs de noms du domaine.",
        "Tester un transfert de zone consiste à demander directement à vos serveurs DNS de "
        "livrer l'intégralité de la zone. C'est une sollicitation active de votre "
        "infrastructure : elle sort du périmètre strictement passif de cet outil.",
        "Vérifier ce point en interne : « dig AXFR @serveur-de-noms votre-domaine » doit "
        "échouer depuis Internet. N'autoriser les transferts qu'entre serveurs maîtres et "
        "esclaves identifiés.",
        [refs.ANSSI_DNS],
    )

    return run_.done()
