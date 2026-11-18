"""Module 4 — hygiène DNS : enregistrement du domaine, DNSSEC, serveurs de noms, CAA,
risque de reprise de sous-domaine.

Le transfert de zone (AXFR) n'est pas tenté : il s'agit d'une sollicitation directe
des serveurs de la cible, hors du périmètre strictement passif de l'outil.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
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

#: Service RDAP de redirection : il aiguille vers le serveur du registre de l'extension.
RDAP_URL = "https://rdap.org/domain/{domain}"

#: Seuils d'alerte sur l'expiration du nom de domaine, en jours.
DOMAIN_EXPIRY_CRITICAL_DAYS = 15
DOMAIN_EXPIRY_WARNING_DAYS = 45

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


def parse_rdap(payload: dict) -> dict:
    """Extrait d'une réponse RDAP les dates d'événement et les verrous du domaine."""
    evenements: dict[str, str] = {}
    for evenement in payload.get("events") or []:
        action = str(evenement.get("eventAction") or "").lower()
        date = evenement.get("eventDate")
        if action and date:
            evenements[action] = str(date)

    statuts = [str(s).lower().replace(" ", "") for s in payload.get("status") or []]
    return {
        "expiration": evenements.get("expiration"),
        "creation": evenements.get("registration"),
        "derniere_modification": evenements.get("lastchanged"),
        "statuts": statuts,
        "verrou_transfert": any("transferprohibited" in s for s in statuts),
        "verrou_suppression": any("deleteprohibited" in s for s in statuts),
    }


def _jours_restants(date_iso: str | None) -> int | None:
    if not date_iso:
        return None
    try:
        echeance = datetime.fromisoformat(date_iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if echeance.tzinfo is None:
        echeance = echeance.replace(tzinfo=UTC)
    return (echeance - datetime.now(UTC)).days


async def check_domain_registration(ctx: ModuleContext, run_: ModuleRun) -> None:
    """Interroge RDAP : expiration du nom de domaine et verrous posés par le registrar."""
    # rdap.org redirige vers le registre de l'extension : redirection explicite.
    result = await ctx.http.request(
        "rdap", RDAP_URL.format(domain=ctx.name), retries=2, follow_redirects=True
    )
    run_.source(result.source_ref(label="RDAP (registre du nom de domaine)"))

    if not result.ok or not isinstance(result.payload, dict):
        run_.error(
            "RDAP : impossible de lire l'enregistrement du domaine "
            f"({result.describe_error()}). Certains registres restreignent l'accès à leur "
            "service RDAP, ou le réseau de la machine d'analyse le bloque."
        )
        return

    infos = parse_rdap(result.payload)
    run_.data["enregistrement"] = infos
    jours = _jours_restants(infos["expiration"])
    run_.data["expiration_jours"] = jours

    if jours is not None:
        echeance = str(infos["expiration"])[:10]
        rappel_auto = (
            " Ce constat ne dit pas si le renouvellement automatique est actif : cette "
            "information n'est pas publique. Vérifiez-le chez votre bureau d'enregistrement."
        )
        if jours < 0:
            run_.add(
                "DNS_DOMAIN_EXPIRED", Severity.CRITIQUE,
                f"Le nom de domaine a expiré il y a {abs(jours)} jour(s)",
                f"Date d'expiration relevée auprès du registre : {echeance}.",
                "Un domaine expiré cesse de fonctionner : le site devient inaccessible et les "
                "emails ne sont plus distribués. Après une période de grâce, il peut être "
                "racheté par n'importe qui — y compris par un tiers qui en ferait un usage "
                "frauduleux en se faisant passer pour vous.",
                "Renouveler immédiatement auprès du bureau d'enregistrement, avant la fin de la "
                "période de rédemption, puis activer le renouvellement automatique.",
                [refs.ANSSI_NOMS_DE_DOMAINE, refs.CIS_INVENTAIRE],
                {"expiration": infos["expiration"]},
            )
        elif jours <= DOMAIN_EXPIRY_CRITICAL_DAYS:
            run_.add(
                "DNS_DOMAIN_EXPIRING", Severity.ELEVE,
                f"Le nom de domaine expire dans {jours} jour(s)",
                f"Date d'expiration relevée auprès du registre : {echeance}.",
                "À l'échéance, tout s'arrête d'un coup : site web, messagerie, applications "
                "qui dépendent du domaine. La remise en service n'est pas instantanée, et un "
                "domaine laissé expirer peut être capté par un tiers." + rappel_auto,
                "Renouveler dès maintenant, et activer le renouvellement automatique avec un "
                "moyen de paiement valide.",
                [refs.ANSSI_NOMS_DE_DOMAINE],
                {"expiration": infos["expiration"], "jours": jours},
            )
        elif jours <= DOMAIN_EXPIRY_WARNING_DAYS:
            run_.add(
                "DNS_DOMAIN_EXPIRING_SOON", Severity.MOYEN,
                f"Le nom de domaine expire dans {jours} jours",
                f"Date d'expiration relevée auprès du registre : {echeance}.",
                "L'échéance approche. Un domaine oublié à son renouvellement interrompt "
                "l'ensemble des services qui en dépendent." + rappel_auto,
                "Vérifier que le renouvellement automatique est actif et que le moyen de "
                "paiement associé est à jour.",
                [refs.ANSSI_NOMS_DE_DOMAINE],
                {"expiration": infos["expiration"], "jours": jours},
            )
        else:
            run_.add(
                "DNS_DOMAIN_EXPIRY_OK", Severity.INFO,
                f"Le nom de domaine est enregistré jusqu'au {echeance}",
                f"Expiration dans {jours} jours.",
                "L'échéance d'enregistrement est suffisamment lointaine.",
                "Conserver le renouvellement automatique et surveiller l'échéance.",
                [refs.ANSSI_NOMS_DE_DOMAINE],
            )

    if infos["expiration"] is not None or infos["statuts"]:
        if infos["verrou_transfert"]:
            run_.add(
                "DNS_DOMAIN_LOCKED", Severity.INFO,
                "Le transfert du domaine est verrouillé",
                "Statuts relevés : " + ", ".join(infos["statuts"]),
                "Le verrou empêche qu'un tiers fasse transférer votre domaine vers un autre "
                "bureau d'enregistrement à votre insu. C'est une bonne pratique.",
                "Maintenir ce verrou et protéger le compte du bureau d'enregistrement par une "
                "authentification multifacteur.",
                [refs.ANSSI_NOMS_DE_DOMAINE],
            )
        else:
            run_.add(
                "DNS_DOMAIN_NO_LOCK", Severity.MOYEN,
                "Aucun verrou de transfert sur le nom de domaine",
                "Statuts relevés : " + (", ".join(infos["statuts"]) or "aucun"),
                "Sans verrou, une personne ayant obtenu l'accès au compte du bureau "
                "d'enregistrement peut faire transférer le domaine ailleurs. Le détournement "
                "d'un nom de domaine est l'une des attaques les plus difficiles à défaire : "
                "l'attaquant contrôle alors le site, les emails et les certificats.",
                "Activer le verrou de transfert (« clientTransferProhibited ») chez le bureau "
                "d'enregistrement, et y imposer l'authentification multifacteur.",
                [refs.ANSSI_NOMS_DE_DOMAINE, refs.CIS_CONTROLS],
            )


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

    # ------------------------------------------- enregistrement du domaine --
    await check_domain_registration(ctx, run_)

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
