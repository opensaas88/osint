"""Module 5 — sous-domaines découverts via la transparence des certificats (crt.sh).

La transparence des certificats est un registre public : aucune sollicitation de
l'infrastructure de la cible n'est nécessaire. Les noms obtenus sont dédoublonnés
puis résolus, sans aucune connexion aux services qu'ils désignent.
"""

from __future__ import annotations

import asyncio

from .. import refs
from ..models import ModuleResult, ModuleStatus, Severity
from ..resolver import strip_root
from . import MODULE_LABELS, ModuleContext, ModuleRun

KEY = "subdomains"
LABEL = MODULE_LABELS[KEY]
WEIGHT = 5
DEPENDS_ON: tuple[str, ...] = ()
TIMEOUT = 180.0

CRTSH_URL = "https://crt.sh/"

#: Noms évoquant un environnement hors production ou un outil d'administration.
SENSITIVE_KEYWORDS: dict[str, str] = {
    "dev": "environnement de développement",
    "develop": "environnement de développement",
    "staging": "environnement de pré-production",
    "stage": "environnement de pré-production",
    "preprod": "environnement de pré-production",
    "test": "environnement de test",
    "qa": "environnement de recette",
    "uat": "environnement de recette",
    "demo": "environnement de démonstration",
    "sandbox": "environnement d'essai",
    "old": "ressource obsolète",
    "legacy": "ressource obsolète",
    "backup": "sauvegarde",
    "admin": "interface d'administration",
    "phpmyadmin": "administration de base de données",
    "jenkins": "chaîne d'intégration continue",
    "gitlab": "forge logicielle",
    "grafana": "supervision",
    "kibana": "supervision",
    "prometheus": "supervision",
    "vpn": "accès distant",
    "rdp": "accès distant",
    "citrix": "accès distant",
    "vcenter": "administration de virtualisation",
    "idrac": "administration matérielle",
    "ilo": "administration matérielle",
    "pve": "administration de virtualisation",
    "proxmox": "administration de virtualisation",
}


def parse_crtsh(payload) -> set[str]:
    """Extrait les noms de l'export JSON de crt.sh."""
    names: set[str] = set()
    if not isinstance(payload, list):
        return names
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            raw = entry.get(field)
            if not raw:
                continue
            for line in str(raw).split("\n"):
                name = line.strip().lower().rstrip(".")
                if name.startswith("*."):
                    name = name[2:]
                if name and " " not in name and "@" not in name:
                    names.add(name)
    return names


def classify_sensitive(name: str) -> list[str]:
    """Retourne les motifs sensibles présents dans un nom d'hôte."""
    labels = set(name.split("."))
    hits = []
    for keyword, meaning in SENSITIVE_KEYWORDS.items():
        if keyword in labels or any(label.startswith(f"{keyword}-") for label in labels):
            hits.append(f"{keyword} ({meaning})")
    return hits


async def run(ctx: ModuleContext) -> ModuleResult:
    """Énumère et résout les sous-domaines publiés dans les journaux de certificats."""
    run_ = ModuleRun(KEY)

    # crt.sh exécute une requête SQL lourde : l'historique complet échoue souvent en 502,
    # alors que la variante restreinte aux certificats valides répond. On tente donc
    # l'historique une seule fois, puis la variante légère, et on fusionne ce qui a abouti.
    attempts = (
        ({"q": f"%.{ctx.name}", "output": "json"}, "crt.sh (historique complet)", 1),
        (
            {"q": f"%.{ctx.name}", "output": "json", "exclude": "expired"},
            "crt.sh (certificats valides)",
            None,
        ),
    )
    names: set[str] = set()
    succeeded: list[str] = []
    for params, label, retries in attempts:
        result = await ctx.http.request(
            "crtsh", CRTSH_URL, params=params, timeout=ctx.settings.crtsh_timeout, retries=retries
        )
        run_.source(result.source_ref(label=label))
        if result.ok:
            names |= parse_crtsh(result.payload)
            succeeded.append(label)
        else:
            run_.error(f"{label} : {result.describe_error()}")

    if not succeeded:
        return run_.failed(
            "crt.sh n'a renvoyé aucun résultat exploitable (service momentanément saturé)"
        )
    run_.data["sources_utilisees"] = succeeded
    if len(succeeded) < len(attempts):
        run_.data["historique_partiel"] = True
    suffix = f".{ctx.name}"
    subdomains = sorted(n for n in names if n.endswith(suffix) and n != ctx.name)
    run_.data["discovered_count"] = len(subdomains)

    limit = max(1, int(ctx.settings.subdomain_resolve_limit))
    truncated = len(subdomains) > limit
    to_resolve = subdomains[:limit]
    if truncated:
        run_.error(
            f"{len(subdomains)} sous-domaines découverts, résolution limitée aux {limit} premiers "
            "(paramètre SUBDOMAIN_RESOLVE_LIMIT)"
        )

    async def resolve(name: str) -> dict:
        a_answer, cname_answer = await asyncio.gather(
            ctx.resolver.query(name, "A"), ctx.resolver.query(name, "CNAME")
        )
        cnames = [strip_root(c) for c in (cname_answer.records or a_answer.cnames)]
        return {
            "name": name,
            "a": list(a_answer.records),
            "cname": cnames,
            "resolves": bool(a_answer.records or cnames),
            "rcode": a_answer.rcode,
        }

    resolved = await asyncio.gather(*(resolve(n) for n in to_resolve)) if to_resolve else []
    alive = [r for r in resolved if r["resolves"]]
    dead = [r for r in resolved if not r["resolves"]]

    run_.data["records"] = resolved
    run_.data["alive"] = [r["name"] for r in alive]
    run_.data["dead"] = [r["name"] for r in dead]
    run_.data["truncated"] = truncated
    ips = sorted({ip for r in alive for ip in r["a"]})
    run_.data["ips"] = ips

    if not subdomains:
        run_.add(
            "SUBDOMAIN_NONE", Severity.INFO,
            "Aucun sous-domaine dans les journaux de certificats",
            f"crt.sh ne référence aucun certificat pour « *.{ctx.name} ».",
            "La surface exposée publiquement est réduite, ou les services utilisent des "
            "certificats sans nom de sous-domaine (rare).",
            "Aucune action nécessaire. Un inventaire interne reste utile pour confirmer.",
            [refs.CIS_INVENTAIRE],
        )
        return run_.done()

    run_.add(
        "SUBDOMAIN_INVENTORY", Severity.INFO,
        f"{len(subdomains)} sous-domaines publiés, dont {len(alive)} actifs",
        f"{len(subdomains)} noms distincts relevés dans les journaux de certificats ; "
        f"{len(alive)} résolvent aujourd'hui, {len(dead)} ne résolvent plus.",
        "Chaque certificat émis pour un sous-domaine est inscrit dans un registre public et "
        "consultable par n'importe qui : la liste de vos sous-domaines est donc connue des "
        "attaquants, y compris ceux que vous pensiez confidentiels.",
        "Tenir à jour l'inventaire de ces noms et retirer les enregistrements DNS devenus "
        "inutiles. Pour les services internes, préférer des certificats d'une autorité privée.",
        [refs.CIS_INVENTAIRE, refs.ANSSI_CARTOGRAPHIE],
        {"total": len(subdomains), "actifs": len(alive), "inactifs": len(dead)},
    )

    sensibles = {r["name"]: classify_sensitive(r["name"]) for r in alive}
    sensibles = {name: hits for name, hits in sensibles.items() if hits}
    if sensibles:
        detail = "; ".join(f"{name} → {', '.join(hits)}" for name, hits in list(sensibles.items())[:10])
        run_.add(
            "SUBDOMAIN_SENSITIVE_NAMES", Severity.MOYEN,
            f"{len(sensibles)} sous-domaines actifs portent un nom révélateur",
            f"Exemples : {detail}",
            "Les noms d'hôtes renseignent sur votre infrastructure : un sous-domaine nommé "
            "« staging » ou « vcenter » signale à un attaquant où chercher un environnement "
            "moins surveillé ou une console d'administration. Aucune connexion n'a été établie "
            "vers ces hôtes : seul leur nom est analysé.",
            "Vérifier que ces services ne sont pas joignables depuis Internet, les placer "
            "derrière un VPN ou un filtrage par IP, et éviter les noms descriptifs.",
            [refs.ANSSI_CARTOGRAPHIE, refs.CIS_INVENTAIRE],
            {"noms": sensibles},
        )

    if dead:
        run_.add(
            "SUBDOMAIN_DANGLING", Severity.FAIBLE,
            f"{len(dead)} sous-domaines certifiés ne résolvent plus",
            "Exemples : " + ", ".join(r["name"] for r in dead[:10]),
            "Un certificat a été émis pour ces noms, mais ils ne pointent plus vers rien. "
            "C'est souvent le signe d'un service démantelé dont l'entrée DNS a été oubliée. "
            "Si l'entrée existe encore et pointe vers un hébergeur, elle peut être récupérée "
            "par un tiers.",
            "Supprimer les enregistrements DNS résiduels et révoquer les certificats inutilisés.",
            [refs.ANSSI_NOMS_DE_DOMAINE, refs.CIS_INVENTAIRE],
            {"noms": [r["name"] for r in dead[:50]]},
        )

    return run_.done(status=ModuleStatus.PARTIAL if run_.errors else ModuleStatus.OK)
