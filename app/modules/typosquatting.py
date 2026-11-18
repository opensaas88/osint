"""Module 8 — domaines ressemblants (typosquatting), via dnstwist.

dnstwist n'est utilisé que comme générateur de permutations : la résolution est
confiée au résolveur de l'application, ce qui garantit des délais maîtrisés, un
module testable et aucune contention de threads.

Un domaine ressemblant qui pointe vers la même infrastructure que le domaine
analysé est considéré comme un dépôt défensif du propriétaire, et non comme une
menace.
"""

from __future__ import annotations

import asyncio

from .. import refs
from ..models import ModuleResult, ModuleStatus, Severity
from . import MODULE_LABELS, ModuleContext, ModuleRun

KEY = "typosquatting"
LABEL = MODULE_LABELS[KEY]
WEIGHT = 5
DEPENDS_ON: tuple[str, ...] = ()
TIMEOUT = 150.0

#: Familles de permutations, des plus exploitées en hameçonnage aux moins probables.
#: Les homoglyphes sont très nombreux (plus de 1700 pour un domaine court) : ils
#: ferment la liste afin de ne pas épuiser le budget de résolutions.
FAMILY_PRIORITY = (
    "omission", "transposition", "replacement", "repetition", "insertion",
    "hyphenation", "vowel-swap", "plural", "addition", "bitsquatting",
    "various", "subdomain", "dictionary", "tld-swap", "homoglyph",
)


def generate_permutations(domain: str, limit: int) -> tuple[list[dict], int]:
    """Génère les permutations dnstwist et retient les plus pertinentes.

    Retourne `(permutations retenues, nombre total généré)`.
    """
    import dnstwist

    fuzzer = dnstwist.Fuzzer(domain)
    fuzzer.generate()
    everything = [
        p for p in fuzzer.permutations()
        if p.get("domain") and p.get("domain") != domain and p.get("fuzzer") != "*original"
    ]

    by_family: dict[str, list[dict]] = {}
    for permutation in everything:
        by_family.setdefault(permutation.get("fuzzer", "autre"), []).append(permutation)

    retained: list[dict] = []
    for family in FAMILY_PRIORITY:
        for permutation in by_family.pop(family, []):
            if len(retained) >= limit:
                return retained, len(everything)
            retained.append(permutation)
    for remaining in by_family.values():  # familles non listées explicitement
        for permutation in remaining:
            if len(retained) >= limit:
                return retained, len(everything)
            retained.append(permutation)
    return retained, len(everything)


async def run(ctx: ModuleContext) -> ModuleResult:
    """Recherche les domaines ressemblants effectivement enregistrés."""
    run_ = ModuleRun(KEY)

    if not ctx.settings.enable_typosquatting:
        return run_.skipped("module désactivé par la configuration (ENABLE_TYPOSQUATTING)")

    limit = max(10, int(ctx.settings.typo_max_permutations))
    try:
        permutations, total = await asyncio.to_thread(
            generate_permutations, ctx.name, limit
        )
    except Exception as exc:
        return run_.failed(f"génération des permutations impossible ({type(exc).__name__})")

    run_.data["permutations_generees"] = total
    run_.data["permutations_testees"] = len(permutations)
    run_.source(None)

    legitimate_ips = set(ctx.recon.ips)

    async def probe(permutation: dict) -> dict | None:
        name = permutation["domain"]
        a_answer = await ctx.resolver.query(name, "A")
        records = list(a_answer.records)
        if not records:
            ns_answer = await ctx.resolver.query(name, "NS")
            if not ns_answer.records:
                return None
            return {
                "domaine": name,
                "famille": permutation.get("fuzzer"),
                "ips": [],
                "enregistre": True,
                "actif": False,
                "mx": [],
                "defensif": False,
            }
        mx_answer = await ctx.resolver.query(name, "MX")
        return {
            "domaine": name,
            "famille": permutation.get("fuzzer"),
            "ips": records,
            "enregistre": True,
            "actif": True,
            "mx": list(mx_answer.records),
            "defensif": bool(legitimate_ips and set(records) & legitimate_ips),
        }

    found = [r for r in await asyncio.gather(*(probe(p) for p in permutations)) if r]
    defensifs = [r for r in found if r["defensif"]]
    tiers = [r for r in found if not r["defensif"]]
    avec_mx = [r for r in tiers if r["mx"]]

    run_.data["enregistres"] = found
    run_.data["tiers"] = tiers
    run_.data["defensifs"] = defensifs

    if avec_mx:
        detail = ", ".join(f"{r['domaine']} ({r['famille']})" for r in avec_mx[:10])
        run_.add(
            "TYPO_MAIL_CAPABLE", Severity.ELEVE,
            f"{len(avec_mx)} domaine(s) ressemblant(s) sont configurés pour envoyer des emails",
            f"Domaines concernés : {detail}",
            "Ces domaines imitent le vôtre et disposent d'un serveur de messagerie. Ils sont "
            "donc prêts à envoyer des emails qui sembleront venir de votre organisation, vers "
            "vos clients, vos fournisseurs ou vos collaborateurs — c'est le montage classique "
            "de la fraude au virement.",
            "Signaler ces domaines auprès du registrar et de la plateforme Pharos, surveiller "
            "leur activité, et déposer défensivement les variantes les plus proches de votre "
            "marque. Sensibiliser la comptabilité à la vérification des changements de "
            "coordonnées bancaires.",
            [refs.ANSSI_NOMS_DE_DOMAINE, refs.CIS_EMAIL],
            {"domaines": avec_mx[:30]},
        )

    autres = [r for r in tiers if not r["mx"]]
    if autres:
        detail = ", ".join(f"{r['domaine']} ({r['famille']})" for r in autres[:10])
        run_.add(
            "TYPO_REGISTERED_BY_THIRD_PARTY", Severity.MOYEN,
            f"{len(autres)} domaine(s) ressemblant(s) sont enregistrés par des tiers",
            f"Domaines concernés : {detail}",
            "Des domaines très proches du vôtre appartiennent à d'autres personnes. Ils peuvent "
            "servir à héberger une fausse page de connexion, ou être activés plus tard pour une "
            "campagne de hameçonnage visant vos utilisateurs.",
            "Surveiller ces domaines, et envisager le dépôt défensif des variantes les plus "
            "crédibles (inversion de lettres, tiret, extension proche).",
            [refs.ANSSI_NOMS_DE_DOMAINE],
            {"domaines": autres[:30]},
        )

    if defensifs:
        run_.add(
            "TYPO_DEFENSIVE_REGISTRATIONS", Severity.INFO,
            f"{len(defensifs)} domaine(s) ressemblant(s) pointent vers votre infrastructure",
            "Domaines : " + ", ".join(r["domaine"] for r in defensifs[:10]),
            "Ces variantes pointent vers les mêmes adresses IP que votre domaine : il s'agit "
            "très probablement de dépôts défensifs que vous maîtrisez déjà. C'est une bonne "
            "pratique.",
            "Vérifier que ces domaines sont bien les vôtres et qu'ils redirigent en HTTPS vers "
            "le domaine principal.",
            [refs.ANSSI_NOMS_DE_DOMAINE],
        )

    if not found:
        run_.add(
            "TYPO_NONE", Severity.INFO,
            "Aucun domaine ressemblant enregistré parmi les variantes testées",
            f"{len(permutations)} variantes testées sur {total} générées : aucune n'est "
            "enregistrée.",
            "Aucune usurpation de nom de domaine détectée à ce jour parmi les variantes les plus "
            "probables. La vérification ne couvre pas toutes les combinaisons possibles.",
            "Renouveler cette vérification périodiquement et surveiller les dépôts de domaines "
            "proches de votre marque.",
            [refs.ANSSI_NOMS_DE_DOMAINE],
        )

    if len(permutations) < total:
        run_.data["troncature"] = True
        run_.error(
            f"{total} variantes générées, {len(permutations)} testées (limite "
            "TYPO_MAX_PERMUTATIONS) : les homoglyphes les moins probables ont été écartés"
        )

    return run_.done(status=ModuleStatus.PARTIAL if run_.errors else ModuleStatus.OK)
