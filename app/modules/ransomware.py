"""Module 2 — revendications de rançongiciel (ransomware.live).

L'API publique de ransomware.live agrège les victimes revendiquées sur les sites
de fuite des groupes de rançongiciels. La recherche étant approximative, le module
distingue une correspondance exacte de domaine d'une simple ressemblance de nom.

Choix éthique : l'URL de revendication pointe vers un site .onion diffusant les
données volées. Son existence est signalée, l'adresse n'est jamais enregistrée ni
affichée.
"""

from __future__ import annotations

import re
from typing import Any

from .. import refs
from ..models import ModuleResult, ModuleStatus, Severity
from . import MODULE_LABELS, ModuleContext, ModuleRun

KEY = "ransomware"
LABEL = MODULE_LABELS[KEY]
WEIGHT = 10
DEPENDS_ON: tuple[str, ...] = ()
TIMEOUT = 60.0

SEARCH_URL = "https://api.ransomware.live/v2/searchvictims/{keyword}"

#: Champs conservés d'une victime revendiquée (whitelist : pas d'URL de fuite).
VICTIM_FIELDS = ("victim", "domain", "group", "attackdate", "discovered", "country", "activity")


def normalise(value: str | None) -> str:
    return (value or "").strip().lower().rstrip(".")


def classify_match(victim: dict[str, Any], domain: str, organisation: str) -> str | None:
    """Qualifie la correspondance : « exact », « apparente » ou None (hors sujet)."""
    victim_domain = normalise(victim.get("domain"))
    if victim_domain:
        if victim_domain == domain:
            return "exact"
        if victim_domain.endswith(f".{domain}") or domain.endswith(f".{victim_domain}"):
            return "exact"

    name = normalise(victim.get("victim"))
    if organisation and len(organisation) >= 4 and name:
        if re.search(rf"\b{re.escape(organisation)}\b", name):
            return "apparente"
    return None


async def run(ctx: ModuleContext) -> ModuleResult:
    """Recherche le domaine et le nom de l'organisation parmi les victimes revendiquées."""
    run_ = ModuleRun(KEY)
    domain = normalise(ctx.name)
    organisation = domain.split(".")[0]

    keywords = [domain]
    if organisation and organisation != domain:
        keywords.append(organisation)

    victims: list[dict[str, Any]] = []
    answered = False
    for keyword in keywords:
        result = await ctx.http.request("ransomware", SEARCH_URL.format(keyword=keyword))
        run_.source(result.source_ref(label=f"ransomware.live — recherche « {keyword} »"))
        if result.status == 404:
            answered = True
            continue
        if not result.ok:
            run_.error(f"ransomware.live (« {keyword} ») : {result.describe_error()}")
            continue
        answered = True
        if isinstance(result.payload, list):
            victims.extend(v for v in result.payload if isinstance(v, dict))

    if not answered:
        return run_.failed("ransomware.live n'a renvoyé aucune réponse exploitable")

    exacts: list[dict[str, Any]] = []
    apparentes: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for victim in victims:
        kind = classify_match(victim, domain, organisation)
        if kind is None:
            continue
        identity = (
            normalise(victim.get("victim")),
            normalise(victim.get("group")),
            normalise(victim.get("attackdate")),
        )
        if identity in seen:
            continue
        seen.add(identity)
        entry = {field: victim.get(field) for field in VICTIM_FIELDS}
        entry["revendication_publiee"] = bool(victim.get("claim_url"))
        (exacts if kind == "exact" else apparentes).append(entry)

    run_.data["correspondances_exactes"] = exacts
    run_.data["correspondances_apparentes"] = apparentes
    run_.data["victimes_examinees"] = len(victims)

    for entry in exacts:
        groupe = entry.get("group") or "groupe non identifié"
        date = (entry.get("attackdate") or entry.get("discovered") or "")[:10] or "date inconnue"
        run_.add(
            "RANSOMWARE_CLAIMED_VICTIM", Severity.CRITIQUE,
            f"Organisation revendiquée comme victime du rançongiciel {groupe}",
            f"Victime : {entry.get('victim')} — domaine : {entry.get('domain')} — "
            f"groupe : {groupe} — revendication du {date}."
            + (" Une publication de données existe sur le site de fuite du groupe."
               if entry.get("revendication_publiee") else ""),
            "Un groupe de rançongiciel affirme publiquement avoir compromis cette organisation "
            "et publié ses données. Cela signifie qu'une intrusion a eu lieu : les données "
            "internes sont probablement en circulation, et les identifiants dérobés servent "
            "souvent à de nouvelles attaques, y compris contre vos clients et partenaires. "
            "DomainExposure ne consulte ni ne télécharge aucune donnée publiée.",
            "Déclencher la procédure de réponse à incident : isoler les systèmes concernés, "
            "déposer plainte, notifier la CNIL sous 72 h en cas de données personnelles "
            "(article 33 du RGPD), réinitialiser l'ensemble des accès et faire intervenir un "
            "prestataire de réponse à incident.",
            [refs.ANSSI_ATTAQUE_PAR_RANCON, refs.CIS_CONTROLS],
            entry,
        )

    for entry in apparentes:
        groupe = entry.get("group") or "groupe non identifié"
        date = (entry.get("attackdate") or entry.get("discovered") or "")[:10] or "date inconnue"
        run_.add(
            "RANSOMWARE_POSSIBLE_HOMONYM", Severity.MOYEN,
            f"Victime au nom proche revendiquée par {groupe} — à confirmer",
            f"Victime : {entry.get('victim')} — domaine déclaré : "
            f"{entry.get('domain') or 'aucun'} — groupe : {groupe} — {date}.",
            "Une victime portant un nom proche de votre organisation apparaît sur un site de "
            "fuite, mais le domaine ne correspond pas exactement. Il peut s'agir d'une "
            "homonymie, d'une filiale, ou d'une entité du même groupe. Ce constat demande une "
            "vérification humaine avant toute conclusion.",
            "Vérifier s'il s'agit d'une entité liée (filiale, ancienne marque, prestataire). "
            "Si oui, traiter comme un incident ; sinon, écarter le constat.",
            [refs.ANSSI_ATTAQUE_PAR_RANCON],
            entry,
        )

    if not exacts and not apparentes:
        run_.add(
            "RANSOMWARE_NONE", Severity.INFO,
            "Aucune revendication de rançongiciel",
            f"{len(victims)} fiches examinées pour « {' », « '.join(keywords)} » : aucune "
            "correspondance avec ce domaine.",
            "L'organisation n'apparaît pas parmi les victimes revendiquées publiquement par les "
            "groupes de rançongiciels suivis. Les groupes ne publient toutefois que les victimes "
            "qui refusent de payer : l'absence de revendication ne prouve pas l'absence "
            "d'attaque.",
            "Maintenir les sauvegardes hors ligne testées et le plan de réponse à incident.",
            [refs.ANSSI_ATTAQUE_PAR_RANCON],
        )

    return run_.done(status=ModuleStatus.PARTIAL if run_.errors else ModuleStatus.OK)
