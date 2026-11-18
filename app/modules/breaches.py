"""Module 1 — fuites de données : métadonnées publiques, jamais de contenu.

Sources :
  * Have I Been Pwned, endpoint public `/breaches?Domain=` : fuites ayant touché
    le site du domaine lui-même. Aucune clé nécessaire.
  * Have I Been Pwned Domain Search : comptes du domaine apparaissant dans des
    fuites. Nécessite une clé ET la case « domaine vérifié » cochée ; les adresses
    sont masquées.
  * Have I Been Pwned Stealer Logs : identifiants capturés par un logiciel
    voleur (infostealer) sur des postes réellement infectés. Deux angles — les
    comptes du domaine de messagerie (vos collaborateurs) et les comptes ayant
    saisi leurs identifiants sur votre site (vos utilisateurs). Mêmes conditions :
    clé de palier « Pro » et domaine vérifié dans le tableau de bord HIBP.
  * LeakCheck et Intelligence X, optionnels, en mode métadonnées uniquement.

Règle absolue : aucun mot de passe, aucune empreinte, aucune donnée personnelle en
clair n'est récupéré, stocké ni affiché. Seules les métadonnées de fuite sont
conservées (nom, date, volume, catégories de données exposées).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from .. import refs
from ..models import ModuleResult, ModuleStatus, Severity
from ..sanitize import mask_email, mask_emails_in_text, pick
from . import MODULE_LABELS, ModuleContext, ModuleRun

KEY = "breaches"
LABEL = MODULE_LABELS[KEY]
WEIGHT = 15
DEPENDS_ON: tuple[str, ...] = ()
TIMEOUT = 90.0

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_DOMAIN_SEARCH_URL = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
HIBP_STEALER_EMAIL_DOMAIN_URL = (
    "https://haveibeenpwned.com/api/v3/stealerLogsByEmailDomain/{domain}"
)
HIBP_STEALER_WEBSITE_DOMAIN_URL = (
    "https://haveibeenpwned.com/api/v3/stealerLogsByWebsiteDomain/{domain}"
)
LEAKCHECK_URL = "https://leakcheck.io/api/v2/query/{query}"
INTELX_SEARCH_URL = "https://2.intelx.io/phonebook/search"

#: Champs conservés d'une fuite HIBP (whitelist stricte).
BREACH_FIELDS = (
    "Name", "Title", "Domain", "BreachDate", "AddedDate", "PwnCount", "DataClasses",
    "IsVerified", "IsSensitive", "IsRetired", "IsStealerLog", "IsMalware", "IsSpamList",
)

#: Catégories de données dont l'exposition est la plus lourde de conséquences.
CRITICAL_DATA_CLASSES = {
    "passwords", "historical passwords", "partial credit card data", "credit cards",
    "bank account numbers", "government issued ids", "social security numbers",
    "security questions and answers", "auth tokens", "encrypted keys", "private keys",
    "biometric data", "health insurance information", "medical conditions",
}
_TAG_RE = re.compile(r"<[^>]+>")


def _clean_description(raw: str | None) -> str:
    """Nettoie une description HIBP : balisage retiré, adresses masquées, longueur bornée.

    Le masquage est appliqué ici, à la source, en plus du filet de sécurité
    appliqué par l'orchestrateur : un module doit rester sûr pris isolément.
    """
    if not raw:
        return ""
    text = _TAG_RE.sub("", raw).replace("&quot;", '"').replace("&amp;", "&")
    text = mask_emails_in_text(" ".join(text.split()))
    return text[:600] + (" […]" if len(text) > 600 else "")


def _years_since(date_str: str | None) -> float | None:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(date_str, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return (datetime.now(UTC) - parsed).days / 365.25
    return None


def breach_severity(breach: dict[str, Any]) -> Severity:
    """Gravité d'une fuite ayant touché le site, selon sa nature et son ancienneté."""
    classes = {str(c).lower() for c in breach.get("DataClasses") or []}
    age = _years_since(breach.get("BreachDate"))
    sensitive = bool(classes & CRITICAL_DATA_CLASSES)
    verified = bool(breach.get("IsVerified", True))

    if sensitive:
        severity = Severity.CRITIQUE if (age is not None and age <= 3) else Severity.ELEVE
    else:
        severity = Severity.MOYEN

    if not verified:  # fuite non confirmée : on tempère d'un cran
        severity = {
            Severity.CRITIQUE: Severity.ELEVE,
            Severity.ELEVE: Severity.MOYEN,
            Severity.MOYEN: Severity.FAIBLE,
        }.get(severity, severity)

    if not sensitive and age is not None and age > 8:
        severity = Severity.FAIBLE
    return severity


async def _hibp_site_breaches(ctx: ModuleContext, run_: ModuleRun) -> list[dict[str, Any]]:
    """Fuites ayant touché le site du domaine (endpoint public, sans clé)."""
    result = await ctx.http.request(
        "hibp", HIBP_BREACHES_URL, params={"Domain": ctx.name}
    )
    run_.source(result.source_ref(label="Have I Been Pwned — fuites du domaine"))
    if not result.ok:
        run_.error(f"Have I Been Pwned (fuites du site) : {result.describe_error()}")
        return []
    if not isinstance(result.payload, list):
        return []
    return [pick(b, BREACH_FIELDS) | {"Description": _clean_description(b.get("Description"))}
            for b in result.payload if isinstance(b, dict)]


async def _hibp_domain_search(ctx: ModuleContext, run_: ModuleRun) -> dict[str, Any] | None:
    """Comptes du domaine présents dans des fuites. Clé + domaine vérifié requis."""
    key = ctx.settings.key("hibp_api_key")
    if not key:
        return None
    result = await ctx.http.request(
        "hibp",
        HIBP_DOMAIN_SEARCH_URL.format(domain=ctx.name),
        headers={"hibp-api-key": key},
        use_cache=True,
    )
    run_.source(result.source_ref(label="Have I Been Pwned — Domain Search"))
    if result.status == 404:
        return {"comptes": 0, "par_fuite": {}, "exemples": []}
    if not result.ok:
        run_.error(f"Have I Been Pwned (Domain Search) : {result.describe_error()}")
        return None
    payload = result.payload if isinstance(result.payload, dict) else {}

    par_fuite: dict[str, int] = {}
    exemples: list[str] = []
    for alias, breaches in payload.items():
        for name in breaches or []:
            par_fuite[name] = par_fuite.get(name, 0) + 1
        if len(exemples) < 10:
            exemples.append(mask_email(f"{alias}@{ctx.name}"))
    return {"comptes": len(payload), "par_fuite": par_fuite, "exemples": exemples}


def _explain_stealer_error(result) -> str:
    """Message d'erreur spécifique aux endpoints « stealer logs »."""
    if result.status == 403:
        return (
            "accès refusé (403) : le domaine doit d'abord être ajouté et vérifié dans le "
            "tableau de bord de recherche par domaine de Have I Been Pwned"
        )
    if result.status == 401:
        return (
            "clé refusée (401) : ces recherches exigent une clé de palier « Pro »"
        )
    return result.describe_error()


async def _hibp_stealer_logs_email_domain(
    ctx: ModuleContext, run_: ModuleRun
) -> dict[str, Any] | None:
    """Comptes du domaine de messagerie dont les identifiants ont été volés.

    Réponse HIBP : un dictionnaire alias -> domaines des services concernés,
    par exemple `{"jean": ["netflix.com", "spotify.com"]}`. Les alias sont
    masqués ; les domaines de services, eux, ne sont pas des données
    personnelles et sont conservés tels quels car ce sont eux qui indiquent
    quels accès renouveler.
    """
    key = ctx.settings.key("hibp_api_key")
    if not key:
        return None
    result = await ctx.http.request(
        "hibp",
        HIBP_STEALER_EMAIL_DOMAIN_URL.format(domain=ctx.name),
        headers={"hibp-api-key": key},
    )
    run_.source(
        result.source_ref(
            label="Have I Been Pwned — journaux d'infostealers (domaine de messagerie)"
        )
    )
    if result.status == 404:
        return {"comptes": 0, "services": [], "exemples": []}
    if not result.ok:
        run_.error(f"Have I Been Pwned (infostealers, messagerie) : {_explain_stealer_error(result)}")
        return None

    payload = result.payload if isinstance(result.payload, dict) else {}
    services: set[str] = set()
    exemples: list[dict[str, Any]] = []
    for alias, domaines in payload.items():
        domaines = [str(d) for d in (domaines or [])]
        services.update(domaines)
        if len(exemples) < 10:
            exemples.append(
                {"compte": mask_email(f"{alias}@{ctx.name}"), "services": sorted(domaines)[:8]}
            )
    return {"comptes": len(payload), "services": sorted(services), "exemples": exemples}


async def _hibp_stealer_logs_website_domain(
    ctx: ModuleContext, run_: ModuleRun
) -> dict[str, Any] | None:
    """Comptes ayant saisi leurs identifiants sur ce site et capturés par un infostealer.

    Réponse HIBP : un tableau d'adresses complètes. Ces adresses appartiennent à
    des tiers (vos utilisateurs) : seules leur volumétrie, la répartition par
    fournisseur de messagerie et quelques exemples masqués sont conservés. La
    liste nominative, nécessaire pour notifier les personnes, reste consultable
    dans le tableau de bord Have I Been Pwned.
    """
    key = ctx.settings.key("hibp_api_key")
    if not key:
        return None
    result = await ctx.http.request(
        "hibp",
        HIBP_STEALER_WEBSITE_DOMAIN_URL.format(domain=ctx.name),
        headers={"hibp-api-key": key},
    )
    run_.source(result.source_ref(label="Have I Been Pwned — journaux d'infostealers (site web)"))
    if result.status == 404:
        return {"comptes": 0, "par_fournisseur": {}, "exemples": []}
    if not result.ok:
        run_.error(f"Have I Been Pwned (infostealers, site web) : {_explain_stealer_error(result)}")
        return None

    adresses = [str(a) for a in (result.payload or []) if isinstance(a, str)]
    par_fournisseur: dict[str, int] = {}
    for adresse in adresses:
        fournisseur = adresse.rpartition("@")[2].lower() or "inconnu"
        par_fournisseur[fournisseur] = par_fournisseur.get(fournisseur, 0) + 1
    return {
        "comptes": len(adresses),
        "par_fournisseur": dict(sorted(par_fournisseur.items(), key=lambda kv: -kv[1])),
        "exemples": [mask_email(a) for a in adresses[:10]],
    }


async def _leakcheck(ctx: ModuleContext, run_: ModuleRun) -> dict[str, Any] | None:
    """LeakCheck, en mode métadonnées : agrégation par source, sans adresse en clair."""
    key = ctx.settings.key("leakcheck_api_key")
    if not key:
        return None
    result = await ctx.http.request(
        "leakcheck",
        LEAKCHECK_URL.format(query=ctx.name),
        params={"type": "domain"},
        headers={"X-API-Key": key},
    )
    run_.source(result.source_ref(label="LeakCheck"))
    if not result.ok or not isinstance(result.payload, dict):
        run_.error(f"LeakCheck : {result.describe_error()}")
        return None
    entries = result.payload.get("result") or []
    par_source: dict[str, int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        name = source.get("name") if isinstance(source, dict) else str(source or "inconnue")
        par_source[str(name)] = par_source.get(str(name), 0) + 1
    return {"comptes": int(result.payload.get("found") or len(entries)), "par_source": par_source}


async def _intelx(ctx: ModuleContext, run_: ModuleRun) -> dict[str, Any] | None:
    """Intelligence X, en mode métadonnées : volumétrie par type de sélecteur."""
    key = ctx.settings.key("intelx_api_key")
    if not key:
        return None
    started = await ctx.http.request(
        "intelx",
        INTELX_SEARCH_URL,
        method="POST",
        headers={"x-key": key, "content-type": "application/json"},
        data={"term": ctx.name, "maxresults": 100, "media": 0, "target": 0},
        use_cache=False,
    )
    run_.source(started.source_ref(label="Intelligence X"))
    if not started.ok or not isinstance(started.payload, dict):
        run_.error(f"Intelligence X : {started.describe_error()}")
        return None
    search_id = started.payload.get("id")
    if not search_id:
        run_.error("Intelligence X : identifiant de recherche absent de la réponse")
        return None
    results = await ctx.http.request(
        "intelx",
        f"{INTELX_SEARCH_URL}/result",
        params={"id": search_id, "limit": 100},
        headers={"x-key": key},
        use_cache=False,
    )
    if not results.ok or not isinstance(results.payload, dict):
        run_.error(f"Intelligence X (résultats) : {results.describe_error()}")
        return None
    selectors = results.payload.get("selectors") or []
    # Seule la volumétrie est conservée : aucun sélecteur (adresse, URL) n'est stocké.
    return {"selecteurs": len(selectors)}


async def run(ctx: ModuleContext) -> ModuleResult:
    """Recense les fuites connues concernant le domaine, en métadonnées uniquement."""
    run_ = ModuleRun(KEY)
    desactivees: list[dict[str, str]] = []

    # --------------------------------------- fuites ayant touché le site ----
    breaches = await _hibp_site_breaches(ctx, run_)
    run_.data["fuites_du_site"] = breaches
    run_.data["chronologie"] = sorted(
        (
            {
                "nom": b.get("Title") or b.get("Name"),
                "date": b.get("BreachDate"),
                "comptes": b.get("PwnCount"),
                "categories": b.get("DataClasses") or [],
                "verifiee": bool(b.get("IsVerified", True)),
            }
            for b in breaches
        ),
        key=lambda item: item["date"] or "",
    )

    for breach in breaches:
        titre = breach.get("Title") or breach.get("Name") or "fuite sans nom"
        classes = breach.get("DataClasses") or []
        comptes = breach.get("PwnCount") or 0
        date = breach.get("BreachDate") or "date inconnue"
        sensibles = sorted({str(c) for c in classes if str(c).lower() in CRITICAL_DATA_CLASSES})
        run_.add(
            f"BREACH_SITE_{(breach.get('Name') or 'INCONNUE').upper()[:40]}",
            breach_severity(breach),
            f"Fuite de données « {titre} » ({date})",
            f"{comptes:,} comptes concernés. Catégories exposées : "
            f"{', '.join(str(c) for c in classes) or 'non précisées'}."
            f"{' Fuite non confirmée par HIBP.' if not breach.get('IsVerified', True) else ''}"
            .replace(",", " "),
            "Le service hébergé sur ce domaine a subi une fuite : les données de ses "
            "utilisateurs circulent publiquement. "
            + (
                f"Les éléments les plus sensibles exposés sont : {', '.join(sensibles)}. "
                "Ces données servent directement à des tentatives de connexion sur d'autres "
                "services, où les utilisateurs réutilisent souvent le même mot de passe."
                if sensibles
                else "Les données exposées facilitent le hameçonnage ciblé et l'usurpation "
                "d'identité, même sans mot de passe."
            )
            + " DomainExposure ne récupère que la fiche descriptive de la fuite : aucun mot de "
            "passe ni donnée personnelle n'est consulté ni stocké.",
            "Imposer la réinitialisation des mots de passe concernés, activer "
            "l'authentification multifacteur, et informer les personnes concernées conformément "
            "à l'article 34 du RGPD si la notification n'a pas déjà eu lieu.",
            [refs.ANSSI_MOTS_DE_PASSE, refs.OWASP_CREDENTIAL_STUFFING, refs.CIS_CONTROLS],
            {k: v for k, v in breach.items() if k != "Description"},
        )

    if not breaches:
        run_.add(
            "BREACH_SITE_NONE", Severity.INFO,
            "Aucune fuite connue concernant ce site",
            f"Have I Been Pwned ne référence aucune fuite pour le domaine {ctx.name}.",
            "Aucune compromission publiquement documentée du service hébergé sur ce domaine. "
            "Cela ne garantit pas l'absence de fuite : seules les fuites rendues publiques et "
            "analysées sont répertoriées.",
            "Maintenir une veille et surveiller les notifications de fuite.",
            [refs.OWASP_CREDENTIAL_STUFFING],
        )

    # --------------------------------------------- comptes dans les fuites --
    if not ctx.settings.has_key("hibp_api_key"):
        desactivees.append(
            {
                "source": "HIBP — journaux d'infostealers",
                "raison": "clé HIBP_API_KEY absente : ces recherches exigent une clé de "
                          "palier « Pro »",
            }
        )
        desactivees.append(
            {
                "source": "HIBP Domain Search",
                "raison": "clé HIBP_API_KEY absente (offre payante) — les fuites du site "
                          "restent listées via l'endpoint public",
            }
        )
    elif not ctx.consents.domain_verified:
        for source in ("HIBP Domain Search", "HIBP — journaux d'infostealers"):
            desactivees.append(
                {
                    "source": source,
                    "raison": "la case « domaine vérifié auprès de HIBP » n'a pas été cochée : "
                              "la recherche de comptes est volontairement bloquée",
                }
            )
    else:
        domain_search = await _hibp_domain_search(ctx, run_)
        if domain_search is not None:
            run_.data["comptes_exposes"] = domain_search
            comptes = domain_search["comptes"]
            if comptes:
                severity = (
                    Severity.ELEVE if comptes >= 10
                    else Severity.MOYEN if comptes >= 3
                    else Severity.FAIBLE
                )
                run_.add(
                    "BREACH_DOMAIN_ACCOUNTS", severity,
                    f"{comptes} adresse(s) du domaine apparaissent dans des fuites",
                    "Fuites concernées : "
                    + (", ".join(f"{n} ({c})" for n, c in domain_search["par_fuite"].items())
                       or "non précisées")
                    + f". Exemples masqués : {', '.join(domain_search['exemples'])}.",
                    "Des adresses professionnelles de ce domaine figurent dans des fuites "
                    "publiques. Les attaquants s'en servent pour deviner les identifiants de vos "
                    "services internes, ou pour un hameçonnage crédible visant nommément vos "
                    "collaborateurs. Les adresses ne sont affichées que masquées, et uniquement "
                    "parce que la propriété du domaine a été attestée.",
                    "Forcer le renouvellement des mots de passe des comptes concernés, déployer "
                    "l'authentification multifacteur, et sensibiliser les personnes identifiées "
                    "au hameçonnage ciblé.",
                    [refs.ANSSI_MOTS_DE_PASSE, refs.OWASP_CREDENTIAL_STUFFING],
                    {"comptes": comptes, "par_fuite": domain_search["par_fuite"]},
                )
            else:
                run_.add(
                    "BREACH_DOMAIN_ACCOUNTS_NONE", Severity.INFO,
                    "Aucune adresse du domaine dans les fuites référencées",
                    "La recherche par domaine ne remonte aucun compte.",
                    "Aucune adresse de ce domaine n'apparaît dans les fuites indexées par Have "
                    "I Been Pwned.",
                    "Maintenir la surveillance : l'inscription aux notifications de domaine "
                    "alerte automatiquement en cas de nouvelle fuite.",
                    [refs.OWASP_CREDENTIAL_STUFFING],
                )

        # ------------------------------------- journaux d'infostealers ----
        collaborateurs = await _hibp_stealer_logs_email_domain(ctx, run_)
        utilisateurs = await _hibp_stealer_logs_website_domain(ctx, run_)
        run_.data["stealer_logs"] = {
            "domaine_de_messagerie": collaborateurs,
            "site_web": utilisateurs,
        }

        if collaborateurs and collaborateurs["comptes"]:
            services = collaborateurs["services"]
            exemples = ", ".join(
                f"{e['compte']} ({', '.join(e['services']) or 'service non précisé'})"
                for e in collaborateurs["exemples"][:6]
            )
            run_.add(
                "BREACH_STEALER_LOG_STAFF", Severity.CRITIQUE,
                f"{collaborateurs['comptes']} compte(s) du domaine capturés par un logiciel voleur",
                f"Services concernés : {', '.join(services[:15]) or 'non précisés'}"
                + (f" (et {len(services) - 15} autres)" if len(services) > 15 else "")
                + f". Exemples masqués : {exemples}.",
                "Un logiciel voleur d'identifiants s'est exécuté sur des postes utilisant ces "
                "adresses, et a transmis les identifiants saisis dans le navigateur. "
                "C'est bien plus grave qu'une fuite chez un prestataire : ce n'est pas un tiers "
                "qui a été compromis, c'est la machine de la personne. Les mots de passe, mais "
                "aussi les cookies de session, ont pu être volés — ce qui permet de contourner "
                "l'authentification multifacteur. Ces données se revendent en lots et sont "
                "exploitées rapidement.",
                "Traiter les postes concernés comme compromis : les isoler et les réinstaller, "
                "renouveler les mots de passe de tous les services listés depuis une machine "
                "saine, révoquer les sessions et jetons en cours, puis activer "
                "l'authentification multifacteur. La liste nominative des comptes est "
                "consultable dans votre tableau de bord Have I Been Pwned.",
                [refs.ANSSI_MOTS_DE_PASSE, refs.OWASP_CREDENTIAL_STUFFING, refs.CIS_CONTROLS],
                {"comptes": collaborateurs["comptes"], "services": services[:60]},
            )

        if utilisateurs and utilisateurs["comptes"]:
            repartition = ", ".join(
                f"{fournisseur} : {nombre}"
                for fournisseur, nombre in list(utilisateurs["par_fournisseur"].items())[:8]
            )
            run_.add(
                "BREACH_STEALER_LOG_CUSTOMERS", Severity.ELEVE,
                f"{utilisateurs['comptes']} utilisateur(s) de votre service ont eu leurs "
                "identifiants capturés",
                f"Répartition par fournisseur de messagerie : {repartition}. "
                f"Exemples masqués : {', '.join(utilisateurs['exemples'][:6])}.",
                "Ces personnes saisissaient leurs identifiants sur votre site lorsque leur "
                "poste a été infecté par un logiciel voleur. Leurs comptes chez vous sont donc "
                "directement exposés à une prise de contrôle, sans qu'aucune faille de votre "
                "côté ne soit en cause. Les adresses ne sont affichées que masquées : la liste "
                "nominative, nécessaire pour notifier les personnes, reste dans votre tableau "
                "de bord Have I Been Pwned.",
                "Forcer la réinitialisation du mot de passe de ces comptes, invalider leurs "
                "sessions en cours, imposer l'authentification multifacteur et informer les "
                "personnes concernées de l'infection de leur poste.",
                [refs.OWASP_CREDENTIAL_STUFFING, refs.ANSSI_MOTS_DE_PASSE, refs.CIS_CONTROLS],
                {
                    "comptes": utilisateurs["comptes"],
                    "par_fournisseur": utilisateurs["par_fournisseur"],
                },
            )

        if (
            collaborateurs is not None
            and utilisateurs is not None
            and not collaborateurs["comptes"]
            and not utilisateurs["comptes"]
        ):
            run_.add(
                "BREACH_STEALER_LOG_NONE", Severity.INFO,
                "Aucune trace de logiciel voleur d'identifiants",
                "Les journaux d'infostealers indexés par Have I Been Pwned ne référencent ni "
                "compte de ce domaine, ni utilisateur ayant saisi ses identifiants sur ce site.",
                "Aucun poste associé à ce domaine n'apparaît dans les lots d'identifiants "
                "volés analysés à ce jour. Ces journaux ne couvrent évidemment qu'une partie "
                "des infections réelles.",
                "Maintenir la protection des postes et renouveler cette vérification "
                "régulièrement.",
                [refs.ANSSI_MOTS_DE_PASSE, refs.CIS_CONTROLS],
            )

    # ------------------------------------------------- sources optionnelles --
    leakcheck = await _leakcheck(ctx, run_)
    if leakcheck is None and not ctx.settings.has_key("leakcheck_api_key"):
        desactivees.append({"source": "LeakCheck", "raison": "clé LEAKCHECK_API_KEY absente"})
    elif leakcheck:
        run_.data["leakcheck"] = leakcheck
        if leakcheck["comptes"]:
            run_.add(
                "BREACH_LEAKCHECK", Severity.MOYEN,
                f"LeakCheck référence {leakcheck['comptes']} enregistrement(s) pour ce domaine",
                "Sources : "
                + (", ".join(f"{n} ({c})" for n, c in leakcheck["par_source"].items()) or "non précisées"),
                "Une seconde base de fuites confirme la présence de données liées à ce domaine. "
                "Seules les métadonnées sont récupérées : noms des fuites et volumétrie.",
                "Croiser avec les résultats HIBP et traiter les comptes concernés.",
                [refs.OWASP_CREDENTIAL_STUFFING],
                {"par_source": leakcheck["par_source"]},
            )

    intelx = await _intelx(ctx, run_)
    if intelx is None and not ctx.settings.has_key("intelx_api_key"):
        desactivees.append({"source": "Intelligence X", "raison": "clé INTELX_API_KEY absente"})
    elif intelx:
        run_.data["intelx"] = intelx
        if intelx["selecteurs"]:
            run_.add(
                "BREACH_INTELX", Severity.FAIBLE,
                f"Intelligence X référence {intelx['selecteurs']} sélecteur(s) liés au domaine",
                f"{intelx['selecteurs']} entrées correspondantes dans l'index Intelligence X. "
                "Seule la volumétrie est conservée.",
                "Des données associées à ce domaine sont indexées dans une base de "
                "renseignement sur les fuites. Le détail n'est volontairement pas récupéré : il "
                "contiendrait des données personnelles.",
                "Si une investigation approfondie est nécessaire, la mener dans un cadre "
                "contractuel explicite, avec un périmètre et une conservation documentés.",
                [refs.OWASP_CREDENTIAL_STUFFING],
            )

    run_.data["sources_desactivees"] = desactivees
    return run_.done(status=ModuleStatus.PARTIAL if run_.errors else ModuleStatus.OK)
