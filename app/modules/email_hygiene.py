"""Module 3 — hygiène de la messagerie : MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI.

Toutes les vérifications reposent sur des enregistrements DNS publics et, pour
MTA-STS, sur la récupération de la politique publiée en HTTPS. Aucune connexion
SMTP n'est établie vers la cible.
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import refs
from ..models import ModuleResult, Severity
from . import MODULE_LABELS, ModuleContext, ModuleRun

KEY = "email"
LABEL = MODULE_LABELS[KEY]
WEIGHT = 20
DEPENDS_ON: tuple[str, ...] = ()
TIMEOUT = 90.0

#: Mécanismes SPF consommant une résolution DNS (RFC 7208 §4.6.4, limite de 10).
SPF_LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:")
SPF_MAX_LOOKUPS = 10
SPF_MAX_DEPTH = 5

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load_selectors() -> list[str]:
    try:
        payload = json.loads((_DATA_DIR / "dkim_selectors.json").read_text(encoding="utf-8"))
        return list(payload.get("selectors", []))
    except (OSError, ValueError):  # pragma: no cover - fichier de données absent
        return ["default", "google", "selector1", "selector2", "k1", "dkim"]


def find_records(txt_records: list[str], prefix: str) -> list[str]:
    """Isole les enregistrements TXT commençant par un préfixe (insensible à la casse)."""
    return [r.strip() for r in txt_records if r.strip().lower().startswith(prefix.lower())]


def spf_terms(record: str) -> list[str]:
    """Découpe un enregistrement SPF en termes."""
    return [t for t in record.split() if t and not t.lower().startswith("v=spf1")]


def spf_all_qualifier(record: str) -> str | None:
    """Retourne le qualificateur du mécanisme `all` : '-', '~', '?' ou '+'."""
    for term in spf_terms(record):
        lowered = term.lower()
        if lowered in ("all", "+all"):
            return "+"
        if lowered.endswith("all") and lowered[:-3] in ("-", "~", "?", "+"):
            return lowered[:-3]
    return None


async def count_spf_lookups(
    resolver, record: str, depth: int = 0, seen: set[str] | None = None
) -> tuple[int, list[str]]:
    """Compte récursivement les résolutions DNS imposées par un enregistrement SPF."""
    seen = seen if seen is not None else set()
    count = 0
    notes: list[str] = []
    if depth > SPF_MAX_DEPTH:
        return 0, [f"profondeur d'inclusion SPF supérieure à {SPF_MAX_DEPTH}, comptage interrompu"]

    for term in spf_terms(record):
        lowered = term.lower().lstrip("+-~?")
        target: str | None = None

        if lowered.startswith("include:"):
            count += 1
            target = lowered.split(":", 1)[1]
        elif lowered.startswith("redirect="):
            count += 1
            target = lowered.split("=", 1)[1]
        elif lowered.startswith("exists:"):
            count += 1
        elif lowered == "ptr" or lowered.startswith("ptr:"):
            count += 1
        elif lowered == "a" or lowered.startswith("a:") or lowered.startswith("a/"):
            count += 1
        elif lowered == "mx" or lowered.startswith("mx:") or lowered.startswith("mx/"):
            count += 1

        if target and target not in seen:
            seen.add(target)
            answer = await resolver.query(target, "TXT")
            nested = find_records(answer.records, "v=spf1")
            if not nested:
                notes.append(f"« {target} » ne publie pas de SPF : le mécanisme produit une erreur")
                continue
            sub_count, sub_notes = await count_spf_lookups(resolver, nested[0], depth + 1, seen)
            count += sub_count
            notes.extend(sub_notes)
            if len(nested) > 1:
                notes.append(f"« {target} » publie plusieurs SPF, son inclusion est invalide")

    return count, notes


async def _check_dkim(ctx: ModuleContext, run: ModuleRun) -> list[str]:
    """Teste les sélecteurs DKIM courants. Retourne ceux qui répondent."""
    import asyncio

    selectors = _load_selectors()

    async def probe(selector: str) -> str | None:
        name = f"{selector}._domainkey.{ctx.name}"
        answer = await ctx.resolver.query(name, "TXT")
        if answer.records and any("p=" in r or "v=dkim1" in r.lower() for r in answer.records):
            return selector
        if answer.cnames:  # délégation DKIM vers un prestataire
            return selector
        return None

    found = await asyncio.gather(*(probe(s) for s in selectors))
    return [s for s in found if s]


async def run(ctx: ModuleContext) -> ModuleResult:
    """Évalue la configuration anti-usurpation de la messagerie."""
    run_ = ModuleRun(KEY)
    recon = ctx.recon
    run_.source(None)

    # Si le domaine ne résout pas du tout, l'absence d'enregistrement n'est pas un
    # défaut de configuration mais une panne de mesure : conclure « SPF absent,
    # DMARC absent » serait un faux positif. Le module s'abstient explicitement.
    if not recon.resolves:
        return run_.failed(
            "le domaine ne renvoie aucun enregistrement DNS : la configuration de la "
            "messagerie n'est pas mesurable (domaine expiré, non délégué, ou résolution "
            "indisponible depuis cette machine)"
        )

    # ------------------------------------------------------------------ MX --
    mx_hosts = recon.mx_hosts
    null_mx = recon.has_null_mx
    run_.data["mx"] = mx_hosts
    run_.data["null_mx"] = null_mx

    if null_mx:
        run_.add(
            "EMAIL_NULL_MX", Severity.INFO,
            "Le domaine déclare ne pas recevoir d'email (null MX)",
            "L'enregistrement MX vaut « 0 . », conformément à la RFC 7505.",
            "C'est une bonne pratique : le domaine annonce explicitement qu'aucune messagerie "
            "n'y est rattachée, ce qui évite les tentatives de livraison et les rebonds.",
            "Vérifier qu'un SPF strict (« v=spf1 -all ») et un DMARC en rejet accompagnent ce "
            "null MX, pour interdire aussi l'envoi au nom du domaine.",
            [refs.RFC_NULL_MX, refs.ANSSI_MESSAGERIE],
            {"mx": recon.mx},
        )
    elif not mx_hosts:
        run_.add(
            "EMAIL_MX_MISSING", Severity.MOYEN,
            "Aucun serveur de messagerie déclaré",
            "Le domaine ne publie aucun enregistrement MX.",
            "Sans MX, les serveurs qui veulent écrire à ce domaine se rabattent sur l'adresse IP "
            "du site web. Les emails peuvent donc arriver sur une machine qui n'est pas un "
            "serveur de messagerie, ou être perdus.",
            "Publier des enregistrements MX explicites si le domaine reçoit du courrier, ou un "
            "null MX (« 0 . ») s'il n'en reçoit pas.",
            [refs.RFC_NULL_MX, refs.ANSSI_MESSAGERIE],
        )

    # ----------------------------------------------------------------- SPF --
    spf_records = find_records(recon.txt, "v=spf1")
    run_.data["spf"] = spf_records

    if len(spf_records) > 1:
        run_.add(
            "EMAIL_SPF_MULTIPLE", Severity.CRITIQUE,
            f"{len(spf_records)} enregistrements SPF publiés au lieu d'un seul",
            "Enregistrements trouvés : " + " | ".join(spf_records),
            "La norme n'autorise qu'un seul enregistrement SPF par domaine. Quand il y en a "
            "plusieurs, les serveurs destinataires considèrent le SPF comme définitivement "
            "invalide : la protection ne s'applique plus du tout, et n'importe qui peut envoyer "
            "des emails en se faisant passer pour ce domaine.",
            "Fusionner les enregistrements en un seul, en combinant leurs mécanismes « include » "
            "dans la limite de 10 résolutions DNS, puis vérifier le résultat.",
            [refs.RFC_SPF, refs.ANSSI_MESSAGERIE, refs.CIS_EMAIL],
            {"records": spf_records},
        )
    elif not spf_records:
        run_.add(
            "EMAIL_SPF_MISSING", Severity.ELEVE,
            "Aucun enregistrement SPF",
            "Le domaine ne publie pas d'enregistrement « v=spf1 ».",
            "SPF indique quels serveurs sont autorisés à envoyer des emails au nom du domaine. "
            "Sans lui, un attaquant peut usurper vos adresses d'expédition pour du hameçonnage, "
            "et rien ne permet au destinataire de s'en apercevoir.",
            "Publier un enregistrement SPF listant les serveurs d'envoi légitimes et terminant "
            "par « -all » (ou « ~all » pendant la phase de mise au point).",
            [refs.RFC_SPF, refs.ANSSI_MESSAGERIE, refs.CIS_EMAIL],
        )
    else:
        record = spf_records[0]
        qualifier = spf_all_qualifier(record)
        lookups, notes = await count_spf_lookups(ctx.resolver, record)
        run_.data["spf_lookups"] = lookups
        run_.data["spf_notes"] = notes

        if qualifier == "+":
            run_.add(
                "EMAIL_SPF_ALLOW_ALL", Severity.CRITIQUE,
                "Le SPF autorise le monde entier à envoyer des emails",
                f"L'enregistrement se termine par « +all » : {record}",
                "Le mécanisme « +all » déclare que n'importe quel serveur sur Internet peut "
                "envoyer du courrier au nom du domaine. C'est l'équivalent d'une absence totale "
                "de protection, avec en plus une apparence de conformité.",
                "Remplacer « +all » par « -all » et n'autoriser que les serveurs d'envoi légitimes.",
                [refs.RFC_SPF, refs.ANSSI_MESSAGERIE],
                {"record": record},
            )
        elif qualifier is None:
            run_.add(
                "EMAIL_SPF_NO_ALL", Severity.MOYEN,
                "Le SPF ne conclut pas par un mécanisme « all »",
                f"Enregistrement analysé : {record}",
                "Sans mécanisme final « all », le comportement attendu pour les serveurs non "
                "listés n'est pas défini : chaque destinataire décide seul, et la protection "
                "devient imprévisible.",
                "Terminer l'enregistrement par « -all » (rejet) ou « ~all » (échec souple).",
                [refs.RFC_SPF],
                {"record": record},
            )
        elif qualifier == "?":
            run_.add(
                "EMAIL_SPF_NEUTRAL", Severity.MOYEN,
                "Le SPF se termine par « ?all » (neutre)",
                f"Enregistrement analysé : {record}",
                "Un SPF neutre n'exprime aucune opinion sur les serveurs non listés : il ne "
                "protège donc pas contre l'usurpation du domaine.",
                "Durcir l'enregistrement en « -all » après avoir vérifié que tous les services "
                "d'envoi légitimes y figurent.",
                [refs.RFC_SPF, refs.ANSSI_MESSAGERIE],
                {"record": record},
            )
        elif qualifier == "~":
            run_.add(
                "EMAIL_SPF_SOFTFAIL", Severity.FAIBLE,
                "Le SPF se termine par « ~all » (échec souple) plutôt que « -all »",
                f"Enregistrement analysé : {record}",
                "En échec souple, un email envoyé depuis un serveur non autorisé est accepté puis "
                "simplement marqué comme suspect. La plupart des destinataires le livrent quand "
                "même, souvent en boîte de réception.",
                "Passer à « -all » une fois la liste des serveurs d'envoi validée, en s'appuyant "
                "sur les rapports DMARC pour vérifier qu'aucun flux légitime n'est oublié.",
                [refs.RFC_SPF, refs.ANSSI_MESSAGERIE],
                {"record": record},
            )

        if any(t.lower().lstrip("+-~?") in ("ptr",) or t.lower().startswith("ptr:")
               for t in spf_terms(record)):
            run_.add(
                "EMAIL_SPF_PTR", Severity.FAIBLE,
                "Le SPF utilise le mécanisme obsolète « ptr »",
                f"Enregistrement analysé : {record}",
                "Le mécanisme « ptr » impose aux destinataires des résolutions DNS inverses "
                "lentes et peu fiables. La norme recommande de ne plus l'utiliser, et certains "
                "serveurs l'ignorent, ce qui fausse la validation.",
                "Remplacer « ptr » par les mécanismes « a », « mx » ou « ip4/ip6 » correspondants.",
                [refs.RFC_SPF],
                {"record": record},
            )

        if lookups > SPF_MAX_LOOKUPS:
            run_.add(
                "EMAIL_SPF_TOO_MANY_LOOKUPS", Severity.ELEVE,
                f"Le SPF impose {lookups} résolutions DNS, au-delà de la limite de 10",
                f"Décompte effectué en suivant les « include » : {lookups} résolutions. "
                + (" ".join(notes) if notes else ""),
                "Au-delà de dix résolutions DNS, la norme impose aux destinataires de considérer "
                "le SPF comme invalide. La protection tombe alors, exactement comme si elle "
                "n'existait pas, et des emails légitimes peuvent aussi être rejetés.",
                "Réduire le nombre d'« include » (regrouper les prestataires, remplacer certaines "
                "inclusions par des plages « ip4 »/« ip6 » explicites) pour repasser sous 10.",
                [refs.RFC_SPF, refs.ANSSI_MESSAGERIE],
                {"lookups": lookups, "notes": notes},
            )
        elif lookups >= 9:
            run_.add(
                "EMAIL_SPF_LOOKUPS_NEAR_LIMIT", Severity.FAIBLE,
                f"Le SPF est proche de la limite de résolutions DNS ({lookups}/10)",
                f"Décompte effectué en suivant les « include » : {lookups} résolutions.",
                "La marge est faible : l'ajout d'un prestataire d'envoi, ou une modification "
                "chez un prestataire existant, suffirait à invalider tout le SPF.",
                "Simplifier l'enregistrement dès maintenant pour conserver une marge.",
                [refs.RFC_SPF],
                {"lookups": lookups},
            )
        for note in notes:
            run_.error(f"SPF : {note}")

    # --------------------------------------------------------------- DMARC --
    dmarc_answer = await ctx.resolver.query(f"_dmarc.{ctx.name}", "TXT")
    dmarc_records = find_records(dmarc_answer.records, "v=DMARC1")
    run_.data["dmarc"] = dmarc_records

    if len(dmarc_records) > 1:
        run_.add(
            "EMAIL_DMARC_MULTIPLE", Severity.ELEVE,
            f"{len(dmarc_records)} enregistrements DMARC publiés au lieu d'un seul",
            " | ".join(dmarc_records),
            "Plusieurs enregistrements DMARC rendent la politique inapplicable : les "
            "destinataires l'ignorent, et le domaine se retrouve sans protection.",
            "Ne conserver qu'un seul enregistrement TXT sur « _dmarc ».",
            [refs.RFC_DMARC, refs.ANSSI_MESSAGERIE],
            {"records": dmarc_records},
        )
    elif not dmarc_records:
        run_.add(
            "EMAIL_DMARC_MISSING", Severity.ELEVE,
            "Aucune politique DMARC",
            f"« _dmarc.{ctx.name} » ne publie aucun enregistrement "
            f"(code DNS : {dmarc_answer.rcode}).",
            "DMARC est ce qui dit aux messageries destinataires quoi faire des emails qui "
            "prétendent venir de votre domaine sans y être autorisés. Sans DMARC, même avec SPF, "
            "l'usurpation reste possible et vous ne recevez aucun rapport sur les tentatives.",
            "Publier « v=DMARC1; p=none; rua=mailto:dmarc@votre-domaine » pour commencer à "
            "recevoir les rapports, puis durcir progressivement vers « p=quarantine » et « p=reject ».",
            [refs.RFC_DMARC, refs.ANSSI_MESSAGERIE, refs.CIS_EMAIL],
        )
    else:
        record = dmarc_records[0]
        tags = {}
        for part in record.split(";"):
            if "=" in part:
                name, _, value = part.strip().partition("=")
                tags[name.strip().lower()] = value.strip()
        policy = tags.get("p", "").lower()
        run_.data["dmarc_tags"] = tags

        if policy == "none":
            run_.add(
                "EMAIL_DMARC_POLICY_NONE", Severity.MOYEN,
                "La politique DMARC est en simple observation (p=none)",
                f"Enregistrement analysé : {record}",
                "En « p=none », vous recevez des rapports mais aucune action n'est demandée aux "
                "destinataires : les emails usurpant votre domaine continuent d'arriver "
                "normalement dans les boîtes de réception de vos interlocuteurs.",
                "Après analyse des rapports, passer à « p=quarantine » puis « p=reject ».",
                [refs.RFC_DMARC, refs.ANSSI_MESSAGERIE],
                {"policy": policy},
            )
        elif policy == "quarantine":
            run_.add(
                "EMAIL_DMARC_POLICY_QUARANTINE", Severity.FAIBLE,
                "La politique DMARC met en quarantaine plutôt qu'en rejet",
                f"Enregistrement analysé : {record}",
                "La quarantaine range les emails usurpés en indésirables : ils restent "
                "accessibles et peuvent être consultés par le destinataire.",
                "Viser « p=reject » pour que les emails usurpant le domaine soient refusés.",
                [refs.RFC_DMARC, refs.ANSSI_MESSAGERIE],
                {"policy": policy},
            )
        elif policy == "reject":
            run_.add(
                "EMAIL_DMARC_POLICY_REJECT", Severity.INFO,
                "La politique DMARC est en rejet (p=reject)",
                f"Enregistrement analysé : {record}",
                "C'est le niveau recommandé : les messageries destinataires refusent les emails "
                "qui usurpent votre domaine.",
                "Maintenir ce niveau et continuer à surveiller les rapports agrégés.",
                [refs.RFC_DMARC, refs.ANSSI_MESSAGERIE],
                {"policy": policy},
            )
        else:
            run_.add(
                "EMAIL_DMARC_POLICY_INVALID", Severity.ELEVE,
                "La politique DMARC est absente ou invalide",
                f"Enregistrement analysé : {record}",
                "Le champ « p= » est obligatoire. S'il manque ou contient une valeur inconnue, "
                "l'enregistrement est ignoré par les destinataires.",
                "Corriger l'enregistrement pour qu'il contienne « p=none », « p=quarantine » "
                "ou « p=reject ».",
                [refs.RFC_DMARC],
                {"policy": policy or None},
            )

        if not tags.get("rua"):
            run_.add(
                "EMAIL_DMARC_NO_RUA", Severity.MOYEN,
                "Aucune adresse de rapport DMARC (rua)",
                f"Enregistrement analysé : {record}",
                "Sans adresse « rua », vous ne recevez aucun rapport : impossible de savoir qui "
                "usurpe votre domaine, ni de vérifier que vos propres envois sont conformes "
                "avant de durcir la politique.",
                "Ajouter « rua=mailto:dmarc@votre-domaine » et traiter les rapports reçus.",
                [refs.RFC_DMARC, refs.ANSSI_MESSAGERIE],
            )

        pct = tags.get("pct")
        if pct and pct.isdigit() and int(pct) < 100:
            run_.add(
                "EMAIL_DMARC_PARTIAL_PCT", Severity.FAIBLE,
                f"La politique DMARC ne s'applique qu'à {pct} % des messages",
                f"Enregistrement analysé : {record}",
                f"Avec « pct={pct} », seuls {pct} % des emails non conformes subissent la "
                "politique : le reste passe sans contrôle.",
                "Porter « pct » à 100 une fois la phase de déploiement terminée.",
                [refs.RFC_DMARC],
            )

    # ---------------------------------------------------------------- DKIM --
    dkim_found = await _check_dkim(ctx, run_)
    run_.data["dkim_selectors_found"] = dkim_found
    if dkim_found:
        run_.add(
            "EMAIL_DKIM_PRESENT", Severity.INFO,
            f"Signature DKIM détectée ({', '.join(dkim_found)})",
            f"Sélecteurs répondant : {', '.join(dkim_found)}.",
            "DKIM signe cryptographiquement vos emails : le destinataire peut vérifier qu'ils "
            "n'ont pas été modifiés et qu'ils viennent bien de votre domaine.",
            "Vérifier que les clés font au moins 2048 bits et les faire tourner régulièrement.",
            [refs.RFC_DKIM, refs.ANSSI_MESSAGERIE],
            {"selectors": dkim_found},
        )
    else:
        run_.add(
            "EMAIL_DKIM_NOT_FOUND", Severity.MOYEN,
            "Aucun sélecteur DKIM courant ne répond",
            f"{len(_load_selectors())} sélecteurs répandus ont été testés sans résultat.",
            "DKIM signe les emails pour prouver leur authenticité, et DMARC s'appuie dessus. "
            "Attention : un sélecteur DKIM peut porter n'importe quel nom, donc ce test ne "
            "prouve pas l'absence de DKIM — il indique seulement qu'aucun nom usuel n'a répondu.",
            "Vérifier auprès de votre prestataire de messagerie quel sélecteur est utilisé, et "
            "publier DKIM s'il est absent.",
            [refs.RFC_DKIM, refs.ANSSI_MESSAGERIE],
            {"selectors_tested": len(_load_selectors())},
        )

    # -------------------------------------------------------------- MTA-STS --
    sts_answer = await ctx.resolver.query(f"_mta-sts.{ctx.name}", "TXT")
    sts_records = find_records(sts_answer.records, "v=STSv1")
    run_.data["mta_sts"] = sts_records
    if sts_records:
        policy_url = f"https://mta-sts.{ctx.name}/.well-known/mta-sts.txt"
        result = await ctx.http.request("cible", policy_url)
        run_.source(result.source_ref(label="Politique MTA-STS"))
        if result.ok and result.text and "version:" in result.text.lower():
            mode = ""
            for line in result.text.splitlines():
                if line.lower().startswith("mode:"):
                    mode = line.split(":", 1)[1].strip().lower()
            run_.data["mta_sts_mode"] = mode
            if mode == "enforce":
                run_.add(
                    "EMAIL_MTA_STS_ENFORCE", Severity.INFO,
                    "MTA-STS est actif en mode « enforce »",
                    f"Politique publiée sur {policy_url} (mode : {mode}).",
                    "MTA-STS impose aux serveurs expéditeurs d'utiliser une connexion chiffrée "
                    "et vérifiée pour vous écrire, ce qui empêche l'interception des emails.",
                    "Maintenir la politique et surveiller les rapports TLS-RPT.",
                    [refs.RFC_MTA_STS, refs.ANSSI_MESSAGERIE],
                )
            else:
                run_.add(
                    "EMAIL_MTA_STS_TESTING", Severity.FAIBLE,
                    f"MTA-STS est publié mais en mode « {mode or 'inconnu'} »",
                    f"Politique publiée sur {policy_url} (mode : {mode or 'non précisé'}).",
                    "En mode « testing », les erreurs de chiffrement sont signalées mais les "
                    "emails sont quand même acceptés : la protection n'est pas effective.",
                    "Passer le mode à « enforce » après avoir vérifié les rapports.",
                    [refs.RFC_MTA_STS],
                )
        else:
            run_.add(
                "EMAIL_MTA_STS_POLICY_UNREACHABLE", Severity.MOYEN,
                "MTA-STS est annoncé dans le DNS mais la politique est introuvable",
                f"L'enregistrement « _mta-sts » existe, mais {policy_url} n'a pas renvoyé de "
                f"politique valide ({result.describe_error()}).",
                "Les serveurs expéditeurs qui tentent d'appliquer MTA-STS ne trouvent pas la "
                "politique : selon leur implémentation, ils peuvent refuser de vous écrire.",
                "Publier le fichier « /.well-known/mta-sts.txt » sur l'hôte « mta-sts » du "
                "domaine, en HTTPS avec un certificat valide.",
                [refs.RFC_MTA_STS],
            )
    elif not null_mx:
        run_.add(
            "EMAIL_MTA_STS_MISSING", Severity.FAIBLE,
            "MTA-STS n'est pas déployé",
            f"« _mta-sts.{ctx.name} » ne publie aucun enregistrement.",
            "Sans MTA-STS, un attaquant en position d'interception peut forcer l'envoi de vos "
            "emails entrants en clair, et les lire au passage.",
            "Déployer MTA-STS (enregistrement TXT « _mta-sts » puis politique HTTPS), "
            "idéalement avec TLS-RPT pour recevoir les rapports d'échec.",
            [refs.RFC_MTA_STS, refs.ANSSI_MESSAGERIE],
        )

    # -------------------------------------------------------------- TLS-RPT --
    tlsrpt_answer = await ctx.resolver.query(f"_smtp._tls.{ctx.name}", "TXT")
    tlsrpt = find_records(tlsrpt_answer.records, "v=TLSRPTv1")
    run_.data["tls_rpt"] = tlsrpt
    if not tlsrpt and not null_mx:
        run_.add(
            "EMAIL_TLSRPT_MISSING", Severity.FAIBLE,
            "Aucun rapport TLS (TLS-RPT) configuré",
            f"« _smtp._tls.{ctx.name} » ne publie aucun enregistrement.",
            "TLS-RPT vous fait remonter les échecs de chiffrement rencontrés par ceux qui vous "
            "écrivent. Sans lui, une attaque d'interception sur vos emails entrants passe inaperçue.",
            "Publier « v=TLSRPTv1; rua=mailto:tlsrpt@votre-domaine ».",
            [refs.RFC_MTA_STS],
        )

    # ---------------------------------------------------------------- BIMI --
    bimi_answer = await ctx.resolver.query(f"default._bimi.{ctx.name}", "TXT")
    bimi = find_records(bimi_answer.records, "v=BIMI1")
    run_.data["bimi"] = bimi
    if bimi:
        run_.add(
            "EMAIL_BIMI_PRESENT", Severity.INFO,
            "BIMI est publié",
            f"Enregistrement : {bimi[0]}",
            "BIMI affiche votre logo vérifié dans la boîte de réception des destinataires, ce "
            "qui aide vos interlocuteurs à repérer les emails frauduleux.",
            "Vérifier que le certificat de marque (VMC) reste valide.",
            [refs.BIMI_SPEC],
        )

    return run_.done()
