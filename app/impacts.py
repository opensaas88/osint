"""Traduction des constats techniques en conséquences pour l'organisation.

« SPF invalide » ne décide aucun budget ; « n'importe qui peut envoyer une facture
au nom de votre entreprise » si. Ce module porte, pour chaque constat, la phrase
qui dit ce qui arrive concrètement, et à qui.

Aucun chiffre n'y figure volontairement : une statistique citée de mémoire se
démonétise au premier contrôle. Les renvois pointent vers des ressources publiques
francophones où le lecteur trouvera les données à jour.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Reference

CYBERMALVEILLANCE = "https://www.cybermalveillance.gouv.fr/"
CNIL = "https://www.cnil.fr/"


@dataclass(frozen=True)
class Impact:
    """Conséquence concrète d'un constat, et qui la subit."""

    consequence: str
    subi_par: str
    ressource: Reference | None = None


def _ressource(sujet: str, url: str = CYBERMALVEILLANCE) -> Reference:
    return Reference(
        framework="Cybermalveillance.gouv.fr" if url == CYBERMALVEILLANCE else "CNIL",
        label=sujet,
        url=url,
    )


#: Conséquence métier par code de constat. Les constats purement informatifs n'y
#: figurent pas : ils ne demandent aucune décision.
IMPACT_BY_CODE: dict[str, Impact] = {
    # --- Usurpation de la messagerie ---------------------------------------
    "EMAIL_SPF_MULTIPLE": Impact(
        "Un tiers peut envoyer des emails qui semblent venir de votre entreprise : "
        "fausse facture, changement de coordonnées bancaires, demande urgente au nom "
        "d'un dirigeant. Vos interlocuteurs n'ont aucun moyen de s'en apercevoir.",
        "vos clients, vos fournisseurs et votre comptabilité",
        _ressource("Fiche réflexe « Arnaque au faux ordre de virement »"),
    ),
    "EMAIL_SPF_MISSING": Impact(
        "Rien n'empêche un tiers d'écrire au nom de votre domaine. C'est le montage de "
        "base de l'arnaque au virement et du hameçonnage visant vos partenaires.",
        "vos clients, vos fournisseurs et votre comptabilité",
        _ressource("Fiche réflexe « Hameçonnage »"),
    ),
    "EMAIL_SPF_ALLOW_ALL": Impact(
        "Votre domaine autorise explicitement le monde entier à écrire en son nom, tout "
        "en donnant l'apparence d'une configuration en règle.",
        "vos clients et vos fournisseurs",
        _ressource("Fiche réflexe « Hameçonnage »"),
    ),
    "EMAIL_DMARC_MISSING": Impact(
        "Les messageries destinataires ne savent pas quoi faire des emails frauduleux "
        "émis en votre nom : elles les livrent. Vous n'êtes par ailleurs averti d'aucune "
        "tentative d'usurpation.",
        "vos clients et votre réputation",
        _ressource("Fiche réflexe « Hameçonnage »"),
    ),
    "EMAIL_DMARC_POLICY_NONE": Impact(
        "Vous recevez les rapports d'usurpation mais aucune protection n'est appliquée : "
        "les emails frauduleux arrivent toujours en boîte de réception.",
        "vos clients et vos fournisseurs",
    ),
    "EMAIL_DKIM_NOT_FOUND": Impact(
        "Sans signature, vos emails légitimes sont plus souvent classés en indésirables, "
        "et rien ne distingue techniquement un message authentique d'une contrefaçon.",
        "la délivrabilité de vos échanges commerciaux",
    ),
    "EMAIL_MTA_STS_MISSING": Impact(
        "Un attaquant en position d'interception peut forcer la remise de vos emails "
        "entrants en clair et les lire, notamment sur un réseau partagé.",
        "la confidentialité de vos échanges",
    ),
    # --- Nom de domaine ------------------------------------------------------
    "DNS_DOMAIN_EXPIRED": Impact(
        "Site web et messagerie sont à l'arrêt. Passé la période de rédemption, le "
        "domaine redevient achetable par n'importe qui, y compris par un concurrent ou "
        "un escroc qui en ferait usage en votre nom.",
        "toute l'activité en ligne de l'organisation",
        _ressource("Protéger son nom de domaine"),
    ),
    "DNS_DOMAIN_EXPIRING": Impact(
        "À l'échéance, tout s'arrête d'un coup : site, messagerie, applications métier "
        "qui dépendent du domaine. La remise en service n'est pas immédiate.",
        "toute l'activité en ligne de l'organisation",
    ),
    "DNS_DOMAIN_EXPIRING_SOON": Impact(
        "Un renouvellement oublié interrompt l'ensemble des services rattachés au "
        "domaine, sans préavis pour vos utilisateurs.",
        "toute l'activité en ligne de l'organisation",
    ),
    "DNS_DOMAIN_NO_LOCK": Impact(
        "Une personne ayant obtenu l'accès au compte du bureau d'enregistrement peut "
        "faire transférer le domaine ailleurs. Reprendre la main sur un domaine détourné "
        "est long, coûteux, et parfois impossible.",
        "l'organisation tout entière",
        _ressource("Protéger son nom de domaine"),
    ),
    "DNS_DNSSEC_MISSING": Impact(
        "Un attaquant capable de s'interposer sur le réseau peut diriger vos visiteurs "
        "et vos emails vers ses propres serveurs sans que rien ne l'indique.",
        "vos visiteurs et vos échanges",
    ),
    "DNS_SUBDOMAIN_TAKEOVER_RISK": Impact(
        "Un tiers peut récupérer l'un de vos sous-domaines et y publier ce qu'il veut "
        "sous votre nom : fausse page de connexion, contenu illicite, certificat valide "
        "à votre nom.",
        "votre marque et vos utilisateurs",
    ),
    "DNS_SINGLE_NS": Impact(
        "La panne d'un seul serveur rend site et messagerie injoignables, sans solution "
        "de contournement.",
        "la disponibilité de vos services",
    ),
    # --- Web et TLS ----------------------------------------------------------
    "TLS_CERT_EXPIRED": Impact(
        "Les navigateurs bloquent l'accès derrière un avertissement de sécurité en pleine "
        "page. Vos visiteurs ne peuvent plus vous joindre et beaucoup renoncent.",
        "vos visiteurs et votre chiffre d'affaires en ligne",
    ),
    "TLS_CERT_EXPIRING_SOON": Impact(
        "Sans renouvellement, le site devient inaccessible à l'échéance, derrière une "
        "alerte de sécurité qui inquiète les visiteurs.",
        "vos visiteurs",
    ),
    "SUBDOMAIN_CERT_EXPIRING": Impact(
        "Les services portés par ces sous-domaines deviendront inaccessibles à "
        "l'échéance, souvent sans que personne ne surveille ces noms secondaires.",
        "les utilisateurs de vos applications annexes",
    ),
    "TLS_OBSOLETE_VERSION": Impact(
        "Les échanges peuvent être déchiffrés ou modifiés par un attaquant bien placé, "
        "et les navigateurs récents refusent purement et simplement la connexion.",
        "vos visiteurs et vos utilisateurs",
    ),
    "HTTP_CSP_MISSING": Impact(
        "Une faille d'injection suffit à exécuter du code arbitraire dans la page de vos "
        "utilisateurs : vol de session, détournement de formulaire, redirection vers une "
        "page de hameçonnage.",
        "les comptes de vos utilisateurs",
    ),
    "HTTP_XFO_MISSING": Impact(
        "Un attaquant peut afficher votre site dans un cadre invisible et faire cliquer "
        "la victime sur vos boutons à son insu — validation d'un virement, modification "
        "de droits.",
        "les comptes de vos utilisateurs",
    ),
    "HTTP_NO_REDIRECT": Impact(
        "Les pages, formulaires et identifiants transitent en clair : quiconque contrôle "
        "le réseau, un Wi-Fi public par exemple, peut les lire ou les modifier.",
        "vos visiteurs",
    ),
    "HTTP_COOKIE_NOT_SECURE": Impact(
        "Le cookie de session peut être capté sur un réseau partagé, ce qui permet de "
        "prendre la place d'un utilisateur connecté.",
        "les comptes de vos utilisateurs",
    ),
    "HTTP_HSTS_MISSING": Impact(
        "La première visite peut être interceptée et basculée en clair, y compris la "
        "saisie des identifiants.",
        "vos visiteurs",
    ),
    # --- Exposition ----------------------------------------------------------
    "EXPOSURE_CRITICAL_PORTS": Impact(
        "Bases de données et accès distants joignables depuis Internet sont la porte "
        "d'entrée habituelle des rançongiciels : essais de mots de passe automatisés, "
        "puis chiffrement de l'ensemble du système d'information.",
        "l'organisation tout entière",
        _ressource("Fiche réflexe « Rançongiciel »"),
    ),
    "EXPOSURE_SENSITIVE_PORTS": Impact(
        "Chaque interface d'administration exposée subit des tentatives de connexion "
        "automatisées en continu.",
        "vos systèmes internes",
    ),
    "EXPOSURE_KNOWN_CVE": Impact(
        "Des failles publiées affectent ces machines : les codes d'exploitation sont "
        "souvent publics et des robots balaient Internet en permanence pour les utiliser.",
        "vos serveurs et les données qu'ils hébergent",
    ),
    "EXPOSURE_HOSTING_OUTSIDE_EU": Impact(
        "Héberger hors de l'Union européenne implique un transfert de données qui doit "
        "être encadré et documenté dans votre registre de traitements.",
        "votre conformité au RGPD",
        _ressource("Transferts de données hors UE", CNIL),
    ),
    # --- Fuites et compromission ---------------------------------------------
    "BREACH_DOMAIN_ACCOUNTS": Impact(
        "Des adresses professionnelles circulent dans des fuites : elles servent à "
        "deviner vos identifiants internes et à bâtir un hameçonnage crédible visant "
        "nommément vos collaborateurs.",
        "vos collaborateurs et vos accès internes",
        _ressource("Fiche réflexe « Hameçonnage »"),
    ),
    "BREACH_STEALER_LOG_STAFF": Impact(
        "Des postes de travail ont été infectés : mots de passe et cookies de session "
        "ont été transmis à des tiers, ce qui permet de contourner l'authentification "
        "multifacteur. Ces lots se revendent et s'exploitent vite.",
        "vos collaborateurs et l'ensemble de vos accès",
        _ressource("Fiche réflexe « Rançongiciel »"),
    ),
    "BREACH_STEALER_LOG_CUSTOMERS": Impact(
        "Les comptes de ces utilisateurs chez vous sont directement exposés à une prise "
        "de contrôle, sans qu'aucune faille de votre côté ne soit en cause.",
        "vos utilisateurs et votre service client",
    ),
    "RANSOMWARE_CLAIMED_VICTIM": Impact(
        "Une intrusion a eu lieu et des données internes circulent. Au-delà de "
        "l'interruption d'activité, la notification à la CNIL sous 72 heures et "
        "l'information des personnes concernées deviennent des obligations.",
        "l'organisation, ses clients et ses obligations légales",
        _ressource("Notifier une violation de données", CNIL),
    ),
    # --- Marque --------------------------------------------------------------
    "TYPO_MAIL_CAPABLE": Impact(
        "Ces domaines imitent le vôtre et peuvent déjà envoyer des emails : c'est le "
        "montage classique de la fraude au virement visant vos clients.",
        "vos clients et vos fournisseurs",
        _ressource("Fiche réflexe « Arnaque au faux ordre de virement »"),
    ),
    "TYPO_REGISTERED_BY_THIRD_PARTY": Impact(
        "Des domaines très proches du vôtre appartiennent à des tiers et peuvent être "
        "activés à tout moment pour une campagne de hameçonnage visant vos utilisateurs.",
        "votre marque et vos utilisateurs",
    ),
    "SUBDOMAIN_SENSITIVE_NAMES": Impact(
        "Les noms de vos machines renseignent un attaquant sur où chercher : "
        "environnements de test moins surveillés, consoles d'administration.",
        "vos systèmes internes",
    ),
    # --- Réputation ----------------------------------------------------------
    "REPUTATION_VT_FLAGGED": Impact(
        "Vos emails partent en indésirables, les navigateurs affichent un avertissement "
        "et certains réseaux d'entreprise bloquent purement et simplement votre site.",
        "votre visibilité commerciale",
    ),
    "REPUTATION_URLHAUS_MALWARE": Impact(
        "Votre site sert de relais pour attaquer d'autres victimes, avec les "
        "conséquences juridiques et de réputation que cela implique.",
        "votre responsabilité et votre réputation",
    ),
    "REPUTATION_ABUSEIPDB_FLAGGED": Impact(
        "La mauvaise réputation de vos adresses dégrade la délivrabilité de vos emails "
        "et l'accès à vos services.",
        "vos échanges commerciaux",
    ),
}


def impact_for(code: str) -> Impact | None:
    """Conséquence métier d'un constat, si elle est documentée."""
    return IMPACT_BY_CODE.get(code)


def phrase_impact(code: str) -> str | None:
    """Formulation prête à l'emploi : la conséquence, puis qui la subit."""
    impact = impact_for(code)
    if impact is None:
        return None
    return f"{impact.consequence} Concerne {impact.subi_par}."
