"""Module 7 — TLS et en-têtes HTTP de sécurité.

Deux requêtes standard, du même type que celles d'un navigateur : un GET HTTPS sur
la page d'accueil et, si l'option est active, un GET HTTP pour vérifier la
redirection vers HTTPS. Le certificat est lu lors de la poignée de main TLS.
Aucun balayage de versions ni de suites cryptographiques n'est effectué : cela
exigerait des dizaines de connexions forcées, ce qui sortirait du cadre passif.
"""

from __future__ import annotations

import asyncio
import os
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .. import refs
from ..models import ModuleResult, ModuleStatus, Severity
from . import MODULE_LABELS, ModuleContext, ModuleRun

KEY = "tls"
LABEL = MODULE_LABELS[KEY]
WEIGHT = 15
DEPENDS_ON: tuple[str, ...] = ()
TIMEOUT = 90.0

HSTS_MIN_AGE = 31_536_000  # un an, en secondes
EXPIRY_CRITICAL_DAYS = 7
EXPIRY_WARNING_DAYS = 30
WEAK_RSA_BITS = 2048
_VERSION_RE = re.compile(r"\d+\.\d+")
WEAK_SIGNATURES = ("md5", "sha1")
OBSOLETE_TLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


@dataclass(slots=True)
class CertificateInfo:
    """Caractéristiques du certificat présenté par le serveur."""

    subject: str = ""
    issuer: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    sans: list[str] = field(default_factory=list)
    tls_version: str | None = None
    cipher: str | None = None
    key_bits: int | None = None
    key_type: str | None = None
    signature: str | None = None
    verified: bool = False
    verify_error: str | None = None
    self_signed: bool = False

    @property
    def days_left(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - datetime.now(UTC)).days


def _parse_der(der: bytes, info: CertificateInfo) -> None:
    """Complète `info` à partir du certificat DER, via la bibliothèque cryptography."""
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    info.subject = cert.subject.rfc4514_string()
    info.issuer = cert.issuer.rfc4514_string()
    info.not_before = cert.not_valid_before_utc
    info.not_after = cert.not_valid_after_utc
    info.self_signed = cert.issuer == cert.subject
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info.sans = list(extension.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        info.sans = []
    public_key = cert.public_key()
    info.key_bits = getattr(public_key, "key_size", None)
    info.key_type = type(public_key).__name__.replace("_", "").replace("PublicKey", "")
    if cert.signature_hash_algorithm is not None:
        info.signature = cert.signature_hash_algorithm.name


async def fetch_certificate(
    host: str, port: int = 443, timeout: float = 10.0
) -> tuple[CertificateInfo | None, str | None]:
    """Établit une poignée de main TLS et retourne les informations du certificat.

    Retourne `(info, erreur)`. Une première tentative stricte détermine si la chaîne
    et le nom d'hôte sont valides ; en cas d'échec de validation, une seconde
    tentative permissive permet de lire malgré tout le certificat présenté.
    """
    info = CertificateInfo()

    async def handshake(context: ssl.SSLContext) -> tuple[bytes, str | None, str | None]:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host), timeout
        )
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True)
            version = ssl_object.version()
            cipher = ssl_object.cipher()
            return der, version, cipher[0] if cipher else None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # pragma: no cover - fermeture best effort
                pass

    try:
        der, version, cipher = await handshake(ssl.create_default_context())
        info.verified = True
    except ssl.SSLCertVerificationError as exc:
        info.verified = False
        info.verify_error = str(exc.verify_message or exc).strip()
        permissive = ssl.create_default_context()
        permissive.check_hostname = False
        permissive.verify_mode = ssl.CERT_NONE
        try:
            der, version, cipher = await handshake(permissive)
        except Exception as exc2:
            return None, f"{type(exc2).__name__} : {str(exc2)[:160]}"
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        return None, f"{type(exc).__name__} : {str(exc)[:160]}"

    info.tls_version = version
    info.cipher = cipher
    if der:
        try:
            _parse_der(der, info)
        except Exception as exc:  # pragma: no cover - certificat illisible
            return info, f"certificat illisible ({type(exc).__name__})"
    return info, None


def evaluate_certificate(run_: ModuleRun, cert: CertificateInfo, host: str) -> None:
    """Transforme les caractéristiques du certificat en findings."""
    days = cert.days_left

    if days is not None and days < 0:
        run_.add(
            "TLS_CERT_EXPIRED", Severity.CRITIQUE,
            f"Le certificat TLS a expiré il y a {abs(days)} jour(s)",
            f"Expiration : {cert.not_after:%d/%m/%Y} — émetteur : {cert.issuer}",
            "Les navigateurs affichent un avertissement de sécurité en pleine page et bloquent "
            "l'accès au site. Vos visiteurs ne peuvent plus vous joindre, et ceux qui passent "
            "outre s'habituent à ignorer ces alertes.",
            "Renouveler le certificat immédiatement et mettre en place un renouvellement "
            "automatique (ACME/Let's Encrypt) avec une supervision de la date d'expiration.",
            [refs.ANSSI_TLS, refs.OWASP_TLS, refs.CIS_CONTROLS],
            {"expiration": cert.not_after.isoformat() if cert.not_after else None},
        )
    elif days is not None and days <= EXPIRY_CRITICAL_DAYS:
        run_.add(
            "TLS_CERT_EXPIRING_SOON", Severity.ELEVE,
            f"Le certificat TLS expire dans {days} jour(s)",
            f"Expiration : {cert.not_after:%d/%m/%Y} — émetteur : {cert.issuer}",
            "À l'expiration, le site devient inaccessible derrière un avertissement de sécurité. "
            "Le délai restant est trop court pour absorber un incident de renouvellement.",
            "Renouveler sans attendre et vérifier que le renouvellement automatique fonctionne.",
            [refs.ANSSI_TLS, refs.OWASP_TLS],
            {"jours_restants": days},
        )
    elif days is not None and days <= EXPIRY_WARNING_DAYS:
        run_.add(
            "TLS_CERT_EXPIRY_WARNING", Severity.MOYEN,
            f"Le certificat TLS expire dans {days} jours",
            f"Expiration : {cert.not_after:%d/%m/%Y} — émetteur : {cert.issuer}",
            "Le renouvellement doit être planifié. Une expiration non anticipée rend le site "
            "inaccessible pour tous les visiteurs.",
            "Automatiser le renouvellement et ajouter une alerte à 30 jours de l'échéance.",
            [refs.ANSSI_TLS],
            {"jours_restants": days},
        )
    elif days is not None:
        run_.add(
            "TLS_CERT_VALID", Severity.INFO,
            f"Certificat TLS valide pendant encore {days} jours",
            f"Émetteur : {cert.issuer} — expiration : {cert.not_after:%d/%m/%Y}",
            "Le certificat est en cours de validité : les navigateurs établissent la connexion "
            "chiffrée sans avertissement.",
            "Maintenir le renouvellement automatique et la supervision de l'échéance.",
            [refs.ANSSI_TLS],
        )

    if cert.self_signed:
        run_.add(
            "TLS_CERT_SELF_SIGNED", Severity.ELEVE,
            "Le certificat est auto-signé",
            f"Émetteur identique au sujet : {cert.issuer}",
            "Un certificat auto-signé n'est reconnu par aucun navigateur : l'accès au site "
            "déclenche une alerte de sécurité, et rien ne distingue ce certificat de celui "
            "qu'un attaquant présenterait lors d'une interception.",
            "Déployer un certificat délivré par une autorité de certification reconnue.",
            [refs.ANSSI_TLS, refs.OWASP_TLS],
        )
    elif not cert.verified and cert.verify_error:
        run_.add(
            "TLS_CERT_NOT_TRUSTED", Severity.ELEVE,
            "Le certificat n'est pas validé par les navigateurs",
            f"Erreur de validation : {cert.verify_error}",
            "Le certificat est rejeté lors de la vérification : chaîne de certification "
            "incomplète, nom d'hôte non couvert ou autorité inconnue. Les visiteurs voient un "
            "avertissement de sécurité.",
            "Corriger la chaîne de certification (inclure les certificats intermédiaires) et "
            "vérifier que tous les noms servis figurent dans le certificat.",
            [refs.ANSSI_TLS, refs.OWASP_TLS],
            {"erreur": cert.verify_error},
        )

    if cert.sans and not any(
        host == san or (san.startswith("*.") and host.endswith(san[1:])) for san in cert.sans
    ):
        run_.add(
            "TLS_CERT_HOSTNAME_MISMATCH", Severity.ELEVE,
            "Le nom du domaine ne figure pas dans le certificat",
            f"Noms couverts : {', '.join(cert.sans[:10])}",
            "Le certificat présenté ne couvre pas le domaine demandé : les navigateurs "
            "refusent la connexion. C'est souvent le signe d'une configuration de serveur "
            "incorrecte (mauvais hôte virtuel par défaut).",
            "Émettre un certificat couvrant le domaine, ou corriger la configuration du serveur.",
            [refs.ANSSI_TLS, refs.OWASP_TLS],
            {"noms_couverts": cert.sans[:30]},
        )

    if cert.tls_version in OBSOLETE_TLS:
        run_.add(
            "TLS_OBSOLETE_VERSION", Severity.CRITIQUE,
            f"La connexion est établie en {cert.tls_version}, version obsolète",
            f"Version négociée : {cert.tls_version} — suite : {cert.cipher}",
            "Les versions antérieures à TLS 1.2 comportent des faiblesses connues et ne sont "
            "plus considérées comme sûres : un attaquant bien placé peut déchiffrer ou altérer "
            "les échanges. Les navigateurs récents refusent d'ailleurs ces versions.",
            "Désactiver SSLv3, TLS 1.0 et TLS 1.1 sur le serveur et n'autoriser que TLS 1.2 "
            "et TLS 1.3, avec des suites cryptographiques recommandées.",
            [refs.ANSSI_TLS, refs.OWASP_TLS, refs.CIS_CONTROLS],
            {"version": cert.tls_version},
        )
    elif cert.tls_version:
        run_.add(
            "TLS_VERSION_OK", Severity.INFO,
            f"Connexion chiffrée en {cert.tls_version}",
            f"Version négociée : {cert.tls_version} — suite : {cert.cipher}",
            "La version négociée est considérée comme sûre à ce jour.",
            "Privilégier TLS 1.3 lorsque l'infrastructure le permet, et suivre les "
            "recommandations de l'ANSSI sur les suites cryptographiques.",
            [refs.ANSSI_TLS],
        )

    if cert.key_bits and cert.key_type and "rsa" in cert.key_type.lower():
        if cert.key_bits < WEAK_RSA_BITS:
            run_.add(
                "TLS_WEAK_KEY", Severity.ELEVE,
                f"La clé RSA du certificat ne fait que {cert.key_bits} bits",
                f"Type de clé : {cert.key_type} {cert.key_bits} bits",
                "Une clé RSA de moins de 2048 bits est trop courte face aux capacités de calcul "
                "actuelles : elle peut être cassée, ce qui permettrait d'usurper votre site.",
                "Régénérer le certificat avec une clé RSA de 3072 bits minimum, ou une clé "
                "elliptique (ECDSA P-256).",
                [refs.ANSSI_TLS, refs.OWASP_TLS],
                {"bits": cert.key_bits},
            )

    if cert.signature and cert.signature.lower() in WEAK_SIGNATURES:
        run_.add(
            "TLS_WEAK_SIGNATURE", Severity.ELEVE,
            f"Le certificat est signé avec l'algorithme obsolète {cert.signature.upper()}",
            f"Algorithme de signature : {cert.signature}",
            "Les algorithmes MD5 et SHA-1 sont cassés : il est possible de fabriquer un faux "
            "certificat présentant la même signature, donc d'usurper votre site.",
            "Faire réémettre le certificat avec une signature SHA-256 ou supérieure.",
            [refs.ANSSI_TLS, refs.OWASP_TLS],
            {"signature": cert.signature},
        )


def parse_cookies(raw_cookies: list[str]) -> list[dict]:
    """Extrait le nom et les attributs de sécurité des cookies, jamais leur valeur."""
    parsed = []
    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip() if parts else ""
        attributes = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        samesite = next(
            (p.split("=", 1)[1].strip().lower() for p in parts[1:]
             if p.lower().startswith("samesite=")),
            None,
        )
        parsed.append(
            {
                "nom": name,
                "secure": "secure" in attributes,
                "httponly": "httponly" in attributes,
                "samesite": samesite,
            }
        )
    return parsed


def evaluate_headers(
    run_: ModuleRun, headers: Mapping[str, str], raw_cookies: list[str], final_url: str
) -> None:
    """Transforme les en-têtes de la réponse en findings."""
    lower = {k.lower(): v for k, v in headers.items()}
    run_.data["headers"] = lower

    # --- HSTS ---
    hsts = lower.get("strict-transport-security")
    if not hsts:
        run_.add(
            "HTTP_HSTS_MISSING", Severity.MOYEN,
            "L'en-tête HSTS est absent",
            "Aucun en-tête « Strict-Transport-Security » dans la réponse.",
            "HSTS force le navigateur à n'utiliser que HTTPS pour votre domaine. Sans lui, la "
            "toute première visite peut être interceptée et basculée en HTTP non chiffré, ce qui "
            "permet de lire ou modifier les échanges, y compris les identifiants saisis.",
            "Ajouter « Strict-Transport-Security: max-age=31536000; includeSubDomains » après "
            "avoir vérifié que tous les sous-domaines sont bien servis en HTTPS.",
            [refs.RFC_HSTS, refs.OWASP_HEADERS, refs.ANSSI_SITE_WEB],
        )
    else:
        max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        if max_age < HSTS_MIN_AGE:
            run_.add(
                "HTTP_HSTS_SHORT", Severity.FAIBLE,
                f"La durée HSTS est courte ({max_age} s)",
                f"En-tête reçu : {hsts}",
                "Une durée inférieure à un an laisse une fenêtre pendant laquelle le navigateur "
                "peut à nouveau accepter une connexion en clair.",
                "Porter « max-age » à 31536000 (un an) au minimum.",
                [refs.RFC_HSTS, refs.OWASP_HEADERS],
                {"max_age": max_age},
            )
        if "includesubdomains" not in hsts.lower():
            run_.add(
                "HTTP_HSTS_NO_SUBDOMAINS", Severity.FAIBLE,
                "HSTS ne couvre pas les sous-domaines",
                f"En-tête reçu : {hsts}",
                "Sans « includeSubDomains », un sous-domaine servi en clair reste exploitable "
                "pour intercepter des cookies ou tromper un visiteur.",
                "Ajouter « includeSubDomains » une fois tous les sous-domaines passés en HTTPS.",
                [refs.RFC_HSTS, refs.OWASP_HEADERS],
            )
        elif "preload" not in hsts.lower():
            run_.add(
                "HTTP_HSTS_NO_PRELOAD", Severity.INFO,
                "HSTS est correctement configuré mais sans inscription préalable (preload)",
                f"En-tête reçu : {hsts}",
                "L'inscription sur la liste « preload » des navigateurs protège aussi la "
                "première visite, avant tout contact avec votre serveur.",
                "Envisager l'inscription sur hstspreload.org, en mesurant son caractère "
                "difficilement réversible.",
                [refs.RFC_HSTS],
            )

    # --- CSP ---
    csp = lower.get("content-security-policy")
    if not csp:
        run_.add(
            "HTTP_CSP_MISSING", Severity.MOYEN,
            "Aucune politique de sécurité du contenu (CSP)",
            "Aucun en-tête « Content-Security-Policy » dans la réponse.",
            "La CSP indique au navigateur quelles ressources il peut charger et exécuter. "
            "Sans elle, une faille d'injection de code (XSS) permet d'exécuter n'importe quel "
            "script dans la page : vol de session, défiguration, redirection vers du hameçonnage.",
            "Déployer une CSP, d'abord en mode rapport (« Content-Security-Policy-Report-Only ») "
            "pour mesurer l'impact, puis en mode bloquant avec « default-src 'self' ».",
            [refs.OWASP_CSP, refs.OWASP_HEADERS, refs.ANSSI_SITE_WEB],
        )
    else:
        unsafe = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token in csp.lower()]
        if unsafe:
            run_.add(
                "HTTP_CSP_UNSAFE", Severity.FAIBLE,
                f"La CSP autorise {' et '.join(unsafe)}",
                f"Politique reçue : {csp[:300]}",
                "Ces directives rétablissent l'exécution de scripts écrits directement dans la "
                "page, ce qui annule l'essentiel de la protection contre les injections de code.",
                "Remplacer ces autorisations par des « nonces » ou des empreintes de scripts.",
                [refs.OWASP_CSP],
                {"directives": unsafe},
            )

    # --- protection contre l'insertion dans un cadre ---
    xfo = lower.get("x-frame-options")
    if not xfo and (not csp or "frame-ancestors" not in csp.lower()):
        run_.add(
            "HTTP_XFO_MISSING", Severity.MOYEN,
            "Rien n'empêche l'inclusion du site dans un cadre (clickjacking)",
            "Ni « X-Frame-Options » ni la directive CSP « frame-ancestors » ne sont présents.",
            "Un attaquant peut afficher votre site dans un cadre invisible sur sa propre page et "
            "faire cliquer la victime sur vos boutons sans qu'elle s'en aperçoive — par exemple "
            "pour valider un virement ou modifier des droits.",
            "Ajouter la directive CSP « frame-ancestors 'self' », complétée au besoin par "
            "« X-Frame-Options: SAMEORIGIN » pour les navigateurs anciens.",
            [refs.OWASP_HEADERS, refs.ANSSI_SITE_WEB],
        )

    # --- divers en-têtes ---
    if lower.get("x-content-type-options", "").lower() != "nosniff":
        run_.add(
            "HTTP_NOSNIFF_MISSING", Severity.FAIBLE,
            "L'en-tête « X-Content-Type-Options: nosniff » est absent",
            f"Valeur reçue : {lower.get('x-content-type-options') or 'aucune'}",
            "Sans cet en-tête, le navigateur peut deviner le type d'un fichier et exécuter "
            "comme script un contenu téléversé par un utilisateur.",
            "Ajouter « X-Content-Type-Options: nosniff » sur toutes les réponses.",
            [refs.OWASP_HEADERS],
        )

    if not lower.get("referrer-policy"):
        run_.add(
            "HTTP_REFERRER_POLICY_MISSING", Severity.FAIBLE,
            "Aucune politique de référent (Referrer-Policy)",
            "Aucun en-tête « Referrer-Policy » dans la réponse.",
            "Sans politique de référent, le navigateur transmet l'adresse complète de vos pages "
            "aux sites tiers. Des informations sensibles présentes dans les URL (identifiants, "
            "jetons, noms de clients) peuvent ainsi fuiter.",
            "Ajouter « Referrer-Policy: strict-origin-when-cross-origin ».",
            [refs.OWASP_HEADERS, refs.ANSSI_SITE_WEB],
        )

    if not lower.get("permissions-policy"):
        run_.add(
            "HTTP_PERMISSIONS_POLICY_MISSING", Severity.INFO,
            "Aucune politique d'autorisations (Permissions-Policy)",
            "Aucun en-tête « Permissions-Policy » dans la réponse.",
            "Cet en-tête permet de désactiver explicitement l'accès à la caméra, au micro ou à "
            "la géolocalisation pour les contenus de la page, y compris les cadres tiers.",
            "Ajouter une politique restrictive, par exemple "
            "« Permissions-Policy: camera=(), microphone=(), geolocation=() ».",
            [refs.OWASP_HEADERS],
        )

    # --- divulgation de version ---
    disclosed = {
        name: value
        for name, value in lower.items()
        if name in ("server", "x-powered-by", "x-aspnet-version", "x-generator")
        and value and _VERSION_RE.search(value)
    }
    if disclosed:
        run_.add(
            "HTTP_VERSION_DISCLOSURE", Severity.FAIBLE,
            "Les en-têtes révèlent la version précise des logiciels serveur",
            "En-têtes concernés : "
            + ", ".join(f"{name}: {value}" for name, value in disclosed.items()),
            "Connaître la version exacte du serveur permet à un attaquant de rechercher "
            "directement les vulnérabilités publiées correspondantes, sans avoir à tâtonner.",
            "Masquer ou raccourcir ces en-têtes dans la configuration du serveur.",
            [refs.OWASP_HEADERS, refs.ANSSI_SITE_WEB],
            {"entetes": disclosed},
        )

    # --- cookies (noms et attributs uniquement, jamais les valeurs) ---
    cookies = parse_cookies(raw_cookies)
    run_.data["temoins"] = cookies
    insecure = [c["nom"] for c in cookies if not c["secure"]]
    no_httponly = [c["nom"] for c in cookies if not c["httponly"]]
    no_samesite = [c["nom"] for c in cookies if not c["samesite"]]

    if insecure:
        run_.add(
            "HTTP_COOKIE_NOT_SECURE", Severity.ELEVE,
            f"{len(insecure)} cookie(s) sans attribut « Secure »",
            "Cookies concernés : " + ", ".join(insecure[:10]),
            "Un cookie sans l'attribut « Secure » est renvoyé par le navigateur même sur une "
            "connexion non chiffrée : il peut être capté sur un réseau partagé, ce qui permet "
            "de détourner la session d'un utilisateur.",
            "Ajouter l'attribut « Secure » à tous les cookies.",
            [refs.OWASP_HEADERS, refs.ANSSI_SITE_WEB],
            {"cookies": insecure[:20]},
        )
    if no_httponly:
        run_.add(
            "HTTP_COOKIE_NOT_HTTPONLY", Severity.MOYEN,
            f"{len(no_httponly)} cookie(s) accessibles au JavaScript de la page",
            "Cookies concernés : " + ", ".join(no_httponly[:10]),
            "Sans l'attribut « HttpOnly », un script injecté dans la page peut lire le cookie de "
            "session et le transmettre à un attaquant, qui prend alors la place de l'utilisateur.",
            "Ajouter l'attribut « HttpOnly » aux cookies qui n'ont pas besoin d'être lus par le "
            "code de la page.",
            [refs.OWASP_HEADERS],
            {"cookies": no_httponly[:20]},
        )
    if no_samesite:
        run_.add(
            "HTTP_COOKIE_NO_SAMESITE", Severity.FAIBLE,
            f"{len(no_samesite)} cookie(s) sans attribut « SameSite »",
            "Cookies concernés : " + ", ".join(no_samesite[:10]),
            "L'attribut « SameSite » empêche l'envoi du cookie lors des requêtes déclenchées "
            "depuis un autre site, ce qui limite les actions effectuées à l'insu de "
            "l'utilisateur (CSRF).",
            "Définir « SameSite=Lax » par défaut, ou « Strict » pour les cookies sensibles.",
            [refs.OWASP_HEADERS],
            {"cookies": no_samesite[:20]},
        )

    run_.data["url_finale"] = final_url


async def run(ctx: ModuleContext) -> ModuleResult:
    """Analyse le certificat TLS puis les en-têtes de sécurité de la page d'accueil."""
    run_ = ModuleRun(KEY)
    host = ctx.name

    if not ctx.recon.resolves:
        return run_.failed("le domaine ne résout pas : aucun service web à analyser")

    # ---------------------------------------------------------- certificat --
    cert, cert_error = await fetch_certificate(host, timeout=min(12.0, ctx.settings.http_timeout))
    if cert is not None:
        run_.data["certificat"] = {
            "sujet": cert.subject,
            "emetteur": cert.issuer,
            "valide_du": cert.not_before.isoformat() if cert.not_before else None,
            "valide_au": cert.not_after.isoformat() if cert.not_after else None,
            "jours_restants": cert.days_left,
            "noms_couverts": cert.sans[:50],
            "version_tls": cert.tls_version,
            "suite": cert.cipher,
            "cle": f"{cert.key_type} {cert.key_bits}" if cert.key_bits else None,
            "signature": cert.signature,
            "valide": cert.verified,
        }
        evaluate_certificate(run_, cert, host)
    else:
        behind_proxy = bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"))
        raison = (
            "la machine d'analyse sort par un proxy HTTPS, qui termine la connexion TLS à la "
            "place du serveur cible"
            if behind_proxy
            else "la poignée de main TLS n'a pas abouti"
        )
        run_.error(f"inspection du certificat impossible : {raison} ({cert_error})")
        run_.add(
            "TLS_CERT_NOT_INSPECTED", Severity.INFO,
            "Le certificat n'a pas pu être inspecté depuis cette machine",
            f"Cause : {raison}. Détail technique : {cert_error}",
            "Ce point n'est pas un défaut du domaine analysé : c'est une limite de "
            "l'environnement d'exécution. Les en-têtes HTTP, eux, ont bien été analysés.",
            "Relancer l'analyse depuis une machine disposant d'un accès direct au port 443, ou "
            "vérifier le certificat avec un service dédié.",
            [refs.ANSSI_TLS],
        )

    # ------------------------------------------------------------ en-têtes --
    result = await ctx.http.request("cible", f"https://{host}/", use_cache=False)
    run_.source(result.source_ref(label=f"Page d'accueil https://{host}/"))
    if not result.ok:
        run_.error(f"page d'accueil inaccessible en HTTPS : {result.describe_error()}")
        if cert is None:
            return run_.failed("ni le certificat ni les en-têtes n'ont pu être analysés")
        return run_.done(status=ModuleStatus.PARTIAL)

    evaluate_headers(run_, result.headers, result.cookies, result.url)
    if result.url.rstrip("/") != f"https://{host}":
        run_.data["redirection_finale"] = result.url

    # ------------------------------------------- redirection HTTP -> HTTPS --
    if ctx.settings.check_http_redirect:
        plain = await ctx.http.request(
            "cible", f"http://{host}/", follow_redirects=False, use_cache=False, timeout=8.0,
            retries=1,
        )
        if not plain.ok and plain.status is None:
            run_.error(
                f"vérification de la redirection HTTP impossible depuis cette machine "
                f"({plain.describe_error()})"
            )
        else:
            location = plain.headers.get("location", "")
            run_.data["http_status"] = plain.status
            run_.data["http_location"] = location
            if plain.status in (301, 308) and location.startswith("https://"):
                run_.add(
                    "HTTP_REDIRECT_OK", Severity.INFO,
                    "Le site redirige le trafic en clair vers HTTPS de façon permanente",
                    f"HTTP {plain.status} vers {location}",
                    "Un visiteur qui tape l'adresse sans « https:// » est automatiquement "
                    "basculé vers la version chiffrée.",
                    "Conserver cette redirection et la compléter par HSTS.",
                    [refs.RFC_HSTS, refs.ANSSI_SITE_WEB],
                )
            elif plain.status in (302, 303, 307) and location.startswith("https://"):
                run_.add(
                    "HTTP_REDIRECT_TEMPORARY", Severity.FAIBLE,
                    "La redirection vers HTTPS est temporaire et non permanente",
                    f"HTTP {plain.status} vers {location}",
                    "Une redirection temporaire n'est pas mémorisée par les navigateurs ni par "
                    "les listes HSTS : chaque nouvelle visite repart en clair.",
                    "Utiliser une redirection permanente (301 ou 308).",
                    [refs.RFC_HSTS],
                )
            elif plain.status is not None and 200 <= plain.status < 300:
                run_.add(
                    "HTTP_NO_REDIRECT", Severity.ELEVE,
                    "Le site répond en clair sans rediriger vers HTTPS",
                    f"http://{host}/ répond HTTP {plain.status} sans redirection.",
                    "Le contenu est servi sans chiffrement : tout ce qui transite — pages "
                    "consultées, formulaires, identifiants — peut être lu ou modifié par qui "
                    "contrôle le réseau, par exemple un Wi-Fi public.",
                    "Rediriger systématiquement le port 80 vers HTTPS en 301, puis activer HSTS.",
                    [refs.RFC_HSTS, refs.ANSSI_SITE_WEB, refs.OWASP_TLS],
                )

    return run_.done(status=ModuleStatus.PARTIAL if run_.errors else ModuleStatus.OK)
