"""References normatives citees par les findings.

Les URL des standards (RFC, OWASP, CIS) sont stables. Pour l'ANSSI, le titre exact
du guide est donné et l'URL pointe sur le catalogue des publications, dont les
adresses de documents évoluent au fil des rééditions.
"""

from __future__ import annotations

from .models import Reference

ANSSI_PUBLICATIONS = "https://cyber.gouv.fr/publications"

# --- ANSSI -----------------------------------------------------------------
ANSSI_MESSAGERIE = Reference(
    framework="ANSSI",
    label="Recommandations relatives à la sécurisation des systèmes de messagerie électronique",
    url=ANSSI_PUBLICATIONS,
)
ANSSI_TLS = Reference(
    framework="ANSSI",
    label="Recommandations de sécurité relatives à TLS (v1.2)",
    url=ANSSI_PUBLICATIONS,
)
ANSSI_SITE_WEB = Reference(
    framework="ANSSI",
    label="Recommandations pour la sécurisation des sites web",
    url=ANSSI_PUBLICATIONS,
)
ANSSI_DNS = Reference(
    framework="ANSSI",
    label="Bonnes pratiques d'administration et de sécurisation du service DNS",
    url=ANSSI_PUBLICATIONS,
)
ANSSI_CARTOGRAPHIE = Reference(
    framework="ANSSI",
    label="Cartographie du système d'information — guide d'élaboration",
    url=ANSSI_PUBLICATIONS,
)
ANSSI_ATTAQUE_PAR_RANCON = Reference(
    framework="ANSSI",
    label="Attaques par rançongiciels, tous concernés — guide de prévention et de remédiation",
    url=ANSSI_PUBLICATIONS,
)
ANSSI_MOTS_DE_PASSE = Reference(
    framework="ANSSI",
    label="Recommandations relatives à l'authentification multifacteur et aux mots de passe",
    url=ANSSI_PUBLICATIONS,
)
ANSSI_NOMS_DE_DOMAINE = Reference(
    framework="ANSSI",
    label="Recommandations relatives à la gestion des noms de domaine",
    url=ANSSI_PUBLICATIONS,
)

# --- CIS -------------------------------------------------------------------
CIS_CONTROLS = Reference(
    framework="CIS",
    label="CIS Controls v8",
    url="https://www.cisecurity.org/controls/cis-controls-list",
)
CIS_INVENTAIRE = Reference(
    framework="CIS",
    label="CIS Control 1 & 2 — inventaire des actifs et des logiciels",
    url="https://www.cisecurity.org/controls/cis-controls-list",
)
CIS_VULN = Reference(
    framework="CIS",
    label="CIS Control 7 — gestion continue des vulnérabilités",
    url="https://www.cisecurity.org/controls/cis-controls-list",
)
CIS_EMAIL = Reference(
    framework="CIS",
    label="CIS Control 9 — protection de la messagerie et des navigateurs",
    url="https://www.cisecurity.org/controls/cis-controls-list",
)

# --- OWASP -----------------------------------------------------------------
OWASP_HEADERS = Reference(
    framework="OWASP",
    label="HTTP Security Headers Cheat Sheet",
    url="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
)
OWASP_TLS = Reference(
    framework="OWASP",
    label="Transport Layer Security Cheat Sheet",
    url="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
)
OWASP_CSP = Reference(
    framework="OWASP",
    label="Content Security Policy Cheat Sheet",
    url="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
)
OWASP_CREDENTIAL_STUFFING = Reference(
    framework="OWASP",
    label="Credential Stuffing Prevention Cheat Sheet",
    url="https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html",
)

# --- RFC et standards ------------------------------------------------------
RFC_SPF = Reference(framework="RFC", label="RFC 7208 — Sender Policy Framework",
                    url="https://datatracker.ietf.org/doc/html/rfc7208")
RFC_DMARC = Reference(framework="RFC", label="RFC 7489 — DMARC",
                      url="https://datatracker.ietf.org/doc/html/rfc7489")
RFC_DKIM = Reference(framework="RFC", label="RFC 6376 — DomainKeys Identified Mail",
                     url="https://datatracker.ietf.org/doc/html/rfc6376")
RFC_MTA_STS = Reference(framework="RFC", label="RFC 8461 — SMTP MTA Strict Transport Security",
                        url="https://datatracker.ietf.org/doc/html/rfc8461")
RFC_NULL_MX = Reference(framework="RFC", label="RFC 7505 — Null MX",
                        url="https://datatracker.ietf.org/doc/html/rfc7505")
RFC_DNSSEC = Reference(framework="RFC", label="RFC 4033 — DNS Security Introduction",
                       url="https://datatracker.ietf.org/doc/html/rfc4033")
RFC_CAA = Reference(framework="RFC", label="RFC 8659 — DNS Certification Authority Authorization",
                    url="https://datatracker.ietf.org/doc/html/rfc8659")
RFC_HSTS = Reference(framework="RFC", label="RFC 6797 — HTTP Strict Transport Security",
                     url="https://datatracker.ietf.org/doc/html/rfc6797")
BIMI_SPEC = Reference(framework="Standard", label="BIMI — Brand Indicators for Message Identification",
                      url="https://bimigroup.org/")
