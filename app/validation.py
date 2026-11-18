"""Validation stricte du domaine saisi : ni IP, ni URL, IDN pris en charge."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import idna

MAX_TOTAL_LENGTH = 253
MAX_LABEL_LENGTH = 63
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

#: TLD sans existence publique : une analyse OSINT passive n'y a aucun sens.
RESERVED_TLDS = frozenset(
    {"localhost", "local", "internal", "intranet", "lan", "home", "corp", "onion", "invalid", "test", "arpa"}
)


class InvalidDomain(ValueError):
    """Le domaine saisi est refuse. `reason` est affichable a l'utilisateur."""

    def __init__(self, reason: str, hint: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.hint = hint


@dataclass(frozen=True)
class DomainName:
    """Domaine normalise : forme ASCII pour les requetes, Unicode pour l'affichage."""

    ascii: str
    unicode: str

    def __str__(self) -> str:  # pragma: no cover - confort de debug
        return self.ascii

    @property
    def is_idn(self) -> bool:
        return self.ascii != self.unicode

    @property
    def tld(self) -> str:
        return self.ascii.rsplit(".", 1)[-1]


def normalize_domain(raw: str | None) -> DomainName:
    """Normalise et valide un nom de domaine.

    Leve `InvalidDomain` avec un message en francais si la saisie est refusee.
    """
    if raw is None:
        raise InvalidDomain("Aucun domaine fourni.")

    candidate = raw.strip().lower()
    if not candidate:
        raise InvalidDomain("Aucun domaine fourni.")

    if any(ch.isspace() for ch in candidate):
        raise InvalidDomain("Un nom de domaine ne contient pas d'espace.")

    if "://" in candidate or candidate.startswith("//"):
        raise InvalidDomain(
            "Saisis un nom de domaine, pas une URL.", hint="exemple.fr, et non https://exemple.fr/page"
        )
    for forbidden, message in (
        ("/", "Saisis un nom de domaine, pas une URL."),
        ("?", "Saisis un nom de domaine, sans paramètres d'URL."),
        ("#", "Saisis un nom de domaine, sans ancre."),
        ("@", "Saisis un nom de domaine, pas une adresse email."),
        ("_", "Un nom de domaine public ne contient pas de tiret bas."),
        (",", "Un seul domaine a la fois."),
        ("*", "Les jokers ne sont pas acceptés : indique un domaine précis."),
    ):
        if forbidden in candidate:
            raise InvalidDomain(message)

    if ":" in candidate:
        raise InvalidDomain("Indique le domaine seul, sans port ni adresse IPv6.")

    # Adresse IP deguisee ?
    is_ip = True
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        is_ip = False
    if is_ip:
        raise InvalidDomain(
            "Les adresses IP ne sont pas acceptées : l'analyse porte sur un nom de domaine.",
            hint="Indique le domaine qui pointe vers cette IP.",
        )

    candidate = candidate.rstrip(".")
    if candidate.startswith("."):
        raise InvalidDomain("Nom de domaine mal formé (point en début de chaîne).")
    if ".." in candidate:
        raise InvalidDomain("Nom de domaine mal formé (deux points consécutifs).")
    if "." not in candidate:
        raise InvalidDomain(
            "Il manque l'extension du domaine.", hint="exemple.fr plutôt que exemple"
        )

    # Conversion IDN -> punycode (UTS-46 : normalise aussi la casse et les variantes Unicode).
    try:
        ascii_name = idna.encode(candidate, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise InvalidDomain(f"Nom de domaine invalide ({exc}).") from exc

    if len(ascii_name) > MAX_TOTAL_LENGTH:
        raise InvalidDomain(f"Nom de domaine trop long ({len(ascii_name)} caractères, maximum 253).")

    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise InvalidDomain("Il manque l'extension du domaine.")
    for label in labels:
        if len(label) > MAX_LABEL_LENGTH:
            raise InvalidDomain(f"Le segment « {label[:20]}... » dépasse 63 caractères.")
        if not _LABEL_RE.match(label):
            raise InvalidDomain(f"Le segment « {label} » contient un caractère interdit.")

    tld = labels[-1]
    if tld.isdigit():
        raise InvalidDomain("L'extension d'un domaine ne peut pas être numérique.")
    if len(tld) < 2:
        raise InvalidDomain("Extension de domaine trop courte.")
    if tld in RESERVED_TLDS:
        raise InvalidDomain(
            f"L'extension « .{tld} » est réservée à un usage interne et n'est pas analysable publiquement."
        )

    try:
        unicode_name = idna.decode(ascii_name)
    except idna.IDNAError:
        unicode_name = ascii_name

    return DomainName(ascii=ascii_name, unicode=unicode_name)
