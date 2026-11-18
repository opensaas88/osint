"""Garde-fous ethiques : aucune donnee personnelle en clair, aucun secret stocke.

Deux couches complementaires :
  1. une whitelist explicite de champs par source (appliquee dans les modules) ;
  2. un filet de securite recursif applique a tout resultat avant stockage.
"""

from __future__ import annotations

import re
from typing import Any

#: Clefs dont la presence est interdite dans un resultat, quelle que soit la source.
FORBIDDEN_KEY_RE = re.compile(
    r"(?i)(pass(word|wd|phrase)?|pwd|hash|md5|sha_?\d+|ntlm|bcrypt|scrypt|argon|salt"
    r"|secret|api[_-]?key|access[_-]?token|token|credential|cookie|session[_-]?id"
    r"|cvv|iban|card[_-]?number|ssn|social[_-]?security|birth|dob|plaintext|cleartext)"
)

_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

MAX_STRING_LENGTH = 2000
REDACTED = "[supprime par DomainExposure]"


def mask_email(email: str) -> str:
    """Masque une adresse email : `jean.dupont@exemple.fr` -> `j***@exemple.fr`."""
    email = (email or "").strip()
    if "@" not in email:
        return "***"
    local, _, domain = email.rpartition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


def mask_emails_in_text(text: str) -> str:
    """Masque toute adresse email apparaissant dans un texte libre."""
    return _EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)


def pick(data: dict[str, Any], allowed: tuple[str, ...]) -> dict[str, Any]:
    """Whitelist : ne conserve que les champs explicitement autorises."""
    return {k: data[k] for k in allowed if k in data and data[k] is not None}


def scrub(value: Any, _depth: int = 0) -> Any:
    """Filet de securite : retire recursivement tout champ sensible et masque les emails.

    Applique a chaque `ModuleResult` avant stockage, de sorte qu'aucun mot de passe,
    hash ou adresse en clair ne puisse se retrouver en base meme si une source
    modifie son format sans preavis.
    """
    if _depth > 12:
        return REDACTED
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and FORBIDDEN_KEY_RE.search(key):
                cleaned[key] = REDACTED
                continue
            cleaned[key] = scrub(item, _depth + 1)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [scrub(item, _depth + 1) for item in value]
    if isinstance(value, str):
        text = mask_emails_in_text(value)
        if len(text) > MAX_STRING_LENGTH:
            text = text[:MAX_STRING_LENGTH] + " […]"
        return text
    return value


def scrub_module_result(result) -> None:
    """Nettoie en place les donnees d'un `ModuleResult` (evidence et data)."""
    result.data = scrub(result.data)
    for finding in result.findings:
        finding.evidence = scrub(finding.evidence)
