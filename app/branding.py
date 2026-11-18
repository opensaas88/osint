"""Marque blanche : identité du prestataire dans l'interface et les rapports.

Le logo est incorporé en base64 plutôt que référencé par une URL : le rapport HTML
doit rester un fichier autonome, lisible hors ligne et transmissible tel quel.
"""

from __future__ import annotations

import base64
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

#: Taille maximale du logo incorporé. Au-delà, le rapport deviendrait inutilement
#: lourd pour un élément décoratif.
MAX_LOGO_OCTETS = 512 * 1024

TYPES_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".gif": "image/gif",
}

_COULEUR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


@lru_cache(maxsize=8)
def logo_data_uri(chemin: str | None) -> str | None:
    """Incorpore le logo en data URI, ou None s'il est absent ou inexploitable."""
    if not chemin:
        return None
    fichier = Path(chemin)
    if not fichier.is_file():
        return None
    mime = TYPES_MIME.get(fichier.suffix.lower())
    if mime is None:
        return None
    octets = fichier.read_bytes()
    if len(octets) > MAX_LOGO_OCTETS:
        return None
    return f"data:{mime};base64,{base64.b64encode(octets).decode('ascii')}"


def couleur_valide(valeur: str | None, defaut: str = "#256abf") -> str:
    """N'accepte qu'une couleur hexadécimale : la valeur part dans du CSS."""
    return valeur if valeur and _COULEUR_RE.match(valeur) else defaut


def branding(settings) -> dict[str, Any]:
    """Identité visuelle à appliquer, prête à l'emploi."""
    return {
        "nom": settings.brand_name or "DomainExposure",
        "couleur": couleur_valide(settings.brand_color),
        "logo": logo_data_uri(
            str(settings.brand_logo_path) if settings.brand_logo_path else None
        ),
        "pied_de_page": settings.brand_footer,
    }
