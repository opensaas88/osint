"""Export PDF via WeasyPrint, avec désactivation propre si la bibliothèque manque."""

from __future__ import annotations

from typing import Any

from .html import render_html


class PdfUnavailable(RuntimeError):
    """WeasyPrint ou ses dépendances système ne sont pas disponibles."""


def pdf_available() -> tuple[bool, str | None]:
    """Indique si l'export PDF est possible, et la raison de l'indisponibilité."""
    try:
        import weasyprint  # noqa: F401
    except Exception as exc:  # ImportError, OSError (pango/cairo absents)...
        return False, (
            "WeasyPrint est indisponible : "
            f"{type(exc).__name__} — {str(exc)[:200]}. "
            "L'export HTML autonome reste disponible. Sous Debian/Ubuntu, installer "
            "libpango-1.0-0, libpangoft2-1.0-0 et libharfbuzz0b."
        )
    return True, None


def render_pdf(report: dict[str, Any], settings) -> bytes:
    """Produit le PDF du rapport. Lève `PdfUnavailable` si WeasyPrint manque."""
    available, reason = pdf_available()
    if not available:
        raise PdfUnavailable(reason or "WeasyPrint indisponible")

    from weasyprint import HTML

    html = render_html(report, settings)
    return HTML(string=html).write_pdf()
