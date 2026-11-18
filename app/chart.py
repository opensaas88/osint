"""Courbe d'évolution du score, rendue en SVG.

Un seul graphique dans l'application, et une seule implémentation : le SVG produit
ici est embarqué tel quel dans le rapport (WeasyPrint le rend sans JavaScript) et
injecté dans l'interface, qui obtient les infobulles par les éléments `<title>`.

Choix de représentation :
  * échelle verticale fixée de 0 à 100, jamais ajustée aux données — un cadrage
    automatique exagérerait visuellement une variation de deux points ;
  * un seul jeu de données, donc pas de légende : le titre dit ce qui est tracé ;
  * trait fin, grille discrète, et une seule valeur étiquetée, la dernière.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

#: Couleurs de la courbe : encre sobre pour le tracé, état pour le point courant.
TRACE = "#2a78d6"
GRILLE = "#e3e3df"
ENCRE = "#52514e"
SURFACE = "#fcfcfb"

BANDES = (
    (80, "#0ca30c"),
    (70, "#fab219"),
    (60, "#ec835a"),
    (0, "#d03b3b"),
)


def couleur_du_score(score: int | None) -> str:
    if score is None:
        return ENCRE
    for seuil, couleur in BANDES:
        if score >= seuil:
            return couleur
    return BANDES[-1][1]


def _date_courte(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).strftime("%d/%m/%y")
    except ValueError:
        return str(iso)[:10]


def score_evolution_svg(
    points: list[dict[str, Any]], largeur: int = 620, hauteur: int = 170
) -> str:
    """Trace l'évolution du score. `points` : [{date, score, grade}], du plus ancien au plus récent.

    Retourne une chaîne vide s'il y a moins de deux mesures : une courbe à un point
    n'apprend rien et occuperait la place d'une information utile.
    """
    mesures = [p for p in points if p.get("score") is not None]
    if len(mesures) < 2:
        return ""

    marge_g, marge_d, marge_h, marge_b = 34, 46, 14, 26
    aire_l = largeur - marge_g - marge_d
    aire_h = hauteur - marge_h - marge_b

    def x(index: int) -> float:
        return marge_g + (aire_l * index / (len(mesures) - 1))

    def y(score: int) -> float:
        return marge_h + aire_h * (1 - max(0, min(100, score)) / 100)

    grille = "".join(
        f'<line x1="{marge_g}" y1="{y(v):.1f}" x2="{marge_g + aire_l}" y2="{y(v):.1f}" '
        f'stroke="{GRILLE}" stroke-width="1"/>'
        f'<text x="{marge_g - 6}" y="{y(v) + 3.5:.1f}" text-anchor="end" font-size="9" '
        f'fill="{ENCRE}">{v}</text>'
        for v in (0, 50, 100)
    )

    tracé = " ".join(
        f"{'M' if i == 0 else 'L'}{x(i):.1f},{y(p['score']):.1f}"
        for i, p in enumerate(mesures)
    )

    marqueurs = []
    for i, p in enumerate(mesures):
        dernier = i == len(mesures) - 1
        rayon = 5 if dernier else 3.5
        couleur = couleur_du_score(p["score"]) if dernier else TRACE
        marqueurs.append(
            f'<circle cx="{x(i):.1f}" cy="{y(p["score"]):.1f}" r="{rayon}" fill="{couleur}" '
            f'stroke="{SURFACE}" stroke-width="2">'
            f"<title>{_date_courte(p.get('date'))} : {p['score']}/100"
            f"{' (' + str(p['grade']) + ')' if p.get('grade') else ''}</title></circle>"
        )

    final = mesures[-1]
    etiquette = (
        f'<text x="{x(len(mesures) - 1) + 10:.1f}" y="{y(final["score"]) + 4:.1f}" '
        f'font-size="12" font-weight="600" fill="{couleur_du_score(final["score"])}">'
        f'{final["score"]}{" " + str(final["grade"]) if final.get("grade") else ""}</text>'
    )

    dates = (
        f'<text x="{marge_g}" y="{hauteur - 8}" font-size="9" fill="{ENCRE}">'
        f"{_date_courte(mesures[0].get('date'))}</text>"
        f'<text x="{marge_g + aire_l}" y="{hauteur - 8}" font-size="9" fill="{ENCRE}" '
        f'text-anchor="end">{_date_courte(final.get("date"))}</text>'
    )

    return (
        f'<svg viewBox="0 0 {largeur} {hauteur}" width="100%" height="{hauteur}" '
        f'role="img" aria-label="Évolution du score d\'exposition, de '
        f'{_date_courte(mesures[0].get("date"))} à {_date_courte(final.get("date"))}, '
        f'valeur actuelle {final["score"]} sur 100" '
        f'xmlns="http://www.w3.org/2000/svg" font-family="DejaVu Sans, Helvetica, Arial, '
        f'sans-serif">{grille}'
        f'<path d="{tracé}" fill="none" stroke="{TRACE}" stroke-width="2" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
        f'{"".join(marqueurs)}{etiquette}{dates}</svg>'
    )
