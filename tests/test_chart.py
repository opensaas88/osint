"""Courbe d'évolution du score."""

from app.chart import couleur_du_score, score_evolution_svg


def points(*scores):
    return [
        {"date": f"2026-0{i + 1}-01T10:00:00+00:00", "score": s, "grade": "C"}
        for i, s in enumerate(scores)
    ]


def test_moins_de_deux_mesures_ne_trace_rien():
    """Une courbe à un point occuperait la place d'une information utile."""
    assert score_evolution_svg([]) == ""
    assert score_evolution_svg(points(70)) == ""


def test_les_mesures_sans_score_sont_ignorees():
    mesures = [{"date": "2026-01-01", "score": None}, {"date": "2026-02-01", "score": 80}]
    assert score_evolution_svg(mesures) == ""


def test_svg_bien_forme_et_accessible():
    svg = score_evolution_svg(points(45, 69, 91))
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert 'role="img"' in svg
    # L'alternative textuelle résume la série pour qui n'en voit pas le tracé.
    alternative = svg.split('aria-label="')[1].split('"')[0]
    assert "Évolution du score" in alternative and "91" in alternative
    # Une infobulle par mesure : la valeur reste accessible au survol.
    assert svg.count("<title>") == 3
    assert svg.count("<circle") == 3


def test_echelle_verticale_toujours_de_zero_a_cent():
    """Un cadrage automatique exagérerait une variation de deux points."""
    plat = score_evolution_svg(points(80, 82))
    assert ">0</text>" in plat and ">100</text>" in plat
    # Les deux points restent proches verticalement malgré l'écart de 2 points.
    import re
    ys = [float(v) for v in re.findall(r'<circle cx="[\d.]+" cy="([\d.]+)"', plat)]
    assert abs(ys[0] - ys[1]) < 10


def test_le_point_courant_est_colore_par_sa_bande_et_etiquete():
    svg = score_evolution_svg(points(40, 95))
    assert couleur_du_score(95) in svg  # vert : bande A/B
    assert ">95 C</text>" in svg or ">95" in svg


def test_couleur_par_bande():
    assert couleur_du_score(95) == "#0ca30c"
    assert couleur_du_score(75) == "#fab219"
    assert couleur_du_score(65) == "#ec835a"
    assert couleur_du_score(30) == "#d03b3b"


def test_dates_extremes_seulement_sur_laxe():
    """Étiqueter chaque point rendrait l'axe illisible : seules les bornes le sont."""
    import re

    svg = score_evolution_svg(points(10, 20, 30, 40, 50))
    etiquettes = re.findall(r"<text[^>]*>([^<]+)</text>", svg)
    dates = [e for e in etiquettes if "/" in e]
    assert dates == ["01/01/26", "01/05/26"]
    # Les dates intermédiaires restent accessibles au survol, pas sur l'axe.
    assert "01/03/26" in svg
