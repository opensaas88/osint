"""Marque blanche."""

import base64

from app.branding import branding, couleur_valide, logo_data_uri
from app.config import Settings


def test_valeurs_par_defaut():
    marque = branding(Settings(_env_file=None))
    assert marque["nom"] == "DomainExposure"
    assert marque["couleur"] == "#256abf"
    assert marque["logo"] is None


def test_identite_personnalisee():
    marque = branding(Settings(
        _env_file=None, brand_name="OpenSaaS Cyber", brand_color="#0b5fff",
        brand_footer="mission 2026-114",
    ))
    assert marque["nom"] == "OpenSaaS Cyber"
    assert marque["couleur"] == "#0b5fff"
    assert marque["pied_de_page"] == "mission 2026-114"


def test_une_couleur_invalide_ne_part_pas_dans_le_css():
    """La couleur est injectée dans un attribut style : elle doit être validée."""
    for hostile in ("javascript:alert(1)", "red; background:url(x)", "#12", "", None):
        assert couleur_valide(hostile) == "#256abf"
    assert couleur_valide("#AABBCC") == "#AABBCC"


def test_logo_incorpore_en_base64(tmp_path):
    """Le rapport doit rester un fichier autonome : pas d'URL externe."""
    fichier = tmp_path / "logo.png"
    contenu = b"\x89PNG\r\n\x1a\n-faux-png"
    fichier.write_bytes(contenu)
    uri = logo_data_uri(str(fichier))
    assert uri.startswith("data:image/png;base64,")
    assert base64.b64decode(uri.split(",", 1)[1]) == contenu


def test_logo_absent_ou_inexploitable(tmp_path):
    assert logo_data_uri(None) is None
    assert logo_data_uri(str(tmp_path / "absent.png")) is None
    exotique = tmp_path / "logo.bmp"
    exotique.write_bytes(b"x")
    assert logo_data_uri(str(exotique)) is None


def test_logo_trop_lourd_est_refuse(tmp_path):
    fichier = tmp_path / "gros.png"
    fichier.write_bytes(b"\x00" * (512 * 1024 + 1))
    assert logo_data_uri(str(fichier)) is None
