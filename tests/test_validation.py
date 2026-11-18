"""Validation stricte du domaine saisi."""

import pytest

from app.validation import InvalidDomain, normalize_domain


@pytest.mark.parametrize(
    ("saisie", "attendu"),
    [
        ("exemple.fr", "exemple.fr"),
        ("EXEMPLE.FR", "exemple.fr"),
        ("  exemple.fr  ", "exemple.fr"),
        ("exemple.fr.", "exemple.fr"),
        ("sous.domaine.co.uk", "sous.domaine.co.uk"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
        ("ÉLYSÉE.fr", "xn--lyse-9oad.fr"),
    ],
)
def test_domaines_acceptes(saisie, attendu):
    assert normalize_domain(saisie).ascii == attendu


def test_idn_conserve_la_forme_lisible():
    domaine = normalize_domain("münchen.de")
    assert domaine.unicode == "münchen.de"
    assert domaine.is_idn is True
    assert domaine.tld == "de"


@pytest.mark.parametrize(
    "saisie",
    [
        "https://exemple.fr/page",
        "exemple.fr/chemin",
        "1.1.1.1",
        "2606:4700::1",
        "exemple.fr:443",
        "admin@exemple.fr",
        "*.exemple.fr",
        "exemple",
        "localhost",
        "machine.local",
        "serveur.internal",
        "a_b.fr",
        "exem ple.fr",
        "exemple.123",
        "..fr",
        "",
        None,
    ],
)
def test_domaines_refuses(saisie):
    with pytest.raises(InvalidDomain):
        normalize_domain(saisie)


def test_le_message_de_refus_est_en_francais_et_exploitable():
    with pytest.raises(InvalidDomain) as exc:
        normalize_domain("https://exemple.fr/x")
    assert "nom de domaine" in exc.value.reason.lower()
    assert exc.value.hint


def test_label_trop_long_refuse():
    with pytest.raises(InvalidDomain):
        normalize_domain("a" * 64 + ".fr")
