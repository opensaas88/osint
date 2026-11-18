"""Garanties éthiques : aucun secret ni donnée personnelle en clair ne doit subsister."""

import pytest

from app.models import Finding, ModuleResult, ModuleStatus, Severity
from app.sanitize import REDACTED, mask_email, mask_emails_in_text, pick, scrub, scrub_module_result


@pytest.mark.parametrize(
    ("entree", "attendu"),
    [
        ("jean.dupont@exemple.fr", "j***@exemple.fr"),
        ("a@exemple.fr", "a***@exemple.fr"),
        ("@exemple.fr", "***@exemple.fr"),
        ("pas-une-adresse", "***"),
    ],
)
def test_masquage_des_adresses(entree, attendu):
    assert mask_email(entree) == attendu


def test_masquage_dans_un_texte_libre():
    texte = "Contactez admin@exemple.fr ou secours@autre.org"
    masque = mask_emails_in_text(texte)
    assert "admin@exemple.fr" not in masque
    assert "a***@exemple.fr" in masque
    assert "s***@autre.org" in masque


@pytest.mark.parametrize(
    "cle",
    ["password", "Password", "passwd", "pwd_hash", "sha256", "md5", "ntlm", "salt",
     "api_key", "access_token", "session_id", "cookie", "iban", "card_number", "dob"],
)
def test_les_champs_sensibles_sont_supprimes(cle):
    assert scrub({cle: "valeur secrète"})[cle] == REDACTED


def test_les_metadonnees_de_fuite_sont_conservees():
    """Les catégories de données exposées sont des métadonnées : elles restent lisibles."""
    nettoye = scrub({"DataClasses": ["Passwords", "Email addresses"], "PwnCount": 1000})
    assert nettoye["DataClasses"] == ["Passwords", "Email addresses"]
    assert nettoye["PwnCount"] == 1000


def test_nettoyage_recursif_et_adresses_dans_les_textes():
    sale = {
        "niveau1": {"niveau2": [{"password": "x", "contact": "admin@exemple.fr"}]},
    }
    propre = scrub(sale)
    entree = propre["niveau1"]["niveau2"][0]
    assert entree["password"] == REDACTED
    assert entree["contact"] == "a***@exemple.fr"


def test_whitelist():
    assert pick({"a": 1, "b": 2, "c": None}, ("a", "c", "d")) == {"a": 1}


def test_nettoyage_dun_resultat_de_module():
    resultat = ModuleResult(
        key="breaches", label="Fuites", status=ModuleStatus.OK, score=100,
        data={"hash": "deadbeef", "ok": 1},
        findings=[
            Finding(code="C", module="breaches", severity=Severity.INFO, title="t",
                    constat="c", explication="e", recommandation="r",
                    evidence={"password": "hunter2", "Name": "Adobe"})
        ],
    )
    scrub_module_result(resultat)
    assert resultat.data["hash"] == REDACTED
    assert resultat.findings[0].evidence["password"] == REDACTED
    assert resultat.findings[0].evidence["Name"] == "Adobe"


def test_les_chaines_tres_longues_sont_tronquees():
    assert len(scrub({"texte": "a" * 5000})["texte"]) < 2100
