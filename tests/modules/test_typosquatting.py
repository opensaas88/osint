"""Module Typosquatting : génération dnstwist et qualification des domaines trouvés."""

from app.modules import ReconData, typosquatting
from app.modules.typosquatting import FAMILY_PRIORITY, generate_permutations
from tests.conftest import FakeResolver


def codes(resultat) -> set[str]:
    return {f.code for f in resultat.findings}


def test_generation_priorisee_et_plafonnee():
    retenues, total = generate_permutations("exemple.fr", 30)
    assert len(retenues) == 30
    assert total > 30
    assert all(p["domain"] != "exemple.fr" for p in retenues)
    # Les familles les plus exploitées en hameçonnage passent avant les homoglyphes,
    # qui représentent l'essentiel du volume généré.
    assert retenues[0]["fuzzer"] in FAMILY_PRIORITY[:6]


def test_toutes_les_permutations_si_la_limite_est_haute():
    retenues, total = generate_permutations("exemple.fr", 100000)
    assert len(retenues) == total


async def test_domaine_ressemblant_avec_messagerie_est_eleve(settings, http, make_context):
    retenues, _ = generate_permutations("exemple.fr", settings.typo_max_permutations)
    cible = retenues[0]["domain"]
    resolver = FakeResolver(records={
        (cible, "A"): ["198.51.100.9"],
        (cible, "MX"): ["10 mail.pirate.fr."],
    })
    ctx = await make_context(settings, http, resolver,
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await typosquatting.run(ctx)
    assert "TYPO_MAIL_CAPABLE" in codes(resultat)
    assert next(f for f in resultat.findings if f.code == "TYPO_MAIL_CAPABLE").severity.value == "eleve"


async def test_depot_defensif_identifie(settings, http, make_context):
    """Une variante pointant vers nos propres IP est un dépôt défensif, pas une menace."""
    retenues, _ = generate_permutations("exemple.fr", settings.typo_max_permutations)
    cible = retenues[0]["domain"]
    resolver = FakeResolver(records={(cible, "A"): ["203.0.113.10"]})
    ctx = await make_context(settings, http, resolver,
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await typosquatting.run(ctx)
    assert "TYPO_DEFENSIVE_REGISTRATIONS" in codes(resultat)
    assert "TYPO_REGISTERED_BY_THIRD_PARTY" not in codes(resultat)
    assert "TYPO_MAIL_CAPABLE" not in codes(resultat)


async def test_variante_enregistree_sans_service(settings, http, make_context):
    retenues, _ = generate_permutations("exemple.fr", settings.typo_max_permutations)
    cible = retenues[0]["domain"]
    resolver = FakeResolver(records={(cible, "NS"): ["ns1.parking.fr."]})
    ctx = await make_context(settings, http, resolver,
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await typosquatting.run(ctx)
    assert "TYPO_REGISTERED_BY_THIRD_PARTY" in codes(resultat)


async def test_aucune_variante_enregistree(settings, http, make_context):
    ctx = await make_context(settings, http, FakeResolver(),
                             recon=ReconData(domain="exemple.fr", a=["203.0.113.10"]))
    resultat = await typosquatting.run(ctx)
    assert "TYPO_NONE" in codes(resultat)
    assert resultat.score == 100


async def test_module_desactivable(settings, http, make_context):
    settings.enable_typosquatting = False
    ctx = await make_context(settings, http, FakeResolver())
    resultat = await typosquatting.run(ctx)
    assert resultat.status.value == "skipped"
    assert resultat.score is None
