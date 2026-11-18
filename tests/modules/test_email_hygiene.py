"""Module Hygiène email : SPF, DMARC, DKIM, MTA-STS, BIMI."""

import pytest

from app.modules import email_hygiene
from app.modules.email_hygiene import count_spf_lookups, spf_all_qualifier, spf_terms
from tests.conftest import FakeResolver

SOCLE = {("exemple.fr", "A"): ["203.0.113.10"], ("exemple.fr", "NS"): ["ns1.h.fr."]}


def resolver(extra: dict | None = None, **kwargs) -> FakeResolver:
    """Résolveur d'un domaine qui résout normalement, enrichi des enregistrements du test."""
    return FakeResolver(records={**SOCLE, **(extra or {})}, **kwargs)


def codes(resultat) -> set[str]:
    return {f.code for f in resultat.findings}


def severity_of(resultat, code) -> str:
    return next(f.severity.value for f in resultat.findings if f.code == code)


@pytest.mark.parametrize(
    ("enregistrement", "attendu"),
    [
        ("v=spf1 include:x.fr -all", "-"),
        ("v=spf1 ~all", "~"),
        ("v=spf1 ?all", "?"),
        ("v=spf1 +all", "+"),
        ("v=spf1 all", "+"),
        ("v=spf1 include:x.fr", None),
    ],
)
def test_qualificateur_all(enregistrement, attendu):
    assert spf_all_qualifier(enregistrement) == attendu


def test_decoupage_des_termes():
    assert spf_terms("v=spf1 a mx include:x.fr -all") == ["a", "mx", "include:x.fr", "-all"]


async def test_comptage_recursif_des_resolutions_spf():
    resolver = FakeResolver(records={
        ("a.fr", "TXT"): ["v=spf1 include:b.fr ip4:1.2.3.4 -all"],
        ("b.fr", "TXT"): ["v=spf1 a mx -all"],
    })
    total, notes = await count_spf_lookups(resolver, "v=spf1 a mx include:a.fr -all")
    # a + mx + include:a.fr = 3, puis include:b.fr = 1, puis a + mx = 2
    assert total == 6
    assert notes == []


async def test_include_sans_spf_est_signale():
    resolver = FakeResolver(records={})
    total, notes = await count_spf_lookups(resolver, "v=spf1 include:absent.fr -all")
    assert total == 1
    assert any("ne publie pas de SPF" in note for note in notes)


async def test_spf_multiple_est_critique(settings, http, make_context):
    ctx = await make_context(settings, http, resolver({
        ("exemple.fr", "TXT"): ["v=spf1 include:a.fr ~all", "v=spf1 -all"],
        ("exemple.fr", "MX"): ["10 mail.exemple.fr."],
    }))
    resultat = await email_hygiene.run(ctx)
    assert "EMAIL_SPF_MULTIPLE" in codes(resultat)
    assert severity_of(resultat, "EMAIL_SPF_MULTIPLE") == "critique"


async def test_spf_permissif_est_critique(settings, http, make_context):
    ctx = await make_context(settings, http, resolver({("exemple.fr", "TXT"): ["v=spf1 +all"]}))
    resultat = await email_hygiene.run(ctx)
    assert severity_of(resultat, "EMAIL_SPF_ALLOW_ALL") == "critique"


async def test_spf_absent_et_dmarc_absent(settings, http, make_context):
    ctx = await make_context(settings, http, resolver({("exemple.fr", "MX"): ["10 mail.exemple.fr."]}))
    resultat = await email_hygiene.run(ctx)
    assert {"EMAIL_SPF_MISSING", "EMAIL_DMARC_MISSING"} <= codes(resultat)
    assert severity_of(resultat, "EMAIL_SPF_MISSING") == "eleve"


async def test_depassement_de_la_limite_de_dix_resolutions(settings, http, make_context):
    inclusions = " ".join(f"include:s{i}.fr" for i in range(12))
    faux = resolver({("exemple.fr", "TXT"): [f"v=spf1 {inclusions} -all"]})
    for i in range(12):
        faux.records[(f"s{i}.fr", "TXT")] = ["v=spf1 ip4:1.2.3.4 -all"]
    ctx = await make_context(settings, http, faux)
    resultat = await email_hygiene.run(ctx)
    assert "EMAIL_SPF_TOO_MANY_LOOKUPS" in codes(resultat)


@pytest.mark.parametrize(
    ("politique", "code", "gravite"),
    [
        ("p=none", "EMAIL_DMARC_POLICY_NONE", "moyen"),
        ("p=quarantine", "EMAIL_DMARC_POLICY_QUARANTINE", "faible"),
        ("p=reject", "EMAIL_DMARC_POLICY_REJECT", "info"),
        ("p=inconnu", "EMAIL_DMARC_POLICY_INVALID", "eleve"),
    ],
)
async def test_politiques_dmarc(settings, http, make_context, politique, code, gravite):
    ctx = await make_context(settings, http, resolver({
        ("exemple.fr", "TXT"): ["v=spf1 -all"],
        ("_dmarc.exemple.fr", "TXT"): [f"v=DMARC1; {politique}; rua=mailto:d@exemple.fr"],
    }))
    resultat = await email_hygiene.run(ctx)
    assert code in codes(resultat)
    assert severity_of(resultat, code) == gravite


async def test_dmarc_sans_adresse_de_rapport(settings, http, make_context):
    ctx = await make_context(settings, http, resolver({
        ("_dmarc.exemple.fr", "TXT"): ["v=DMARC1; p=reject"],
    }))
    assert "EMAIL_DMARC_NO_RUA" in codes(await email_hygiene.run(ctx))


async def test_null_mx_est_une_bonne_pratique(settings, http, make_context):
    ctx = await make_context(settings, http, resolver({
        ("exemple.fr", "MX"): ["0 ."],
        ("exemple.fr", "TXT"): ["v=spf1 -all"],
        ("_dmarc.exemple.fr", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@exemple.fr"],
    }))
    resultat = await email_hygiene.run(ctx)
    assert "EMAIL_NULL_MX" in codes(resultat)
    # Un domaine sans messagerie ne se voit pas reprocher l'absence de MTA-STS.
    assert "EMAIL_MTA_STS_MISSING" not in codes(resultat)
    assert "EMAIL_TLSRPT_MISSING" not in codes(resultat)


async def test_dkim_detecte_par_selecteur(settings, http, make_context):
    ctx = await make_context(settings, http, resolver({
        ("google._domainkey.exemple.fr", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjAN"],
    }))
    resultat = await email_hygiene.run(ctx)
    assert "EMAIL_DKIM_PRESENT" in codes(resultat)
    assert "google" in resultat.data["dkim_selectors_found"]


async def test_dkim_absent_reste_prudent(settings, http, make_context):
    ctx = await make_context(settings, http, resolver())
    resultat = await email_hygiene.run(ctx)
    finding = next(f for f in resultat.findings if f.code == "EMAIL_DKIM_NOT_FOUND")
    assert "ne prouve pas l'absence" in finding.explication


async def test_bimi_present(settings, http, make_context):
    ctx = await make_context(settings, http, resolver({
        ("default._bimi.exemple.fr", "TXT"): ["v=BIMI1; l=https://exemple.fr/logo.svg"],
    }))
    assert "EMAIL_BIMI_PRESENT" in codes(await email_hygiene.run(ctx))


async def test_chaque_finding_porte_explication_et_reference(settings, http, make_context):
    ctx = await make_context(settings, http, resolver())
    resultat = await email_hygiene.run(ctx)
    assert resultat.findings
    for finding in resultat.findings:
        assert len(finding.explication) > 40, finding.code
        assert finding.recommandation, finding.code
        assert finding.references, finding.code
        assert any(r.framework in ("ANSSI", "CIS", "OWASP", "RFC", "Standard")
                   for r in finding.references), finding.code


async def test_abstention_si_le_domaine_ne_resout_pas(settings, http, make_context):
    """Une panne de résolution ne doit pas se transformer en constats « tout est absent »."""
    from app.models import ModuleStatus

    ctx = await make_context(settings, http, FakeResolver(records={}))
    resultat = await email_hygiene.run(ctx)
    assert resultat.status is ModuleStatus.ERROR
    assert resultat.score is None
    assert resultat.findings == []
    assert "pas mesurable" in resultat.disabled_reason
