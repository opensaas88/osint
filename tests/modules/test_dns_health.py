"""Module Hygiène DNS : DNSSEC, serveurs de noms, CAA, reprise de sous-domaine."""

import httpx
import pytest
import respx

from app.models import ModuleResult, ModuleStatus
from app.modules import dns_health
from app.modules.dns_health import match_fingerprint, parse_rdap
from tests.conftest import FakeResolver

RDAP = "https://rdap.org/domain/exemple.fr"


@pytest.fixture(autouse=True)
def rdap():
    """Neutralise RDAP par défaut : aucun test ne doit dépendre du réseau.

    Les tests qui portent sur l'enregistrement du domaine redéfinissent la route.
    """
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith="https://rdap.org/domain/", name="rdap").mock(
            return_value=httpx.Response(404)
        )
        yield router


def rdap_payload(expiration: str, statuts: list[str] | None = None) -> dict:
    return {
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": expiration},
        ],
        "status": statuts if statuts is not None else ["client transfer prohibited"],
    }


def codes(resultat) -> set[str]:
    return {f.code for f in resultat.findings}


def finding_by_code(resultat, code):
    """Récupère un constat par son code, avec un message clair s'il manque."""
    for finding in resultat.findings:
        if finding.code == code:
            return finding
    raise AssertionError(f"constat {code} absent ; présents : {sorted(codes(resultat))}")


def base_records(extra: dict | None = None):
    records = {
        ("exemple.fr", "A"): ["203.0.113.10"],
        ("exemple.fr", "NS"): ["ns1.hebergeur.fr.", "ns2.hebergeur.fr."],
        ("exemple.fr", "SOA"): ["ns1.hebergeur.fr. admin.exemple.fr. 1 2 3 4 5"],
    }
    records.update(extra or {})
    return records


def test_reconnaissance_des_empreintes():
    empreintes = dns_health.load_fingerprints()
    assert match_fingerprint("monsite.s3.amazonaws.com", empreintes) == "Amazon S3"
    assert match_fingerprint("app.herokuapp.com", empreintes) == "Heroku"
    assert match_fingerprint("www.exemple.fr", empreintes) is None


async def test_dnssec_absent(settings, http, make_context):
    ctx = await make_context(settings, http, FakeResolver(records=base_records()))
    assert "DNS_DNSSEC_MISSING" in codes(await dns_health.run(ctx))


async def test_dnssec_valide(settings, http, make_context):
    resolver = FakeResolver(
        records=base_records({("exemple.fr", "DS"): ["12345 13 2 ABCD"]}),
        authenticated={"exemple.fr"},
    )
    ctx = await make_context(settings, http, resolver)
    assert "DNS_DNSSEC_OK" in codes(await dns_health.run(ctx))


async def test_dnssec_declare_mais_non_valide(settings, http, make_context):
    resolver = FakeResolver(records=base_records({("exemple.fr", "DS"): ["12345 13 2 ABCD"]}))
    ctx = await make_context(settings, http, resolver)
    assert "DNS_DNSSEC_UNVALIDATED" in codes(await dns_health.run(ctx))


async def test_un_seul_serveur_de_noms(settings, http, make_context):
    records = base_records()
    records[("exemple.fr", "NS")] = ["ns1.hebergeur.fr."]
    ctx = await make_context(settings, http, FakeResolver(records=records))
    assert "DNS_SINGLE_NS" in codes(await dns_health.run(ctx))


async def test_serveurs_de_noms_du_meme_operateur(settings, http, make_context):
    ctx = await make_context(settings, http, FakeResolver(records=base_records()))
    assert "DNS_NS_SINGLE_PROVIDER" in codes(await dns_health.run(ctx))


async def test_caa_present_et_absent(settings, http, make_context):
    ctx = await make_context(settings, http, FakeResolver(records=base_records()))
    assert "DNS_CAA_MISSING" in codes(await dns_health.run(ctx))

    records = base_records({("exemple.fr", "CAA"): ['0 issue "letsencrypt.org"']})
    ctx = await make_context(settings, http, FakeResolver(records=records))
    assert "DNS_CAA_PRESENT" in codes(await dns_health.run(ctx))


async def test_risque_de_reprise_de_sous_domaine(settings, http, make_context):
    """Un CNAME vers un service tiers qui ne résout plus : faisceau d'indices, jamais confirmé."""
    resolver = FakeResolver(
        records=base_records({("blog.exemple.fr", "CNAME"): ["ancien.herokuapp.com"]}),
        nxdomain={"ancien.herokuapp.com"},
    )
    ctx = await make_context(settings, http, resolver)
    resultat = await dns_health.run(ctx)
    assert "DNS_SUBDOMAIN_TAKEOVER_RISK" in codes(resultat)
    finding = finding_by_code(resultat, "DNS_SUBDOMAIN_TAKEOVER_RISK")
    assert finding.severity.value == "eleve"
    assert "ne tente jamais" in finding.explication


async def test_dependance_tierce_active_nest_pas_une_alerte(settings, http, make_context):
    resolver = FakeResolver(
        records=base_records({
            ("www.exemple.fr", "CNAME"): ["site.netlify.app"],
            ("site.netlify.app", "A"): ["198.51.100.4"],
        }),
    )
    ctx = await make_context(settings, http, resolver)
    resultat = await dns_health.run(ctx)
    assert "DNS_THIRD_PARTY_DEPENDENCIES" in codes(resultat)
    assert "DNS_SUBDOMAIN_TAKEOVER_RISK" not in codes(resultat)


async def test_les_sous_domaines_du_module_ct_sont_reutilises(settings, http, make_context):
    """Le module réutilise les CNAME déjà découverts plutôt que de les re-résoudre."""
    precedent = ModuleResult(
        key="subdomains", label="Sous-domaines", status=ModuleStatus.OK, score=100, weight=5,
        data={"records": [{"name": "vieux.exemple.fr", "cname": ["x.s3.amazonaws.com"], "a": []}]},
    )
    resolver = FakeResolver(records=base_records(), nxdomain={"x.s3.amazonaws.com"})
    ctx = await make_context(settings, http, resolver, results={"subdomains": precedent})
    resultat = await dns_health.run(ctx)
    candidats = resultat.data["takeover_candidates"]
    assert any(c["subdomain"] == "vieux.exemple.fr" for c in candidats)


async def test_aucun_transfert_de_zone_nest_tente(settings, http, make_context):
    resolver = FakeResolver(records=base_records())
    ctx = await make_context(settings, http, resolver)
    resultat = await dns_health.run(ctx)
    assert not any(rrtype == "AXFR" for _, rrtype in resolver.queries)
    assert "DNS_AXFR_NOT_TESTED" in codes(resultat)


async def test_domaine_qui_ne_resout_pas(settings, http, make_context):
    ctx = await make_context(settings, http, FakeResolver(records={}))
    resultat = await dns_health.run(ctx)
    assert resultat.status is ModuleStatus.ERROR
    assert resultat.score is None


# ---------------------------------------------------------------------------
# Enregistrement du nom de domaine (RDAP)
# ---------------------------------------------------------------------------


def test_lecture_dune_reponse_rdap():
    infos = parse_rdap(rdap_payload("2027-05-01T00:00:00Z",
                                    ["client transfer prohibited", "client delete prohibited"]))
    assert infos["expiration"] == "2027-05-01T00:00:00Z"
    assert infos["creation"] == "2020-01-01T00:00:00Z"
    assert infos["verrou_transfert"] is True
    assert infos["verrou_suppression"] is True


def test_rdap_sans_verrou():
    infos = parse_rdap(rdap_payload("2027-05-01T00:00:00Z", ["active"]))
    assert infos["verrou_transfert"] is False


async def test_domaine_expire(settings, http, make_context, rdap):
    from datetime import UTC, datetime, timedelta

    passe = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    rdap["rdap"].mock(return_value=httpx.Response(200, json=rdap_payload(passe)))
    ctx = await make_context(settings, http, FakeResolver(records=base_records()))
    resultat = await dns_health.run(ctx)
    assert "DNS_DOMAIN_EXPIRED" in codes(resultat)
    assert finding_by_code(resultat, "DNS_DOMAIN_EXPIRED").severity.value == "critique"


async def test_domaine_expirant_bientot(settings, http, make_context, rdap):
    from datetime import UTC, datetime, timedelta

    proche = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    rdap["rdap"].mock(return_value=httpx.Response(200, json=rdap_payload(proche)))
    ctx = await make_context(settings, http, FakeResolver(records=base_records()))
    resultat = await dns_health.run(ctx)
    finding = finding_by_code(resultat, "DNS_DOMAIN_EXPIRING")
    assert finding.severity.value == "eleve"
    # Le constat précise ce qu'il ne peut pas savoir : l'état du renouvellement automatique.
    assert "renouvellement automatique" in finding.explication
    assert resultat.data["expiration_jours"] in (4, 5)


async def test_domaine_expirant_dans_un_mois(settings, http, make_context, rdap):
    from datetime import UTC, datetime, timedelta

    moyen = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    rdap["rdap"].mock(return_value=httpx.Response(200, json=rdap_payload(moyen)))
    ctx = await make_context(settings, http, FakeResolver(records=base_records()))
    resultat = await dns_health.run(ctx)
    assert finding_by_code(resultat, "DNS_DOMAIN_EXPIRING_SOON").severity.value == "moyen"


async def test_echeance_lointaine_et_verrou_present(settings, http, make_context, rdap):
    from datetime import UTC, datetime, timedelta

    loin = (datetime.now(UTC) + timedelta(days=300)).isoformat()
    rdap["rdap"].mock(return_value=httpx.Response(200, json=rdap_payload(loin)))
    ctx = await make_context(settings, http, FakeResolver(records=base_records()))
    resultat = await dns_health.run(ctx)
    assert "DNS_DOMAIN_EXPIRY_OK" in codes(resultat)
    assert "DNS_DOMAIN_LOCKED" in codes(resultat)
    assert "DNS_DOMAIN_NO_LOCK" not in codes(resultat)


async def test_absence_de_verrou_de_transfert(settings, http, make_context, rdap):
    from datetime import UTC, datetime, timedelta

    loin = (datetime.now(UTC) + timedelta(days=300)).isoformat()
    rdap["rdap"].mock(return_value=httpx.Response(200, json=rdap_payload(loin, ["active"])))
    ctx = await make_context(settings, http, FakeResolver(records=base_records()))
    resultat = await dns_health.run(ctx)
    finding = finding_by_code(resultat, "DNS_DOMAIN_NO_LOCK")
    assert finding.severity.value == "moyen"


async def test_rdap_indisponible_degrade_sans_constat(settings, http, make_context, rdap):
    """Un registre injoignable ne doit produire ni constat, ni faux positif."""
    rdap["rdap"].mock(return_value=httpx.Response(503))
    ctx = await make_context(settings, http, FakeResolver(records=base_records()))
    resultat = await dns_health.run(ctx)
    assert not any(c.startswith("DNS_DOMAIN_") for c in codes(resultat))
    assert any("RDAP" in erreur for erreur in resultat.errors)
    assert resultat.status is ModuleStatus.PARTIAL
