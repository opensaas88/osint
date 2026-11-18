"""Module TLS & en-têtes HTTP."""

from datetime import UTC, datetime, timedelta

import httpx
import respx

from app.modules import ModuleRun, tls_headers
from app.modules.tls_headers import (
    CertificateInfo,
    evaluate_certificate,
    evaluate_headers,
    parse_cookies,
)
from tests.conftest import FakeResolver

ACCUEIL = "https://exemple.fr/"


def run_certificat(**kwargs) -> set[str]:
    run_ = ModuleRun("tls")
    defaults = {
        "subject": "CN=exemple.fr", "issuer": "CN=AC",
        "not_before": datetime.now(UTC) - timedelta(days=30),
        "not_after": datetime.now(UTC) + timedelta(days=200),
        "sans": ["exemple.fr", "www.exemple.fr"],
        "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
        "key_bits": 256, "key_type": "EllipticCurve", "signature": "sha256",
        "verified": True,
    }
    defaults.update(kwargs)
    evaluate_certificate(run_, CertificateInfo(**defaults), "exemple.fr")
    return {f.code for f in run_.findings}


def run_entetes(headers: dict, cookies: list[str] | None = None) -> ModuleRun:
    run_ = ModuleRun("tls")
    evaluate_headers(run_, headers, cookies or [], ACCUEIL)
    return run_


def test_certificat_valide():
    assert "TLS_CERT_VALID" in run_certificat()
    assert "TLS_VERSION_OK" in run_certificat()


def test_certificat_expire():
    codes = run_certificat(not_after=datetime.now(UTC) - timedelta(days=2))
    assert "TLS_CERT_EXPIRED" in codes


def test_certificat_expirant_bientot():
    assert "TLS_CERT_EXPIRING_SOON" in run_certificat(
        not_after=datetime.now(UTC) + timedelta(days=3))
    assert "TLS_CERT_EXPIRY_WARNING" in run_certificat(
        not_after=datetime.now(UTC) + timedelta(days=20))


def test_certificat_auto_signe():
    assert "TLS_CERT_SELF_SIGNED" in run_certificat(self_signed=True)


def test_nom_dhote_absent_du_certificat():
    assert "TLS_CERT_HOSTNAME_MISMATCH" in run_certificat(sans=["autre.fr"])


def test_joker_couvre_le_domaine():
    assert "TLS_CERT_HOSTNAME_MISMATCH" not in run_certificat(sans=["*.exemple.fr", "exemple.fr"])


def test_version_tls_obsolete():
    assert "TLS_OBSOLETE_VERSION" in run_certificat(tls_version="TLSv1")


def test_cle_rsa_trop_courte_et_signature_faible():
    assert "TLS_WEAK_KEY" in run_certificat(key_bits=1024, key_type="RSA")
    assert "TLS_WEAK_SIGNATURE" in run_certificat(signature="sha1")


def test_chaine_non_validee():
    assert "TLS_CERT_NOT_TRUSTED" in run_certificat(
        verified=False, verify_error="unable to get local issuer certificate")


def test_entetes_absents():
    codes = {f.code for f in run_entetes({"content-type": "text/html"}).findings}
    assert {
        "HTTP_HSTS_MISSING", "HTTP_CSP_MISSING", "HTTP_XFO_MISSING",
        "HTTP_NOSNIFF_MISSING", "HTTP_REFERRER_POLICY_MISSING",
        "HTTP_PERMISSIONS_POLICY_MISSING",
    } <= codes


def test_hsts_correct_sans_preload():
    codes = {f.code for f in run_entetes({
        "strict-transport-security": "max-age=31536000; includeSubDomains"}).findings}
    assert "HTTP_HSTS_NO_PRELOAD" in codes
    assert "HTTP_HSTS_MISSING" not in codes
    assert "HTTP_HSTS_SHORT" not in codes


def test_hsts_trop_court():
    codes = {f.code for f in run_entetes({
        "strict-transport-security": "max-age=600"}).findings}
    assert {"HTTP_HSTS_SHORT", "HTTP_HSTS_NO_SUBDOMAINS"} <= codes


def test_csp_permissive():
    codes = {f.code for f in run_entetes({
        "content-security-policy": "default-src 'self' 'unsafe-inline'"}).findings}
    assert "HTTP_CSP_UNSAFE" in codes
    assert "HTTP_CSP_MISSING" not in codes


def test_frame_ancestors_remplace_x_frame_options():
    codes = {f.code for f in run_entetes({
        "content-security-policy": "frame-ancestors 'self'"}).findings}
    assert "HTTP_XFO_MISSING" not in codes


def test_divulgation_de_version():
    codes = {f.code for f in run_entetes({"server": "nginx/1.18.0"}).findings}
    assert "HTTP_VERSION_DISCLOSURE" in codes
    # Un serveur sans numéro de version ne déclenche rien.
    assert "HTTP_VERSION_DISCLOSURE" not in {
        f.code for f in run_entetes({"server": "cloudflare"}).findings}


def test_analyse_des_cookies_sans_jamais_lire_leur_valeur():
    cookies = ["SESSION=valeur-secrete-123; Path=/", "autre=x; Secure; HttpOnly; SameSite=Lax"]
    analyse = parse_cookies(cookies)
    assert analyse[0] == {"nom": "SESSION", "secure": False, "httponly": False, "samesite": None}
    assert analyse[1]["samesite"] == "lax"
    # La valeur ne doit apparaître nulle part.
    assert "valeur-secrete-123" not in str(analyse)

    run_ = run_entetes({}, cookies)
    codes = {f.code for f in run_.findings}
    assert {"HTTP_COOKIE_NOT_SECURE", "HTTP_COOKIE_NOT_HTTPONLY", "HTTP_COOKIE_NO_SAMESITE"} <= codes
    assert "valeur-secrete-123" not in str(run_.data)


@respx.mock
async def test_une_seule_requete_vers_la_cible(settings, http, make_context, monkeypatch):
    """Le module ne doit solliciter la page d'accueil qu'une fois (plus le port 80)."""
    settings.check_http_redirect = False

    async def faux_certificat(host, port=443, timeout=10.0):
        return None, "handshake impossible en test"

    monkeypatch.setattr(tls_headers, "fetch_certificate", faux_certificat)
    route = respx.get(ACCUEIL).mock(return_value=httpx.Response(
        200, headers={"strict-transport-security": "max-age=31536000; includeSubDomains"}))

    resolver = FakeResolver(records={("exemple.fr", "A"): ["203.0.113.10"]})
    ctx = await make_context(settings, http, resolver)
    resultat = await tls_headers.run(ctx)

    assert route.call_count == 1
    assert "TLS_CERT_NOT_INSPECTED" in {f.code for f in resultat.findings}


@respx.mock
async def test_absence_de_redirection_http_vers_https(settings, http, make_context, monkeypatch):
    async def faux_certificat(host, port=443, timeout=10.0):
        return None, "non testé"

    monkeypatch.setattr(tls_headers, "fetch_certificate", faux_certificat)
    respx.get(ACCUEIL).mock(return_value=httpx.Response(200, headers={}))
    respx.get("http://exemple.fr/").mock(return_value=httpx.Response(200, text="site en clair"))

    resolver = FakeResolver(records={("exemple.fr", "A"): ["203.0.113.10"]})
    ctx = await make_context(settings, http, resolver)
    resultat = await tls_headers.run(ctx)
    assert "HTTP_NO_REDIRECT" in {f.code for f in resultat.findings}


@respx.mock
async def test_redirection_permanente_est_valorisee(settings, http, make_context, monkeypatch):
    async def faux_certificat(host, port=443, timeout=10.0):
        return None, "non testé"

    monkeypatch.setattr(tls_headers, "fetch_certificate", faux_certificat)
    respx.get(ACCUEIL).mock(return_value=httpx.Response(200, headers={}))
    respx.get("http://exemple.fr/").mock(
        return_value=httpx.Response(301, headers={"location": "https://exemple.fr/"}))

    resolver = FakeResolver(records={("exemple.fr", "A"): ["203.0.113.10"]})
    ctx = await make_context(settings, http, resolver)
    assert "HTTP_REDIRECT_OK" in {f.code for f in (await tls_headers.run(ctx)).findings}
