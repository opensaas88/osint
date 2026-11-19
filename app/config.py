"""Configuration applicative et inventaire des cles API."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


@dataclass(frozen=True)
class ApiKeySpec:
    """Decrit une cle API optionnelle, pour l'afficher dans le rapport et l'UI."""

    field: str  # nom de l'attribut sur Settings
    env: str  # nom de la variable d'environnement
    label: str  # nom lisible de la source
    url: str  # ou obtenir la cle
    pricing: str  # "gratuite", "gratuite (obligatoire)", "payante"


#: Inventaire des cles reconnues par l'application.
API_KEYS: tuple[ApiKeySpec, ...] = (
    ApiKeySpec("hibp_api_key", "HIBP_API_KEY", "Have I Been Pwned (Domain Search)",
               "https://haveibeenpwned.com/API/Key", "payante"),
    ApiKeySpec("shodan_api_key", "SHODAN_API_KEY", "Shodan (API complete)",
               "https://account.shodan.io", "payante"),
    ApiKeySpec("virustotal_api_key", "VIRUSTOTAL_API_KEY", "VirusTotal",
               "https://www.virustotal.com/gui/my-apikey", "gratuite"),
    ApiKeySpec("abuseipdb_api_key", "ABUSEIPDB_API_KEY", "AbuseIPDB",
               "https://www.abuseipdb.com/account/api", "gratuite"),
    ApiKeySpec("urlhaus_auth_key", "URLHAUS_AUTH_KEY", "URLhaus (abuse.ch)",
               "https://auth.abuse.ch", "gratuite (obligatoire)"),
    ApiKeySpec("github_search_token", "GITHUB_SEARCH_TOKEN",
               "GitHub (recherche de code public)",
               "https://github.com/settings/tokens", "gratuite"),
    ApiKeySpec("safebrowsing_api_key", "SAFEBROWSING_API_KEY", "Google Safe Browsing",
               "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
               "gratuite"),
    ApiKeySpec("leakcheck_api_key", "LEAKCHECK_API_KEY", "LeakCheck",
               "https://leakcheck.io", "payante"),
    ApiKeySpec("intelx_api_key", "INTELX_API_KEY", "Intelligence X",
               "https://intelx.io", "payante"),
)


class Settings(BaseSettings):
    """Parametres lus depuis l'environnement puis depuis .env."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # --- Serveur ---
    host: str = "127.0.0.1"
    port: int = 8080
    operator: str = "operateur-local"

    # --- Persistance ---
    db_path: Path = Path("data/domainexposure.db")
    cache_ttl_hours: int = 24
    audit_retention_days: int = 365

    # --- DNS ---
    dns_backend: Literal["auto", "system", "doh"] = "auto"
    dns_timeout: float = 5.0
    doh_endpoints: tuple[str, ...] = (
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    )
    dns_concurrency: int = 12

    # --- HTTP ---
    # Délai minimal entre deux appels à une même source. À ne désactiver que
    # face à des réponses simulées : il protège les quotas des fournisseurs.
    rate_limits_enabled: bool = True
    http_timeout: float = 15.0
    http_retries: int = 3
    crtsh_timeout: float = 60.0
    user_agent: str = "DomainExposure/1.0 (outil d'audit passif; +https://localhost)"

    # --- Marque blanche ---
    # La marque habille l'en-tête et les accents. Elle ne touche jamais aux
    # couleurs de gravité : un constat critique reste rouge chez tout le monde.
    brand_name: str = "DomainExposure"
    brand_color: str = "#256abf"
    brand_logo_path: Path | None = None
    brand_footer: str | None = None

    # --- Surveillance planifiée ---
    scheduler_enabled: bool = True
    scheduler_tick_seconds: int = 300
    scheduler_concurrency: int = 2
    alert_score_drop: int = 5

    # --- Notifications par courriel (facultatif) ---
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_starttls: bool = True

    # --- Modules ---
    typo_max_permutations: int = 200
    subdomain_resolve_limit: int = 150
    enable_typosquatting: bool = True
    check_http_redirect: bool = True

    # --- Cles API (toutes optionnelles) ---
    hibp_api_key: str | None = None
    shodan_api_key: str | None = None
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    urlhaus_auth_key: str | None = None
    github_search_token: str | None = None
    safebrowsing_api_key: str | None = None
    leakcheck_api_key: str | None = None
    intelx_api_key: str | None = None

    def key(self, field: str) -> str | None:
        """Retourne la cle si elle est renseignee et non vide."""
        value = getattr(self, field, None)
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    def has_key(self, field: str) -> bool:
        return self.key(field) is not None

    def api_key_inventory(self) -> list[dict[str, object]]:
        """Etat de chaque cle, pour l'UI et l'annexe du rapport."""
        return [
            {
                "env": spec.env,
                "label": spec.label,
                "url": spec.url,
                "pricing": spec.pricing,
                "configured": self.has_key(spec.field),
            }
            for spec in API_KEYS
        ]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
