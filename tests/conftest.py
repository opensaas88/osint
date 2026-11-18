"""Fixtures communes : réglages hermétiques, faux résolveur DNS, contexte de module."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.httpclient import HttpClient
from app.models import Consents
from app.modules import ModuleContext, ReconData
from app.orchestrator import collect_recon
from app.resolver import DnsAnswer
from app.storage import Store
from app.validation import normalize_domain


@dataclass
class FakeResolver:
    """Résolveur DNS déterministe. `records` : {(nom, type): [valeurs]}."""

    records: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    cnames: dict[str, list[str]] = field(default_factory=dict)
    authenticated: set[str] = field(default_factory=set)
    nxdomain: set[str] = field(default_factory=set)
    backend: str = "fake"
    queries: list[tuple[str, str]] = field(default_factory=list)

    async def query(self, name: str, rrtype: str) -> DnsAnswer:
        key = (name.lower().rstrip("."), rrtype.upper())
        self.queries.append(key)
        if key[0] in self.nxdomain:
            return DnsAnswer(name=name, rrtype=rrtype, rcode="NXDOMAIN")
        return DnsAnswer(
            name=name,
            rrtype=rrtype,
            records=list(self.records.get(key, [])),
            cnames=list(self.cnames.get(key[0], [])),
            authenticated=key[0] in self.authenticated,
        )


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Réglages isolés : aucune clé API, base temporaire, pas de lecture de .env."""
    return Settings(
        _env_file=None,
        db_path=tmp_path / "test.db",
        http_timeout=5.0,
        http_retries=1,
        cache_ttl_hours=24,
        audit_retention_days=365,
        operator="pytest",
        typo_max_permutations=20,
        subdomain_resolve_limit=10,
        # L'ordonnanceur est piloté explicitement par les tests qui le concernent :
        # aucune tâche de fond ne doit s'exécuter à l'improviste.
        scheduler_enabled=False,
    )


@pytest.fixture
async def store(settings: Settings) -> Store:
    store = Store(settings.db_path)
    await store.init()
    return store


@pytest.fixture
def http(settings: Settings) -> HttpClient:
    """Client HTTP sans cache (store=None) pour que respx voie chaque appel."""
    return HttpClient(settings, store=None)


async def build_context(
    settings: Settings,
    http: HttpClient,
    resolver: FakeResolver,
    *,
    domain: str = "exemple.fr",
    consents: Consents | None = None,
    results: dict[str, Any] | None = None,
    recon: ReconData | None = None,
) -> ModuleContext:
    """Assemble un contexte de module à partir du vrai code de reconnaissance."""
    target = normalize_domain(domain)
    return ModuleContext(
        domain=target,
        settings=settings,
        http=http,
        resolver=resolver,
        consents=consents or Consents(authorization=True, passive_only=True),
        recon=recon if recon is not None else await collect_recon(resolver, target),
        results=results or {},
    )


@pytest.fixture
def make_context():
    return build_context
