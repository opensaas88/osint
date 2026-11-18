"""Interface commune à tous les modules d'analyse.

Chaque module est un fichier de ce paquet qui expose :

    KEY         : str                     identifiant stable
    WEIGHT      : int                     poids dans le score global
    DEPENDS_ON  : tuple[str, ...]         modules dont il réutilise le résultat
    TIMEOUT     : float                   délai maximal d'exécution, en secondes
    async def run(ctx: ModuleContext) -> ModuleResult

`ctx` porte le domaine analysé ainsi que les ressources partagées (résolveur DNS,
client HTTP, consentements), afin qu'un module reste testable en isolation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding, ModuleResult, ModuleStatus, SourceRef
from ..resolver import strip_root
from ..scoring import MODULE_WEIGHTS, module_score
from ..validation import DomainName

#: Libellés affichés dans l'interface et les rapports.
MODULE_LABELS: dict[str, str] = {
    "breaches": "Fuites de données",
    "ransomware": "Ransomware",
    "email": "Hygiène email",
    "dns": "Hygiène DNS",
    "subdomains": "Sous-domaines",
    "exposure": "Services exposés",
    "tls": "TLS & en-têtes HTTP",
    "typosquatting": "Typosquatting",
    "reputation": "Réputation",
}


@dataclass(slots=True)
class ReconData:
    """Enregistrements DNS de l'apex, résolus une seule fois et partagés."""

    domain: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    soa: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    ds: list[str] = field(default_factory=list)
    dnssec_authenticated: bool = False
    resolves: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def ips(self) -> list[str]:
        """Adresses IP de l'apex, IPv4 puis IPv6."""
        return [*self.a, *self.aaaa]

    @property
    def mx_hosts(self) -> list[str]:
        """Noms d'hôtes des serveurs de messagerie, triés par préférence."""
        hosts: list[tuple[int, str]] = []
        for record in self.mx:
            parts = record.split(None, 1)
            if len(parts) != 2:
                continue
            try:
                priority = int(parts[0])
            except ValueError:
                continue
            host = strip_root(parts[1].strip())
            hosts.append((priority, host))
        return [host for _, host in sorted(hosts) if host and host != "."]

    @property
    def has_null_mx(self) -> bool:
        """RFC 7505 : `0 .` déclare explicitement que le domaine ne reçoit pas d'email."""
        return any(strip_root(r.split(None, 1)[-1].strip()) == "" for r in self.mx if " " in r)


@dataclass
class ModuleContext:
    """Contexte passé à chaque module."""

    domain: DomainName
    settings: Any
    http: Any
    resolver: Any
    consents: Any
    recon: ReconData
    results: dict[str, ModuleResult] = field(default_factory=dict)

    @property
    def name(self) -> str:
        """Forme ASCII du domaine, à utiliser pour toute requête."""
        return self.domain.ascii


class ModuleRun:
    """Petit utilitaire de construction d'un `ModuleResult` (chronomètre inclus)."""

    def __init__(self, key: str) -> None:
        self.key = key
        self.label = MODULE_LABELS.get(key, key)
        self.weight = MODULE_WEIGHTS.get(key, 0)
        self.started = time.perf_counter()
        self.findings: list[Finding] = []
        self.sources: list[SourceRef] = []
        self.errors: list[str] = []
        self.data: dict[str, Any] = {}

    def add(
        self,
        code: str,
        severity,
        title: str,
        constat: str,
        explication: str,
        recommandation: str,
        references: list | None = None,
        evidence: dict | None = None,
    ) -> Finding:
        """Ajoute un finding au module courant."""
        finding = Finding(
            code=code,
            module=self.key,
            severity=severity,
            title=title,
            constat=constat,
            explication=explication,
            recommandation=recommandation,
            references=references or [],
            evidence=evidence or {},
        )
        self.findings.append(finding)
        return finding

    def source(self, ref: SourceRef | None) -> None:
        if ref is not None:
            self.sources.append(ref)

    def error(self, message: str) -> None:
        self.errors.append(message)

    @property
    def elapsed_ms(self) -> int:
        return int((time.perf_counter() - self.started) * 1000)

    def done(self, status: ModuleStatus | None = None, score: int | None = None) -> ModuleResult:
        """Clôture le module : statut déduit des erreurs si non précisé."""
        if status is None:
            status = ModuleStatus.PARTIAL if self.errors else ModuleStatus.OK
        return ModuleResult(
            key=self.key,
            label=self.label,
            status=status,
            score=module_score(self.findings) if score is None else score,
            weight=self.weight,
            findings=self.findings,
            sources=self.sources,
            errors=self.errors,
            duration_ms=self.elapsed_ms,
            data=self.data,
        )

    def skipped(self, reason: str) -> ModuleResult:
        """Module désactivé : exclu du score, raison affichée dans le rapport."""
        return ModuleResult(
            key=self.key,
            label=self.label,
            status=ModuleStatus.SKIPPED,
            score=None,
            weight=self.weight,
            findings=self.findings,
            sources=self.sources,
            errors=self.errors,
            disabled_reason=reason,
            duration_ms=self.elapsed_ms,
            data=self.data,
        )

    def failed(self, reason: str) -> ModuleResult:
        """Aucun résultat exploitable : exclu du score, erreur affichée."""
        self.errors.append(reason)
        return ModuleResult(
            key=self.key,
            label=self.label,
            status=ModuleStatus.ERROR,
            score=None,
            weight=self.weight,
            findings=self.findings,
            sources=self.sources,
            errors=self.errors,
            disabled_reason=reason,
            duration_ms=self.elapsed_ms,
            data=self.data,
        )


def load_registry() -> list[Any]:
    """Charge les modules d'analyse dans l'ordre déclaré."""
    from . import (
        breaches,
        dns_health,
        email_hygiene,
        exposure,
        ransomware,
        reputation,
        subdomains,
        tls_headers,
        typosquatting,
    )

    return [
        email_hygiene,
        dns_health,
        subdomains,
        tls_headers,
        breaches,
        ransomware,
        typosquatting,
        reputation,
        exposure,
    ]
