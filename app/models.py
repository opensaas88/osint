"""Modeles de donnees partages par tous les modules d'analyse."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Niveaux de gravite d'un finding, du plus grave au plus benin."""

    CRITIQUE = "critique"
    ELEVE = "eleve"
    MOYEN = "moyen"
    FAIBLE = "faible"
    INFO = "info"


#: Penalite retiree au score d'un module pour chaque finding, par gravite.
SEVERITY_PENALTY: dict[Severity, int] = {
    Severity.CRITIQUE: 40,
    Severity.ELEVE: 25,
    Severity.MOYEN: 10,
    Severity.FAIBLE: 4,
    Severity.INFO: 0,
}

#: Libelles francais affichables.
SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITIQUE: "Critique",
    Severity.ELEVE: "Eleve",
    Severity.MOYEN: "Moyen",
    Severity.FAIBLE: "Faible",
    Severity.INFO: "Info",
}

#: Ordre de tri (0 = affiche en premier).
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITIQUE: 0,
    Severity.ELEVE: 1,
    Severity.MOYEN: 2,
    Severity.FAIBLE: 3,
    Severity.INFO: 4,
}


class ModuleStatus(StrEnum):
    """Etat d'execution d'un module."""

    OK = "ok"
    PARTIAL = "partial"  # resultat exploitable mais une source a echoue
    SKIPPED = "skipped"  # module desactive (cle absente, option coupee)
    ERROR = "error"  # aucun resultat exploitable


class Reference(BaseModel):
    """Reference normative justifiant une recommandation."""

    framework: str  # ANSSI, CIS, OWASP, RFC, NIST...
    label: str
    url: str


class Finding(BaseModel):
    """Un constat unitaire, comprehensible par un non-technicien."""

    code: str  # identifiant stable, ex. EMAIL_DMARC_MISSING
    module: str
    severity: Severity
    title: str
    constat: str  # le fait technique observe
    explication: str  # ce que cela signifie, en francais courant
    recommandation: str  # action concrete a mener
    references: list[Reference] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)  # donnees brutes sanitisees

    @property
    def penalty(self) -> int:
        return SEVERITY_PENALTY[self.severity]


class SourceRef(BaseModel):
    """Source consultee, pour l'annexe du rapport et la tracabilite."""

    name: str
    url: str | None = None
    fetched_at: datetime | None = None
    cached: bool = False
    status: int | None = None


class ModuleResult(BaseModel):
    """Resultat normalise d'un module d'analyse."""

    key: str
    label: str
    status: ModuleStatus
    score: int | None = None  # None si le module n'a pas tourne
    weight: int = 0
    findings: list[Finding] = Field(default_factory=list)
    sources: list[SourceRef] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    disabled_reason: str | None = None
    duration_ms: int = 0
    data: dict[str, Any] = Field(default_factory=dict)  # donnees structurees pour l'UI

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out


class Consents(BaseModel):
    """Cases cochees par l'operateur avant l'analyse. Journalisees telles quelles."""

    authorization: bool = False
    passive_only: bool = False
    domain_verified: bool = False  # debloque HIBP Domain Search (emails masques)

    @property
    def mandatory_granted(self) -> bool:
        return self.authorization and self.passive_only

    def missing(self) -> list[str]:
        manquantes = []
        if not self.authorization:
            manquantes.append("authorization")
        if not self.passive_only:
            manquantes.append("passive_only")
        return manquantes


class AnalysisStatus(StrEnum):
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Report(BaseModel):
    """Rapport complet d'une analyse."""

    id: str
    domain: str  # forme ASCII / punycode
    domain_unicode: str
    status: AnalysisStatus = AnalysisStatus.RUNNING
    started_at: datetime
    finished_at: datetime | None = None
    score: int | None = None
    grade: str | None = None
    score_capped_by_critical: bool = False
    modules: list[ModuleResult] = Field(default_factory=list)
    consents: Consents = Field(default_factory=Consents)
    actor: str = "inconnu"
    app_version: str = "1.0.0"
    dns_backend: str | None = None
    notes: list[str] = Field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for m in self.modules:
            for f in m.findings:
                out[f.severity.value] += 1
        return out

    def all_findings(self) -> list[Finding]:
        findings = [f for m in self.modules for f in m.findings]
        return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.module, f.code))
