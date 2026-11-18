"""Resolution DNS abstraite : resolveur systeme (UDP/53) ou DNS-over-HTTPS.

L'abstraction sert deux objectifs :
  * fonctionner derriere un reseau qui filtre le port 53 (bascule DoH) ;
  * rendre les modules testables en injectant un faux resolveur.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Protocol

import httpx

#: Codes de type DNS utilises par l'API JSON DoH.
RRTYPE_CODES: dict[str, int] = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33, "DS": 43, "DNSKEY": 48, "CAA": 257,
}

RCODES: dict[int, str] = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}


@dataclass(slots=True)
class DnsAnswer:
    """Reponse DNS normalisee, quel que soit le backend."""

    name: str
    rrtype: str
    records: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    rcode: str = "NOERROR"
    authenticated: bool = False  # flag AD : reponse validee DNSSEC par le resolveur
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.rcode == "NOERROR"

    @property
    def exists(self) -> bool:
        """Le nom existe-t-il (meme sans enregistrement du type demande) ?"""
        return self.error is None and self.rcode != "NXDOMAIN"

    @property
    def empty(self) -> bool:
        return not self.records


class Resolver(Protocol):
    """Interface attendue par les modules."""

    backend: str

    async def query(self, name: str, rrtype: str) -> DnsAnswer: ...


def strip_root(value: str) -> str:
    """Retire le point final d'un nom DNS absolu."""
    return value[:-1] if value.endswith(".") else value


def join_txt(raw: str) -> str:
    """Recolle un TXT renvoye sous forme de segments entre guillemets."""
    parts = []
    for chunk in raw.split('" "'):
        parts.append(chunk.strip().strip('"'))
    return "".join(parts)


class _CachingResolver:
    """Socle commun : cache par (nom, type) et limitation de concurrence."""

    backend = "abstract"

    def __init__(self, concurrency: int = 12) -> None:
        self._cache: dict[tuple[str, str], DnsAnswer] = {}
        self._sem = asyncio.Semaphore(concurrency)
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}

    async def query(self, name: str, rrtype: str) -> DnsAnswer:
        key = (name.lower().rstrip("."), rrtype.upper())
        if key in self._cache:
            return self._cache[key]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._cache:  # un autre appel a resolu pendant l'attente
                return self._cache[key]
            async with self._sem:
                answer = await self._lookup(key[0], key[1])
            self._cache[key] = answer
            return answer

    async def _lookup(self, name: str, rrtype: str) -> DnsAnswer:  # pragma: no cover
        raise NotImplementedError


class SystemResolver(_CachingResolver):
    """Resolveur systeme via dnspython (UDP/53)."""

    backend = "system"

    def __init__(self, timeout: float = 5.0, concurrency: int = 12) -> None:
        super().__init__(concurrency)
        self.timeout = timeout

    async def _lookup(self, name: str, rrtype: str) -> DnsAnswer:
        import dns.asyncresolver
        import dns.flags
        import dns.rdatatype
        import dns.resolver

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout
        try:
            answer = await resolver.resolve(name, rrtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(name=name, rrtype=rrtype, rcode="NXDOMAIN")
        except dns.resolver.NoNameservers as exc:
            return DnsAnswer(name=name, rrtype=rrtype, rcode="SERVFAIL", error=str(exc)[:200])
        except (dns.resolver.LifetimeTimeout, TimeoutError):
            return DnsAnswer(name=name, rrtype=rrtype, error="delai DNS depasse")
        except Exception as exc:  # resolveur injoignable, nom mal forme...
            return DnsAnswer(name=name, rrtype=rrtype, error=f"{type(exc).__name__}: {str(exc)[:160]}")

        records: list[str] = []
        cnames: list[str] = []
        if answer.rrset is not None:
            records = [rdata.to_text() for rdata in answer.rrset]
        for rrset in answer.response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                cnames.extend(strip_root(rdata.to_text()) for rdata in rrset)
        if rrtype.upper() == "TXT":
            records = [join_txt(r) for r in records]
        authenticated = bool(answer.response.flags & dns.flags.AD)
        return DnsAnswer(
            name=name, rrtype=rrtype, records=records, cnames=cnames, authenticated=authenticated
        )


class DohResolver(_CachingResolver):
    """Resolveur DNS-over-HTTPS (API JSON Cloudflare / Google)."""

    backend = "doh"

    def __init__(
        self,
        client: httpx.AsyncClient,
        endpoints: tuple[str, ...],
        timeout: float = 5.0,
        concurrency: int = 12,
    ) -> None:
        super().__init__(concurrency)
        self.client = client
        self.endpoints = endpoints
        self.timeout = timeout

    async def _lookup(self, name: str, rrtype: str) -> DnsAnswer:
        last_error = "aucun resolveur DoH disponible"
        for endpoint in self.endpoints:
            try:
                response = await self.client.get(
                    endpoint,
                    params={"name": name, "type": rrtype},
                    headers={"accept": "application/dns-json"},
                    timeout=self.timeout,
                )
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {str(exc)[:120]}"
                continue
            if response.status_code != 200:
                last_error = f"HTTP {response.status_code} sur {endpoint}"
                continue
            try:
                payload = response.json()
            except ValueError:
                last_error = f"reponse DoH illisible depuis {endpoint}"
                continue
            return self._parse(name, rrtype, payload)
        return DnsAnswer(name=name, rrtype=rrtype, error=last_error)

    @staticmethod
    def _parse(name: str, rrtype: str, payload: dict) -> DnsAnswer:
        rcode = RCODES.get(int(payload.get("Status", 0)), f"RCODE{payload.get('Status')}")
        wanted = RRTYPE_CODES.get(rrtype.upper())
        records: list[str] = []
        cnames: list[str] = []
        for entry in payload.get("Answer") or []:
            data = str(entry.get("data", ""))
            etype = entry.get("type")
            if etype == RRTYPE_CODES["CNAME"]:
                cnames.append(strip_root(data))
            if wanted is not None and etype != wanted:
                continue
            records.append(join_txt(data) if rrtype.upper() == "TXT" else data)
        return DnsAnswer(
            name=name,
            rrtype=rrtype,
            records=records,
            cnames=cnames,
            rcode=rcode,
            authenticated=bool(payload.get("AD", False)),
        )


#: Nom tres stable servant a tester si le resolveur systeme fonctionne.
PROBE_NAME = "a.root-servers.net"


async def build_resolver(settings, client: httpx.AsyncClient) -> Resolver:
    """Construit le resolveur selon la configuration (`auto` teste puis bascule)."""
    doh = DohResolver(client, settings.doh_endpoints, settings.dns_timeout, settings.dns_concurrency)
    if settings.dns_backend == "doh":
        return doh
    system = SystemResolver(settings.dns_timeout, settings.dns_concurrency)
    if settings.dns_backend == "system":
        return system
    probe = await system.query(PROBE_NAME, "A")
    if probe.ok and probe.records:
        return system
    return doh
