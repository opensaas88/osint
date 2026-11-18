"""Client HTTP partage : timeouts, retries avec backoff, 429, cache 24 h, politesse par source.

Aucune methode ne leve d'exception reseau : les modules recoivent toujours un
`HttpResult` qu'ils interpretent, afin qu'une source en panne n'interrompe pas
l'analyse complete.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from .models import SourceRef

#: Delai minimal entre deux appels a une meme source, en secondes.
#: Valeurs calees sur les CGU/rate limits publics de chaque service.
SOURCE_RATE_LIMITS: dict[str, float] = {
    "hibp": 1.6,  # 1 requete / 1,5 s pour les cles de base
    "crtsh": 1.0,  # crt.sh est lent et gratuit : on reste doux
    "internetdb": 0.25,
    "shodan": 1.0,
    "virustotal": 15.5,  # 4 requetes / minute en offre gratuite
    "abuseipdb": 0.25,
    "ransomware": 0.4,
    "urlhaus": 0.4,
    "leakcheck": 1.0,
    "intelx": 1.0,
    "doh": 0.0,
    "cible": 0.0,
}

RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504, 520, 522, 524})
MAX_BACKOFF = 20.0


@dataclass(slots=True)
class HttpResult:
    """Resultat normalise d'un appel HTTP."""

    source: str
    url: str
    status: int | None = None
    payload: Any | None = None  # JSON decode si possible
    text: str | None = None
    cached: bool = False
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    error: str | None = None
    attempts: int = 1
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 300

    def source_ref(self, label: str | None = None, url: str | None = None) -> SourceRef:
        return SourceRef(
            name=label or self.source,
            url=url or self.url,
            fetched_at=self.fetched_at,
            cached=self.cached,
            status=self.status,
        )

    def describe_error(self) -> str:
        """Message d'erreur lisible, destine au champ `errors` du module."""
        if self.error:
            return self.error
        if self.status == 401:
            return "authentification refusée (clé absente ou invalide)"
        if self.status == 403:
            return "accès refusé par la source (403)"
        if self.status == 429:
            return "quota de la source atteint (429), à réessayer plus tard"
        return f"réponse inattendue de la source (HTTP {self.status})"


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def _cache_key(source: str, method: str, url: str, params: Any, body: Any) -> str:
    raw = json.dumps(
        {"s": source, "m": method.upper(), "u": url, "p": params, "b": body},
        sort_keys=True, default=str,
    )
    return hashlib.sha256(raw.encode()).hexdigest()


class HttpClient:
    """Enveloppe httpx avec cache, politesse et resilience."""

    def __init__(self, settings, store=None, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self.store = store
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(
            headers={"user-agent": settings.user_agent},
            timeout=settings.http_timeout,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        self._last_call: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def _throttle(self, source: str) -> None:
        """Respecte le delai minimal entre deux appels a la meme source."""
        interval = SOURCE_RATE_LIMITS.get(source, 0.5)
        if interval <= 0:
            return
        lock = self._locks.setdefault(source, asyncio.Lock())
        async with lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            previous = self._last_call.get(source)
            if previous is not None:
                wait = interval - (now - previous)
                if wait > 0:
                    await asyncio.sleep(wait)
            self._last_call[source] = asyncio.get_running_loop().time()

    async def request(
        self,
        source: str,
        url: str,
        *,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        timeout: float | None = None,
        follow_redirects: bool | None = None,
        use_cache: bool = True,
        cacheable_statuses: tuple[int, ...] = (200, 404),
        retries: int | None = None,
    ) -> HttpResult:
        """Execute un appel HTTP avec cache, politesse, retries et backoff."""
        key = _cache_key(source, method, url, params, data)

        if use_cache and self.store is not None:
            cached = await self.store.cache_get(key)
            if cached is not None:
                return HttpResult(
                    source=source,
                    url=url,
                    status=cached["status"],
                    payload=_maybe_json(cached["payload"]),
                    text=cached["payload"],
                    cached=True,
                    fetched_at=cached["fetched_at"],
                )

        retries = max(1, int(self.settings.http_retries if retries is None else retries))
        last = HttpResult(source=source, url=url, error="aucune tentative effectuée")

        for attempt in range(1, retries + 1):
            await self._throttle(source)
            try:
                kwargs: dict[str, Any] = {}
                if follow_redirects is not None:
                    kwargs["follow_redirects"] = follow_redirects
                response = await self.client.request(
                    method, url, params=params, headers=headers, data=data,
                    timeout=timeout or self.settings.http_timeout, **kwargs,
                )
            except httpx.TimeoutException:
                last = HttpResult(source=source, url=url, error="délai d'attente dépassé", attempts=attempt)
            except httpx.HTTPError as exc:
                last = HttpResult(
                    source=source, url=url,
                    error=f"erreur réseau ({type(exc).__name__} : {str(exc)[:120]})", attempts=attempt,
                )
            else:
                result = HttpResult(
                    source=source, url=str(response.url), status=response.status_code,
                    payload=_maybe_json(response.text), text=response.text, attempts=attempt,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    cookies=list(response.headers.get_list("set-cookie")),
                )
                if response.status_code in RETRYABLE_STATUSES and attempt < retries:
                    delay = _parse_retry_after(response.headers.get("retry-after"))
                    await asyncio.sleep(delay if delay is not None else _backoff(attempt))
                    last = result
                    continue
                if (
                    use_cache
                    and self.store is not None
                    and response.status_code in cacheable_statuses
                ):
                    await self.store.cache_put(
                        key, source, str(response.url), response.status_code,
                        response.text, self.settings.cache_ttl_hours,
                    )
                return result

            if attempt < retries:
                await asyncio.sleep(_backoff(attempt))

        return last


def _backoff(attempt: int) -> float:
    """Backoff exponentiel avec jitter, plafonne."""
    return min(MAX_BACKOFF, (2 ** (attempt - 1)) * 0.8 + random.uniform(0, 0.4))


def _maybe_json(text: str | None) -> Any | None:
    if not text:
        return None
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None
