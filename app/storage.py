"""Persistance SQLite : cache des reponses d'API, analyses et journal d'audit."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id              TEXT PRIMARY KEY,
    domain          TEXT NOT NULL,
    domain_unicode  TEXT,
    status          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    score           INTEGER,
    grade           TEXT,
    actor           TEXT,
    report_json     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_domain ON analyses (domain, started_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    actor         TEXT,
    domain        TEXT,
    action        TEXT NOT NULL,
    consents_json TEXT,
    client_ip     TEXT,
    user_agent    TEXT,
    analysis_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts DESC);

CREATE TABLE IF NOT EXISTS http_cache (
    key        TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    url        TEXT,
    status     INTEGER,
    payload    TEXT,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON http_cache (expires_at);
"""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


class Store:
    """Acces SQLite. Les appels bloquants sont deportes dans un thread."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    # -- infrastructure -----------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_sync(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    async def init(self) -> None:
        await asyncio.to_thread(self._init_sync)

    # -- cache HTTP ---------------------------------------------------------
    def _cache_get_sync(self, key: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload, status, fetched_at, expires_at FROM http_cache WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        expires = _parse_iso(row["expires_at"])
        if expires is None or expires <= _utcnow():
            return None
        return {
            "payload": row["payload"],
            "status": row["status"],
            "fetched_at": _parse_iso(row["fetched_at"]) or _utcnow(),
        }

    async def cache_get(self, key: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._cache_get_sync, key)

    def _cache_put_sync(
        self, key: str, source: str, url: str, status: int, payload: str, ttl_hours: int
    ) -> None:
        now = _utcnow()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO http_cache (key, source, url, status, payload, fetched_at,"
                " expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (key, source, url, status, payload, _iso(now),
                 _iso(now + timedelta(hours=max(0, ttl_hours)))),
            )

    async def cache_put(
        self, key: str, source: str, url: str, status: int, payload: str, ttl_hours: int
    ) -> None:
        await asyncio.to_thread(self._cache_put_sync, key, source, url, status, payload, ttl_hours)

    def _cache_purge_sync(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM http_cache WHERE expires_at <= ?", (_iso(_utcnow()),))
            return cur.rowcount

    async def cache_purge_expired(self) -> int:
        return await asyncio.to_thread(self._cache_purge_sync)

    # -- analyses -----------------------------------------------------------
    def _save_report_sync(self, report_dict: dict[str, Any], report_json: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO analyses (id, domain, domain_unicode, status, started_at,"
                " finished_at, score, grade, actor, report_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    report_dict["id"], report_dict["domain"], report_dict.get("domain_unicode"),
                    report_dict["status"], report_dict["started_at"], report_dict.get("finished_at"),
                    report_dict.get("score"), report_dict.get("grade"), report_dict.get("actor"),
                    report_json,
                ),
            )

    async def save_report(self, report) -> None:
        payload = json.loads(report.model_dump_json())
        await asyncio.to_thread(self._save_report_sync, payload, json.dumps(payload))

    def _get_report_sync(self, analysis_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        return json.loads(row["report_json"]) if row else None

    async def get_report(self, analysis_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._get_report_sync, analysis_id)

    def _list_analyses_sync(self, domain: str | None, limit: int) -> list[dict[str, Any]]:
        query = (
            "SELECT id, domain, domain_unicode, status, started_at, finished_at, score, grade, actor"
            " FROM analyses"
        )
        args: list[Any] = []
        if domain:
            query += " WHERE domain = ?"
            args.append(domain)
        query += " ORDER BY started_at DESC LIMIT ?"
        args.append(limit)
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(query, args).fetchall()]

    async def list_analyses(self, domain: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._list_analyses_sync, domain, limit)

    # -- journal d'audit ----------------------------------------------------
    def _log_sync(self, entry: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, actor, domain, action, consents_json, client_ip,"
                " user_agent, analysis_id) VALUES (?,?,?,?,?,?,?,?)",
                (
                    entry["ts"], entry.get("actor"), entry.get("domain"), entry["action"],
                    entry.get("consents_json"), entry.get("client_ip"), entry.get("user_agent"),
                    entry.get("analysis_id"),
                ),
            )

    async def log_audit(self, entry: dict[str, Any]) -> None:
        await asyncio.to_thread(self._log_sync, entry)

    def _list_audit_sync(self, limit: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    async def list_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._list_audit_sync, limit)

    def _purge_audit_sync(self, days: int) -> int:
        cutoff = _iso(_utcnow() - timedelta(days=max(0, days)))
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
            return cur.rowcount

    async def purge_audit(self, days: int) -> int:
        """Supprime les entrees d'audit plus anciennes que `days` (conformite RGPD)."""
        return await asyncio.to_thread(self._purge_audit_sync, days)
