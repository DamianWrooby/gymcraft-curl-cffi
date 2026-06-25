"""Persistent Garmin token storage (Phase 2a).

Stores the JSON blob produced by `garminconnect`'s `client.dumps()`
(`{di_token, di_refresh_token, di_client_id}`) keyed by the per-user hash, so a
worker can resume a session via `Garmin(...).login(tokenstore=<blob_string>)`
instead of re-running the ~60s SSO cascade. Survives Render deploys / spin-down,
which the previous on-disk store (ephemeral FS) did not.

Backend selection:
- If DATABASE_URL is set -> PostgresTokenStore (the shared GymCraft DB).
- Otherwise           -> DiskTokenStore at GARMIN_TOKEN_DIR (local dev fallback,
                          same on-disk layout garminconnect itself uses).

The blob is an account credential (a JWT to the user's Garmin account). Treat the
`garmin_tokens` table as secrets: restrict access and prefer DB-level encryption
at rest. App-level encryption can be layered here later without touching callers.
"""

import logging
import os
import threading
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)


class TokenStore(Protocol):
    def get(self, user_hash: str) -> str | None: ...
    def save(self, user_hash: str, blob: str) -> None: ...
    def delete(self, user_hash: str) -> None: ...


class DiskTokenStore:
    """Local-dev fallback: one file per user, matching garminconnect's own format."""

    def __init__(self, base_dir: Path):
        self._base = base_dir

    def _path(self, user_hash: str) -> Path:
        return self._base / user_hash / "garmin_tokens.json"

    def get(self, user_hash: str) -> str | None:
        p = self._path(user_hash)
        try:
            return p.read_text() if p.exists() else None
        except OSError as e:
            logger.warning("DiskTokenStore.get failed for %s: %s", user_hash, e)
            return None

    def save(self, user_hash: str, blob: str) -> None:
        p = self._path(user_hash)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(blob)

    def delete(self, user_hash: str) -> None:
        p = self._path(user_hash)
        with __import__("contextlib").suppress(OSError):
            p.unlink(missing_ok=True)


class PostgresTokenStore:
    """Postgres-backed store. Connect-per-operation: token ops only happen on a cache
    miss (rare after warmup), so a fresh connection each time is simpler and more
    resilient to managed-PG idle drops than a long-lived pool — and inherently safe
    across the gthread worker's threads."""

    _DDL = """
        CREATE TABLE IF NOT EXISTS garmin_tokens (
            user_hash  TEXT PRIMARY KEY,
            token_blob TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """

    def __init__(self, dsn: str):
        import psycopg2  # imported lazily so local dev needn't install the driver

        self._psycopg2 = psycopg2
        self._dsn = dsn
        self._init_lock = threading.Lock()
        self._initialized = False

    def _connect(self):
        return self._psycopg2.connect(self._dsn)

    def _ensure_schema(self) -> None:
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(self._DDL)
                conn.commit()
            self._initialized = True
            logger.info("PostgresTokenStore: schema ensured (garmin_tokens)")

    def get(self, user_hash: str) -> str | None:
        self._ensure_schema()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT token_blob FROM garmin_tokens WHERE user_hash = %s", (user_hash,)
            )
            row = cur.fetchone()
        return row[0] if row else None

    def save(self, user_hash: str, blob: str) -> None:
        self._ensure_schema()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO garmin_tokens (user_hash, token_blob, updated_at)
                VALUES (%s, %s, now())
                ON CONFLICT (user_hash)
                DO UPDATE SET token_blob = EXCLUDED.token_blob, updated_at = now()
                """,
                (user_hash, blob),
            )
            conn.commit()

    def delete(self, user_hash: str) -> None:
        self._ensure_schema()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM garmin_tokens WHERE user_hash = %s", (user_hash,))
            conn.commit()


def _build_default_store() -> TokenStore:
    dsn = os.getenv("DATABASE_URL")
    if dsn:
        logger.info("token_store: using PostgresTokenStore (DATABASE_URL set)")
        return PostgresTokenStore(dsn)
    base = Path(os.getenv("GARMIN_TOKEN_DIR", "~/.garmin_tokens")).expanduser()
    logger.info("token_store: DATABASE_URL not set, using DiskTokenStore at %s", base)
    return DiskTokenStore(base)


# Module-level singleton chosen at import time.
store: TokenStore = _build_default_store()
