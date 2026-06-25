"""Opaque session tokens (Phase 2b).

Closes the email-keyed impersonation bypass: identity is a 256-bit unguessable
token, not the user's email. `/authenticate` issues a token after a real Garmin
login; protected endpoints require it (Bearer). The token maps to a `user_hash`,
and the live Garmin client is rebuilt from the persisted token blob in
`token_store` — so a session keeps working across deploys/restarts.

Backend selection mirrors token_store:
- DATABASE_URL set -> PostgresSessionStore (sessions survive restarts).
- otherwise        -> InMemorySessionStore (local dev; lost on restart).

Expiry: sliding idle TTL, capped by an absolute lifetime. Lazy eviction on
resolve(); `purge_expired()` is available for an optional sweep.
"""

import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger(__name__)

SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", str(12 * 60 * 60)))          # idle
SESSION_MAX_LIFETIME_SECONDS = int(os.getenv("SESSION_MAX_LIFETIME_SECONDS", str(7 * 86400)))  # absolute

# Only persist a slid idle-deadline when it moves by at least this much, to avoid a
# DB write on every single request while keeping sliding-expiry semantics.
_SLIDE_WRITE_THRESHOLD_SECONDS = 300


@dataclass
class Session:
    token: str
    user_hash: str
    username: str
    created_at: float
    expires_at: float  # idle deadline (epoch seconds)


def _new_token() -> str:
    return secrets.token_urlsafe(32)


class SessionStore(Protocol):
    def create(self, username: str, user_hash: str) -> str: ...
    def resolve(self, token: str) -> Session | None: ...
    def revoke(self, token: str) -> None: ...
    def purge_expired(self) -> int: ...


def _validate_and_slide(s: Session, now: float) -> float | None:
    """Return the new idle deadline if the session is still valid, else None."""
    if now > s.expires_at:
        return None  # idle timeout
    if now > s.created_at + SESSION_MAX_LIFETIME_SECONDS:
        return None  # absolute lifetime reached
    # Slide, but never past the absolute lifetime.
    return min(now + SESSION_TTL_SECONDS, s.created_at + SESSION_MAX_LIFETIME_SECONDS)


class InMemorySessionStore:
    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, username: str, user_hash: str) -> str:
        token = _new_token()
        now = time.time()
        with self._lock:
            self._sessions[token] = Session(token, user_hash, username, now, now + SESSION_TTL_SECONDS)
        return token

    def resolve(self, token: str) -> Session | None:
        now = time.time()
        with self._lock:
            s = self._sessions.get(token)
            if s is None:
                return None
            new_deadline = _validate_and_slide(s, now)
            if new_deadline is None:
                self._sessions.pop(token, None)
                return None
            s.expires_at = new_deadline
            return Session(s.token, s.user_hash, s.username, s.created_at, s.expires_at)

    def revoke(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def purge_expired(self) -> int:
        now = time.time()
        with self._lock:
            dead = [t for t, s in self._sessions.items() if _validate_and_slide(s, now) is None]
            for t in dead:
                self._sessions.pop(t, None)
        return len(dead)


class PostgresSessionStore:
    _DDL = """
        CREATE TABLE IF NOT EXISTS garmin_sessions (
            token      TEXT PRIMARY KEY,
            user_hash  TEXT NOT NULL,
            username   TEXT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL,
            expires_at DOUBLE PRECISION NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_garmin_sessions_expires
            ON garmin_sessions (expires_at);
    """

    def __init__(self, dsn: str):
        import psycopg2  # lazy: local dev needn't install the driver

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
            logger.info("PostgresSessionStore: schema ensured (garmin_sessions)")

    def create(self, username: str, user_hash: str) -> str:
        self._ensure_schema()
        token = _new_token()
        now = time.time()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO garmin_sessions (token, user_hash, username, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (token, user_hash, username, now, now + SESSION_TTL_SECONDS),
            )
            conn.commit()
        return token

    def resolve(self, token: str) -> Session | None:
        self._ensure_schema()
        now = time.time()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT token, user_hash, username, created_at, expires_at "
                "FROM garmin_sessions WHERE token = %s",
                (token,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            s = Session(*row)
            new_deadline = _validate_and_slide(s, now)
            if new_deadline is None:
                cur.execute("DELETE FROM garmin_sessions WHERE token = %s", (token,))
                conn.commit()
                return None
            # Throttle write amplification: only persist a meaningful slide.
            if new_deadline - s.expires_at >= _SLIDE_WRITE_THRESHOLD_SECONDS:
                cur.execute(
                    "UPDATE garmin_sessions SET expires_at = %s WHERE token = %s",
                    (new_deadline, token),
                )
                conn.commit()
            s.expires_at = new_deadline
            return s

    def revoke(self, token: str) -> None:
        self._ensure_schema()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM garmin_sessions WHERE token = %s", (token,))
            conn.commit()

    def purge_expired(self) -> int:
        self._ensure_schema()
        now = time.time()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM garmin_sessions "
                "WHERE expires_at < %s OR created_at < %s",
                (now, now - SESSION_MAX_LIFETIME_SECONDS),
            )
            deleted = cur.rowcount
            conn.commit()
        return deleted


def _build_default_store() -> SessionStore:
    dsn = os.getenv("DATABASE_URL")
    if dsn:
        logger.info("sessions: using PostgresSessionStore (DATABASE_URL set)")
        return PostgresSessionStore(dsn)
    logger.info("sessions: DATABASE_URL not set, using InMemorySessionStore (lost on restart)")
    return InMemorySessionStore()


store: SessionStore = _build_default_store()
