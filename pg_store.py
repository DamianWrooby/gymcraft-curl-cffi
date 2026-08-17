"""Shared Postgres scaffolding for `token_store` and `sessions`.

Both stores are connect-per-operation: their DB work only happens on a client-cache
miss or at session boundaries (rare after warmup), so a fresh connection each time
is simpler and more resilient to managed-PG idle drops than a long-lived pool — and
inherently safe across the gthread worker's threads.

Both tables live in the `garmin` schema, never `public`. The DB is shared with
GymCraft, whose Prisma schema owns `public` — a table there that Prisma does not
know about reads as schema drift, and `prisma migrate dev` offers to reset the
database to resolve it. Prisma only introspects `public`, so a separate schema puts
these tables structurally out of its reach.
"""

import logging
import threading

logger = logging.getLogger(__name__)

SCHEMA = "garmin"


def bootstrap_ddl(table: str) -> str:
    """Leading DDL for `table`: create the schema, then relocate the table into it.

    TODO(one-time): the `DO $$` relocation below can be deleted once prod is
    confirmed running on the `garmin` schema — it is a no-op from the second deploy
    onward. Keep the `CREATE SCHEMA` line.

    `SET SCHEMA` carries the rows and indexes along with the table, so persisted
    tokens and live sessions stay valid across the move. The `public` check alone is
    what makes an ordinary redeploy a no-op (a relocated table is gone from
    `public`); the second check exists for a different case — a manually recreated
    `public.<table>` would otherwise make `ALTER TABLE` raise "already exists in
    schema garmin", and since `_initialized` only flips after the DDL succeeds, that
    would re-run and re-fail on every request.
    """
    return f"""
        CREATE SCHEMA IF NOT EXISTS {SCHEMA};

        DO $$
        BEGIN
            IF to_regclass('public.{table}') IS NOT NULL
               AND to_regclass('{SCHEMA}.{table}') IS NULL THEN
                ALTER TABLE public.{table} SET SCHEMA {SCHEMA};
            END IF;
        END $$;
    """


class PostgresStore:
    """Base for the Postgres-backed stores: lazy driver import, one-time schema
    bootstrap, connection per operation.

    Subclasses supply `_DDL` (idempotent, run once per process on first use) and
    `_TABLE` (schema-qualified, for log lines)."""

    _DDL: str = ""
    _TABLE: str = ""

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
            logger.info("%s: schema ensured (%s)", type(self).__name__, self._TABLE)
