# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GymCraft Connect (curl_cffi edition) is a Flask API that acts as a backend proxy to Garmin Connect. It authenticates users, fetches daily stats + body composition, and uploads workouts. It is the backend for the GymCraft frontend at `https://gymcraft.damianwroblewski.com`.

This project replaces an earlier `garth`-based implementation whose authentication flow was permanently blocked by Cloudflare WAF on Render's datacenter IPs (root cause: Python `requests` TLS fingerprint). This version delegates auth to `garminconnect`, which uses `curl_cffi` to impersonate real browser TLS fingerprints and cascades through 5 SSO fallback strategies.

## Running the App

```bash
pip install -r requirements.txt
python app.py               # dev server on 0.0.0.0:5000
```

Production uses gunicorn via `Procfile`:
```
web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 8 --worker-class gthread --timeout 120
```
- **`--workers 1`**: a single process so the in-memory `_client_cache` is shared by all requests (no cross-worker cache fragmentation) and the per-user login lock can collapse a cold-start herd.
- **`--threads 8 --worker-class gthread`**: real concurrency for I/O-bound work. Verified safe: garminconnect's data path uses a fresh plain `requests.Session` per call (`_run_request` → `_fresh_api_session`), which releases the GIL; curl_cffi is only used in the login cascade.
- **`--timeout 120`** is required: the 5-strategy login cascade includes anti-WAF delays (widget 3-8s, portal 10-20s), so the worst case is ~60s.

## Architecture

- **`app.py`** — Flask routes (thin layer, delegates to `garmin_service`). Auth model is **opaque session tokens** (Bearer), not credentials-per-call:
  - `POST /authenticate` — JSON `{username, password}` → `{status, session_token}`. Runs a real Garmin login, then issues a token.
  - `POST /logout` — `Authorization: Bearer <token>` → revokes the session (idempotent).
  - `POST /user-stats` — Bearer → `{status, data}` (`client.get_stats_and_body(today)`).
  - `POST /activities`, `POST /activity/detail`, `POST /progress-summary` — Bearer + JSON params.
  - `POST /upload-workout` — Bearer + multipart form (`file`) → `{status, response}`.
  - `GET /health` — unauthenticated liveness probe. `GET /metrics` — diagnostic counters/latency (behind the API-key gate).
  - **The Bearer token is the sole identity** — any `username`/`password` in the body is ignored. This closes the old email-keyed impersonation bypass. Protected routes check auth *before* param validation and return 401 on a missing/invalid/expired token.
  - Two auth layers: service-level `X-API-Key` (`before_request`, for the proxy) **and** user-level Bearer session token.
  - CORS: `localhost:5173` and `gymcraft.damianwroblewski.com`

- **`garmin_service.py`** — Garmin client management, caching, session orchestration:
  - In-memory `_client_cache: dict[str, Garmin]` keyed by MD5 of email. Guarded by `_cache_lock`; per-user locks (`_get_user_lock`) serialize logins so concurrent first-time callers share one login.
  - `get_client(username, password=None)`: fast cache check → on miss, under the per-user lock, `_login_locked` loads the token blob from `token_store` and resumes via `Garmin(email).login(tokenstore=<blob_string>)`; falls back to a password cascade if there's no blob; persists via `_persist_tokens` (`client.client.dumps()`).
  - `create_session(username, password)` → authenticates, then `sessions.store.create(...)` → token. `get_client_for_session(token)` → resolves the session, rebuilds the client by hash (no password), raises `PermissionError` if unusable. `revoke_session(token)`.

- **`token_store.py`** — persistent Garmin token blobs. `PostgresTokenStore` (table `garmin.garmin_tokens`) when `DATABASE_URL` is set, else `DiskTokenStore` (local dev). Stores the `{di_token, di_refresh_token, di_client_id}` JSON string from `client.dumps()`.

- **`sessions.py`** — opaque session tokens. `PostgresSessionStore` (table `garmin.garmin_sessions`) when `DATABASE_URL` is set, else `InMemorySessionStore`. Sliding idle TTL (`SESSION_TTL_SECONDS`, default 12h) capped by absolute lifetime (`SESSION_MAX_LIFETIME_SECONDS`, default 7d).

- **`metrics.py`** — in-process counters + timing percentiles, surfaced at `GET /metrics`.

## Key Design Details

- **5-strategy login cascade** (inside `garminconnect.Garmin.login()`): mobile iOS+curl_cffi → mobile iOS+requests → SSO widget+curl_cffi → portal web+curl_cffi → portal web+requests. Rate limits fall through; credential errors and MFA stop the chain.
- **String vs path tokenstore**: `Garmin.login(tokenstore=...)` treats the arg as a raw JSON blob when `len > 512`, else a path. Token blobs (JWT `di_token`) exceed 512, so the DB-string path loads in-memory with no disk. Note: a string-loaded client does not auto-persist mid-session refreshes (no tokenstore path set) — we persist right after login (which proactively refreshes).
- **`display_name`**: populated by `garminconnect`, which fetches `/userprofile-service/socialProfile` after login.
- **`upload_workout()`** in `garminconnect` already returns a parsed `dict`. No response unwrapping needed.
- **Persistence on Render**: tokens and sessions live in Postgres (the shared GymCraft DB), so they survive deploys/spin-down — the in-memory client cache is just a per-process accelerator rebuilt from the DB on demand. `DATABASE_URL` must be set on the Render service; without it both stores silently fall back to their dev backends (ephemeral disk + in-memory), which Render's 15-minute idle spin-down then wipes on every visit.
- **`garmin` schema**: both tables live in a dedicated `garmin` schema, never `public`. The DB is shared with GymCraft, whose Prisma schema owns `public`; an unmodelled table there reads as drift and `prisma migrate dev` offers to reset the database. Prisma only introspects `public`, so the separate schema is what keeps these tables out of its reach. Use the **direct** (unpooled) DSN with no query parameters — libpq rejects Prisma-only ones such as `pgbouncer` and `connection_limit`.
- **curl_cffi on Render**: the pip package bundles a compiled libcurl-impersonate — no system-level dependencies required.
- **Do not set `GARMINTOKENS`** in the environment: garminconnect would pick it up as a default tokenstore and interfere with the password-login path.

## Dependencies

- `Flask`, `flask-cors` — web framework + CORS
- `garminconnect>=0.3.2,<0.4.0` — high-level Garmin client with the 5-strategy login cascade
- `curl_cffi>=0.7.0` — TLS fingerprint impersonation (must be explicit; `garminconnect` conditionally imports it)
- `ua_generator>=1.0` — random browser UA generation (used by `garminconnect` when present)
- `psycopg2-binary` — Postgres driver for the token/session stores (imported lazily; only needed when `DATABASE_URL` is set)
- `gunicorn` — production WSGI server

## Environment

- `DATABASE_URL` — Postgres DSN. When set, tokens/sessions persist to Postgres; otherwise local disk/in-memory fallbacks are used.
- `INTERNAL_API_KEY` — service-level `X-API-Key` gate (optional; gate disabled if unset).
- `SESSION_TTL_SECONDS` / `SESSION_MAX_LIFETIME_SECONDS` — session idle / absolute lifetimes.
- `GARMIN_TOKEN_DIR` — disk fallback location when `DATABASE_URL` is unset (default `~/.garmin_tokens`).
