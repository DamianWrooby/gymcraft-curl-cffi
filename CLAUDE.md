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
web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
```
The 120s timeout is required: the 5-strategy login cascade includes anti-WAF delays (widget 3-8s, portal 10-20s), so the worst case is ~60s.

## Architecture

- **`app.py`** — Flask routes (thin layer, delegates to `garmin_service`):
  - `POST /authenticate` — JSON `{username, password}` → `{status, message}`
  - `POST /user-stats` — JSON `{username, password}` → `{status, data}` (calls `client.get_stats_and_body(today)`)
  - `POST /upload-workout` — multipart form (`username`, optional `password`, `file`) → `{status, response}` (calls `client.upload_workout(workout_json)`)
  - CORS: `localhost:5173` and `gymcraft.damianwroblewski.com`

- **`garmin_service.py`** — Authentication, caching, token persistence:
  - In-memory `_client_cache: dict[str, Garmin]` keyed by MD5 of email. Survives within a gunicorn worker lifetime.
  - Token dir: `~/.garmin_tokens/{md5_user_hash}/`, file `garmin_tokens.json` (new format: `{di_token, di_refresh_token, di_client_id}`).
  - `get_client(username, password=None)` flow:
    1. Return cached client if present.
    2. If token file exists: `Garmin(email=username).login(tokenstore=<dir>)`. On `GarminConnectTooManyRequestsError`, re-raise (no password fallback). On other errors, warn and continue.
    3. Require password; `Garmin(email, password).login()` triggers the 5-strategy cascade.
    4. Persist tokens via `client.client.dump(<dir>)`. Cache and return.

## Key Design Details

- **5-strategy login cascade** (inside `garminconnect.Garmin.login()`): mobile iOS+curl_cffi → mobile iOS+requests → SSO widget+curl_cffi → portal web+curl_cffi → portal web+requests. Rate limits fall through; credential errors and MFA stop the chain.
- **`display_name`**: Correctly populated by `garminconnect`, which fetches `/userprofile-service/socialProfile` after login.
- **`upload_workout()`** in `garminconnect` already returns a parsed `dict` (calls `.json()` internally). No response unwrapping needed.
- **Token format migration**: Tokens from the previous `garth` implementation (`oauth1_token.json` + `oauth2_token.json`) are incompatible. Users must re-authenticate once after migration to produce a `garmin_tokens.json`.
- **Render ephemeral FS**: Tokens on disk are lost per deploy. In-memory cache survives within worker lifetime. When tokens are missing, the frontend must supply credentials to trigger a fresh login. Redis/DB token storage is a future improvement.
- **curl_cffi on Render**: The pip package bundles a compiled libcurl-impersonate — no system-level dependencies required.

## Dependencies

- `Flask`, `flask-cors` — web framework + CORS
- `garminconnect>=0.3.2,<0.4.0` — high-level Garmin client with the 5-strategy login cascade
- `curl_cffi>=0.7.0` — TLS fingerprint impersonation (must be explicit; `garminconnect` conditionally imports it)
- `ua_generator>=1.0` — random browser UA generation (used by `garminconnect` when present)
- `gunicorn` — production WSGI server
