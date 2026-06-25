"""Garmin Connect client management: authentication, caching, token persistence."""

import hashlib
import logging
import threading
import time

from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)

import metrics
import sessions
import token_store

logger = logging.getLogger(__name__)

_client_cache: dict[str, Garmin] = {}

# Phase 1 concurrency: with `--worker-class gthread`, multiple threads share this process and the
# cache. `_cache_lock` guards the dict itself; `_user_locks` gives one lock per user so that a
# cold-start "thundering herd" (a dashboard firing several endpoints at once for the same user)
# collapses into a single login instead of N parallel cascades + a 429 storm. Data calls are NOT
# serialized — garminconnect uses a fresh requests.Session per call, so parallel reads are safe.
_cache_lock = threading.Lock()
_user_locks: dict[str, threading.Lock] = {}
_user_locks_guard = threading.Lock()


def _user_hash(username: str) -> str:
    # MD5 is a filesystem-safe slug for the username, not a security primitive.
    return hashlib.md5(username.encode("utf-8")).hexdigest()


def _get_user_lock(uhash: str) -> threading.Lock:
    with _user_locks_guard:
        lock = _user_locks.get(uhash)
        if lock is None:
            lock = threading.Lock()
            _user_locks[uhash] = lock
        return lock


def get_client(username: str, password: str | None = None) -> Garmin:
    """Return an authenticated Garmin client, using cache then tokens then password."""
    if not username:
        raise ValueError("username is required")

    uhash = _user_hash(username)

    # Fast path: serve a warm client without taking the per-user login lock.
    with _cache_lock:
        cached = _client_cache.get(uhash)
    if cached is not None:
        logger.info("get_client[%s]: in-memory cache hit (no Garmin login)", uhash)
        metrics.incr("get_client.cache_hit")
        return cached

    # Miss: serialize logins for this user so concurrent first-time callers don't each run a
    # separate cascade. The first thread logs in; the rest wait and reuse its result.
    with _get_user_lock(uhash):
        # Re-check under the lock: another thread may have finished logging in while we waited.
        with _cache_lock:
            cached = _client_cache.get(uhash)
        if cached is not None:
            logger.info("get_client[%s]: cache hit after waiting for in-flight login", uhash)
            metrics.incr("get_client.cache_hit")
            return cached
        return _login_locked(username, password, uhash)


def _login_locked(username: str, password: str | None, uhash: str) -> Garmin:
    """Perform token-then-password login. Caller MUST hold the per-user lock."""
    metrics.incr("get_client.cache_miss")
    blob = token_store.store.get(uhash)
    logger.info("get_client[%s]: cache miss; token_in_store=%s", uhash, bool(blob))

    if blob:
        try:
            start = time.perf_counter()
            client = Garmin(email=username)
            # A stored blob (>512 chars) loads in-memory via garminconnect's loads();
            # no disk/temp file. login() also proactively refreshes a near-expiry token.
            client.login(tokenstore=blob)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            metrics.record_timing("get_client.token_login", elapsed_ms)
            metrics.incr("get_client.token_login_ok")
            # Persist again: the proactive refresh may have rotated the token, and a
            # string-loaded client does not auto-write back (no tokenstore path set).
            _persist_tokens(uhash, client)
            with _cache_lock:
                _client_cache[uhash] = client
            logger.info("get_client[%s]: token-based login OK in %.0f ms", uhash, elapsed_ms)
            return client
        except GarminConnectTooManyRequestsError:
            # Do not fall back to password on rate limit; bubble up immediately.
            metrics.incr("garmin.429")
            metrics.incr("get_client.token_login_429")
            logger.warning("get_client[%s]: rate limited (429) during token login", uhash)
            raise
        except Exception as e:
            # Stale/invalid token, expired refresh token, transient error. Fall through
            # to the password path so the frontend can prompt for credentials.
            metrics.incr("get_client.token_login_failed")
            logger.warning(
                "get_client[%s]: token login failed (%s): %s", uhash, type(e).__name__, e
            )

    if not password:
        metrics.incr("get_client.no_token_no_password")
        logger.info("get_client[%s]: no token and no password -> No valid token found", uhash)
        raise ValueError("No valid token found, and password is required.")

    # Cold password login: the most rate-limit-prone path. Frequent hits here in prod
    # indicate the persisted token store is not surviving (e.g. Render cold starts).
    logger.warning("get_client[%s]: performing COLD password login", uhash)
    start = time.perf_counter()
    try:
        client = Garmin(email=username, password=password)
        client.login()  # no tokenstore -> full SSO cascade
    except GarminConnectTooManyRequestsError:
        metrics.incr("garmin.429")
        metrics.incr("get_client.password_login_429")
        raise
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    metrics.record_timing("get_client.cold_password_login", elapsed_ms)
    metrics.incr("get_client.password_login_ok")
    _persist_tokens(uhash, client)
    with _cache_lock:
        _client_cache[uhash] = client
    logger.info("get_client[%s]: password login OK in %.0f ms; tokens persisted", uhash, elapsed_ms)
    return client


def create_session(username: str, password: str) -> str:
    """Authenticate with Garmin, then issue an opaque session token.

    The token is the sole identity for subsequent requests — it maps to the user
    (via user_hash) whose Garmin tokens are persisted in token_store, so the live
    client can be rebuilt later without the password.
    """
    if not username or not password:
        raise ValueError("username and password are required")
    get_client(username, password)  # full login; caches client + persists tokens
    token = sessions.store.create(username, _user_hash(username))
    metrics.incr("session.created")
    logger.info("create_session: issued token for %s", _user_hash(username))
    return token


def get_client_for_session(token: str) -> Garmin:
    """Resolve a Bearer token to its authenticated Garmin client.

    Raises PermissionError if the token is missing/invalid/expired, or if the
    user's persisted Garmin tokens can no longer restore a client.
    """
    if not token:
        metrics.incr("session.missing")
        raise PermissionError("missing session token")
    session = sessions.store.resolve(token)
    if session is None:
        metrics.incr("session.invalid")
        raise PermissionError("session invalid or expired")
    try:
        # No password: rebuild from the persisted token blob (or in-memory cache).
        client = get_client(session.username)
        metrics.incr("session.resolved")
        return client
    except Exception as e:
        metrics.incr("session.unrestorable")
        logger.warning(
            "get_client_for_session: token valid but client unrestorable (%s): %s",
            type(e).__name__, e,
        )
        raise PermissionError("session can no longer be restored; please re-authenticate") from e


def revoke_session(token: str) -> None:
    if token:
        sessions.store.revoke(token)
        metrics.incr("session.revoked")


def _persist_tokens(uhash: str, client: Garmin) -> None:
    """Save the client's current token blob to the store. Best-effort: a storage
    failure must not fail the user's request — they already hold a live client."""
    try:
        blob = client.client.dumps()
        token_store.store.save(uhash, blob)
        metrics.incr("token_store.save_ok")
        logger.info("get_client[%s]: tokens persisted to store", uhash)
    except Exception as e:
        metrics.incr("token_store.save_failed")
        logger.warning(
            "get_client[%s]: token persist failed (%s): %s", uhash, type(e).__name__, e
        )


_MAX_DETAIL_SAMPLES = 1000


def get_activity_detail(client: Garmin, activity_id):
    """
    Fetch a single activity's detailed payload — overall summary, per-lap splits,
    and a downsampled HR/speed/elevation time-series suitable for charting and AI analysis.

    Response shape: see gym-craft/.ai/PYTHON_ACTIVITY_DETAIL_SPEC.md.
    """
    aid = int(activity_id)
    logger.debug("Requesting activity detail for %s", aid)

    details = client.get_activity_details(aid) or {}
    try:
        splits_raw = client.get_activity_splits(aid)
    except Exception as e:
        # Not every activity has lap data; do not fail the whole call.
        logger.warning("get_activity_splits failed for %s: %s", aid, e)
        splits_raw = None

    summary = details.get("summaryDTO") or {}
    metric_descriptors = details.get("metricDescriptors") or []
    detail_metrics = details.get("activityDetailMetrics") or []

    name_to_index = {}
    for descriptor in metric_descriptors:
        if not isinstance(descriptor, dict):
            continue
        key = descriptor.get("key")
        index = descriptor.get("metricsIndex")
        if key is not None and index is not None:
            name_to_index[key] = index

    type_dto = details.get("activityTypeDTO") or {}
    activity_type = type_dto.get("typeKey") if isinstance(type_dto, dict) else None

    return {
        "activityId": aid,
        "activityName": summary.get("activityName") or details.get("activityName"),
        "activityType": activity_type or "unknown",
        "startTimeGMT": summary.get("startTimeGMT") or details.get("startTimeGMT"),
        "duration": summary.get("duration"),
        "distance": summary.get("distance"),
        "splits": _build_splits(splits_raw),
        "samples": _build_samples(detail_metrics, name_to_index),
    }


def _build_splits(splits_raw):
    if not isinstance(splits_raw, dict):
        return []
    laps = splits_raw.get("lapDTOs") or []
    out = []
    for i, lap in enumerate(laps):
        if not isinstance(lap, dict):
            continue
        out.append(
            {
                "splitIndex": i,
                "distanceM": _coerce_number(lap.get("distance")),
                "durationSec": _coerce_number(lap.get("duration")),
                "averageHr": _coerce_number(lap.get("averageHR")),
                "averageSpeed": _coerce_number(lap.get("averageSpeed")),
                "elevationGainM": _coerce_number(lap.get("elevationGain")),
                "elevationLossM": _coerce_number(lap.get("elevationLoss")),
            }
        )
    return out


def _build_samples(detail_metrics, name_to_index):
    if not detail_metrics:
        return []

    total = len(detail_metrics)
    step = max(1, total // _MAX_DETAIL_SAMPLES)

    ts_idx = name_to_index.get("sumElapsedDuration") or name_to_index.get("sumDuration")
    hr_idx = name_to_index.get("directHeartRate")
    speed_idx = name_to_index.get("directSpeed")
    elev_idx = name_to_index.get("directElevation")

    samples = []
    for i in range(0, total, step):
        entry = detail_metrics[i]
        row = entry.get("metrics") if isinstance(entry, dict) else None
        if not isinstance(row, list):
            continue
        samples.append(
            {
                "timestampSec": _row_number(row, ts_idx, default=float(i)),
                "heartRate": _row_number(row, hr_idx),
                "speed": _row_number(row, speed_idx),
                "elevationM": _row_number(row, elev_idx),
            }
        )
    return samples


def _row_number(row, index, default=None):
    if index is None or index >= len(row):
        return default
    return _coerce_number(row[index], default=default)


def _coerce_number(value, default=None):
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)) and value == value:  # rejects NaN
        return value
    return default
