"""Garmin Connect client management: authentication, caching, token persistence."""

import hashlib
import logging
import os
from pathlib import Path

from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)

logger = logging.getLogger(__name__)

TOKEN_DIR = Path(os.getenv("GARMIN_TOKEN_DIR", "~/.garmin_tokens")).expanduser()

_client_cache: dict[str, Garmin] = {}


def _user_hash(username: str) -> str:
    # MD5 is a filesystem-safe slug for the username, not a security primitive.
    return hashlib.md5(username.encode("utf-8")).hexdigest()


def get_client(username: str, password: str | None = None) -> Garmin:
    """Return an authenticated Garmin client, using cache then tokens then password."""
    if not username:
        raise ValueError("username is required")

    uhash = _user_hash(username)

    cached = _client_cache.get(uhash)
    if cached is not None:
        return cached

    user_token_dir = str(TOKEN_DIR / uhash)

    try:
        client = Garmin(email=username)
        client.login(tokenstore=user_token_dir)
        _client_cache[uhash] = client
        return client
    except GarminConnectTooManyRequestsError:
        # Do not fall back to password on rate limit; bubble up immediately.
        raise
    except Exception as e:
        # Covers GarminConnectAuthenticationError, GarminConnectConnectionError,
        # and FileNotFoundError / OSError when the token dir does not exist yet
        # (first-time users). All of these should fall through to the
        # password-required path so the frontend can prompt for credentials.
        logger.warning("Token-based login failed: %s", e)

    if not password:
        raise ValueError("No valid token found, and password is required.")

    client = Garmin(email=username, password=password)
    client.login(tokenstore=user_token_dir)
    _client_cache[uhash] = client
    return client


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
