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
    except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
        logger.warning("Token-based login failed: %s", e)

    if not password:
        raise ValueError("No valid token found, and password is required.")

    client = Garmin(email=username, password=password)
    client.login(tokenstore=user_token_dir)
    _client_cache[uhash] = client
    return client
