"""In-process performance metrics (Phase 0 instrumentation).

Lightweight, dependency-free, thread-safe counters + timing samples so we can
attribute latency to auth path vs data call vs Garmin throttling. Read a snapshot
via the /metrics endpoint. State is per-process (per gunicorn worker) and resets
on restart — this is diagnostic instrumentation, not durable telemetry.
"""

import threading
import time
from collections import defaultdict, deque

# Keep the last N samples per timing name. Bounded so a long-lived worker can't
# grow memory without limit; large enough for stable p95/p99 over a busy window.
_MAX_SAMPLES = 1000

_lock = threading.Lock()
_counters: dict[str, int] = defaultdict(int)
_timings: dict[str, deque] = defaultdict(lambda: deque(maxlen=_MAX_SAMPLES))


def incr(name: str, n: int = 1) -> None:
    """Increment a named counter (e.g. cache hits, 429s)."""
    with _lock:
        _counters[name] += n


def record_timing(name: str, elapsed_ms: float) -> None:
    """Record an elapsed-time sample (milliseconds) under a named operation."""
    with _lock:
        _timings[name].append(elapsed_ms)


class timer:
    """Context manager that records elapsed ms under `name` and exposes `.elapsed_ms`.

    Usage:
        with timer("user-stats.fetch") as t:
            client.get_stats_and_body(...)
        logger.info("fetched in %.0f ms", t.elapsed_ms)
    """

    def __init__(self, name: str):
        self.name = name
        self.elapsed_ms = 0.0
        self._start = 0.0

    def __enter__(self) -> "timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000.0
        record_timing(self.name, self.elapsed_ms)
        return False  # never suppress exceptions


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    # Nearest-rank percentile; index clamped to the last element.
    k = max(0, min(len(sorted_values) - 1, int(round((pct / 100.0) * len(sorted_values) + 0.5)) - 1))
    return sorted_values[k]


def snapshot() -> dict:
    """Return a JSON-serializable view of counters and per-operation latency stats."""
    with _lock:
        counters = dict(_counters)
        timings = {name: list(samples) for name, samples in _timings.items()}

    stats = {}
    for name, samples in timings.items():
        ordered = sorted(samples)
        count = len(ordered)
        stats[name] = {
            "count": count,
            "p50_ms": round(_percentile(ordered, 50), 1),
            "p95_ms": round(_percentile(ordered, 95), 1),
            "p99_ms": round(_percentile(ordered, 99), 1),
            "max_ms": round(ordered[-1], 1) if count else 0.0,
            "mean_ms": round(sum(ordered) / count, 1) if count else 0.0,
        }

    return {"counters": counters, "timings": stats}
