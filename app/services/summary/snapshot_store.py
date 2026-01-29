"""Lightweight in-memory snapshot store for summary deltas.

Stores aggregated counters at a fixed cadence (5 minutes) for ~2 hours.
Thread-safe and O(1) retrieval by time bucket.
"""

import threading
import time
from collections import deque

_BUCKET_SECONDS = 300  # 5 minutes
_MAX_SNAPSHOTS = 36  # ~3 hours at 5-min cadence (>= 2 hours)

_lock = threading.Lock()
_snapshots = {}
_order = deque()


def record_snapshot(stats, now_ts=None):
    """Record a snapshot if we haven't stored one in the current bucket."""
    if not isinstance(stats, dict):
        return False
    ts = now_ts or time.time()
    bucket = int(ts // _BUCKET_SECONDS)

    with _lock:
        if _order and _order[-1] == bucket:
            return False
        _snapshots[bucket] = {"ts": ts, **stats}
        _order.append(bucket)
        while len(_order) > _MAX_SNAPSHOTS:
            old_bucket = _order.popleft()
            _snapshots.pop(old_bucket, None)
    return True


def get_snapshot_near(target_ts, max_drift_seconds=900):
    """Get snapshot closest to target_ts within max drift (default ±15m)."""
    if not target_ts:
        return None
    target_bucket = int(target_ts // _BUCKET_SECONDS)
    span = max(1, int(max_drift_seconds // _BUCKET_SECONDS))

    best = None
    best_diff = None
    with _lock:
        for offset in range(-span, span + 1):
            bucket = target_bucket + offset
            snap = _snapshots.get(bucket)
            if not snap:
                continue
            diff = abs(snap["ts"] - target_ts)
            if best_diff is None or diff < best_diff:
                best = snap
                best_diff = diff
    return best
