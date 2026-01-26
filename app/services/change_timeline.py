"""Change timeline storage and emitters.

This module stores a sparse, human-readable record of state transitions
for the Overview Change Timeline widget.
"""

from dataclasses import dataclass
from datetime import datetime
import threading
import time
from collections import deque
from typing import Dict, List, Optional


@dataclass
class ChangeTimelineEntry:
    ts: int
    source: str
    title: str
    detail: Optional[str]
    level: str

    def to_public_dict(self) -> Dict[str, Optional[str]]:
        return {
            "time": datetime.fromtimestamp(self.ts).strftime("%Y-%m-%d %H:%M"),
            "source": self.source,
            "title": self.title,
            "detail": self.detail,
            "level": self.level,
        }


class ChangeTimelineStore:
    def __init__(
        self,
        max_entries: int = 200,
        ttl_seconds: int = 43200,
        dedupe_window_s: int = 60,
        update_window_s: int = 60,
        rate_limit_per_min: int = 30,
    ) -> None:
        self._entries: Dict[str, ChangeTimelineEntry] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._dedupe_window_s = dedupe_window_s
        self._update_window_s = update_window_s
        self._rate_limit_per_min = rate_limit_per_min
        self._rate_limit_ts: deque[int] = deque()

    def _prune_rate_limit(self, now_ts: int) -> None:
        cutoff = now_ts - 60
        while self._rate_limit_ts and self._rate_limit_ts[0] < cutoff:
            self._rate_limit_ts.popleft()

    def _prune_expired(self, now_ts: int) -> None:
        cutoff = now_ts - self._ttl_seconds
        stale_keys = [key for key, entry in self._entries.items() if entry.ts < cutoff]
        for key in stale_keys:
            self._entries.pop(key, None)

    def _prune_overflow(self) -> None:
        if len(self._entries) <= self._max_entries:
            return
        oldest = sorted(self._entries.items(), key=lambda item: item[1].ts)
        for key, _ in oldest[: max(0, len(self._entries) - self._max_entries)]:
            self._entries.pop(key, None)

    def add_or_update(self, entry: ChangeTimelineEntry, key: str) -> bool:
        now_ts = entry.ts
        with self._lock:
            self._prune_expired(now_ts)
            existing = self._entries.get(key)
            if existing:
                if now_ts - existing.ts < self._dedupe_window_s:
                    return False
                if now_ts - existing.ts < self._update_window_s:
                    return False
                existing.ts = now_ts
                existing.title = entry.title
                existing.detail = entry.detail
                existing.level = entry.level
                existing.source = entry.source
                return True

            self._prune_rate_limit(now_ts)
            if len(self._rate_limit_ts) >= self._rate_limit_per_min:
                return False

            self._rate_limit_ts.append(now_ts)
            self._entries[key] = entry
            self._prune_overflow()
            return True

    def list_entries(self, limit: int = 8) -> List[Dict[str, Optional[str]]]:
        now_ts = int(time.time())
        with self._lock:
            self._prune_expired(now_ts)
            entries = sorted(self._entries.values(), key=lambda e: e.ts, reverse=True)
        return [entry.to_public_dict() for entry in entries[:limit]]


_store: Optional[ChangeTimelineStore] = None
_store_lock = threading.Lock()


def _get_store() -> ChangeTimelineStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = ChangeTimelineStore()
                # Record startup event
                entry = ChangeTimelineEntry(
                    ts=int(time.time()),
                    source="system",
                    title="System Startup",
                    detail="Change tracking active",
                    level="info",
                )
                _store.add_or_update(entry, "system_startup")
    return _store


def record_change(
    source: str,
    title: str,
    detail: Optional[str] = None,
    level: str = "info",
    ts: Optional[float] = None,
    key: Optional[str] = None,
) -> bool:
    now_ts = int(ts or time.time())
    safe_level = level if level in {"info", "notice", "warn"} else "info"
    entry = ChangeTimelineEntry(
        ts=now_ts,
        source=source,
        title=title,
        detail=detail,
        level=safe_level,
    )
    entry_key = key or f"{source}|{title}|{detail or ''}"
    return _get_store().add_or_update(entry, entry_key)


_firewall_blocks_lock = threading.Lock()
_firewall_blocks_abnormal: Optional[bool] = None


def record_firewall_blocks_change(
    is_abnormal: bool, ts: Optional[float] = None
) -> None:
    global _firewall_blocks_abnormal
    with _firewall_blocks_lock:
        if _firewall_blocks_abnormal is None:
            _firewall_blocks_abnormal = is_abnormal
            return
        if _firewall_blocks_abnormal == is_abnormal:
            return
        _firewall_blocks_abnormal = is_abnormal

    if is_abnormal:
        record_change(
            source="firewall",
            title="Firewall block rate elevated",
            detail="Above baseline range",
            level="warn",
            ts=ts,
        )
    else:
        record_change(
            source="firewall",
            title="Firewall block rate normalized",
            detail="Back within baseline range",
            level="notice",
            ts=ts,
        )


def list_changes(limit: int = 8) -> List[Dict[str, Optional[str]]]:
    capped = max(0, min(int(limit), 8))
    return _get_store().list_entries(limit=capped)
