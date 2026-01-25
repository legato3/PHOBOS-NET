import json
import threading
import time
from collections import deque
from typing import Dict, List, Optional

from app.services.timeline.model import TimelineEvent


class TimelineStore:
    def __init__(
        self,
        max_events: int = 2000,
        dedupe_window_s: int = 60,
        rate_limit_per_min: int = 30,
    ) -> None:
        self._buffer: deque[TimelineEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._dedupe_window_s = dedupe_window_s
        self._rate_limit_per_min = rate_limit_per_min
        self._dedupe_cache: Dict[str, int] = {}
        self._rate_limit_ts: deque[int] = deque()
        self._rate_limit_notice_ts: int = 0
        self._suppressed_dedupe_ts: deque[int] = deque()
        self._suppressed_rate_ts: deque[int] = deque()

    def _event_key(self, event: TimelineEvent) -> str:
        meta_json = "{}"
        if event.meta:
            try:
                meta_json = json.dumps(
                    event.meta, sort_keys=True, separators=(",", ":"), default=str
                )
            except (TypeError, ValueError):
                meta_json = "{}"
        return f"{event.title}|{event.source}|{meta_json}"

    def _prune_dedupe_cache(self, now_ts: int) -> None:
        if len(self._dedupe_cache) < 5000:
            return
        cutoff = now_ts - (self._dedupe_window_s * 2)
        stale_keys = [key for key, ts in self._dedupe_cache.items() if ts < cutoff]
        for key in stale_keys:
            self._dedupe_cache.pop(key, None)

    def _prune_rate_limit(self, now_ts: int) -> None:
        cutoff = now_ts - 60
        while self._rate_limit_ts and self._rate_limit_ts[0] < cutoff:
            self._rate_limit_ts.popleft()

    def _add_event_internal(self, event: TimelineEvent) -> None:
        self._buffer.append(event)

    def add_event(self, event: TimelineEvent) -> bool:
        now_ts = event.ts or int(time.time())
        with self._lock:
            event_key = self._event_key(event)
            last_ts = self._dedupe_cache.get(event_key)
            if last_ts is not None and now_ts - last_ts <= self._dedupe_window_s:
                self._suppressed_dedupe_ts.append(now_ts)
                return False

            self._dedupe_cache[event_key] = now_ts
            self._prune_dedupe_cache(now_ts)

            self._prune_rate_limit(now_ts)
            if len(self._rate_limit_ts) >= self._rate_limit_per_min:
                self._suppressed_rate_ts.append(now_ts)
                if now_ts - self._rate_limit_notice_ts >= 60:
                    self._rate_limit_notice_ts = now_ts
                    notice = TimelineEvent(
                        ts=now_ts,
                        type="rate_limited",
                        severity="notice",
                        title="Event stream busy (rate limited)",
                        detail=None,
                        source="system",
                        meta={},
                    )
                    self._add_event_internal(notice)
                return False

            self._rate_limit_ts.append(now_ts)
            self._add_event_internal(event)
            try:
                from app.services.events.normalize import normalize_timeline_event
                from app.services.events.store import insert_activity_event

                normalized = normalize_timeline_event(event.to_dict())
                if normalized:
                    insert_activity_event(normalized)
            except Exception:
                pass
            return True

    def list_events(
        self, range_s: int, limit: int, types: Optional[List[str]] = None
    ) -> List[Dict[str, object]]:
        now_ts = int(time.time())
        cutoff = now_ts - max(0, int(range_s))
        results: List[Dict[str, object]] = []
        with self._lock:
            for event in reversed(self._buffer):
                if event.ts < cutoff:
                    continue
                if types and (event.source not in types and event.type not in types):
                    continue
                results.append(event.to_dict())
                if len(results) >= limit:
                    break
        return results

    def suppression_stats(self, range_s: int) -> Dict[str, object]:
        now_ts = int(time.time())
        cutoff = now_ts - max(0, int(range_s))
        with self._lock:
            self._suppressed_dedupe_ts = deque(
                ts for ts in self._suppressed_dedupe_ts if ts >= cutoff
            )
            self._suppressed_rate_ts = deque(
                ts for ts in self._suppressed_rate_ts if ts >= cutoff
            )
            dedupe_last = (
                self._suppressed_dedupe_ts[-1] if self._suppressed_dedupe_ts else None
            )
            rate_last = (
                self._suppressed_rate_ts[-1] if self._suppressed_rate_ts else None
            )
            return {
                "dedupe": {
                    "count": len(self._suppressed_dedupe_ts),
                    "last_ts": dedupe_last,
                },
                "rate_limited": {
                    "count": len(self._suppressed_rate_ts),
                    "last_ts": rate_last,
                },
            }

    def list_events_between(
        self, start_ts: int, end_ts: int, source: Optional[str] = None, limit: int = 10
    ) -> List[Dict[str, object]]:
        results: List[Dict[str, object]] = []
        with self._lock:
            for event in reversed(self._buffer):
                if event.ts < start_ts or event.ts > end_ts:
                    continue
                if source and event.source != source:
                    continue
                results.append(event.to_dict())
                if len(results) >= limit:
                    break
        return results

    def summary(self, range_s: int) -> Dict[str, object]:
        now_ts = int(time.time())
        cutoff = now_ts - max(0, int(range_s))
        counts: Dict[str, int] = {}
        last_event_ts: Optional[int] = None
        with self._lock:
            for event in self._buffer:
                if event.ts < cutoff:
                    continue
                counts[event.type] = counts.get(event.type, 0) + 1
                if last_event_ts is None or event.ts > last_event_ts:
                    last_event_ts = event.ts
        return {"counts": counts, "last_event_ts": last_event_ts}


_timeline_store: Optional[TimelineStore] = None
_timeline_store_lock = threading.Lock()


def get_timeline_store() -> TimelineStore:
    global _timeline_store
    if _timeline_store is None:
        with _timeline_store_lock:
            if _timeline_store is None:
                _timeline_store = TimelineStore()
    return _timeline_store
