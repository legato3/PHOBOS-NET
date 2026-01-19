"""
Unified Event Timeline Store

A bounded, thread-safe ring buffer for state-changing events across all data sources.
This is observational only - events represent changes that occurred, not ongoing metrics.

Event Sources:
- filterlog: Firewall pass/block decisions from port 514
- firewall: Control log events from port 515 (rule changes, restarts, service events)
- snmp: State changes (interface up/down, device unreachable/recovered)
- system: PHOBOS-NET system events (service start/stop, data source availability)
"""

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class TimelineEvent:
    """A single event in the unified timeline."""
    timestamp: float  # Unix timestamp
    source: str       # filterlog | firewall | snmp | system
    summary: str      # One-line human readable description
    raw: Optional[Dict[str, Any]] = None  # Optional expandable details

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "timestamp_ts": self.timestamp,
            "source": self.source,
            "summary": self.summary,
            "raw": self.raw
        }


class TimelineStore:
    """
    Thread-safe ring buffer for timeline events.

    Events are stored newest-first and automatically evicted when buffer is full.
    Reset on restart is acceptable per requirements.
    """

    def __init__(self, max_events: int = 1000):
        self._buffer: deque[TimelineEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def add_event(
        self,
        source: str,
        summary: str,
        raw: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None
    ) -> None:
        """
        Add an event to the timeline.

        Args:
            source: Event source identifier (filterlog|firewall|snmp|system)
            summary: One-line human readable description
            raw: Optional dict of raw details for expansion
            timestamp: Unix timestamp (defaults to now)
        """
        event = TimelineEvent(
            timestamp=timestamp or time.time(),
            source=source,
            summary=summary,
            raw=raw
        )
        with self._lock:
            self._buffer.append(event)

    def get_events(
        self,
        limit: int = 50,
        since_ts: Optional[float] = None,
        until_ts: Optional[float] = None,
        source_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve events, newest first.

        Args:
            limit: Maximum number of events to return
            since_ts: Only events after this timestamp
            until_ts: Only events before this timestamp
            source_filter: Filter by source type

        Returns:
            List of event dicts, newest first
        """
        results = []
        with self._lock:
            # Iterate newest first (reversed)
            for event in reversed(self._buffer):
                # Apply time filters
                if since_ts is not None and event.timestamp < since_ts:
                    continue
                if until_ts is not None and event.timestamp > until_ts:
                    continue
                # Apply source filter
                if source_filter is not None and event.source != source_filter:
                    continue

                results.append(event.to_dict())
                if len(results) >= limit:
                    break

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the timeline buffer."""
        with self._lock:
            total = len(self._buffer)
            by_source = {}
            oldest_ts = None
            newest_ts = None

            for event in self._buffer:
                by_source[event.source] = by_source.get(event.source, 0) + 1
                if oldest_ts is None or event.timestamp < oldest_ts:
                    oldest_ts = event.timestamp
                if newest_ts is None or event.timestamp > newest_ts:
                    newest_ts = event.timestamp

        return {
            "total": total,
            "by_source": by_source,
            "oldest_ts": oldest_ts,
            "newest_ts": newest_ts
        }

    def clear(self) -> None:
        """Clear all events from the timeline."""
        with self._lock:
            self._buffer.clear()


# Global singleton instance
_timeline_store: Optional[TimelineStore] = None
_timeline_store_lock = threading.Lock()


def get_timeline_store() -> TimelineStore:
    """Get or create the global timeline store singleton."""
    global _timeline_store
    if _timeline_store is None:
        with _timeline_store_lock:
            if _timeline_store is None:
                _timeline_store = TimelineStore(max_events=1000)
    return _timeline_store


def add_timeline_event(
    source: str,
    summary: str,
    raw: Optional[Dict[str, Any]] = None,
    timestamp: Optional[float] = None
) -> None:
    """
    Convenience function to add an event to the global timeline.

    Args:
        source: Event source identifier (filterlog|firewall|snmp|system)
        summary: One-line human readable description
        raw: Optional dict of raw details for expansion
        timestamp: Unix timestamp (defaults to now)
    """
    get_timeline_store().add_event(source, summary, raw, timestamp)
