import threading
from collections import deque, Counter
from datetime import datetime
from typing import List, Dict, Optional, Any
from app.services.firewall.parser import FirewallEvent
from app.services.timeline.emitters import record_firewall_stream_activity

# Configurable max events for the ring buffer
# 10,000 events * ~200 bytes = ~2MB memory footprint
MAX_EVENTS = 10000


class FirewallStore:
    """
    In-memory storage for normalized FirewallEvents.

    SCOPE:
    - Ring buffer storage (deque)
    - Basic retrieval
    - Descriptive counting

    DOES NOT:
    - Persist to disk/DB
    - Correlate events
    - Trigger alerts
    - Assess risk
    """

    def __init__(self, max_events: int = MAX_EVENTS):
        self._buffer: deque[FirewallEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def add_event(self, event: FirewallEvent) -> None:
        """Add a normalized event to the store in a thread-safe manner."""
        with self._lock:
            self._buffer.append(event)
        try:
            record_firewall_stream_activity(ts=event.timestamp.timestamp())
        except Exception:
            pass

    def get_events(
        self, limit: int = 100, since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve recent events, optionally filtered by time.
        Returns serialized dicts for easier consumption.
        """
        results = []
        with self._lock:
            # Iterate in reverse to get newest first
            for event in reversed(self._buffer):
                if since and event.timestamp < since:
                    break
                results.append(event.to_dict())
                if len(results) >= limit:
                    break
        return results

    def get_counts(self, since: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Calculate descriptive statistics for the requested time window.
        Returns:
            - total_events
            - by_action (pass, block, reject)
            - by_interface
            - by_direction
        """
        stats = {
            "total": 0,
            "actions": Counter(),
            "interfaces": Counter(),
            "directions": Counter(),
        }

        with self._lock:
            # We iterate backwards. If 'since' is provided, we stop when we hit older events.
            # If 'since' is None, we process the whole buffer.
            for event in reversed(self._buffer):
                if since and event.timestamp < since:
                    break

                stats["total"] += 1
                if event.action:
                    stats["actions"][event.action] += 1
                if event.interface:
                    stats["interfaces"][event.interface] += 1
                if event.direction:
                    stats["directions"][event.direction] += 1

        return {
            "total": stats["total"],
            "by_action": dict(stats["actions"]),
            "by_interface": dict(stats["interfaces"]),
            "by_direction": dict(stats["directions"]),
        }


# Global instance for application usage
firewall_store = FirewallStore()
