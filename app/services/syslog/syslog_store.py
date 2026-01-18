"""
Dedicated in-memory store for port 515 syslog events.
Separate from firewall_store to avoid mixing filterlog with generic syslog.
"""
import threading
from collections import deque
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class SyslogEvent:
    """A generic syslog event from port 515."""
    timestamp: datetime
    program: str
    message: str
    facility: Optional[str] = None
    severity: Optional[str] = None
    hostname: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "timestamp_ts": self.timestamp.timestamp(),
            "program": self.program,
            "message": self.message,
            "facility": self.facility,
            "severity": self.severity,
            "hostname": self.hostname
        }


class SyslogStore:
    """
    In-memory ring buffer for generic syslog events (port 515).

    SCOPE:
    - Store generic syslog events
    - Retrieve recent events
    - Basic statistics (by program)

    DOES NOT:
    - Persist to disk
    - Parse filterlog
    - Trigger alerts
    """

    def __init__(self, max_events: int = 5000):
        self._buffer: deque[SyslogEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def add_event(self, event: SyslogEvent) -> None:
        """Add an event to the store."""
        with self._lock:
            self._buffer.append(event)

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events, newest first."""
        results = []
        with self._lock:
            for event in reversed(self._buffer):
                results.append(event.to_dict())
                if len(results) >= limit:
                    break
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about stored events."""
        program_counts: Dict[str, int] = {}
        total = 0

        with self._lock:
            for event in self._buffer:
                total += 1
                program_counts[event.program] = program_counts.get(event.program, 0) + 1

        return {
            "total": total,
            "programs": program_counts
        }

    def clear(self) -> None:
        """Clear all events."""
        with self._lock:
            self._buffer.clear()


# Global instance for port 515 syslog
syslog_store = SyslogStore()
