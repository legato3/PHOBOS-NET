import threading
import time
from collections import deque

class IngestionTracker:
    """
    Tracks event ingestion rates (Events Per Second) for data sources.
    Scope: Descriptive metrics ONLY. No alerts.
    Implementation: Sliding window of counts over ~60 seconds.
    """
    
    def __init__(self, window_seconds=60):
        self.window_seconds = window_seconds
        # Stores (timestamp, count) tuples
        self._syslog_history = deque()
        self._firewall_history = deque()
        self._netflow_history = deque()
        self._lock = threading.Lock()
        
    def _prune_and_add(self, queue: deque, count=1):
        """Add event count and prune old entries."""
        now = time.time()
        cutoff = now - self.window_seconds
        
        # Add current event(s)
        if count > 0:
            queue.append((now, count))
            
        # Prune old
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def track_syslog(self, count=1):
        with self._lock:
            self._prune_and_add(self._syslog_history, count)
            
    def track_firewall(self, count=1):
        with self._lock:
            self._prune_and_add(self._firewall_history, count)
            
    def track_netflow(self, count=1):
        with self._lock:
            self._prune_and_add(self._netflow_history, count)
            
    def _calculate_rate(self, queue: deque) -> float:
        """Calculate EPS over the actual time span in the buffer."""
        if not queue:
            return 0.0
            
        now = time.time()
        # Prune first locally to ensure accuracy
        cutoff = now - self.window_seconds
        
        # Sum counts within window
        total_events = sum(count for ts, count in queue if ts >= cutoff)
        
        # If no events in window
        if total_events == 0:
            return 0.0
            
        # Calculate rate: total / window
        # We use fixed window size for stability vs actual span which can be jumpy
        return round(total_events / self.window_seconds, 2)

    def get_rates(self):
        with self._lock:
            # Prune all before returning
            self._prune_and_add(self._syslog_history, 0)
            self._prune_and_add(self._firewall_history, 0)
            self._prune_and_add(self._netflow_history, 0)
            
            return {
                "syslog_eps": self._calculate_rate(self._syslog_history),
                "firewall_eps": self._calculate_rate(self._firewall_history),
                "netflow_eps": self._calculate_rate(self._netflow_history)
            }

# Global instance
ingestion_tracker = IngestionTracker()
