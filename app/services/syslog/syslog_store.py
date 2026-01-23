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
    Persistent store for generic syslog events (port 515) using SQLite.
    
    Now supports multi-worker access by using the shared firewall.db (syslog_events table).
    """

    def __init__(self, max_events: int = 5000):
        # We don't cache locally anymore to ensure multi-process consistency
        pass

    def add_event(self, event: SyslogEvent) -> None:
        """Add an event to the store (persistent DB)."""
        from app.db.sqlite import _firewall_db_connect, _firewall_db_lock, _firewall_db_init
        
        # Ensure DB is ready
        _firewall_db_init()
        
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                conn.execute("""
                    INSERT INTO syslog_events (timestamp, timestamp_iso, program, message, hostname, facility, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp.timestamp(),
                    event.timestamp.isoformat(),
                    event.program,
                    event.message,
                    event.hostname,
                    event.facility,
                    event.severity
                ))
                conn.commit()
            except Exception as e:
                print(f"Error inserting syslog event: {e}")
            finally:
                conn.close()

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events, newest first."""
        from app.db.sqlite import _firewall_db_connect, _firewall_db_lock, _firewall_db_init
        
        # Ensure DB is ready
        _firewall_db_init()
        results = []
        
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                cur = conn.execute("""
                    SELECT timestamp, timestamp_iso, program, message, hostname, facility, severity
                    FROM syslog_events
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
                
                for row in cur.fetchall():
                    results.append({
                        "timestamp": row[1], # iso
                        "timestamp_ts": row[0], # ts
                        "program": row[2],
                        "message": row[3],
                        "hostname": row[4],
                        "facility": row[5],
                        "severity": row[6]
                    })
            except Exception as e:
                print(f"Error fetching syslog events: {e}")
            finally:
                conn.close()
                
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about stored events (last 24h)."""
        from app.db.sqlite import _firewall_db_connect, _firewall_db_lock, _firewall_db_init
        
        # Ensure DB is ready
        _firewall_db_init()
        
        program_counts: Dict[str, int] = {}
        total = 0
        cutoff = datetime.now().timestamp() - 86400  # Last 24 hours only
        
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                cur = conn.execute("SELECT COUNT(*) FROM syslog_events WHERE timestamp > ?", (cutoff,))
                total = cur.fetchone()[0] or 0
                
                cur = conn.execute("""
                    SELECT program, COUNT(*) 
                    FROM syslog_events 
                    WHERE timestamp > ?
                    GROUP BY program
                """, (cutoff,))
                
                for row in cur.fetchall():
                    program_counts[row[0]] = row[1]
            except Exception as e:
                print(f"Error fetching syslog stats: {e}")
            finally:
                conn.close()

        return {
            "total": total,
            "programs": program_counts
        }

    def clear(self) -> None:
        """Clear all events."""
        from app.db.sqlite import _firewall_db_connect, _firewall_db_lock
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                conn.execute("DELETE FROM syslog_events")
                conn.execute("VACUUM")
                conn.commit()
            finally:
                conn.close()


# Global instance for port 515 syslog
syslog_store = SyslogStore()
