"""
OPNsense Syslog Listener (Port 515).

Receives generic syslog messages from OPNsense on a dedicated port.
Stores events in syslog_store (separate from filterlog on port 514).

SCOPE:
- UDP syslog reception on port 515
- Parse program name and message from syslog
- In-memory storage via syslog_store
- Ingestion metrics

DOES NOT:
- Parse filterlog (that's port 514)
- Write to SQLite
- Trigger alerts
"""
import threading
import socket as socket_module
import time
import re
from datetime import datetime

from app.config import FIREWALL_SYSLOG_PORT, FIREWALL_SYSLOG_BIND, FIREWALL_IP
from app.core.app_state import _shutdown_event, add_app_log
from app.services.syslog.syslog_store import syslog_store, SyslogEvent

# Ingestion counter
_syslog_515_stats = {
    "received": 0,
    "parsed": 0,
    "errors": 0,
    "last_log": None
}
_syslog_515_stats_lock = threading.Lock()

# Thread started flag
_firewall_syslog_thread_started = False

# Regex patterns for parsing syslog
# RFC5424 timestamp: 2026-01-18T19:15:00+01:00
RFC5424_TS = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)')
# Program name with optional PID: configd[1234]: or openvpn:
PROGRAM_PATTERN = re.compile(r'\s([a-zA-Z][a-zA-Z0-9_-]*)(?:\[\d+\])?:\s*(.*)$')
# Hostname pattern (after timestamp)
HOSTNAME_PATTERN = re.compile(r'^\s*\S+\s+\S+\s+(\S+)\s+')


def start_firewall_syslog_thread():
    """Start the syslog listener thread for port 515."""
    global _firewall_syslog_thread_started

    if _firewall_syslog_thread_started:
        return
    _firewall_syslog_thread_started = True

    t = threading.Thread(target=_syslog_receiver_loop, daemon=True)
    t.start()


def _parse_syslog(raw: str) -> SyslogEvent:
    """
    Parse a raw syslog line into a SyslogEvent.
    Extracts timestamp, program name, and message.
    """
    timestamp = datetime.now()
    program = "unknown"
    message = raw.strip()
    hostname = None

    # Try to extract RFC5424 timestamp
    ts_match = RFC5424_TS.search(raw)
    if ts_match:
        try:
            ts_str = ts_match.group(1)
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+00:00'
            timestamp = datetime.fromisoformat(ts_str)
        except (ValueError, IndexError):
            pass

    # Try to extract hostname
    host_match = HOSTNAME_PATTERN.match(raw)
    if host_match:
        hostname = host_match.group(1)

    # Try to extract program name and message
    prog_match = PROGRAM_PATTERN.search(raw)
    if prog_match:
        program = prog_match.group(1)
        message = prog_match.group(2).strip()

    return SyslogEvent(
        timestamp=timestamp,
        program=program,
        message=message[:1000],  # Limit message length
        hostname=hostname
    )


def _syslog_receiver_loop():
    """UDP syslog receiver loop for port 515."""
    sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    sock.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)

    try:
        sock.bind((FIREWALL_SYSLOG_BIND, FIREWALL_SYSLOG_PORT))
        msg = f"[SYSLOG 515] Listener started on {FIREWALL_SYSLOG_BIND}:{FIREWALL_SYSLOG_PORT}"
        print(msg)
        add_app_log(msg, 'INFO')
    except PermissionError:
        msg = f"[SYSLOG 515] ERROR: Cannot bind to port {FIREWALL_SYSLOG_PORT}"
        print(msg)
        add_app_log(msg, 'ERROR')
        return
    except Exception as e:
        msg = f"[SYSLOG 515] ERROR: Bind failed: {e}"
        print(msg)
        add_app_log(msg, 'ERROR')
        return

    sock.settimeout(1.0)

    while not _shutdown_event.is_set():
        try:
            data, addr = sock.recvfrom(8192)

            # Security: Only accept from configured IP
            if addr[0] != FIREWALL_IP and FIREWALL_IP != "0.0.0.0":
                continue

            with _syslog_515_stats_lock:
                _syslog_515_stats["received"] += 1

            raw = data.decode('utf-8', errors='ignore')

            try:
                event = _parse_syslog(raw)
                syslog_store.add_event(event)

                with _syslog_515_stats_lock:
                    _syslog_515_stats["parsed"] += 1
                    _syslog_515_stats["last_log"] = time.time()

                # Track ingestion rate
                from app.services.shared.ingestion_metrics import ingestion_tracker
                ingestion_tracker.track_firewall(1)

                print(f"[SYSLOG 515] {event.program}: {event.message[:80]}...")

            except Exception as e:
                with _syslog_515_stats_lock:
                    _syslog_515_stats["errors"] += 1
                print(f"[SYSLOG 515] Parse error: {e}")

        except socket_module.timeout:
            continue
        except Exception as e:
            print(f"[SYSLOG 515] Receiver error: {e}")
            continue


def get_firewall_syslog_stats():
    """Get ingestion statistics for port 515 listener."""
    with _syslog_515_stats_lock:
        return {
            "received": _syslog_515_stats["received"],
            "parsed": _syslog_515_stats["parsed"],
            "errors": _syslog_515_stats["errors"],
            "last_log": _syslog_515_stats["last_log"]
        }
