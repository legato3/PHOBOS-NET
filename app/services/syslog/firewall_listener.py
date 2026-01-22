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
from app.services.shared.timeline import add_timeline_event

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
_firewall_syslog_thread = None
_syslog_515_stop_event = threading.Event()
_syslog_515_socket = None

# Regex patterns for parsing syslog
# RFC5424 timestamp: 2026-01-18T19:15:00+01:00
RFC5424_TS = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)')
# Program name with optional PID: configd[1234]: or openvpn:
PROGRAM_PATTERN = re.compile(r'\s([a-zA-Z][a-zA-Z0-9_-]*)(?:\[\d+\])?:\s*(.*)$')
# Hostname pattern (after timestamp)
HOSTNAME_PATTERN = re.compile(r'^\s*\S+\s+\S+\s+(\S+)\s+')


def start_firewall_syslog_thread():
    """Start the syslog listener thread for port 515."""
    global _firewall_syslog_thread_started, _firewall_syslog_thread

    if _firewall_syslog_thread_started:
        return
    _firewall_syslog_thread_started = True

    _firewall_syslog_thread = threading.Thread(target=_syslog_receiver_loop, daemon=True)
    _firewall_syslog_thread.start()


def restart_firewall_syslog_thread():
    """Restart the syslog listener thread for port 515."""
    if _shutdown_event.is_set():
        return {"status": "error", "message": "Shutdown in progress"}

    _syslog_515_stop_event.set()
    _close_syslog_515_socket()
    _join_firewall_syslog_thread(timeout=2)
    _syslog_515_stop_event.clear()

    global _firewall_syslog_thread_started
    _firewall_syslog_thread_started = False
    start_firewall_syslog_thread()
    add_app_log("Syslog listener restarted (port 515)", "INFO")
    return {"status": "ok"}


def _close_syslog_515_socket():
    """Close the active syslog 515 socket if present."""
    global _syslog_515_socket
    if _syslog_515_socket:
        try:
            _syslog_515_socket.close()
        except Exception:
            pass
        _syslog_515_socket = None


def _join_firewall_syslog_thread(timeout=2):
    """Join firewall syslog thread to avoid duplicate listeners."""
    global _firewall_syslog_thread
    if _firewall_syslog_thread and _firewall_syslog_thread.is_alive():
        _firewall_syslog_thread.join(timeout=timeout)
    _firewall_syslog_thread = None


def _parse_syslog(raw: str) -> SyslogEvent:
    """
    Parse a raw syslog line into a SyslogEvent.
    Supports both RFC 3164 and RFC 5424 formats.
    """
    timestamp = datetime.now()
    program = "unknown"
    message = raw.strip()
    hostname = None

    # RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    # Example: <38>1 2026-01-18T19:36:05+01:00 CHRIS-OPN.phobos-cc.be configd.py 31911 - [meta sequenceId="257"] message
    rfc5424_match = re.match(r'<\d+>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)', raw)
    if rfc5424_match:
        # RFC 5424 format detected
        version, ts_str, hostname, app_name, procid, msgid, rest = rfc5424_match.groups()
        
        # Parse timestamp
        try:
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+00:00'
            timestamp = datetime.fromisoformat(ts_str)
        except (ValueError, IndexError):
            pass
        
        # Extract program name
        if app_name and app_name != '-':
            program = app_name
        
        # Extract message (everything after structured data or msgid)
        message = rest.strip()
    else:
        # Fall back to RFC 3164 parsing
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


# Keywords indicating state-changing events worth tracking in timeline
_STATE_CHANGE_KEYWORDS = [
    ('start', 'Service started'),
    ('stop', 'Service stopped'),
    ('restart', 'Service restarted'),
    ('reload', 'Configuration reloaded'),
    ('rule', 'Rule change'),
    ('config', 'Configuration change'),
    ('error', 'Error'),
    ('fail', 'Failure'),
    ('timeout', 'Timeout'),
    ('connect', 'Connection event'),
    ('disconnect', 'Disconnection event'),
    ('up', 'Interface up'),
    ('down', 'Interface down'),
    ('sync', 'Sync event'),
]


def _emit_timeline_event_if_significant(event: SyslogEvent) -> None:
    """
    Check if a syslog event represents a state change and emit to timeline.

    Only emits events that indicate actual state changes:
    - Service starts/stops/restarts
    - Configuration reloads
    - Errors and failures
    - Connection/disconnection events
    """
    message_lower = event.message.lower()
    program = event.program or 'unknown'

    # Check for state-changing keywords
    for keyword, description in _STATE_CHANGE_KEYWORDS:
        if keyword in message_lower:
            # Build summary
            summary = f"{program}: {event.message[:80]}"
            if len(event.message) > 80:
                summary += "..."

            add_timeline_event(
                source='firewall',
                summary=summary,
                raw={
                    'program': program,
                    'message': event.message,
                    'hostname': event.hostname,
                    'facility': event.facility,
                    'severity': event.severity
                },
                timestamp=event.timestamp.timestamp()
            )
            break  # Only emit one event per message


def _syslog_receiver_loop():
    """UDP syslog receiver loop for port 515."""
    global _syslog_515_socket
    sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    sock.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    _syslog_515_socket = sock

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

    while not _shutdown_event.is_set() and not _syslog_515_stop_event.is_set():
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

                # Check for state-changing events to add to unified timeline
                _emit_timeline_event_if_significant(event)

            except Exception as e:
                with _syslog_515_stats_lock:
                    _syslog_515_stats["errors"] += 1
                print(f"[SYSLOG 515] Parse error: {e}")

        except socket_module.timeout:
            continue
        except Exception as e:
            print(f"[SYSLOG 515] Receiver error: {e}")
            continue
    _close_syslog_515_socket()


def get_firewall_syslog_stats():
    """Get ingestion statistics for port 515 listener."""
    with _syslog_515_stats_lock:
        return {
            "received": _syslog_515_stats["received"],
            "parsed": _syslog_515_stats["parsed"],
            "errors": _syslog_515_stats["errors"],
            "last_log": _syslog_515_stats["last_log"]
        }
