"""
Isolated Firewall Syslog Listener (non-filterlog events).

This listener is SEPARATE from the existing filterlog syslog listener (port 514).
It receives firewall events on a dedicated port (default 515/UDP) and routes them
ONLY to the firewall parser and in-memory store.

SCOPE:
- UDP syslog reception on dedicated port
- Firewall event parsing via FirewallParser
- In-memory storage via firewall_store
- Dedicated ingestion metrics

DOES NOT:
- Process filterlog events (those go to port 514)
- Write to SQLite
- Trigger alerts
- Perform correlation or heuristics
"""
import threading
import socket as socket_module
import time

# Configuration
from app.config import FIREWALL_SYSLOG_PORT, FIREWALL_SYSLOG_BIND, FIREWALL_IP

# State management
from app.core.app_state import _shutdown_event, add_app_log

# Firewall pipeline components
from app.services.firewall.parser import FirewallParser
from app.services.firewall.store import firewall_store

# Dedicated ingestion counter for this listener
_firewall_syslog_stats = {
    "received": 0,
    "parsed": 0,
    "errors": 0,
    "last_log": None
}
_firewall_syslog_stats_lock = threading.Lock()

# Thread started flag
_firewall_syslog_thread_started = False


def start_firewall_syslog_thread():
    """Start the isolated firewall syslog listener thread."""
    global _firewall_syslog_thread_started
    
    if _firewall_syslog_thread_started:
        return
    _firewall_syslog_thread_started = True
    
    t = threading.Thread(target=_firewall_syslog_receiver_loop, daemon=True)
    t.start()


def _firewall_syslog_receiver_loop():
    """UDP syslog receiver loop for firewall (non-filterlog) events."""
    sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    sock.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    
    try:
        sock.bind((FIREWALL_SYSLOG_BIND, FIREWALL_SYSLOG_PORT))
        msg = f"[FIREWALL SYSLOG] Listener started on {FIREWALL_SYSLOG_BIND}:{FIREWALL_SYSLOG_PORT}"
        print(msg)
        add_app_log(msg, 'INFO')
    except PermissionError:
        msg = f"[FIREWALL SYSLOG] ERROR: Cannot bind to port {FIREWALL_SYSLOG_PORT} - need root or CAP_NET_BIND_SERVICE"
        print(msg)
        add_app_log(msg, 'ERROR')
        return
    except Exception as e:
        msg = f"[FIREWALL SYSLOG] ERROR: Bind failed: {e}"
        print(msg)
        add_app_log(msg, 'ERROR')
        return
    
    # Set socket timeout so we can check shutdown event
    sock.settimeout(1.0)
    
    # Instantiate parser once for reuse
    fw_parser = FirewallParser()
    
    while not _shutdown_event.is_set():
        try:
            data, addr = sock.recvfrom(4096)
            
            # Security: Only accept from firewall IP (unless configured for any)
            if addr[0] != FIREWALL_IP and FIREWALL_IP != "0.0.0.0":
                continue
            
            # Track received
            with _firewall_syslog_stats_lock:
                _firewall_syslog_stats["received"] += 1
            
            line = data.decode('utf-8', errors='ignore')
            
            # [FIREWALL SYSLOG] Debug: Message received
            print(f"[FIREWALL SYSLOG] Message received from {addr[0]}")
            
            # Parse using firewall parser ONLY
            # No conditional guessing - route ALL messages to firewall parser
            try:
                fw_event = fw_parser.parse(line)
                
                if fw_event:
                    # Store in firewall in-memory store ONLY
                    firewall_store.add_event(fw_event)
                    
                    with _firewall_syslog_stats_lock:
                        _firewall_syslog_stats["parsed"] += 1
                        _firewall_syslog_stats["last_log"] = time.time()
                    
                    # Track ingestion rate for Filterlog (515)
                    from app.services.shared.ingestion_metrics import ingestion_tracker
                    ingestion_tracker.track_firewall(1)
                    
                    # [FIREWALL SYSLOG] Debug: Parse success
                    print(f"[FIREWALL SYSLOG] Parse success: {fw_event.action} {fw_event.src_ip}->{fw_event.dst_ip}")
                else:
                    # Parser returned None (failed to parse)
                    with _firewall_syslog_stats_lock:
                        _firewall_syslog_stats["errors"] += 1
                    
                    # [FIREWALL SYSLOG] Debug: Parse failure
                    print(f"[FIREWALL SYSLOG] Parse failure: Could not parse message")
                    
            except Exception as e:
                # Parsing exception - log and drop safely
                with _firewall_syslog_stats_lock:
                    _firewall_syslog_stats["errors"] += 1
                
                # [FIREWALL SYSLOG] Debug: Parse failure with exception
                print(f"[FIREWALL SYSLOG] Parse failure: {e}")
                
        except socket_module.timeout:
            continue  # Normal timeout, check shutdown and continue
        except Exception as e:
            # Unexpected error - log but keep listener running
            print(f"[FIREWALL SYSLOG] Receiver error: {e}")
            continue


def get_firewall_syslog_stats():
    """
    Get ingestion statistics for the firewall syslog listener.
    Independent from filterlog stats.
    """
    with _firewall_syslog_stats_lock:
        return {
            "received": _firewall_syslog_stats["received"],
            "parsed": _firewall_syslog_stats["parsed"],
            "errors": _firewall_syslog_stats["errors"],
            "last_log": _firewall_syslog_stats["last_log"]
        }
