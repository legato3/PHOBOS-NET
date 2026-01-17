"""Syslog service for processing OPNsense firewall logs."""
import threading
import time
import socket as socket_module
import re
from datetime import datetime
import sqlite3

# Import configuration
from app.config import SYSLOG_BIND, SYSLOG_PORT, FIREWALL_IP, FIREWALL_RETENTION_DAYS, FIREWALL_DB_PATH

# Import state
from app.core.app_state import (
    _shutdown_event,
    _syslog_thread_started,
    _syslog_stats, _syslog_stats_lock,
    _syslog_buffer, _syslog_buffer_lock, _syslog_buffer_size,
    _alert_history, _alert_history_lock,
    add_app_log
)

# Import helpers
from app.db.sqlite import _firewall_db_connect, _firewall_db_init, _firewall_db_lock
from app.services.shared.geoip import lookup_geo
from app.services.shared.helpers import check_disk_space, is_internal
from app.services.security.threats import load_threatlist

# Regex to parse OPNsense filterlog messages
FILTERLOG_PATTERN = re.compile(
    r'filterlog.*?\]\s*'
    r'(?P<rule>\d+)?,'           # Rule number
    r'(?P<subrule>[^,]*),'       # Sub-rule
    r'(?P<anchor>[^,]*),'        # Anchor
    r'(?P<tracker>[^,]*),'       # Tracker ID
    r'(?P<iface>\w+),'           # Interface
    r'(?P<reason>\w+),'          # Reason
    r'(?P<action>\w+),'          # Action (pass/block/reject)
    r'(?P<dir>\w+),'             # Direction (in/out)
    r'(?P<ipver>\d),'            # IP version
    r'[^,]*,'                    # TOS
    r'[^,]*,'                    # ECN
    r'(?P<ttl>\d+)?,'            # TTL
    r'[^,]*,'                    # ID
    r'[^,]*,'                    # Offset
    r'[^,]*,'                    # Flags
    r'(?P<proto_num>\d+)?,'      # Protocol number
    r'(?P<proto>\w+)?,'          # Protocol name
    r'(?P<length>\d+)?,'         # Packet length
    r'(?P<src_ip>[\d\.]+),'      # Source IP
    r'(?P<dst_ip>[\d\.]+),'      # Destination IP
    r'(?P<src_port>\d+)?,'       # Source port
    r'(?P<dst_port>\d+)?'        # Destination port
)


def start_syslog_thread():
    """Start the syslog receiver and maintenance threads."""
    import app.core.app_state as state
    if state._syslog_thread_started:
        return
    state._syslog_thread_started = True
    _firewall_db_init()
    
    # Receiver thread
    t1 = threading.Thread(target=_syslog_receiver_loop, daemon=True)
    t1.start()
    
    # Maintenance thread
    t2 = threading.Thread(target=_syslog_maintenance_loop, daemon=True)
    t2.start()


def _syslog_receiver_loop():
    """UDP syslog receiver loop."""
    sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
    sock.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    
    try:
        sock.bind((SYSLOG_BIND, SYSLOG_PORT))
        msg = f"Syslog receiver started on {SYSLOG_BIND}:{SYSLOG_PORT}"
        print(msg)
        add_app_log(msg, 'INFO')
    except PermissionError:
        msg = f"ERROR: Cannot bind to port {SYSLOG_PORT} - need root or CAP_NET_BIND_SERVICE"
        print(msg)
        add_app_log(msg, 'ERROR')
        return
    except Exception as e:
        msg = f"ERROR: Syslog bind failed: {e}"
        print(msg)
        add_app_log(msg, 'ERROR')
        return
    
    # Set socket timeout so we can check shutdown event
    sock.settimeout(1.0)
    
    while not _shutdown_event.is_set():
        try:
            data, addr = sock.recvfrom(4096)
            
            # Security: Only accept from firewall IP
            if addr[0] != FIREWALL_IP and FIREWALL_IP != "0.0.0.0":
                continue
            
            with _syslog_stats_lock:
                _syslog_stats["received"] += 1
            line = data.decode('utf-8', errors='ignore')
            
            # Only process filterlog messages
            if 'filterlog' not in line:
                continue
            
            parsed = _parse_filterlog(line)
            if parsed:
                with _syslog_stats_lock:
                    _syslog_stats["parsed"] += 1
                    _syslog_stats["last_log"] = time.time()
                _insert_fw_log(parsed, line)
            else:
                with _syslog_stats_lock:
                    _syslog_stats["errors"] += 1
        except socket_module.timeout:
            continue  # Normal timeout, check shutdown and continue
        except Exception:
            with _syslog_stats_lock:
                _syslog_stats["errors"] += 1


def _syslog_maintenance_loop():
    """Periodic maintenance for firewall logs."""
    while not _shutdown_event.is_set():
        try:
            _cleanup_old_fw_logs()
            
            # Check disk space and log warning if high
            disk_info = check_disk_space('/var/cache/nfdump')
            if disk_info['percent_used'] > 90:
                print(f"WARNING: NetFlow disk usage at {disk_info['percent_used']:.1f}% ({disk_info['used_gb']:.1f}GB / {disk_info['total_gb']:.1f}GB)")
            elif disk_info['percent_used'] > 75:
                print(f"INFO: NetFlow disk usage at {disk_info['percent_used']:.1f}% ({disk_info['used_gb']:.1f}GB / {disk_info['total_gb']:.1f}GB)")
        except Exception as e:
            print(f"Maintenance error: {e}")
        _shutdown_event.wait(timeout=3600)  # Run every hour


def _parse_filterlog(line: str) -> dict:
    """Parse OPNsense filterlog syslog message."""
    match = FILTERLOG_PATTERN.search(line)
    if not match:
        return None
    
    return {
        'rule_id': match.group('rule'),
        'interface': match.group('iface'),
        'action': match.group('action'),
        'direction': match.group('dir'),
        'proto': match.group('proto'),
        'length': int(match.group('length') or 0),
        'src_ip': match.group('src_ip'),
        'dst_ip': match.group('dst_ip'),
        'src_port': int(match.group('src_port') or 0),
        'dst_port': int(match.group('dst_port') or 0),
    }


def _insert_fw_log(parsed: dict, raw_log: str):
    """Insert parsed firewall log into database with enrichment (buffered batch insert)."""
    now = time.time()
    now_iso = datetime.fromtimestamp(now).isoformat()
    
    # Enrich with GeoIP
    src_ip = parsed['src_ip']
    country_iso = None
    country_name = None
    if not is_internal(src_ip):
        geo = lookup_geo(src_ip)
        if geo:
            country_iso = geo.get('country_iso')
            country_name = geo.get('country')
    
    # Check if threat
    threat_set = load_threatlist()
    is_threat = 1 if src_ip in threat_set else 0
    
    # Inject important blocks as alerts
    if parsed['action'] == 'block':
        dst_port = parsed.get('dst_port', 0)
        
        # Define high-value ports that warrant alerts
        HIGH_VALUE_PORTS = {22, 23, 445, 3389, 5900, 1433, 3306, 5432, 27017}
        
        # Create alert for: threat IPs, sensitive ports, or external sources
        should_alert = False
        severity = 'low'
        alert_type = 'firewall_block'
        msg = f"Blocked {src_ip}"
        mitre = ''
        
        if is_threat:
            should_alert = True
            severity = 'high'
            alert_type = 'threat_blocked'
            msg = f"🔥 Threat IP blocked: {src_ip}"
            mitre = 'T1595'  # Active Scanning - threat IP attempting access
            if country_name:
                msg += f" ({country_name})"
        elif dst_port in HIGH_VALUE_PORTS:
            should_alert = True
            severity = 'medium'
            alert_type = 'sensitive_port_blocked'
            port_names = {22: 'SSH', 23: 'Telnet', 445: 'SMB', 3389: 'RDP',
                         5900: 'VNC', 1433: 'MSSQL', 3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB'}
            service = port_names.get(dst_port, str(dst_port))
            msg = f"🛡️ {service} probe blocked: {src_ip}:{dst_port}"
            mitre = 'T1046'  # Network Service Discovery
        
        if should_alert:
            alert = {
                'type': alert_type,
                'severity': severity,
                'ip': src_ip,
                'port': dst_port,
                'msg': msg,
                'ts': now,
                'source': 'firewall',
                'mitre': mitre
            }
            # Use escalation and deduplication from threats module
            from app.services.security.threats import _should_escalate_anomaly, _upsert_alert_to_history
            if _should_escalate_anomaly(alert):
                _upsert_alert_to_history(alert)
    
    # Add to buffer for batch insert
    log_tuple = (now, now_iso, parsed['action'], parsed['direction'], parsed['interface'],
                 parsed['src_ip'], parsed['src_port'], parsed['dst_ip'], parsed['dst_port'],
                 parsed['proto'], parsed['rule_id'], parsed['length'], country_iso, is_threat, raw_log[:500])
    
    flush_needed = False
    with _syslog_buffer_lock:
        _syslog_buffer.append(log_tuple)
        if len(_syslog_buffer) >= _syslog_buffer_size:
            flush_needed = True
    
    # Flush if buffer is full (periodic flush handled by maintenance thread)
    if flush_needed:
        _flush_syslog_buffer()


def _flush_syslog_buffer():
    """Flush buffered syslog entries to database in batch."""
    logs_to_insert = []
    with _syslog_buffer_lock:
        if not _syslog_buffer:
            return
        logs_to_insert = _syslog_buffer[:]
        _syslog_buffer.clear()
    
    if not logs_to_insert:
        return
    
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            conn.executemany("""
                INSERT INTO fw_logs (timestamp, timestamp_iso, action, direction, interface,
                    src_ip, src_port, dst_ip, dst_port, proto, rule_id, length, country_iso, is_threat, raw_log)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, logs_to_insert)
            conn.commit()
        except Exception as e:
            print(f"Error flushing syslog buffer: {e}")
        finally:
            conn.close()


def _cleanup_old_fw_logs():
    """Remove firewall logs older than retention period."""
    cutoff = time.time() - (FIREWALL_RETENTION_DAYS * 86400)
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            conn.execute("DELETE FROM fw_logs WHERE timestamp < ?", (cutoff,))
            conn.execute("VACUUM")
            conn.commit()
        finally:
            conn.close()
