"""Threat intelligence service for PHOBOS-NET application."""
import time
import os
import json
import requests
import threading
import queue
import concurrent.futures
from datetime import datetime, timezone
from collections import defaultdict, deque
from app.core.app_state import add_app_log, update_dependency_health
from app.services.shared.observability import instrument_service
from app.config import (
    WATCHLIST_PATH, THREATLIST_PATH, THREAT_FEEDS_PATH, THREAT_FEED_URL_PATH, MITRE_MAPPINGS,
    SECURITY_WEBHOOK_PATH, WEBHOOK_PATH, PORTS, SUSPICIOUS_PORTS, BRUTE_FORCE_PORTS,
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW, EXFIL_THRESHOLD_MB, EXFIL_RATIO_THRESHOLD,
    DNS_QUERY_THRESHOLD, BUSINESS_HOURS_START, BUSINESS_HOURS_END, OFF_HOURS_THRESHOLD_MB,
    VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
)
from app.services.shared.helpers import is_internal, fmt_bytes
from app.services.shared.geoip import lookup_geo
from app.services.shared.config_helpers import load_notify_cfg

# Global state for threat intelligence
_threat_status = {'last_attempt': 0, 'last_ok': 0, 'size': 0, 'status': 'unknown', 'error': None}
_threat_ip_to_feed = {}  # Maps IP -> {category, feed_name}
_threat_timeline = {}  # Maps IP -> {first_seen, last_seen, hit_count}
_feed_status = {}  # Per-feed health tracking
_feed_data_lock = threading.Lock()  # Protects _threat_ip_to_feed and _feed_status
_watchlist_cache = {"data": set(), "mtime": 0, "last_check": 0}
_threat_cache = {"data": set(), "mtime": 0, "last_check": 0}  # Cache for threat list file

FILE_CHECK_INTERVAL = 5  # Check file mtime every 5 seconds

# Webhook queue for non-blocking security alerts
_webhook_queue = queue.Queue()
_webhook_thread = None
_webhook_config_cache = {"data": None, "mtime": 0, "last_check": 0}

# Detection state
# ALERTS: Rare, actionable security events requiring human attention
# DEFINITION:
# - Explicitly created by alert logic
# - Requires human action
# - Represents a persistent condition
# - Deduplicated by condition key
#
# An ALERT is NOT:
# - A timeline event
# - An anomaly
# - A heuristic match
# - A single firewall decision
# - A flow count or volume spike
_alert_history = deque(maxlen=1000)  # Security alerts only (24h+ retention)
_alert_history_lock = threading.Lock()

# SIGNALS: High-volume, informational network health indicators (NOT alerts)
# Examples: TCP reset rates, SYN-only flow percentages, ICMP traffic levels
# These do NOT count toward active_alerts and do NOT affect health state
_signal_history = deque(maxlen=500)  # Network health signals (informational only)
_signal_history_lock = threading.Lock()

_alert_sent_ts = 0  # Timestamp of last notification sent (rate limiting)
_port_scan_tracker = {}  # {ip: {ports: set(), first_seen: ts}}
_seen_external = {"countries": set(), "asns": set()}  # First-seen tracking
_protocol_baseline = {}  # {proto: {"avg_bytes": int, "count": int}}

# Anomaly tracking for escalation (fingerprint -> occurrences)
_anomaly_tracker = {}  # {(type, source_ip, dest_ip, port): [timestamps]}
_anomaly_tracker_lock = threading.Lock()
_ANOMALY_TRACKER_TTL = 600  # 10 minutes

# Threat intelligence cache
_threat_intel_cache = {}  # Cache for threat intelligence results (IP -> {vt: {...}, abuse: {...}, ts: ...})
_threat_intel_cache_lock = threading.Lock()
_threat_intel_cache_ttl = 3600  # Cache for 1 hour


def parse_feed_line(line):
    """Parse feed line: URL or URL|CATEGORY|NAME"""
    parts = line.split('|')
    url = parts[0].strip()
    category = parts[1].strip() if len(parts) > 1 else 'UNKNOWN'
    name = parts[2].strip() if len(parts) > 2 else url.split('/')[-2] if '/' in url else 'feed'
    return url, category, name


def _process_feed(url, category, name, last_ok):
    """Process a single feed in a separate thread."""
    feed_start = time.time()
    try:
        r = requests.get(url, timeout=25)
        latency_ms = int((time.time() - feed_start) * 1000)

        if r.status_code != 200:
            return {
                'name': name,
                'success': False,
                'status_data': {
                    'status': 'error', 'category': category, 'ips': 0,
                    'error': f'HTTP {r.status_code}', 'latency_ms': latency_ms,
                    'last_attempt': time.time(), 'last_ok': last_ok
                },
                'error_msg': f'{name}: HTTP {r.status_code}'
            }

        # Parse IPs from feed
        feed_ips = []
        feed_ip_map = {}
        for line in r.text.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            # Handle CIDR notation in DROP lists
            if '/' in line:
                line = line.split('/')[0].strip()
            # Handle space-separated formats (some feeds have "IP ; comment")
            if ' ' in line:
                line = line.split()[0].strip()
            if line:
                feed_ips.append(line)
                feed_ip_map[line] = {'category': category, 'feed': name}

        return {
            'name': name,
            'success': True,
            'ips': feed_ips,
            'ip_map': feed_ip_map,
            'status_data': {
                'status': 'ok', 'category': category, 'ips': len(feed_ips),
                'error': None, 'latency_ms': latency_ms,
                'last_attempt': time.time(), 'last_ok': time.time()
            }
        }
    except Exception as e:
        latency_ms = int((time.time() - feed_start) * 1000)
        return {
            'name': name,
            'success': False,
            'status_data': {
                'status': 'error', 'category': category, 'ips': 0,
                'error': str(e)[:50], 'latency_ms': latency_ms,
                'last_attempt': time.time(), 'last_ok': last_ok
            },
            'error_msg': f'{name}: {str(e)[:30]}'
        }


def fetch_threat_feed():
    global _threat_status, _threat_ip_to_feed, _feed_status, _feed_data_lock
    try:
        now = time.time()
        _threat_status['last_attempt'] = now
        
        # Report start of fetch
        update_dependency_health('threat_feeds', last_fetch=now)
        
        # Support multiple feeds from threat-feeds.txt
        feed_entries = []
        # Use configured path
        feeds_file = THREAT_FEEDS_PATH
        if os.path.exists(feeds_file):
            with open(feeds_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        feed_entries.append(parse_feed_line(line))
        elif os.path.exists(THREAT_FEED_URL_PATH):
            with open(THREAT_FEED_URL_PATH, 'r') as f:
                url = f.read().strip()
                if url:
                    feed_entries.append((url, 'UNKNOWN', 'legacy-feed'))
        
        if not feed_entries:
            _threat_status['status'] = 'missing'
            return
        
        all_ips = set()
        ip_to_feed = {}
        errors = []
        new_feed_status = {}
        
        # PERFORMANCE: Parallelize feed fetching
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for url, category, name in feed_entries:
                last_ok = _feed_status.get(name, {}).get('last_ok', 0)
                futures.append(executor.submit(_process_feed, url, category, name, last_ok))

            # Process results in order to preserve priority (last feed wins for overlapping IPs)
            for future in futures:
                try:
                    result = future.result()
                    name = result['name']
                    new_feed_status[name] = result['status_data']

                    if result['success']:
                        all_ips.update(result['ips'])
                        ip_to_feed.update(result['ip_map'])
                    else:
                        errors.append(result['error_msg'])
                except Exception as exc:
                    # Should be caught in _process_feed, but just in case
                    errors.append(f'Feed processing error: {str(exc)}')

        # Update global state atomically
        with _feed_data_lock:
            _feed_status = new_feed_status
            _threat_ip_to_feed = ip_to_feed

        if not all_ips:
            _threat_status['status'] = 'empty'
            _threat_status['size'] = 0
            _threat_status['error'] = '; '.join(errors) if errors else None
            return
        
        tmp_path = THREATLIST_PATH + '.tmp'
        with open(tmp_path, 'w') as f:
            f.write('\n'.join(sorted(all_ips)))
        os.replace(tmp_path, THREATLIST_PATH)
        
        _threat_status['last_ok'] = time.time()
        _threat_status['size'] = len(all_ips)
        _threat_status['feeds_ok'] = sum(1 for f in new_feed_status.values() if f['status'] == 'ok')
        _threat_status['feeds_total'] = len(new_feed_status)
        _threat_status['status'] = 'ok'
        _threat_status['error'] = '; '.join(errors) if errors else None
        
        # Report success
        update_dependency_health('threat_feeds', 
            records_count=len(all_ips),
            feeds_status=new_feed_status,
            fetch_success_count=_threat_status.get('success_count', 0) + 1,
            last_ok=time.time()
        )
    except Exception as e:
        _threat_status['status'] = 'error'
        _threat_status['error'] = str(e)
        
        # Report error
        update_dependency_health('threat_feeds', 
            last_error=str(e),
            fetch_error_count=_threat_status.get('error_count', 0) + 1
        )


def get_threat_info(ip):
    """Get threat category and feed name for an IP"""
    info = _threat_ip_to_feed.get(ip, {'category': 'UNKNOWN', 'feed': 'unknown'})
    # Add MITRE ATT&CK mapping
    mitre = MITRE_MAPPINGS.get(info.get('category', 'UNKNOWN'), {})
    info['mitre_technique'] = mitre.get('technique', '')
    info['mitre_tactic'] = mitre.get('tactic', '')
    info['mitre_name'] = mitre.get('name', '')
    return info


def update_threat_timeline(ip):
    """Track first/last seen timestamps for threat IPs"""
    now = time.time()
    if ip in _threat_timeline:
        _threat_timeline[ip]['last_seen'] = now
        _threat_timeline[ip]['hit_count'] += 1
    else:
        _threat_timeline[ip] = {
            'first_seen': now,
            'last_seen': now,
            'hit_count': 1
        }


def get_threat_timeline(ip):
    """Get timeline info for a threat IP"""
    return _threat_timeline.get(ip, {'first_seen': 0, 'last_seen': 0, 'hit_count': 0})


def is_ip_threat(ip):
    """Check if IP is in the threat list."""
    return ip in load_threatlist()


def get_recent_alert_ips(seconds):
    """Get unique IPs involved in alerts within X seconds."""
    threshold = time.time() - seconds
    ips = set()
    with _alert_history_lock:
        # Convert deque to list to avoid iteration issues during concurrent modifications
        alerts_snapshot = list(_alert_history)
    for alert in alerts_snapshot:
        if alert.get('ts', 0) >= threshold:
            ip = alert.get('ip') or alert.get('src_ip')
            if ip:
                ips.add(ip)
    return ips


def load_watchlist():
    """Load custom watchlist IPs"""
    global _watchlist_cache
    now = time.monotonic()

    # PERFORMANCE: Check file mtime only periodically to reduce syscalls
    if now - _watchlist_cache.get("last_check", 0) < FILE_CHECK_INTERVAL:
        return _watchlist_cache["data"]

    _watchlist_cache["last_check"] = now

    try:
        if not os.path.exists(WATCHLIST_PATH):
            # Clear cache if file is missing to prevent serving stale data
            _watchlist_cache["data"] = set()
            _watchlist_cache["mtime"] = 0
            return _watchlist_cache["data"]

        mtime = os.path.getmtime(WATCHLIST_PATH)
        if mtime != _watchlist_cache["mtime"]:
            with open(WATCHLIST_PATH, "r") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                _watchlist_cache["data"] = set(lines)
                _watchlist_cache["mtime"] = mtime
    except Exception as e:
        add_app_log(f"Error loading watchlist: {e}", "ERROR")
    return _watchlist_cache["data"]


def add_to_watchlist(ip):
    """Add IP to watchlist"""
    try:
        watchlist = load_watchlist()
        if ip in watchlist:
            return False
        with open(WATCHLIST_PATH, "a") as f:
            f.write(f"\n{ip}")
        _watchlist_cache["mtime"] = 0  # Force reload
        return True
    except Exception as e:
        print(f"Error adding to watchlist: {e}")
        return False


def remove_from_watchlist(ip):
    """Remove IP from watchlist"""
    try:
        watchlist = load_watchlist()
        if ip not in watchlist:
            return False
        watchlist.discard(ip)
        with open(WATCHLIST_PATH, "w") as f:
            f.write('\n'.join(sorted(watchlist)))
        _watchlist_cache["mtime"] = 0
        return True
    except Exception as e:
        print(f"Error removing from watchlist: {e}")
        return False


def load_security_webhook_config():
    """Load security webhook config with caching."""
    global _webhook_config_cache
    now = time.monotonic()

    # Check cache freshness
    if now - _webhook_config_cache.get("last_check", 0) < FILE_CHECK_INTERVAL:
        return _webhook_config_cache["data"]

    _webhook_config_cache["last_check"] = now

    try:
        if not os.path.exists(SECURITY_WEBHOOK_PATH):
            _webhook_config_cache["data"] = None
            _webhook_config_cache["mtime"] = 0
            return None

        mtime = os.path.getmtime(SECURITY_WEBHOOK_PATH)
        if mtime != _webhook_config_cache["mtime"] or _webhook_config_cache["data"] is None:
            with open(SECURITY_WEBHOOK_PATH, 'r') as f:
                _webhook_config_cache["data"] = json.load(f)
            _webhook_config_cache["mtime"] = mtime
    except Exception as e:
        print(f"Error loading security webhook config: {e}")
        # Keep old data on error if available

    return _webhook_config_cache["data"]


def _process_webhooks():
    """Background worker to process security webhooks."""
    session = requests.Session()
    BATCH_SIZE = 50

    while True:
        try:
            batch = []
            stop = False

            # Block for first item
            item = _webhook_queue.get()
            if item is None:
                _webhook_queue.task_done()
                break
            batch.append(item)

            # Try to fill batch without blocking
            try:
                while len(batch) < BATCH_SIZE:
                    item = _webhook_queue.get_nowait()
                    if item is None:
                        _webhook_queue.task_done()
                        stop = True
                        break
                    batch.append(item)
            except queue.Empty:
                pass

            # Process batch
            try:
                if batch:
                    config = load_security_webhook_config()
                    if config:
                        url = config.get('url')
                        if url:
                            headers = config.get('headers', {'Content-Type': 'application/json'})
                            payload = {
                                'source': 'netflow-dashboard',
                                'timestamp': time.time(),
                                'threats': batch,
                                'count': len(batch)
                            }
                            try:
                                session.post(url, json=payload, headers=headers, timeout=5)
                            except Exception as e:
                                print(f"Security webhook error: {e}")
            finally:
                # Mark tasks done
                for _ in batch:
                    _webhook_queue.task_done()

            if stop:
                break
        except Exception as e:
            print(f"Webhook worker error: {e}")


def start_webhook_worker():
    """Start the webhook worker thread if not running."""
    global _webhook_thread
    if _webhook_thread is None or not _webhook_thread.is_alive():
        _webhook_thread = threading.Thread(target=_process_webhooks, daemon=True, name="SecurityWebhookWorker")
        _webhook_thread.start()


def send_security_webhook(threat_data):
    """Enqueue threat data for security webhook (non-blocking)."""
    start_webhook_worker()
    _webhook_queue.put(threat_data)
    return True


def detect_anomalies(ports_data, sources_data, threat_set, whitelist, feed_label="threat-feed", destinations_data=None):
    alerts = []
    seen = set()
    threat_set = threat_set - whitelist
    
    # PERFORMANCE: Load watchlist once at start instead of per-IP check (reduces file I/O)
    watchlist = load_watchlist()
    
    LARGE_TRANSFER_THRESHOLD = 100 * 1024 * 1024  # 100MB

    # Enhanced detection logic for ports
    for item in ports_data:
        try:
            port = int(item["key"])
            if port in SUSPICIOUS_PORTS:
                alert_key = f"suspicious_{port}"
                if alert_key not in seen:
                    service = PORTS.get(port, "Unknown")
                    alerts.append({"type":"suspicious_port","msg":f"Suspicious port {port} ({service}): {fmt_bytes(item['bytes'])}","severity":"high","feed":"local"})
                    seen.add(alert_key)
        except Exception:
            pass

    # Process sources (Outbound/Upload) and destinations (Inbound/Download) separately
    # properly identifying direction

    # Prepare datasets: list of (data, direction_label, is_source)
    datasets = [
        (sources_data, "from", True),
        (destinations_data or [], "to", False)
    ]

    for data_list, dir_label, is_source in datasets:
        for item in data_list:
            ip = item.get("key")
            if not ip: continue

            # Large Transfer Check
            if item["bytes"] > LARGE_TRANSFER_THRESHOLD:
                alert_key = f"large_{ip}"
                if alert_key not in seen:
                    alerts.append({
                        "type": "large_transfer",
                        "msg": f"Large transfer {dir_label} {ip}: {fmt_bytes(item['bytes'])}",
                        "severity": "medium",
                        "feed": "local",
                        "direction": "outbound" if is_source else "inbound"
                    })
                    seen.add(alert_key)

            # Threat Check
            if ip in threat_set:
                alert_key = f"threat_{ip}"
                if alert_key not in seen:
                    info = get_threat_info(ip)
                    geo = lookup_geo(ip) or {}
                    alert = {
                        "type": "threat_ip",
                        "msg": f"🚨 {info.get('feed', feed_label)} match: {ip} ({fmt_bytes(item['bytes'])})",
                        "severity": "critical",
                        "feed": info.get('feed', feed_label),
                        "ip": ip,
                        "category": info.get('category', 'UNKNOWN'),
                        "mitre": info.get('mitre_technique', ''),
                        "country": geo.get('country_code', '--'),
                        "bytes": item.get('bytes', 0),
                        "ts": time.time()
                    }
                    alerts.append(alert)
                    seen.add(alert_key)
                    # Track timeline
                    update_threat_timeline(ip)
                    # Send to security webhook if configured
                    send_security_webhook(alert)

            # Watchlist Check
            if ip in watchlist:
                alert_key = f"watchlist_{ip}"
                if alert_key not in seen:
                    alerts.append({
                        "type": "watchlist",
                        "msg": f"Watchlist IP Activity ({dir_label}): {ip}",
                        "severity": "medium",
                        "feed": "watchlist",
                        "ip": ip,
                        "ts": time.time()
                    })
                    seen.add(alert_key)

    # Escalate anomalies to alerts and persist with deduplication
    for alert in alerts:
        if _should_escalate_anomaly(alert):
            _upsert_alert_to_history(alert)

    return alerts


def detect_port_scan(flow_data):
    """Detect port scanning - single IP hitting many ports."""
    global _port_scan_tracker
    alerts = []
    current_time = time.time()
    
    # Clean old entries
    _port_scan_tracker = {ip: data for ip, data in _port_scan_tracker.items() 
                          if current_time - data.get('first_seen', 0) < PORT_SCAN_WINDOW}
    
    for flow in flow_data:
        src_ip = flow.get('src_ip') or flow.get('key')
        dst_port = flow.get('dst_port') or flow.get('port')
        if not src_ip or not dst_port:
            continue
        
        # Only track external IPs scanning internal
        if not is_internal(src_ip):
            if src_ip not in _port_scan_tracker:
                _port_scan_tracker[src_ip] = {'ports': set(), 'first_seen': current_time}
            
            _port_scan_tracker[src_ip]['ports'].add(dst_port)
            
            if len(_port_scan_tracker[src_ip]['ports']) >= PORT_SCAN_THRESHOLD:
                alerts.append({
                    "type": "port_scan",
                    "msg": f"Port Scan Detected: {src_ip} probed {len(_port_scan_tracker[src_ip]['ports'])} ports",
                    "severity": "high",
                    "ip": src_ip,
                    "source": src_ip,  # Context for fingerprinting
                    "ports_scanned": len(_port_scan_tracker[src_ip]['ports']),
                    "ts": current_time,
                    "mitre": "T1046"  # Network Service Discovery
                })
                # Reset to avoid repeated alerts
                _port_scan_tracker[src_ip]['ports'] = set()
    
    return alerts


def detect_brute_force(flow_data):
    """Detect brute force attempts - many connections to auth ports."""
    alerts = []
    auth_attempts = defaultdict(lambda: {'count': 0, 'bytes': 0})
    
    for flow in flow_data:
        dst_port = flow.get('dst_port') or flow.get('port')
        src_ip = flow.get('src_ip') or flow.get('key')
        
        try:
            dst_port = int(dst_port)
        except (ValueError, TypeError):
            continue
        
        if dst_port in BRUTE_FORCE_PORTS and src_ip:
            auth_attempts[src_ip]['count'] += flow.get('flows', 1)
            auth_attempts[src_ip]['port'] = dst_port
    
    # PERFORMANCE: Compute timestamp once for all alerts instead of per-alert
    now_ts = time.time()
    for ip, data in auth_attempts.items():
        if data['count'] >= 50:  # 50+ connection attempts
            service = PORTS.get(data['port'], f"Port {data['port']}")
            alerts.append({
                "type": "brute_force",
                "msg": f"Possible Brute Force: {ip} → {service} ({data['count']} attempts)",
                "severity": "high",
                "ip": ip,
                "port": data['port'],
                "attempts": data['count'],
                "ts": now_ts,
                "mitre": "T1110"  # Brute Force
            })
    
    return alerts


def detect_data_exfiltration(sources_data, destinations_data):
    """Detect potential data exfiltration - large outbound from internal hosts."""
    alerts = []
    
    # Build inbound/outbound map for internal hosts
    internal_traffic = defaultdict(lambda: {'in': 0, 'out': 0})
    
    for item in sources_data:
        ip = item.get('key')
        if ip and is_internal(ip):
            internal_traffic[ip]['out'] += item.get('bytes', 0)
    
    for item in (destinations_data or []):
        ip = item.get('key')
        if ip and is_internal(ip):
            internal_traffic[ip]['in'] += item.get('bytes', 0)
    
    # PERFORMANCE: Compute timestamp once for all alerts instead of per-alert
    now_ts = time.time()
    for ip, traffic in internal_traffic.items():
        out_mb = traffic['out'] / (1024 * 1024)
        in_mb = max(traffic['in'] / (1024 * 1024), 0.1)  # Avoid div by 0
        ratio = out_mb / in_mb
        
        if out_mb >= EXFIL_THRESHOLD_MB:
            alerts.append({
                "type": "data_exfil",
                "msg": f"📤 Large Outbound: {ip} sent {out_mb:.1f} MB",
                "severity": "high",
                "ip": ip,
                "bytes_out": traffic['out'],
                "ratio": ratio,
                "ts": now_ts,
                "mitre": "T1041"  # Exfiltration Over C2 Channel
            })
        elif ratio >= EXFIL_RATIO_THRESHOLD and out_mb >= 50:  # At least 50MB with high ratio
            alerts.append({
                "type": "data_exfil",
                "msg": f"📤 Suspicious Outbound Ratio: {ip} ({ratio:.1f}x out/in)",
                "severity": "medium",
                "ip": ip,
                "bytes_out": traffic['out'],
                "ratio": ratio,
                "ts": now_ts,
                "mitre": "T1041"
            })
    
    return alerts


def detect_dns_anomaly(flow_data):
    """Detect DNS tunneling indicators - excessive DNS queries."""
    alerts = []
    dns_queries = defaultdict(int)
    
    for flow in flow_data:
        dst_port = flow.get('dst_port') or flow.get('port')
        src_ip = flow.get('src_ip') or flow.get('key')
        
        try:
            if int(dst_port) == 53:
                dns_queries[src_ip] += flow.get('flows', 1)
        except (ValueError, TypeError):
            continue
    
    # PERFORMANCE: Compute timestamp once for all alerts instead of per-alert
    now_ts = time.time()
    for ip, count in dns_queries.items():
        if count >= DNS_QUERY_THRESHOLD:
            alerts.append({
                "type": "dns_tunneling",
                "msg": f"Excessive DNS: {ip} made {count} queries",
                "severity": "medium",
                "ip": ip,
                "query_count": count,
                "ts": now_ts,
                "mitre": "T1071.004"  # DNS Protocol
            })
    
    return alerts


def detect_new_external(sources_data, destinations_data):
    """Detect first-time connections to new countries/ASNs.
    
    The _seen_external set is periodically cleaned (every 24h) to:
    1. Prevent memory growth from accumulating forever
    2. Re-enable alerts for countries/ASNs not seen recently
    """
    global _seen_external
    alerts = []
    
    # Initialize tracking metadata if not present
    if 'last_cleanup' not in _seen_external:
        _seen_external['last_cleanup'] = time.time()
    
    # Periodic cleanup: reset every 24 hours to re-enable new-external detection
    now_ts = time.time()
    if now_ts - _seen_external['last_cleanup'] > 86400:  # 24 hours
        # Preserve some recent entries to avoid immediate flood after cleanup
        # Keep only a subset of most "recent" entries (we don't track recency, so just cap size)
        if len(_seen_external['countries']) > 50:
            # Keep arbitrary 20 countries (can't track recency, so just trim)
            _seen_external['countries'] = set(list(_seen_external['countries'])[:20])
        if len(_seen_external['asns']) > 200:
            _seen_external['asns'] = set(list(_seen_external['asns'])[:50])
        _seen_external['last_cleanup'] = now_ts
    
    all_ips = set()
    for item in sources_data:
        all_ips.add(item.get('key'))
    for item in (destinations_data or []):
        all_ips.add(item.get('key'))
    
    for ip in all_ips:
        if not ip or is_internal(ip):
            continue
        
        geo = lookup_geo(ip)
        if geo:
            country = geo.get('country_code')
            asn = geo.get('asn')
            
            if country and country not in _seen_external['countries']:
                _seen_external['countries'].add(country)
                # Only alert after initial population (don't flood on startup)
                if len(_seen_external['countries']) > 10:
                    alerts.append({
                        "type": "new_country",
                        "msg": f"🌍 First Contact: {country} ({geo.get('country_name', 'Unknown')})",
                        "severity": "low",
                        "ip": ip,
                        "country": country,
                        "ts": now_ts,
                        "mitre": "T1071"
                    })
            
            if asn and asn not in _seen_external['asns']:
                _seen_external['asns'].add(asn)
                if len(_seen_external['asns']) > 50:
                    alerts.append({
                        "type": "new_asn",
                        "msg": f"🏢 New ASN Contact: AS{asn} ({geo.get('asn_name', 'Unknown')[:30]})",
                        "severity": "low",
                        "ip": ip,
                        "asn": asn,
                        "ts": now_ts,
                        "mitre": "T1071"
                    })
    
    return alerts


def detect_lateral_movement(flow_data):
    """Detect internal-to-internal traffic spikes."""
    alerts = []
    internal_pairs = defaultdict(lambda: {'bytes': 0, 'flows': 0})
    
    for flow in flow_data:
        src_ip = flow.get('src_ip') or flow.get('key')
        dst_ip = flow.get('dst_ip')
        
        if not src_ip or not dst_ip:
            continue
        
        src_internal = is_internal(src_ip)
        dst_internal = is_internal(dst_ip)
        
        if src_internal and dst_internal and src_ip != dst_ip:
            pair_key = f"{src_ip}->{dst_ip}"
            internal_pairs[pair_key]['bytes'] += flow.get('bytes', 0)
            internal_pairs[pair_key]['flows'] += flow.get('flows', 1)
            internal_pairs[pair_key]['src'] = src_ip
            internal_pairs[pair_key]['dst'] = dst_ip
    
    # PERFORMANCE: Compute timestamp once for all alerts instead of per-alert
    now_ts = time.time()
    for pair, data in internal_pairs.items():
        mb = data['bytes'] / (1024 * 1024)
        if mb >= 100 or data['flows'] >= 1000:  # 100MB or 1000 flows internal
            alerts.append({
                "type": "lateral_movement",
                "msg": f"Internal Transfer: {data['src']} → {data['dst']} ({mb:.1f} MB)",
                "severity": "medium",
                "src_ip": data['src'],
                "dst_ip": data['dst'],
                "bytes": data['bytes'],
                "flows": data['flows'],
                "ts": now_ts,
                "mitre": "T1021"  # Remote Services
            })
    
    return alerts


def detect_protocol_anomaly(protocols_data):
    """Detect unusual protocol usage patterns."""
    global _protocol_baseline
    alerts = []
    
    for proto in protocols_data:
        proto_name = proto.get('proto') or proto.get('key')
        proto_bytes = proto.get('bytes', 0)
        
        if proto_name not in _protocol_baseline:
            _protocol_baseline[proto_name] = {'total_bytes': proto_bytes, 'samples': 1}
        else:
            baseline = _protocol_baseline[proto_name]
            avg = baseline['total_bytes'] / baseline['samples']
            
            # Update baseline (exponential moving average)
            baseline['total_bytes'] += proto_bytes
            baseline['samples'] += 1
            
            # Alert if 5x average and significant volume
            if proto_bytes > avg * 5 and proto_bytes > 10 * 1024 * 1024:  # 10MB minimum
                alerts.append({
                    "type": "protocol_anomaly",
                    "msg": f"Protocol Spike: {proto_name} at {fmt_bytes(proto_bytes)} (5x normal)",
                    "severity": "medium",
                    "protocol": proto_name,
                    "bytes": proto_bytes,
                    "avg_bytes": avg,
                    "port": proto_name,  # Context for fingerprinting (protocol as port identifier)
                    "ts": time.time(),  # Keep per-alert for anomaly timing precision
                    "mitre": "T1095"  # Non-Application Layer Protocol
                })
    
    return alerts


def detect_off_hours_activity(sources_data):
    """Detect significant activity during off-hours."""
    alerts = []
    current_hour = datetime.now().hour
    
    # Check if outside business hours
    if current_hour >= BUSINESS_HOURS_START and current_hour < BUSINESS_HOURS_END:
        return alerts  # During business hours, no alerts
    
    # PERFORMANCE: Compute timestamp once for all alerts instead of per-alert
    now_ts = time.time()
    for item in sources_data:
        ip = item.get('key')
        bytes_val = item.get('bytes', 0)
        mb = bytes_val / (1024 * 1024)
        
        # Only internal hosts
        if ip and is_internal(ip):
            if mb >= OFF_HOURS_THRESHOLD_MB:
                alerts.append({
                    "type": "off_hours",
                    "msg": f"Off-Hours Activity: {ip} transferred {mb:.1f} MB at {current_hour}:00",
                    "severity": "low",
                    "ip": ip,
                    "bytes": bytes_val,
                    "hour": current_hour,
                    "ts": now_ts,
                    "mitre": "T1029"  # Scheduled Transfer
                })
    
    return alerts


@instrument_service('run_all_detections')
def run_all_detections(ports_data, sources_data, destinations_data, protocols_data, flow_data=None):
    """Run all detection algorithms and aggregate alerts.
    
    OBSERVABILITY: Instrumented to track execution time and call frequency.
    """
    all_alerts = []
    
    # Basic flow data (simplified if not provided)
    if flow_data is None:
        flow_data = sources_data + (destinations_data or [])
    
    try:
        all_alerts.extend(detect_port_scan(flow_data))
    except Exception as e:
        print(f"Port scan detection error: {e}")
    
    try:
        all_alerts.extend(detect_brute_force(flow_data))
    except Exception as e:
        print(f"Brute force detection error: {e}")
    
    try:
        all_alerts.extend(detect_data_exfiltration(sources_data, destinations_data))
    except Exception as e:
        print(f"Data exfil detection error: {e}")
    
    try:
        all_alerts.extend(detect_dns_anomaly(flow_data))
    except Exception as e:
        print(f"DNS anomaly detection error: {e}")
    
    try:
        all_alerts.extend(detect_new_external(sources_data, destinations_data))
    except Exception as e:
        print(f"New external detection error: {e}")
    
    try:
        all_alerts.extend(detect_lateral_movement(flow_data))
    except Exception as e:
        print(f"Lateral movement detection error: {e}")
    
    try:
        all_alerts.extend(detect_protocol_anomaly(protocols_data))
    except Exception as e:
        print(f"Protocol anomaly detection error: {e}")
    
    try:
        all_alerts.extend(detect_off_hours_activity(sources_data))
    except Exception as e:
        print(f"Off-hours detection error: {e}")
    
    # Escalate anomalies to alerts and persist with deduplication
    for alert in all_alerts:
        if _should_escalate_anomaly(alert):
            _upsert_alert_to_history(alert)
    
    return all_alerts


def load_threatlist():
    """Load threat list from file with caching."""
    now = time.monotonic()

    # PERFORMANCE: Check file mtime only periodically to reduce syscalls
    if now - _threat_cache.get("last_check", 0) < FILE_CHECK_INTERVAL:
        return _threat_cache["data"]

    _threat_cache["last_check"] = now

    try:
        mtime = os.path.getmtime(THREATLIST_PATH)
    except FileNotFoundError:
        # Clear cache if file is missing to prevent serving stale data
        _threat_cache["data"] = set()
        _threat_cache["mtime"] = 0
        return _threat_cache["data"]

    if mtime != _threat_cache["mtime"]:
        try:
            with open(THREATLIST_PATH, "r") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                _threat_cache["data"] = set(lines)
                _threat_cache["mtime"] = mtime
        except Exception as e:
            add_app_log(f"Error loading threatlist: {e}", "ERROR")
    return _threat_cache["data"]


def get_feed_label():
    """Get the label for the threat feed."""
    return "threat-feed"


def send_webhook(alerts):
    """Send alerts to webhook URL if configured."""
    notify = load_notify_cfg()
    if not notify.get("webhook", True):
        return
    if not os.path.exists(WEBHOOK_PATH):
        return
    try:
        with open(WEBHOOK_PATH, "r") as f:
            url = f.read().strip()
        if url:
            requests.post(url, json={"alerts": alerts}, timeout=3)
    except Exception:
        pass


def record_history(alerts):
    """Record alerts in history queue."""
    if not alerts:
        return
    ts = time.time()
    for a in alerts:
        entry = {"ts": ts, "msg": a.get('msg'), "severity": a.get('severity', 'info')}
        _alert_history.appendleft(entry)


def _get_alert_fingerprint(alert):
    """Generate fingerprint for alert deduplication: (type, source_ip, destination_ip, port).
    
    Args:
        alert: Alert dictionary
        
    Returns:
        Tuple of (type, source_ip, destination_ip, port) for fingerprinting
    """
    alert_type = alert.get('type', 'unknown')
    source_ip = alert.get('ip') or alert.get('source') or alert.get('src_ip') or ''
    dest_ip = alert.get('destination') or alert.get('dst_ip') or alert.get('dest') or ''
    port = alert.get('port') or alert.get('dst_port') or alert.get('src_port') or ''
    
    return (alert_type, source_ip, dest_ip, str(port))


def _should_escalate_anomaly(alert):
    """Determine if an anomaly should be escalated to an alert.
    
    Escalation criteria:
    - Severity is HIGH or CRITICAL, OR
    - Same anomaly repeats ≥ 3 times within 10 minutes, OR
    - Anomaly persists across consecutive polling intervals, OR
    - Anomaly involves a watchlist IP
    
    Args:
        alert: Anomaly/alert dictionary
        
    Returns:
        Boolean indicating if anomaly should be escalated
    """
    global _anomaly_tracker
    severity = alert.get('severity', 'low').lower()
    
    # Escalate if severity is HIGH or CRITICAL
    if severity in ('high', 'critical'):
        return True
    
    # Escalate if involves watchlist IP
    ip = alert.get('ip') or alert.get('source') or alert.get('src_ip')
    if ip and ip in load_watchlist():
        return True
    
    # Check repetition and persistence
    fingerprint = _get_alert_fingerprint(alert)
    now_ts = time.time()
    
    with _anomaly_tracker_lock:
        # Clean old entries in-place (avoid replacing global reference)
        stale_keys = [
            k for k, v in _anomaly_tracker.items()
            if not any(now_ts - ts < _ANOMALY_TRACKER_TTL for ts in v)
        ]
        for k in stale_keys:
            del _anomaly_tracker[k]
        for k in _anomaly_tracker:
            _anomaly_tracker[k] = [ts for ts in _anomaly_tracker[k] if now_ts - ts < _ANOMALY_TRACKER_TTL]

        # Track this anomaly
        if fingerprint not in _anomaly_tracker:
            _anomaly_tracker[fingerprint] = []
        _anomaly_tracker[fingerprint].append(now_ts)
        
        occurrences = _anomaly_tracker[fingerprint]
        
        # STRICTER ESCALATION RULES
        
        # Escalate if ≥ 5 occurrences within 10 minutes (was 3)
        if len(occurrences) >= 5:
            return True
        
        # Escalate if persists across intervals (3+ occurrences with > 1 minute gap) (was 2)
        if len(occurrences) >= 3:
            time_gaps = [occurrences[i+1] - occurrences[i] for i in range(len(occurrences)-1)]
            if any(gap > 60 for gap in time_gaps):  # Persisted across polling intervals
                return True
    
    return False


def _upsert_alert_to_history(alert):
    """Add or update alert in history with deduplication and lifecycle management.

    ALERTS are rare, actionable security events requiring human attention.
    One alert per condition - repeated triggers update the same alert, not create new ones.

    Lifecycle fields:
    - created_at: When the alert was first created
    - last_seen: When the condition was last observed
    - active: True if alert is still active, False if resolved
    - resolved_at: When the alert was auto-resolved (None if active)

    If a matching alert (by fingerprint) exists within the last 30 minutes:
    - Update last_seen timestamp
    - Increment count
    - Re-activate if it was resolved
    - Do not create a new alert row

    Otherwise, create a new alert with required fields.

    Args:
        alert: Alert dictionary with at least type, severity, msg
    """
    now_ts = time.time()
    fingerprint = _get_alert_fingerprint(alert)

    # Ensure required fields
    if 'ts' not in alert:
        alert['ts'] = now_ts
    if 'severity' not in alert:
        alert['severity'] = 'medium'
    if 'type' not in alert:
        alert['type'] = 'unknown'

    # Ensure context fields for UI
    if 'ip' not in alert:
        alert['ip'] = alert.get('source') or alert.get('src_ip') or ''
    if 'source' not in alert and alert.get('ip'):
        alert['source'] = alert['ip']
    if 'destination' not in alert and alert.get('dest_ip'):
        alert['destination'] = alert['dest_ip']

    with _alert_history_lock:
        # Look for matching alert within last 30 minutes
        cutoff_ts = now_ts - 1800  # 30 minutes
        matching_alert = None

        for existing_alert in _alert_history:
            if existing_alert.get('ts', 0) > cutoff_ts:
                existing_fp = _get_alert_fingerprint(existing_alert)
                if existing_fp == fingerprint:
                    matching_alert = existing_alert
                    break

        if matching_alert:
            # Update existing alert - one alert per condition
            matching_alert['last_seen'] = now_ts
            matching_alert['count'] = matching_alert.get('count', 1) + 1
            # Re-activate if it was resolved
            matching_alert['active'] = True
            matching_alert['resolved_at'] = None
            # Preserve created_at/first_seen
            if 'created_at' not in matching_alert:
                matching_alert['created_at'] = matching_alert.get('first_seen', matching_alert.get('ts', now_ts))
            if 'first_seen' not in matching_alert:
                matching_alert['first_seen'] = matching_alert.get('ts', now_ts)
            # Update message to reflect count (strip existing count suffix if present)
            original_msg = matching_alert.get('msg', '')
            if ' (x' in original_msg:
                original_msg = original_msg.rsplit(' (x', 1)[0]
            matching_alert['msg'] = f"{original_msg} (x{matching_alert['count']})"
        else:
            # Create new alert with lifecycle fields
            alert['count'] = 1
            alert['created_at'] = now_ts
            alert['first_seen'] = now_ts
            alert['last_seen'] = now_ts
            alert['active'] = True
            alert['resolved_at'] = None
            _alert_history.append(alert)


def auto_resolve_stale_alerts(stale_threshold_seconds=1800):
    """Auto-resolve alerts that haven't been seen for the threshold period.

    Alerts auto-resolve when conditions clear (no new occurrences for 30 minutes).
    This prevents alert accumulation and reflects current system state.

    Args:
        stale_threshold_seconds: Time without activity before auto-resolve (default 30 min)

    Returns:
        Number of alerts resolved
    """
    now_ts = time.time()
    cutoff = now_ts - stale_threshold_seconds
    resolved_count = 0

    with _alert_history_lock:
        for alert in _alert_history:
            if alert.get('active', True) and alert.get('last_seen', 0) < cutoff:
                alert['active'] = False
                alert['resolved_at'] = now_ts
                resolved_count += 1

    return resolved_count


def get_active_alerts_count():
    """Get count of truly active alerts (not resolved, not signals).

    Returns the number of DISTINCT active alert conditions, not the sum of
    occurrence counts. This is the correct metric for "active alerts".

    Returns:
        Integer count of active alert conditions
    """
    # First, auto-resolve any stale alerts
    auto_resolve_stale_alerts()

    with _alert_history_lock:
        # Count distinct active alerts, not their occurrence counts
        return sum(1 for a in _alert_history if a.get('active', True))


def add_health_signal(signal_type, message, level='info', **kwargs):
    """Add a network health signal to the signal store (NOT the alert store).

    IMPORTANT: Signals are informational indicators, NOT actionable alerts.
    They do NOT count toward active_alerts and do NOT affect overall health state.

    Args:
        signal_type: Type (e.g., 'tcp_reset', 'syn_scan', 'icmp_anomaly', 'tiny_flows')
        message: Signal description
        level: 'info', 'elevated', 'high' (NOT severity - these are not alerts)
        **kwargs: Additional context fields
    """
    now_ts = time.time()
    signal = {
        "type": signal_type,
        "msg": message,
        "level": level,  # 'info', 'elevated', 'high' - NOT severity
        "ts": now_ts,
        "is_signal": True,  # Explicit marker - this is NOT an alert
        **kwargs
    }

    with _signal_history_lock:
        # Deduplicate: update existing signal of same type within 5 minutes
        cutoff = now_ts - 300
        for existing in _signal_history:
            if existing.get('type') == signal_type and existing.get('ts', 0) > cutoff:
                existing['ts'] = now_ts
                existing['msg'] = message
                existing['level'] = level
                existing['count'] = existing.get('count', 1) + 1
                return
        # New signal
        signal['count'] = 1
        _signal_history.append(signal)


def get_signal_history(max_age_seconds=3600):
    """Get recent network health signals (NOT alerts).

    Returns:
        List of signal dicts, newest first
    """
    cutoff = time.time() - max_age_seconds
    with _signal_history_lock:
        signals = [s for s in _signal_history if s.get('ts', 0) > cutoff]
    return sorted(signals, key=lambda x: x.get('ts', 0), reverse=True)


# DEPRECATED: Use add_health_signal() instead
# This function is kept for backwards compatibility but now routes to signal store
def add_health_alert_to_history(alert_type, message, severity='medium', **kwargs):
    """DEPRECATED: Use add_health_signal() instead.

    Health indicators are signals, not alerts. This function now routes to the
    signal store to prevent alert inflation.
    """
    # Map old severity to new level
    level_map = {'critical': 'high', 'high': 'high', 'medium': 'elevated', 'low': 'info'}
    level = level_map.get(severity, 'info')
    add_health_signal(alert_type, message, level=level, **kwargs)


def _should_deliver(alert):
    """Check if alert should be delivered based on notification config."""
    cfg = load_notify_cfg()
    if cfg.get('mute_until', 0) > time.time():
        return False
    return True


def send_notifications(alerts):
    """Send notifications for alerts (rate limited to once per minute)."""
    global _alert_sent_ts
    if not alerts:
        return
    filtered = [a for a in alerts if _should_deliver(a)]
    if not filtered:
        return
    now = time.time()
    if now - _alert_sent_ts < 60:
        return
    send_webhook(filtered)
    record_history(filtered)
    _alert_sent_ts = now


def query_virustotal(ip, timeout=5):
    """Query VirusTotal API for IP reputation."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }
        response = requests.get(url, headers=headers, timeout=timeout)
        
        if response.status_code == 200:
            data = response.json()
            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            
            return {
                "reputation": attr.get("reputation", 0),
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "asn": attr.get("asn"),
                "as_owner": attr.get("as_owner", ""),
                "country": attr.get("country", ""),
                "last_analysis_date": attr.get("last_analysis_date"),
                "whois": attr.get("whois", "")[:200] if attr.get("whois") else "",  # Truncate
                "status": "found"
            }
        elif response.status_code == 404:
            return {"status": "not_found"}
        elif response.status_code == 429:
            return {"status": "rate_limited", "error": "Rate limit exceeded"}
        else:
            return {"status": "error", "error": f"HTTP {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"status": "timeout", "error": "Request timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def query_abuseipdb(ip, timeout=5):
    """Query AbuseIPDB API for IP reputation."""
    if not ABUSEIPDB_API_KEY:
        return None
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        
        if response.status_code == 200:
            data = response.json()
            result = data.get("data", {})
            
            return {
                "abuse_confidence_score": result.get("abuseConfidenceScore", 0),
                "usage_type": result.get("usageType", ""),
                "isp": result.get("isp", ""),
                "domain": result.get("domain", ""),
                "country_code": result.get("countryCode", ""),
                "is_whitelisted": result.get("isWhitelisted", False),
                "is_public": result.get("isPublic", False),
                "is_tor": result.get("isTor", False),
                "is_known_attacker": result.get("isKnownAttacker", False),
                "num_reports": result.get("numReports", 0),
                "last_reported_at": result.get("lastReportedAt"),
                "status": "found"
            }
        elif response.status_code == 429:
            return {"status": "rate_limited", "error": "Rate limit exceeded"}
        else:
            return {"status": "error", "error": f"HTTP {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"status": "timeout", "error": "Request timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def lookup_threat_intelligence(ip):
    """Lookup IP reputation from VirusTotal and AbuseIPDB (optional, requires API keys)."""
    # Skip internal IPs
    if is_internal(ip):
        return {"enabled": False, "reason": "Internal IP"}
    
    # Check cache first
    now = time.time()
    with _threat_intel_cache_lock:
        if ip in _threat_intel_cache:
            cached = _threat_intel_cache[ip]
            if now - cached.get('ts', 0) < _threat_intel_cache_ttl:
                return cached.get('data', {})
    
    result = {
        "enabled": False,
        "virustotal": None,
        "abuseipdb": None
    }
    
    # VirusTotal lookup
    if VIRUSTOTAL_API_KEY:
        try:
            vt_result = query_virustotal(ip)
            result["virustotal"] = vt_result
            result["enabled"] = True
        except Exception as e:
            result["virustotal"] = {"error": str(e)}
    
    # AbuseIPDB lookup
    if ABUSEIPDB_API_KEY:
        try:
            abuse_result = query_abuseipdb(ip)
            result["abuseipdb"] = abuse_result
            result["enabled"] = True
        except Exception as e:
            result["abuseipdb"] = {"error": str(e)}
    
    # Cache result
    with _threat_intel_cache_lock:
        _threat_intel_cache[ip] = {"data": result, "ts": now}
        # Simple cache size limit (keep last 1000)
        if len(_threat_intel_cache) > 1000:
            oldest = min(_threat_intel_cache.items(), key=lambda x: x[1].get('ts', 0))
            _threat_intel_cache.pop(oldest[0], None)
    
    return result


def detect_ip_anomalies(ip, tf, direction, src_ports, dst_ports, protocols):
    """Detect traffic pattern anomalies for a specific IP."""
    anomalies = []
    
    try:
        # Anomaly 1: High upload/download ratio (potential data exfiltration)
        upload = direction.get('upload', 0)
        download = direction.get('download', 0)
        if upload > 0 and download > 0:
            ratio = upload / download
            if ratio > 10:  # 10:1 upload to download ratio
                anomalies.append({
                    "type": "high_upload_ratio",
                    "severity": "high",
                    "message": f"High upload/download ratio ({ratio:.1f}:1) - potential data exfiltration",
                    "upload_mb": round(upload / (1024*1024), 2),
                    "download_mb": round(download / (1024*1024), 2),
                    "ratio": round(ratio, 2)
                })
        
        # Anomaly 2: High number of unique ports (potential port scan)
        unique_ports = len(set([p.get('key', '') for p in (src_ports or [])] + [p.get('key', '') for p in (dst_ports or [])]))
        if unique_ports > 20:
            anomalies.append({
                "type": "port_scan",
                "severity": "medium",
                "message": f"High number of unique ports ({unique_ports}) - potential port scan",
                "port_count": unique_ports
            })
        
        # Anomaly 3: Suspicious ports
        suspicious_ports_found = []
        for port_list in [src_ports or [], dst_ports or []]:
            for p in port_list:
                port_num = p.get('key', '')
                try:
                    port_int = int(port_num)
                    if port_int in SUSPICIOUS_PORTS:
                        suspicious_ports_found.append(port_int)
                except (ValueError, TypeError):
                    pass
        
        if suspicious_ports_found:
            anomalies.append({
                "type": "suspicious_ports",
                "severity": "medium",
                "message": f"Suspicious ports detected: {', '.join(map(str, set(suspicious_ports_found)))}",
                "ports": list(set(suspicious_ports_found))
            })
        
        # Anomaly 4: High traffic volume (if external IP)
        if not is_internal(ip):
            total_bytes = upload + download
            total_mb = total_bytes / (1024*1024)
            if total_mb > 1000:  # More than 1GB
                anomalies.append({
                    "type": "high_traffic_volume",
                    "severity": "low",
                    "message": f"High traffic volume ({total_mb:.0f} MB) from external IP",
                    "total_mb": round(total_mb, 2)
                })
        
        # Anomaly 5: ICMP-only or unusual protocol mix
        proto_names = [p.get('proto_name', p.get('key', '')) for p in (protocols or [])]
        if len(proto_names) == 1 and 'ICMP' in proto_names[0]:
            anomalies.append({
                "type": "icmp_only",
                "severity": "low",
                "message": "Traffic consists only of ICMP - potential reconnaissance",
                "protocols": proto_names
            })
        
    except Exception as e:
        print(f"Warning: Anomaly detection failed for IP {ip}: {e}")
    
    return anomalies


def generate_ip_anomaly_alerts(ip, anomalies, geo):
    """Generate alerts for high-severity anomalies detected during IP investigation."""
    if not anomalies:
        return
    
    now = time.time()
    hour_ago = now - 3600
    with _alert_history_lock:
        # PERFORMANCE: Convert deque to list once and filter in single pass
        # Check if we've already alerted for this IP recently (within last hour)
        recent_history = list(_alert_history)[-50:]  # Convert once
        recent_alerts = [a for a in recent_history if a.get('ip') == ip and a.get('ts', 0) > hour_ago]
        if recent_alerts:
            return  # Already alerted recently
        
        # Generate alerts for high and medium severity anomalies
        for anomaly in anomalies:
            if anomaly.get('severity') in ('high', 'medium'):
                alert = {
                    "type": "ip_anomaly",
                    "msg": f"IP Investigation Anomaly: {anomaly.get('message', 'Unknown anomaly')}",
                    "severity": anomaly.get('severity', 'medium'),
                    "feed": "ip_investigation",
                    "ip": ip,
                    "source": ip,  # Ensure context fields for fingerprinting
                    "category": anomaly.get('type', 'UNKNOWN'),
                    "anomaly": anomaly,
                    "country": geo.get('country_code', '--') if geo else '--',
                    "ts": now
                }
                # Escalate and persist with deduplication
                if _should_escalate_anomaly(alert):
                    _upsert_alert_to_history(alert)
                    # Send notification if high severity
                    if anomaly.get('severity') == 'high':
                        send_security_webhook(alert)
