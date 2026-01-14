"""Threat intelligence service for PROX_NFDUMP application."""
import time
import os
import json
import requests
import threading
from datetime import datetime, timezone
from collections import defaultdict, deque
from app.config import (
    WATCHLIST_PATH, THREATLIST_PATH, THREAT_FEED_URL_PATH, MITRE_MAPPINGS,
    SECURITY_WEBHOOK_PATH, WEBHOOK_PATH, PORTS, SUSPICIOUS_PORTS, BRUTE_FORCE_PORTS,
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW, EXFIL_THRESHOLD_MB, EXFIL_RATIO_THRESHOLD,
    DNS_QUERY_THRESHOLD, BUSINESS_HOURS_START, BUSINESS_HOURS_END, OFF_HOURS_THRESHOLD_MB
)
from app.utils.helpers import is_internal, fmt_bytes
from app.utils.geoip import lookup_geo
from app.utils.config_helpers import load_notify_cfg

# Global state for threat intelligence
_threat_status = {'last_attempt': 0, 'last_ok': 0, 'size': 0, 'status': 'unknown', 'error': None}
_threat_ip_to_feed = {}  # Maps IP -> {category, feed_name}
_threat_timeline = {}  # Maps IP -> {first_seen, last_seen, hit_count}
_feed_status = {}  # Per-feed health tracking
_watchlist_cache = {"data": set(), "mtime": 0}
_threat_cache = {"data": set(), "mtime": 0}  # Cache for threat list file

# Detection state
_alert_history = deque(maxlen=200)  # Increased for 24h history
_alert_history_lock = threading.Lock()
_alert_sent_ts = 0  # Timestamp of last notification sent (rate limiting)
_port_scan_tracker = {}  # {ip: {ports: set(), first_seen: ts}}
_seen_external = {"countries": set(), "asns": set()}  # First-seen tracking
_protocol_baseline = {}  # {proto: {"avg_bytes": int, "count": int}}


def parse_feed_line(line):
    """Parse feed line: URL or URL|CATEGORY|NAME"""
    parts = line.split('|')
    url = parts[0].strip()
    category = parts[1].strip() if len(parts) > 1 else 'UNKNOWN'
    name = parts[2].strip() if len(parts) > 2 else url.split('/')[-2] if '/' in url else 'feed'
    return url, category, name


def fetch_threat_feed():
    global _threat_status, _threat_ip_to_feed, _feed_status
    try:
        _threat_status['last_attempt'] = time.time()
        
        # Support multiple feeds from threat-feeds.txt
        feed_entries = []
        # Try /app first (Docker), then /root (production)
        feeds_file = '/app/threat-feeds.txt' if os.path.exists('/app/threat-feeds.txt') else '/root/threat-feeds.txt'
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
        
        for url, category, name in feed_entries:
            feed_start = time.time()
            try:
                r = requests.get(url, timeout=25)
                latency_ms = int((time.time() - feed_start) * 1000)
                
                if r.status_code != 200:
                    new_feed_status[name] = {
                        'status': 'error', 'category': category, 'ips': 0,
                        'error': f'HTTP {r.status_code}', 'latency_ms': latency_ms,
                        'last_attempt': time.time(), 'last_ok': _feed_status.get(name, {}).get('last_ok', 0)
                    }
                    errors.append(f'{name}: HTTP {r.status_code}')
                    continue
                
                # Parse IPs from feed
                feed_ips = []
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
                        ip_to_feed[line] = {'category': category, 'feed': name}
                
                all_ips.update(feed_ips)
                new_feed_status[name] = {
                    'status': 'ok', 'category': category, 'ips': len(feed_ips),
                    'error': None, 'latency_ms': latency_ms,
                    'last_attempt': time.time(), 'last_ok': time.time()
                }
            except Exception as e:
                latency_ms = int((time.time() - feed_start) * 1000)
                new_feed_status[name] = {
                    'status': 'error', 'category': category, 'ips': 0,
                    'error': str(e)[:50], 'latency_ms': latency_ms,
                    'last_attempt': time.time(), 'last_ok': _feed_status.get(name, {}).get('last_ok', 0)
                }
                errors.append(f'{name}: {str(e)[:30]}')
        
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
    except Exception as e:
        _threat_status['status'] = 'error'
        _threat_status['error'] = str(e)


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


def load_watchlist():
    """Load custom watchlist IPs"""
    global _watchlist_cache
    try:
        if not os.path.exists(WATCHLIST_PATH):
            return set()
        mtime = os.path.getmtime(WATCHLIST_PATH)
        if mtime != _watchlist_cache["mtime"]:
            with open(WATCHLIST_PATH, "r") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                _watchlist_cache["data"] = set(lines)
                _watchlist_cache["mtime"] = mtime
    except Exception:
        pass
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


def send_security_webhook(threat_data):
    """Send threat data to configured security webhook (for auto-blocking)"""
    try:
        if not os.path.exists(SECURITY_WEBHOOK_PATH):
            return False
        with open(SECURITY_WEBHOOK_PATH, 'r') as f:
            config = json.load(f)
        
        url = config.get('url')
        if not url:
            return False
        
        headers = config.get('headers', {'Content-Type': 'application/json'})
        payload = {
            'source': 'netflow-dashboard',
            'timestamp': time.time(),
            'threat': threat_data
        }
        
        requests.post(url, json=payload, headers=headers, timeout=5)
        return True
    except Exception as e:
        print(f"Security webhook error: {e}")
        return False


def detect_anomalies(ports_data, sources_data, threat_set, whitelist, feed_label="threat-feed", destinations_data=None):
    alerts = []
    seen = set()
    threat_set = threat_set - whitelist
    
    # Combine sources and destinations for IP checking
    all_ips_data = list(sources_data)
    if destinations_data:
        # Add destination IPs, avoiding duplicates by key
        seen_keys = {item['key'] for item in sources_data}
        for item in destinations_data:
            if item['key'] not in seen_keys:
                all_ips_data.append(item)
                seen_keys.add(item['key'])

    # Enhanced detection logic
    for item in ports_data:
        try:
            port = int(item["key"])
            if port in SUSPICIOUS_PORTS:
                alert_key = f"suspicious_{port}"
                if alert_key not in seen:
                    service = PORTS.get(port, "Unknown")
                    alerts.append({"type":"suspicious_port","msg":f"⚠️ Suspicious port {port} ({service}): {fmt_bytes(item['bytes'])}","severity":"high","feed":"local"})
                    seen.add(alert_key)
        except Exception:
            pass

    # Lower threshold for sample data triggering
    for item in all_ips_data:
        if item["bytes"] > 50*1024*1024: # 50MB
            alert_key = f"large_{item['key']}"
            if alert_key not in seen:
                alerts.append({"type":"large_transfer","msg":f"📊 Large transfer from {item['key']}: {fmt_bytes(item['bytes'])}","severity":"medium","feed":"local"})
                seen.add(alert_key)

        # Threat Check
        if item["key"] in threat_set:
            alert_key = f"threat_{item['key']}"
            if alert_key not in seen:
                ip = item["key"]
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
                # Add to history
                with _alert_history_lock:
                    _alert_history.append(alert)
                # Send to security webhook if configured
                send_security_webhook(alert)

        # Watchlist Check (custom watchlist)
        watchlist = load_watchlist()
        if item["key"] in watchlist:
            alert_key = f"watchlist_{item['key']}"
            if alert_key not in seen:
                alerts.append({
                    "type": "watchlist",
                    "msg": f"👁️ Watchlist IP Activity: {item['key']}",
                    "severity": "medium",
                    "feed": "watchlist",
                    "ip": item["key"],
                    "ts": time.time()
                })
                seen.add(alert_key)

    # Add all alerts to history
    with _alert_history_lock:
        for alert in alerts:
            if 'ts' not in alert:
                alert['ts'] = time.time()
            if alert not in list(_alert_history):
                _alert_history.append(alert)

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
                    "msg": f"🔍 Port Scan Detected: {src_ip} probed {len(_port_scan_tracker[src_ip]['ports'])} ports",
                    "severity": "high",
                    "ip": src_ip,
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
    
    for ip, data in auth_attempts.items():
        if data['count'] >= 50:  # 50+ connection attempts
            service = PORTS.get(data['port'], f"Port {data['port']}")
            alerts.append({
                "type": "brute_force",
                "msg": f"🔐 Possible Brute Force: {ip} → {service} ({data['count']} attempts)",
                "severity": "high",
                "ip": ip,
                "port": data['port'],
                "attempts": data['count'],
                "ts": time.time(),
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
                "ts": time.time(),
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
                "ts": time.time(),
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
    
    for ip, count in dns_queries.items():
        if count >= DNS_QUERY_THRESHOLD:
            alerts.append({
                "type": "dns_tunneling",
                "msg": f"🌐 Excessive DNS: {ip} made {count} queries",
                "severity": "medium",
                "ip": ip,
                "query_count": count,
                "ts": time.time(),
                "mitre": "T1071.004"  # DNS Protocol
            })
    
    return alerts


def detect_new_external(sources_data, destinations_data):
    """Detect first-time connections to new countries/ASNs."""
    global _seen_external
    alerts = []
    
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
                        "ts": time.time(),
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
                        "ts": time.time(),
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
    
    for pair, data in internal_pairs.items():
        mb = data['bytes'] / (1024 * 1024)
        if mb >= 100 or data['flows'] >= 1000:  # 100MB or 1000 flows internal
            alerts.append({
                "type": "lateral_movement",
                "msg": f"↔️ Internal Transfer: {data['src']} → {data['dst']} ({mb:.1f} MB)",
                "severity": "medium",
                "src_ip": data['src'],
                "dst_ip": data['dst'],
                "bytes": data['bytes'],
                "flows": data['flows'],
                "ts": time.time(),
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
                    "msg": f"⚡ Protocol Spike: {proto_name} at {fmt_bytes(proto_bytes)} (5x normal)",
                    "severity": "medium",
                    "protocol": proto_name,
                    "bytes": proto_bytes,
                    "avg_bytes": avg,
                    "ts": time.time(),
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
    
    for item in sources_data:
        ip = item.get('key')
        bytes_val = item.get('bytes', 0)
        mb = bytes_val / (1024 * 1024)
        
        # Only internal hosts
        if ip and is_internal(ip):
            if mb >= OFF_HOURS_THRESHOLD_MB:
                alerts.append({
                    "type": "off_hours",
                    "msg": f"🌙 Off-Hours Activity: {ip} transferred {mb:.1f} MB at {current_hour}:00",
                    "severity": "low",
                    "ip": ip,
                    "bytes": bytes_val,
                    "hour": current_hour,
                    "ts": time.time(),
                    "mitre": "T1029"  # Scheduled Transfer
                })
    
    return alerts


def run_all_detections(ports_data, sources_data, destinations_data, protocols_data, flow_data=None):
    """Run all detection algorithms and aggregate alerts."""
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
    
    # Add all new alerts to history
    with _alert_history_lock:
        for alert in all_alerts:
            if 'ts' not in alert:
                alert['ts'] = time.time()
            # Avoid duplicates in recent history
            existing_keys = {(a.get('type'), a.get('ip'), a.get('msg')) for a in list(_alert_history)[-50:]}
            if (alert.get('type'), alert.get('ip'), alert.get('msg')) not in existing_keys:
                _alert_history.append(alert)
    
    return all_alerts


def load_threatlist():
    """Load threat list from file with caching."""
    try:
        mtime = os.path.getmtime(THREATLIST_PATH)
    except FileNotFoundError:
        _threat_cache["data"] = set()
        _threat_cache["mtime"] = 0
        return set()
    if mtime != _threat_cache["mtime"]:
        try:
            with open(THREATLIST_PATH, "r") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                _threat_cache["data"] = set(lines)
                _threat_cache["mtime"] = mtime
        except Exception:
            pass
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
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for a in alerts:
        entry = {"ts": ts, "msg": a.get('msg'), "severity": a.get('severity', 'info')}
        _alert_history.appendleft(entry)


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
